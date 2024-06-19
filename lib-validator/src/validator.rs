use super::{error::*, log::*, ValidationConfig};
use crate::{constants::ENDPOINT_JWKS_PATH, ValidationConfigInner};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use futures::future::join_all;
use libcommon::{
  token_fields::{Audiences, ClientId, Issuer, TryNewField},
  Claims, ValidationKey, ValidationOptions,
};
use rustc_hash::FxHashMap as HashMap;
use serde::{de::DeserializeOwned, Deserialize};
use std::{hash::Hash, sync::Arc};
use tokio::sync::RwLock;
use url::Url;

#[cfg(feature = "blind-signatures")]
use crate::constants::{ENDPOINT_BLIND_JWKS_PATH, STALE_BLIND_JWKS_TIMEOUT_SEC};
#[cfg(feature = "blind-signatures")]
use libcommon::blind_sig::*;
#[cfg(feature = "blind-signatures")]
use tokio::time::{Duration, Instant};

/// Trait defining http client for jwks retrieval
#[async_trait]
pub trait JwksHttpClient {
  /// Fetch jwks from the given url
  async fn fetch_jwks<R>(&self, url: &Url) -> Result<R>
  where
    R: DeserializeOwned + Send + Sync;
}

#[derive(Deserialize, Debug)]
/// Jwks response
pub(super) struct JwksResponse {
  pub keys: Vec<serde_json::Value>,
}

/// Validator for ID token
pub struct TokenValidator<H>
where
  H: JwksHttpClient,
{
  /// Keys for each token API
  pub(crate) inner: Arc<Vec<TokenValidatorInner<H>>>,
}

impl<H> TokenValidator<H>
where
  H: JwksHttpClient,
{
  pub async fn try_new(config: &ValidationConfig, http_client: Arc<H>) -> Result<Self> {
    let inner = config
      .inner
      .iter()
      .map(|each| TokenValidatorInner::new(each, &http_client))
      .collect::<Vec<_>>();
    let validator = Self { inner: Arc::new(inner) };
    validator.refetch_all_jwks().await?;

    #[cfg(feature = "blind-signatures")]
    validator.refetch_all_blind_jwks().await?;

    Ok(validator)
  }

  /// Validate an id token.
  /// First by checking the key id in the id token header and try to find the validation key with the key id.
  /// Return Ok(()) if validation is successful with the found validation key.
  pub async fn validate(&self, id_token: &str) -> Result<Vec<Claims>> {
    let key_id_in_id_token = key_id_in_id_token(id_token).ok_or(anyhow!("key id not found in id token"))?;

    let futures = self.inner.iter().map(|each| {
      let key_id_in_id_token = key_id_in_id_token.clone();
      async move {
        let lock = each.validation_keys.read().await;
        let Some(vk) = lock.get(&key_id_in_id_token) else {
          return None; // no matched key id
        };
        // matched case
        let res = vk.validate(&id_token.try_into().ok()?, &each.validation_options);
        Some(res)
      }
    });

    let key_matched_results = join_all(futures).await.into_iter().flatten().collect::<Vec<_>>();
    if key_matched_results.is_empty() {
      debug!("Empty validation results, no matched key id");
      bail!(ValidationError::ValidationFailed);
    }

    let results = key_matched_results.into_iter().filter_map(|res| res.ok()).collect::<Vec<_>>();
    if results.is_empty() {
      debug!("Empty validation results, all failed to validate id token");
      bail!(ValidationError::ValidationFailed);
    };

    Ok(results)
  }

  /// Update validation keys of all token APIs
  pub async fn refetch_all_jwks(&self) -> Result<()> {
    let futures = self.inner.iter().map(|each_endpoint| async {
      if let Err(e) = each_endpoint.refetch_jwks().await {
        error!("Failed to retrieve jwks. No update: {}", e);
      };
    });

    join_all(futures).await;

    Ok(())
  }

  /// Validate an anonymous token in base64url.
  /// Return Ok(()) if validation is successful with a validation key matching the key_id in the signature.
  pub async fn validate_anonymous_token(&self, anonymous_token_b64u: &str) -> Result<()> {
    let anonymous_token = AnonymousToken::try_from_base64url(anonymous_token_b64u)?;
    let key_id_in_anonymous_token = KeyId(anonymous_token.signature.key_id.clone());

    let futures = self.inner.iter().map(|each| {
      let anonymous_token = anonymous_token.clone();
      let key_id_in_anonymous_token = key_id_in_anonymous_token.clone();
      async move {
        // try current key
        let lock = each.blind_validation_keys.read().await;
        if let Some(bvk) = lock.get(&key_id_in_anonymous_token) {
          // matched case
          let res = bvk.verify(&anonymous_token);
          return Some(res);
        }
        drop(lock);

        // try stale key within the certain period
        let can_try_stale = each.blind_validation_keys_updated_at.read().await.elapsed() < each.blind_validation_keys_stale_alive;
        if !can_try_stale {
          return None;
        }
        // try stale key
        let lock = each.blind_validation_keys_stale.read().await;
        if let Some(bvk_stale) = lock.get(&key_id_in_anonymous_token) {
          debug!(
            "Try stale key for anonymous token validation: key_id = {}",
            bvk_stale.key_id().unwrap_or("invalid".to_string())
          );
          // matched case for stale key
          let res = bvk_stale.verify(&anonymous_token);
          return Some(res);
        }
        drop(lock);
        // no matched key id
        None
      }
    });

    let key_matched_results = join_all(futures).await.into_iter().flatten().collect::<Vec<_>>();
    if key_matched_results.is_empty() {
      debug!("Empty blind validation results, no matched key id");
      bail!(ValidationError::BlindValidationFailed);
    }

    let results = key_matched_results.into_iter().filter_map(|res| res.ok()).collect::<Vec<_>>();
    if results.is_empty() {
      debug!("Empty blind validation results, all failed to validate id token");
      bail!(ValidationError::BlindValidationFailed);
    };

    Ok(())
  }

  /// Update blinkd validation keys of all token APIs
  #[cfg(feature = "blind-signatures")]
  pub async fn refetch_all_blind_jwks(&self) -> Result<()> {
    let futures = self.inner.iter().map(|each_endpoint| async {
      if let Err(e) = each_endpoint.refetch_blind_jwks().await {
        error!("Failed to retrieve blind jwks. No update: {}", e);
      };
    });

    join_all(futures).await;

    Ok(())
  }
}

/* ------------------------------------------------------------------------ */
/// Key Id to avoid the DoS attack like DNS key trap!
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyId(String);

/// Inner state of the validator
pub struct TokenValidatorInner<H>
where
  H: JwksHttpClient,
{
  /// Token API endpoint
  pub(crate) token_api: url::Url,
  /// Validation key retrieved from the server
  pub(crate) validation_keys: Arc<RwLock<HashMap<KeyId, ValidationKey>>>,
  /// Validation options
  pub(crate) validation_options: ValidationOptions,
  /// http client to fetch jwks
  jwks_http_client: Arc<H>,

  #[cfg(feature = "blind-signatures")]
  /// Blind validation key (up-to-date)
  pub(crate) blind_validation_keys: Arc<RwLock<HashMap<KeyId, RsaPublicKey>>>,
  #[cfg(feature = "blind-signatures")]
  /// Stale blind validation key (to handle the case where the key is rotated)
  /// this is used to verify the anonymous token signed by the previous key
  pub(crate) blind_validation_keys_stale: Arc<RwLock<HashMap<KeyId, RsaPublicKey>>>,
  #[cfg(feature = "blind-signatures")]
  /// Time when the blind validation key is updated
  pub(crate) blind_validation_keys_updated_at: Arc<RwLock<Instant>>,
  #[cfg(feature = "blind-signatures")]
  /// Accept stale key for a certain period after refetching the new key
  pub(crate) blind_validation_keys_stale_alive: Duration,
}

impl<H> TokenValidatorInner<H>
where
  H: JwksHttpClient,
{
  /// Create a new instance of TokenValidatorInner
  pub(crate) fn new(config: &ValidationConfigInner, http_client: &Arc<H>) -> Self {
    let token_api = config.token_api.clone();

    let validation_keys = Arc::new(RwLock::new(HashMap::default()));

    let mut iss = std::collections::HashSet::new();
    iss.insert(Issuer::new(config.token_issuer.as_str()).unwrap_or(Issuer::new("http://localhost:3000").unwrap()));
    let aud = Audiences::from(config.client_ids.iter().flat_map(|id| ClientId::new(id.as_str())));
    let validation_options = ValidationOptions {
      allowed_issuers: Some(iss),
      allowed_audiences: Some(aud),
      ..Default::default()
    };

    TokenValidatorInner {
      token_api,
      validation_keys,
      validation_options,
      jwks_http_client: http_client.clone(),

      #[cfg(feature = "blind-signatures")]
      blind_validation_keys: Arc::new(RwLock::new(HashMap::default())),
      #[cfg(feature = "blind-signatures")]
      blind_validation_keys_stale: Arc::new(RwLock::new(HashMap::default())),
      #[cfg(feature = "blind-signatures")]
      blind_validation_keys_updated_at: Arc::new(RwLock::new(Instant::now())),
      #[cfg(feature = "blind-signatures")]
      blind_validation_keys_stale_alive: Duration::from_secs(STALE_BLIND_JWKS_TIMEOUT_SEC),
    }
  }
  /// refetch jwks from the server
  async fn refetch_jwks(&self) -> Result<()> {
    debug!("refetch jwks: {}/{}", self.token_api, ENDPOINT_JWKS_PATH);

    let jwks_res = self.refetch_jwks_inner(ENDPOINT_JWKS_PATH).await?;

    let vk_map = jwks_res
      .keys
      .iter()
      .map(ValidationKey::from_jwk)
      .map(|vk| vk.map(|vk| (KeyId(vk.key_id()), vk)))
      .collect::<Result<HashMap<_, _>>>()?;

    let mut validation_key_lock = self.validation_keys.write().await;
    *validation_key_lock = vk_map;
    drop(validation_key_lock);

    info!(
      "validation key updated from jwks endpoint: {}/{}",
      self.token_api.as_str(),
      ENDPOINT_JWKS_PATH
    );

    Ok(())
  }

  #[cfg(feature = "blind-signatures")]
  /// refetch blind validation keys from the server
  async fn refetch_blind_jwks(&self) -> Result<()> {
    debug!("refetch blind_jwks: {}/{}", self.token_api, ENDPOINT_BLIND_JWKS_PATH);

    let jwks_res = self.refetch_jwks_inner(ENDPOINT_BLIND_JWKS_PATH).await?;

    let blind_vk_map = jwks_res
      .keys
      .iter()
      .map(RsaPublicKey::from_jwk)
      .map(|bvk| bvk.and_then(|bvk| bvk.key_id().map(|key_id| (KeyId(key_id), bvk))))
      .collect::<Result<HashMap<_, _>>>()?;

    let mut lock = self.blind_validation_keys.write().await;
    if *lock == blind_vk_map {
      // no update
      debug!("no update blind_jwks: {}/{}", self.token_api, ENDPOINT_BLIND_JWKS_PATH);
      return Ok(());
    }
    let stale = lock.clone();
    *lock = blind_vk_map;
    drop(lock);
    // update the stale key
    let mut lock = self.blind_validation_keys_stale.write().await;
    *lock = stale;
    drop(lock);
    // update the time when the blind validation key is updated
    let mut lock = self.blind_validation_keys_updated_at.write().await;
    *lock = Instant::now();
    drop(lock);
    debug!(
      "validation key for blind signature: current = {:?}, stale = {:?}, instant = {}",
      self.blind_validation_keys.read().await.keys().collect::<Vec<_>>(),
      self.blind_validation_keys_stale.read().await.keys().collect::<Vec<_>>(),
      self.blind_validation_keys_updated_at.read().await.elapsed().as_secs()
    );

    info!(
      "validation key for blind signature updated from blindjwks endpoint: {}/{}",
      self.token_api.as_str(),
      ENDPOINT_BLIND_JWKS_PATH
    );

    Ok(())
  }

  async fn refetch_jwks_inner(&self, path: &str) -> Result<JwksResponse> {
    let mut jwks_endpoint = self.token_api.clone();
    jwks_endpoint
      .path_segments_mut()
      .map_err(|_| ValidationError::JwksUrlError)?
      .push(path);

    let jwks_res = self.jwks_http_client.fetch_jwks::<JwksResponse>(&jwks_endpoint).await?;

    if jwks_res.keys.is_empty() {
      bail!(ValidationError::EmptyJwks)
    }
    Ok(jwks_res)
  }
}

/* ------------------------------------------------------------------------ */
/// Extract key id from id token header (jwt)
fn key_id_in_id_token(id_token: &str) -> Option<KeyId> {
  let header = id_token.split('.').next()?;
  let Ok(header_json_bytes) = general_purpose::URL_SAFE_NO_PAD.decode(header.as_bytes()) else {
    return None;
  };
  let Ok(header_json) = serde_json::from_slice(&header_json_bytes) as Result<serde_json::Value, _> else {
    return None;
  };
  let kid = header_json
    .get("kid")
    .and_then(|kid| kid.clone().to_string().into())
    .map(|kid| kid.trim_matches('"').to_string()); // remove unnecessary double quotes

  kid.map(KeyId)
}
