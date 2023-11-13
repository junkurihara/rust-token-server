use super::{error::*, log::*, validation_key::ValidationKey, ValidationConfig};
use crate::constants::ENDPOINT_JWKS_PATH;
use async_trait::async_trait;
use futures::future::join_all;
use jwt_simple::prelude::{JWTClaims, NoCustomClaims, VerificationOptions};
use serde::{de::DeserializeOwned, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

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

/// Inner state of the validator
pub struct TokenValidatorInner<H>
where
  H: JwksHttpClient,
{
  /// Token API endpoint
  pub(crate) token_api: url::Url,
  /// Validation key retrieved from the server
  pub(crate) validation_keys: Arc<RwLock<Option<Vec<ValidationKey>>>>,
  /// Validation options
  pub(crate) validation_options: VerificationOptions,
  /// http client to fetch jwks
  jwks_http_client: Arc<RwLock<H>>,
}

impl<H> TokenValidator<H>
where
  H: JwksHttpClient,
{
  pub async fn try_new(config: &ValidationConfig, http_client: Arc<RwLock<H>>) -> Result<Self> {
    let inner = config
      .inner
      .iter()
      .map(|each| {
        let token_api = each.token_api.clone();

        let validation_keys = Arc::new(RwLock::new(None));

        let mut iss = std::collections::HashSet::new();
        iss.insert(each.token_issuer.as_str().to_string());
        let mut aud = std::collections::HashSet::new();
        aud.extend(each.client_ids.iter().map(|s| s.to_string()));
        let validation_options = VerificationOptions {
          allowed_issuers: Some(iss),
          allowed_audiences: Some(aud),
          ..Default::default()
        };

        TokenValidatorInner {
          token_api,
          validation_keys,
          validation_options,
          jwks_http_client: http_client.clone(),
        }
      })
      .collect::<Vec<_>>();
    let validator = Self { inner: Arc::new(inner) };
    validator.refetch_all_jwks().await?;

    Ok(validator)
  }

  /// Validate an id token. Return Ok(()) if validation is successful with any one of validation keys.
  pub async fn validate(&self, id_token: &str) -> Result<Vec<JWTClaims<NoCustomClaims>>> {
    let futures = self.inner.iter().map(|each| async move {
      let validation_keys = each.validation_keys.read().await;
      if let Some(validation_keys) = validation_keys.as_ref() {
        let res = validation_keys
          .iter()
          .map(|vk| vk.validate(id_token, Some(&each.validation_options)))
          .filter_map(|res| {
            if res.as_ref().is_err() {
              debug!("Failed to validate id token: {}", res.as_ref().err().unwrap());
            }
            res.ok()
          })
          .collect::<Vec<_>>();
        return Ok(res);
      }
      Err(ValidationError::ValidationFailed)
    });

    let results = join_all(futures)
      .await
      .into_iter()
      .filter_map(|res| res.ok())
      .flatten()
      .collect::<Vec<_>>();

    if results.is_empty() {
      debug!("Empty validation results");
      bail!(ValidationError::ValidationFailed);
    }
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
}

impl<H> TokenValidatorInner<H>
where
  H: JwksHttpClient,
{
  /// refetch jwks from the server
  async fn refetch_jwks(&self) -> Result<()> {
    debug!("refetch jwks: {}/{}", self.token_api, ENDPOINT_JWKS_PATH);
    let mut jwks_endpoint = self.token_api.clone();
    jwks_endpoint
      .path_segments_mut()
      .map_err(|_| ValidationError::JwksUrlError)?
      .push(ENDPOINT_JWKS_PATH);

    let client = self.jwks_http_client.read().await;
    let jwks_res = client.fetch_jwks::<JwksResponse>(&jwks_endpoint).await?;
    drop(client);

    if jwks_res.keys.is_empty() {
      bail!(ValidationError::EmptyJwks)
    }

    let vks = jwks_res
      .keys
      .iter()
      .map(ValidationKey::from_jwk)
      .collect::<Result<Vec<_>>>()?;

    let mut validation_key_lock = self.validation_keys.write().await;
    validation_key_lock.replace(vks);
    drop(validation_key_lock);

    info!(
      "validation key updated from jwks endpoint: {}/{}",
      self.token_api.as_str(),
      ENDPOINT_JWKS_PATH
    );

    Ok(())
  }
}
