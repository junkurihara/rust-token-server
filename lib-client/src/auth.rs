use crate::{
  constants::*,
  error::*,
  log::*,
  message::*,
  token::{Algorithm, TokenInner, VerificationKeyType},
  AuthenticationConfig,
};
use async_trait::async_trait;
use base64::{engine::general_purpose, Engine as _};
use chrono::Local;
use jwt_simple::prelude::{ES256PublicKey, Ed25519PublicKey, JWTClaims, NoCustomClaims};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use serde::{de::DeserializeOwned, Serialize};
use std::{
  marker::{Send, Sync},
  str::FromStr,
  sync::Arc,
};
use tokio::sync::RwLock;
use url::Url;

/// Trait defining http client for post and get
#[async_trait]
pub trait TokenHttpClient {
  /// Send POST request with JSON body and get JSON response
  async fn post_json<S, R>(&self, url: &Url, json_body: &S) -> Result<R>
  where
    S: Serialize + Send + Sync,
    R: DeserializeOwned + Send + Sync;
  /// Send GET request and get JSON response
  async fn get_json<R>(&self, url: &Url) -> Result<R>
  where
    R: DeserializeOwned + Send + Sync;
}

/// Token client
pub struct TokenClient<H>
where
  H: TokenHttpClient,
{
  config: AuthenticationConfig,
  http_client: Arc<RwLock<H>>,
  id_token: Arc<RwLock<Option<TokenInner>>>,
  refresh_token: Arc<RwLock<Option<String>>>,
  validation_key: Arc<RwLock<Option<VerificationKeyType>>>,
}

impl<H> TokenClient<H>
where
  H: TokenHttpClient,
{
  /// Build authenticator
  pub async fn new(auth_config: &AuthenticationConfig, http_client: Arc<RwLock<H>>) -> Result<Self> {
    Ok(Self {
      config: auth_config.clone(),
      http_client,
      id_token: Arc::new(RwLock::new(None)),
      refresh_token: Arc::new(RwLock::new(None)),
      validation_key: Arc::new(RwLock::new(None)),
    })
  }

  /// Login to the authentication server
  pub async fn login(&self) -> Result<()> {
    let mut login_endpoint = self.config.token_api.clone();
    login_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_LOGIN_PATH);

    let json_request = AuthenticationRequest {
      auth: AuthenticationReqInner {
        username: self.config.username.clone(),
        password: self.config.password.clone(),
      },
      client_id: self.config.client_id.clone(),
    };

    let client_lock = self.http_client.read().await;
    let res_token = client_lock
      .post_json::<_, AuthenticationResponse>(&login_endpoint, &json_request)
      .await?;
    drop(client_lock);

    if let Some(refresh) = &res_token.token.refresh {
      let mut refresh_token_lock = self.refresh_token.write().await;
      refresh_token_lock.replace(refresh.clone());
      drop(refresh_token_lock);
    }

    let mut id_token_lock = self.id_token.write().await;
    id_token_lock.replace(res_token.token);
    drop(id_token_lock);

    info!("Token retrieved via login process");

    // update validation key
    self.update_validation_key().await?;

    // verify id token with validation key
    let Ok(_clm) = self.verify_id_token().await else {
      bail!(AuthError::InvalidIdToken);
    };

    info!("Login success!");
    Ok(())
  }

  /// refresh id token using refresh token. fails if refresh token is expired (not explicitly specified in token)
  pub async fn refresh(&self) -> Result<()> {
    let refresh_token_lock = self.refresh_token.read().await;
    let Some(refresh_token) = refresh_token_lock.as_ref() else {
      bail!(AuthError::NoRefreshToken);
    };
    let refresh_token = refresh_token.clone();
    drop(refresh_token_lock);

    let mut refresh_endpoint = self.config.token_api.clone();
    refresh_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_REFRESH_PATH);

    let json_request = RefreshRequest {
      refresh_token: refresh_token.clone(),
      client_id: Some(self.config.client_id.clone()),
    };

    let client_lock = self.http_client.read().await;
    let refresh_res = client_lock
      .post_json::<_, AuthenticationResponse>(&refresh_endpoint, &json_request)
      .await?;
    drop(client_lock);

    if refresh_res.token.refresh.is_some() {
      let mut refresh_token_lock = self.refresh_token.write().await;
      refresh_token_lock.replace(refresh_res.token.refresh.clone().unwrap());
      drop(refresh_token_lock);
    }

    let mut id_token_lock = self.id_token.write().await;
    id_token_lock.replace(refresh_res.token);
    drop(id_token_lock);

    debug!("Token retrieved via refresh token");

    // update validation key
    self.update_validation_key().await?;

    // verify id token with validation key
    let Ok(_clm) = self.verify_id_token().await else {
      bail!(AuthError::InvalidIdToken);
    };

    info!("Refresh success!");
    Ok(())
  }

  /// Update jwks key
  async fn update_validation_key(&self) -> Result<()> {
    let id_token_lock = self.id_token.read().await;
    let Some(id_token) = id_token_lock.as_ref() else {
      bail!(AuthError::NoIdToken);
    };
    let meta = id_token.decode_id_token().await?;
    drop(id_token_lock);

    let key_id = meta.key_id().ok_or_else(|| AuthError::NoKeyIdInIdToken)?;

    let mut jwks_endpoint = self.config.token_api.clone();
    jwks_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_JWKS_PATH);

    let client_lock = self.http_client.read().await;
    let jwks_res = client_lock.get_json::<JwksResponse>(&jwks_endpoint).await?;
    drop(client_lock);

    let matched_key = jwks_res.keys.iter().find(|x| {
      let kid = x["kid"].as_str().unwrap_or("");
      kid == key_id
    });
    if matched_key.is_none() {
      bail!(AuthError::NoJwkMatched {
        kid: key_id.to_string()
      });
    }

    let mut matched = matched_key.unwrap().clone();
    let Some(matched_jwk) = matched.as_object_mut() else {
      bail!(AuthError::InvalidJwk);
    };
    matched_jwk.remove_entry("kid");
    let Ok(jwk_string) = serde_json::to_string(matched_jwk) else {
      bail!(AuthError::FailedToSerializeJwk);
    };
    debug!("Matched JWK given at jwks endpoint is {}", &jwk_string);

    let Some(crv) = matched_jwk.get("crv") else {
      bail!(AuthError::InvalidJwk);
    };
    let crv = crv.as_str().unwrap_or("");

    let verification_key = match Algorithm::from_str(meta.algorithm())? {
      Algorithm::ES256 => {
        ensure!(crv == "P-256", AuthError::InvalidJwk);
        let pk = p256::PublicKey::from_jwk_str(&jwk_string)?;
        let sec1key = pk.to_encoded_point(false);
        VerificationKeyType::ES256(ES256PublicKey::from_bytes(sec1key.as_bytes())?)
      }
      Algorithm::Ed25519 => {
        ensure!(crv == "Ed25519", AuthError::InvalidJwk);
        let Some(x) = matched_jwk.get("x") else {
          bail!(AuthError::InvalidJwk);
        };
        let x = x.as_str().unwrap_or("");
        let x = general_purpose::URL_SAFE_NO_PAD.decode(x)?;
        VerificationKeyType::Ed25519(Ed25519PublicKey::from_bytes(x.as_slice())?)
      }
    };

    let mut validation_key_lock = self.validation_key.write().await;
    validation_key_lock.replace(verification_key);
    drop(validation_key_lock);

    info!("validation key updated");

    Ok(())
  }

  /// Verify id token
  async fn verify_id_token(&self) -> Result<JWTClaims<NoCustomClaims>> {
    let vk_lock = self.validation_key.read().await;
    let Some(vk) = vk_lock.as_ref() else {
      bail!(AuthError::NoValidationKey);
    };
    let verification_key = vk.to_owned();
    drop(vk_lock);

    let token_lock = self.id_token.read().await;
    let Some(token_inner) = token_lock.as_ref() else {
      bail!(AuthError::NoIdToken);
    };
    let token = token_inner.clone();
    drop(token_lock);

    token.verify_id_token(&verification_key, &self.config).await
  }

  /// Remaining seconds until expiration of id token
  pub async fn remaining_seconds_until_expiration(&self) -> Result<i64> {
    // These return unix time in secs
    let clm = self.verify_id_token().await?;
    let expires_at: i64 = clm.expires_at.unwrap().as_secs() as i64;
    let current = Local::now().timestamp();

    Ok(expires_at - current)
  }

  /// Get id and refresh tokens with some meta data
  pub async fn token(&self) -> Result<TokenInner> {
    let token_lock = self.id_token.read().await;
    let Some(token_inner) = token_lock.as_ref() else {
      bail!(AuthError::NoIdToken);
    };
    let token = token_inner.clone();
    drop(token_lock);

    Ok(token)
  }
}