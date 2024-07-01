use crate::{constants::*, error::*, log::*, message::*, AuthenticationConfig};
use async_trait::async_trait;
use chrono::Local;
use libcommon::{
  token_fields::{Field, RefreshToken},
  Claims, TokenBody, ValidationKey,
};
use serde::{de::DeserializeOwned, Serialize};
use std::{
  marker::{Send, Sync},
  sync::Arc,
};
use tokio::sync::RwLock;
use url::Url;

#[cfg(feature = "blind-signatures")]
use libcommon::blind_sig::*;

/// Trait defining http client for post and get
#[async_trait]
pub trait TokenHttpClient {
  /// Send POST request with JSON body and get JSON response
  async fn post_json<S, R>(&self, url: &Url, json_body: &S) -> AuthResult<R>
  where
    S: Serialize + Send + Sync,
    R: DeserializeOwned + Send + Sync;
  /// Send GET request and get JSON response
  async fn get_json<R>(&self, url: &Url) -> AuthResult<R>
  where
    R: DeserializeOwned + Send + Sync;

  #[cfg(feature = "blind-signatures")]
  async fn post_json_with_bearer_token<S, R>(&self, url: &Url, json_body: &S, bearer_token: &str) -> AuthResult<R>
  where
    S: Serialize + Send + Sync,
    R: DeserializeOwned + Send + Sync;
}

/// Trait defining http client for post and get with id token header as admin
#[async_trait]
pub trait AdminTokenHttpClient: TokenHttpClient {
  /// Send POST request with JSON body and get JSON response using admin id token
  async fn post_json_admin<S, R>(&self, url: &Url, json_body: &S, token: &TokenBody) -> AuthResult<R>
  where
    S: Serialize + Send + Sync,
    R: DeserializeOwned + Send + Sync;
}

/// Token client
pub struct TokenClient<H>
where
  H: TokenHttpClient,
{
  pub(super) config: AuthenticationConfig,
  pub(super) http_client: Arc<RwLock<H>>,
  pub(super) id_token: Arc<RwLock<Option<TokenBody>>>,
  refresh_token: Arc<RwLock<Option<RefreshToken>>>,
  validation_key: Arc<RwLock<Option<ValidationKey>>>,

  #[cfg(feature = "blind-signatures")]
  pub(super) anonymous_token: Arc<RwLock<Option<AnonymousToken>>>,
  #[cfg(feature = "blind-signatures")]
  pub(super) blind_validation_key: Arc<RwLock<Option<RsaPublicKey>>>,
  #[cfg(feature = "blind-signatures")]
  pub(super) blind_expires_at: Arc<RwLock<Option<u64>>>,
}

impl<H> TokenClient<H>
where
  H: TokenHttpClient,
{
  /// Build authenticator
  pub async fn new(auth_config: &AuthenticationConfig, http_client: Arc<RwLock<H>>) -> AuthResult<Self> {
    Ok(Self {
      config: auth_config.clone(),
      http_client,
      id_token: Arc::new(RwLock::new(None)),
      refresh_token: Arc::new(RwLock::new(None)),
      validation_key: Arc::new(RwLock::new(None)),

      #[cfg(feature = "blind-signatures")]
      anonymous_token: Arc::new(RwLock::new(None)),
      #[cfg(feature = "blind-signatures")]
      blind_validation_key: Arc::new(RwLock::new(None)),
      #[cfg(feature = "blind-signatures")]
      blind_expires_at: Arc::new(RwLock::new(None)),
    })
  }

  /// Login to the authentication server
  pub async fn login(&self) -> AuthResult<()> {
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
    let _clm = self.verify_id_token().await?;

    info!("Login success!");
    Ok(())
  }

  /// refresh id token using refresh token. fails if refresh token is expired (not explicitly specified in token)
  pub async fn refresh(&self) -> AuthResult<()> {
    let refresh_token_lock = self.refresh_token.read().await;
    let Some(refresh_token) = refresh_token_lock.as_ref() else {
      return Err(AuthError::NoRefreshToken);
    };
    let refresh_token = refresh_token.clone();
    drop(refresh_token_lock);

    let mut refresh_endpoint = self.config.token_api.clone();
    refresh_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_REFRESH_PATH);

    let json_request = RefreshRequest {
      refresh_token: refresh_token.into_string(),
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
    let _clm = self.verify_id_token().await?;

    info!("Refresh success!");
    Ok(())
  }

  /// Update jwks key
  async fn update_validation_key(&self) -> AuthResult<()> {
    let id_token_lock = self.id_token.read().await;
    let Some(id_token) = id_token_lock.as_ref() else {
      return Err(AuthError::NoIdToken);
    };
    let meta = id_token.decode_id_token().map_err(AuthError::FailedToDecodeIdToken)?;
    let key_id = meta.header().key_id.clone().ok_or_else(|| AuthError::NoKeyIdInIdToken)?;
    drop(id_token_lock);

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
      return Err(AuthError::NoJwkMatched { kid: key_id.to_string() });
    }

    let mut matched = matched_key.unwrap().clone();
    let Some(matched_jwk) = matched.as_object_mut() else {
      return Err(AuthError::InvalidJwk);
    };
    matched_jwk.remove_entry("kid");
    let Ok(jwk_string) = serde_json::to_string(matched_jwk) else {
      return Err(AuthError::FailedToSerializeJwk);
    };
    debug!("Matched JWK given at jwks endpoint is {}", &jwk_string);

    let jwk_value = serde_json::to_value(matched_jwk)?;
    let validation_key = ValidationKey::from_jwk(&jwk_value).map_err(AuthError::FailedToParseJwk)?;

    let mut validation_key_lock = self.validation_key.write().await;
    validation_key_lock.replace(validation_key);
    drop(validation_key_lock);

    info!("validation key updated");

    Ok(())
  }

  /// Verify id token
  async fn verify_id_token(&self) -> AuthResult<Claims> {
    let token_lock = self.id_token.read().await;
    let Some(token_inner) = token_lock.as_ref() else {
      return Err(AuthError::NoIdToken);
    };
    let token = token_inner.clone();
    drop(token_lock);

    let vk_lock = self.validation_key.read().await;
    let Some(vk) = vk_lock.as_ref() else {
      return Err(AuthError::NoValidationKey);
    };
    let validation_key = vk.to_owned();
    // drop(vk_lock);

    token
      .verify_id_token(validation_key, &self.config.client_id, self.config.token_api.as_str())
      .await
      .map_err(|_| AuthError::InvalidIdToken)
  }

  /// Remaining seconds until expiration of id token
  pub async fn remaining_seconds_until_expiration(&self) -> AuthResult<i64> {
    // These return unix time in secs
    let clm = self.verify_id_token().await?;
    let expires_at = clm.expiration.map(|v| v.timestamp()).ok_or(AuthError::NoExpInIdToken)?;

    let current = Local::now().timestamp();

    Ok(expires_at - current)
  }

  /// Get id and refresh tokens with some meta data
  pub async fn token(&self) -> AuthResult<TokenBody> {
    let token_lock = self.id_token.read().await;
    let Some(token) = token_lock.as_ref() else {
      return Err(AuthError::NoIdToken);
    };
    let token = token.clone();
    drop(token_lock);

    Ok(token)
  }

  /// Check if myself is admin
  pub async fn is_admin(&self) -> AuthResult<bool> {
    let clm = self.verify_id_token().await?;
    let is_admin = clm.custom.get("iad").and_then(|v| v.as_bool()).unwrap_or(false);
    Ok(is_admin)
  }
}

/* ---------------------------------------------------- */
/// Token client with admin privilege
impl<H> TokenClient<H>
where
  H: AdminTokenHttpClient,
{
  /// Create a user under the admin privilege
  pub async fn create_user(&self, username: &str, password: &str) -> AuthResult<String> {
    let is_admin = self.is_admin().await?;
    if !is_admin {
      return Err(AuthError::NotAllowed);
    }

    let mut create_endpoint = self.config.token_api.clone();
    create_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_CREATE_USER_PATH);

    let json_request = CreateUserRequest {
      auth: CreateUserReqInner {
        username: username.to_string(),
        password: password.to_string(),
      },
    };
    let token_body = self.token().await?;

    let client_lock = self.http_client.read().await;
    let _res = client_lock
      .post_json_admin::<_, MessageResponse>(&create_endpoint, &json_request, &token_body)
      .await?;
    drop(client_lock);

    Ok(_res.message)
  }

  /// Delete a user under the admin privilege
  pub async fn delete_user(&self, username: &str) -> AuthResult<String> {
    let is_admin = self.is_admin().await?;
    if !is_admin {
      return Err(AuthError::NotAllowed);
    }

    let mut delete_endpoint = self.config.token_api.clone();
    delete_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_DELETE_USER_PATH);

    let json_request = DeleteUserRequest {
      username: username.to_string(),
    };
    let token_body = self.token().await?;

    let client_lock = self.http_client.read().await;
    let _res = client_lock
      .post_json_admin::<_, MessageResponse>(&delete_endpoint, &json_request, &token_body)
      .await?;
    drop(client_lock);

    Ok(_res.message)
  }
}
