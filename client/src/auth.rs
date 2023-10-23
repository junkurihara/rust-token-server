use crate::{
  constants::*,
  error::*,
  log::*,
  message::*,
  token::{Algorithm, TokenInner, VerificationKeyType},
  AuthenticationConfig,
};
use async_trait::async_trait;
use jwt_simple::prelude::ES256PublicKey;
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
      .map_err(|_| anyhow!("Failed to parse token api url".to_string()))?
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

    info!("Token retrieved");

    // // update validation key
    // self.update_validation_key().await?;

    // // verify id token with validation key
    // let Ok(_clm) = self.verify_id_token().await else {
    //   return Err(DapError::AuthenticationError(
    //     "Invalid Id token! Carefully check if target DNS or Token API is compromised!".to_string(),
    //   ));
    // };

    // info!("Login success!");
    Ok(())
  }

  /// Update jwks key
  async fn update_validation_key(&self) -> Result<()> {
    let id_token_lock = self.id_token.read().await;
    let Some(id_token) = id_token_lock.as_ref() else {
      bail!("No id token");
    };
    let meta = id_token.decode_id_token().await?;
    drop(id_token_lock);

    let key_id = meta.key_id().ok_or_else(|| anyhow!("No key id in token"))?;

    let mut jwks_endpoint = self.config.token_api.clone();
    jwks_endpoint
      .path_segments_mut()
      .map_err(|_| anyhow!("Failed to parse token api url".to_string()))?
      .push(ENDPOINT_JWKS_PATH);

    let client_lock = self.http_client.read().await;
    let jwks_res = client_lock.get_json::<JwksResponse>(&jwks_endpoint).await?;
    drop(client_lock);

    let matched_key = jwks_res.keys.iter().find(|x| {
      let kid = x["kid"].as_str().unwrap_or("");
      kid == key_id
    });
    if matched_key.is_none() {
      bail!(
        "No JWK matched to Id token is given at jwks endpoint! key_id: {}",
        key_id
      );
    }

    let mut matched = matched_key.unwrap().clone();
    let Some(matched_jwk) = matched.as_object_mut() else {
      bail!("Invalid jwk retrieved from jwks endpoint");
    };
    matched_jwk.remove_entry("kid");
    let Ok(jwk_string) = serde_json::to_string(matched_jwk) else {
      bail!("Failed to serialize jwk");
    };
    debug!("Matched JWK given at jwks endpoint is {}", &jwk_string);

    let verification_key = match Algorithm::from_str(meta.algorithm())? {
      Algorithm::ES256 => {
        let pk = p256::PublicKey::from_jwk_str(&jwk_string)?;
        let sec1key = pk.to_encoded_point(false);
        VerificationKeyType::ES256(ES256PublicKey::from_bytes(sec1key.as_bytes())?)
      }
    };

    let mut validation_key_lock = self.validation_key.write().await;
    validation_key_lock.replace(verification_key);
    drop(validation_key_lock);

    info!("validation key updated");

    Ok(())
  }

  // /// Verify id token
  // async fn verify_id_token(&self) -> Result<JWTClaims<NoCustomClaims>> {
  //   let vk_lock = self.validation_key.read().await;
  //   let Some(vk) = vk_lock.as_ref() else {
  //     return Err(DapError::AuthenticationError("No validation key".to_string()));
  //   };
  //   let verification_key = vk.to_owned();
  //   drop(vk_lock);

  //   let token_lock = self.id_token.read().await;
  //   let Some(token_inner) = token_lock.as_ref() else {
  //     return Err(DapError::AuthenticationError("No id token".to_string()));
  //   };
  //   let token = token_inner.clone();
  //   drop(token_lock);

  //   token.verify_id_token(&verification_key, &self.config).await
  // }
}

#[cfg(test)]
mod tests {
  use super::*;
  use reqwest::Client;
  use serde::de::DeserializeOwned;
  struct MockHttpClient {
    inner: Client,
  }
  #[async_trait]
  impl TokenHttpClient for MockHttpClient {
    async fn post_json<S, R>(&self, url: &Url, json_body: &S) -> Result<R>
    where
      S: Serialize + Send + Sync,
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.post(url.to_owned()).json(json_body).send().await?;
      let json_res = res.json::<R>().await?;

      Ok(json_res)
    }
    async fn get_json<R>(&self, url: &Url) -> Result<R>
    where
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.get(url.to_owned()).send().await?;
      let json_res = res.json::<R>().await?;

      Ok(json_res)
    }
  }

  #[tokio::test]
  async fn token_api() {
    let http_client = MockHttpClient { inner: Client::new() };
    let url = "http://localhost:8000/v1.0/tokens".parse::<Url>().unwrap();
    let json_body = AuthenticationRequest {
      auth: AuthenticationReqInner {
        username: "admin".to_string(),
        password: std::env::var("ADMIN_PASSWORD").unwrap(),
      },
      client_id: std::env::var("CLIENT_ID").unwrap(),
    };
    let res: AuthenticationResponse = http_client.post_json(&url, &json_body).await.unwrap();
    println!("{:?}", res);
  }
}
