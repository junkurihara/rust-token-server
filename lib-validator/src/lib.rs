mod constants;
mod error;
mod log;
// mod validation_key;
mod validator;

use url::Url;

pub use validator::{JwksHttpClient, TokenValidator};
pub mod reexports {
  pub use libcommon::*;
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// Validation of source, typically user clients, using Id token
pub struct ValidationConfig {
  /// Allowed token information
  pub inner: Vec<ValidationConfigInner>,
}

#[derive(PartialEq, Eq, Debug, Clone)]
/// Allowed token information
pub struct ValidationConfigInner {
  /// Token api endpoint from which validation_key is automatically retrieved
  pub token_api: Url,
  /// Token issuer evaluated from iss claim
  pub token_issuer: Url,
  /// Allowed client ids evaluated from aud claim
  pub client_ids: Vec<String>,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::{error::*, log::*};
  use async_trait::async_trait;
  use reqwest::Client;
  use serde::de::DeserializeOwned;
  use std::{sync::Arc, time::Duration};

  #[cfg(feature = "blind-signatures")]
  use libclient::*;

  #[cfg(feature = "blind-signatures")]
  use serde::Serialize;

  pub const JWKS_REFETCH_TIMEOUT_SEC: u64 = 3;

  struct MockHttpClient {
    inner: Client,
  }
  #[async_trait]
  impl JwksHttpClient for MockHttpClient {
    async fn fetch_jwks<R>(&self, url: &Url) -> Result<R>
    where
      R: DeserializeOwned + Send + Sync,
    {
      let jwks_res = self
        .inner
        .get(url.clone())
        .timeout(Duration::from_secs(JWKS_REFETCH_TIMEOUT_SEC))
        .send()
        .await?;
      let jwks = jwks_res.json::<R>().await?;
      Ok(jwks)
    }
  }

  #[cfg(feature = "blind-signatures")]
  #[async_trait]
  impl TokenHttpClient for MockHttpClient {
    async fn post_json<S, R>(&self, url: &Url, json_body: &S) -> Result<R, AuthError>
    where
      S: Serialize + Send + Sync,
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.post(url.to_owned()).json(json_body).send().await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        return Err(AuthError::ReqwestClientError(err_res.unwrap_err()));
      }
      let json_res = res.json::<R>().await?;
      Ok(json_res)
    }
    async fn get_json<R>(&self, url: &Url) -> Result<R, AuthError>
    where
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.get(url.to_owned()).send().await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        return Err(AuthError::ReqwestClientError(err_res.unwrap_err()));
      }
      let json_res = res.json::<R>().await?;

      Ok(json_res)
    }
    async fn post_json_with_bearer_token<S, R>(&self, url: &Url, json_body: &S, bearer_token: &str) -> Result<R, AuthError>
    where
      S: Serialize + Send + Sync,
      R: DeserializeOwned + Send + Sync,
    {
      let authorization_header = format!("Bearer {}", bearer_token);
      let res = self
        .inner
        .post(url.to_owned())
        .header(reqwest::header::AUTHORIZATION, authorization_header)
        .json(json_body)
        .send()
        .await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        return Err(AuthError::ReqwestClientError(err_res.unwrap_err()));
      }
      let json_res = res.json::<R>().await?;
      Ok(json_res)
    }
  }

  #[tokio::test]
  async fn jwks_apis_works_validation_success() -> Result<()> {
    let token_validator = get_validator().await?;

    let id_token_path = std::env::var("ID_TOKEN_ENV").unwrap();
    let id_token = std::fs::read_to_string(id_token_path)?.trim().to_string();
    debug!("id_token: {}", id_token);
    let res = token_validator.validate(&id_token).await;
    debug!("decoded claims: {:#?}", res);
    assert!(res.is_ok());

    Ok(())
  }

  #[cfg(feature = "blind-signatures")]
  #[tokio::test]
  async fn blind_jwks_apis_works_validation_success() -> Result<()> {
    let token_validator = get_validator().await?;
    let token_client = get_token_client().await;

    token_client.login().await.unwrap();

    token_client.update_blind_validation_key_if_stale().await.unwrap();

    token_client.request_blind_signature_with_id_token().await.unwrap();
    let anonymous_token = token_client.anonymous_token().await.unwrap();

    let anonymous_token_b64u = anonymous_token.try_into_base64url();
    assert!(anonymous_token_b64u.is_ok());

    let anonymous_token_b64u = anonymous_token_b64u.unwrap();

    let res = token_validator.validate_anonymous_token(&anonymous_token_b64u).await;
    assert!(res.is_ok());

    Ok(())
  }

  async fn get_validator() -> Result<TokenValidator<MockHttpClient>> {
    let http_client = MockHttpClient { inner: Client::new() };

    let token_api = std::env::var("TOKEN_ENDPOINT").unwrap().parse::<Url>().unwrap();
    let config = ValidationConfig {
      inner: vec![ValidationConfigInner {
        token_api: token_api.clone(),
        token_issuer: std::env::var("TOKEN_ISSUER").unwrap().parse::<Url>().unwrap(),
        client_ids: vec![std::env::var("CLIENT_ID").unwrap()],
      }],
    };
    TokenValidator::try_new(&config, Arc::new(http_client)).await
  }

  #[cfg(feature = "blind-signatures")]
  async fn get_token_client() -> TokenClient<MockHttpClient> {
    let http_client = MockHttpClient { inner: Client::new() };

    let token_api = std::env::var("TOKEN_ENDPOINT").unwrap().parse::<Url>().unwrap();
    let auth_config = AuthenticationConfig {
      token_api,
      client_id: std::env::var("CLIENT_ID").unwrap(),
      username: std::env::var("ADMIN_NAME").unwrap(),
      password: std::env::var("ADMIN_PASSWORD").unwrap(),
    };

    TokenClient::new(&auth_config, Arc::new(tokio::sync::RwLock::new(http_client)))
      .await
      .unwrap()
  }
}
