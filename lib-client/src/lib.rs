mod auth;
mod constants;
mod error;
mod log;
mod message;

#[cfg(feature = "blind-signatures")]
mod auth_blind;

use url::Url;

pub use crate::error::AuthError;
pub use auth::{AdminTokenHttpClient, TokenClient, TokenHttpClient};
pub mod token {
  pub use libcommon::*;
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct AuthenticationConfig {
  pub username: String,
  pub password: String,
  pub client_id: String,
  pub token_api: Url,
}

/* -------------------------------------------- */
#[cfg(feature = "reqwest")]
#[cfg(test)]
mod tests {
  use super::*;
  use crate::error::*;
  use async_trait::async_trait;
  use libcommon::{token_fields::Field, TokenBody};
  use reqwest::Client;
  use serde::{de::DeserializeOwned, Serialize};
  use std::sync::Arc;
  use tokio::sync::RwLock;

  struct MockHttpClient {
    inner: Client,
  }
  #[async_trait]
  impl TokenHttpClient for MockHttpClient {
    async fn post_json<S, R>(&self, url: &Url, json_body: &S) -> AuthResult<R>
    where
      S: Serialize + Send + Sync,
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.post(url.to_owned()).json(json_body).send().await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        return Err(AuthError::TokenHttpClientErrorResponse {
          source: Box::new(err_res.unwrap_err()),
          code: res.status().as_u16(),
        });
      }
      let json_res = res.json::<R>().await?;
      Ok(json_res)
    }
    async fn get_json<R>(&self, url: &Url) -> AuthResult<R>
    where
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.get(url.to_owned()).send().await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        return Err(AuthError::TokenHttpClientErrorResponse {
          source: Box::new(err_res.unwrap_err()),
          code: res.status().as_u16(),
        });
      }
      let json_res = res.json::<R>().await?;

      Ok(json_res)
    }
    #[cfg(feature = "blind-signatures")]
    async fn post_json_with_bearer_token<S, R>(&self, url: &Url, json_body: &S, bearer_token: &str) -> AuthResult<R>
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
        return Err(AuthError::TokenHttpClientErrorResponse {
          source: Box::new(err_res.unwrap_err()),
          code: res.status().as_u16(),
        });
      }
      let json_res = res.json::<R>().await?;
      Ok(json_res)
    }
  }

  #[async_trait]
  impl AdminTokenHttpClient for MockHttpClient {
    async fn post_json_admin<S, R>(&self, url: &Url, json_body: &S, token: &TokenBody) -> AuthResult<R>
    where
      S: Serialize + Send + Sync,
      R: DeserializeOwned + Send + Sync,
    {
      let authorization_header = format!("Bearer {}", token.id.as_str());

      let res = self
        .inner
        .post(url.to_owned())
        .header(reqwest::header::AUTHORIZATION, authorization_header)
        .json(json_body)
        .send()
        .await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        return Err(AuthError::TokenHttpClientErrorResponse {
          source: Box::new(err_res.unwrap_err()),
          code: res.status().as_u16(),
        });
      }
      let json_res = res.json::<R>().await?;
      Ok(json_res)
    }
  }

  /* -------------------------------------------- */
  #[tokio::test]
  async fn token_apis_works() {
    let token_client = get_token_client().await;

    token_client.login().await.unwrap();
    assert!(token_client.token().await.is_ok());

    token_client.refresh().await.unwrap();
    assert!(token_client.token().await.is_ok());
  }

  #[tokio::test]
  async fn check_expiration() {
    let token_client = get_token_client().await;

    token_client.login().await.unwrap();
    assert!(token_client.token().await.is_ok());

    let remaining = token_client.remaining_seconds_until_expiration().await.unwrap();
    assert!(remaining > 0);
  }

  #[tokio::test]
  async fn create_delete_user_api_works() {
    let token_client = get_token_client().await;

    token_client.login().await.unwrap();
    assert!(token_client.token().await.is_ok());

    let user = "test_user";
    let password = "test_password";
    let res = token_client.create_user(user, password).await;
    assert!(res.is_ok());

    let res = token_client.delete_user(user).await;
    assert!(res.is_ok());

    let res = token_client.delete_user(user).await;
    assert!(res.is_err());
  }

  #[tokio::test]
  async fn blind_sign_api_works() {
    let token_client = get_token_client().await;

    token_client.login().await.unwrap();
    assert!(token_client.token().await.is_ok());

    let res = token_client.update_blind_validation_key_if_stale().await;
    assert!(res.is_ok());

    let res = token_client.request_blind_signature_with_id_token().await;
    assert!(res.is_ok());

    let anonymous_token = token_client.anonymous_token().await;
    assert!(anonymous_token.is_ok());
    let anonymous_token = anonymous_token.unwrap();
    println!("anonymous_token: {:?}", anonymous_token.try_into_base64url().unwrap());

    let remaining = token_client.blind_remaining_seconds_until_expiration().await;
    assert!(remaining.is_ok());
    let remaining = remaining.unwrap();
    assert!(remaining > 0);
  }

  async fn get_token_client() -> TokenClient<MockHttpClient> {
    let http_client = MockHttpClient { inner: Client::new() };

    let token_api = std::env::var("TOKEN_ENDPOINT").unwrap().parse::<Url>().unwrap();
    let auth_config = AuthenticationConfig {
      token_api,
      client_id: std::env::var("CLIENT_ID").unwrap(),
      username: std::env::var("ADMIN_NAME").unwrap(),
      password: std::env::var("ADMIN_PASSWORD").unwrap(),
    };

    TokenClient::new(&auth_config, Arc::new(RwLock::new(http_client)))
      .await
      .unwrap()
  }
}
