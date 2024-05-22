mod auth;
mod constants;
mod error;
mod log;
mod message;
// mod token;

use url::Url;

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
    async fn post_json<S, R>(&self, url: &Url, json_body: &S) -> Result<R>
    where
      S: Serialize + Send + Sync,
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.post(url.to_owned()).json(json_body).send().await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        bail!(AuthError::TokenHttpClientError {
          source: Box::new(err_res.unwrap_err())
        });
      }
      let json_res = res.json::<R>().await?;
      Ok(json_res)
    }
    async fn get_json<R>(&self, url: &Url) -> Result<R>
    where
      R: DeserializeOwned + Send + Sync,
    {
      let res = self.inner.get(url.to_owned()).send().await?;
      if !res.status().is_success() {
        let err_res = res.error_for_status_ref();
        bail!(AuthError::TokenHttpClientError {
          source: Box::new(err_res.unwrap_err())
        });
      }
      let json_res = res.json::<R>().await?;

      Ok(json_res)
    }
  }

  #[async_trait]
  impl AdminTokenHttpClient for MockHttpClient {
    async fn post_json_admin<S, R>(&self, url: &Url, json_body: &S, token: &TokenBody) -> Result<R>
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
        bail!(AuthError::TokenHttpClientError {
          source: Box::new(err_res.unwrap_err())
        });
      }
      let json_res = res.json::<R>().await?;
      Ok(json_res)
    }
  }

  #[tokio::test]
  async fn token_apis_works() {
    let http_client = MockHttpClient { inner: Client::new() };

    let token_api = std::env::var("TOKEN_ENDPOINT").unwrap().parse::<Url>().unwrap();
    let auth_config = AuthenticationConfig {
      token_api,
      client_id: std::env::var("CLIENT_ID").unwrap(),
      username: std::env::var("ADMIN_NAME").unwrap(),
      password: std::env::var("ADMIN_PASSWORD").unwrap(),
    };
    let token_client = TokenClient::new(&auth_config, Arc::new(RwLock::new(http_client)))
      .await
      .unwrap();

    token_client.login().await.unwrap();
    assert!(token_client.token().await.is_ok());

    token_client.refresh().await.unwrap();
    assert!(token_client.token().await.is_ok());
  }

  #[tokio::test]
  async fn check_expiration() {
    let http_client = MockHttpClient { inner: Client::new() };

    let token_api = std::env::var("TOKEN_ENDPOINT").unwrap().parse::<Url>().unwrap();
    let auth_config = AuthenticationConfig {
      token_api,
      client_id: std::env::var("CLIENT_ID").unwrap(),
      username: std::env::var("ADMIN_NAME").unwrap(),
      password: std::env::var("ADMIN_PASSWORD").unwrap(),
    };
    let token_client = TokenClient::new(&auth_config, Arc::new(RwLock::new(http_client)))
      .await
      .unwrap();

    token_client.login().await.unwrap();
    assert!(token_client.token().await.is_ok());

    let remaining = token_client.remaining_seconds_until_expiration().await.unwrap();
    assert!(remaining > 0);
  }

  #[tokio::test]
  async fn create_delete_user_api_works() {
    let http_client = MockHttpClient { inner: Client::new() };

    let token_api = std::env::var("TOKEN_ENDPOINT").unwrap().parse::<Url>().unwrap();
    let auth_config = AuthenticationConfig {
      token_api,
      client_id: std::env::var("CLIENT_ID").unwrap(),
      username: std::env::var("ADMIN_NAME").unwrap(),
      password: std::env::var("ADMIN_PASSWORD").unwrap(),
    };
    let token_client = TokenClient::new(&auth_config, Arc::new(RwLock::new(http_client)))
      .await
      .unwrap();

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
}
