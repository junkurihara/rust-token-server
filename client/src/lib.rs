mod auth;
mod constants;
mod error;
mod log;
mod message;
mod token;

pub use auth::{TokenClient, TokenHttpClient};
pub use token::{Algorithm, TokenInner, TokenMeta, VerificationKeyType};
use url::Url;

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

    token_client.refresh().await.unwrap();
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

    let remaining = token_client.remaining_seconds_until_expiration().await.unwrap();
    assert!(remaining > 0);
  }
}
