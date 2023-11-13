mod constants;
mod error;
mod log;
mod validation_key;
mod validator;

use url::Url;

pub use validator::{JwksHttpClient, TokenValidator};
pub mod reexports {
  pub use jwt_simple::prelude::{JWTClaims, NoCustomClaims};
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
  use tokio::sync::RwLock;

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

  #[tokio::test]
  async fn jwks_apis_works_validation_success() -> Result<()> {
    let http_client = MockHttpClient { inner: Client::new() };

    let token_api = std::env::var("TOKEN_ENDPOINT").unwrap().parse::<Url>().unwrap();
    let config = ValidationConfig {
      inner: vec![ValidationConfigInner {
        token_api: token_api.clone(),
        token_issuer: std::env::var("TOKEN_ISSUER").unwrap().parse::<Url>().unwrap(),
        client_ids: vec![std::env::var("CLIENT_ID").unwrap()],
      }],
    };
    let token_validator = TokenValidator::try_new(&config, Arc::new(RwLock::new(http_client))).await?;

    let id_token_path = std::env::var("ID_TOKEN_ENV").unwrap();
    let id_token = std::fs::read_to_string(id_token_path)?.trim().to_string();
    debug!("id_token: {}", id_token);
    let res = token_validator.validate(&id_token).await;
    debug!("decoded claims: {:#?}", res);
    assert!(res.is_ok());

    Ok(())
  }
}
