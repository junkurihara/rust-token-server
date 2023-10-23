mod auth;
mod constants;
mod error;
mod log;
mod message;
mod token;

pub use auth::{TokenClient, TokenHttpClient};
use url::Url;

#[derive(PartialEq, Eq, Debug, Clone)]
pub struct AuthenticationConfig {
  pub username: String,
  pub password: String,
  pub client_id: String,
  pub token_api: Url,
}
