use libcommon::{TokenBody, TokenMeta};
// use crate::token::{TokenInner, TokenMeta};
use serde::{Deserialize, Serialize};

/// Authentication request
#[derive(Serialize, Debug)]
pub(super) struct AuthenticationRequest {
  pub auth: AuthenticationReqInner,
  pub client_id: String,
}
#[derive(Serialize, Debug)]
/// Auth req inner
pub(super) struct AuthenticationReqInner {
  pub username: String,
  pub password: String,
}

#[allow(dead_code)]
#[derive(Deserialize, Debug)]
/// Auth response
pub(super) struct AuthenticationResponse {
  pub token: TokenBody,
  pub metadata: TokenMeta,
  pub message: String,
}

#[derive(Deserialize, Debug)]
/// Jwks response
pub(super) struct JwksResponse {
  pub keys: Vec<serde_json::Value>,
}

/// Authentication request
#[derive(Serialize, Debug)]
pub(super) struct RefreshRequest {
  pub refresh_token: String,
  pub client_id: Option<String>,
}
