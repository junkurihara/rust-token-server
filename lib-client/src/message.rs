use libcommon::{TokenBody, TokenMeta};
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

/// Create user request
#[derive(Serialize, Debug)]
pub(super) struct CreateUserRequest {
  pub auth: CreateUserReqInner,
}
#[derive(Serialize, Debug)]
/// Create user request inner

pub(super) struct CreateUserReqInner {
  pub username: String,
  pub password: String,
}

/// Delete user request
#[derive(Serialize, Debug)]
pub struct DeleteUserRequest {
  pub username: String,
}

#[derive(Deserialize, Debug)]
/// Create/delete user response
pub(super) struct MessageResponse {
  pub message: String,
}

#[cfg(feature = "blind-signatures")]
/// Sign request for blind signatures
#[derive(Serialize, Debug)]
pub(super) struct BlindSignRequest {
  pub blinded_token: libcommon::blind_sig::BlindedToken,
}

#[cfg(feature = "blind-signatures")]
/// Sign response for blind signatures
#[derive(Deserialize, Debug)]
pub(super) struct BlindSignResponse {
  pub blind_signature: libcommon::blind_sig::BlindSignature,
  pub expires_at: u64,
  #[allow(dead_code)]
  pub message: String,
}
