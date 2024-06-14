use libcommon::{TokenBody, TokenMeta};
use serde::Serialize;

#[cfg(feature = "blind-signatures")]
use libcommon::blind_sig::BlindSignature;

#[derive(Serialize, Debug, Clone)]
pub struct TokensResponse {
  pub token: TokenBody,
  pub metadata: TokenMeta,
  pub message: String,
}
#[derive(Serialize, Debug, Clone)]
pub struct MessageResponse {
  pub message: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ListUserResponse {
  pub users: Vec<ListUserResponseInner>,
  pub page: u32,
  pub total_pages: u32,
  pub total_users: u32,
  pub message: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct ListUserResponseInner {
  pub username: String,
  pub subscriber_id: String,
  pub is_admin: bool,
}

#[cfg(feature = "blind-signatures")]
#[derive(Serialize, Debug, Clone)]
pub struct BlindSignResponse {
  pub blind_signature: BlindSignature,
  pub expires_at: u64,
  pub message: String,
}
