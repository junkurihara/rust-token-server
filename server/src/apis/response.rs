use libcommon::{TokenBody, TokenMeta};
use serde::Serialize;

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
