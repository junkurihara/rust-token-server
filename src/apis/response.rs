use crate::jwt::{TokenInner, TokenMeta};
use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct TokensResponse {
  pub token: TokenInner,
  pub metadata: TokenMeta,
  pub message: String,
}
