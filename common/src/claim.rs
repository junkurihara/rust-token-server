use crate::token_fields::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct CustomClaims {
  #[serde(rename = "iss")]
  pub issuer: Issuer,
  #[serde(rename = "sub")]
  pub subscriber_id: SubscriberId,
  #[serde(rename = "aud")]
  pub audiences: Audiences,
  #[serde(rename = "iad")]
  pub is_admin: bool,
}
