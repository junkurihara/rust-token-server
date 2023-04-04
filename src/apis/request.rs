use serde::Deserialize;

use crate::entity::{ClientId, Password, RefreshTokenInner, Username};

#[derive(Deserialize, Debug, Clone)]
pub struct PasswordCredentialRequest {
  pub username: Username,
  pub password: Password,
}

#[derive(Deserialize, Debug, Clone)]
pub struct TokensRequest {
  pub auth: PasswordCredentialRequest,
  pub client_id: Option<ClientId>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RefreshRequest {
  pub refresh_token: RefreshTokenInner,
  pub client_id: Option<ClientId>,
}
