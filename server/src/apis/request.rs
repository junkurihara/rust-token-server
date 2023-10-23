use serde::Deserialize;

use crate::entity::{ClientId, Password, RefreshTokenInner, Username};

#[derive(Deserialize, Debug, Clone)]
pub struct PasswordCredentialRequest {
  pub username: Username,
  pub password: Password,
}
#[derive(Deserialize, Debug, Clone)]
pub struct PasswordCredentialOptionalRequest {
  pub username: Option<Username>,
  pub password: Option<Password>,
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

#[derive(Deserialize, Debug, Clone)]
pub struct CreateUserRequest {
  pub auth: PasswordCredentialRequest,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpdateUserRequest {
  pub auth: PasswordCredentialOptionalRequest,
}
