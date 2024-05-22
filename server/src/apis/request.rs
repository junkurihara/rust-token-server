use crate::entity::{Password, Username};
use serde::Deserialize;

use libcommon::token_fields::{ClientId, RefreshToken};

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
  pub refresh_token: RefreshToken,
  pub client_id: Option<ClientId>,
}

#[derive(Deserialize, Debug, Clone)]
pub struct CreateUserRequest {
  pub auth: PasswordCredentialRequest,
}

#[derive(Deserialize, Debug, Clone)]
pub struct DeleteUserRequest {
  pub username: Username,
}

#[derive(Deserialize, Debug, Clone)]
pub struct UpdateUserRequest {
  pub auth: PasswordCredentialOptionalRequest,
}
