use serde::Deserialize;

use crate::{
  entity::{Password, Username},
  error::*,
};

#[derive(Deserialize, Debug, Clone)]
pub struct PasswordCredentialRequest {
  pub username: String,
  pub password: String,
}
impl PasswordCredentialRequest {
  pub fn username(&self) -> Result<Username> {
    Username::new(&self.username)
  }
  pub fn password(&self) -> Result<Password> {
    Password::new(&self.password)
  }
}

#[derive(Deserialize, Debug, Clone)]
pub struct TokensRequest {
  pub auth: PasswordCredentialRequest,
  pub client_id: Option<String>,
}
