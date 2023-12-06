use crate::{
  entity::User,
  error::*,
  table::{SqliteRefreshTokenTable, SqliteUserTable},
};
use libcommon::{
  token_fields::{Audiences, ClientId, IdToken, Issuer},
  Claims, SigningKey, TokenBody, TokenMeta, ValidationOptions,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Token generated at server as a response to login request
pub struct Token {
  pub body: TokenBody,
  pub meta: TokenMeta,
}

pub struct CryptoState {
  pub signing_key: SigningKey,
  pub issuer: Issuer,
  pub audiences: Option<Audiences>,
}

impl CryptoState {
  pub fn generate_token(&self, user: &User, client_id: &ClientId, refresh_required: bool) -> Result<Token> {
    let body = self.signing_key.authorize(
      &user.subscriber_id,
      client_id,
      &self.issuer,
      user.is_admin(),
      refresh_required,
    )?;
    let meta = TokenMeta {
      username: user.username().to_string(),
      is_admin: user.is_admin(),
    };

    Ok(Token { body, meta })
  }
  pub fn verify_token(&self, id_token: &IdToken) -> Result<Claims> {
    let mut iss = std::collections::HashSet::new();
    iss.insert(self.issuer.clone());

    let vo = ValidationOptions {
      allowed_audiences: self.audiences.clone(),
      allowed_issuers: Some(iss),
      ..Default::default()
    };

    self.signing_key.validate(id_token, &vo)
  }
}
pub struct TableState {
  pub user: SqliteUserTable,
  pub refresh_token: SqliteRefreshTokenTable,
}

pub struct AppState {
  pub listen_socket: SocketAddr,
  pub crypto: CryptoState,
  pub table: TableState,
}

// client ids = audiences テーブルは持つのをやめた。テーブルに格納する意味はあんまりなさそう。
