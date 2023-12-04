use crate::{
  entity::{Audiences, ClientId, IdToken, Issuer, User},
  error::*,
  jwt::{AdditionalClaimData, Algorithm, JwtKeyPair, Token},
  table::{SqliteRefreshTokenTable, SqliteUserTable},
};
use jwt_simple::prelude::JWTClaims;
use std::net::SocketAddr;
// use libcommon::Claims;

pub struct CryptoState {
  pub algorithm: Algorithm,
  pub keypair: JwtKeyPair,
  pub issuer: Issuer,
  pub audiences: Option<Audiences>,
}

impl CryptoState {
  pub fn generate_token(&self, user: &User, client_id: &ClientId, refresh_required: bool) -> Result<Token> {
    self
      .keypair
      .generate_token(user, client_id, &self.issuer, refresh_required)
  }
  pub fn verify_token(&self, id_token: &IdToken) -> Result<JWTClaims<AdditionalClaimData>> {
    self.keypair.verify_token(id_token, &self.issuer, &self.audiences)
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
