use std::net::SocketAddr;

use jwt_simple::prelude::JWTClaims;

use crate::{
  entity::User,
  error::*,
  jwt::{AdditionalClaimData, Algorithm, Audiences, ClientId, Issuer, JwtKeyPair, Token},
  table::SqliteUserTable,
};

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
  pub fn verify_token(&self, token: &str) -> Result<JWTClaims<AdditionalClaimData>> {
    self.keypair.verify_token(token, &self.issuer, &self.audiences)
  }
}

pub struct AppState {
  pub listen_socket: SocketAddr,
  pub crypto: CryptoState,
  pub user_table: SqliteUserTable,
}

// TODO: add token table

// client ids = audiences テーブルは持つのをやめた。テーブルに格納する意味はあんまりなさそう。
