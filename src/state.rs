use std::net::SocketAddr;

use crate::{
  db::table::SqliteUserTable,
  jwt::{Algorithm, JwtSigningKey},
};

pub struct CryptoState {
  pub algorithm: Algorithm,
  pub signing_key: JwtSigningKey,
}

pub struct AppState {
  pub listen_socket: SocketAddr,
  pub crypto: CryptoState,
  pub user_table: SqliteUserTable,
}
