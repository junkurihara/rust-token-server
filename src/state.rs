use std::net::SocketAddr;

use crate::{
  db::table::SqliteUserTable,
  jwt::{Algorithm, JwtKeyPair},
};

pub struct CryptoState {
  pub algorithm: Algorithm,
  pub signing_key: JwtKeyPair,
}

pub struct AppState {
  pub listen_socket: SocketAddr,
  pub crypto: CryptoState,
  pub user_table: SqliteUserTable,
}
