use crate::{
  db::table::SqliteUserTable,
  jwt::{Algorithm, JwtSigningKey},
};

pub struct CryptoState {
  pub algorithm: Algorithm,
  pub signing_key: JwtSigningKey,
}

pub struct AppState {
  pub crypto: CryptoState,
  pub user_table: SqliteUserTable,
}
