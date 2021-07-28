use crate::db::UserDB;
use crate::jwt::{Algorithm, JwtSigningKey};

pub struct Globals {
  pub user_db: UserDB,
  pub algorithm: Algorithm,
  pub signing_key: JwtSigningKey,
  pub allowed_client_ids: Option<Vec<String>>,
  pub token_issuer: String,
}

pub enum Mode {
  RUN,
  INIT,
  NONE,
}
