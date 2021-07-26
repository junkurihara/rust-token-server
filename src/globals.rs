use crate::db::UserDB;
use crate::jwt::{Algorithm, JwtSigningKey};

pub struct Globals {
  pub user_db: UserDB,
  pub algorithm: Algorithm,
  pub signing_key: JwtSigningKey,
}

pub enum Mode {
  RUN,
  INIT,
  NONE,
}
