use crate::constants::{ARGON2_CONFIG, ARGON2_SALT_LEN};
use crate::error::*;
use argon2;
use rand::prelude::*;

pub fn generate_argon2(password: &str) -> Result<String, Error> {
  let mut salt = [0u8; ARGON2_SALT_LEN];
  rand::thread_rng().fill_bytes(&mut salt);

  let hash = argon2::hash_encoded(password.as_bytes(), &salt, &ARGON2_CONFIG)?;

  Ok(hash)
}

pub fn verify_argon2(password: &str, encoded_hash: &str) -> Result<bool, Error> {
  let matches = argon2::verify_encoded(encoded_hash, password.as_bytes())?;

  Ok(matches)
}
