use crate::{
  constants::{ARGON2_CONFIG, ARGON2_SALT_LEN},
  error::*,
};
use rand::prelude::*;

pub fn generate_argon2(password: &str) -> Result<String> {
  let mut salt = [0u8; ARGON2_SALT_LEN];
  rand::thread_rng().fill_bytes(&mut salt);

  let hash = argon2::hash_encoded(password.as_bytes(), &salt, &ARGON2_CONFIG)?;

  Ok(hash)
}

pub fn verify_argon2(password: &str, encoded_hash: &str) -> Result<bool> {
  let matches = argon2::verify_encoded(encoded_hash, password.as_bytes())?;

  Ok(matches)
}

pub fn generate_random_string(length: usize) -> Result<String> {
  const BASE_STR: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let mut rng = &mut rand::thread_rng();
  let res = String::from_utf8(BASE_STR.as_bytes().choose_multiple(&mut rng, length).cloned().collect())?;
  Ok(res)
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn argon2_works() {
    let password = "password";
    let hash = generate_argon2(password);
    assert!(hash.is_ok());
    let hash = hash.unwrap();
    assert_eq!(hash.len(), 117);
    assert!(hash.starts_with("$argon2id$v=19$m=4096,t=3,p=4$"));

    let verify = verify_argon2(password, &hash);
    assert!(verify.is_ok());
    assert!(verify.unwrap());
  }
  #[test]
  fn random_string_works() {
    let length = 32;
    let random_string = generate_random_string(length);
    assert!(random_string.is_ok());
    assert_eq!(random_string.unwrap().len(), length);
  }
}
