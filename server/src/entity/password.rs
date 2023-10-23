use super::{EncodedHash, Entity, TryNewEntity};
use crate::{argon2::*, error::*};
use serde::{
  de::{self, Visitor},
  Deserialize,
};
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Validate)]
pub struct Password {
  #[validate(length(min = 1))]
  value: String,
}
impl<'a, T: Into<Cow<'a, str>>> TryNewEntity<T> for Password {
  fn new(password: T) -> Result<Self> {
    let value = password.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Entity for Password {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}
impl Password {
  pub fn hash(&self) -> Result<String> {
    generate_argon2(self.as_str())
  }
  pub fn verify(&self, encoded_hash: &EncodedHash) -> Result<bool> {
    verify_argon2(self.as_str(), encoded_hash.as_str())
  }
}

impl<'de> Deserialize<'de> for Password {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct PasswordVisitor;
    impl<'de> Visitor<'de> for PasswordVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("password string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(PasswordVisitor)?;

    Ok(Self { value })
  }
}
