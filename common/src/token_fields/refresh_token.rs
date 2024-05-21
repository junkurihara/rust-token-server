use super::{Field, TryNewField};
use crate::constants::REFRESH_TOKEN_LEN;
use anyhow::Result;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{
  de::{self, Visitor},
  Deserialize, Serialize,
};
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Eq, PartialEq, Validate)]
pub struct RefreshToken {
  #[validate(length(equal = "REFRESH_TOKEN_LEN"))]
  value: String,
}
impl<'a, T> TryNewField<T> for RefreshToken
where
  T: Into<Cow<'a, str>>,
{
  fn new(value: T) -> Result<Self> {
    let value = value.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Field for RefreshToken {
  // impl Entity for RefreshTokenInner {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}
impl RefreshToken {
  pub fn generate() -> Result<Self> {
    let value: String = thread_rng()
      .sample_iter(&Alphanumeric)
      .take(REFRESH_TOKEN_LEN as usize)
      .map(char::from)
      .collect();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Serialize for RefreshToken {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

impl<'de> Deserialize<'de> for RefreshToken {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct RefreshTokenVisitor;
    impl<'de> Visitor<'de> for RefreshTokenVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("refresh token string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(RefreshTokenVisitor)?;

    Ok(Self { value })
  }
}
