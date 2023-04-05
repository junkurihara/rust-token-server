use super::{Entity, TryNewEntity};
use crate::error::*;
use serde::{
  de::{self, Visitor},
  Deserialize, Serialize,
};
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Eq, PartialEq, Validate)]
pub struct Username {
  #[validate(length(min = 1))]
  value: String,
}
impl<'a, T: Into<Cow<'a, str>>> TryNewEntity<T> for Username {
  fn new(username: T) -> Result<Self> {
    let value = username.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Entity for Username {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}
impl Serialize for Username {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}
impl<'de> Deserialize<'de> for Username {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct UsernameVisitor;
    impl<'de> Visitor<'de> for UsernameVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("username string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(UsernameVisitor)?;

    Ok(Self { value })
  }
}
