use super::{Field, TryNewField};
use anyhow::Result;
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
impl<'a, T: Into<Cow<'a, str>>> TryNewField<T> for Username {
  fn new(username: T) -> Result<Self> {
    let value = username.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Field for Username {
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

#[derive(Debug, Clone)]
pub struct IsAdmin {
  value: bool,
}
impl TryNewField<bool> for IsAdmin {
  fn new(is_admin: bool) -> Result<Self> {
    let object = Self { value: is_admin };
    Ok(object)
  }
}
impl IsAdmin {
  pub fn into_string(self) -> String {
    self.value.to_string()
  }
  pub fn get(&self) -> bool {
    self.value
  }
}
impl Serialize for IsAdmin {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bool(self.get())
  }
}
impl<'de> Deserialize<'de> for IsAdmin {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct IsAdminVisitor;
    impl<'de> Visitor<'de> for IsAdminVisitor {
      type Value = bool;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("is_admin bool")
      }
      fn visit_bool<E>(self, v: bool) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(v)
      }
    }

    let value = deserializer.deserialize_bool(IsAdminVisitor)?;

    Ok(Self { value })
  }
}
