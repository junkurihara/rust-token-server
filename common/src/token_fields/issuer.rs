use super::{Field, TryNewField};
use anyhow::Result;
use serde::{
  de::{self, Visitor},
  Deserialize, Serialize,
};
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Eq, PartialEq, Validate, Hash)]
pub struct Issuer {
  #[validate(length(min = 1), url)]
  value: String,
}
impl<'a, T: Into<Cow<'a, str>>> TryNewField<T> for Issuer {
  fn new(input: T) -> Result<Self> {
    let value = input.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}

impl Field for Issuer {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}
impl Serialize for Issuer {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}
impl<'de> Deserialize<'de> for Issuer {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct IssuerVisitor;
    impl<'de> Visitor<'de> for IssuerVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("issuer string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(IssuerVisitor)?;

    Ok(Self { value })
  }
}
