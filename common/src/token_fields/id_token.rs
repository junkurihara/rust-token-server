use super::{Field, TryNewField};
use anyhow::Result;
use serde::{
  de::{self, Visitor},
  Deserialize, Serialize,
};
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Eq, PartialEq, Validate)]
pub struct IdToken {
  #[validate(length(min = 1))]
  value: String,
}
impl<'a, T> TryNewField<T> for IdToken
where
  T: Into<Cow<'a, str>>,
{
  fn new(id_token_str: T) -> Result<Self> {
    let value = id_token_str.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Field for IdToken {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}
impl Serialize for IdToken {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}
impl<'de> Deserialize<'de> for IdToken {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct IdTokenVisitor;
    impl<'de> Visitor<'de> for IdTokenVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("id_token jwt string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(IdTokenVisitor)?;

    Ok(Self { value })
  }
}
