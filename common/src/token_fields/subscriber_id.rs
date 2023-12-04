use super::{Field, TryNewField};
use anyhow::Result;
use serde::{
  de::{self, Visitor},
  Deserialize, Serialize,
};
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Validate)]
pub struct SubscriberId {
  #[validate(length(min = 1))]
  value: String,
}
impl<'a, T: Into<Cow<'a, str>>> TryNewField<T> for SubscriberId {
  fn new(sub_id: T) -> Result<Self> {
    let value = sub_id.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Field for SubscriberId {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}
impl Serialize for SubscriberId {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}
impl<'de> Deserialize<'de> for SubscriberId {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct SubscriberIdVisitor;
    impl<'de> Visitor<'de> for SubscriberIdVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("subscriber_id string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(SubscriberIdVisitor)?;

    Ok(Self { value })
  }
}
