use super::{Entity, TryNewEntity};
use crate::error::*;
use serde::Serialize;
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Validate)]
pub struct SubscriberId {
  #[validate(length(min = 1))]
  value: String,
}
impl<'a, T: Into<Cow<'a, str>>> TryNewEntity<T> for SubscriberId {
  fn new(sub_id: T) -> Result<Self> {
    let value = sub_id.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Entity for SubscriberId {
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
