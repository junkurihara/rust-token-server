use super::{Entity, TryNewEntity};
use crate::error::*;
use serde::Serialize;
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Eq, PartialEq, Validate)]
pub struct Issuer {
  #[validate(length(min = 1), url)]
  value: String,
}
impl<'a, T: Into<Cow<'a, str>>> TryNewEntity<T> for Issuer {
  fn new(input: T) -> Result<Self> {
    let value = input.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}

impl Entity for Issuer {
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
