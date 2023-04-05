use super::{Entity, Password, TryNewEntity};
use crate::error::*;
use std::borrow::Cow;
use validator::Validate;

#[derive(Debug, Clone, Validate)]
pub struct EncodedHash {
  #[validate(length(min = 1))]
  value: String,
}
impl<'a, T: Into<Cow<'a, str>>> TryNewEntity<T> for EncodedHash {
  fn new(encoded_hash: T) -> Result<Self> {
    let value = encoded_hash.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Entity for EncodedHash {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}

impl EncodedHash {
  pub fn generate(password: &Password) -> Result<Self> {
    let value = password.hash()?;
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
