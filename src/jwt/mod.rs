mod alg;
mod jwt_key_pair;
mod token;

use crate::error::*;
use std::borrow::Cow;
use validator::Validate;

pub use alg::{Algorithm, AlgorithmType};
pub use jwt_key_pair::{AdditionalClaimData, JwtKeyPair};
pub use token::{Token, TokenInner, TokenMeta};

#[derive(Debug, Clone, Eq, PartialEq, Validate)]
pub struct Issuer {
  #[validate(length(min = 1))]
  value: String,
}
impl Issuer {
  pub fn new<'a>(username: impl Into<Cow<'a, str>>) -> Result<Self> {
    let value = username.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
  pub fn as_str(&self) -> &str {
    &self.value
  }
  pub fn into_string(self) -> String {
    self.value
  }
}
