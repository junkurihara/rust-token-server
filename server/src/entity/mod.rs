mod encoded_hash;
mod password;
mod refresh_token_info;
mod user;
mod username;

use crate::error::{Error, Result};

pub use encoded_hash::EncodedHash;
pub use password::Password;
pub use refresh_token_info::*;
pub use user::*;
pub use username::*;

pub trait Entity
where
  Self: std::marker::Sized,
{
  fn as_str(&self) -> &str;
  fn into_string(self) -> String;
}

pub trait TryNewEntity<T>
where
  Self: std::marker::Sized,
{
  fn new(input: T) -> Result<Self, Error>;
}
