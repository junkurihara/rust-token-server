mod client_apps;
mod encoded_hash;
mod id_token;
mod issuer;
mod password;
mod refresh_token;
mod subscriber_id;
mod user;
mod username;

use crate::error::{Error, Result};

pub use client_apps::{Audiences, ClientId};
pub use encoded_hash::EncodedHash;
pub use id_token::IdToken;
pub use issuer::Issuer;
pub use password::Password;
pub use refresh_token::*;
pub use subscriber_id::SubscriberId;
pub use user::*;
pub use username::Username;

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
