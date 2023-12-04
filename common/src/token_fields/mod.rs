mod client_apps;
mod id_token;
mod issuer;
mod refresh_token;
mod subscriber_id;

pub use client_apps::{Audiences, ClientId};
pub use id_token::IdToken;
pub use issuer::Issuer;
pub use refresh_token::RefreshToken;
pub use subscriber_id::SubscriberId;

pub trait Field
where
  Self: std::marker::Sized,
{
  fn as_str(&self) -> &str;
  fn into_string(self) -> String;
}

pub trait TryNewField<T>
where
  Self: std::marker::Sized,
{
  fn new(input: T) -> Result<Self, anyhow::Error>;
}
