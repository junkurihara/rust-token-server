#[allow(unused_imports)]
pub use anyhow::{anyhow, bail, ensure, Result};
use thiserror::Error;

/// Describes things that can go wrong in the authentication process
#[derive(Debug, Error)]
pub enum ValidationError {
  #[error("Failed to validate token")]
  ValidationFailed,
  #[error("Failed to parse jwks url")]
  JwksUrlError,
  #[error("Empty jwks response")]
  EmptyJwks,

  #[cfg(feature = "blind-signatures")]
  #[error("Faild to validate anonymous token")]
  BlindValidationFailed,
}
