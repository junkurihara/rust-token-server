pub use anyhow::{anyhow, bail, ensure, Result};
use thiserror::Error;

/// Describes things that can go wrong in the authentication process
#[derive(Debug, Error)]
pub enum ValidationError {
  // validation key errors
  #[error("Unsupported validation key")]
  UnsupportedValidationKey,
  #[error("Failed to validate token")]
  ValidationFailed,
  #[error("Failed to parse jwks url")]
  JwksUrlError,
  #[error("Empty jwks response")]
  EmptyJwks,
  // #[error("TokenHttpClient error")]
  // TokenHttpClientError {
  //   #[from]
  //   source: Box<dyn std::error::Error + Send + Sync>,
  // },

  // #[error("Unsupported alg in Id token")]
  // UnsupportedAlg,
  // #[error("Failed to decode Id token")]
  // FailedToDecodeIdToken(anyhow::Error),
  // #[error("Inconsistent kty and alg in jwk")]
  // InconsistentKtyAndAlg,
  // #[error("Failed to parse token api url")]
  // UrlError,
  // #[error("No JWK matched to Id token is given at jwks endpoint! key_id: {kid}")]
  // NoJwkMatched { kid: String },
  // #[error("Invalid jwk retrieved from jwks endpoint")]
  // InvalidJwk,
  // #[error("Failed to serialize jwk")]
  // FailedToSerializeJwk,
  // #[error("Invalid Id Token")]
  // InvalidIdToken,
  // #[error("No key id in Id token")]
  // NoKeyIdInIdToken,
  // #[error("No Id token previously retrieved")]
  // NoIdToken,
  // #[error("No refresh token previously retrieved")]
  // NoRefreshToken,
  // #[error("No validation key previously retrieved")]
  // NoValidationKey,
}
