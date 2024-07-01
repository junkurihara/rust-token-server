use thiserror::Error;

pub(super) type AuthResult<T> = Result<T, AuthError>;

/// Describes things that can go wrong in the authentication process
#[derive(Debug, Error)]
pub enum AuthError {
  #[error("TokenHttpClient response is not 20x: {source}")]
  TokenHttpClientErrorResponse {
    source: Box<dyn std::error::Error + Send + Sync>,
    code: u16,
  },

  #[cfg(feature = "reqwest")]
  #[error(transparent)]
  ReqwestClientError(#[from] reqwest::Error),

  #[error("Failed to decode Id token: {0}")]
  FailedToDecodeIdToken(anyhow::Error),

  #[error("Failed to parse token api url")]
  UrlError,
  #[error("No JWK matched to Id token is given at jwks endpoint! key_id: {kid}")]
  NoJwkMatched { kid: String },
  #[error("Invalid jwk retrieved from jwks endpoint")]
  InvalidJwk,
  #[error("Failed to serialize jwk")]
  FailedToSerializeJwk,
  #[error("Failed to deserialize jwk: {0}")]
  FailedToDeserializeJwk(#[from] serde_json::Error),
  #[error("Failed to parse jwk: {0}")]
  FailedToParseJwk(anyhow::Error),
  #[error("Invalid Id Token")]
  InvalidIdToken,
  #[error("No key id in Id token")]
  NoKeyIdInIdToken,
  #[error("No exp in Id token")]
  NoExpInIdToken,
  #[error("No Id token previously retrieved")]
  NoIdToken,
  #[error("No refresh token previously retrieved")]
  NoRefreshToken,
  #[error("No validation key previously retrieved")]
  NoValidationKey,
  #[error("Not allowed operation. Needs admin privilege")]
  NotAllowed,

  #[cfg(feature = "blind-signatures")]
  #[error("Failed to make blind signature request: {0}")]
  FailedToMakeBlindSignatureRequest(anyhow::Error),

  #[cfg(feature = "blind-signatures")]
  #[error("Failed to unblind signed response: {0}")]
  FailedToUnblindSignedResponse(anyhow::Error),

  #[cfg(feature = "blind-signatures")]
  #[error("Failed to parse key id of blind jwks: {0}")]
  BlindKeyIdParseError(anyhow::Error),

  #[cfg(feature = "blind-signatures")]
  #[error("No JWK in blind jwks")]
  NoJwkInBlindJwks,

  #[cfg(feature = "blind-signatures")]
  #[error("No kid in blind jwks")]
  NoKeyIdInBlindJwks,

  #[cfg(feature = "blind-signatures")]
  #[error("No blind validation key previously retrieved")]
  NoBlindValidationKey,

  #[cfg(feature = "blind-signatures")]
  #[error("Invalid expiration time of blind validation key (given in blind sign result)")]
  InvalidExpireTimeBlindValidationKey,

  #[cfg(feature = "blind-signatures")]
  #[error("Invalid blind signature")]
  InvalidBlindSignature,

  #[cfg(feature = "blind-signatures")]
  #[error("No anonymous token including unblinded signature previously generated")]
  NoAnonymousToken,

  // black hole
  #[error(transparent)]
  Other(#[from] anyhow::Error),
}
