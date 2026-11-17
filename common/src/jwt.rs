//! Minimal implementation of JWT (RFC 7519) in the JWS compact serialization (RFC 7515).
//! This module handles only the token format and the time-related claims,
//! and signing and signature verification are done by the keys in `validation_key`.
//! The behavior follows `jwt-compact`, which was previously used, to keep the compatibility of tokens.

use crate::constants::JWT_LEEWAY_SECS;
use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

/* -------------------------------- */
#[derive(Debug, Clone, Copy)]
/// Time-related options to create and validate claims
pub struct TimeOptions<F = fn() -> DateTime<Utc>> {
  /// Leeway to tolerate clock skew in validating `exp` and `nbf`
  pub leeway: Duration,
  /// Source of the current time
  pub clock_fn: F,
}

impl<F> TimeOptions<F>
where
  F: Fn() -> DateTime<Utc>,
{
  /// Create options with the leeway and the clock function
  pub fn new(leeway: Duration, clock_fn: F) -> Self {
    Self { leeway, clock_fn }
  }
}

impl Default for TimeOptions {
  /// Create options with the default leeway and the system clock
  fn default() -> Self {
    Self::new(Duration::seconds(JWT_LEEWAY_SECS), Utc::now)
  }
}

/* -------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// Claims of JWT, comprised of the time-related registered claims and custom claims
pub struct Claims<T> {
  /// Expiration time (`exp`)
  #[serde(rename = "exp", default, skip_serializing_if = "Option::is_none", with = "timestamp")]
  pub expiration: Option<DateTime<Utc>>,
  /// Not before (`nbf`)
  #[serde(rename = "nbf", default, skip_serializing_if = "Option::is_none", with = "timestamp")]
  pub not_before: Option<DateTime<Utc>>,
  /// Issued at (`iat`)
  #[serde(rename = "iat", default, skip_serializing_if = "Option::is_none", with = "timestamp")]
  pub issued_at: Option<DateTime<Utc>>,
  /// Custom claims
  #[serde(flatten)]
  pub custom: T,
}

impl<T> Claims<T> {
  /// Create claims only with custom claims
  pub fn new(custom: T) -> Self {
    Self {
      expiration: None,
      not_before: None,
      issued_at: None,
      custom,
    }
  }

  /// Set `iat` to the current time and `exp` to the current time plus the duration
  #[must_use]
  pub fn set_duration_and_issuance<F>(self, options: &TimeOptions<F>, duration: Duration) -> Self
  where
    F: Fn() -> DateTime<Utc>,
  {
    let issued_at = (options.clock_fn)();
    Self {
      expiration: Some(issued_at + duration),
      issued_at: Some(issued_at),
      ..self
    }
  }

  /// Set `nbf`
  #[must_use]
  pub fn set_not_before(self, moment: DateTime<Utc>) -> Self {
    Self {
      not_before: Some(moment),
      ..self
    }
  }

  /// Validate `exp` with the leeway, where `exp` is required
  pub fn validate_expiration<F>(&self, options: &TimeOptions<F>) -> Result<&Self>
  where
    F: Fn() -> DateTime<Utc>,
  {
    let expiration = self.expiration.ok_or_else(|| anyhow!("No exp is specified in JWT"))?;
    let expiration_with_leeway = expiration
      .checked_add_signed(options.leeway)
      .unwrap_or(DateTime::<Utc>::MAX_UTC);
    ensure!((options.clock_fn)() <= expiration_with_leeway, "JWT has expired");
    Ok(self)
  }

  /// Validate `nbf` with the leeway, where `nbf` is required
  pub fn validate_maturity<F>(&self, options: &TimeOptions<F>) -> Result<&Self>
  where
    F: Fn() -> DateTime<Utc>,
  {
    let not_before = self.not_before.ok_or_else(|| anyhow!("No nbf is specified in JWT"))?;
    let not_before_with_leeway = not_before
      .checked_sub_signed(options.leeway)
      .unwrap_or(DateTime::<Utc>::MIN_UTC);
    ensure!((options.clock_fn)() >= not_before_with_leeway, "JWT is not yet valid");
    Ok(self)
  }
}

/// (De)serialization of time-related claims as NumericDate (RFC 7519), i.e., seconds since the epoch
mod timestamp {
  use chrono::{DateTime, TimeZone, Utc};
  use serde::{de, Deserializer, Serializer};
  use std::fmt;

  struct TimestampVisitor;

  impl de::Visitor<'_> for TimestampVisitor {
    type Value = DateTime<Utc>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
      formatter.write_str("UTC timestamp")
    }

    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Self::Value, E> {
      Utc
        .timestamp_opt(value, 0)
        .single()
        .ok_or_else(|| E::custom("UTC timestamp overflow"))
    }

    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Self::Value, E> {
      let value = i64::try_from(value).map_err(E::custom)?;
      self.visit_i64(value)
    }

    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Self::Value, E> {
      // NumericDate may be non-integer, and the fractional part is truncated.
      // An out-of-range value saturates and then results in the overflow error above.
      self.visit_i64(value as i64)
    }
  }

  pub fn serialize<S: Serializer>(time: &Option<DateTime<Utc>>, serializer: S) -> Result<S::Ok, S::Error> {
    match time {
      Some(time) => serializer.serialize_i64(time.timestamp()),
      None => serializer.serialize_none(),
    }
  }

  pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<DateTime<Utc>>, D::Error> {
    deserializer.deserialize_i64(TimestampVisitor).map(Some)
  }
}

/* -------------------------------- */
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// JOSE header of JWT, where unsupported parameters are ignored in parsing
pub struct Header {
  /// Algorithm (`alg`)
  #[serde(rename = "alg")]
  pub algorithm: String,
  /// Content type (`cty`)
  #[serde(rename = "cty", default, skip_serializing_if = "Option::is_none")]
  pub content_type: Option<String>,
  /// Key ID (`kid`)
  #[serde(rename = "kid", default, skip_serializing_if = "Option::is_none")]
  pub key_id: Option<String>,
  /// Token type (`typ`)
  #[serde(rename = "typ", default, skip_serializing_if = "Option::is_none")]
  pub token_type: Option<String>,
}

impl Header {
  /// Create header with the algorithm
  pub(crate) fn new(algorithm: impl Into<String>) -> Self {
    Self {
      algorithm: algorithm.into(),
      content_type: None,
      key_id: None,
      token_type: None,
    }
  }

  /// Set key ID
  #[must_use]
  pub(crate) fn with_key_id(self, key_id: impl Into<String>) -> Self {
    Self {
      key_id: Some(key_id.into()),
      ..self
    }
  }
}

/* -------------------------------- */
#[derive(Debug, Clone)]
/// JWT parsed from the JWS compact serialization, whose signature and claims are not validated yet
pub struct UntrustedToken {
  /// Signing input, i.e., base64url-encoded header and claims joined with `.`
  signed_data: String,
  /// Decoded header
  header: Header,
  /// Decoded but not yet deserialized claims
  serialized_claims: Vec<u8>,
  /// Decoded signature
  signature: Vec<u8>,
}

impl UntrustedToken {
  /// Parse JWT in the JWS compact serialization
  pub fn new(token: &str) -> Result<Self> {
    let parts = token.splitn(4, '.').collect::<Vec<_>>();
    let &[encoded_header, encoded_claims, encoded_signature] = parts.as_slice() else {
      bail!("Invalid token structure");
    };
    let header = decode_base64url(encoded_header)?;
    let serialized_claims = decode_base64url(encoded_claims)?;
    let signature = decode_base64url(encoded_signature)?;

    let header: Header = serde_json::from_slice(&header).map_err(|e| anyhow!("Malformed header: {e}"))?;
    // Only JSON claims are supported
    if let Some(content_type) = &header.content_type {
      ensure!(
        content_type.eq_ignore_ascii_case("json"),
        "Unsupported content type: {content_type}"
      );
    }

    Ok(Self {
      signed_data: format!("{encoded_header}.{encoded_claims}"),
      header,
      serialized_claims,
      signature,
    })
  }

  /// Header
  pub fn header(&self) -> &Header {
    &self.header
  }

  /// Algorithm specified in the header
  pub fn algorithm(&self) -> &str {
    &self.header.algorithm
  }

  /// Signing input to verify the signature
  pub(crate) fn signed_data(&self) -> &[u8] {
    self.signed_data.as_bytes()
  }

  /// Signature
  pub(crate) fn signature(&self) -> &[u8] {
    &self.signature
  }

  /// Deserialize claims without any validation
  pub(crate) fn deserialize_claims<T: DeserializeOwned>(&self) -> Result<Claims<T>> {
    serde_json::from_slice(&self.serialized_claims).map_err(|e| anyhow!("Malformed claims: {e}"))
  }
}

/* -------------------------------- */
/// Create JWT in the JWS compact serialization by signing the header and the claims with `sign`
pub(crate) fn encode<T, S>(header: &Header, claims: &Claims<T>, sign: S) -> Result<String>
where
  T: Serialize,
  S: FnOnce(&[u8]) -> Result<Vec<u8>>,
{
  let encoded_header = encode_base64url(serde_json::to_vec(header)?);
  let encoded_claims = encode_base64url(serde_json::to_vec(claims)?);
  let signed_data = format!("{encoded_header}.{encoded_claims}");
  let encoded_signature = encode_base64url(sign(signed_data.as_bytes())?);
  Ok(format!("{signed_data}.{encoded_signature}"))
}

/// Encode into base64url without padding
fn encode_base64url(input: impl AsRef<[u8]>) -> String {
  general_purpose::URL_SAFE_NO_PAD.encode(input)
}

/// Decode base64url without padding
fn decode_base64url(input: &str) -> Result<Vec<u8>> {
  general_purpose::URL_SAFE_NO_PAD
    .decode(input)
    .map_err(|e| anyhow!("Invalid base64url encoding: {e}"))
}

#[cfg(test)]
mod tests {
  use super::*;

  type JWTClaims = serde_json::Map<String, serde_json::Value>;

  const DUMMY_SIGNATURE: &[u8] = b"dummy signature";

  fn custom_claims() -> JWTClaims {
    let mut custom = JWTClaims::new();
    custom.insert("sub".to_string(), serde_json::Value::String("test_user".to_string()));
    custom
  }

  fn stopped_time(timestamp: i64) -> TimeOptions<impl Fn() -> DateTime<Utc>> {
    TimeOptions::new(Duration::seconds(60), move || DateTime::from_timestamp(timestamp, 0).unwrap())
  }

  #[test]
  fn test_encode_and_parse() -> Result<()> {
    let header = Header::new("ES256").with_key_id("kid1");
    let claims = Claims::new(custom_claims())
      .set_duration_and_issuance(&stopped_time(1699287705), Duration::minutes(30))
      .set_not_before(DateTime::from_timestamp(1699287105, 0).unwrap());

    let mut signed_by_signer = Vec::new();
    let token = encode(&header, &claims, |message| {
      signed_by_signer = message.to_vec();
      Ok(DUMMY_SIGNATURE.to_vec())
    })?;

    // Same serialization as jwt-compact
    let parts = token.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    assert_eq!(decode_base64url(parts[0])?, br#"{"alg":"ES256","kid":"kid1"}"#);
    assert_eq!(
      decode_base64url(parts[1])?,
      br#"{"exp":1699289505,"nbf":1699287105,"iat":1699287705,"sub":"test_user"}"#
    );

    let parsed = UntrustedToken::new(&token)?;
    assert_eq!(parsed.header(), &header);
    assert_eq!(parsed.algorithm(), "ES256");
    assert_eq!(parsed.signed_data(), signed_by_signer.as_slice());
    assert_eq!(parsed.signature(), DUMMY_SIGNATURE);
    assert_eq!(parsed.deserialize_claims::<JWTClaims>()?, claims);
    Ok(())
  }

  #[test]
  fn test_parse_invalid_tokens() -> Result<()> {
    let header = encode_base64url(br#"{"alg":"ES256"}"#);
    let claims = encode_base64url(br#"{"sub":"test_user"}"#);
    let signature = encode_base64url(DUMMY_SIGNATURE);
    assert!(UntrustedToken::new(&format!("{header}.{claims}.{signature}")).is_ok());

    // Invalid number of parts
    assert!(UntrustedToken::new(&format!("{header}.{claims}")).is_err());
    assert!(UntrustedToken::new(&format!("{header}.{claims}.{signature}.{signature}")).is_err());
    // Invalid base64url encoding
    assert!(UntrustedToken::new(&format!("{header}.{claims}.{signature}=")).is_err());
    assert!(UntrustedToken::new(&format!("{header}.{claims}+.{signature}")).is_err());
    // Malformed header
    let no_alg = encode_base64url(br#"{"kid":"kid1"}"#);
    assert!(UntrustedToken::new(&format!("{no_alg}.{claims}.{signature}")).is_err());
    let not_json = encode_base64url(b"not json");
    assert!(UntrustedToken::new(&format!("{not_json}.{claims}.{signature}")).is_err());
    // Content type
    let json_cty = encode_base64url(br#"{"alg":"ES256","cty":"JSON"}"#);
    assert!(UntrustedToken::new(&format!("{json_cty}.{claims}.{signature}")).is_ok());
    let cbor_cty = encode_base64url(br#"{"alg":"ES256","cty":"CBOR"}"#);
    assert!(UntrustedToken::new(&format!("{cbor_cty}.{claims}.{signature}")).is_err());
    // Malformed claims are detected in deserialization
    let parsed = UntrustedToken::new(&format!("{header}.{not_json}.{signature}"))?;
    assert!(parsed.deserialize_claims::<JWTClaims>().is_err());
    Ok(())
  }

  #[test]
  fn test_deserialize_timestamps() -> Result<()> {
    let claims: Claims<JWTClaims> = serde_json::from_str(r#"{"exp":1699289505,"nbf":1699287105.9,"sub":"test_user"}"#)?;
    assert_eq!(claims.expiration, DateTime::from_timestamp(1699289505, 0));
    assert_eq!(claims.not_before, DateTime::from_timestamp(1699287105, 0));
    assert_eq!(claims.issued_at, None);
    assert_eq!(claims.custom, custom_claims());

    assert!(serde_json::from_str::<Claims<JWTClaims>>(r#"{"exp":"1699289505"}"#).is_err());
    assert!(serde_json::from_str::<Claims<JWTClaims>>(r#"{"exp":18446744073709551615}"#).is_err());
    Ok(())
  }

  #[test]
  fn test_validate_time() {
    let exp = 1699289505;
    let nbf = 1699287105;
    let claims = Claims::new(custom_claims())
      .set_duration_and_issuance(&stopped_time(exp - 1800), Duration::minutes(30))
      .set_not_before(DateTime::from_timestamp(nbf, 0).unwrap());

    // Expiration with the leeway of 60 secs
    assert!(claims.validate_expiration(&stopped_time(exp)).is_ok());
    assert!(claims.validate_expiration(&stopped_time(exp + 60)).is_ok());
    assert!(claims.validate_expiration(&stopped_time(exp + 61)).is_err());
    // Maturity with the leeway of 60 secs
    assert!(claims.validate_maturity(&stopped_time(nbf)).is_ok());
    assert!(claims.validate_maturity(&stopped_time(nbf - 60)).is_ok());
    assert!(claims.validate_maturity(&stopped_time(nbf - 61)).is_err());

    // Both claims are required
    let claims = Claims::new(custom_claims());
    assert!(claims.validate_expiration(&stopped_time(exp)).is_err());
    assert!(claims.validate_maturity(&stopped_time(nbf)).is_err());

    // Default leeway is 60 secs
    assert_eq!(TimeOptions::default().leeway, Duration::seconds(60));
  }
}
