use crate::{
  claim::CustomClaims,
  constants::JWT_DURATION_MINS,
  jwt::{self, Header, TimeOptions, UntrustedToken},
  token::TokenBody,
  token_fields::*,
};
use anyhow::{anyhow, bail, ensure, Result};
use base64::{engine::general_purpose, Engine as _};
use chrono::{DateTime, Duration, Utc};
use p256::ecdsa::signature::{Signer, Verifier};
use pkcs8::{der::Decode, Document, PrivateKeyInfoRef};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use spki::SubjectPublicKeyInfoRef;
use std::collections::HashSet;
use tracing::{debug, info};

#[allow(non_upper_case_globals, dead_code)]
/// Algorithm OIDs
mod algorithm_oids {
  /// OID for `id-ecPublicKey`, if you're curious
  pub const EC: &str = "1.2.840.10045.2.1";
  /// OID for `id-Ed25519`, if you're curious
  pub const Ed25519: &str = "1.3.101.112";
}
#[allow(non_upper_case_globals, dead_code)]
/// Params OIDs
mod params_oids {
  // Example parameters value: OID for the NIST P-256 elliptic curve.
  pub const Prime256v1: &str = "1.2.840.10045.3.1.7";
}
#[allow(non_upper_case_globals)]
/// Algorithm names in JWS header
mod jws_algorithms {
  /// ECDSA using P-256 and SHA-256
  pub const ES256: &str = "ES256";
  /// EdDSA, which is Ed25519 here
  pub const EdDSA: &str = "EdDSA";
}
#[allow(non_upper_case_globals)]
/// Parameters of JWK
mod jwk_params {
  /// Curve name of P-256 for key type `EC`
  pub const P256: &str = "P-256";
  /// Byte length of the coordinates of P-256
  pub const P256_COORDINATE_LEN: usize = 32;
  /// Curve name of Ed25519 for key type `OKP`
  pub const Ed25519: &str = "Ed25519";
}
/// Tag of the uncompressed point in SEC1 encoding
const SEC1_UNCOMPRESSED_TAG: u8 = 0x04;

pub type JWTClaims = serde_json::Map<String, serde_json::Value>;
pub type Claims = jwt::Claims<JWTClaims>;

#[derive(Serialize, Deserialize)]
#[serde(tag = "kty")]
/// Public key in JWK (RFC 7517) for validation keys, where unsupported parameters such as `kid` are ignored in parsing
enum Jwk {
  #[serde(rename = "EC")]
  EllipticCurve { crv: String, x: String, y: String },
  #[serde(rename = "OKP")]
  KeyPair { crv: String, x: String },
  #[serde(other)]
  Unsupported,
}

/// Decode a base64url-encoded parameter of JWK and check its byte length
fn decode_jwk_param(name: &str, value: &str, len: usize) -> Result<Vec<u8>> {
  let bytes = general_purpose::URL_SAFE_NO_PAD
    .decode(value)
    .map_err(|e| anyhow!("Invalid JWK parameter `{name}`: {e}"))?;
  ensure!(bytes.len() == len, "Invalid length of JWK parameter `{name}`");
  Ok(bytes)
}

/* -------------------------------- */
/// Signing key for JWT
pub enum SigningKey {
  Es256(p256::ecdsa::SigningKey),
  Ed25519(ed25519_compact::SecretKey),
}

impl SigningKey {
  /// Derive signing key from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| anyhow!("Error decoding private key: {}", e))?;
    ensure!(tag == "PRIVATE KEY", "Invalid tag");

    let pki = PrivateKeyInfoRef::from_der(doc.as_bytes()).map_err(|e| anyhow!("Error decoding private key: {}", e))?;

    match pki.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        debug!("Read EC private key");
        let param = pki
          .algorithm
          .parameters_oid()
          .map_err(|e| anyhow!("Error decoding private key: {}", e))?;
        match param.to_string().as_ref() {
          params_oids::Prime256v1 => {
            let private_key = sec1::EcPrivateKey::try_from(pki.private_key.as_bytes())
              .map_err(|e| anyhow!("Error decoding EcPrivateKey: {e}"))?
              .private_key;
            type SecretKey = p256::ecdsa::SigningKey;
            let inner = SecretKey::from_slice(private_key).map_err(|e| anyhow!("Error decoding private key: {}", e))?;
            Ok(Self::Es256(inner))
          }
          _ => bail!("Unsupported curve"),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        debug!("Read Ed25519 private key");
        type SecretKey = ed25519_compact::SecretKey;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&pki.private_key.as_bytes()[2..]);
        let sk = ed25519_compact::KeyPair::from_seed(ed25519_compact::Seed::new(seed))
          .sk
          .to_vec();
        let inner = SecretKey::from_slice(&sk)?;
        Ok(Self::Ed25519(inner))
      }
      _ => bail!("Unsupported algorithm"),
    }
  }

  /// Generate token
  pub fn authorize(
    &self,
    subscriber_id: &SubscriberId,
    client_id: &ClientId,
    issuer: &Issuer,
    is_admin: bool,
    refresh_required: bool,
  ) -> Result<TokenBody> {
    let custom_claims = CustomClaims {
      issuer: issuer.to_owned(),
      subscriber_id: subscriber_id.to_owned(),
      audiences: Audiences::new(client_id.as_str())?,
      is_admin,
    };
    let time_options = TimeOptions::default();
    let claims = jwt::Claims::new(custom_claims)
      .set_duration_and_issuance(&time_options, Duration::minutes(JWT_DURATION_MINS as i64))
      .set_not_before(Utc::now() - Duration::minutes(10));
    let validation_key = self.validation_key();
    let header = Header::new(validation_key.algorithm()).with_key_id(validation_key.key_id());
    let id_token = jwt::encode(&header, &claims, |message| self.sign(message)).map(IdToken::new)??;
    info!("[{}] Issued a JWT: {}", subscriber_id.as_str(), id_token.as_str());

    TokenBody::new(&id_token, refresh_required)
  }

  /// Sign the message and return the signature in the format of JWS
  fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
    match self {
      // The message is hashed with SHA-256, and the signature is the 64-byte concatenation of r and s
      Self::Es256(key) => {
        let signature: p256::ecdsa::Signature = key.try_sign(message).map_err(|e| anyhow!("Failed to sign JWT: {e}"))?;
        Ok(signature.to_bytes().to_vec())
      }
      // Hedged signature with random noise, as jwt-compact did
      Self::Ed25519(key) => Ok(key.sign(message, Some(ed25519_compact::Noise::generate())).to_vec()),
    }
  }

  /// Validate JWT using the validation key derived from this signing key
  pub fn validate<T>(&self, token: &IdToken, opt: &ValidationOptions<T>) -> Result<Claims>
  where
    T: Fn() -> DateTime<Utc>,
  {
    let vk = self.validation_key();
    vk.validate(token, opt)
  }

  /// Get validation key from signing key
  pub fn validation_key(&self) -> ValidationKey {
    match &self {
      Self::Es256(key) => {
        let vk = key.verifying_key().to_owned();
        ValidationKey::Es256(vk)
      }
      Self::Ed25519(key) => {
        let vk = key.public_key();
        ValidationKey::Ed25519(vk)
      }
    }
  }
}

/* -------------------------------- */
/// Validation key for JWT
pub enum ValidationKey {
  Es256(p256::ecdsa::VerifyingKey),
  Ed25519(ed25519_compact::PublicKey),
}

/// Validation options
pub struct ValidationOptions<T = fn() -> DateTime<Utc>>
where
  T: Fn() -> DateTime<Utc>,
{
  pub time_options: TimeOptions<T>,
  pub allowed_issuers: Option<HashSet<Issuer>>,
  pub allowed_audiences: Option<Audiences>,
}
impl Default for ValidationOptions<fn() -> DateTime<Utc>> {
  fn default() -> Self {
    Self {
      time_options: TimeOptions::default(),
      allowed_issuers: None,
      allowed_audiences: None,
    }
  }
}

impl ValidationKey {
  #[allow(dead_code)]
  /// Convert from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| anyhow!("Error decoding public key: {}", e))?;
    ensure!(tag == "PUBLIC KEY", "Invalid tag");
    let spki_ref = SubjectPublicKeyInfoRef::from_der(doc.as_bytes()).map_err(|e| anyhow!("Error decoding public key: {}", e))?;
    match spki_ref.algorithm.oid.to_string().as_ref() {
      // ec
      algorithm_oids::EC => {
        let param = spki_ref
          .algorithm
          .parameters_oid()
          .map_err(|e| anyhow!("Error decoding public key: {}", e))?;
        match param.to_string().as_ref() {
          // prime256v1 = es256
          params_oids::Prime256v1 => {
            let public_key = spki_ref.subject_public_key.as_bytes().ok_or(anyhow!("Invalid public key"))?;
            type PublicKey = p256::ecdsa::VerifyingKey;
            let inner = PublicKey::from_sec1_bytes(public_key)?;
            Ok(Self::Es256(inner))
          }
          _ => bail!("Unsupported curve"),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        let public_key = spki_ref.subject_public_key.as_bytes().ok_or(anyhow!("Invalid public key"))?;
        type PublicKey = ed25519_compact::PublicKey;
        let inner = PublicKey::from_slice(public_key)?;
        Ok(Self::Ed25519(inner))
      }
      _ => bail!("Unsupported algorithm"),
    }
  }
  /// Convert from jwk
  pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self> {
    let jwk_parsed: Jwk = serde_json::from_value(jwk.clone())?;

    match &jwk_parsed {
      Jwk::EllipticCurve { crv, x, y } => match crv.as_ref() {
        jwk_params::P256 => {
          let x = decode_jwk_param("x", x, jwk_params::P256_COORDINATE_LEN)?;
          let y = decode_jwk_param("y", y, jwk_params::P256_COORDINATE_LEN)?;
          let mut sec1_bytes = vec![SEC1_UNCOMPRESSED_TAG];
          sec1_bytes.extend_from_slice(&x);
          sec1_bytes.extend_from_slice(&y);
          type PublicKey = p256::ecdsa::VerifyingKey;
          let inner = PublicKey::from_sec1_bytes(&sec1_bytes)?;
          Ok(Self::Es256(inner))
        }
        _ => bail!("Unsupported curve"),
      },
      Jwk::KeyPair { crv, x } => match crv.as_ref() {
        jwk_params::Ed25519 => {
          type PublicKey = ed25519_compact::PublicKey;
          let x = decode_jwk_param("x", x, PublicKey::BYTES)?;
          let inner = PublicKey::from_slice(&x)?;
          Ok(Self::Ed25519(inner))
        }
        _ => bail!("Unsupported curve"),
      },
      Jwk::Unsupported => bail!("Unsupported key type"),
    }
  }

  /// Convert to jwk
  pub fn to_jwk(&self) -> Result<serde_json::Value> {
    let kid = self.key_id();
    let jwk = match self {
      Self::Es256(vk) => {
        let point = vk.to_sec1_point(false);
        let (Some(x), Some(y)) = (point.x(), point.y()) else {
          bail!("Invalid public key");
        };
        Jwk::EllipticCurve {
          crv: jwk_params::P256.to_string(),
          x: general_purpose::URL_SAFE_NO_PAD.encode(x),
          y: general_purpose::URL_SAFE_NO_PAD.encode(y),
        }
      }
      Self::Ed25519(vk) => Jwk::KeyPair {
        crv: jwk_params::Ed25519.to_string(),
        x: general_purpose::URL_SAFE_NO_PAD.encode(vk.as_ref()),
      },
    };
    let mut jwk = serde_json::to_value(jwk)?;
    jwk["kid"] = serde_json::Value::String(kid);
    Ok(jwk)
  }
  /// Create key id
  pub fn key_id(&self) -> String {
    let bytes = match self {
      Self::Es256(vk) => vk.to_sec1_point(true).as_bytes().to_vec(),
      Self::Ed25519(vk) => vk.as_ref().to_vec(),
    };
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
  }

  /// Algorithm name in JWS header
  fn algorithm(&self) -> &'static str {
    match self {
      Self::Es256(_) => jws_algorithms::ES256,
      Self::Ed25519(_) => jws_algorithms::EdDSA,
    }
  }

  /// Verify the signature in the format of JWS for the message
  fn verify_signature(&self, message: &[u8], signature: &[u8]) -> Result<()> {
    match self {
      // The message is hashed with SHA-256, and the signature is the 64-byte concatenation of r and s
      Self::Es256(key) => {
        let signature = p256::ecdsa::Signature::from_slice(signature).map_err(|e| anyhow!("Malformed signature: {e}"))?;
        key
          .verify(message, &signature)
          .map_err(|e| anyhow!("Invalid signature: {e}"))?;
      }
      Self::Ed25519(key) => {
        let signature = ed25519_compact::Signature::from_slice(signature).map_err(|e| anyhow!("Malformed signature: {e}"))?;
        key
          .verify(message, &signature)
          .map_err(|e| anyhow!("Invalid signature: {e}"))?;
      }
    }
    Ok(())
  }

  /// Validate JWT
  pub fn validate<T>(&self, token: &IdToken, opt: &ValidationOptions<T>) -> Result<Claims>
  where
    T: Fn() -> DateTime<Utc>,
  {
    // Parse the token.
    let token = UntrustedToken::new(token.as_str())?;
    // Verify signature with the algorithm of this key, not trusting the algorithm in the header
    ensure!(
      token.algorithm() == self.algorithm(),
      "Algorithm mismatch: expected {}, actual {}",
      self.algorithm(),
      token.algorithm()
    );
    self.verify_signature(token.signed_data(), token.signature())?;
    let claims = token.deserialize_claims::<JWTClaims>()?;
    // validate time
    claims
      .validate_maturity(&opt.time_options)?
      .validate_expiration(&opt.time_options)?;
    // validate issuer
    if let Some(issuers) = &opt.allowed_issuers {
      let iss = claims
        .custom
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("No issuer is specified in JWT"))?;
      if !issuers.contains(&Issuer::new(iss)?) {
        bail!("Invalid issuer");
      }
    }
    // validate audience
    if let Some(audiences) = &opt.allowed_audiences {
      let aud = claims
        .custom
        .get("aud")
        .ok_or_else(|| anyhow!("No audience is specified in JWT"))?;
      match aud.as_str() {
        Some(aud) => {
          // string case
          if !audiences.contains(&ClientId::new(aud)?) {
            bail!("Invalid audience");
          }
        }
        None => {
          // array case
          let aud = aud
            .as_array()
            .ok_or_else(|| anyhow!("Invalid audience"))?
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|v| ClientId::new(v).ok())
            .collect::<Vec<_>>();
          if !aud.iter().any(|v| audiences.contains(v)) {
            bail!("Invalid audience");
          }
        }
      }
    }
    Ok(claims)
  }
}

#[cfg(test)]
mod tests {
  use crate::jwt::TimeOptions;
  use chrono::{DateTime, Duration};

  use super::*;

  const P256_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv7zxW56ojrWwmSo1\n4uOdbVhUfj9Jd+5aZIB9u8gtWnihRANCAARGYsMe0CT6pIypwRvoJlLNs4+cTh2K\nL7fUNb5i6WbKxkpAoO+6T3pMBG5Yw7+8NuGTvvtrZAXduA2giPxQ8zCf\n-----END PRIVATE KEY-----";
  const EDDSA_PRIVATE_KEY: &str =
    "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C\n-----END PRIVATE KEY-----";

  #[test]
  fn generate_and_validate_token() -> Result<()> {
    let keys = [P256_PRIVATE_KEY, EDDSA_PRIVATE_KEY];

    for key in keys.iter() {
      let sk = SigningKey::from_pem(key)?;
      let token = sk.authorize(
        &SubscriberId::new("test_user")?,
        &ClientId::new("client_id1")?,
        &Issuer::new("https://auth.example.com/v1.0")?,
        false,
        false,
      )?;
      let vk = SigningKey::from_pem(key)?.validation_key();
      let res = vk.validate(&token.id, &ValidationOptions::default());
      assert!(res.is_ok());
    }
    Ok(())
  }

  #[test]
  fn test_kid() -> Result<()> {
    let vk = SigningKey::from_pem(P256_PRIVATE_KEY)?.validation_key();
    let kid = vk.key_id();
    assert_eq!(kid, "k34r3Nqfak67bhJSXTjTRo5tCIr1Bsre1cPoJ3LJ9xE");

    let vk = SigningKey::from_pem(EDDSA_PRIVATE_KEY)?.validation_key();
    let kid = vk.key_id();
    assert_eq!(kid, "gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is");
    Ok(())
  }

  #[test]
  fn tes_pem() -> std::result::Result<(), anyhow::Error> {
    struct PemTokenPair {
      pem: &'static str,
      id_token: &'static str,
    }
    let es256 = PemTokenPair {
      pem: "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERmLDHtAk+qSMqcEb6CZSzbOPnE4d\nii+31DW+YulmysZKQKDvuk96TARuWMO/vDbhk777a2QF3bgNoIj8UPMwnw==\n-----END PUBLIC KEY-----\n",
      id_token: "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTkyODcxNzYsImV4cCI6MTY5OTI4ODk3NiwibmJmIjoxNjk5Mjg3MTc2LCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdjEuMCIsInN1YiI6ImI2MjZmNTBlLTllYWUtNDlkOC04MjAxLTBhZmQyODNhZWNmZCIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjpmYWxzZX0.mmNxox_4nabjrlm-3AjDVX9U_tkQEKH5iHw3KSj22WnsmP4pKDEgZnVSWlxg3prLSfJZCfD3ZR1iiq6EFke45w",
    };
    let ed25519 = PemTokenPair {
      pem: "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=\n-----END PUBLIC KEY-----\n",
      id_token: "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTkyODYzNjgsImV4cCI6MTY5OTI4ODE2OCwibmJmIjoxNjk5Mjg2MzY4LCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdjEuMCIsInN1YiI6IjZiYmI2NGVhLTMyZmUtNGEyNi05MjhlLWZlODlmNTcxNTA0YiIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjpmYWxzZX0.e6D156U4pwalnWmZNK5fDBSjUDflmHQObAiHJLPYu7AS-x81RlO3sRsNoqHz47m0zxOBEFVA3esV74U6xwkyAw",
    };

    let pairs = [es256, ed25519];

    for pair in pairs.iter() {
      let vk = ValidationKey::from_pem(pair.pem)?;

      let mut iss = std::collections::HashSet::new();
      iss.insert(Issuer::new("https://auth.example.com/v1.0")?);
      let aud = Audiences::new("client_id1")?;
      let stopped_time = TimeOptions::new(Duration::seconds(10), move || {
        DateTime::from_timestamp(1699287705, 0).unwrap()
      });
      let vo = ValidationOptions {
        time_options: stopped_time,
        allowed_issuers: Some(iss),
        allowed_audiences: Some(aud),
      };
      let _res = vk.validate(&IdToken::new(pair.id_token)?, &vo)?;
    }

    Ok(())
  }

  #[test]
  fn test_jwk() -> std::result::Result<(), anyhow::Error> {
    struct JwkTokenPair {
      jwk: &'static str,
      id_token: &'static str,
    }
    let ed25519 = JwkTokenPair {
      jwk: "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"1ixMQcxO46PLlgQfYS46ivFd-n0CcDHSKUnuhm3i1O0\"}",
      id_token: "eyJhbGciOiJFZERTQSIsImtpZCI6ImdqckU3QUNNeGd6WWZGSGdhYmdmNGtMVGcxZUtJZHNKOTRBaUZURmoxaXMiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjUsImV4cCI6MTY5OTYyNzkyNSwibmJmIjoxNjk5NjI2MTI1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6ImY2ZDMzNmVlLWFjNDgtNGNlYy04MTYzLTI5OThlMTc4YWVlMyIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.GVJhFknZP5iWe0fKoUJO-Wfg1Ti0ayb7mjUEWvfYhQXwM_dYt39nICiebLEQr3vqctxdyKO8PlXxFpe9bI6bCg",
    };

    let es256 = JwkTokenPair {
      jwk: "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"RmLDHtAk-qSMqcEb6CZSzbOPnE4dii-31DW-YulmysY\",\"y\":\"SkCg77pPekwEbljDv7w24ZO--2tkBd24DaCI_FDzMJ8\"}",
      id_token: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImszNHIzTnFmYWs2N2JoSlNYVGpUUm81dENJcjFCc3JlMWNQb0ozTEo5eEUiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjIsImV4cCI6MTY5OTYyNzkyMiwibmJmIjoxNjk5NjI2MTIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6IjZhMDJlNTRiLTk3NGEtNDViYy04ZDlhLWZhYzQzNzdhMDQ5MiIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.6O6wBd51zO-wZv7Y5r99NSqbEXg1XZtjhCW_FtvScZ8sPIOiU8GTHMfPxVriDyhiAC_W7NEOMZx-4myIeDiZCA",
    };

    let pairs = [ed25519, es256];

    for pair in pairs.iter() {
      let jwk_val = serde_json::from_str::<serde_json::Value>(pair.jwk)?;
      let vk = ValidationKey::from_jwk(&jwk_val)?;

      let mut iss = std::collections::HashSet::new();
      iss.insert(Issuer::new("http://localhost:3000/v1.0")?);
      let aud = Audiences::new("client_id1")?;

      let stopped_time = TimeOptions::new(Duration::seconds(10), move || {
        DateTime::from_timestamp(1699626347, 0).unwrap()
      });
      let vo = ValidationOptions {
        time_options: stopped_time,
        allowed_issuers: Some(iss),
        allowed_audiences: Some(aud),
      };
      let _res = vk.validate(&IdToken::new(pair.id_token)?, &vo)?;
    }

    Ok(())
  }

  fn issue_token(sk: &SigningKey) -> Result<IdToken> {
    let token = sk.authorize(
      &SubscriberId::new("test_user")?,
      &ClientId::new("client_id1")?,
      &Issuer::new("https://auth.example.com/v1.0")?,
      false,
      false,
    )?;
    Ok(token.id)
  }

  /// Replace a part of the token, where `index` is 0 for the header, 1 for the claims and 2 for the signature
  fn replace_part(token: &IdToken, index: usize, decoded_part: &[u8]) -> Result<IdToken> {
    let encoded_part = general_purpose::URL_SAFE_NO_PAD.encode(decoded_part);
    let mut parts = token.as_str().split('.').collect::<Vec<_>>();
    parts[index] = &encoded_part;
    IdToken::new(parts.join("."))
  }

  #[test]
  fn test_jwk_of_signing_keys() -> Result<()> {
    // Same JWKs as jwt-compact
    let pairs = [
      (
        P256_PRIVATE_KEY,
        r#"{"crv":"P-256","kid":"k34r3Nqfak67bhJSXTjTRo5tCIr1Bsre1cPoJ3LJ9xE","kty":"EC","x":"RmLDHtAk-qSMqcEb6CZSzbOPnE4dii-31DW-YulmysY","y":"SkCg77pPekwEbljDv7w24ZO--2tkBd24DaCI_FDzMJ8"}"#,
      ),
      (
        EDDSA_PRIVATE_KEY,
        r#"{"crv":"Ed25519","kid":"gjrE7ACMxgzYfFHgabgf4kLTg1eKIdsJ94AiFTFj1is","kty":"OKP","x":"1ixMQcxO46PLlgQfYS46ivFd-n0CcDHSKUnuhm3i1O0"}"#,
      ),
    ];

    for (key, expected_jwk) in pairs {
      let vk = SigningKey::from_pem(key)?.validation_key();
      let jwk = vk.to_jwk()?;
      assert_eq!(jwk, serde_json::from_str::<serde_json::Value>(expected_jwk)?);
      // `kid` is ignored in parsing
      let parsed = ValidationKey::from_jwk(&jwk)?;
      assert_eq!(parsed.key_id(), vk.key_id());
    }
    Ok(())
  }

  #[test]
  fn test_invalid_jwk() -> Result<()> {
    let es256_jwk = SigningKey::from_pem(P256_PRIVATE_KEY)?.validation_key().to_jwk()?;
    let ed25519_jwk = SigningKey::from_pem(EDDSA_PRIVATE_KEY)?.validation_key().to_jwk()?;
    assert!(ValidationKey::from_jwk(&es256_jwk).is_ok());
    assert!(ValidationKey::from_jwk(&ed25519_jwk).is_ok());

    let modified = |base: &serde_json::Value, name: &str, value: serde_json::Value| {
      let mut jwk = base.clone();
      jwk[name] = value;
      jwk
    };
    let encoded = |bytes: &[u8]| serde_json::Value::String(general_purpose::URL_SAFE_NO_PAD.encode(bytes));
    let mut y_off_curve = general_purpose::URL_SAFE_NO_PAD.decode(es256_jwk["y"].as_str().unwrap_or_default())?;
    y_off_curve[31] ^= 1;
    let mut no_y = es256_jwk.clone();
    if let Some(jwk) = no_y.as_object_mut() {
      jwk.remove("y");
    }

    let invalid_jwks = [
      // Unsupported key types and curves
      serde_json::json!({"kty": "oct", "k": "AQAB"}),
      modified(&es256_jwk, "kty", "RSA".into()),
      modified(&es256_jwk, "crv", "P-384".into()),
      modified(&ed25519_jwk, "crv", "X25519".into()),
      // Missing parameters
      modified(&es256_jwk, "kty", serde_json::Value::Null),
      no_y,
      // Invalid lengths
      modified(&es256_jwk, "x", encoded(&[0u8; 31])),
      modified(&es256_jwk, "y", encoded(&[0u8; 33])),
      modified(&ed25519_jwk, "x", encoded(&[0u8; 33])),
      // Point not on the curve
      modified(&es256_jwk, "y", encoded(&y_off_curve)),
      // Invalid base64url
      modified(&ed25519_jwk, "x", "1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0".into()),
      modified(&ed25519_jwk, "x", "1ixMQcxO46PLlgQfYS46ivFd-n0CcDHSKUnuhm3i1O0=".into()),
    ];
    for jwk in invalid_jwks.iter() {
      assert!(ValidationKey::from_jwk(jwk).is_err(), "{jwk}");
    }
    Ok(())
  }

  #[test]
  fn test_invalid_tokens() -> Result<()> {
    let es256 = SigningKey::from_pem(P256_PRIVATE_KEY)?;
    let ed25519 = SigningKey::from_pem(EDDSA_PRIVATE_KEY)?;
    let opts = ValidationOptions::default();

    for (sk, other_sk) in [(&es256, &ed25519), (&ed25519, &es256)] {
      let vk = sk.validation_key();
      let other_vk = other_sk.validation_key();
      let token = issue_token(sk)?;
      assert!(vk.validate(&token, &opts).is_ok());

      let parts = token
        .as_str()
        .split('.')
        .map(|part| general_purpose::URL_SAFE_NO_PAD.decode(part))
        .collect::<std::result::Result<Vec<_>, _>>()?;
      let (header, claims, signature) = (&parts[0], &parts[1], &parts[2]);

      // Tampered claims
      let tampered_claims = String::from_utf8(claims.clone())?.replace(r#""iad":false"#, r#""iad":true"#);
      assert_ne!(tampered_claims.as_bytes(), claims.as_slice());
      let tampered = replace_part(&token, 1, tampered_claims.as_bytes())?;
      assert!(vk.validate(&tampered, &opts).is_err());

      // Tampered signature
      let mut tampered_signature = signature.clone();
      tampered_signature[0] ^= 1;
      assert!(vk.validate(&replace_part(&token, 2, &tampered_signature)?, &opts).is_err());

      // Invalid signature lengths
      let mut longer_signature = signature.clone();
      longer_signature.push(0);
      assert!(vk.validate(&replace_part(&token, 2, &longer_signature)?, &opts).is_err());
      let shorter_signature = &signature[..signature.len() - 1];
      assert!(vk.validate(&replace_part(&token, 2, shorter_signature)?, &opts).is_err());
      assert!(vk.validate(&replace_part(&token, 2, &[])?, &opts).is_err());

      // Tampered header
      let tampered_header = String::from_utf8(header.clone())?.replace(vk.algorithm(), other_vk.algorithm());
      assert_ne!(tampered_header.as_bytes(), header.as_slice());
      assert!(vk
        .validate(&replace_part(&token, 0, tampered_header.as_bytes())?, &opts)
        .is_err());
      let none_header = replace_part(&token, 0, br#"{"alg":"none"}"#)?;
      assert!(vk.validate(&replace_part(&none_header, 2, &[])?, &opts).is_err());

      // Algorithm in the header must match the key even if the signature is valid
      let decoded_claims = UntrustedToken::new(token.as_str())?.deserialize_claims::<JWTClaims>()?;
      let sign_with_header = |alg: &str| -> Result<IdToken> {
        let header = Header::new(alg).with_key_id(vk.key_id());
        IdToken::new(jwt::encode(&header, &decoded_claims, |message| sk.sign(message))?)
      };
      assert!(vk.validate(&sign_with_header(vk.algorithm())?, &opts).is_ok());
      for alg in ["none", "HS256", other_vk.algorithm()] {
        let res = vk.validate(&sign_with_header(alg)?, &opts);
        assert!(res.is_err_and(|e| e.to_string().starts_with("Algorithm mismatch")));
      }

      // Key of the other algorithm
      assert!(other_vk.validate(&token, &opts).is_err());
    }
    Ok(())
  }

  #[test]
  fn test_time_validation() -> Result<()> {
    let sk = SigningKey::from_pem(P256_PRIVATE_KEY)?;
    let vk = sk.validation_key();
    let token = issue_token(&sk)?;
    let claims = vk.validate(&token, &ValidationOptions::default())?;
    let (Some(exp), Some(nbf)) = (claims.expiration, claims.not_before) else {
      bail!("exp or nbf is missing");
    };

    let at = |time: DateTime<Utc>| ValidationOptions {
      time_options: TimeOptions::new(Duration::seconds(60), move || time),
      allowed_issuers: None,
      allowed_audiences: None,
    };
    assert!(vk.validate(&token, &at(exp + Duration::seconds(60))).is_ok());
    assert!(vk.validate(&token, &at(exp + Duration::seconds(61))).is_err());
    assert!(vk.validate(&token, &at(nbf - Duration::seconds(60))).is_ok());
    assert!(vk.validate(&token, &at(nbf - Duration::seconds(61))).is_err());

    // Both exp and nbf are required
    let custom_claims = CustomClaims {
      issuer: Issuer::new("https://auth.example.com/v1.0")?,
      subscriber_id: SubscriberId::new("test_user")?,
      audiences: Audiences::new("client_id1")?,
      is_admin: false,
    };
    let header = Header::new(vk.algorithm()).with_key_id(vk.key_id());
    let sign_claims = |claims: &jwt::Claims<&CustomClaims>| -> Result<IdToken> {
      IdToken::new(jwt::encode(&header, claims, |message| sk.sign(message))?)
    };
    let no_nbf = jwt::Claims::new(&custom_claims).set_duration_and_issuance(&TimeOptions::default(), Duration::minutes(30));
    let no_exp = jwt::Claims::new(&custom_claims).set_not_before(nbf);
    let both = no_nbf.clone().set_not_before(nbf);
    assert!(vk.validate(&sign_claims(&both)?, &ValidationOptions::default()).is_ok());
    let res = vk.validate(&sign_claims(&no_nbf)?, &ValidationOptions::default());
    assert!(res.is_err_and(|e| e.to_string() == "No nbf is specified in JWT"));
    let res = vk.validate(&sign_claims(&no_exp)?, &ValidationOptions::default());
    assert!(res.is_err_and(|e| e.to_string() == "No exp is specified in JWT"));
    Ok(())
  }
}
