use crate::{claim::CustomClaims, constants::JWT_DURATION_MINS, token::TokenBody, token_fields::*};
use anyhow::{anyhow, bail, ensure, Result};
use chrono::{DateTime, Duration, Utc};
use jwt_compact::{
  alg::{Ed25519, Es256, VerifyingKey},
  jwk::JsonWebKey,
  Algorithm, AlgorithmExt, Header, TimeOptions, UntrustedToken,
};
use pkcs8::{der::Decode, Document, PrivateKeyInfo};
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

pub type JWTClaims = serde_json::Map<String, serde_json::Value>;
pub type Claims = jwt_compact::Claims<JWTClaims>;

/* -------------------------------- */
/// Signing key for JWT
pub enum SigningKey {
  Es256(<Es256 as Algorithm>::SigningKey),
  Ed25519(<Ed25519 as Algorithm>::SigningKey),
}

impl SigningKey {
  /// Derive signing key from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let (tag, doc) = Document::from_pem(pem).map_err(|e| anyhow!("Error decoding private key: {}", e))?;
    ensure!(tag == "PRIVATE KEY", "Invalid tag");

    let pki = PrivateKeyInfo::from_der(doc.as_bytes()).map_err(|e| anyhow!("Error decoding private key: {}", e))?;

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
            let private_key = sec1::EcPrivateKey::try_from(pki.private_key)
              .map_err(|e| anyhow!("Error decoding EcPrivateKey: {e}"))?
              .private_key;
            type SecretKey = <Es256 as Algorithm>::SigningKey;
            let inner = SecretKey::from_slice(private_key).map_err(|e| anyhow!("Error decoding private key: {}", e))?;
            Ok(Self::Es256(inner))
          }
          _ => bail!("Unsupported curve"),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        debug!("Read Ed25519 private key");
        type SecretKey = <Ed25519 as Algorithm>::SigningKey;
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&pki.private_key[2..]);
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
    let claims = jwt_compact::Claims::new(custom_claims)
      .set_duration_and_issuance(&time_options, Duration::minutes(JWT_DURATION_MINS as i64))
      .set_not_before(Utc::now() - Duration::minutes(10));
    let key_id = self.validation_key().key_id();
    let header = Header::empty().with_key_id(key_id);
    let id_token = match self {
      Self::Es256(key) => Es256.token(&header, &claims, key),
      Self::Ed25519(key) => Ed25519.token(&header, &claims, key),
    }
    .map(IdToken::new)??;
    info!("[{}] Issued a JWT: {}", subscriber_id.as_str(), id_token.as_str());

    TokenBody::new(&id_token, refresh_required)
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
  Es256(<Es256 as Algorithm>::VerifyingKey),
  Ed25519(<Ed25519 as Algorithm>::VerifyingKey),
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
            type PublicKey = <Es256 as Algorithm>::VerifyingKey;
            let inner = PublicKey::from_slice(public_key)?;
            Ok(Self::Es256(inner))
          }
          _ => bail!("Unsupported curve"),
        }
      }
      // ed25519
      algorithm_oids::Ed25519 => {
        let public_key = spki_ref.subject_public_key.as_bytes().ok_or(anyhow!("Invalid public key"))?;
        type PublicKey = <Ed25519 as Algorithm>::VerifyingKey;
        let inner = PublicKey::from_slice(public_key)?;
        Ok(Self::Ed25519(inner))
      }
      _ => bail!("Unsupported algorithm"),
    }
  }
  /// Convert from jwk
  pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self> {
    let jwk_parsed: JsonWebKey<'_> = serde_json::from_value(jwk.clone())?;

    match &jwk_parsed {
      JsonWebKey::EllipticCurve { curve, .. } => match curve.as_ref() {
        "P-256" => {
          type PublicKey = <Es256 as Algorithm>::VerifyingKey;
          let inner = PublicKey::try_from(&jwk_parsed)?;
          Ok(Self::Es256(inner))
        }
        _ => bail!("Unsupported curve"),
      },
      JsonWebKey::KeyPair { curve, .. } => match curve.as_ref() {
        "Ed25519" => {
          type PublicKey = <Ed25519 as Algorithm>::VerifyingKey;
          let inner = PublicKey::try_from(&jwk_parsed)?;
          Ok(Self::Ed25519(inner))
        }
        _ => bail!("Unsupported curve"),
      },
      _ => bail!("Unsupported key type"),
    }
  }

  /// Convert to jwk
  pub fn to_jwk(&self) -> Result<serde_json::Value> {
    let kid = self.key_id();
    let jwk = match self {
      Self::Es256(vk) => JsonWebKey::from(vk),
      Self::Ed25519(vk) => JsonWebKey::from(vk),
    };
    let mut jwk = serde_json::to_value(jwk)?;
    jwk["kid"] = serde_json::Value::String(kid);
    Ok(jwk)
  }
  /// Create key id
  pub fn key_id(&self) -> String {
    use base64::{engine::general_purpose, Engine as _};

    let bytes = match self {
      Self::Es256(vk) => vk.to_encoded_point(true).as_bytes().to_vec(),
      Self::Ed25519(vk) => vk.as_ref().to_vec(),
    };
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    general_purpose::URL_SAFE_NO_PAD.encode(hash)
  }

  /// Validate JWT
  pub fn validate<T>(&self, token: &IdToken, opt: &ValidationOptions<T>) -> Result<Claims>
  where
    T: Fn() -> DateTime<Utc>,
  {
    // Parse the token.
    let token = UntrustedToken::new(token.as_str())?;
    // Verify signature
    let token = match &self {
      Self::Es256(key) => Es256.validator::<JWTClaims>(key).validate(&token)?,
      Self::Ed25519(key) => Ed25519.validator::<JWTClaims>(key).validate(&token)?,
    };
    // validate time
    let claims = token
      .claims()
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
    Ok(claims.to_owned())
  }
}

#[cfg(test)]
mod tests {
  use chrono::{DateTime, Duration};
  use jwt_compact::TimeOptions;

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
    let ed25519 = PemTokenPair{
      pem : "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=\n-----END PUBLIC KEY-----\n",
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
      id_token: "eyJhbGciOiJFZERTQSIsImtpZCI6ImdqckU3QUNNeGd6WWZGSGdhYmdmNGtMVGcxZUtJZHNKOTRBaUZURmoxaXMiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjUsImV4cCI6MTY5OTYyNzkyNSwibmJmIjoxNjk5NjI2MTI1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6ImY2ZDMzNmVlLWFjNDgtNGNlYy04MTYzLTI5OThlMTc4YWVlMyIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.GVJhFknZP5iWe0fKoUJO-Wfg1Ti0ayb7mjUEWvfYhQXwM_dYt39nICiebLEQr3vqctxdyKO8PlXxFpe9bI6bCg"
    };

    let es256 = JwkTokenPair{
      jwk: "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"RmLDHtAk-qSMqcEb6CZSzbOPnE4dii-31DW-YulmysY\",\"y\":\"SkCg77pPekwEbljDv7w24ZO--2tkBd24DaCI_FDzMJ8\"}",
      id_token: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImszNHIzTnFmYWs2N2JoSlNYVGpUUm81dENJcjFCc3JlMWNQb0ozTEo5eEUiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjIsImV4cCI6MTY5OTYyNzkyMiwibmJmIjoxNjk5NjI2MTIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6IjZhMDJlNTRiLTk3NGEtNDViYy04ZDlhLWZhYzQzNzdhMDQ5MiIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.6O6wBd51zO-wZv7Y5r99NSqbEXg1XZtjhCW_FtvScZ8sPIOiU8GTHMfPxVriDyhiAC_W7NEOMZx-4myIeDiZCA"
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
}
