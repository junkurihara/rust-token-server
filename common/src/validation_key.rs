use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use jwt_compact::{
  alg::{Ed25519, Es256},
  jwk::JsonWebKey,
  Algorithm, AlgorithmExt, Claims, TimeOptions, UntrustedToken,
};
use std::collections::HashSet;

pub type JWTClaims = serde_json::Map<String, serde_json::Value>;

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
  pub allowed_issuers: Option<HashSet<String>>,
  pub allowed_audiences: Option<HashSet<String>>,
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
  // #[allow(dead_code)]
  // /// Convert from pem string
  // pub fn from_pem(pem: &str) -> Result<Self> {
  //   let (_s, doc) = Document::from_pem(pem)?;
  //   let alg = SubjectPublicKeyInfoRef::from_der(doc.as_bytes())?.algorithm;
  //   match alg.oid.to_string().as_ref() {
  //     // ec
  //     algorithm_oids::EC => {
  //       let param = alg.parameters_oid()?;
  //       match param.to_string().as_ref() {
  //         // prime256v1 = es256
  //         params_oids::Prime256v1 => {
  //           let inner = DecodingKey::from_ec_pem(pem.as_ref())?;
  //           Ok(Self {
  //             inner,
  //             algorithm: Algorithm::ES256,
  //           })
  //         }
  //         _ => bail!(ValidationError::UnsupportedValidationKey),
  //       }
  //     }
  //     // ed25519
  //     algorithm_oids::Ed25519 => {
  //       let inner = DecodingKey::from_ed_pem(pem.as_ref())?;
  //       Ok(Self {
  //         inner,
  //         algorithm: Algorithm::EdDSA,
  //       })
  //     }
  //     _ => bail!(ValidationError::UnsupportedValidationKey),
  //   }
  // }
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

  /// Validate JWT
  pub fn validate<T>(&self, token: &str, opt: &ValidationOptions<T>) -> Result<Claims<JWTClaims>>
  where
    T: Fn() -> DateTime<Utc>,
  {
    // Parse the token.
    let token = UntrustedToken::new(token)?;
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
      if !issuers.contains(iss) {
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
          if !audiences.contains(aud) {
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
            .collect::<Vec<_>>();
          if !aud.iter().any(|v| audiences.contains(*v)) {
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

  // #[test]
  // fn test_es256_pem() -> std::result::Result<(), anyhow::Error> {
  //   let pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAERmLDHtAk+qSMqcEb6CZSzbOPnE4d\nii+31DW+YulmysZKQKDvuk96TARuWMO/vDbhk777a2QF3bgNoIj8UPMwnw==\n-----END PUBLIC KEY-----\n";
  //   let id_token="eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTkyODcxNzYsImV4cCI6MTY5OTI4ODk3NiwibmJmIjoxNjk5Mjg3MTc2LCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdjEuMCIsInN1YiI6ImI2MjZmNTBlLTllYWUtNDlkOC04MjAxLTBhZmQyODNhZWNmZCIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjpmYWxzZX0.mmNxox_4nabjrlm-3AjDVX9U_tkQEKH5iHw3KSj22WnsmP4pKDEgZnVSWlxg3prLSfJZCfD3ZR1iiq6EFke45w";

  //   let vk = ValidationKey::from_pem(pem)?;
  //   assert!(matches!(vk, ValidationKey::ES256(_)));

  //   let mut iss = std::collections::HashSet::new();
  //   iss.insert("https://auth.example.com/v1.0".to_string());
  //   let mut aud = std::collections::HashSet::new();
  //   aud.insert("client_id1".to_string());
  //   let vo = VerificationOptions {
  //     artificial_time: Some(Duration::from_secs(1699286705)),
  //     allowed_issuers: Some(iss),
  //     allowed_audiences: Some(aud),
  //     ..Default::default()
  //   };
  //   let _res = vk.validate(id_token, Some(&vo))?;
  //   Ok(())
  // }

  #[test]
  fn test_es256_jwk() -> std::result::Result<(), anyhow::Error> {
    let jwk =  "{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"RmLDHtAk-qSMqcEb6CZSzbOPnE4dii-31DW-YulmysY\",\"y\":\"SkCg77pPekwEbljDv7w24ZO--2tkBd24DaCI_FDzMJ8\"}";
    let id_token= "eyJhbGciOiJFUzI1NiIsImtpZCI6ImszNHIzTnFmYWs2N2JoSlNYVGpUUm81dENJcjFCc3JlMWNQb0ozTEo5eEUiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjIsImV4cCI6MTY5OTYyNzkyMiwibmJmIjoxNjk5NjI2MTIyLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6IjZhMDJlNTRiLTk3NGEtNDViYy04ZDlhLWZhYzQzNzdhMDQ5MiIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.6O6wBd51zO-wZv7Y5r99NSqbEXg1XZtjhCW_FtvScZ8sPIOiU8GTHMfPxVriDyhiAC_W7NEOMZx-4myIeDiZCA";

    let jwk_val = serde_json::from_str::<serde_json::Value>(jwk)?;
    let vk = ValidationKey::from_jwk(&jwk_val)?;

    let mut iss = std::collections::HashSet::new();
    iss.insert("http://localhost:3000/v1.0".to_string());
    let mut aud = std::collections::HashSet::new();
    aud.insert("client_id1".to_string());

    let stopped_time = TimeOptions::new(Duration::seconds(10), move || {
      DateTime::from_timestamp(1699626347, 0).unwrap()
    });
    let vo = ValidationOptions {
      time_options: stopped_time,
      allowed_issuers: Some(iss),
      allowed_audiences: Some(aud),
    };
    let _res = vk.validate(id_token, &vo)?;

    Ok(())
  }
  // #[test]
  // fn test_ed25519_pem() -> std::result::Result<(), anyhow::Error> {
  //   let pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1ixMQcxO46PLlgQfYS46ivFd+n0CcDHSKUnuhm3i1O0=\n-----END PUBLIC KEY-----\n";
  //   let id_token: &str = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2OTkyODYzNjgsImV4cCI6MTY5OTI4ODE2OCwibmJmIjoxNjk5Mjg2MzY4LCJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20vdjEuMCIsInN1YiI6IjZiYmI2NGVhLTMyZmUtNGEyNi05MjhlLWZlODlmNTcxNTA0YiIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjpmYWxzZX0.e6D156U4pwalnWmZNK5fDBSjUDflmHQObAiHJLPYu7AS-x81RlO3sRsNoqHz47m0zxOBEFVA3esV74U6xwkyAw";

  //   let vk = ValidationKey::from_pem(pem)?;
  //   assert!(matches!(vk, ValidationKey::EdDSA(_)));

  //   let mut iss = std::collections::HashSet::new();
  //   iss.insert("https://auth.example.com/v1.0".to_string());
  //   let mut aud = std::collections::HashSet::new();
  //   aud.insert("client_id1".to_string());
  //   let vo = VerificationOptions {
  //     artificial_time: Some(Duration::from_secs(1699286705)),
  //     allowed_issuers: Some(iss),
  //     allowed_audiences: Some(aud),
  //     ..Default::default()
  //   };
  //   let _res = vk.validate(id_token, Some(&vo))?;
  //   Ok(())
  // }

  #[test]
  fn test_ed25519_jwk() -> std::result::Result<(), anyhow::Error> {
    let jwk = "{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"1ixMQcxO46PLlgQfYS46ivFd-n0CcDHSKUnuhm3i1O0\"}";
    let id_token= "eyJhbGciOiJFZERTQSIsImtpZCI6ImdqckU3QUNNeGd6WWZGSGdhYmdmNGtMVGcxZUtJZHNKOTRBaUZURmoxaXMiLCJ0eXAiOiJKV1QifQ.eyJpYXQiOjE2OTk2MjYxMjUsImV4cCI6MTY5OTYyNzkyNSwibmJmIjoxNjk5NjI2MTI1LCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjMwMDAvdjEuMCIsInN1YiI6ImY2ZDMzNmVlLWFjNDgtNGNlYy04MTYzLTI5OThlMTc4YWVlMyIsImF1ZCI6WyJjbGllbnRfaWQxIl0sImlzX2FkbWluIjp0cnVlfQ.GVJhFknZP5iWe0fKoUJO-Wfg1Ti0ayb7mjUEWvfYhQXwM_dYt39nICiebLEQr3vqctxdyKO8PlXxFpe9bI6bCg";

    let jwk_val = serde_json::from_str::<serde_json::Value>(jwk)?;
    let vk = ValidationKey::from_jwk(&jwk_val)?;

    let mut iss = std::collections::HashSet::new();
    iss.insert("http://localhost:3000/v1.0".to_string());
    let mut aud = std::collections::HashSet::new();
    aud.insert("client_id1".to_string());
    let stopped_time = TimeOptions::new(Duration::seconds(10), move || {
      DateTime::from_timestamp(1699626347, 0).unwrap()
    });
    let vo = ValidationOptions {
      time_options: stopped_time,
      allowed_issuers: Some(iss),
      allowed_audiences: Some(aud),
    };
    let _res = vk.validate(id_token, &vo)?;
    Ok(())
  }
}
