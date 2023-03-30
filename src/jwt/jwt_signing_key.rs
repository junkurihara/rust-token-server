use super::{
  alg::Algorithm,
  token_with_meta::{Token, TokenInner, TokenMetaData},
};
use crate::{constants::*, db::entity::*, error::*, log::*};
use base64::Engine;
use chrono::{DateTime, Local, TimeZone};
use jwt_simple::prelude::*;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug)]
pub struct AdditionalClaimData {
  pub is_admin: bool,
}

pub enum JwtSigningKey {
  EdDSA(Ed25519KeyPair),
  ES256(ES256KeyPair),
}

impl JwtSigningKey {
  pub fn new(validation_algorithm: &Algorithm, key_str: &str, with_key_id: bool) -> Result<Self> {
    let signing_key = match validation_algorithm {
      Algorithm::ES256 => {
        let keypair = jwt_simple::algorithms::ES256KeyPair::from_pem(key_str)
          .map_err(|e| anyhow!("Error decoding private key: {}", e))?;
        if with_key_id {
          let mut pk = keypair.public_key();
          JwtSigningKey::ES256(keypair.with_key_id(pk.create_key_id()))
        } else {
          JwtSigningKey::ES256(keypair)
        }
      }
      Algorithm::EdDSA => {
        let keypair = jwt_simple::algorithms::Ed25519KeyPair::from_pem(key_str)
          .map_err(|e| anyhow!("Error decoding private key: {}", e))?;
        if with_key_id {
          let mut pk = keypair.public_key();
          JwtSigningKey::EdDSA(keypair.with_key_id(pk.create_key_id()))
        } else {
          JwtSigningKey::EdDSA(keypair)
        }
      }
    };
    Ok(signing_key)
  }

  pub fn public_jwk(&self) -> Result<Value> {
    use jwt_compact::{
      alg::{Ed25519, Es256, VerifyingKey},
      jwk::JsonWebKey,
      Algorithm,
    };
    let (jwk, kid_opt) = match self {
      JwtSigningKey::ES256(sk) => {
        let pk = sk.public_key();
        let kid = pk.key_id().to_owned();
        type PublicKey = <Es256 as Algorithm>::VerifyingKey;
        let public_key = <PublicKey as VerifyingKey<Es256>>::from_slice(&pk.to_bytes())?;

        let jwk = JsonWebKey::from(&public_key);
        let jwk = serde_json::from_str::<serde_json::Value>(jwk.to_string().as_ref())?;
        (jwk, kid)
      }
      JwtSigningKey::EdDSA(sk) => {
        let pk = sk.public_key();
        let kid = pk.key_id().to_owned();

        type PublicKey = <Ed25519 as Algorithm>::VerifyingKey;
        let public_key = <PublicKey as VerifyingKey<Ed25519>>::from_slice(&pk.to_bytes())?;
        let jwk = JsonWebKey::from(&public_key);
        let jwk = serde_json::from_str::<serde_json::Value>(jwk.to_string().as_ref())?;
        (jwk, kid)
      }
    };
    let mut jwk = serde_json::from_str::<serde_json::Value>(jwk.to_string().as_ref())?;
    if let Some(kid) = kid_opt {
      jwk["kid"] = serde_json::Value::String(kid);
    }
    Ok(jwk)
  }

  pub fn generate_token_with_meta(
    &self,
    user: &User,
    client_id: &str,
    token_issuer: &str,
    refresh_required: bool,
  ) -> Result<Token> {
    let addition = AdditionalClaimData {
      is_admin: user.is_admin(),
    };
    let mut audiences = HashSet::new();
    audiences.insert(client_id);
    let claims = Claims::with_custom_claims(addition, Duration::from_mins(JWT_DURATION_MINS as u64))
      .with_subject(user.subscriber_id())
      .with_issuer(token_issuer)
      .with_audiences(audiences);
    let (generated_jwt, iat, exp, iss, aud) = self.generate_token(claims)?;
    info!(
      "[{}] Issued a JWT for sub: {} with iat: {}, exp: {}, iss: {}, aud: {:?}",
      user.username(),
      user.subscriber_id(),
      iat,
      exp,
      iss,
      aud
    );
    let refresh: Option<String> = if refresh_required {
      let refresh_string = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(REFRESH_TOKEN_LEN)
        .map(char::from)
        .collect();
      debug!("[{}] Created refresh token: {}", user.username(), refresh_string);
      Some(refresh_string)
    } else {
      None
    };

    return Ok(Token {
      inner: TokenInner {
        id: generated_jwt,
        refresh,
        issuer: iss,
        allowed_apps: aud.to_vec(),
        issued_at: iat,
        expires: exp,
        subscriber_id: user.subscriber_id().to_string(),
      },
      meta: TokenMetaData {
        username: user.username().to_owned(),
        is_admin: user.is_admin(),
      },
    });
  }

  pub fn generate_token(
    &self,
    claims: JWTClaims<AdditionalClaimData>,
  ) -> Result<(String, String, String, String, Vec<String>)> {
    let generated_jwt = match self {
      JwtSigningKey::EdDSA(pk) => pk.sign(claims),
      JwtSigningKey::ES256(pk) => pk.sign(claims),
    }?;
    // get token info
    let parsed: Vec<&str> = generated_jwt.split('.').collect();
    let decoded_claims =
      base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, base64::engine::general_purpose::NO_PAD)
        .decode(parsed[1])?;
    // debug!("{:?}", String::from_utf8(base64::decode(parsed[0])?)?);
    let json_string = String::from_utf8(decoded_claims)?;
    let json_value: Value = serde_json::from_str(&json_string).map_err(|e| anyhow!("{}", e))?;

    let iat = json_value["iat"].to_string().parse::<i64>()?;
    let exp = json_value["exp"].to_string().parse::<i64>()?;
    let iss = if let Some(i) = json_value["iss"].as_str() {
      i.to_string()
    } else {
      bail!("No issuer is specified in JWT");
    };
    let aud = if let Value::Array(aud_vec) = &json_value["aud"] {
      aud_vec
        .iter()
        .filter_map(|x| x.as_str())
        .map(|y| y.to_string())
        .collect()
    } else {
      vec![]
    };

    let issued_at: DateTime<Local> = Local.timestamp_opt(iat, 0).unwrap();
    let expires: DateTime<Local> = Local.timestamp_opt(exp, 0).unwrap();
    Ok((generated_jwt, issued_at.to_string(), expires.to_string(), iss, aud))
  }

  pub fn verify_token(
    &self,
    token: &str,
    token_issuer: &str,
    allowed_client_ids: &Option<Vec<String>>,
  ) -> Result<JWTClaims<AdditionalClaimData>> {
    let mut options = VerificationOptions::default();
    if let Some(allowed) = allowed_client_ids {
      options.allowed_audiences = Some(HashSet::from_strings(allowed));
    }
    options.allowed_issuers = Some(HashSet::from_strings(&[token_issuer]));
    match self {
      JwtSigningKey::ES256(sk) => sk
        .public_key()
        .verify_token::<AdditionalClaimData>(token, Some(options)),
      JwtSigningKey::EdDSA(sk) => sk
        .public_key()
        .verify_token::<AdditionalClaimData>(token, Some(options)),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  const P256_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv7zxW56ojrWwmSo1\n4uOdbVhUfj9Jd+5aZIB9u8gtWnihRANCAARGYsMe0CT6pIypwRvoJlLNs4+cTh2K\nL7fUNb5i6WbKxkpAoO+6T3pMBG5Yw7+8NuGTvvtrZAXduA2giPxQ8zCf\n-----END PRIVATE KEY-----";
  const EDDSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C\n-----END PRIVATE KEY-----";

  #[test]
  fn test_generate_and_verify() {
    init_logger();
    let user = User::new(&Username::new("test_user").unwrap(), None);
    assert!(user.is_ok());
    let user = user.unwrap();

    let client_id = "client_id";
    let token_issuer = "issuer";
    let refresh_required = true;

    let keys = [P256_PRIVATE_KEY, EDDSA_PRIVATE_KEY];
    let algs = [Algorithm::ES256, Algorithm::EdDSA];
    for (alg, key_str) in algs.iter().zip(keys.iter()) {
      let signing_key = JwtSigningKey::new(alg, key_str, false).unwrap();
      let token = signing_key.generate_token_with_meta(&user, client_id, token_issuer, refresh_required);
      assert!(token.is_ok());

      let id_token = token.unwrap().inner.id;
      let validation_result = signing_key.verify_token(&id_token, token_issuer, &None);
      assert!(validation_result.is_ok());
    }
  }
}
