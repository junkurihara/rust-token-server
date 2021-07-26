use crate::constants::*;
use crate::db::UserInfo;
use crate::error::*;
use crate::globals::Globals;
use base64;
use chrono::{DateTime, Local, TimeZone};
use jwt_simple::prelude::*;
use p256;
use rocket::serde::Serialize;
use rocket::State;
use serde_json::Value;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Serialize, Debug, Clone)]
pub struct Token {
  issued_at: String,
  expires: String,
  id: String, // jwt itself is given here
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdditionalClaimData {
  pub is_admin: bool,
}

pub fn generate_jwt(user_info: &UserInfo, globals: &State<Arc<Globals>>) -> Result<Token, Error> {
  let addition = AdditionalClaimData {
    is_admin: *user_info.clone().is_admin(),
  };
  let claims = Claims::with_custom_claims(addition, Duration::from_days(JWT_DURATION_DAYS as u64))
    .with_subject(user_info.get_username());
  let (generated_jwt, iat, exp) = &globals.signing_key.generate_token(claims)?;
  info!(
    "Issued a JWT for {} with iat: {}, exp: {}",
    user_info.get_username(),
    iat,
    exp
  );

  return Ok(Token {
    issued_at: iat.to_string(),
    expires: exp.to_string(),
    id: generated_jwt.to_string(),
  });
}

#[derive(Debug, Clone)]
pub enum Algorithm {
  ES256,
  HS256,
  HS384,
  HS512,
}
impl FromStr for Algorithm {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Error> {
    match s {
      "HS256" => Ok(Algorithm::HS256),
      "HS384" => Ok(Algorithm::HS384),
      "HS512" => Ok(Algorithm::HS512),
      "ES256" => Ok(Algorithm::ES256),
      // "ES384" => Ok(Algorithm::ES384),
      // "RS256" => Ok(Algorithm::RS256),
      // "RS384" => Ok(Algorithm::RS384),
      // "PS256" => Ok(Algorithm::PS256),
      // "PS384" => Ok(Algorithm::PS384),
      // "PS512" => Ok(Algorithm::PS512),
      // "RS512" => Ok(Algorithm::RS512),
      _ => bail!("Invalid Algorithm Name"),
    }
  }
}
#[derive(Debug, Clone)]
pub enum AlgorithmType {
  ECC,
  HMAC,
  RSA,
}
impl Algorithm {
  pub fn get_type(&self) -> AlgorithmType {
    match self {
      Algorithm::ES256 => AlgorithmType::ECC,
      _ => AlgorithmType::HMAC,
    }
  }
}

pub enum JwtSigningKey {
  ES256(ES256KeyPair),
  HS256(HS256Key),
  HS384(HS384Key),
  HS512(HS512Key),
}

impl JwtSigningKey {
  pub fn new(validation_algorithm: &Algorithm, key_str: &str) -> Result<Self, Error> {
    let signing_key = match validation_algorithm {
      Algorithm::HS256 => JwtSigningKey::HS256(HS256Key::from_bytes(key_str.as_ref())),
      Algorithm::HS384 => JwtSigningKey::HS384(HS384Key::from_bytes(key_str.as_ref())),
      Algorithm::HS512 => JwtSigningKey::HS512(HS512Key::from_bytes(key_str.as_ref())),
      Algorithm::ES256 => {
        let private_key: Result<p256::SecretKey, p256::pkcs8::Error> =
          p256::pkcs8::FromPrivateKey::from_pkcs8_pem(key_str);
        if let Ok(unwrapped) = private_key {
          let keypair = ES256KeyPair::from_bytes(&unwrapped.to_bytes())?;
          JwtSigningKey::ES256(keypair)
        } else {
          bail!("Unsupported key format");
        }
      } // _ => {
        //   bail!("Unsupported Key Type");
        // }
    };
    Ok(signing_key)
  }

  pub fn generate_token(
    &self,
    claims: JWTClaims<AdditionalClaimData>,
  ) -> Result<(String, String, String), Error> {
    let generated_jwt = match self {
      JwtSigningKey::ES256(pk) => pk.sign(claims),
      JwtSigningKey::HS256(pk) => pk.authenticate(claims),
      JwtSigningKey::HS384(pk) => pk.authenticate(claims),
      JwtSigningKey::HS512(pk) => pk.authenticate(claims),
      _ => {
        bail!("Unsupported key");
      }
    }?;
    // get token info
    let parsed: Vec<&str> = (&generated_jwt).split(".").collect();
    let decoded_claims = base64::decode(parsed[1])?;
    let json_string = String::from_utf8(decoded_claims)?;
    let json_value: Value = serde_json::from_str(&json_string).map_err(|e| anyhow!("{}", e))?;

    let iat = (&json_value["iat"]).to_string().parse::<i64>()?;
    let exp = (&json_value["exp"]).to_string().parse::<i64>()?;

    let issued_at: DateTime<Local> = Local.timestamp(iat, 0);
    let expires: DateTime<Local> = Local.timestamp(exp, 0);
    return Ok((generated_jwt, issued_at.to_string(), expires.to_string()));
  }

  pub fn verify_token(&self, token: &str) -> Result<JWTClaims<AdditionalClaimData>, Error> {
    let verified = match self {
      JwtSigningKey::ES256(sk) => sk
        .public_key()
        .verify_token::<AdditionalClaimData>(token, None),
      JwtSigningKey::HS256(k) => k.verify_token::<AdditionalClaimData>(token, None),
      JwtSigningKey::HS384(k) => k.verify_token::<AdditionalClaimData>(token, None),
      JwtSigningKey::HS512(k) => k.verify_token::<AdditionalClaimData>(token, None),
      _ => {
        bail!("Unsupported key");
      }
    };

    return verified;
  }
}
