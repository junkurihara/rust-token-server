use crate::constants::*;
use crate::db::UserInfo;
use crate::error::*;
use crate::globals::Globals;
use base64;
use chrono::{DateTime, Local, TimeZone};
use jwt_simple::prelude::*;
use p256;
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rocket::serde::Serialize;
use rocket::State;
use serde_json::Value;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

#[derive(Serialize, Debug, Clone)]
pub struct Token {
  pub id: String, // jwt itself is given here
  pub refresh: Option<String>,
  pub issued_at: String,
  pub expires: String,
  pub allowed_apps: Vec<String>, // allowed apps, i.e, client_ids
  pub issuer: String,            // like 'https://....' for IdToken
  pub subscriber_id: String,
}

#[derive(Serialize, Debug, Clone)]
pub struct TokenMetaData {
  username: String,
  is_admin: bool,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AdditionalClaimData {
  pub is_admin: bool,
}

pub fn generate_jwt(
  user_info: &UserInfo,
  client_id: &str,
  globals: &State<Arc<Globals>>,
  refresh_required: bool,
) -> Result<(Token, TokenMetaData), Error> {
  let addition = AdditionalClaimData {
    is_admin: *user_info.clone().is_admin(),
  };
  let mut audiences = HashSet::new();
  audiences.insert(client_id);
  let claims = Claims::with_custom_claims(addition, Duration::from_mins(JWT_DURATION_MINS as u64))
    .with_subject(user_info.get_subscriber_id())
    .with_issuer(&globals.token_issuer)
    .with_audiences(audiences);
  let (generated_jwt, iat, exp, iss, aud) = &globals.signing_key.generate_token(claims)?;
  info!(
    "[{}] Issued a JWT for sub: {} with iat: {}, exp: {}, iss: {}, aud: {:?}",
    user_info.get_username(),
    user_info.get_subscriber_id(),
    iat,
    exp,
    iss,
    aud
  );
  let refresh: Option<String> = match refresh_required {
    true => {
      let refresh_string = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(REFRESH_TOKEN_LEN)
        .map(char::from)
        .collect();
      debug!(
        "[{}] Created refresh token: {}",
        user_info.get_username(),
        refresh_string
      );
      Some(refresh_string)
    }
    _ => None,
  };

  return Ok((
    Token {
      id: generated_jwt.to_string(),
      refresh,
      issuer: iss.to_string(),
      allowed_apps: aud.to_vec(),
      issued_at: iat.to_string(),
      expires: exp.to_string(),
      subscriber_id: user_info.get_subscriber_id().to_string(),
    },
    TokenMetaData {
      username: user_info.get_username().to_string(),
      is_admin: *user_info.is_admin(),
    },
  ));
}

#[derive(Debug, Clone)]
pub enum Algorithm {
  ES256,
  // HS256,
  // HS384,
  // HS512,
}
impl FromStr for Algorithm {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self, Error> {
    match s {
      // "HS256" => Ok(Algorithm::HS256),
      // "HS384" => Ok(Algorithm::HS384),
      // "HS512" => Ok(Algorithm::HS512),
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
  // RSA,
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
  // HS256(HS256Key),
  // HS384(HS384Key),
  // HS512(HS512Key),
}

impl JwtSigningKey {
  pub fn new(
    validation_algorithm: &Algorithm,
    key_str: &str,
    with_key_id: bool,
  ) -> Result<Self, Error> {
    let signing_key = match validation_algorithm {
      // Algorithm::HS256 => {
      //   let mut k = HS256Key::from_bytes(key_str.as_ref());
      //   if with_key_id {
      //     k.create_key_id();
      //   };
      //   JwtSigningKey::HS256(k)
      // }
      // Algorithm::HS384 => {
      //   let mut k = HS384Key::from_bytes(key_str.as_ref());
      //   if with_key_id {
      //     k.create_key_id();
      //   };
      //   JwtSigningKey::HS384(k)
      // }
      // Algorithm::HS512 => {
      //   let mut k = HS512Key::from_bytes(key_str.as_ref());
      //   if with_key_id {
      //     k.create_key_id();
      //   };
      //   JwtSigningKey::HS512(k)
      // }
      Algorithm::ES256 => {
        let private_key: Result<p256::SecretKey, p256::pkcs8::Error> =
          p256::pkcs8::FromPrivateKey::from_pkcs8_pem(key_str);
        if let Ok(unwrapped) = private_key {
          let keypair = ES256KeyPair::from_bytes(&unwrapped.to_bytes())?;
          if with_key_id {
            let mut pk = keypair.public_key();
            JwtSigningKey::ES256(keypair.with_key_id(pk.create_key_id()))
          } else {
            JwtSigningKey::ES256(keypair)
          }
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
  ) -> Result<(String, String, String, String, Vec<String>), Error> {
    let generated_jwt = match self {
      JwtSigningKey::ES256(pk) => pk.sign(claims),
      // JwtSigningKey::HS256(pk) => pk.authenticate(claims),
      // JwtSigningKey::HS384(pk) => pk.authenticate(claims),
      // JwtSigningKey::HS512(pk) => pk.authenticate(claims),
      // _ => {
      //   bail!("Unsupported key");
      // }
    }?;
    // get token info
    let parsed: Vec<&str> = (&generated_jwt).split(".").collect();
    let decoded_claims = base64::decode(parsed[1])?;
    // debug!("{:?}", String::from_utf8(base64::decode(parsed[0])?)?);
    let json_string = String::from_utf8(decoded_claims)?;
    let json_value: Value = serde_json::from_str(&json_string).map_err(|e| anyhow!("{}", e))?;

    let iat = (&json_value["iat"]).to_string().parse::<i64>()?;
    let exp = (&json_value["exp"]).to_string().parse::<i64>()?;
    let iss = match (&json_value["iss"]).as_str() {
      None => bail!("No issuer is specified in JWT"),
      Some(i) => i.to_string(),
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

    let issued_at: DateTime<Local> = Local.timestamp(iat, 0);
    let expires: DateTime<Local> = Local.timestamp(exp, 0);
    return Ok((
      generated_jwt,
      issued_at.to_string(),
      expires.to_string(),
      iss,
      aud,
    ));
  }

  pub fn verify_token(
    &self,
    token: &str,
    globals: &Arc<Globals>,
  ) -> Result<JWTClaims<AdditionalClaimData>, Error> {
    let mut options = VerificationOptions::default();
    if let Some(allowed) = &globals.allowed_client_ids {
      options.allowed_audiences = Some(HashSet::from_strings(&allowed));
    }
    options.allowed_issuers = Some(HashSet::from_strings(&vec![&globals.token_issuer]));
    // debug!("options: {:?}", options);
    let verified = match self {
      JwtSigningKey::ES256(sk) => sk
        .public_key()
        .verify_token::<AdditionalClaimData>(token, Some(options)),
      // JwtSigningKey::HS256(k) => k.verify_token::<AdditionalClaimData>(token, Some(options)),
      // JwtSigningKey::HS384(k) => k.verify_token::<AdditionalClaimData>(token, Some(options)),
      // JwtSigningKey::HS512(k) => k.verify_token::<AdditionalClaimData>(token, Some(options)),
      // _ => {
      //   bail!("Unsupported key");
      // }
    };

    return verified;
  }
}
