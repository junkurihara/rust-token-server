use crate::{jwt::JwtSigningKey, Globals};
use jwt_simple::{algorithms::ECDSAP256PublicKeyLike, prelude::EdDSAPublicKeyLike};
use p256::PublicKey;
use rocket::{
  http::{ContentType, Status},
  serde::{json::Json, Serialize},
  State,
};
use std::sync::Arc;

#[derive(Serialize)]
pub struct Jwks {
  pub keys: Option<Vec<serde_json::Value>>,
}

#[get("/jwks")]
pub fn jwks(globals: &State<Arc<Globals>>) -> (Status, (ContentType, Json<Jwks>)) {
  let error_res = (Status::new(503), (ContentType::JSON, Json(Jwks { keys: None })));
  let current_public_jwk = match &globals.signing_key {
    JwtSigningKey::ES256(sk) => {
      let pk = sk.public_key();
      let kid = pk.key_id();
      let ecjwk = match PublicKey::from_sec1_bytes(&pk.to_bytes()) {
        Ok(p) => p.to_jwk(),
        Err(e) => {
          eprintln!("{}", e);
          return error_res;
        }
      };
      let mut val: serde_json::Value = match serde_json::from_str(&ecjwk.to_string()) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{}", e);
          return error_res;
        }
      };
      if let Some(id) = kid {
        val["kid"] = serde_json::Value::String(id.to_string());
      }
      val
    }
    JwtSigningKey::EdDSA(sk) => {
      let pk = sk.public_key();
      let kid = pk.key_id();
      let ecjwk = match PublicKey::from_sec1_bytes(&pk.to_bytes()) {
        Ok(p) => p.to_jwk(),
        Err(e) => {
          eprintln!("{}", e);
          return error_res;
        }
      };
      let mut val: serde_json::Value = match serde_json::from_str(&ecjwk.to_string()) {
        Ok(v) => v,
        Err(e) => {
          eprintln!("{}", e);
          return error_res;
        }
      };
      if let Some(id) = kid {
        val["kid"] = serde_json::Value::String(id.to_string());
      }
      val
    }
  };

  let jwks = vec![current_public_jwk];

  (Status::new(200), (ContentType::JSON, Json(Jwks { keys: Some(jwks) })))
}
