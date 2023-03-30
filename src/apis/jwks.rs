use crate::{jwt::JwtSigningKey, log::*, state::AppState};
use axum::{
  extract::State,
  http::StatusCode,
  response::{IntoResponse, Response},
  Json,
};
use jwt_compact::{
  alg::{Ed25519, Es256, VerifyingKey},
  jwk::JsonWebKey,
  Algorithm,
};
use jwt_simple::{algorithms::ECDSAP256PublicKeyLike, prelude::EdDSAPublicKeyLike};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
#[derive(Serialize)]
pub struct Jwks {
  pub keys: Option<Vec<serde_json::Value>>,
}

#[derive(Debug)]
pub enum JwksError {
  SerializationFailure,
  InvalidPublicKeys,
}
impl IntoResponse for JwksError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      JwksError::SerializationFailure => (StatusCode::INTERNAL_SERVER_ERROR, "Key serialization failure"),
      JwksError::InvalidPublicKeys => (StatusCode::INTERNAL_SERVER_ERROR, "Invalid public keys"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn jwks(State(state): State<Arc<AppState>>) -> Result<Json<Jwks>, JwksError> {
  let current_public_jwk = match &state.crypto.signing_key {
    JwtSigningKey::ES256(sk) => {
      let pk = sk.public_key();
      let kid = pk.key_id();
      type PublicKey = <Es256 as Algorithm>::VerifyingKey;
      let Ok(public_key) = <PublicKey as VerifyingKey<Es256>>::from_slice(&pk.to_bytes()) else {
        return Err(JwksError::InvalidPublicKeys);
      };
      let ecjwk = JsonWebKey::from(&public_key);
      let Ok(mut val ) = serde_json::from_str::<serde_json::Value>(ecjwk.to_string().as_ref()) else {
        return Err(JwksError::SerializationFailure);
      };
      if let Some(id) = kid {
        val["kid"] = serde_json::Value::String(id.to_string());
      }
      val
    }
    JwtSigningKey::EdDSA(sk) => {
      let pk = sk.public_key();
      let kid = pk.key_id();

      type PublicKey = <Ed25519 as Algorithm>::VerifyingKey;
      let Ok(public_key) = <PublicKey as VerifyingKey<Ed25519>>::from_slice(&pk.to_bytes()) else {
        return Err(JwksError::InvalidPublicKeys);
      };
      let edjwk = JsonWebKey::from(&public_key);
      let Ok(mut val ) = serde_json::from_str::<serde_json::Value>(edjwk.to_string().as_ref()) else {
        return Err(JwksError::SerializationFailure);
      };
      if let Some(id) = kid {
        val["kid"] = serde_json::Value::String(id.to_string());
      }
      val
    }
  };

  let jwks = Jwks {
    keys: Some(vec![current_public_jwk]),
  };

  Ok(Json(jwks))
}
