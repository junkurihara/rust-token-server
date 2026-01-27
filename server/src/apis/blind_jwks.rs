use crate::state::AppState;
use axum::{
  extract::State,
  http::{header, HeaderValue, StatusCode},
  response::{IntoResponse, Response},
  Json,
};
use serde::Serialize;
use serde_json::json;
use std::sync::Arc;
#[derive(Serialize)]
pub struct BlindJwks {
  pub keys: Option<Vec<serde_json::Value>>,
}

#[derive(Debug)]
pub enum BlindJwksError {
  InvalidPublicKeys,
}
impl IntoResponse for BlindJwksError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      BlindJwksError::InvalidPublicKeys => (StatusCode::INTERNAL_SERVER_ERROR, "Invalid public keys for blind signature"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn blind_jwks(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, BlindJwksError> {
  let Ok(lock) = state.blind_crypto.signing_key.read() else {
    return Err(BlindJwksError::InvalidPublicKeys);
  };
  let Ok(current_public_jwk) = lock.to_public_key().to_jwk() else {
    return Err(BlindJwksError::InvalidPublicKeys);
  };

  let jwks = BlindJwks {
    keys: Some(vec![current_public_jwk]),
  };

  let headers = [
    (
      header::CACHE_CONTROL,
      HeaderValue::from_static("no-store, no-cache, must-revalidate, max-age=0"),
    ),
    (header::PRAGMA, HeaderValue::from_static("no-cache")),
    (header::EXPIRES, HeaderValue::from_static("0")),
  ];

  Ok((StatusCode::OK, headers, Json(jwks)))
}
