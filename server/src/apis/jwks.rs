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
pub struct Jwks {
  pub keys: Option<Vec<serde_json::Value>>,
}

#[derive(Debug)]
pub enum JwksError {
  InvalidPublicKeys,
}
impl IntoResponse for JwksError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      JwksError::InvalidPublicKeys => (StatusCode::INTERNAL_SERVER_ERROR, "Invalid public keys"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn jwks(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse, JwksError> {
  let Ok(current_public_jwk) = state.crypto.signing_key.validation_key().to_jwk() else {
    return Err(JwksError::InvalidPublicKeys);
  };

  let jwks = Jwks {
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
