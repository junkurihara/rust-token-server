use crate::state::AppState;
use axum::{
  extract::State,
  http::StatusCode,
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

pub async fn blind_jwks(State(state): State<Arc<AppState>>) -> Result<Json<BlindJwks>, BlindJwksError> {
  let Ok(lock) = state.blind_crypto.signing_key.read() else {
    return Err(BlindJwksError::InvalidPublicKeys);
  };
  let Ok(current_public_jwk) = lock.to_public_key().to_jwk() else {
    return Err(BlindJwksError::InvalidPublicKeys);
  };

  let jwks = BlindJwks {
    keys: Some(vec![current_public_jwk]),
  };

  Ok(Json(jwks))
}
