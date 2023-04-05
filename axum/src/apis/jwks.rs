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

pub async fn jwks(State(state): State<Arc<AppState>>) -> Result<Json<Jwks>, JwksError> {
  let Ok(current_public_jwk) = state.crypto.keypair.public_jwk() else {
    return Err(JwksError::InvalidPublicKeys);
  };

  let jwks = Jwks {
    keys: Some(vec![current_public_jwk]),
  };

  Ok(Json(jwks))
}
