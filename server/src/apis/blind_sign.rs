use super::{request::BlindSignRequest, response::BlindSignResponse};
use crate::{
  constants::DEFAUTL_CLIENT_ID,
  entity::Entity,
  log::*,
  state::AppState,
  table::{UserSearchKey, UserTable},
};
use axum::{
  extract::State,
  http::{HeaderMap, StatusCode},
  response::{IntoResponse, Response},
  Json,
};
use serde_json::json;
use std::sync::Arc;

use libcommon::{
  blind_sig::BlindedToken,
  token_fields::{ClientId, Field, IdToken, SubscriberId, TryNewField},
};

#[derive(Debug)]
pub enum BlindSignError {
  SignFailed,
  InvalidPassword,
  Argon2Failure,
  UnauthorizedClientApp,
  UnauthorizedUser,
  InvalidRequest,
  MissingToken,
  InvalidToken,
}
impl IntoResponse for BlindSignError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      BlindSignError::SignFailed => (StatusCode::INTERNAL_SERVER_ERROR, "Signature creation failed"),
      BlindSignError::InvalidPassword => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      BlindSignError::Argon2Failure => (StatusCode::INTERNAL_SERVER_ERROR, "Something failed in authentication"),
      BlindSignError::UnauthorizedClientApp => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      BlindSignError::UnauthorizedUser => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      BlindSignError::InvalidRequest => (StatusCode::BAD_REQUEST, "Invalid request"),
      BlindSignError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token"),
      BlindSignError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn blind_sign(
  State(state): State<Arc<AppState>>,
  headers: HeaderMap,
  Json(input): Json<BlindSignRequest>,
) -> Result<Json<BlindSignResponse>, BlindSignError> {
  // Either id/password or id token is required

  if let Some(auth) = input.auth {
    // found id/password, which is prioritized over the id token based verification
    debug!("Performing blind signing based on the authentication with id/password.");
    let (username, password) = (auth.username, auth.password);

    // check user existence
    let Ok(user) = state.table.user.find_user(UserSearchKey::Username(&username)).await else {
      return Err(BlindSignError::SignFailed);
    };
    let Some(user) = user else {
      return Err(BlindSignError::UnauthorizedUser);
    };
    // check allowed client ids if audience is some
    if state.crypto.audiences.is_some() {
      let Some(client_id) = input.client_id else {
        return Err(BlindSignError::InvalidRequest);
      };
      if !state.crypto.audiences.as_ref().unwrap().contains(&client_id) {
        return Err(BlindSignError::UnauthorizedClientApp);
      }
      debug!("{} is verified by client_id {}.", username.as_str(), client_id.as_str());
    } else if ClientId::new(DEFAUTL_CLIENT_ID).is_err() {
      return Err(BlindSignError::SignFailed);
    };

    // verify password
    let Ok(password_verified) = password.verify(&user.encoded_hash) else {
      return Err(BlindSignError::Argon2Failure);
    };
    if !password_verified {
      return Err(BlindSignError::InvalidPassword);
    }
  } else {
    debug!("Performing blind signing based on the authentication with id token.");
    let Some(Ok(bearer)) = headers.get("authorization").map(|v| v.to_str()) else {
      return Err(BlindSignError::MissingToken);
    };
    let mut iter = bearer.split(' ');
    let token_str_opt = if let Some("Bearer") = iter.next() {
      iter.next()
    } else {
      return Err(BlindSignError::MissingToken);
    };
    let Some(Ok(id_token)) = token_str_opt.map(IdToken::new) else {
      return Err(BlindSignError::MissingToken);
    };
    let Ok(claims) = state.crypto.verify_token(&id_token) else {
      return Err(BlindSignError::InvalidToken);
    };

    // just in case, check user existence
    let Some(Ok(sub)) = claims.custom.get("sub").and_then(|v| v.as_str()).map(SubscriberId::new) else {
      return Err(BlindSignError::InvalidToken);
    };
    let Ok(opt) = state.table.user.find_user(UserSearchKey::SubscriberId(&sub)).await else {
      return Err(BlindSignError::SignFailed);
    };
    if opt.is_none() {
      return Err(BlindSignError::UnauthorizedUser);
    };
  }

  let blinded_token = BlindedToken::new(&input.blinded_token_message.0, &input.blinded_token_options);

  // sign the blinded token
  let Ok(blind_signature) = state.blind_crypto.blind_sign(&blinded_token) else {
    return Err(BlindSignError::SignFailed);
  };

  let expires_at =
    state.blind_crypto.rotated_at.load(std::sync::atomic::Ordering::Relaxed) + state.blind_crypto.rotation_period.as_secs();

  Ok(Json(BlindSignResponse {
    blind_signature,
    expires_at,
    message: "ok".to_string(),
  }))
}
