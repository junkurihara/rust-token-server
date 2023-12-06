use super::{request::CreateUserRequest, response::MessageResponse};
use crate::{
  entity::*,
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

use libcommon::token_fields::{IdToken, SubscriberId, TryNewField};

#[derive(Debug)]
pub enum CreateUserError {
  UserCreationFailed,
  UnauthorizedUser,
  MissingToken,
  InvalidToken,
}
impl IntoResponse for CreateUserError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      CreateUserError::UserCreationFailed => (StatusCode::INTERNAL_SERVER_ERROR, "User creation failed"),
      CreateUserError::UnauthorizedUser => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      CreateUserError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token"),
      CreateUserError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn create_user(
  State(state): State<Arc<AppState>>,
  headers: HeaderMap,
  Json(request): Json<CreateUserRequest>,
) -> Result<Json<MessageResponse>, CreateUserError> {
  // First retrieve and verify bearer token
  let Some(Ok(bearer)) = headers.get("authorization").map(|v| v.to_str()) else {
    return Err(CreateUserError::MissingToken);
  };
  let mut iter = bearer.split(' ');
  let token_str_opt = if let Some("Bearer") = iter.next() {
    iter.next()
  } else {
    return Err(CreateUserError::MissingToken);
  };
  let Some(Ok(id_token)) = token_str_opt.map(IdToken::new) else {
    return Err(CreateUserError::MissingToken);
  };
  let Ok(claims) = state.crypto.verify_token(&id_token) else {
    return Err(CreateUserError::InvalidToken);
  };

  // is_admin must be true here
  if !claims.custom.get("is_admin").and_then(|v| v.as_bool()).unwrap_or(false) {
    return Err(CreateUserError::UnauthorizedUser);
  }

  // just in case, check user existence
  let Some(Ok(sub)) = claims
    .custom
    .get("subscriber_id")
    .and_then(|v| v.as_str())
    .map(SubscriberId::new)
  else {
    return Err(CreateUserError::InvalidToken);
  };
  let Ok(opt) = state.table.user.find_user(UserSearchKey::SubscriberId(&sub)).await else {
    return Err(CreateUserError::UserCreationFailed);
  };
  let Some(u) = opt else {
    return Err(CreateUserError::UnauthorizedUser);
  };
  if !u.is_admin() {
    return Err(CreateUserError::InvalidToken);
  }

  // add if new user doesn't exist
  let Ok(new_user) = User::new(&request.auth.username, Some(request.auth.password)) else {
    return Err(CreateUserError::UserCreationFailed);
  };
  let Ok(_) = state.table.user.add(new_user).await else {
    return Err(CreateUserError::UserCreationFailed);
  };

  Ok(Json(MessageResponse {
    message: "ok. created the user.".to_string(),
  }))
}
