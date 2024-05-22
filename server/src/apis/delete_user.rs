use super::{request::DeleteUserRequest, response::MessageResponse};
use crate::{
  state::AppState,
  table::{UserSearchKey, UserTable},
  ADMIN_USERNAME,
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
pub enum DeleteUserError {
  UserDeletionFailed,
  UnauthorizedUser,
  MissingToken,
  InvalidToken,
  NoSuchUser,
  DeleteProhibitedUser,
}
impl IntoResponse for DeleteUserError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      DeleteUserError::UserDeletionFailed => (StatusCode::INTERNAL_SERVER_ERROR, "User deletion failed"),
      DeleteUserError::UnauthorizedUser => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      DeleteUserError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token"),
      DeleteUserError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
      DeleteUserError::NoSuchUser => (StatusCode::BAD_REQUEST, "No such user"),
      DeleteUserError::DeleteProhibitedUser => (StatusCode::BAD_REQUEST, "Delete prohibited user"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn delete_user(
  State(state): State<Arc<AppState>>,
  headers: HeaderMap,
  Json(request): Json<DeleteUserRequest>,
) -> Result<Json<MessageResponse>, DeleteUserError> {
  // First retrieve and verify bearer token
  let Some(Ok(bearer)) = headers.get("authorization").map(|v| v.to_str()) else {
    return Err(DeleteUserError::MissingToken);
  };
  let mut iter = bearer.split(' ');
  let token_str_opt = if let Some("Bearer") = iter.next() {
    iter.next()
  } else {
    return Err(DeleteUserError::MissingToken);
  };
  let Some(Ok(id_token)) = token_str_opt.map(IdToken::new) else {
    return Err(DeleteUserError::MissingToken);
  };
  let Ok(claims) = state.crypto.verify_token(&id_token) else {
    return Err(DeleteUserError::InvalidToken);
  };

  // is_admin must be true here
  if !claims.custom.get("iad").and_then(|v| v.as_bool()).unwrap_or(false) {
    return Err(DeleteUserError::UnauthorizedUser);
  }

  // just in case, check user existence
  let Some(Ok(sub)) = claims.custom.get("sub").and_then(|v| v.as_str()).map(SubscriberId::new) else {
    return Err(DeleteUserError::InvalidToken);
  };
  let Ok(opt) = state.table.user.find_user(UserSearchKey::SubscriberId(&sub)).await else {
    return Err(DeleteUserError::UserDeletionFailed);
  };
  let Some(request_user) = opt else {
    return Err(DeleteUserError::UnauthorizedUser);
  };
  if !request_user.is_admin() {
    return Err(DeleteUserError::InvalidToken);
  }

  // check if the user exist
  let target_username = &request.username;
  let Ok(u) = state.table.user.find_user(UserSearchKey::Username(target_username)).await else {
    return Err(DeleteUserError::UserDeletionFailed);
  };
  let Some(target_user) = u else {
    return Err(DeleteUserError::NoSuchUser);
  };
  // admin cannot remove himself
  if request_user.username() == target_user.username() || target_user.username() == ADMIN_USERNAME {
    return Err(DeleteUserError::DeleteProhibitedUser);
  }
  let Ok(_) = state.table.user.delete_user(UserSearchKey::Username(target_username)).await else {
    return Err(DeleteUserError::UserDeletionFailed);
  };
  Ok(Json(MessageResponse {
    message: "ok. deleted the user.".to_string(),
  }))
}
