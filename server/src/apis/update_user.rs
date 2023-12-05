use super::{request::UpdateUserRequest, response::MessageResponse};
use crate::{
  constants::ADMIN_USERNAME,
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
pub enum UpdateUserError {
  UserUpdateFailed,
  UnauthorizedUser,
  MissingToken,
  InvalidToken,
  ChangeAdminNameProhibited,
}
impl IntoResponse for UpdateUserError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      UpdateUserError::UserUpdateFailed => (StatusCode::INTERNAL_SERVER_ERROR, "User update failed"),
      UpdateUserError::UnauthorizedUser => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      UpdateUserError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token"),
      UpdateUserError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
      UpdateUserError::ChangeAdminNameProhibited => (
        StatusCode::BAD_REQUEST,
        "Changing the admin name 'admin' is not allowed.",
      ),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn update_user(
  State(state): State<Arc<AppState>>,
  headers: HeaderMap,
  Json(request): Json<UpdateUserRequest>,
) -> Result<Json<MessageResponse>, UpdateUserError> {
  // First retrieve and verify bearer token
  let Some(Ok(bearer)) = headers.get("authorization").map(|v| v.to_str()) else {
    return Err(UpdateUserError::MissingToken);
  };
  let mut iter = bearer.split(' ');
  let token_str_opt = if let Some("Bearer") = iter.next() {
    iter.next()
  } else {
    return Err(UpdateUserError::MissingToken);
  };
  let Some(Ok(id_token)) = token_str_opt.map(IdToken::new) else {
    return Err(UpdateUserError::MissingToken);
  };
  let Ok(claims) = state.crypto.verify_token(&id_token) else {
    return Err(UpdateUserError::InvalidToken);
  };

  // just in case, check user existence
  let Some(Ok(sub)) = claims.subject.map(SubscriberId::new) else {
    return Err(UpdateUserError::InvalidToken);
  };
  let Ok(opt) = state.table.user.find_user(UserSearchKey::SubscriberId(&sub)).await else {
    return Err(UpdateUserError::UserUpdateFailed);
  };
  let Some(u) = opt else {
    return Err(UpdateUserError::UnauthorizedUser);
  };
  // admin cannot change username
  if u.username() == ADMIN_USERNAME && request.auth.username.is_some() {
    return Err(UpdateUserError::ChangeAdminNameProhibited);
  }

  // update the user itself for the given subscriber_id
  let Ok(_) = state
    .table
    .user
    .update_user(&sub, request.auth.username.as_ref(), request.auth.password.as_ref())
    .await
  else {
    return Err(UpdateUserError::UserUpdateFailed);
  };

  Ok(Json(MessageResponse {
    message: "ok. updated the user.".to_string(),
  }))
}
