use super::{
  request::ListUserRequest,
  response::{ListUserResponse, ListUserResponseInner},
};
use crate::{
  entity::Entity,
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

use libcommon::token_fields::{Field, IdToken, SubscriberId, TryNewField};

#[derive(Debug)]
pub enum ListUserError {
  UserListFailed,
  UnauthorizedUser,
  MissingToken,
  InvalidToken,
}
impl IntoResponse for ListUserError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      ListUserError::UserListFailed => (StatusCode::INTERNAL_SERVER_ERROR, "User listing failed"),
      ListUserError::UnauthorizedUser => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      ListUserError::MissingToken => (StatusCode::UNAUTHORIZED, "Missing token"),
      ListUserError::InvalidToken => (StatusCode::BAD_REQUEST, "Invalid token"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn list_users(
  State(state): State<Arc<AppState>>,
  headers: HeaderMap,
  Json(request): Json<ListUserRequest>,
) -> Result<Json<ListUserResponse>, ListUserError> {
  // First retrieve and verify bearer token
  let Some(Ok(bearer)) = headers.get("authorization").map(|v| v.to_str()) else {
    return Err(ListUserError::MissingToken);
  };
  let mut iter = bearer.split(' ');
  let token_str_opt = if let Some("Bearer") = iter.next() {
    iter.next()
  } else {
    return Err(ListUserError::MissingToken);
  };
  let Some(Ok(id_token)) = token_str_opt.map(IdToken::new) else {
    return Err(ListUserError::MissingToken);
  };
  let Ok(claims) = state.crypto.verify_token(&id_token) else {
    return Err(ListUserError::InvalidToken);
  };

  // is_admin must be true here
  if !claims.custom.get("iad").and_then(|v| v.as_bool()).unwrap_or(false) {
    return Err(ListUserError::UnauthorizedUser);
  }

  // just in case, check user existence
  let Some(Ok(sub)) = claims.custom.get("sub").and_then(|v| v.as_str()).map(SubscriberId::new) else {
    return Err(ListUserError::InvalidToken);
  };
  let Ok(opt) = state.table.user.find_user(UserSearchKey::SubscriberId(&sub)).await else {
    return Err(ListUserError::UserListFailed);
  };
  let Some(request_user) = opt else {
    return Err(ListUserError::UnauthorizedUser);
  };
  if !request_user.is_admin() {
    return Err(ListUserError::InvalidToken);
  }

  let current_page = request.page.unwrap_or(1u32);

  let Ok((users, total_pages, total_users)) = state.table.user.list_users(current_page).await else {
    return Err(ListUserError::UserListFailed);
  };

  Ok(Json(ListUserResponse {
    users: users
      .into_iter()
      .map(|u| ListUserResponseInner {
        username: u.username.into_string(),
        subscriber_id: u.subscriber_id.into_string(),
        is_admin: u.is_admin.get(),
      })
      .collect(),
    page: current_page,
    total_pages,
    total_users,
    message: "Success".to_string(),
  }))
}
