use super::{request::RefreshRequest, response::TokensResponse};
use crate::{
  constants::DEFAUTL_CLIENT_ID, jwt::ClientId, log::*, state::AppState, table::UserSearchKey, table::UserTable,
};
use axum::{
  extract::State,
  http::StatusCode,
  response::{IntoResponse, Response},
  Json,
};
use serde_json::json;
use std::sync::Arc;

#[derive(Debug)]
pub enum RefreshError {
  TokenCreationFailed,
  UnauthorizedClientApp,
  UnauthorizedOrExpiredRefreshToken,
  InvalidRequest,
}
impl IntoResponse for RefreshError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      RefreshError::TokenCreationFailed => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation failed"),
      RefreshError::UnauthorizedClientApp => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      RefreshError::UnauthorizedOrExpiredRefreshToken => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      RefreshError::InvalidRequest => (StatusCode::BAD_REQUEST, "Invalid request"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn refresh(
  State(state): State<Arc<AppState>>,
  Json(input): Json<RefreshRequest>,
) -> Result<Json<TokensResponse>, RefreshError> {
  let refresh_token = input.refresh_token;

  // check allowed client ids if audience is some
  let client_id = if state.crypto.audiences.is_some() {
    let Some(client_id) = input.client_id else {
      return Err(RefreshError::InvalidRequest);
    };
    if !state.crypto.audiences.as_ref().unwrap().contains(&client_id) {
      return Err(RefreshError::UnauthorizedClientApp);
    }
    debug!("client_id is ok: {}.", client_id.as_str());
    client_id
  } else {
    let Ok(cid) = ClientId::new(DEFAUTL_CLIENT_ID) else {
      return Err(RefreshError::TokenCreationFailed);
    };
    cid
  };
  // check user existence
  let Ok(entry_opt) = state.table.refresh_token.prune_and_find(&refresh_token, &client_id).await else {
    return Err(RefreshError::TokenCreationFailed);
  };
  let Some(entry) = entry_opt else {
    return Err(RefreshError::UnauthorizedOrExpiredRefreshToken);
  };

  // find user by subscriber_id
  let Ok(Some(user)) = state.table.user.find_user(UserSearchKey::SubscriberId(&entry.subscriber_id)).await else{
    return Err(RefreshError::TokenCreationFailed);
  };

  // generate id_token without refresh token
  let Ok(token) = state.crypto.generate_token(&user, &client_id, false) else {
    return Err(RefreshError::TokenCreationFailed)
  };
  Ok(Json(TokensResponse {
    token: token.inner,
    metadata: token.meta,
    message: "ok. id_token is refreshed.".to_string(),
  }))
}
