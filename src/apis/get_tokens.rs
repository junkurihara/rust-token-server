use super::{request::TokensRequest, response::TokensResponse};
use crate::{
  constants::DEFAUTL_CLIENT_ID,
  entity::{ClientId, RefreshToken},
  log::*,
  state::AppState,
  table::{UserSearchKey, UserTable},
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
pub enum GetTokensError {
  TokenCreationFailed,
  InvalidPassword,
  Argon2Failure,
  UnauthorizedClientApp,
  UnauthorizedUser,
  InvalidRequest,
}
impl IntoResponse for GetTokensError {
  fn into_response(self) -> Response {
    let (status, error_message) = match self {
      GetTokensError::TokenCreationFailed => (StatusCode::INTERNAL_SERVER_ERROR, "Token creation failed"),
      GetTokensError::InvalidPassword => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      GetTokensError::Argon2Failure => (StatusCode::INTERNAL_SERVER_ERROR, "Something failed in authentication"),
      GetTokensError::UnauthorizedClientApp => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      GetTokensError::UnauthorizedUser => (StatusCode::UNAUTHORIZED, "Unauthorized"),
      GetTokensError::InvalidRequest => (StatusCode::BAD_REQUEST, "Invalid request"),
    };
    let body = Json(json!({
        "error": error_message,
    }));
    (status, body).into_response()
  }
}

pub async fn get_tokens(
  State(state): State<Arc<AppState>>,
  Json(input): Json<TokensRequest>,
) -> Result<Json<TokensResponse>, GetTokensError> {
  // Getusername and password form
  let (username, password) = (input.auth.username, input.auth.password);

  // check user existence
  let Ok(user) = state.table.user.find_user(UserSearchKey::Username(&username)).await else{
    return Err(GetTokensError::TokenCreationFailed);
  };
  let Some(user) = user else {
    return Err(GetTokensError::UnauthorizedUser);
  };
  // check allowed client ids if audience is some
  let client_id = if state.crypto.audiences.is_some() {
    let Some(client_id) = input.client_id else {
      return Err(GetTokensError::InvalidRequest);
    };
    if !state.crypto.audiences.as_ref().unwrap().contains(&client_id) {
      return Err(GetTokensError::UnauthorizedClientApp);
    }
    debug!("{} is verified by client_id {}.", username.as_str(), client_id.as_str());
    client_id
  } else {
    let Ok(cid) = ClientId::new(DEFAUTL_CLIENT_ID) else {
      return Err(GetTokensError::TokenCreationFailed);
    };
    cid
  };

  // verify password
  let Ok(password_verified) = password.verify(&user.encoded_hash) else {
    return Err(GetTokensError::Argon2Failure);
  };
  if !password_verified {
    return Err(GetTokensError::InvalidPassword);
  }

  debug!("{} is verified by password. Issue id_token.", username.as_str());

  // generate id_token with refresh token
  let Ok(token) = state.crypto.generate_token(&user, &client_id, true) else {
    return Err(GetTokensError::TokenCreationFailed)
  };

  // Record refresh token to db
  let Ok(refresh) = RefreshToken::try_from(&token) else {
    error!("Failed to retrieve refresh token from token struct");
    return Err(GetTokensError::TokenCreationFailed)
  };
  if state.table.refresh_token.add_and_prune(&refresh).await.is_err() {
    error!("Failed to store refresh token");
    return Err(GetTokensError::TokenCreationFailed);
  };

  Ok(Json(TokensResponse {
    token: token.inner,
    metadata: token.meta,
    message: "ok. login.".to_string(),
  }))
}
