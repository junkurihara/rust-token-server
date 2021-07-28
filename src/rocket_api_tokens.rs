use crate::auth;
use crate::constants::*;
use crate::db::{UserInfo, UserSearchKey};
use crate::error::*;
use crate::jwt::generate_jwt;
use crate::request::PasswordCredentialRequest;
use crate::response::{token_response_error, TokenResponse, TokenResponseBody};
use crate::Globals;
use chrono::Local;
use rocket::http::{ContentType, Status};
use rocket::serde::{json::Json, Deserialize};
use rocket::State;
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
pub struct RequestBody {
  auth: PasswordCredentialRequest,
  client_id: String,
}

#[post("/tokens", format = "application/json", data = "<request_body>")]
pub fn tokens<'a>(
  request_body: Json<RequestBody>,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<TokenResponseBody>)) {
  // find user
  let login_info = request_body.auth.clone();
  let client_id = request_body.client_id.clone();
  let username = login_info.username;
  let user_db = globals.user_db.clone();

  let user_info = match user_db.get_user(UserSearchKey::Username(&username)) {
    Err(e) => {
      error!("Failed to seek database: {}", e);
      return token_response_error(Status::ServiceUnavailable);
    }
    Ok(s) => s,
  };

  if let Some(info) = user_info {
    // password check
    let verified = auth::verify_argon2(&login_info.password, info.get_encoded_hash());
    // client check
    let client_is_allowed = match &globals.allowed_client_ids {
      None => true, // anything is allowed
      Some(cid) => cid.contains(&client_id),
    };
    if client_is_allowed {
      match verified {
        Ok(v) => {
          if v {
            match access(&info, &client_id, globals) {
              Ok(res) => {
                return res;
              }
              Err(e) => {
                error!("Failed to create token: {}", e);
                return token_response_error(Status::Forbidden);
              }
            }
          } else {
            warn!("Invalid password is given for [{}]", username);
            return token_response_error(Status::Unauthorized);
          }
        }
        Err(e) => {
          error!("Argon2 verification failed: {}", e);
          return token_response_error(Status::ServiceUnavailable);
        }
      }
    } else {
      error!("Access from a client that is not allowed");
      return token_response_error(Status::Forbidden);
    }
  } else {
    warn!("Non-registered username [{}] was attempted", username);
    return token_response_error(Status::BadRequest);
  }
}

pub fn access(
  info: &UserInfo,
  client_id: &str,
  globals: &State<Arc<Globals>>,
) -> Result<(Status, (ContentType, Json<TokenResponseBody>)), Error> {
  let (token, metadata) = generate_jwt(info, client_id, globals, true)?;
  // generate refresh token? refresh token must be added to userdb if used
  // Add database refresh token
  let refresh_token = match &token.refresh {
    None => bail!("refresh token is not generated"),
    Some(t) => t,
  };
  let current: u64 = Local::now().timestamp() as u64;
  let expires: u64 = current + ((REFRESH_TOKEN_DURATION_MINS as i64) * 60) as u64;
  &globals
    .user_db
    .add_refresh_token(&info.get_subscriber_id(), refresh_token, expires, current);

  return Ok((
    Status::new(200),
    (
      ContentType::JSON,
      Json(TokenResponseBody::Access(TokenResponse {
        token,
        metadata,
        message: "ok. login.".to_string(),
      })),
    ),
  ));
}
