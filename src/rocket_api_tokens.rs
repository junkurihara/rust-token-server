use crate::auth;
use crate::db::{UserInfo, UserSearchKey};
use crate::error::*;
use crate::jwt::{generate_jwt, Token, TokenMetaData};
use crate::Globals;
use rocket::http::{ContentType, Status};
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::State;
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
pub struct PasswordCredential {
  username: String,
  password: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct RequestBody {
  auth: PasswordCredential,
  client_id: String,
}

#[derive(Serialize, Debug, Clone)]
pub enum ResponseBody {
  Access(TokenResponse),
  Error(TokenError),
}
#[derive(Serialize, Debug, Clone)]
pub struct TokenResponse {
  token: Token,
  metadata: TokenMetaData,
  message: String,
}
#[derive(Serialize, Debug, Clone)]
pub struct TokenError {
  message: String,
}

#[post("/tokens", format = "application/json", data = "<request_body>")]
pub fn tokens<'a>(
  request_body: Json<RequestBody>,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<ResponseBody>)) {
  // find user
  let login_info = request_body.auth.clone();
  let client_id = request_body.client_id.clone();
  let username = login_info.username;
  let user_db = globals.user_db.clone();

  let user_info = match user_db.get_user(UserSearchKey::Username(&username)) {
    Err(e) => {
      error!("Failed to seek database: {}", e);
      return error(503);
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
                return error(403);
              }
            }
          } else {
            warn!("Invalid password is given for [{}]", username);
            return error(403);
          }
        }
        Err(e) => {
          error!("Argon2 verification failed: {}", e);
          return error(503);
        }
      }
    } else {
      error!("Access from a client that is not allowed");
      return error(403);
    }
  } else {
    warn!("Non-registered username [{}] was attempted", username);
    return error(400);
  }
}

pub fn access(
  info: &UserInfo,
  client_id: &str,
  globals: &State<Arc<Globals>>,
) -> Result<(Status, (ContentType, Json<ResponseBody>)), Error> {
  let (token, metadata) = generate_jwt(info, client_id, globals)?;
  return Ok((
    Status::new(200),
    (
      ContentType::JSON,
      Json(ResponseBody::Access(TokenResponse {
        token,
        metadata,
        message: "ok".to_string(),
      })),
    ),
  ));
}

fn error(code: usize) -> (Status, (ContentType, Json<ResponseBody>)) {
  match code {
    500 => (
      Status::new(500),
      (
        ContentType::JSON,
        Json(ResponseBody::Error(TokenError {
          message: "Server Fail".to_string(),
        })),
      ),
    ),
    403 => (
      Status::new(403),
      (
        ContentType::JSON,
        Json(ResponseBody::Error(TokenError {
          message: "Authentication Error".to_string(),
        })),
      ),
    ),
    _ => (
      Status::new(400),
      (
        ContentType::JSON,
        Json(ResponseBody::Error(TokenError {
          message: "Bad Request".to_string(),
        })),
      ),
    ),
  }
}
