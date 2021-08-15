use crate::db::UserInfo;
use crate::db::UserSearchKey;
use crate::error::*;
use crate::jwt::generate_jwt;
use crate::response::{token_response_error, TokenResponse, TokenResponseBody};
use crate::Globals;
use chrono::Local;
use rocket::http::{ContentType, Status};
use rocket::serde::{json::Json, Deserialize};
use rocket::State;
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
pub struct RequestBody {
  refresh_token: String,
  client_id: String,
}

#[post("/refresh", format = "application/json", data = "<request_body>")]
pub fn refresh<'a>(
  request_body: Json<RequestBody>,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<TokenResponseBody>)) {
  let refresh_token = request_body.refresh_token.clone();
  let client_id = request_body.client_id.clone();

  // search user_db refresh token table with client_id and refresh_token, and check its existence and expiration
  let user_db = globals.user_db.clone();
  let current: u64 = Local::now().timestamp() as u64;
  let associated_subscriber_id =
    match user_db.get_subid_for_refresh_token(&client_id, &refresh_token, current) {
      Ok(v) => match v {
        Some(subscriber_id) => subscriber_id,
        None => {
          return token_response_error(Status::Unauthorized);
        }
      },
      Err(_) => return token_response_error(Status::ServiceUnavailable),
    };

  // find user info from subscriber id from refresh token table
  let info: UserInfo = match user_db
    .get_user(UserSearchKey::SubscriberId(&associated_subscriber_id))
  {
    Err(e) => {
      error!("Failed to get user info: {}", e);
      return token_response_error(Status::ServiceUnavailable);
    }
    Ok(opt) => match opt {
      None => {
        error!(
          "Internally non-registered user username [{:?}] was registered for user. maybe deleted user.",
          &associated_subscriber_id
        );
        return token_response_error(Status::ServiceUnavailable);
      }
      Some(info) => info,
    },
  };

  match access(&info, &client_id, globals) {
    Ok(res) => {
      return res;
    }
    Err(e) => {
      error!("Failed to create token: {}", e);
      return token_response_error(Status::Forbidden);
    }
  }
}

pub fn access(
  info: &UserInfo,
  client_id: &str,
  globals: &State<Arc<Globals>>,
) -> Result<(Status, (ContentType, Json<TokenResponseBody>)), Error> {
  let (token, metadata) = generate_jwt(info, client_id, globals, false)?;
  return Ok((
    Status::new(200),
    (
      ContentType::JSON,
      Json(TokenResponseBody::Access(TokenResponse {
        token,
        metadata,
        message: "ok. token is refreshed.".to_string(),
      })),
    ),
  ));
}
