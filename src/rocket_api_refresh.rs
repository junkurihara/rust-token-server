use crate::db::UserInfo;
use crate::error::*;
use crate::jwt::{generate_jwt, AdditionalClaimData};
use crate::request_bearer_token::*;
use crate::response::{token_response_error, TokenResponse, TokenResponseBody};
use crate::rocket_api_token_checkflow::check_token_and_db;
use crate::Globals;
use chrono::Local;
use jwt_simple::prelude::*;
use rocket::http::{ContentType, Status};
use rocket::serde::{json::Json, Deserialize};
use rocket::State;
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
pub struct RequestBody {
  refresh_token: String,
}

#[post("/refresh", format = "application/json", data = "<request_body>")]
pub fn refresh<'a>(
  request_body: Json<RequestBody>,
  bearer_token: BearerToken,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<TokenResponseBody>)) {
  let (info, claims): (UserInfo, JWTClaims<AdditionalClaimData>) =
    match check_token_and_db(globals, bearer_token, false) {
      Ok(i) => i,
      Err(e) => return token_response_error(e),
    };

  let refresh_token = request_body.refresh_token.clone();

  // search user_db refresh token table with subscriber_id and refresh_token, and check its existence and expiration
  let user_db = globals.user_db.clone();
  let current: u64 = Local::now().timestamp() as u64;
  let is_valid_refresh_token =
    match user_db.is_valid_refresh_token(&info.get_subscriber_id(), &refresh_token, current) {
      Ok(valid) => valid,
      Err(_) => return token_response_error(Status::ServiceUnavailable),
    };
  if !is_valid_refresh_token {
    return token_response_error(Status::Unauthorized);
  }

  // renew id token here
  let aud: Vec<String> = match claims.audiences {
    None => {
      warn!("No aud is given in token");
      return token_response_error(Status::Forbidden);
    }
    Some(a) => a.into_set().into_iter().collect(),
  };
  match access(&info, &aud[0], globals) {
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
