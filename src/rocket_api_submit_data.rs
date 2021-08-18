use crate::db::UserInfo;
use crate::error::*;
use crate::jwt::AdditionalClaimData;
use crate::request_bearer_token::*;
use crate::response::{message_response_error, MessageResponse, MessageResponseBody};
use crate::rocket_api_token_checkflow::check_token_and_db;
use crate::Globals;
use jwt_simple::prelude::*;
use log::{debug, error, info, warn};
use rocket::http::{ContentType, Status};
use rocket::serde::{json::Json, Deserialize};
use rocket::State;
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
pub struct RequestBody {
  pub data: Vec<Vec<i64>>,
}

#[post("/submit_data", format = "application/json", data = "<request_body>")]
pub fn submit_data<'a>(
  request_body: Json<RequestBody>,
  bearer_token: BearerToken,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<MessageResponseBody>)) {
  let (info, _claims): (UserInfo, JWTClaims<AdditionalClaimData>) =
    match check_token_and_db(globals, bearer_token, true) {
      Ok(i) => i,
      Err(e) => return message_response_error(e),
    };

  info!(
    "[Submitted data] Accepted: from {} ({}), Data {:?}",
    info.get_username(),
    info.get_subscriber_id(),
    request_body.into_inner().data
  );

  if let Ok(res) = access(info.get_username(), info.get_subscriber_id()) {
    return res;
  } else {
    error!("Failed to create user");
    return message_response_error(Status::Forbidden);
  }
}

pub fn access(
  username: &str,
  sub: &str,
) -> Result<(Status, (ContentType, Json<MessageResponseBody>)), Error> {
  return Ok((
    Status::Created,
    (
      ContentType::JSON,
      Json(MessageResponseBody::Access(MessageResponse {
        message: format!("ok. accepted data. (user = {}, sub = {})", username, sub),
      })),
    ),
  ));
}
