use crate::db::{UserInfo, UserDB};
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
  pub data: Vec<Vec<u64>>,
}

#[post("/submit_data", format = "application/json", data = "<request_body>")]
pub fn submit_data<'a>(
  request_body: Json<RequestBody>,
  bearer_token: BearerToken,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<MessageResponseBody>)) {
  let (info, _claims): (UserInfo, JWTClaims<AdditionalClaimData>) =
    match check_token_and_db(globals, bearer_token, false) {
      Ok(i) => i,
      Err(e) => return message_response_error(e),
    };

  let data = request_body.into_inner().data;
  let subscriber_id = info.get_subscriber_id();
  info!(
    "[Submitted data] Accepted: from {} ({}), Data {:?}",
    info.get_username(),
    &subscriber_id,
    &data
  );

  let user_db = globals.user_db.clone();
  let event_logs: Vec<Result<(), Error>> = data.iter().map( |elog| {
    if elog.len() == 2 {
      let utime: u64 = elog[0];
      let eid: u64 = elog[1];
      user_db.add_event_log(subscriber_id, utime, eid)
    }
    else {
      Err(anyhow!("Invalid data"))
    }
  }).collect();
  let result: Result<Vec<()>,Error> = event_logs.into_iter().collect();
  println!("{:?}", result);
  match result {
    Ok(_) => {
      if let Ok(res) = access(info.get_username(), info.get_subscriber_id()) {
        return res;
      } else {
        error!("Failed to make response");
        return message_response_error(Status::Forbidden);
      }
    },
    Err(_) => {
      error!("Failed to write all events");
      return message_response_error(Status::BadRequest);
    }
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
