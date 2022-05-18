use crate::{
  db::UserInfo,
  error::*,
  jwt::AdditionalClaimData,
  request::PasswordCredentialRequest,
  request_bearer_token::*,
  response::{message_response_error, MessageResponse, MessageResponseBody},
  rocket_api_token_checkflow::check_token_and_db,
  Globals,
};
use jwt_simple::prelude::*;
use rocket::{
  http::{ContentType, Status},
  serde::{json::Json, Deserialize},
  State,
};
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
pub struct RequestBody {
  auth: PasswordCredentialRequest,
}

#[post("/create_user", format = "application/json", data = "<request_body>")]
pub fn create_user(
  request_body: Json<RequestBody>,
  bearer_token: BearerToken,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<MessageResponseBody>)) {
  let (_info, _claims): (UserInfo, JWTClaims<AdditionalClaimData>) =
    match check_token_and_db(globals, bearer_token, true) {
      Ok(i) => i,
      Err(e) => return message_response_error(e),
    };
  // // Verify bearer token with aud and iss checks
  // let claims = match globals.signing_key.verify_token(&bearer_token.0, globals) {
  //   Ok(c) => c,
  //   Err(e) => {
  //     error!("Unauthorized access, failed to verify JWT: {}", e);
  //     return message_response_error(403);
  //   }
  // };
  // if !claims.custom.is_admin {
  //   error!("Non administrator flag in token");
  //   return message_response_error(403);
  // }

  // // Check db for user existence
  // let user_db = globals.user_db.clone();
  // let info: UserInfo = match &claims.subject {
  //   Some(sub) => {
  //     let info: UserInfo = match user_db.get_user(UserSearchKey::SubscriberId(&sub)) {
  //       Err(e) => {
  //         error!("Failed to get user info: {}", e);
  //         return message_response_error(503);
  //       }

  //       Ok(opt) => match opt {
  //         None => {
  //           warn!("Non-registered user username [{}] was attempted", sub);
  //           return message_response_error(400);
  //         }
  //         Some(info) => info,
  //       },
  //     };
  //     info
  //   }
  //   None => {
  //     error!("Invalid user");
  //     return message_response_error(403);
  //   }
  // };

  // // check admin flag in DB etc to verify access as an id token
  // if !*info.is_admin() {
  //   warn!("In DB, requested user is not registered as admin");
  //   return message_response_error(400);
  // }

  // Finally try to add a new user
  let login_info = request_body.auth.clone();
  let username = login_info.username;
  let password = login_info.password;
  let user_db = globals.user_db.clone();

  match user_db.add_user(&username, &password, false) {
    Err(e) => {
      error!("Failed to add new user: {}", e);
      message_response_error(Status::ServiceUnavailable)
    }
    Ok(_) => {
      info!("Add a new standard user: {}", username);
      if let Ok(res) = access() {
        res
      } else {
        error!("Failed to create user");
        message_response_error(Status::Forbidden)
      }
    }
  }
}

pub fn access() -> Result<(Status, (ContentType, Json<MessageResponseBody>))> {
  Ok((
    Status::Created,
    (
      ContentType::JSON,
      Json(MessageResponseBody::Access(MessageResponse {
        message: "ok. new user is created.".to_string(),
      })),
    ),
  ))
}
