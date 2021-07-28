use crate::db::{UserInfo, UserSearchKey};
use crate::jwt::AdditionalClaimData;
use crate::request_bearer_token::*;
use crate::Globals;
use jwt_simple::prelude::*;
use rocket::http::Status;
use rocket::State;
use std::sync::Arc;

pub fn check_token_and_db(
  globals: &State<Arc<Globals>>,
  bearer_token: BearerToken,
  admin_required: bool,
) -> Result<(UserInfo, JWTClaims<AdditionalClaimData>), Status> {
  // Verify bearer token with aud and iss checks
  let claims = match globals.signing_key.verify_token(&bearer_token.0, globals) {
    Ok(c) => c,
    Err(e) => {
      error!("Unauthorized access, failed to verify JWT: {}", e);
      return Err(Status::Unauthorized);
    }
  };
  if admin_required && !claims.custom.is_admin {
    error!("Non administrator flag in token");
    return Err(Status::Unauthorized);
  }

  // Check db for user existence
  let user_db = globals.user_db.clone();
  let info: UserInfo = match &claims.subject {
    Some(sub) => {
      let info: UserInfo = match user_db.get_user(UserSearchKey::SubscriberId(&sub)) {
        Err(e) => {
          error!("Failed to get user info: {}", e);
          return Err(Status::ServiceUnavailable);
        }

        Ok(opt) => match opt {
          None => {
            warn!("Non-registered user username [{}] was attempted", sub);
            return Err(Status::BadRequest);
          }
          Some(info) => info,
        },
      };
      info
    }
    None => {
      error!("Invalid user");
      return Err(Status::Forbidden);
    }
  };

  // check admin flag in DB etc to verify access as an id token
  if !*info.is_admin() {
    warn!("In DB, requested user is not registered as admin");
    return Err(Status::BadRequest);
  }

  Ok((info, claims))
}
