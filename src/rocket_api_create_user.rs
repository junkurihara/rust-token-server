use crate::db::UserSearchKey;
use crate::error::*;
use crate::Globals;
use rocket::http::{ContentType, Status};
use rocket::outcome::Outcome;
use rocket::request;
use rocket::request::FromRequest;
use rocket::serde::{json::Json, Deserialize, Serialize};
use rocket::Request;
use rocket::State;
use std::sync::Arc;

#[derive(Deserialize, Debug, Clone)]
pub struct PasswordCredential {
  username: String,
  password: String,
}

#[derive(Deserialize, Debug, Clone)]
pub struct BearerToken(String);

#[derive(Deserialize, Debug, Clone)]
pub struct RequestBody {
  auth: PasswordCredential,
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerToken {
  type Error = anyhow::Error;

  async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
    let token = request.headers().get_one("Authorization");
    match token {
      Some(token) => {
        // check validity
        Outcome::Success(BearerToken(token.to_string()))
      }
      None => Outcome::Failure((Status::Unauthorized, anyhow!("No bearer token"))),
    }
  }
}

#[derive(Serialize, Debug, Clone)]
pub enum ResponseBody {
  Access(MessageResponse),
  Error(MessageResponse),
}

#[derive(Serialize, Debug, Clone)]
pub struct MessageResponse {
  message: String,
}

#[post("/create_user", format = "application/json", data = "<request_body>")]
pub fn create_user<'a>(
  request_body: Json<RequestBody>,
  bearer_token: BearerToken,
  globals: &State<Arc<Globals>>,
) -> (Status, (ContentType, Json<ResponseBody>)) {
  // Check authorization header first;
  let jwt: Vec<&str> = bearer_token.0.split(" ").collect();
  if jwt[0] != "Bearer" && jwt.len() == 2 {
    warn!("Invalid bearer token");
    return error(403);
  }
  // Verify bearer token with aud and iss checks
  let claims = match globals.signing_key.verify_token(jwt[1], globals) {
    Ok(c) => c,
    Err(e) => {
      error!("Unauthorized access, failed to verify JWT: {}", e);
      return error(403);
    }
  };
  if !claims.custom.is_admin {
    error!("Non administrator flag in token");
    return error(403);
  }

  // Check db for admin existence
  let user_db = globals.user_db.clone();
  match &claims.subject {
    Some(sub) => {
      match user_db.get_user(UserSearchKey::SubscriberId(&sub)) {
        Err(e) => {
          error!("Failed to get admin info: {}", e);
          return error(503);
        }
        Ok(opt) => match opt {
          None => {
            warn!("Non-registered admin username [{}] was attempted", sub);
            return error(400);
          }
          Some(info) => {
            // check admin flag in DB etc to verify access as an id token
            if !*info.is_admin() {
              warn!("In DB, requested user is not registered as admin");
              return error(400);
            }
          }
        },
      };
    }
    None => {
      error!("Invalid administrator");
      return error(403);
    }
  }

  // Finally try to add a new user
  let login_info = request_body.auth.clone();
  let username = login_info.username;
  let password = login_info.password;
  let user_db = globals.user_db.clone();

  match user_db.add_user(&username, &password, false) {
    Err(e) => {
      error!("Failed to add new user: {}", e);
      return error(503);
    }
    Ok(_) => {
      info!("Add a new standard user: {}", username);
      if let Ok(res) = access() {
        return res;
      } else {
        error!("Failed to create user");
        return error(403);
      }
    }
  };
}

pub fn access() -> Result<(Status, (ContentType, Json<ResponseBody>)), Error> {
  return Ok((
    Status::new(200),
    (
      ContentType::JSON,
      Json(ResponseBody::Access(MessageResponse {
        message: "ok".to_string(),
      })),
    ),
  ));
}

fn error(code: usize) -> (Status, (ContentType, Json<ResponseBody>)) {
  match code {
    503 => (
      Status::new(503),
      (
        ContentType::JSON,
        Json(ResponseBody::Error(MessageResponse {
          message: "Server Fail".to_string(),
        })),
      ),
    ),
    403 => (
      Status::new(403),
      (
        ContentType::JSON,
        Json(ResponseBody::Error(MessageResponse {
          message: "Authentication Error".to_string(),
        })),
      ),
    ),
    _ => (
      Status::new(400),
      (
        ContentType::JSON,
        Json(ResponseBody::Error(MessageResponse {
          message: "Bad Request".to_string(),
        })),
      ),
    ),
  }
}
