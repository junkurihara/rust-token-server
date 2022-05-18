use crate::error::*;
use rocket::{
  http::Status, outcome::Outcome, request, request::FromRequest, serde::Deserialize, Request,
};

#[derive(Deserialize, Debug, Clone)]
pub struct BearerToken(pub String);

#[rocket::async_trait]
impl<'r> FromRequest<'r> for BearerToken {
  type Error = Error;

  async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Error> {
    let token = request.headers().get_one("Authorization");
    match token {
      Some(token) => {
        // check validity
        // Check authorization header first;
        let jwt: Vec<&str> = token.split(' ').collect();
        if jwt[0] != "Bearer" || jwt.len() != 2 {
          warn!("Invalid bearer token");
          return Outcome::Failure((Status::BadRequest, anyhow!("Invalid bearer token")));
        }
        Outcome::Success(BearerToken(jwt[1].to_string()))
      }
      None => Outcome::Failure((Status::Unauthorized, anyhow!("No bearer token"))),
    }
  }
}
