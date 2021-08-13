mod auth;
mod config;
mod constants;
mod db;
mod error;
mod globals;
mod jwt;
mod request;
mod request_bearer_token;
mod response;
mod rocket_api_create_user;
mod rocket_api_jwks;
mod rocket_api_refresh;
mod rocket_api_token_checkflow;
mod rocket_api_tokens;
mod utils;
use error::*;
use globals::{Globals, Mode};
use rocket_api_create_user::create_user;
use rocket_api_jwks::jwks;
use rocket_api_refresh::refresh;
use rocket_api_tokens::tokens;

#[macro_use]
extern crate clap;

#[macro_use]
extern crate rocket;

#[get("/")]
fn hello() -> String {
  format!("hello!")
}

#[rocket::main]
async fn main() -> Result<(), Error> {
  env_logger::init();

  let (mode, globals_opt) = config::parse_opts()?;
  match mode {
    Mode::RUN => {
      if let Some(globals) = globals_opt {
        rocket::build()
          .mount("/hello", routes![hello]) // TODO: add healthcheck
          .mount("/v1.0", routes![tokens, create_user, refresh, jwks])
          .manage(globals)
          .launch()
          .await?;

        Ok(())
      } else {
        bail!("Failed to run");
      }
    }
    _ => Ok(()),
  }
}
