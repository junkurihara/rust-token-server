mod auth;
mod config;
mod constants;
mod db;
mod error;
mod globals;
mod health_check;
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
use health_check::health;
use rocket_api_create_user::create_user;
use rocket_api_jwks::jwks;
use rocket_api_refresh::refresh;
use rocket_api_tokens::tokens;

#[macro_use]
extern crate rocket;

#[rocket::main]
async fn main() -> Result<(), Error> {
  env_logger::init();

  let (mode, globals_opt) = config::parse_opts()?;
  match mode {
    Mode::Run => {
      if let Some(globals) = globals_opt {
        let _ = rocket::build()
          .mount("/health", routes![health])
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
