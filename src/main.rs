mod auth;
mod config;
mod constants;
mod db;
mod error;
mod globals;
mod jwt;
mod rocket_api_create_user;
mod rocket_api_tokens;

use error::*;
use globals::{Globals, Mode};
use rocket_api_create_user::create_user;
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
          .mount("/hello", routes![hello])
          .mount("/v1.0", routes![tokens, create_user])
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
