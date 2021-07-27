use crate::constants::*;
use crate::db::UserDB;
use crate::error::*;
use crate::globals::{Globals, Mode};
use crate::jwt::{Algorithm, AlgorithmType, JwtSigningKey};
use clap::{App, Arg};
use std::fs;
use std::str::FromStr;
use std::sync::Arc;

pub fn parse_opts() -> Result<(Mode, Option<Arc<Globals>>), Error> {
  let _ = include_str!("../Cargo.toml");
  let options = app_from_crate!()
    .subcommand(
      App::new("run")
        .arg(
          Arg::with_name("signing_key_path")
            .short("s")
            .long("signing-key-path")
            .takes_value(true)
            .required(true)
            .help("Signing key file path"),
        )
        .arg(
          Arg::with_name("signing_algorithm")
            .short("a")
            .long("signing-algorithm")
            .takes_value(true)
            .required(true)
            .default_value("ES256")
            .help("Signing algorithm of JWT like \"ES256\""),
        )
        .arg(
          Arg::with_name("db_file_path")
            .short("d")
            .long("db-file-path")
            .takes_value(true)
            .default_value(DB_FILE_PATH)
            .help("SQLite database file path"),
        )
        .arg(
          Arg::with_name("with_key_id")
            .short("i")
            .long("with-key-id")
            .help("Include key id in JWT"),
        ),
    )
    .subcommand(
      App::new("init")
        .arg(
          Arg::with_name("db_file_path")
            .short("d")
            .long("db-file-path")
            .takes_value(true)
            .default_value(DB_FILE_PATH)
            .help("SQLite database file path"),
        )
        .arg(
          Arg::with_name("admin_name")
            .short("n")
            .long("admin-name")
            .required(true)
            .takes_value(true)
            .help("SQLite database admin name"),
        )
        .arg(
          Arg::with_name("admin_password")
            .short("p")
            .long("admin-password")
            .takes_value(true)
            .required(true)
            .help("SQLite database admin password"),
        ),
    );

  let matches = options.get_matches();

  if let Some(ref matches) = matches.subcommand_matches("run") {
    let algorithm: Algorithm = match matches.value_of("signing_algorithm") {
      Some(a) => match Algorithm::from_str(a) {
        Ok(ao) => ao,
        Err(_) => {
          bail!("Given algorithm not supported");
        }
      },
      None => {
        bail!("Algorithm must be specified");
      }
    };

    let with_key_id = matches.is_present("with_key_id");
    let signing_key: JwtSigningKey = match matches.value_of("signing_key_path") {
      Some(p) => {
        if let Ok(content) = fs::read_to_string(p) {
          match algorithm.get_type() {
            AlgorithmType::HMAC => {
              let truncate_vec: Vec<&str> = content.split("\n").collect();
              ensure!(truncate_vec.len() > 0, true);
              JwtSigningKey::new(&algorithm, &truncate_vec[0], with_key_id)?
            }
            _ => JwtSigningKey::new(&algorithm, &content, with_key_id)?,
          }
        } else {
          bail!("Failed to read private key");
        }
      }
      None => {
        bail!("Signing key path must be specified");
      }
    };

    let db_file_path: String = match matches.value_of("db_file_path") {
      Some(p) => p.to_string(),
      None => {
        bail!("Database path must be specified");
      }
    };

    // Setting up globals
    let user_db = UserDB {
      db_file_path,
      user_table_name: USER_TABLE_NAME.to_string(),
    };
    user_db.clone().init_db(None, None)?; // check db if it is already initialized.

    let globals = Arc::new(Globals {
      user_db,
      algorithm,
      signing_key,
    });

    Ok((Mode::RUN, Some(globals)))
  } else if let Some(ref matches) = matches.subcommand_matches("init") {
    let db_file_path: String = match matches.value_of("db_file_path") {
      Some(p) => p.to_string(),
      None => {
        bail!("Database path must be specified");
      }
    };

    // Setting up globals
    let user_db = UserDB {
      db_file_path,
      user_table_name: USER_TABLE_NAME.to_string(),
    };

    let admin_name = matches.value_of("admin_name");
    let admin_password = matches.value_of("admin_password");

    user_db.init_db(admin_name, admin_password)?;

    Ok((Mode::INIT, None))
  } else {
    Ok((Mode::NONE, None))
  }
}
