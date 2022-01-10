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
  use crate::utils::verify_url;

  let _ = include_str!("../Cargo.toml");
  let options = app_from_crate!()
    .subcommand(
      App::new("run")
        .arg(
          Arg::new("signing_key_path")
            .short('s')
            .long("signing-key-path")
            .takes_value(true)
            .required(true)
            .help("Signing key file path"),
        )
        .arg(
          Arg::new("signing_algorithm")
            .short('a')
            .long("signing-algorithm")
            .takes_value(true)
            .default_value("ES256")
            .help("Signing algorithm of JWT like \"ES256\""),
        )
        .arg(
          Arg::new("db_file_path")
            .short('d')
            .long("db-file-path")
            .takes_value(true)
            .default_value(DB_FILE_PATH)
            .help("SQLite database file path"),
        )
        .arg(
          Arg::new("with_key_id")
            .short('i')
            .long("with-key-id")
            .help("Include key id in JWT"),
        )
        .arg(
          Arg::new("ignore_client_id")
            .short('o')
            .long("ignore-client-id")
            .help("Ignore checking client id in token request"),
        )
        .arg(
          Arg::new("token_issuer")
            .short('t')
            .long("token-issuer")
            .required(true)
            .validator(verify_url)
            .takes_value(true)
            .help("Issuer of Id token specified as URL like \"https://example.com/issue\""),
        ),
    )
    .subcommand(
      App::new("init")
        .arg(
          Arg::new("db_file_path")
            .short('d')
            .long("db-file-path")
            .takes_value(true)
            .default_value(DB_FILE_PATH)
            .help("SQLite database file path"),
        )
        .arg(
          Arg::new("admin_name")
            .short('n')
            .long("admin-name")
            .required(true)
            .takes_value(true)
            .help("SQLite database admin name"),
        )
        .arg(
          Arg::new("admin_password")
            .short('p')
            .long("admin-password")
            .takes_value(true)
            .required(true)
            .help("SQLite database admin password"),
        )
        .arg(
          Arg::new("client_ids")
            .short('c')
            .long("client-ids")
            .takes_value(true)
            .help("Client ids allowed to connect the API server, split with comma like \"AAAA,BBBBB,CCCC\""),
        ),
    );

  let matches = options.get_matches();

  if let Some(matches) = matches.subcommand_matches("run") {
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
            AlgorithmType::Hmac => {
              let truncate_vec: Vec<&str> = content.split('\n').collect();
              ensure!(!truncate_vec.is_empty(), "Invalid (maybe null) signing key");
              JwtSigningKey::new(&algorithm, truncate_vec[0], with_key_id)?
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
      allowed_client_table_name: ALLOWED_CLIENT_TABLE_NAME.to_string(),
      token_table_name: TOKEN_TABLE_NAME.to_string(),
    };
    user_db.clone().init_db(None, None, vec![])?; // check db if it is already initialized.

    // read client ids
    let ignore_client_id = matches.is_present("ignore_client_id");
    let client_ids = user_db.get_all_allowed_client_ids()?;
    if !ignore_client_id {
      info!("allowed_client_ids {:?}", client_ids);
    }

    // get issuer
    let token_issuer = match matches.value_of("token_issuer") {
      Some(t) => t,
      None => {
        bail!("Issuer must be specified");
      }
    };

    let globals = Arc::new(Globals {
      user_db,
      algorithm,
      signing_key,
      allowed_client_ids: match ignore_client_id {
        false => Some(client_ids),
        true => None,
      },
      token_issuer: token_issuer.to_string(),
    });

    Ok((Mode::Run, Some(globals)))
  } else if let Some(matches) = matches.subcommand_matches("init") {
    let db_file_path: String = match matches.value_of("db_file_path") {
      Some(p) => p.to_string(),
      None => {
        bail!("Database path must be specified");
      }
    };

    // Setting up globals
    let user_db = UserDB {
      db_file_path,
      allowed_client_table_name: ALLOWED_CLIENT_TABLE_NAME.to_string(),
      user_table_name: USER_TABLE_NAME.to_string(),
      token_table_name: TOKEN_TABLE_NAME.to_string(),
    };

    let admin_name = matches.value_of("admin_name");
    let admin_password = matches.value_of("admin_password");

    let client_ids = matches.value_of("client_ids");
    match client_ids {
      Some(cids) => user_db.init_db(
        admin_name,
        admin_password,
        cids.split(',').collect::<Vec<&str>>(),
      )?,
      None => user_db.init_db(admin_name, admin_password, vec![])?,
    }

    Ok((Mode::Init, None))
  } else {
    Ok((Mode::None, None))
  }
}
