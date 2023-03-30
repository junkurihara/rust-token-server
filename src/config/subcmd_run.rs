use super::ClapSubCommand;
use crate::{
  constants::{DB_FILE_PATH, DEFAULT_ADDRESS, DEFAULT_ALGORITHM, DEFAULT_PORT},
  db::setup_sqlite,
  error::*,
  jwt::{Algorithm, AlgorithmType, JwtSigningKey},
  state::{AppState, CryptoState},
};
use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};
use std::{fs, net::SocketAddr, str::FromStr};

pub(super) struct Run {}

#[async_trait]
impl ClapSubCommand for Run {
  fn subcmd() -> Command {
    Command::new("run")
      .arg(
        Arg::new("listen_address")
          .short('l')
          .long("listen-address")
          .value_name("ADDRESS")
          .default_value(DEFAULT_ADDRESS)
          .help("Listen address"),
      )
      .arg(
        Arg::new("port")
          .short('p')
          .long("port")
          .value_name("PORT")
          .default_value(DEFAULT_PORT)
          .help("Listen port"),
      )
      .arg(
        Arg::new("signing_key_path")
          .short('s')
          .long("signing-key-path")
          .value_name("PATH")
          .required(true)
          .help("Signing key file path"),
      )
      .arg(
        Arg::new("signing_algorithm")
          .short('a')
          .long("signing-algorithm")
          .value_name("ALGORITHM")
          .default_value(DEFAULT_ALGORITHM)
          .help("Signing algorithm of JWT like \"ES256\""),
      )
      .arg(
        Arg::new("with_key_id")
          .short('i')
          .long("with-key-id")
          .action(clap::ArgAction::SetTrue)
          .help("Include key id in JWT"),
      )
      .arg(
        Arg::new("db_file_path")
          .short('d')
          .long("db-file-path")
          .value_name("PATH")
          .default_value(DB_FILE_PATH)
          .help("SQLite database file path"),
      )
  }

  async fn exec_matches(sub_m: &ArgMatches) -> Result<Option<crate::AppState>> {
    let Some(address) = sub_m.get_one::<String>("listen_address") else {
      bail!("Listen address must be specified");
    };
    let Some(port) = sub_m.get_one::<String>("port") else {
      bail!("Port must be specified");
    };
    let listen_socket = format!("{}:{}", address, port).parse::<SocketAddr>()?;

    let algorithm: Algorithm = match sub_m.get_one::<String>("signing_algorithm") {
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

    let with_key_id = sub_m.get_flag("with_key_id");
    let signing_key: JwtSigningKey = match sub_m.get_one::<String>("signing_key_path") {
      Some(p) => {
        if let Ok(content) = fs::read_to_string(p) {
          match algorithm.get_type() {
            AlgorithmType::Ec | AlgorithmType::Okp => JwtSigningKey::new(&algorithm, &content, with_key_id)?,
            _ => bail!("Unsupported"),
          }
        } else {
          bail!("Failed to read private key");
        }
      }
      None => {
        bail!("Signing key path must be specified");
      }
    };

    let db_file_path: String = match sub_m.get_one::<String>("db_file_path") {
      Some(p) => p.to_string(),
      None => {
        bail!("Database path must be specified");
      }
    };

    // TODO: returns client_id table and token table as well
    let user_table = setup_sqlite(&format!("sqlite:{}", db_file_path)).await?;

    Ok(Some(AppState {
      listen_socket,
      crypto: CryptoState { algorithm, signing_key },
      user_table,
    }))

    // // Setting up globals
    // let user_db = UserDB {
    //   db_file_path,
    //   user_table_name: USER_TABLE_NAME.to_string(),
    //   allowed_client_table_name: ALLOWED_CLIENT_TABLE_NAME.to_string(),
    //   token_table_name: TOKEN_TABLE_NAME.to_string(),
    // };
    // user_db.clone().init_db(None, None, vec![])?; // check db if it is already initialized.

    // // read client ids
    // let ignore_client_id = matches.get_flag("ignore_client_id");
    // let client_ids = user_db.get_all_allowed_client_ids()?;
    // if !ignore_client_id {
    //   info!("allowed_client_ids {:?}", client_ids);
    // }

    // // get issuer
    // let token_issuer = match matches.get_one::<String>("token_issuer") {
    //   Some(t) => t,
    //   None => {
    //     bail!("Issuer must be specified");
    //   }
    // };
  }
}
