use super::{verify_url, ClapSubCommand};
use crate::{
  constants::{DB_FILE_PATH, DEFAULT_ADDRESS, DEFAULT_ALGORITHM, DEFAULT_PORT},
  entity::*,
  error::*,
  jwt::{Algorithm, AlgorithmType, JwtKeyPair},
  state::{AppState, CryptoState, TableState},
  table::setup_sqlite,
};
use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};
use std::{fs, net::SocketAddr, str::FromStr};

pub(super) struct Run {}

#[async_trait]
impl ClapSubCommand for Run {
  fn subcmd() -> Command {
    Command::new("run").about("Run the authentication and token server")
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
        Arg::new("token_issuer")
          .short('t')
          .long("token-issuer")
          .required(true)
          .value_parser(verify_url)
          .value_name("URL")
          .help("Issuer of Id token specified as URL like \"https://example.com/issue\""),
      )
      .arg(
        Arg::new("client_ids")
          .short('c')
          .long("client-ids")
          .value_name("IDs")
          .help("Client ids allowed to connect the API server, split with comma like 'AAAA,BBBBB,CCCC'. If not specified, any client can be connected."),
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
    let keypair: JwtKeyPair = match sub_m.get_one::<String>("signing_key_path") {
      Some(p) => {
        if let Ok(content) = fs::read_to_string(p) {
          match algorithm.get_type() {
            AlgorithmType::Ec | AlgorithmType::Okp => JwtKeyPair::new(&algorithm, &content, with_key_id)?,
            // _ => bail!("Unsupported"),
          }
        } else {
          bail!("Failed to read private key");
        }
      }
      None => {
        bail!("Signing key path must be specified");
      }
    };

    let issuer = match sub_m.get_one::<String>("token_issuer") {
      Some(t) => Issuer::new(t)?,
      None => {
        bail!("Issuer must be specified");
      }
    };

    let audiences = sub_m
      .get_one::<String>("client_ids")
      .map(|s| Audiences::new(s).unwrap());

    let db_file_path: String = match sub_m.get_one::<String>("db_file_path") {
      Some(p) => p.to_string(),
      None => {
        bail!("Database path must be specified");
      }
    };

    // returns user and valid refresh token tables
    let (user_table, refresh_token_table) = setup_sqlite(&format!("sqlite:{}", db_file_path)).await?;

    Ok(Some(AppState {
      listen_socket,
      crypto: CryptoState {
        algorithm,
        keypair,
        issuer,
        audiences,
      },
      table: TableState {
        user: user_table,
        refresh_token: refresh_token_table,
      },
    }))
  }
}
