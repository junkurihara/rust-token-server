use super::ClapSubCommand;
use crate::{
  constants::{ADMIN_USERNAME, DB_FILE_PATH},
  error::*,
};
use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};

pub(super) struct Admin {}

#[async_trait]
impl ClapSubCommand for Admin {
  fn subcmd() -> Command {
    Command::new("admin")
      .arg(
        Arg::new("admin_password")
          .short('p')
          .long("admin-password")
          .value_name("PASSWORD")
          .required(true)
          .help("SQLite database admin password"),
      )
      .arg(
        Arg::new("client_ids")
          .short('c')
          .long("client-ids")
          .value_name("IDs")
          .help("Client ids allowed to connect the API server, split with comma like \"AAAA,BBBBB,CCCC\""),
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
    let db_file_path: String = match sub_m.get_one::<String>("db_file_path") {
      Some(p) => p.to_string(),
      None => {
        bail!("Database path must be specified");
      }
    };

    // // Setting up globals
    // let user_db = UserDB {
    //   db_file_path,
    //   allowed_client_table_name: ALLOWED_CLIENT_TABLE_NAME.to_string(),
    //   user_table_name: USER_TABLE_NAME.to_string(),
    //   token_table_name: TOKEN_TABLE_NAME.to_string(),
    // };

    let admin_name = ADMIN_USERNAME;
    let admin_password = sub_m.get_one::<String>("admin_password");

    let client_ids = sub_m.get_one::<String>("client_ids");
    // match client_ids {
    //   Some(cids) => user_db.init_db(
    //     admin_name.as_ref().map(AsRef::as_ref),
    //     admin_password.as_ref().map(AsRef::as_ref),
    //     cids.split(',').collect::<Vec<&str>>(),
    //   )?,
    //   None => user_db.init_db(
    //     admin_name.as_ref().map(AsRef::as_ref),
    //     admin_password.as_ref().map(AsRef::as_ref),
    //     vec![],
    //   )?,
    // };
    Ok(None)
  }
}
