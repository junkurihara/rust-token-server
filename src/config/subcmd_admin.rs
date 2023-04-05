use super::ClapSubCommand;
use crate::{
  constants::{ADMIN_USERNAME, DB_FILE_PATH},
  entity::{Password, TryNewEntity, Username},
  error::*,
  table::{setup_sqlite, UserSearchKey, UserTable},
};
use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};

pub(super) struct Admin {}

#[async_trait]
impl ClapSubCommand for Admin {
  fn subcmd() -> Command {
    Command::new("admin")
      .about("Admin command to update admin password")
      .arg(
        Arg::new("admin_password")
          .short('p')
          .long("admin-password")
          .value_name("PASSWORD")
          .required(true)
          .help("SQLite database admin password"),
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

    let admin_name = Username::new(ADMIN_USERNAME).unwrap();
    let admin_password = Password::new(sub_m.get_one::<String>("admin_password").unwrap()).unwrap();

    // First setup sqlite if needed
    let (user_table, _) = setup_sqlite(&format!("sqlite:{}", db_file_path)).await?;
    let _res = user_table
      .update_password(UserSearchKey::Username(&admin_name), &admin_password)
      .await?;

    Ok(None)
  }
}
