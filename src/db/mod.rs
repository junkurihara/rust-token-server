pub mod entity;
pub mod table;

use self::table::UserTable;
use crate::{
  constants::{ADMIN_PASSWORD_VAR, ADMIN_USERNAME},
  db::entity::Password,
  error::*,
  log::*,
};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{env, str::FromStr};

/// Setup sqlite database with automatic creation of user, client, refresh token tables
pub async fn setup_sqlite(sqlite_url: &str) -> Result<table::SqliteUserTable> {
  let conn_opts = SqliteConnectOptions::from_str(sqlite_url)?.create_if_missing(true);
  let pool = SqlitePoolOptions::default().connect_with(conn_opts).await?;

  // Embed migrations into binary
  sqlx::migrate!("./migrations").run(&pool).await?;

  let user_table = table::SqliteUserTable::new(pool.clone());

  // Check existence of admin
  let res = user_table
    .find_user(table::UserSearchKey::Username(&entity::Username::new(ADMIN_USERNAME)?))
    .await?;
  if res.is_none() {
    warn!(
      r#"
-----------------------------------------------------------------------------------------------------------------------
No admin user exist in DB. So we generate the user of name "admin".
Unless ADMIN_PASSWORD was passed through an environment variable, the admin password is randomly generated.
Note the admin password is never automatically overridden by the environment variable if "admin" exists in user table.
If the admin password needs to be updated, call "admin" subcommand.
-----------------------------------------------------------------------------------------------------------------------
"#
    );

    let user = if let Ok(admin_password) = env::var(ADMIN_PASSWORD_VAR) {
      let p = Password::new(admin_password)?;
      entity::User::new(&entity::Username::new(ADMIN_USERNAME)?, Some(p))?
    } else {
      entity::User::new(&entity::Username::new(ADMIN_USERNAME)?, None)?
    };

    user_table.add(user).await?;
  }

  Ok(user_table)
}
