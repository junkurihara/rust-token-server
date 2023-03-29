// let pool = sqlx::SqlitePool::connect("sqlite:test.db").await.unwrap();
// use std::str::FromStr;
// let conn_opts = sqlx::sqlite::SqliteConnectOptions::from_str("sqlite:test.db")
//   .unwrap()
//   .create_if_missing(true);
// let pool = sqlx::sqlite::SqlitePoolOptions::default()
//   .connect_with(conn_opts)
//   .await
//   .unwrap();

pub mod entity;
pub mod table;

// pub use self::table::SqliteUserTable;

use self::table::UserTable;
use crate::{constants::ADMIN_USERNAME, error::*, log::*};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::str::FromStr;

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

    // TODO: Using ENV var and consider client ids
    // admin password should be passed as an env var?
    let user = entity::User::new(&entity::Username::new(ADMIN_USERNAME)?, None)?;
    user_table.add(user).await?;
  }

  Ok(user_table)
}
