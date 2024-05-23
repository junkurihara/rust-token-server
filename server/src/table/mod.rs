mod refresh_table;
mod user_table;

use crate::{
  constants::{ADMIN_PASSWORD_VAR, ADMIN_USERNAME},
  entity::{Password, RefreshTokenInfo, TryNewEntity, User, Username},
  error::*,
  log::*,
};
use async_trait::async_trait;
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use std::{env, str::FromStr};

use libcommon::token_fields::{ClientId, RefreshToken, SubscriberId};

pub use refresh_table::SqliteRefreshTokenTable;
pub use user_table::SqliteUserTable;

pub enum UserSearchKey<'a> {
  SubscriberId(&'a SubscriberId),
  Username(&'a Username),
}

#[async_trait]
pub trait UserTable {
  async fn add(&self, user: User) -> Result<()>;
  async fn delete_user<'a>(&self, user_search_key: UserSearchKey<'a>) -> Result<()>;
  async fn list_users(&self, page: u32) -> Result<(Vec<User>, u32, u32)>;
  async fn update_password<'a>(&self, user_search_key: UserSearchKey<'a>, new_password: &Password) -> Result<()>;
  async fn update_user<'a>(
    &self,
    subscriber_id: &SubscriberId,
    new_username: Option<&Username>,
    new_password: Option<&Password>,
  ) -> Result<()>;
  async fn find_user<'a>(&self, user_search_key: UserSearchKey<'a>) -> Result<Option<User>>;
}

#[async_trait]
pub trait RefreshTokenTable {
  async fn add<'a>(&self, refresh_token: &'a RefreshTokenInfo) -> Result<()>;
  async fn find_refresh_token<'a>(
    &self,
    refresh_token_string: &'a RefreshToken,
    client_id: &'a ClientId,
  ) -> Result<Option<RefreshTokenInfo>>;
  async fn prune_expired(&self) -> Result<()>;
}

/// Setup sqlite database with automatic creation of user, client, refresh token tables
pub async fn setup_sqlite(sqlite_url: &str) -> Result<(SqliteUserTable, SqliteRefreshTokenTable)> {
  let conn_opts = SqliteConnectOptions::from_str(sqlite_url)?.create_if_missing(true);
  let pool = SqlitePoolOptions::default().connect_with(conn_opts).await?;

  // Embed migrations into binary
  sqlx::migrate!("./migrations").run(&pool).await?;

  let user_table = SqliteUserTable::new(pool.clone());

  // Check existence of admin
  let res = user_table
    .find_user(UserSearchKey::Username(&Username::new(ADMIN_USERNAME)?))
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
      User::new(&Username::new(ADMIN_USERNAME)?, Some(p))?
    } else {
      User::new(&Username::new(ADMIN_USERNAME)?, None)?
    };

    user_table.add(user).await?;
  }

  let refresh_token_table = SqliteRefreshTokenTable::new(pool);

  Ok((user_table, refresh_token_table))
}
