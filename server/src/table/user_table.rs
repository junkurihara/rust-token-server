use super::{UserSearchKey, UserTable};
use crate::{constants::*, entity::*, error::*};
use async_trait::async_trait;
use sqlx::sqlite::SqlitePool;
use std::convert::{From, TryInto};
use validator::Validate;

use libcommon::token_fields::{Field, SubscriberId, TryNewField};

#[derive(Debug, Clone)]
pub struct SqliteUserTable {
  pool: SqlitePool,
}

impl SqliteUserTable {
  pub fn new(pool: SqlitePool) -> Self {
    Self { pool }
  }
}

#[async_trait]
impl UserTable for SqliteUserTable {
  async fn add(&self, user: User) -> Result<()> {
    let sql = format!(
      "insert into {} (username, subscriber_id, encoded_hash, is_admin) VALUES (?, ?, ?, ?)",
      USER_TABLE_NAME
    );
    let _res = sqlx::query(&sql)
      .bind(user.username.as_str())
      .bind(user.subscriber_id.as_str())
      .bind(user.encoded_hash.as_str())
      .bind(user.is_admin.into_string())
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  async fn delete_user<'a>(&self, user_search_key: UserSearchKey<'a>) -> Result<()> {
    let sql = match user_search_key {
      UserSearchKey::SubscriberId(sub_id) => {
        format!("delete from {} where subscriber_id=\"{}\"", USER_TABLE_NAME, sub_id.as_str())
      }
      UserSearchKey::Username(username) => format!("delete from {} where username=\"{}\"", USER_TABLE_NAME, username.as_str()),
    };
    let _res = sqlx::query(&sql).execute(&self.pool).await?;
    Ok(())
  }

  async fn list_users(&self, page: u32) -> Result<(Vec<User>, u32, u32)> {
    if page == 0 {
      bail!("Page number starts from 1");
    }
    let total_cnt = sqlx::query_scalar::<_, i64>(&format!("select count(*) from {}", USER_TABLE_NAME))
      .fetch_one(&self.pool)
      .await?;
    let total_pages = (total_cnt as f64 / MAX_USERS_PER_PAGE as f64).ceil() as u32;

    if page > total_pages {
      bail!("Page number exceeds total pages");
    }

    let sql = format!(
      "select * from {} order by username asc limit {} offset {}",
      USER_TABLE_NAME,
      MAX_USERS_PER_PAGE,
      (page - 1) * MAX_USERS_PER_PAGE
    );
    let user_rows: Vec<UserRow> = sqlx::query_as(&sql).fetch_all(&self.pool).await?;

    let users = user_rows
      .into_iter()
      .map(|row| row.try_into())
      .collect::<Result<Vec<User>>>()?;

    Ok((users, total_pages, total_cnt as u32))
  }

  async fn update_user<'a>(
    &self,
    subscriber_id: &SubscriberId,
    new_username: Option<&Username>,
    new_password: Option<&Password>,
  ) -> Result<()> {
    let sql = match (new_username, new_password) {
      (Some(username), None) => format!(
        "update {} set username=\"{}\" where subscriber_id=\"{}\"",
        USER_TABLE_NAME,
        username.as_str(),
        subscriber_id.as_str()
      ),
      (None, Some(password)) => {
        let encoded_hash = EncodedHash::generate(password)?;
        format!(
          "update {} set encoded_hash=\"{}\" where subscriber_id=\"{}\"",
          USER_TABLE_NAME,
          encoded_hash.as_str(),
          subscriber_id.as_str()
        )
      }
      (Some(username), Some(password)) => {
        let encoded_hash = EncodedHash::generate(password)?;
        format!(
          "update {} set username=\"{}\", encoded_hash=\"{}\" where subscriber_id=\"{}\"",
          USER_TABLE_NAME,
          username.as_str(),
          encoded_hash.as_str(),
          subscriber_id.as_str()
        )
      }
      (None, None) => {
        bail!("Both or either one of username and password must be specified");
      }
    };
    let _res = sqlx::query(&sql).execute(&self.pool).await?;
    Ok(())
  }

  async fn update_password<'a>(&self, user_search_key: UserSearchKey<'a>, new_password: &Password) -> Result<()> {
    let encoded_hash = EncodedHash::generate(new_password)?;
    let sql = match user_search_key {
      UserSearchKey::SubscriberId(sub_id) => format!(
        "update {} set encoded_hash=\"{}\" where subscriber_id=\"{}\"",
        USER_TABLE_NAME,
        encoded_hash.as_str(),
        sub_id.as_str()
      ),
      UserSearchKey::Username(username) => format!(
        "update {} set encoded_hash=\"{}\" where username=\"{}\"",
        USER_TABLE_NAME,
        encoded_hash.as_str(),
        username.as_str()
      ),
    };
    let _res = sqlx::query(&sql).execute(&self.pool).await?;
    Ok(())
  }

  async fn find_user<'a>(&self, user_search_key: UserSearchKey<'a>) -> Result<Option<User>> {
    let sql = match user_search_key {
      UserSearchKey::SubscriberId(sub_id) => {
        format!("select * from {} where subscriber_id='{}'", USER_TABLE_NAME, sub_id.as_str())
      }
      UserSearchKey::Username(username) => {
        format!("select * from {} where username='{}'", USER_TABLE_NAME, username.as_str())
      }
    };
    let user_row_opt: Option<UserRow> = sqlx::query_as(&sql).fetch_optional(&self.pool).await?;
    if let Some(user_row) = user_row_opt {
      let user: User = user_row.try_into()?;
      Ok(Some(user))
    } else {
      Ok(None)
    }
  }
}

#[derive(Debug, sqlx::FromRow)]
struct UserRow {
  username: String,
  subscriber_id: String,
  encoded_hash: String,
  is_admin: String,
}

impl From<User> for UserRow {
  fn from(value: User) -> Self {
    Self {
      username: value.username.into_string(),
      subscriber_id: value.subscriber_id.into_string(),
      encoded_hash: value.encoded_hash.into_string(),
      is_admin: value.is_admin.get().to_string(),
    }
  }
}

impl TryInto<User> for UserRow {
  type Error = crate::error::Error;

  fn try_into(self) -> std::result::Result<User, Self::Error> {
    let x = User {
      username: Username::new(self.username)?,
      subscriber_id: SubscriberId::new(self.subscriber_id)?,
      encoded_hash: EncodedHash::new(self.encoded_hash)?,
      is_admin: IsAdmin::new(self.is_admin.parse::<bool>()?)?,
    };
    x.username.validate()?;
    x.subscriber_id.validate()?;
    x.encoded_hash.validate()?;
    Ok(x)
  }
}
