use super::RefreshTokenTable;
use crate::{constants::*, entity::*, error::*};
use async_trait::async_trait;
use chrono::TimeZone;
use sqlx::sqlite::SqlitePool;
use std::convert::TryInto;

#[derive(Debug, Clone)]
pub struct SqliteRefreshTokenTable {
  pool: SqlitePool,
}

impl SqliteRefreshTokenTable {
  pub fn new(pool: SqlitePool) -> Self {
    Self { pool }
  }

  pub async fn add_and_prune<'a>(&self, refresh_token: &'a RefreshToken) -> Result<()> {
    self.add(refresh_token).await?;
    self.prune_expired().await?;
    Ok(())
  }

  pub async fn prune_and_find<'a>(
    &self,
    refresh_token_string: &'a RefreshTokenInner,
    client_id: &'a ClientId,
  ) -> Result<Option<RefreshToken>> {
    self.prune_expired().await?;
    self.find_refresh_token(refresh_token_string, client_id).await
  }
}

#[async_trait]
impl RefreshTokenTable for SqliteRefreshTokenTable {
  async fn add<'a>(&self, refresh_token: &'a RefreshToken) -> Result<()> {
    let sql = format!(
      "insert into {} (subscriber_id, client_id, refresh_token, expires) VALUES (?, ?, ?, ?)",
      REFRESH_TOKEN_TABLE_NAME
    );
    let _res = sqlx::query(&sql)
      .bind(refresh_token.subscriber_id.as_str())
      .bind(refresh_token.client_id.as_str())
      .bind(refresh_token.inner.as_str())
      .bind(refresh_token.expires.timestamp())
      .execute(&self.pool)
      .await?;
    Ok(())
  }

  async fn find_refresh_token<'a>(
    &self,
    refresh_token_string: &'a RefreshTokenInner,
    client_id: &'a ClientId,
  ) -> Result<Option<RefreshToken>> {
    let current = chrono::Local::now().timestamp();
    let sql = format!(
      "select * from {} where client_id='{}' and refresh_token='{}' and expires>{}",
      REFRESH_TOKEN_TABLE_NAME,
      client_id.as_str(),
      refresh_token_string.as_str(),
      current
    );
    let refresh_token_row_opt: Option<RefreshTokenRow> = sqlx::query_as(&sql).fetch_optional(&self.pool).await?;
    if let Some(refresh_token_row) = refresh_token_row_opt {
      let refresh_token: RefreshToken = refresh_token_row.try_into()?;
      Ok(Some(refresh_token))
    } else {
      Ok(None)
    }
  }

  async fn prune_expired(&self) -> Result<()> {
    let current = chrono::Local::now().timestamp();
    let sql = format!("delete from {} where expires < {}", REFRESH_TOKEN_TABLE_NAME, current);
    let _res = sqlx::query(&sql).execute(&self.pool).await?;
    Ok(())
  }
}

#[derive(Debug, sqlx::FromRow)]
struct RefreshTokenRow {
  subscriber_id: String,
  client_id: String,
  #[sqlx(rename = "refresh_token")]
  inner: String,
  expires: i64,
}

impl TryInto<RefreshToken> for RefreshTokenRow {
  type Error = crate::error::Error;

  fn try_into(self) -> std::result::Result<RefreshToken, Self::Error> {
    let Some(expires) = chrono::Local.timestamp_opt(self.expires, 0).single() else {
      return Err(anyhow!("Invalid timestamp"));
    };
    let res = RefreshToken {
      subscriber_id: SubscriberId::new(self.subscriber_id)?,
      client_id: ClientId::new(self.client_id)?,
      inner: RefreshTokenInner::try_from(self.inner.as_str())?,
      expires,
    };
    Ok(res)
  }
}
