use crate::{auth::generate_argon2, utils};
use crate::error::*;
use fallible_streaming_iterator::FallibleStreamingIterator;
use log::{debug, error, info, warn};
use rusqlite::{params, Connection, Result};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct UserInfo {
  id: usize,
  username: String,
  subscriber_id: String,
  encoded_hash: String, // including salt and argon2 config
  is_admin: bool,
}

impl UserInfo {
  pub fn get_encoded_hash<'a>(&'a self) -> &'a str {
    &self.encoded_hash
  }
  pub fn is_admin<'a>(&'a self) -> &'a bool {
    &self.is_admin
  }
  pub fn get_username<'a>(&'a self) -> &'a str {
    &self.username
  }
  pub fn get_subscriber_id<'a>(&'a self) -> &'a str {
    &self.subscriber_id
  }
}

#[derive(Debug, Clone)]
pub struct UserDB {
  pub user_table_name: String,
  pub allowed_client_table_name: String,
  pub token_table_name: String,
  pub event_log_table_name: String,
  pub db_file_path: String,
}

pub enum UserSearchKey<'a> {
  SubscriberId(&'a str),
  Username(&'a str),
}

impl UserDB {
  pub fn init_db(
    self,
    admin_name: Option<&str>,
    admin_password: Option<&str>,
    allowed_client_ids: Vec<&str>,
  ) -> Result<(), Error> {
    // create table if not exist
    let conn = Connection::open(&self.db_file_path)?;
    // user table
    let sql = format!(
      "create table if not exists {} (
      id integer primary key,
      username text not null unique,
      subscriber_id text not null unique,
      encoded_hash text not null,
      is_admin integer
    )",
      &self.user_table_name
    );
    conn.execute(&sql, params![])?;

    // client_id table
    let sql = format!(
      "create table if not exists {} (
      id integer primary key,
      client_id text not null unique
    )",
      &self.allowed_client_table_name
    );
    conn.execute(&sql, params![])?;

    // token table
    // TODO: remove expired tokens periodically
    let sql = format!(
      "create table if not exists {} (
          id integer primary key,
          subscriber_id text,
          client_id text,
          refresh_token text,
          expires integer
        )",
      &self.token_table_name
    );
    conn.execute(&sql, params![])?;

    // event_log table
    let sql = format!(
      "create table if not exists {} (
          rid integer primary key autoincrement,
          subscriber_id text,
          utime integer,
          eid integer
        )",
      &self.event_log_table_name
    );
    conn.execute(&sql, params![])?;
    let sql = format!(
      "CREATE INDEX IF NOT EXISTS idx_event_log_subscriber_id ON {}(subscriber_id)",
      &self.event_log_table_name
    );
    conn.execute(&sql, params![])?;
    let sql = format!(
      "CREATE INDEX IF NOT EXISTS idx_event_log_utime ON {}(utime);",
      &self.event_log_table_name
    );
    conn.execute(&sql, params![])?;
    let sql = format!(
      "CREATE INDEX IF NOT EXISTS idx_event_log_eid ON {}(eid);",
      &self.event_log_table_name
    );
    conn.execute(&sql, params![])?;

    // create admin user if no user exist
    let row_num = self._count_all_members(&conn, &self.user_table_name)?;
    if row_num == 0 {
      if let (Some(aid), Some(apassword)) = (admin_name, admin_password) {
        info!("no_user: create admin user with given username and password");
        self._add_user(&conn, aid, apassword, true)?;
      } else {
        conn.close().map_err(|(_, e)| anyhow!(e))?;
        bail!("DB admin name and password must be given at first for initialization. run \"init\"")
      }
    }

    // create admin user if no user exist
    let row_num = self._count_all_members(&conn, &self.allowed_client_table_name)?;
    if row_num == 0 {
      info!("no_client_ids: add client_ids: {:?}", allowed_client_ids);
      self._add_client_ids(&conn, &allowed_client_ids)?;
    }

    conn.close().map_err(|(_, e)| anyhow!(e))?;

    Ok(())
  }

  fn _count_all_members(&self, conn: &Connection, table_name: &str) -> Result<usize, Error> {
    let sql = &format!("select * from {}", table_name);
    let mut prep = conn.prepare(sql)?;
    let rows = prep.query(params![])?;
    let cnt = rows.count()?;
    return Ok(cnt);
  }

  pub fn get_user(&self, search_key: UserSearchKey) -> Result<Option<UserInfo>, Error> {
    let conn = Connection::open(&self.db_file_path)?;
    let user_info = self._get_user(&conn, search_key);
    conn.close().map_err(|(_, e)| anyhow!(e))?;
    user_info
  }

  fn _get_user(
    &self,
    conn: &Connection,
    search_key: UserSearchKey,
  ) -> Result<Option<UserInfo>, Error> {
    let sql = match search_key {
      UserSearchKey::SubscriberId(sub_id) => format!(
        "select * from {} where subscriber_id='{}'",
        self.user_table_name, sub_id
      ),
      UserSearchKey::Username(username) => format!(
        "select * from {} where username='{}'",
        self.user_table_name, username
      ),
    };
    let mut prep = conn.prepare(&sql)?;
    let mut rows = prep.query_map(params![], |row| {
      Ok(UserInfo {
        id: row.get(0)?,
        username: row.get(1)?,
        subscriber_id: row.get(2)?,
        encoded_hash: row.get(3)?,
        is_admin: row.get(4)?,
      })
    })?;
    let user_info = rows.next();

    // duplication check
    if let Some(_) = rows.next() {
      bail!("Database is corrupted, duplicated usernames");
    }

    match user_info {
      Some(x) => {
        let res = x?;
        return Ok(Some(res));
      }
      None => {
        return Ok(None);
      }
    }
  }

  pub fn get_all_allowed_client_ids(&self) -> Result<Vec<String>, Error> {
    let conn = Connection::open(&self.db_file_path)?;

    let sql = &format!("select * from {}", self.allowed_client_table_name);
    let mut nexts = vec![];
    {
      let mut prep = conn.prepare(sql)?;
      let mut rows = prep.query_map(params![], |row| Ok(row.get(1)?))?;
      while let Some(next) = rows.next() {
        nexts.push(next?)
      }
    }
    conn.close().map_err(|(_, e)| anyhow!(e))?;

    Ok(nexts)
  }

  fn _add_client_ids(&self, conn: &Connection, client_ids: &Vec<&str>) -> Result<(), Error> {
    let sql = &format!(
      "insert into {} (client_id) VALUES (?)",
      &self.allowed_client_table_name
    );
    for cid in client_ids {
      conn.execute(sql, params![*cid])?;
    }
    Ok(())
  }

  pub fn add_user(&self, username: &str, password: &str, is_admin: bool) -> Result<(), Error> {
    let conn = Connection::open(&self.db_file_path)?;
    let res = self._add_user(&conn, username, password, is_admin);
    conn.close().map_err(|(_, e)| anyhow!(e))?;
    res
  }

  fn _add_user(
    &self,
    conn: &Connection,
    username: &str,
    password: &str,
    is_admin: bool,
  ) -> Result<(), Error> {
    let admin_int: usize = match is_admin {
      true => 1,
      false => 0,
    };
    let sql = &format!(
      "insert into {} (username, subscriber_id, encoded_hash, is_admin) VALUES (?, ?, ?, ?)",
      self.user_table_name
    );
    let encoded_hash: &str = &generate_argon2(password)?;
    let subscriber_id: String = Uuid::new_v4().to_string();

    debug!(
      "subscriber_id is created for {}: {}",
      username, subscriber_id
    );
    conn.execute(
      sql,
      params![username, &subscriber_id, encoded_hash, admin_int],
    )?;

    Ok(())
  }

  pub fn add_event_log(&self, subscriber_id: &str, utime: u64, eid: u64) -> Result<(), Error> {
    let conn = Connection::open(&self.db_file_path)?;
    let res = self._add_event_log(&conn, subscriber_id, utime, eid);
    conn.close().map_err(|(_, e)| anyhow!(e))?;
    res
  }

  pub fn _add_event_log(&self, conn: &Connection, subscriber_id: &str, utime: u64, eid: u64) -> Result<(), Error> {
    let sql = &format!(
      "insert into {} (subscriber_id, utime, eid) VALUES (?, ?, ?)",
      self.event_log_table_name
    );
    conn.execute(
      sql,
      params![&subscriber_id, utime, eid],
    )?;

    Ok(())
  }

  pub fn add_refresh_token(
    &self,
    subscriber_id: &str,
    client_id: &str,
    refresh_token: &str,
    expires: u64,
    current: u64,
  ) -> Result<(), Error> {
    let conn = Connection::open(&self.db_file_path)?;

    {
      // add new refresh token
      let sql = &format!(
        "insert into {} (subscriber_id, client_id, refresh_token, expires) VALUES (?, ?, ?, ?)",
        &self.token_table_name
      );

      conn.execute(
        sql,
        params![subscriber_id, client_id, refresh_token, expires as u64],
      )?;
    }
    {
      // prune expired tokens
      let sql = &format!(
        "delete from {} where expires < {}",
        &self.token_table_name, current
      );
      conn.execute(sql, params![])?;
    }
    conn.close().map_err(|(_, e)| anyhow!(e))?;

    Ok(())
  }

  pub fn get_subid_for_refresh_token(
    &self,
    client_id: &str,
    refresh_token: &str,
    current: u64,
  ) -> Result<Option<String>, Error> {
    let conn = Connection::open(&self.db_file_path)?;

    let subscriber_id = {
      // search valid access token
      let sql = &format!(
        "select * from {} where client_id='{}' and refresh_token='{}' and expires>{}",
        &self.token_table_name, client_id, refresh_token, current
      );

      // get sub id
      #[derive(Debug)]
      struct SubId(String);
      let mut nexts = vec![];
      {
        let mut prep = conn.prepare(sql)?;
        let mut rows = prep.query_map(params![], |row| Ok(SubId(row.get(1)?)))?;
        while let Some(next) = rows.next() {
          nexts.push(next?)
        }
      }
      debug!("Exist refresh token for {:?} ", nexts);
      if nexts.len() > 0 {
        Some(nexts[0].0.clone())
      } else {
        None
      }
    };
    {
      // prune expired tokens
      let sql = &format!(
        "delete from {} where expires < {}",
        &self.token_table_name, current
      );
      conn.execute(sql, params![])?;
    }
    conn.close().map_err(|(_, e)| anyhow!(e))?;

    Ok(subscriber_id)
  }
}
