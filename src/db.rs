use crate::auth::generate_argon2;
use crate::error::*;
use log::{debug, error, info, warn};
use rusqlite::{params, Connection, Result};

#[derive(Debug, Clone)]
pub struct UserInfo {
  id: usize,
  username: String,
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
}

#[derive(Debug, Clone)]
pub struct UserDB {
  pub user_table_name: String,
  pub db_file_path: String,
}

impl UserDB {
  pub fn init_db(
    self,
    admin_name: Option<&str>,
    admin_password: Option<&str>,
  ) -> Result<(), Error> {
    // create table if not exist
    let conn = Connection::open(&self.db_file_path)?;
    let sql = format!(
      "create table if not exists {} (
      id integer primary key,
      username text not null unique,
      encoded_hash text not null,
      is_admin integer
    )",
      &self.user_table_name
    );
    conn.execute(&sql, params![])?;

    // create admin user if no user exist
    let row_num = self._count_all_users(&conn)?;
    if row_num == 0 {
      if let (Some(aid), Some(apassword)) = (admin_name, admin_password) {
        info!("no_user: create admin user with given username and password");
        self._add_user(&conn, aid, apassword, true)?;
      } else {
        conn.close().map_err(|(_, e)| anyhow!(e))?;
        bail!("DB admin name and password must be given at first for initialization. run \"init\"")
      }
    }
    conn.close().map_err(|(_, e)| anyhow!(e))?;

    Ok(())
  }

  fn _count_all_users(&self, conn: &Connection) -> Result<usize, Error> {
    let sql = &format!("select count(*) from {}", &self.user_table_name);
    let mut prep = conn.prepare(sql)?;
    let row_num = prep.query_row(params![], |row| return row.get(0) as Result<usize>)?;
    return Ok(row_num);
  }

  pub fn get_user(&self, username: &str) -> Result<Option<UserInfo>, Error> {
    let conn = Connection::open(&self.db_file_path)?;
    let user_info = self._get_user(&conn, username);
    conn.close().map_err(|(_, e)| anyhow!(e))?;
    user_info
  }

  fn _get_user(&self, conn: &Connection, username: &str) -> Result<Option<UserInfo>, Error> {
    let sql = &format!(
      "select * from {} where username='{}'",
      self.user_table_name, username
    );
    let mut prep = conn.prepare(sql)?;
    let mut rows = prep.query_map(params![], |row| {
      Ok(UserInfo {
        id: row.get(0)?,
        username: row.get(1)?,
        encoded_hash: row.get(2)?,
        is_admin: row.get(3)?,
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
      "insert into {} (username, encoded_hash, is_admin) VALUES (?, ?, ?)",
      self.user_table_name
    );
    let encoded_hash: &str = &generate_argon2(password)?;

    conn.execute(sql, params![username, encoded_hash, admin_int])?;

    Ok(())
  }
}
