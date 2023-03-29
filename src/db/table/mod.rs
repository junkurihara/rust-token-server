mod user_table;

pub use user_table::SqliteUserTable;

use super::entity::{SubscriberId, User, Username};
use crate::error::*;
use async_trait::async_trait;

pub enum UserSearchKey<'a> {
  SubscriberId(&'a SubscriberId),
  Username(&'a Username),
}

#[async_trait]
pub trait UserTable {
  async fn add(&self, user: User) -> Result<()>;
  async fn find_user<'a>(&self, user_search_key: UserSearchKey<'a>) -> Result<Option<User>>;
}
