use super::{EncodedHash, Entity, Password, SubscriberId, TryNewEntity, Username};
use crate::{
  constants::{ADMIN_USERNAME, PASSWORD_LEN},
  error::*,
  log::*,
};
use rand::prelude::*;
use serde::Serialize;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct IsAdmin {
  value: bool,
}
impl TryNewEntity<bool> for IsAdmin {
  fn new(is_admin: bool) -> Result<Self> {
    let object = Self { value: is_admin };
    Ok(object)
  }
}
impl IsAdmin {
  pub fn into_string(self) -> String {
    self.value.to_string()
  }
  pub fn get(&self) -> bool {
    self.value
  }
}
impl Serialize for IsAdmin {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_bool(self.get())
  }
}

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct User {
  pub username: Username,
  pub subscriber_id: SubscriberId,
  pub encoded_hash: EncodedHash, // including salt and argon2 config
  pub is_admin: IsAdmin,
}

impl User {
  pub fn new(username: &Username, password: Option<Password>) -> Result<User> {
    let password_unwrapped = if let Some(p) = password {
      p
    } else {
      let random_pass = generate_random_string(PASSWORD_LEN)?;
      warn!(
        r#"
-----------------------------------------------------------------------------------------------------------------------
Password was automatically generated for the user of name "{}". Keep this securely.
{}
-----------------------------------------------------------------------------------------------------------------------
"#,
        username.as_str(),
        random_pass.as_str()
      );
      Password::new(random_pass)?
    };
    let subscriber_id = SubscriberId::new(Uuid::new_v4().to_string())?;
    let encoded_hash = EncodedHash::generate(&password_unwrapped)?;
    let is_admin = if username.as_str() == ADMIN_USERNAME {
      IsAdmin::new(true)
    } else {
      IsAdmin::new(false)
    }?;
    Ok(User {
      username: username.to_owned(),
      subscriber_id,
      encoded_hash,
      is_admin,
    })
  }

  pub fn encoded_hash(&self) -> &str {
    self.encoded_hash.as_str()
  }
  pub fn is_admin(&self) -> bool {
    self.is_admin.get()
  }
  pub fn username(&self) -> &str {
    self.username.as_str()
  }
  pub fn subscriber_id(&self) -> &str {
    self.subscriber_id.as_str()
  }
}

fn generate_random_string(length: usize) -> Result<String> {
  const BASE_STR: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let mut rng = &mut rand::thread_rng();
  let res = String::from_utf8(BASE_STR.as_bytes().choose_multiple(&mut rng, length).cloned().collect())?;
  Ok(res)
}

#[cfg(test)]
mod tests {
  use super::*;
  #[test]
  fn random_string_works() {
    let length = 32;
    let random_string = generate_random_string(length);
    assert!(random_string.is_ok());
    assert_eq!(random_string.unwrap().len(), length);
  }
}
