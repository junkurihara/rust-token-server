use crate::{
  argon2::*,
  constants::{ADMIN_USERNAME, PASSWORD_LEN},
  error::*,
  log::*,
};
use std::borrow::Cow;
use uuid::Uuid;
use validator::Validate;

#[derive(Debug, Clone, Eq, PartialEq, Validate)]
pub struct Username {
  #[validate(length(min = 1))]
  value: String,
}
impl Username {
  pub fn new<'a>(username: impl Into<Cow<'a, str>>) -> Result<Self> {
    let value = username.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
  pub fn as_str(&self) -> &str {
    &self.value
  }
  pub fn into_string(self) -> String {
    self.value
  }
}

#[derive(Debug, Clone, Validate)]
pub struct SubscriberId {
  #[validate(length(min = 1))]
  value: String,
}
impl SubscriberId {
  pub fn new<'a>(sub_id: impl Into<Cow<'a, str>>) -> Result<Self> {
    let value = sub_id.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
  pub fn as_str(&self) -> &str {
    &self.value
  }
  pub fn into_string(self) -> String {
    self.value
  }
}

#[derive(Debug, Clone, Validate)]
pub struct EncodedHash {
  #[validate(length(min = 1))]
  value: String,
}
impl EncodedHash {
  pub fn new(password: &Password) -> Result<Self> {
    let value = password.hash()?;
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
  pub fn new_from_raw<'a>(encoded_hash: impl Into<Cow<'a, str>>) -> Result<Self> {
    let value = encoded_hash.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
  pub fn as_str(&self) -> &str {
    &self.value
  }
  pub fn into_string(self) -> String {
    self.value
  }
}

#[derive(Debug, Clone)]
pub struct IsAdmin {
  value: bool,
}
impl IsAdmin {
  pub fn new(is_admin: bool) -> Result<Self> {
    let object = Self { value: is_admin };
    Ok(object)
  }
  pub fn into_string(self) -> String {
    self.value.to_string()
  }
  pub fn get(&self) -> bool {
    self.value
  }
}

#[derive(Debug, Clone, Validate)]
pub struct Password {
  #[validate(length(min = 1))]
  value: String,
}
impl Password {
  pub fn new<'a>(password: impl Into<Cow<'a, str>>) -> Result<Self> {
    let value = password.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
  pub fn as_str(&self) -> &str {
    &self.value
  }
  #[allow(dead_code)]
  pub fn into_string(self) -> String {
    self.value
  }
  pub fn hash(&self) -> Result<String> {
    let argon2_hash = generate_argon2(self.as_str())?;
    Ok(argon2_hash)
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
    let subscriber_id = SubscriberId {
      value: Uuid::new_v4().to_string(),
    };
    let encoded_hash = EncodedHash::new(&password_unwrapped)?;
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

// #[cfg(test)]
// mod tests {
//   #[test]
//   fn ok() {
//     println!("ok");
//   }
// }
