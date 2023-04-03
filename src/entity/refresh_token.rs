use super::SubscriberId;
use crate::{
  constants::{REFRESH_TOKEN_DURATION_MINS, REFRESH_TOKEN_LEN},
  error::*,
  jwt::{ClientId, Token},
};
use chrono::{DateTime, Duration, Local};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{de::Visitor, Deserialize, Serialize};
use std::convert::TryFrom;
use validator::Validate;

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct RefreshToken {
  pub subscriber_id: SubscriberId,
  pub client_id: ClientId,
  pub inner: RefreshTokenInner,
  pub expires: DateTime<Local>,
}
impl<'a> TryFrom<&'a Token> for RefreshToken {
  type Error = crate::error::Error;

  fn try_from(value: &'a Token) -> std::result::Result<Self, Self::Error> {
    let inner = value
      .inner
      .refresh
      .as_ref()
      .ok_or_else(|| anyhow!("No refresh token"))?
      .to_owned();
    let subscriber_id = SubscriberId::new(&value.inner.subscriber_id)?;
    let client_id = ClientId::new(value.inner.allowed_apps.get(0).ok_or_else(|| anyhow!("No client id"))?)?;
    let expires = Local::now() + Duration::minutes(REFRESH_TOKEN_DURATION_MINS as i64);
    Ok(Self {
      inner,
      subscriber_id,
      client_id,
      expires,
    })
  }
}

#[derive(Debug, Clone, Eq, PartialEq, Validate)]
pub struct RefreshTokenInner {
  #[validate(length(equal = "REFRESH_TOKEN_LEN"))]
  value: String,
}
impl RefreshTokenInner {
  pub fn new() -> Result<Self> {
    let value: String = thread_rng()
      .sample_iter(&Alphanumeric)
      .take(REFRESH_TOKEN_LEN)
      .map(char::from)
      .collect();
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
impl<'a> TryFrom<&'a str> for RefreshTokenInner {
  type Error = crate::error::Error;

  fn try_from(value: &'a str) -> std::result::Result<Self, Self::Error> {
    let value = value.to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Serialize for RefreshTokenInner {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

impl<'de> Deserialize<'de> for RefreshTokenInner {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    // let v: Result<String, D::Error> = deserializer.deserialize_string(self);

    struct RefreshTokenInnerVisitor;
    impl<'de> Visitor<'de> for RefreshTokenInnerVisitor {
      type Value = RefreshTokenInner;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("refresh token string")
      }
      fn visit_str<E>(self, value: &str) -> Result<RefreshTokenInner, E>
      where
        E: serde::de::Error,
      {
        let object = RefreshTokenInner {
          value: value.to_string(),
        };
        object.validate().map_err(|e| serde::de::Error::custom(e))?;
        Ok(object)
      }
    }
    todo!()
  }
}
