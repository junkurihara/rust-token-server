use super::{ClientId, Entity, SubscriberId, TryNewEntity};
use crate::{
  constants::{REFRESH_TOKEN_DURATION_MINS, REFRESH_TOKEN_LEN},
  error::*,
  jwt::Token,
};
use chrono::{DateTime, Duration, Local};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::{
  de::{self, Visitor},
  Deserialize, Serialize,
};
use std::{borrow::Cow, convert::TryFrom};
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
    let subscriber_id = value.inner.subscriber_id.clone();
    let client_id = value
      .inner
      .allowed_apps
      .get_one()
      .ok_or_else(|| anyhow!("No client id"))?
      .to_owned();
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
impl<'a, T> TryNewEntity<T> for RefreshTokenInner
where
  T: Into<Cow<'a, str>>,
{
  fn new(value: T) -> Result<Self> {
    let value = value.into().to_string();
    let object = Self { value };
    object.validate()?;
    Ok(object)
  }
}
impl Entity for RefreshTokenInner {
  // impl Entity for RefreshTokenInner {
  fn as_str(&self) -> &str {
    &self.value
  }
  fn into_string(self) -> String {
    self.value
  }
}
impl RefreshTokenInner {
  pub fn generate() -> Result<Self> {
    let value: String = thread_rng()
      .sample_iter(&Alphanumeric)
      .take(REFRESH_TOKEN_LEN)
      .map(char::from)
      .collect();
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
    struct RefreshTokenInnerVisitor;
    impl<'de> Visitor<'de> for RefreshTokenInnerVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("refresh token string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(RefreshTokenInnerVisitor)?;

    Ok(Self { value })
  }
}
