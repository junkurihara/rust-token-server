use crate::error::*;
use serde::{
  de::{self, Visitor},
  ser::SerializeSeq,
  Deserialize, Serialize,
};
use std::{borrow::Cow, collections::HashSet, convert::From};
use validator::Validate;

#[derive(Debug, Clone, Eq, PartialEq, Validate, Hash)]
pub struct ClientId {
  #[validate(length(min = 1))]
  value: String,
}
impl ClientId {
  pub fn new<'a>(client_id: impl Into<Cow<'a, str>>) -> Result<Self> {
    let value = client_id.into().to_string();
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
impl Serialize for ClientId {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    serializer.serialize_str(self.as_str())
  }
}

impl<'de> Deserialize<'de> for ClientId {
  fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    struct ClientIdVisitor;
    impl<'de> Visitor<'de> for ClientIdVisitor {
      type Value = String;
      fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("client app id string")
      }
      fn visit_str<E>(self, str: &str) -> Result<Self::Value, E>
      where
        E: de::Error,
      {
        Ok(str.to_owned())
      }
    }

    let value = deserializer.deserialize_str(ClientIdVisitor)?;

    Ok(Self { value })
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Audiences {
  value: HashSet<ClientId>,
}
impl Audiences {
  pub fn new<'a>(client_ids: impl Into<Cow<'a, str>>) -> Result<Self> {
    let s: String = client_ids.into().to_string();
    let value = s
      .split(',')
      .map(|s| ClientId::new(s).unwrap())
      .collect::<HashSet<ClientId>>();

    let object = Self { value };
    Ok(object)
  }
  pub fn into_string_hashset(self) -> HashSet<String> {
    self
      .value
      .into_iter()
      .map(|s| s.into_string())
      .collect::<HashSet<String>>()
  }
  pub fn get_one(&self) -> Option<&ClientId> {
    self.value.iter().next()
  }
  pub fn contains(&self, client_id: &ClientId) -> bool {
    self.value.contains(client_id)
  }
}
impl Serialize for Audiences {
  fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
  where
    S: serde::Serializer,
  {
    let hs = self.value.clone();
    let mut seq = serializer.serialize_seq(Some(hs.len()))?;
    for element in hs {
      seq.serialize_element(&element)?;
    }
    seq.end()
  }
}
impl<T> From<T> for Audiences
where
  T: std::iter::Iterator<Item = ClientId>,
{
  fn from(value: T) -> Self {
    let hs = value.into_iter().collect::<HashSet<ClientId>>();
    Self { value: hs }
  }
}
