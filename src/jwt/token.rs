use crate::{constants::*, db::entity::User, error::*, log::*};
use base64::Engine;
use chrono::{DateTime, Local, TimeZone};
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use serde::Serialize;
use serde_json::Value;
use std::fmt;

#[derive(Serialize, Debug, Clone)]
pub struct TokenInner {
  pub id: String, // id_token jwt itself is given here as string
  pub refresh: Option<String>,
  pub issued_at: String,
  pub expires: String,
  pub allowed_apps: Vec<String>, // allowed apps, i.e, client_ids
  pub issuer: String,            // like 'https://....' for IdToken
  pub subscriber_id: String,
}

impl fmt::Display for TokenInner {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f,
      "sub: {}, iss: {}, iat: {}, exp: {}, aud: {:?}",
      self.subscriber_id, self.issuer, self.issued_at, self.expires, self.allowed_apps
    )
  }
}

#[derive(Serialize, Debug, Clone)]
pub struct TokenMeta {
  pub(super) username: String,
  pub(super) is_admin: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct Token {
  pub inner: TokenInner,
  pub meta: TokenMeta,
}

impl TokenInner {
  pub(super) fn new(jwt_str: String, refresh_required: bool) -> Result<Self> {
    // get token info
    let parsed: Vec<&str> = jwt_str.split('.').collect();
    let decoded_claims =
      base64::engine::GeneralPurpose::new(&base64::alphabet::URL_SAFE, base64::engine::general_purpose::NO_PAD)
        .decode(parsed[1])?;
    let json_string = String::from_utf8(decoded_claims)?;
    let json_value: Value = serde_json::from_str(&json_string).map_err(|e| anyhow!("{}", e))?;

    let Some(subscriber_id) = json_value["sub"].as_str() else {
    bail!("No issuer is specified in JWT");
  };
    let iat = json_value["iat"].to_string().parse::<i64>()?;
    let exp = json_value["exp"].to_string().parse::<i64>()?;
    let Some(iss) = json_value["iss"].as_str() else {
    bail!("No issuer is specified in JWT");
  };
    let aud = if let Value::Array(aud_vec) = &json_value["aud"] {
      aud_vec
        .iter()
        .filter_map(|x| x.as_str())
        .map(|y| y.to_string())
        .collect()
    } else {
      vec![]
    };
    let issued_at: DateTime<Local> = Local.timestamp_opt(iat, 0).unwrap();
    let expires: DateTime<Local> = Local.timestamp_opt(exp, 0).unwrap();

    let refresh: Option<String> = if refresh_required {
      debug!("[{subscriber_id}] Create refresh token");
      Some(generate_refresh())
    } else {
      None
    };

    Ok(Self {
      id: jwt_str,
      refresh,
      issuer: iss.to_string(),
      allowed_apps: aud.to_vec(),
      issued_at: issued_at.to_string(),
      expires: expires.to_string(),
      subscriber_id: subscriber_id.to_string(),
    })
  }
}

impl TokenMeta {
  pub(super) fn new(user: &User) -> Self {
    Self {
      username: user.username().to_owned(),
      is_admin: user.is_admin(),
    }
  }
}

fn generate_refresh() -> String {
  thread_rng()
    .sample_iter(&Alphanumeric)
    .take(REFRESH_TOKEN_LEN)
    .map(char::from)
    .collect()
}

#[cfg(test)]
mod tests {
  use crate::db::entity::{Password, Username};

  use super::*;

  #[test]
  fn test_token_inner() {
    let test_vector = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE2ODAyNjIxNTgsImV4cCI6MTY4MDI2Mzk1OCwibmJmIjoxNjgwMjYyMTU4LCJpc3MiOiJpc3N1ZXIiLCJzdWIiOiJhNDYzZTY2Yi1jOThhLTQ4MjAtYWQyNy1mMzg3NGZlMmYzOTEiLCJhdWQiOlsiY2xpZW50X2lkIl0sImlzX2FkbWluIjpmYWxzZX0.tkR9CdX0sMRuI7jS_VGRs9Lojn7Xbuv1YXgnp0QkgiP1vMDo9xKPz7b5VmpaMI0Jg9muazdBbzZxhabJC9qiCA";

    let token_inner = TokenInner::new(test_vector.to_string(), true).expect("Token inner is invalid");
    assert!(token_inner.refresh.is_some());
    assert_eq!(&token_inner.issued_at, "2023-03-31 20:29:18 +09:00");
    assert_eq!(&token_inner.expires, "2023-03-31 20:59:18 +09:00");
    assert_eq!(token_inner.allowed_apps, vec!["client_id".to_string()]);
    assert_eq!(&token_inner.issuer, "issuer");
    assert_eq!(&token_inner.subscriber_id, "a463e66b-c98a-4820-ad27-f3874fe2f391");

    let token_inner = TokenInner::new(test_vector.to_string(), false).expect("Token inner is invalid");
    assert!(token_inner.refresh.is_none());
    assert_eq!(&token_inner.issued_at, "2023-03-31 20:29:18 +09:00");
    assert_eq!(&token_inner.expires, "2023-03-31 20:59:18 +09:00");
    assert_eq!(token_inner.allowed_apps, vec!["client_id".to_string()]);
    assert_eq!(&token_inner.issuer, "issuer");
    assert_eq!(&token_inner.subscriber_id, "a463e66b-c98a-4820-ad27-f3874fe2f391");
  }
  #[test]
  fn test_token_meta() {
    let username = Username::new("test_user").expect("username creation failed");
    let password = Password::new("test_pass").expect("password creation failed");
    let user = User::new(&username, Some(password)).expect("user creation failed");
    let token_meta = TokenMeta::new(&user);
    assert_eq!(token_meta.username, "test_user".to_string());
    assert!(!token_meta.is_admin);

    let username = Username::new("admin").expect("username creation failed");
    let password = Password::new("test_pass").expect("password creation failed");
    let user = User::new(&username, Some(password)).expect("user creation failed");
    let token_meta = TokenMeta::new(&user);
    assert_eq!(token_meta.username, "admin".to_string());
    assert!(token_meta.is_admin);
  }
  #[test]
  fn test_refresh() {
    let refresh = generate_refresh();
    assert_eq!(refresh.len(), REFRESH_TOKEN_LEN);
  }
}
