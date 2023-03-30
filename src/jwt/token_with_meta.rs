use serde::Serialize;

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

#[derive(Serialize, Debug, Clone)]
pub struct TokenMetaData {
  pub(super) username: String,
  pub(super) is_admin: bool,
}

#[derive(Serialize, Debug, Clone)]
pub struct Token {
  pub inner: TokenInner,
  pub meta: TokenMetaData,
}
