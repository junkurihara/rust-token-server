use rocket::serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct PasswordCredentialRequest {
  pub username: String,
  pub password: String,
}
