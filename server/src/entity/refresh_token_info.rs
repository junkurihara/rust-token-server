use crate::{constants::REFRESH_TOKEN_DURATION_MINS, error::*};
use chrono::{DateTime, Duration, Local};

use libcommon::{
  token_fields::{ClientId, RefreshToken, SubscriberId},
  TokenBody,
};

#[derive(sqlx::FromRow, Debug, Clone)]
pub struct RefreshTokenInfo {
  pub subscriber_id: SubscriberId,
  pub client_id: ClientId,
  pub inner: RefreshToken,
  pub expires: DateTime<Local>,
}
impl<'a> TryFrom<&'a TokenBody> for RefreshTokenInfo {
  type Error = crate::error::Error;

  fn try_from(value: &'a TokenBody) -> std::result::Result<Self, Self::Error> {
    let inner = value
      .refresh
      .as_ref()
      .ok_or_else(|| anyhow!("No refresh token"))?
      .to_owned();
    let subscriber_id = value.subscriber_id.clone();
    let client_id = value
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
