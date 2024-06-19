use crate::{
  auth::{TokenClient, TokenHttpClient},
  constants::*,
  error::*,
  log::*,
  message::*,
};
use libcommon::{blind_sig::*, token_fields::Field};
use rand::{rngs::OsRng, RngCore};

/* ---------------------------------------------------- */
// Blind signature related methods
impl<H> TokenClient<H>
where
  H: TokenHttpClient,
{
  /// Request a blind signature with randomly generated message
  pub async fn request_blind_signature_with_id_token(&self) -> Result<()> {
    // get id token
    let id_token_lock = self.id_token.read().await;
    let Some(token_inner) = id_token_lock.as_ref() else {
      bail!(AuthError::NoIdToken);
    };
    let id_token = token_inner.clone().id.clone();
    drop(id_token_lock);

    /* -- request blind signature on random message -- */
    // first update blind jwks key
    self.update_blind_validation_key().await?;

    // build random message
    let mut random_msg = [0u8; BLIND_MESSAGE_BYTES];
    OsRng.fill_bytes(&mut random_msg);

    // make the message blinded
    let pk = self.blind_validation_key.read().await;
    let Some(pk) = pk.as_ref() else {
      bail!(AuthError::NoBlindValidationKey);
    };
    let opts = BlindOptions::default();
    let blind_result = pk.blind(random_msg.as_slice(), Some(&opts))?;
    let blind_sign_req = BlindSignRequest {
      blinded_token: blind_result.blinded_token.clone(),
    };
    let mut blind_sign_endpoint = self.config.token_api.clone();
    blind_sign_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_BLIND_SIGN_PATH);

    let client_lock = self.http_client.read().await;
    let blind_sign_res = client_lock
      .post_json_with_bearer_token::<_, BlindSignResponse>(&blind_sign_endpoint, &blind_sign_req, id_token.as_str())
      .await?;
    drop(client_lock);

    let anonymous_token = pk.unblind(&blind_sign_res.blind_signature, &blind_result, random_msg.as_slice())?;
    let mut anon_token_lock = self.anonymous_token.write().await;
    anon_token_lock.replace(anonymous_token.clone());
    drop(anon_token_lock);

    let mut blind_expires_at_lock = self.blind_expires_at.write().await;
    blind_expires_at_lock.replace(blind_sign_res.expires_at);
    drop(blind_expires_at_lock);

    // verify the anonymous token
    self.verify_anonymous_token().await?;

    /* --------------- */
    Ok(())
  }

  /// Update blind jwks key
  async fn update_blind_validation_key(&self) -> Result<()> {
    let mut blind_jwks_endpoint = self.config.token_api.clone();
    blind_jwks_endpoint
      .path_segments_mut()
      .map_err(|_| AuthError::UrlError)?
      .push(ENDPOINT_BLIND_JWKS_PATH);

    let client_lock = self.http_client.read().await;
    let blind_jwks_res = client_lock.get_json::<JwksResponse>(&blind_jwks_endpoint).await?;
    drop(client_lock);

    let mut jwk = blind_jwks_res
      .keys
      .first()
      .ok_or_else(|| AuthError::NoJwkInBlindJwks)?
      .clone();
    let Some(jwk) = jwk.as_object_mut() else {
      bail!(AuthError::InvalidJwk);
    };
    let Some(kid_in_jwk) = jwk.get("kid").and_then(|v| v.as_str()) else {
      bail!(AuthError::NoKeyIdInBlindJwks);
    };
    let kid = kid_in_jwk.to_string();
    jwk.remove_entry("kid");

    let Ok(jwk_string) = serde_json::to_string(jwk) else {
      bail!(AuthError::FailedToSerializeJwk);
    };
    debug!("Matched JWK given at jwks endpoint is {}", &jwk_string);

    let jwk_value = serde_json::to_value(jwk)?;
    let blind_validation_key = RsaPublicKey::from_jwk(&jwk_value)?;
    // Check key id consistency
    if kid != blind_validation_key.key_id()? {
      bail!(AuthError::InvalidJwk);
    }

    let mut lock = self.blind_validation_key.write().await;
    lock.replace(blind_validation_key);
    drop(lock);

    info!("blind validation key updated");

    Ok(())
  }

  /// Verify anonymous token
  async fn verify_anonymous_token(&self) -> Result<()> {
    let anon_token_lock = self.anonymous_token.read().await;
    let Some(anon_token) = anon_token_lock.as_ref().cloned() else {
      bail!(AuthError::NoAnonymousToken);
    };
    drop(anon_token_lock);

    let vk_lock = self.blind_validation_key.read().await;
    let Some(blind_validation_key) = vk_lock.as_ref().cloned() else {
      bail!(AuthError::NoBlindValidationKey);
    };
    drop(vk_lock);

    let expires_at_lock = self.blind_expires_at.read().await;
    let Some(expires_in) = expires_at_lock.as_ref() else {
      bail!(AuthError::InvalidExpireTimeBlindValidationKey);
    };
    let expires_in = expires_in.to_owned();
    drop(expires_at_lock);

    // Check expiration
    let now = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs();
    ensure!(expires_in > now, AuthError::InvalidExpireTimeBlindValidationKey);

    // verify the signature validity
    ensure!(
      blind_validation_key.verify(&anon_token).is_ok(),
      AuthError::InvalidBlindSignature
    );

    Ok(())
  }

  /// Remaining seconds until expiration of anonymous token, i.e., until the rotation time of blind validation key
  pub async fn blind_remaining_seconds_until_expiration(&self) -> Result<i64> {
    // These return unix time in secs
    let expires_at_lock = self.blind_expires_at.read().await;
    let Some(expires_at) = expires_at_lock.as_ref().cloned() else {
      bail!(AuthError::InvalidExpireTimeBlindValidationKey);
    };
    drop(expires_at_lock);

    let current = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs();

    Ok((expires_at - current) as i64)
  }

  /// Get anonymous token
  pub async fn anonymous_token(&self) -> Result<AnonymousToken> {
    let token_lock = self.anonymous_token.read().await;
    let Some(token) = token_lock.as_ref() else {
      bail!(AuthError::NoAnonymousToken);
    };
    let token = token.clone();
    drop(token_lock);

    Ok(token)
  }
}
