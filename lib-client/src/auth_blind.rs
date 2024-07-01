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
  /// Request a blind signature with randomly generated message and stored blind validation key
  /// The request will be dispatched with the ID token
  pub async fn request_blind_signature_with_id_token(&self) -> AuthResult<()> {
    // get id token
    let id_token_lock = self.id_token.read().await;
    let Some(token_inner) = id_token_lock.as_ref() else {
      return Err(AuthError::NoIdToken);
    };
    let id_token = token_inner.clone().id.clone();
    drop(id_token_lock);

    /* -- request blind signature on random message -- */
    // build random message
    let mut random_msg = [0u8; BLIND_MESSAGE_BYTES];
    OsRng.fill_bytes(&mut random_msg);

    // make the message blinded
    let pk = self.blind_validation_key.read().await;
    let Some(pk) = pk.as_ref() else {
      return Err(AuthError::NoBlindValidationKey);
    };
    let opts = BlindOptions::default();
    let blind_result = pk
      .blind(random_msg.as_slice(), Some(&opts))
      .map_err(AuthError::FailedToMakeBlindSignatureRequest)?;
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

    let anonymous_token = pk
      .unblind(&blind_sign_res.blind_signature, &blind_result, random_msg.as_slice())
      .map_err(AuthError::FailedToUnblindSignedResponse)?;
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

  /// Is hosted blind jwks key updated?
  /// If updated, the inner key is updated and returns Ok(true), otherwise Ok(false)
  pub async fn update_blind_validation_key_if_stale(&self) -> AuthResult<bool> {
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
      return Err(AuthError::InvalidJwk);
    };
    let Some(kid_in_jwk) = jwk.get("kid").and_then(|v| v.as_str()) else {
      return Err(AuthError::NoKeyIdInBlindJwks);
    };
    let kid = kid_in_jwk.to_string();
    jwk.remove_entry("kid");

    let Ok(jwk_string) = serde_json::to_string(jwk) else {
      return Err(AuthError::FailedToSerializeJwk);
    };
    debug!("Matched JWK given at blindjwks endpoint is {}", &jwk_string);

    let jwk_value = serde_json::to_value(jwk)?;
    let fetched_key = RsaPublicKey::from_jwk(&jwk_value).map_err(AuthError::FailedToParseJwk)?;
    // Check key id consistency
    if kid != fetched_key.key_id().map_err(AuthError::BlindKeyIdParseError)? {
      return Err(AuthError::InvalidJwk);
    }

    let lock = self.blind_validation_key.read().await;
    let Some(current_key) = lock.as_ref() else {
      // update the key if it is not set
      drop(lock);
      self.replace_blind_validation_key(fetched_key).await?;
      return Ok(true);
    };
    if current_key != &fetched_key {
      // update the key if it is different
      drop(lock);
      self.replace_blind_validation_key(fetched_key).await?;
      return Ok(true);
    }
    drop(lock);

    debug!("blind validation key is up-to-date");
    Ok(false)
  }

  /// Replace stored blind jwks key with new one
  async fn replace_blind_validation_key(&self, key: RsaPublicKey) -> AuthResult<()> {
    let mut lock = self.blind_validation_key.write().await;
    lock.replace(key);
    drop(lock);
    info!("blind validation key updated");

    Ok(())
  }

  /// Verify anonymous token
  async fn verify_anonymous_token(&self) -> AuthResult<()> {
    let anon_token_lock = self.anonymous_token.read().await;
    let Some(anon_token) = anon_token_lock.as_ref().cloned() else {
      return Err(AuthError::NoAnonymousToken);
    };
    drop(anon_token_lock);

    let vk_lock = self.blind_validation_key.read().await;
    let Some(blind_validation_key) = vk_lock.as_ref().cloned() else {
      return Err(AuthError::NoBlindValidationKey);
    };
    drop(vk_lock);

    let expires_at_lock = self.blind_expires_at.read().await;
    let Some(expires_at) = expires_at_lock.as_ref() else {
      return Err(AuthError::InvalidExpireTimeBlindValidationKey);
    };
    let expires_at = expires_at.to_owned();
    drop(expires_at_lock);

    // Check expiration
    let now = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs();
    if expires_at <= now {
      return Err(AuthError::InvalidExpireTimeBlindValidationKey);
    }

    // verify the signature validity
    blind_validation_key
      .verify(&anon_token)
      .map_err(|_| AuthError::InvalidBlindSignature)
  }

  /// Remaining seconds until expiration of anonymous token, i.e., until the rotation time of blind validation key
  pub async fn blind_remaining_seconds_until_expiration(&self) -> AuthResult<i64> {
    // These return unix time in secs
    let expires_at_lock = self.blind_expires_at.read().await;
    let Some(expires_at) = expires_at_lock.as_ref().cloned() else {
      return Err(AuthError::InvalidExpireTimeBlindValidationKey);
    };
    drop(expires_at_lock);

    let current = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_secs();

    Ok((expires_at - current) as i64)
  }

  /// Get anonymous token
  pub async fn anonymous_token(&self) -> AuthResult<AnonymousToken> {
    let token_lock = self.anonymous_token.read().await;
    let Some(token) = token_lock.as_ref() else {
      return Err(AuthError::NoAnonymousToken);
    };
    let token = token.clone();
    drop(token_lock);

    Ok(token)
  }
}
