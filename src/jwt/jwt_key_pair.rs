use super::{
  alg::Algorithm,
  token::{Token, TokenInner, TokenMeta},
  ClientId, Issuer,
};
use crate::{constants::*, db::entity::*, error::*, log::*};
use jwt_simple::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Debug)]
pub struct AdditionalClaimData {
  pub is_admin: bool,
}
pub enum JwtKeyPair {
  EdDSA(Ed25519KeyPair),
  ES256(ES256KeyPair),
}

impl JwtKeyPair {
  /// Instantiate the object for given PEM formatted key string
  pub fn new(validation_algorithm: &Algorithm, key_str: &str, with_key_id: bool) -> Result<Self> {
    let kp = match validation_algorithm {
      Algorithm::ES256 => {
        let keypair = jwt_simple::algorithms::ES256KeyPair::from_pem(key_str)
          .map_err(|e| anyhow!("Error decoding private key: {}", e))?;
        if with_key_id {
          let mut pk = keypair.public_key();
          JwtKeyPair::ES256(keypair.with_key_id(pk.create_key_id()))
        } else {
          JwtKeyPair::ES256(keypair)
        }
      }
      Algorithm::EdDSA => {
        let keypair = jwt_simple::algorithms::Ed25519KeyPair::from_pem(key_str)
          .map_err(|e| anyhow!("Error decoding private key: {}", e))?;
        if with_key_id {
          let mut pk = keypair.public_key();
          JwtKeyPair::EdDSA(keypair.with_key_id(pk.create_key_id()))
        } else {
          JwtKeyPair::EdDSA(keypair)
        }
      }
    };
    Ok(kp)
  }

  /// Output public key of JWK form in serde_json::value::Value, i.e., JSON
  pub fn public_jwk(&self) -> Result<Value> {
    use jwt_compact::{
      alg::{Ed25519, Es256, VerifyingKey},
      jwk::JsonWebKey,
      Algorithm,
    };
    let (jwk_str, kid_opt) = match self {
      JwtKeyPair::ES256(sk) => {
        let pk = sk.public_key();
        let kid = pk.key_id().to_owned();
        type PublicKey = <Es256 as Algorithm>::VerifyingKey;
        let jwk_str = JsonWebKey::from(&<PublicKey as VerifyingKey<Es256>>::from_slice(&pk.to_bytes())?).to_string();
        (jwk_str, kid)
      }
      JwtKeyPair::EdDSA(sk) => {
        let pk = sk.public_key();
        let kid = pk.key_id().to_owned();
        type PublicKey = <Ed25519 as Algorithm>::VerifyingKey;
        let jwk_str = JsonWebKey::from(&<PublicKey as VerifyingKey<Ed25519>>::from_slice(&pk.to_bytes())?).to_string();
        (jwk_str, kid)
      }
    };
    let mut jwk = serde_json::from_str::<serde_json::Value>(jwk_str.as_ref())?;
    if let Some(kid) = kid_opt {
      jwk["kid"] = serde_json::Value::String(kid);
    }
    Ok(jwk)
  }

  /// common operations for JWT generation
  pub fn generate_token(
    &self,
    user: &User,
    client_id: &ClientId,
    token_issuer: &Issuer,
    refresh_required: bool,
  ) -> Result<Token> {
    let addition = AdditionalClaimData {
      is_admin: user.is_admin(),
    };
    let audiences = super::Audiences::new(client_id.as_str())?.into_string_hashset();
    let claims = Claims::with_custom_claims(addition, Duration::from_mins(JWT_DURATION_MINS as u64))
      .with_subject(user.subscriber_id())
      .with_issuer(token_issuer.as_str())
      .with_audiences(audiences);
    let jwt_str = self.generate_jwt_string(claims)?;
    let inner = TokenInner::new(jwt_str, refresh_required)?;
    let meta = TokenMeta::new(user);
    info!("[{}] Issued a JWT: {}", user.username(), inner);

    Ok(Token { inner, meta })
  }

  /// common operations for JWT verification
  pub fn verify_token(
    &self,
    token: &str,
    token_issuer: &Issuer,
    allowed_audiences: &Option<super::Audiences>,
  ) -> Result<JWTClaims<AdditionalClaimData>> {
    let mut options = VerificationOptions::default();
    if let Some(allowed) = allowed_audiences {
      options.allowed_audiences = Some(allowed.clone().into_string_hashset());
    }
    options.allowed_issuers = Some(HashSet::from_strings(&[token_issuer.as_str()]));
    self.verify_token_string(token, options)
  }

  /// Key-Type specific operations for JWT verification
  fn verify_token_string(&self, token: &str, options: VerificationOptions) -> Result<JWTClaims<AdditionalClaimData>> {
    match self {
      JwtKeyPair::ES256(sk) => sk
        .public_key()
        .verify_token::<AdditionalClaimData>(token, Some(options)),
      JwtKeyPair::EdDSA(sk) => sk
        .public_key()
        .verify_token::<AdditionalClaimData>(token, Some(options)),
    }
  }

  /// Key-Type specific operations for JWT generation
  fn generate_jwt_string(&self, claims: JWTClaims<AdditionalClaimData>) -> Result<String> {
    match self {
      JwtKeyPair::EdDSA(pk) => pk.sign(claims),
      JwtKeyPair::ES256(pk) => pk.sign(claims),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  const P256_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgv7zxW56ojrWwmSo1\n4uOdbVhUfj9Jd+5aZIB9u8gtWnihRANCAARGYsMe0CT6pIypwRvoJlLNs4+cTh2K\nL7fUNb5i6WbKxkpAoO+6T3pMBG5Yw7+8NuGTvvtrZAXduA2giPxQ8zCf\n-----END PRIVATE KEY-----";
  const EDDSA_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIDSHAE++q1BP7T8tk+mJtS+hLf81B0o6CFyWgucDFN/C\n-----END PRIVATE KEY-----";

  #[test]
  fn test_generate_and_verify() {
    init_logger();
    let user = User::new(&Username::new("test_user").unwrap(), None);
    assert!(user.is_ok());
    let user = user.unwrap();

    let client_id = ClientId::new("client_id").expect("ClientId creation failed");
    let token_issuer = Issuer::new("issuer").expect("Issuer creation failed");
    let refresh_required = true;

    let keys = [P256_PRIVATE_KEY, EDDSA_PRIVATE_KEY];
    let algs = [Algorithm::ES256, Algorithm::EdDSA];
    for (alg, key_str) in algs.iter().zip(keys.iter()) {
      let signing_key = JwtKeyPair::new(alg, key_str, false).unwrap();
      let token = signing_key.generate_token(&user, &client_id, &token_issuer, refresh_required);
      assert!(token.is_ok());

      let id_token = token.unwrap().inner.id;
      let validation_result = signing_key.verify_token(&id_token, &token_issuer, &None);
      assert!(validation_result.is_ok());
    }
  }
}
