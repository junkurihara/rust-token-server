use crate::{
  entity::User,
  error::*,
  table::{SqliteRefreshTokenTable, SqliteUserTable},
};
use libcommon::{
  token_fields::{Audiences, ClientId, IdToken, Issuer},
  Claims, SigningKey, TokenBody, TokenMeta, ValidationOptions,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

#[cfg(feature = "blind-signatures")]
use crate::log::*;
#[cfg(feature = "blind-signatures")]
use libcommon::blind_sig;
#[cfg(feature = "blind-signatures")]
use std::sync::{Arc, RwLock};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Token generated at server as a response to login request
pub struct Token {
  pub body: TokenBody,
  pub meta: TokenMeta,
}

/// For JWT
pub struct CryptoState {
  pub signing_key: SigningKey,
  pub issuer: Issuer,
  pub audiences: Option<Audiences>,
}

impl CryptoState {
  pub fn generate_token(&self, user: &User, client_id: &ClientId, refresh_required: bool) -> Result<Token> {
    let body = self.signing_key.authorize(
      &user.subscriber_id,
      client_id,
      &self.issuer,
      user.is_admin(),
      refresh_required,
    )?;
    let meta = TokenMeta {
      username: user.username().to_string(),
      is_admin: user.is_admin(),
    };

    Ok(Token { body, meta })
  }
  pub fn verify_token(&self, id_token: &IdToken) -> Result<Claims> {
    let mut iss = std::collections::HashSet::new();
    iss.insert(self.issuer.clone());

    let vo = ValidationOptions {
      allowed_audiences: self.audiences.clone(),
      allowed_issuers: Some(iss),
      ..Default::default()
    };

    self.signing_key.validate(id_token, &vo)
  }
}
pub struct TableState {
  pub user: SqliteUserTable,
  pub refresh_token: SqliteRefreshTokenTable,
}

pub struct AppState {
  pub listen_socket: SocketAddr,
  pub crypto: CryptoState,

  #[cfg(feature = "blind-signatures")]
  pub blind_crypto: BlindCryptoState,

  pub table: TableState,
}

// client ids = audiences テーブルは持つのをやめた。テーブルに格納する意味はあんまりなさそう。

/* ------------------------------------------------------ */
#[cfg(feature = "blind-signatures")]
/// For blind RSA signature
pub struct BlindCryptoState {
  /// RSA private key for blind signing
  pub signing_key: Arc<RwLock<blind_sig::RsaPrivateKey>>,
  /// Rotated at, in UNIX time
  pub rotated_at: Arc<std::sync::atomic::AtomicU64>,
  /// RSA key size in bits
  pub key_size: usize,
  /// Rotation period of RSA key pair to invalidate old tokens
  pub rotation_period: tokio::time::Duration,
}

#[cfg(feature = "blind-signatures")]
impl BlindCryptoState {
  /// Blind sign a token
  pub fn blind_sign(&self, blinded_token: &blind_sig::BlindedToken) -> Result<blind_sig::BlindSignature> {
    let Ok(sk) = self.signing_key.read() else {
      bail!("Failed to lock signing key");
    };
    sk.blind_sign(blinded_token)
  }

  /// Start RSA key rotation in a separate thread
  pub fn start_rotation(&self) {
    info!("Starting RSA key rotation for blind signature");
    let rotation_period = self.rotation_period;
    let key_size = self.key_size;
    let signing_key = self.signing_key.clone();
    let rotated_at = self.rotated_at.clone();
    tokio::spawn(async move {
      loop {
        tokio::time::sleep(rotation_period).await;
        let now = std::time::SystemTime::now()
          .duration_since(std::time::UNIX_EPOCH)
          .unwrap()
          .as_secs();
        rotated_at.store(now, std::sync::atomic::Ordering::Relaxed);

        let Ok(new_sk) = blind_sig::RsaPrivateKey::new(Some(key_size)) else {
          error!("Failed to generate new RSA key pair");
          continue;
        };
        let Ok(mut lock) = signing_key.write() else {
          error!("Failed to lock signing key");
          continue;
        };
        *lock = new_sk;
        let pk_id = lock.to_public_key().key_id();
        info!(
          "RSA key pair rotated successfully: new key id: {} (refreshed: {})",
          pk_id.unwrap_or_default(),
          now
        );
      }
    });
  }
}
