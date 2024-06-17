use anyhow::{bail, ensure, Result};
use base64::{engine::general_purpose, Engine as _};
use blind_rsa_signatures::{reexports::rsa::pkcs1::EncodeRsaPublicKey, Options};
use jwt_compact::jwk::JsonWebKey;
use rsa::pkcs1::DecodeRsaPublicKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_RSA_BIT_SIZE: usize = 4096;

/// RSA private key wrapper for blind RSA signatures
pub struct RsaPrivateKey {
  inner: blind_rsa_signatures::SecretKey,
}

impl RsaPrivateKey {
  /// Build private key, usually we should use this and should not use static key.
  /// Since we should not add expiration time to the token in order to avoid the privacy leakages, we should dynamically generate the key and rotate it periodically.
  pub fn new(bits: Option<usize>) -> Result<Self> {
    let rng = &mut rand::thread_rng();
    let key = blind_rsa_signatures::SecretKey::new(blind_rsa_signatures::reexports::rsa::RsaPrivateKey::new(
      rng,
      bits.unwrap_or(DEFAULT_RSA_BIT_SIZE),
    )?);
    Ok(Self { inner: key })
  }
  /// Derive key from pem string to use a static private  key
  pub fn from_pem(pem: &str) -> Result<Self> {
    let key = blind_rsa_signatures::SecretKey::from_pem(pem)?;
    Ok(Self { inner: key })
  }
  /// Expose public key
  pub fn to_public_key(&self) -> RsaPublicKey {
    RsaPublicKey {
      inner: blind_rsa_signatures::PublicKey(self.inner.0.to_public_key()),
    }
  }
  /// Blind sign
  /// To avoid leaking the privacy of the user, we should not add any extra information to the token in addition to the original blind message.
  pub fn blind_sign(&self, blinded_token: &BlindedToken) -> Result<BlindSignature> {
    let rng = &mut rand::thread_rng();
    let blind_opts = Options::try_from(blinded_token.blind_opts.clone())?;
    let blind_msg = blinded_token.blind_msg.clone();
    let blind_sig = self.inner.blind_sign(rng, &blind_msg, &blind_opts)?;

    Ok(BlindSignature {
      inner: blind_sig,
      key_id: self.to_public_key().key_id()?,
    })
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// RSA public key wrapper for blind RSA signatures
pub struct RsaPublicKey {
  inner: blind_rsa_signatures::PublicKey,
}

impl RsaPublicKey {
  /// Derive key from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let key = blind_rsa_signatures::PublicKey::from_pem(pem)?;
    Ok(Self { inner: key })
  }
  /// Export jwk public key
  pub fn to_jwk(&self) -> Result<serde_json::Value> {
    let kid = self.key_id()?;
    let doc = self.inner.0.to_pkcs1_der()?;
    let inner = rsa::RsaPublicKey::from_pkcs1_der(doc.as_bytes())?;
    let jwk = JsonWebKey::from(&inner);

    let mut jwk = serde_json::to_value(jwk)?;
    jwk["kid"] = serde_json::Value::String(kid);
    Ok(jwk)
  }
  /// Import jwk public key
  pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self> {
    // let kid = jwk["kid"].as_str().ok_or_else(|| anyhow!("missing kid"))?;
    let jwk_parsed: JsonWebKey<'_> = serde_json::from_value(jwk.clone())?;
    match &jwk_parsed {
      JsonWebKey::Rsa { private_parts: None, .. } => {
        use rsa::pkcs1::EncodeRsaPublicKey;
        let inner = rsa::RsaPublicKey::try_from(&jwk_parsed)?;
        let doc = inner.to_pkcs1_der()?;
        let inner = blind_rsa_signatures::PublicKey::from_der(doc.as_bytes())?;
        Ok(Self { inner })
      }
      JsonWebKey::Rsa {
        private_parts: Some(_), ..
      } => bail!("private key parts found in jwk"),
      _ => bail!("unsupported key type"),
    }
  }
  /// Create key id
  pub fn key_id(&self) -> Result<String> {
    use base64::{engine::general_purpose, Engine as _};

    let bytes = self.inner.0.to_pkcs1_der()?.to_vec();
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(hash))
  }
  /// Blind a message
  pub fn blind(&self, message: &[u8], opts: Option<&BlindOptions>) -> Result<BlindResult> {
    let opts = opts.unwrap_or(&BlindOptions::default()).clone();
    let rng = &mut rand::thread_rng();
    let blinding_result = self.inner.blind(rng, message, true, &opts.clone().try_into()?)?;
    Ok(BlindResult {
      blinded_token: BlindedToken {
        blind_msg: blinding_result.blind_msg,
        blind_opts: opts,
      },
      blind_secret: blinding_result.secret,
      msg_randomizer: blinding_result.msg_randomizer,
    })
  }

  /// Unblind (finalize) the message and signature by redeeming the blinding
  pub fn unblind(&self, blind_sig: &BlindSignature, blind_result: &BlindResult, org_msg: &[u8]) -> Result<AnonymousToken> {
    let secret = &blind_result.blind_secret;
    let opts = blind_result.blinded_token.blind_opts.clone().try_into()?;
    let sig = self
      .inner
      .finalize(&blind_sig.inner, secret, blind_result.msg_randomizer, org_msg, &opts)?;
    let rnd = blind_result
      .msg_randomizer
      .as_ref()
      .ok_or_else(|| anyhow::anyhow!("missing msg_randomizer"))?
      .0;
    let opt = blind_result.blinded_token.blind_opts.clone();
    Ok(AnonymousToken {
      message: org_msg.to_vec(),
      randomizer: rnd,
      signature: UnblindedSignature {
        inner: sig,
        key_id: blind_sig.key_id.clone(),
      },
      options: opt,
    })
  }

  /// Verify the signature of the unblinded message
  pub fn verify(&self, anonymous_token: &AnonymousToken) -> Result<()> {
    let key_id = self.key_id()?;
    ensure!(key_id == anonymous_token.signature.key_id, "key_id mismatch");
    let sig = anonymous_token.signature.inner.clone();
    let rnd = blind_rsa_signatures::MessageRandomizer::new(anonymous_token.randomizer);
    let opt = Options::try_from(anonymous_token.options.clone())?;

    sig.verify(&self.inner, Some(rnd), anonymous_token.message.as_slice(), &opt)?;
    Ok(())
  }
}

/* ------------------------------------------------------ */
/// Blind result wrapper including blind token
#[derive(Debug, Clone)]
pub struct BlindResult {
  pub blinded_token: BlindedToken,
  /// This should not be exposed to the server
  pub blind_secret: blind_rsa_signatures::Secret,
  /// This should not be exposed to the signer, but be exposed to the verifier
  pub msg_randomizer: Option<blind_rsa_signatures::MessageRandomizer>,
}

/// This includes the blinded message and blinding options sent towards the server from the client
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlindedToken {
  pub blind_msg: blind_rsa_signatures::BlindedMessage,
  pub blind_opts: BlindOptions,
}

impl BlindedToken {
  pub fn new(blind_msg: &[u8], blind_opts: &BlindOptions) -> Self {
    Self {
      blind_msg: blind_rsa_signatures::BlindedMessage(blind_msg.to_vec()),
      blind_opts: blind_opts.clone(),
    }
  }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// blinding options
pub struct BlindOptions {
  hash: Hash,
  deterministic: bool,
  salt_len: Option<usize>,
}

impl TryFrom<BlindOptions> for Options {
  type Error = anyhow::Error;

  fn try_from(val: BlindOptions) -> std::result::Result<Self, Self::Error> {
    if val.deterministic {
      ensure!(val.salt_len.is_none(), "salt_len must be None for deterministic");
      return Ok(Options::new(val.hash.into(), val.deterministic, 0));
    }
    ensure!(val.salt_len.is_some(), "salt_len must be Some for non-deterministic");
    ensure!(val.salt_len.unwrap() > 0, "salt_len must be greater than 0");
    Ok(Options::new(val.hash.into(), val.deterministic, val.salt_len.unwrap()))
  }
}

impl Default for BlindOptions {
  fn default() -> Self {
    use blind_rsa_signatures::reexports::digest::DynDigest;
    BlindOptions {
      hash: Hash::Sha384,
      deterministic: false,
      salt_len: Some(blind_rsa_signatures::reexports::hmac_sha512::sha384::Hash::new().output_size()),
    }
  }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Hash {
  Sha256,
  Sha384,
  Sha512,
}

impl From<Hash> for blind_rsa_signatures::Hash {
  fn from(val: Hash) -> Self {
    match val {
      Hash::Sha256 => blind_rsa_signatures::Hash::Sha256,
      Hash::Sha384 => blind_rsa_signatures::Hash::Sha384,
      Hash::Sha512 => blind_rsa_signatures::Hash::Sha512,
    }
  }
}
/* ------------------------------------------------------ */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BlindSignature {
  inner: blind_rsa_signatures::BlindSignature,
  key_id: String,
}
/* ------------------------------------------------------ */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UnblindedSignature {
  pub inner: blind_rsa_signatures::Signature,
  pub key_id: String,
}

/* ------------------------------------------------------ */
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AnonymousToken {
  pub message: Vec<u8>,
  pub randomizer: [u8; 32],
  pub signature: UnblindedSignature,
  pub options: BlindOptions,
}

impl TryFrom<AnonymousToken> for String {
  type Error = anyhow::Error;

  fn try_from(value: AnonymousToken) -> std::result::Result<Self, Self::Error> {
    let value = serde_json::to_string(&value)?;
    Ok(value)
  }
}

impl AnonymousToken {
  /// Convert to base64url string
  pub fn try_into_base64url(&self) -> Result<String> {
    let json_string = serde_json::to_string(&self)?;
    let base64urlsafenopad = general_purpose::URL_SAFE_NO_PAD.encode(json_string.as_bytes());
    Ok(base64urlsafenopad)
  }
  /// Convert from base64url string
  pub fn try_from_base64url(base64urlsafenopad: &str) -> Result<Self> {
    let json_bytes = general_purpose::URL_SAFE_NO_PAD.decode(base64urlsafenopad.as_bytes())?;
    let json_string = std::str::from_utf8(&json_bytes)?;
    let value: AnonymousToken = serde_json::from_str(json_string)?;
    Ok(value)
  }
}

/* ------------------------------------------------------ */
#[cfg(test)]
mod tests {
  use super::*;
  const RSA4096_PRIVATE_KEY: &str = r#"
-----BEGIN PRIVATE KEY-----
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
xIoypu3j0VDHdKednmFQATGplDQ0fw==
-----END PRIVATE KEY-----
"#;
  const RSA4096_PUBLIC_KEY: &str = r#"
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAvT9bXbmqSxn3JrvqWwRz
KU8D6Yr6+FRKt3BV8XgjbPZE/Wyl5oh1FslUsgWjafRB+E43qsWNkYoxDwcUtQGE
B9jveelG3DrmYrTiPySv+E3X5ZXZGtWTvaxVUyWvn11L3qNU1+naG5C0DQqq/2ui
mgqu9kbcfNdjZoVC0PSzplMBult7YFTiGz5CJiGf6WVGSe5rmhoYxvT2+7PqcrQl
RT4hMncSo4PDDh7Xaoa9L2uFD+Qd2+YINUqcS2XHiPHZ6iLQbErSlZwxAudCWUWj
sGONDLJX6OuZVQWR7BJSrPfiDu+0dOuN903SzHZzV43INRBpSfvebFhWy3H6Twql
iXNDQOz7Nougyy8JL1cf5h/JgU9c9AtKmdBUtyaCLVw31c3joS8doQOM33+KlePg
4bbBu27+uuH9KRcPGCDO66V5fJSu+899WT2k1KXy3XjhHaR1RwCl63M/tvRSAPkA
X46M5kPo0mU8S+vi3DXNT6LSGxz5m9j/jVRxx+YNBNSgm4py42lF/1kyxCOwRezk
mxNDUBhjkPClQ1Joi0ut0SxYx31rtUDV8iu6W8abWrCIVALFp/PVM9CxI75S7FHM
2P+jJxQIzYQ1BlqjE3Mse/fj9d8pSd2nu+gJIBiaTSvlOyFW70gp0bjfQU1lnsjx
y7MrHkPEJgI1F3dSiAmbJbECAwEAAQ==
-----END PUBLIC KEY-----
"#;

  #[test]
  fn test_from_pem() {
    let sk = RsaPrivateKey::from_pem(RSA4096_PRIVATE_KEY).unwrap();
    let pk = sk.to_public_key();
    let jwk = pk.to_jwk().unwrap();
    println!("{}", jwk);
    let pk2 = RsaPublicKey::from_jwk(&jwk).unwrap();
    assert!(pk.inner.0 == pk2.inner.0);
    let pk3 = RsaPublicKey::from_pem(RSA4096_PUBLIC_KEY).unwrap();
    assert!(pk.inner.0 == pk3.inner.0);

    let msg = b"hello world";

    // [Client] Make a blind token for the message, send blind_result.blinded_token to the server
    let opts = BlindOptions::default();
    let blind_result = pk.blind(msg, Some(&opts)).unwrap();

    // [Signer] Blind sign the message
    let blind_sig = sk.blind_sign(&blind_result.blinded_token).unwrap();
    assert!(blind_sig.key_id == pk.key_id().unwrap());

    // [Client] Unblind the signature and make an anonymous token, then sent anonymous_token to the verifier
    let anonymous_token = pk.unblind(&blind_sig, &blind_result, msg).unwrap();
    let base64url_anonymous_token = anonymous_token.try_into_base64url().unwrap();

    println!("{}", base64url_anonymous_token);

    // [Verifier] Fetch the public key and verify the signature
    let anonymous_token = AnonymousToken::try_from_base64url(&base64url_anonymous_token).unwrap();
    let res = pk.verify(&anonymous_token);
    assert!(res.is_ok());
  }

  #[test]
  fn test_with_dynamic_generated_key() {
    let sk = RsaPrivateKey::new(Some(2048)).unwrap();
    let pk = sk.to_public_key();
    let jwk = pk.to_jwk().unwrap();
    println!("{}", jwk);
    let pk2 = RsaPublicKey::from_jwk(&jwk).unwrap();
    assert!(pk.inner.0 == pk2.inner.0);

    let msg = b"hello world";

    // [Client] Make a blind token for the message, send blind_result.blinded_token to the server
    let opts = BlindOptions::default();
    let blind_result = pk.blind(msg, Some(&opts)).unwrap();

    // [Signer] Blind sign the message
    let blind_sig = sk.blind_sign(&blind_result.blinded_token).unwrap();
    assert!(blind_sig.key_id == pk.key_id().unwrap());

    // [Client] Unblind the signature and make an anonymous token, then sent anonymous_token to the verifier
    let anonymous = pk.unblind(&blind_sig, &blind_result, msg).unwrap();
    let base64url_anonymous_token = anonymous.try_into_base64url().unwrap();

    println!("{}", base64url_anonymous_token);

    // [Verifier] Fetch the public key and verify the signature
    let anonymous_token = AnonymousToken::try_from_base64url(&base64url_anonymous_token).unwrap();
    let res = pk.verify(&anonymous_token);
    assert!(res.is_ok());
  }
}
