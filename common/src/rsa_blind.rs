use anyhow::{bail, ensure, Result};
use base64::{engine::general_purpose, Engine as _};
use blind_rsa_signatures::{HashAlgorithm, PSSZero, Randomized, PSS};
use rsa::{pkcs1::EncodeRsaPublicKey, traits::PublicKeyParts, BoxedUint};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_RSA_BIT_SIZE: usize = 4096;
/// Key type of RSA in JWK
const JWK_KEY_TYPE_RSA: &str = "RSA";

#[derive(Serialize, Deserialize)]
/// RSA public key in JWK (RFC 7517), where unsupported parameters such as `kid` are ignored in parsing
struct RsaJwk {
  kty: String,
  /// Modulus in base64url
  n: String,
  /// Public exponent in base64url
  e: String,
}

/// Key containers of blind-rsa-signatures.
/// Key parsing, key generation and blind signing do not depend on the hash function, the salt mode and the message preparation,
/// so the type-level parameters are fixed here only to hold keys.
/// Parameters for blinding, finalization and verification are resolved at runtime from `BlindOptions`.
type InnerSecretKey = blind_rsa_signatures::SecretKey<blind_rsa_signatures::Sha384, PSS, Randomized>;
type InnerPublicKey = blind_rsa_signatures::PublicKey<blind_rsa_signatures::Sha384, PSS, Randomized>;

/// Build `blind_rsa_signatures::PublicKey` from the raw RSA public key `$raw_key` with the type-level parameters given by `BlindParams`,
/// bind it to `$pk`, and then evaluate `$body`.
/// Message preparation is always randomized.
macro_rules! with_blind_public_key {
  ($params:expr, $raw_key:expr, |$pk:ident| $body:expr) => {{
    let raw_key = $raw_key;
    match $params {
      BlindParams::Sha256Pss => {
        let $pk = blind_rsa_signatures::PublicKey::<blind_rsa_signatures::Sha256, PSS, Randomized>::new(raw_key.clone());
        $body
      }
      BlindParams::Sha256PssZero => {
        let $pk = blind_rsa_signatures::PublicKey::<blind_rsa_signatures::Sha256, PSSZero, Randomized>::new(raw_key.clone());
        $body
      }
      BlindParams::Sha384Pss => {
        let $pk = blind_rsa_signatures::PublicKey::<blind_rsa_signatures::Sha384, PSS, Randomized>::new(raw_key.clone());
        $body
      }
      BlindParams::Sha384PssZero => {
        let $pk = blind_rsa_signatures::PublicKey::<blind_rsa_signatures::Sha384, PSSZero, Randomized>::new(raw_key.clone());
        $body
      }
      BlindParams::Sha512Pss => {
        let $pk = blind_rsa_signatures::PublicKey::<blind_rsa_signatures::Sha512, PSS, Randomized>::new(raw_key.clone());
        $body
      }
      BlindParams::Sha512PssZero => {
        let $pk = blind_rsa_signatures::PublicKey::<blind_rsa_signatures::Sha512, PSSZero, Randomized>::new(raw_key.clone());
        $body
      }
    }
  }};
}

/// RSA private key wrapper for blind RSA signatures
pub struct RsaPrivateKey {
  inner: InnerSecretKey,
}

impl RsaPrivateKey {
  /// Build private key, usually we should use this and should not use static key.
  /// Since we should not add expiration time to the token in order to avoid the privacy leakages, we should dynamically generate the key and rotate it periodically.
  pub fn new(bits: Option<usize>) -> Result<Self> {
    let rng = &mut rand::rng();
    let key_pair = blind_rsa_signatures::KeyPair::generate(rng, bits.unwrap_or(DEFAULT_RSA_BIT_SIZE))?;
    Ok(Self { inner: key_pair.sk })
  }
  /// Derive key from pem string to use a static private  key
  pub fn from_pem(pem: &str) -> Result<Self> {
    let key = InnerSecretKey::from_pem(pem)?;
    Ok(Self { inner: key })
  }
  /// Expose public key
  pub fn to_public_key(&self) -> RsaPublicKey {
    // RSA parameters of the inner key have already been checked at generation or parsing
    let inner = rsa::RsaPublicKey::from(self.inner.as_ref());
    RsaPublicKey {
      inner: InnerPublicKey::new(inner),
    }
  }
  /// Blind sign
  /// To avoid leaking the privacy of the user, we should not add any extra information to the token in addition to the original blind message.
  pub fn blind_sign(&self, blinded_token: &BlindedToken) -> Result<BlindSignature> {
    // Blind signing itself does not depend on the blinding options, but reject unsupported ones here
    BlindParams::try_from(&blinded_token.blind_opts)?;
    let rng = &mut rand::rng();
    let blind_sig = self.inner.blind_sign_with_rng(rng, &blinded_token.blind_msg)?;

    Ok(BlindSignature {
      inner: blind_sig,
      key_id: self.to_public_key().key_id()?,
    })
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// RSA public key wrapper for blind RSA signatures
pub struct RsaPublicKey {
  inner: InnerPublicKey,
}

impl RsaPublicKey {
  /// Derive key from pem string
  pub fn from_pem(pem: &str) -> Result<Self> {
    let key = InnerPublicKey::from_pem(pem)?;
    Ok(Self { inner: key })
  }
  /// Export jwk public key
  pub fn to_jwk(&self) -> Result<serde_json::Value> {
    let kid = self.key_id()?;
    let key = self.inner.as_ref();
    let jwk = RsaJwk {
      kty: JWK_KEY_TYPE_RSA.to_string(),
      n: general_purpose::URL_SAFE_NO_PAD.encode(key.n().to_be_bytes_trimmed_vartime()),
      e: general_purpose::URL_SAFE_NO_PAD.encode(key.e().to_be_bytes_trimmed_vartime()),
    };

    let mut jwk = serde_json::to_value(jwk)?;
    jwk["kid"] = serde_json::Value::String(kid);
    Ok(jwk)
  }
  /// Import jwk public key
  pub fn from_jwk(jwk: &serde_json::Value) -> Result<Self> {
    // let kid = jwk["kid"].as_str().ok_or_else(|| anyhow!("missing kid"))?;
    ensure!(jwk["kty"] == JWK_KEY_TYPE_RSA, "unsupported key type");
    // `d` is required for RSA private keys (RFC 7518 Section 6.3.2)
    ensure!(jwk.get("d").is_none(), "private key parts found in jwk");
    let jwk_parsed: RsaJwk = serde_json::from_value(jwk.clone())?;

    let n = general_purpose::URL_SAFE_NO_PAD.decode(&jwk_parsed.n)?;
    let e = general_purpose::URL_SAFE_NO_PAD.decode(&jwk_parsed.e)?;
    let n = BoxedUint::from_be_slice_vartime(&n);
    let e = BoxedUint::from_be_slice(&e, rsa::RsaPublicKey::MAX_PUB_EXPONENT.ilog2() + 1)
      .map_err(|e| anyhow::anyhow!("invalid public exponent: {e}"))?;
    let inner = rsa::RsaPublicKey::new(n, e)?;
    // Import via DER to check the RSA parameters (modulus size and public exponent) by blind-rsa-signatures
    let doc = inner.to_pkcs1_der()?;
    let inner = InnerPublicKey::from_der(doc.as_bytes())?;
    Ok(Self { inner })
  }
  /// Create key id
  pub fn key_id(&self) -> Result<String> {
    use base64::{engine::general_purpose, Engine as _};

    let bytes = self.inner.as_ref().to_pkcs1_der()?.to_vec();
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update(&bytes);
    let hash = hasher.finalize();
    Ok(general_purpose::URL_SAFE_NO_PAD.encode(hash))
  }
  /// Blind a message
  pub fn blind(&self, message: &[u8], opts: Option<&BlindOptions>) -> Result<BlindResult> {
    let opts = opts.unwrap_or(&BlindOptions::default()).clone();
    let params = BlindParams::try_from(&opts)?;
    let rng = &mut rand::rng();
    let blinding_result = with_blind_public_key!(params, self.inner.as_ref(), |pk| pk.blind(rng, message))?;
    Ok(BlindResult {
      blinded_token: BlindedToken {
        blind_msg: blinding_result.blind_message,
        blind_opts: opts,
      },
      blind_secret: blinding_result.secret,
      msg_randomizer: blinding_result.msg_randomizer,
    })
  }

  /// Unblind (finalize) the message and signature by redeeming the blinding
  pub fn unblind(&self, blind_sig: &BlindSignature, blind_result: &BlindResult, org_msg: &[u8]) -> Result<AnonymousToken> {
    let params = BlindParams::try_from(&blind_result.blinded_token.blind_opts)?;
    let blinding_result = blind_rsa_signatures::BlindingResult {
      blind_message: blind_result.blinded_token.blind_msg.clone(),
      secret: blind_result.blind_secret.clone(),
      msg_randomizer: blind_result.msg_randomizer,
    };
    let sig = with_blind_public_key!(params, self.inner.as_ref(), |pk| pk.finalize(
      &blind_sig.inner,
      &blinding_result,
      org_msg
    ))?;
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
    let sig = &anonymous_token.signature.inner;
    let rnd = blind_rsa_signatures::MessageRandomizer::new(anonymous_token.randomizer);
    let params = BlindParams::try_from(&anonymous_token.options)?;

    with_blind_public_key!(params, self.inner.as_ref(), |pk| pk.verify(
      sig,
      Some(rnd),
      anonymous_token.message.as_slice()
    ))?;
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
  pub blind_msg: blind_rsa_signatures::BlindMessage,
  pub blind_opts: BlindOptions,
}

impl BlindedToken {
  pub fn new(blind_msg: &[u8], blind_opts: &BlindOptions) -> Self {
    Self {
      blind_msg: blind_rsa_signatures::BlindMessage(blind_msg.to_vec()),
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

/// Combination of the hash function and the PSS salt mode validated from `BlindOptions`,
/// which is mapped to the type-level parameters of blind-rsa-signatures.
#[derive(Debug, Clone, Copy)]
enum BlindParams {
  Sha256Pss,
  Sha256PssZero,
  Sha384Pss,
  Sha384PssZero,
  Sha512Pss,
  Sha512PssZero,
}

impl TryFrom<&BlindOptions> for BlindParams {
  type Error = anyhow::Error;

  fn try_from(val: &BlindOptions) -> std::result::Result<Self, Self::Error> {
    // Deterministic padding means PSS without salt
    if val.deterministic {
      ensure!(val.salt_len.is_none(), "salt_len must be None for deterministic");
      return Ok(match val.hash {
        Hash::Sha256 => Self::Sha256PssZero,
        Hash::Sha384 => Self::Sha384PssZero,
        Hash::Sha512 => Self::Sha512PssZero,
      });
    }
    let Some(salt_len) = val.salt_len else {
      bail!("salt_len must be Some for non-deterministic");
    };
    // blind-rsa-signatures supports only the salt length equal to the hash output length for PSS with salt
    let (params, hash_len) = match val.hash {
      Hash::Sha256 => (Self::Sha256Pss, blind_rsa_signatures::Sha256::SALT_LEN),
      Hash::Sha384 => (Self::Sha384Pss, blind_rsa_signatures::Sha384::SALT_LEN),
      Hash::Sha512 => (Self::Sha512Pss, blind_rsa_signatures::Sha512::SALT_LEN),
    };
    ensure!(
      salt_len == hash_len,
      "salt_len must be equal to the hash output length ({hash_len} bytes) for non-deterministic"
    );
    Ok(params)
  }
}

impl Default for BlindOptions {
  fn default() -> Self {
    BlindOptions {
      hash: Hash::Sha384,
      deterministic: false,
      salt_len: Some(blind_rsa_signatures::Sha384::SALT_LEN),
    }
  }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum Hash {
  Sha256,
  Sha384,
  Sha512,
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
    assert!(pk.inner == pk2.inner);
    let pk3 = RsaPublicKey::from_pem(RSA4096_PUBLIC_KEY).unwrap();
    assert!(pk.inner == pk3.inner);

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
    assert!(pk.inner == pk2.inner);

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

  #[test]
  fn test_jwk() {
    let pk = RsaPrivateKey::from_pem(RSA4096_PRIVATE_KEY).unwrap().to_public_key();
    let jwk = pk.to_jwk().unwrap();
    assert_eq!(jwk["kty"], "RSA");
    assert_eq!(jwk["e"], "AQAB");
    assert_eq!(jwk["kid"], pk.key_id().unwrap().as_str());
    // 4096-bit modulus without leading zeros
    let n = general_purpose::URL_SAFE_NO_PAD.decode(jwk["n"].as_str().unwrap()).unwrap();
    assert_eq!(n.len(), 512);
    assert_ne!(n[0], 0);
    assert!(RsaPublicKey::from_jwk(&jwk).unwrap() == pk);

    let modified = |name: &str, value: serde_json::Value| {
      let mut modified = jwk.clone();
      modified[name] = value;
      modified
    };
    let invalid_jwks = [
      // Private key parts
      modified("d", jwk["n"].clone()),
      // Other key types
      modified("kty", "EC".into()),
      modified("kty", serde_json::Value::Null),
      // Too small modulus to be accepted by blind-rsa-signatures
      modified("n", general_purpose::URL_SAFE_NO_PAD.encode(&n[..128]).into()),
      // Too large public exponent
      modified("e", general_purpose::URL_SAFE_NO_PAD.encode([1u8; 8]).into()),
      // Invalid base64url
      modified("e", "AQAB=".into()),
    ];
    for invalid_jwk in invalid_jwks.iter() {
      assert!(RsaPublicKey::from_jwk(invalid_jwk).is_err(), "{invalid_jwk}");
    }
  }

  #[test]
  fn test_blind_options() {
    let sk = RsaPrivateKey::from_pem(RSA4096_PRIVATE_KEY).unwrap();
    let pk = sk.to_public_key();
    let msg = b"hello world";

    // Supported combinations: PSS with salt length equal to the hash output length, and PSS without salt (deterministic)
    let supported = [
      (Hash::Sha256, false, Some(32)),
      (Hash::Sha384, false, Some(48)),
      (Hash::Sha512, false, Some(64)),
      (Hash::Sha256, true, None),
      (Hash::Sha384, true, None),
      (Hash::Sha512, true, None),
    ];
    for (hash, deterministic, salt_len) in supported {
      let opts = BlindOptions {
        hash,
        deterministic,
        salt_len,
      };
      let blind_result = pk.blind(msg, Some(&opts)).unwrap();
      let blind_sig = sk.blind_sign(&blind_result.blinded_token).unwrap();
      let anonymous_token = pk.unblind(&blind_sig, &blind_result, msg).unwrap();
      assert!(pk.verify(&anonymous_token).is_ok());

      // Verification must fail for a different message
      let mut tampered = anonymous_token.clone();
      tampered.message = b"hello world!".to_vec();
      assert!(pk.verify(&tampered).is_err());
    }

    // Unsupported combinations
    let unsupported = [
      (Hash::Sha384, false, Some(32)),
      (Hash::Sha384, false, None),
      (Hash::Sha384, true, Some(48)),
    ];
    for (hash, deterministic, salt_len) in unsupported {
      let opts = BlindOptions {
        hash,
        deterministic,
        salt_len,
      };
      assert!(pk.blind(msg, Some(&opts)).is_err());
    }
  }
}
