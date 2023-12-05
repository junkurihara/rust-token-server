mod alg;
mod jwt_key_pair;
// mod token;

use libcommon::{TokenBody, TokenMeta};
use serde::{Deserialize, Serialize};

pub use alg::{Algorithm, AlgorithmType};
pub use jwt_key_pair::{AdditionalClaimData, JwtKeyPair};
// pub use token::{Token, TokenInner, TokenMeta};

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Token generated at server as a response to login request
pub struct Token {
  pub body: TokenBody,
  pub meta: TokenMeta,
}
