use crate::error::*;
use std::str::FromStr;

#[derive(Debug, Clone)]
pub enum Algorithm {
  EdDSA,
  ES256,
}
impl FromStr for Algorithm {
  type Err = Error;
  fn from_str(s: &str) -> Result<Self> {
    match s {
      "ES256" => Ok(Algorithm::ES256),
      // "ES384" => Ok(Algorithm::ES384),
      // "RS256" => Ok(Algorithm::RS256),
      // "RS384" => Ok(Algorithm::RS384),
      // "PS256" => Ok(Algorithm::PS256),
      // "PS384" => Ok(Algorithm::PS384),
      // "PS512" => Ok(Algorithm::PS512),
      // "RS512" => Ok(Algorithm::RS512),
      "EdDSA" => Ok(Algorithm::EdDSA),
      _ => bail!("Invalid Algorithm Name"),
    }
  }
}
#[derive(Debug, Clone)]
pub enum AlgorithmType {
  Ec,
  Okp,
  // RSA,
}
impl Algorithm {
  pub fn get_type(&self) -> AlgorithmType {
    match self {
      Algorithm::ES256 => AlgorithmType::Ec,
      Algorithm::EdDSA => AlgorithmType::Okp,
    }
  }
}
