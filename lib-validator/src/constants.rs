pub const ENDPOINT_JWKS_PATH: &str = "jwks";

#[cfg(feature = "blind-signatures")]
pub const ENDPOINT_BLIND_JWKS_PATH: &str = "blindjwks";

#[cfg(feature = "blind-signatures")]
pub const STALE_BLIND_JWKS_TIMEOUT_SEC: u64 = 60 * 60;
