pub const ENDPOINT_LOGIN_PATH: &str = "tokens";
pub const ENDPOINT_REFRESH_PATH: &str = "refresh";
pub const ENDPOINT_JWKS_PATH: &str = "jwks";
pub const ENDPOINT_CREATE_USER_PATH: &str = "create_user";
pub const ENDPOINT_DELETE_USER_PATH: &str = "delete_user";

#[cfg(feature = "blind-signatures")]
pub const BLIND_MESSAGE_BYTES: usize = 32;
#[cfg(feature = "blind-signatures")]
pub const ENDPOINT_BLIND_JWKS_PATH: &str = "blindjwks";
#[cfg(feature = "blind-signatures")]
pub const ENDPOINT_BLIND_SIGN_PATH: &str = "blindsign";
