/// Refresh token length in ascii
pub const REFRESH_TOKEN_LEN: u64 = 256;
/// Default duration of ID Token validity in minutes
/// TODO: Clapで設定できるように
pub const JWT_DURATION_MINS: usize = 30;
/// Default leeway in seconds to tolerate clock skew in validating `exp` and `nbf` of ID Token
pub const JWT_LEEWAY_SECS: i64 = 60;
