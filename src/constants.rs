use argon2::{Config, ThreadMode, Variant, Version};

pub const ALLOWED_CLIENT_TABLE_NAME: &str = "client_ids";
pub const USER_TABLE_NAME: &str = "users";
pub const TOKEN_TABLE_NAME: &str = "tokens";
pub const EVENTLOG_TABLE_NAME: &str = "event_log";
pub const DB_FILE_PATH: &str = "./users.db";

pub const ARGON2_CONFIG: Config = Config {
  variant: Variant::Argon2id,
  version: Version::Version13,
  mem_cost: 4096,
  time_cost: 3,
  lanes: 4,
  thread_mode: ThreadMode::Sequential,
  secret: &[],
  ad: &[],
  hash_length: 32,
};
pub const ARGON2_SALT_LEN: usize = 32;

pub const JWT_DURATION_MINS: usize = 365 * 24 * 60; // TODO: Clapで設定できるように
pub const REFRESH_TOKEN_LEN: usize = 256;
pub const REFRESH_TOKEN_DURATION_MINS: usize = 730 * 24 * 60; // TODO: 2years, clapで設定できるように
