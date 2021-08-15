use argon2::{Config, ThreadMode, Variant, Version};

pub const ALLOWED_CLIENT_TABLE_NAME: &str = "client_ids";
pub const USER_TABLE_NAME: &str = "users";
pub const TOKEN_TABLE_NAME: &str = "tokens";
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

pub const JWT_DURATION_MINS: usize = 30; // TODO: Clapで設定できるように
pub const REFRESH_TOKEN_LEN: usize = 256;
pub const REFRESH_TOKEN_DURATION_MINS: usize = 30 * 24 * 60; // TODO: 30days, clapで設定できるように
