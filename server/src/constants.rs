pub const THREAD_NAME: &str = "id_token_server";

pub const DEFAULT_ADDRESS: &str = "127.0.0.1";
pub const DEFAULT_PORT: &str = "3000";

/// Default admin name that will be written to the database.
pub const ADMIN_USERNAME: &str = "admin";
/// Default password length when random password is needed at the user creation.
pub const PASSWORD_LEN: usize = 32;
/// Default environment variable of admin password
pub const ADMIN_PASSWORD_VAR: &str = "ADMIN_PASSWORD";

// Database settings
pub const DB_FILE_PATH: &str = "./users.db";
pub const USER_TABLE_NAME: &str = "users";
// pub const ALLOWED_CLIENT_TABLE_NAME: &str = "client_ids";
pub const REFRESH_TOKEN_TABLE_NAME: &str = "tokens";

// Argon2 password hashing params
use argon2::{Config, Variant, Version};
pub const ARGON2_CONFIG: Config = Config {
  variant: Variant::Argon2id,
  version: Version::Version13,
  mem_cost: 4096,
  time_cost: 3,
  lanes: 4,
  secret: &[],
  ad: &[],
  hash_length: 32,
};
pub const ARGON2_SALT_LEN: usize = 32;

// ID Token settings
/// Default client ID if no client id check is required
pub const DEFAUTL_CLIENT_ID: &str = "none";
/// Default duration of refresh token validity in minutes
/// TODO: 30days, clapで設定できるように
pub const REFRESH_TOKEN_DURATION_MINS: usize = 30 * 24 * 60;
