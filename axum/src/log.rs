pub use tracing::{debug, error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

pub fn init_logger() {
  let format = fmt::format()
    .with_source_location(false)
    .with_line_number(false)
    .with_thread_ids(false)
    .with_target(false)
    .with_thread_names(false)
    .with_target(true)
    .with_level(true)
    .compact();
  tracing_subscriber::fmt()
    .event_format(format)
    .with_env_filter(EnvFilter::from_default_env())
    .init();
}
