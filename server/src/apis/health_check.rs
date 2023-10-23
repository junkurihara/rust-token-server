use crate::log::*;

pub async fn health_check() -> &'static str {
  // TODO: add health check with pseudo id/password
  debug!("health_check invoked");
  "Works at least as a server. Not checked if APIs work well."
}
