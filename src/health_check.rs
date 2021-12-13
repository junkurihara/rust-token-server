#[get("/")]
pub fn health() -> String {
  // TODO: add health check with pseudo id/password
  "Works at least as a server. Not checked if APIs work well.".to_string()
}
