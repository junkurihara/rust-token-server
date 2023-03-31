mod parse_opts;
mod subcmd_admin;
mod subcmd_run;
use crate::error::Result;
use async_trait::async_trait;
pub use parse_opts::parse_opts;
use url::Url;

#[async_trait]
trait ClapSubCommand {
  fn subcmd() -> clap::Command;

  async fn exec_matches(sub_m: &clap::ArgMatches) -> Result<Option<crate::AppState>>;
}

pub(crate) fn verify_url(arg_val: &str) -> Result<String, String> {
  let url = match Url::parse(arg_val) {
    Ok(addr) => addr,
    Err(_) => return Err(format!("Could not parse \"{}\" as a valid url.", arg_val)),
  };
  if url.scheme() != "http" && url.scheme() != "https" {
    return Err("Invalid scheme".to_string());
  }
  if url.cannot_be_a_base() {
    return Err("Invalid scheme".to_string());
  }
  Ok(url.to_string())
}
