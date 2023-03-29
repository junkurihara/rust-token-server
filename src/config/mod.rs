mod parse_opts;
mod subcmd_admin;
mod subcmd_run;
use crate::error::Result;
use async_trait::async_trait;
pub use parse_opts::parse_opts;

#[async_trait]
trait ClapSubCommand {
  fn subcmd() -> clap::Command;

  async fn exec_matches(sub_m: &clap::ArgMatches) -> Result<Option<crate::AppState>>;
}
