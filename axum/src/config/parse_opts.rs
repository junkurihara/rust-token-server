use super::{subcmd_admin::Admin, subcmd_run::Run, ClapSubCommand};
use crate::{error::*, state::AppState};
use clap::command;

pub async fn parse_opts() -> Result<Option<AppState>> {
  let _ = include_str!("../../Cargo.toml");

  let options = command!().subcommand(Run::subcmd()).subcommand(Admin::subcmd());

  let matches = options.get_matches();

  match matches.subcommand() {
    Some(("run", sub_m)) => {
      let res = Run::exec_matches(sub_m).await?;
      Ok(res)
    }
    Some(("admin", sub_m)) => {
      let _res = Admin::exec_matches(sub_m).await?;
      Ok(None)
    }
    _ => {
      bail!("none");
    }
  }
}
