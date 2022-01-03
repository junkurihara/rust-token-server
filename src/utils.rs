use url::Url;

pub(crate) fn verify_url(arg_val: &str) -> Result<(), String> {
  let url = match Url::parse(arg_val) {
    Ok(addr) => addr,
    Err(_) => return Err(format!("Could not parse \"{}\" as a valid url.", arg_val)),
  };

  match url.scheme() {
    "http" => (),
    "https" => (),
    _ => return Err("Invalid scheme".to_string()),
  };

  if url.cannot_be_a_base() {
    return Err("Invalid scheme".to_string());
  }
  Ok(())
}
