mod apis;
mod argon2;
mod config;
mod constants;
mod db;
mod error;
mod jwt;
mod log;
mod state;

// use crate::api_create_user::create_user;
use crate::{
  apis::{get_tokens, health_check, jwks},
  constants::*,
  error::*,
  log::*,
  state::AppState,
};
use axum::{
  routing::{get, post},
  Router, Server,
};
use config::parse_opts;
use std::sync::Arc;
use tokio::runtime::Builder;

fn main() -> Result<()> {
  init_logger();

  let mut runtime_builder = Builder::new_multi_thread();
  runtime_builder.enable_all();
  runtime_builder.thread_name(THREAD_NAME);
  let runtime = runtime_builder.build()?;

  runtime.block_on(async {
    match parse_opts().await {
      Ok(Some(shared_state)) => {
        define_route(Arc::new(shared_state)).await;
      }
      Ok(None) => {
        // TODO:
        warn!("something init maybe admin password update");
      }
      Err(e) => {
        error!("{e}");
      }
    };
  });

  Ok(())
}

async fn define_route(shared_state: Arc<AppState>) {
  let addr = shared_state.listen_socket;
  info!("Listening on {}", &addr);

  // routes nested under /v1.0
  let api_routes = Router::new()
    .route("/jwks", get(jwks))
    .route("/tokens", post(get_tokens))
    .with_state(shared_state);

  let router = Router::new()
    .route("/", get(root))
    .route("/health", get(health_check))
    .nest("/v1.0", api_routes);
  //.route("/create_user", post(create_user));

  let server = Server::bind(&addr).serve(router.into_make_service());

  if let Err(e) = server.await {
    error!("Server is down!: {e}");
  }
}

async fn root() -> &'static str {
  "Hello World!"
}
