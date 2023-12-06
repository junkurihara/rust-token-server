mod apis;
mod argon2;
mod config;
mod constants;
mod entity;
mod error;
// mod jwt;
mod log;
mod state;
mod table;

// use crate::api_create_user::create_user;
use crate::{
  apis::{create_user, get_tokens, health_check, jwks, refresh, update_user},
  constants::*,
  error::*,
  log::*,
  state::AppState,
};
use axum::{
  routing::{get, post},
  Router,
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
  let tcp_listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
  info!("Listening on {}", &addr);

  // routes nested under /v1.0
  let api_routes = Router::new()
    .route("/jwks", get(jwks))
    .route("/tokens", post(get_tokens))
    .route("/refresh", post(refresh))
    .route("/create_user", post(create_user))
    .route("/update_user", post(update_user))
    .with_state(shared_state);

  let router = Router::new()
    .route("/health", get(health_check))
    .nest("/v1.0", api_routes);

  let server = axum::serve(tcp_listener, router);

  if let Err(e) = server.await {
    error!("Server is down!: {e}");
  }
}
