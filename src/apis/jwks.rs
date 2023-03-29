use crate::{log::*, state::AppState};
use axum::extract::State;
use std::sync::Arc;

pub async fn jwks(State(state): State<Arc<AppState>>) -> &'static str {
  info!("{:#?}", state.crypto.algorithm);
  "jwks"
}
