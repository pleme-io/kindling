use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

use crate::domain::nix_service::NixService;
use crate::domain::node_report::StoredReport;
use crate::domain::node_service::NodeService;
use crate::domain::types::*;
use crate::node_identity::NodeIdentity;

/// Shared application state for all API handlers.
#[derive(Clone)]
pub struct AppState {
    pub nix: Arc<NixService>,
    pub node: Arc<NodeService>,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/ready", get(ready))
        .route("/api/v1/status", get(status))
        .route("/api/v1/platform", get(platform))
        .route("/api/v1/store", get(store))
        .route("/api/v1/config", get(nix_config))
        .route("/api/v1/gc", get(gc_status))
        .route("/api/v1/gc/run", post(gc_run))
        .route("/api/v1/store/optimise", post(optimise_store))
        .route("/api/v1/caches", get(caches))
        // Node identity + report endpoints
        .route("/api/v1/identity", get(identity))
        .route("/api/v1/report", get(report))
        .route("/api/v1/report/refresh", post(refresh_report))
        .with_state(state)
}

async fn health(State(state): State<AppState>) -> Json<DaemonHealth> {
    Json(state.nix.health().await)
}

async fn ready(State(state): State<AppState>) -> Result<Json<NixStatus>, StatusCode> {
    let s = state.nix.status().await;
    if s.installed {
        Ok(Json(s))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

async fn status(State(state): State<AppState>) -> Json<NixStatus> {
    Json(state.nix.status().await)
}

async fn platform(State(state): State<AppState>) -> Json<PlatformInfo> {
    Json(state.nix.platform_info())
}

async fn store(
    State(state): State<AppState>,
) -> Result<Json<StoreInfo>, (StatusCode, String)> {
    state
        .nix
        .store_info()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn nix_config(
    State(state): State<AppState>,
) -> Result<Json<NixConfig>, (StatusCode, String)> {
    state
        .nix
        .nix_config()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn gc_status(State(state): State<AppState>) -> Json<GcStatus> {
    Json(state.nix.gc_status().await)
}

async fn gc_run(
    State(state): State<AppState>,
) -> Result<Json<GcResult>, (StatusCode, String)> {
    state
        .nix
        .trigger_gc()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn optimise_store(
    State(state): State<AppState>,
) -> Result<Json<OptimiseResult>, (StatusCode, String)> {
    state
        .nix
        .optimise_store()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn caches(
    State(state): State<AppState>,
) -> Result<Json<Vec<CacheInfo>>, (StatusCode, String)> {
    state
        .nix
        .cache_info()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn identity(
    State(state): State<AppState>,
) -> Result<Json<NodeIdentity>, (StatusCode, String)> {
    state
        .node
        .identity()
        .await
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                "no node identity loaded (node.yaml not found)".to_string(),
            )
        })
}

/// Serve the cached report from memory. Never triggers collection.
/// Returns 503 if the cache is empty (initial collection hasn't completed yet).
async fn report(
    State(state): State<AppState>,
) -> Result<Json<StoredReport>, (StatusCode, String)> {
    state
        .node
        .cached_report()
        .await
        .map(Json)
        .ok_or_else(|| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "report not yet available (initial collection in progress)".to_string(),
            )
        })
}

/// Trigger a fresh discovery → store → cache cycle and return the result.
async fn refresh_report(
    State(state): State<AppState>,
) -> Result<Json<StoredReport>, (StatusCode, String)> {
    state
        .node
        .refresh()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}
