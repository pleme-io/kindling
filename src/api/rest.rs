use axum::extract::State;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

use crate::domain::nix_service::NixService;
use crate::domain::types::*;

pub fn router(service: Arc<NixService>) -> Router {
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
        .with_state(service)
}

async fn health(State(svc): State<Arc<NixService>>) -> Json<DaemonHealth> {
    Json(svc.health().await)
}

async fn ready(
    State(svc): State<Arc<NixService>>,
) -> Result<Json<NixStatus>, StatusCode> {
    let s = svc.status().await;
    if s.installed {
        Ok(Json(s))
    } else {
        Err(StatusCode::SERVICE_UNAVAILABLE)
    }
}

async fn status(State(svc): State<Arc<NixService>>) -> Json<NixStatus> {
    Json(svc.status().await)
}

async fn platform(State(svc): State<Arc<NixService>>) -> Json<PlatformInfo> {
    Json(svc.platform_info())
}

async fn store(
    State(svc): State<Arc<NixService>>,
) -> Result<Json<StoreInfo>, (StatusCode, String)> {
    svc.store_info()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn nix_config(
    State(svc): State<Arc<NixService>>,
) -> Result<Json<NixConfig>, (StatusCode, String)> {
    svc.nix_config()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn gc_status(State(svc): State<Arc<NixService>>) -> Json<GcStatus> {
    Json(svc.gc_status().await)
}

async fn gc_run(
    State(svc): State<Arc<NixService>>,
) -> Result<Json<GcResult>, (StatusCode, String)> {
    svc.trigger_gc()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn optimise_store(
    State(svc): State<Arc<NixService>>,
) -> Result<Json<OptimiseResult>, (StatusCode, String)> {
    svc.optimise_store()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}

async fn caches(
    State(svc): State<Arc<NixService>>,
) -> Result<Json<Vec<CacheInfo>>, (StatusCode, String)> {
    svc.cache_info()
        .await
        .map(Json)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))
}
