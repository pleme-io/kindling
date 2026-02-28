use anyhow::{Context, Result};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::api::graphql::{self, KindlingSchema};
use crate::api::rest;
use crate::config::DaemonConfig;
use crate::domain::nix_service::NixService;

pub async fn run(config: DaemonConfig) -> Result<()> {
    // Init tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "Kindling daemon starting");

    // Create shared NixService
    let service = NixService::new(config.clone());

    // Build GraphQL schema
    let schema = graphql::build_schema(service.clone());

    // Build GraphQL sub-router with its own state
    let graphql_router = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        .with_state(schema);

    // Build Axum router: REST (with NixService state) + GraphQL (with schema state)
    let app = rest::router(service.clone())
        .merge(graphql_router)
        .layer(TraceLayer::new_for_http());

    // Bind HTTP listener
    let http_addr = &config.http_addr;
    let listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding to {}", http_addr))?;

    info!(addr = %http_addr, "HTTP server listening");

    // Spawn telemetry push loop
    if config.telemetry.enabled {
        let telemetry_service = service.clone();
        let telemetry_config = config.telemetry.clone();
        tokio::spawn(async move {
            crate::telemetry::run_push_loop(telemetry_service, &telemetry_config).await;
        });
    }

    // Spawn GC scheduler
    if config.gc.schedule_secs > 0 {
        let gc_service = service.clone();
        let gc_interval = config.gc.schedule_secs;
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(gc_interval));
            loop {
                interval.tick().await;
                info!("Running scheduled garbage collection");
                match gc_service.trigger_gc().await {
                    Ok(result) => {
                        info!(
                            freed_bytes = result.freed_bytes,
                            freed_paths = result.freed_paths,
                            duration_secs = result.duration_secs,
                            "Scheduled GC completed"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "Scheduled GC failed");
                    }
                }
            }
        });
    }

    // Optionally spawn gRPC server
    #[cfg(feature = "grpc")]
    {
        let grpc_service = service.clone();
        let grpc_addr = config.grpc_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::grpc::serve(grpc_service, &grpc_addr).await {
                tracing::error!(error = %e, "gRPC server failed");
            }
        });
    }

    // Run HTTP server with graceful shutdown
    axum::serve(listener, app.into_make_service())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("HTTP server error")?;

    info!("Kindling daemon stopped");
    Ok(())
}

async fn graphql_playground() -> Html<String> {
    Html(
        async_graphql::http::playground_source(
            async_graphql::http::GraphQLPlaygroundConfig::new("/graphql"),
        ),
    )
}

async fn graphql_handler(
    State(schema): State<KindlingSchema>,
    req: GraphQLRequest,
) -> GraphQLResponse {
    schema.execute(req.into_inner()).await.into()
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received Ctrl+C, shutting down"); },
        _ = terminate => { info!("Received SIGTERM, shutting down"); },
    }
}
