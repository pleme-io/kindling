use anyhow::{Context, Result};
use async_graphql_axum::{GraphQLRequest, GraphQLResponse};
use axum::extract::State;
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};

use crate::api::graphql::{self, KindlingSchema};
use crate::api::rest::{self, AppState};
use crate::config::DaemonConfig;
use crate::domain::nix_service::NixService;
use crate::domain::node_service::NodeService;

pub async fn run(config: DaemonConfig) -> Result<()> {
    // Init tracing
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&config.log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();

    info!(version = env!("CARGO_PKG_VERSION"), "Kindling daemon starting");

    // Create shared services
    let nix_service = NixService::new(config.clone());
    let node_service = Arc::new(NodeService::new(
        config.identity.clone(),
        config.report.clone(),
    ));

    // Load persisted report from disk into memory cache (startup)
    node_service.load_from_disk().await;

    let app_state = AppState {
        nix: nix_service.clone(),
        node: node_service.clone(),
    };

    // Build GraphQL schema
    let schema = graphql::build_schema(nix_service.clone(), node_service.clone());

    // Build GraphQL sub-router with its own state
    let graphql_router = Router::new()
        .route("/graphql", get(graphql_playground).post(graphql_handler))
        .with_state(schema);

    // Build Axum router: REST (with AppState) + GraphQL (with schema state)
    let app = rest::router(app_state)
        .merge(graphql_router)
        .layer(TraceLayer::new_for_http());

    // Bind HTTP listener
    let http_addr = &config.http_addr;
    let listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("binding to {}", http_addr))?;

    info!(addr = %http_addr, "HTTP server listening");

    // Spawn initial discovery (background — daemon starts serving immediately)
    {
        let node = node_service.clone();
        tokio::spawn(async move {
            info!("running initial report collection");
            match node.refresh().await {
                Ok(stored) => {
                    info!(
                        checksum = %stored.checksum,
                        "initial report collection completed"
                    );
                }
                Err(e) => {
                    warn!(error = %e, "initial report collection failed");
                }
            }
        });
    }

    // Spawn telemetry push loop
    if config.telemetry.enabled {
        let telemetry_service = nix_service.clone();
        let telemetry_config = config.telemetry.clone();
        tokio::spawn(async move {
            crate::telemetry::run_push_loop(telemetry_service, &telemetry_config).await;
        });
    }

    // Spawn GC scheduler
    if config.gc.schedule_secs > 0 {
        let gc_service = nix_service.clone();
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

    // Spawn periodic report refresh
    if config.report.refresh_interval_secs > 0 {
        let report_node = node_service.clone();
        let interval_secs = config.report.refresh_interval_secs;
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            // Skip the first tick — initial discovery already handles it
            interval.tick().await;
            loop {
                interval.tick().await;
                match report_node.refresh().await {
                    Ok(stored) => {
                        info!(
                            checksum = %stored.checksum,
                            "periodic report refresh completed"
                        );
                    }
                    Err(e) => {
                        warn!(error = %e, "periodic report refresh failed");
                    }
                }
            }
        });
    }

    // Optionally spawn gRPC server
    #[cfg(feature = "grpc")]
    {
        let grpc_nix = nix_service.clone();
        let grpc_node = node_service.clone();
        let grpc_addr = config.grpc_addr.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::grpc::serve(grpc_nix, grpc_node, &grpc_addr).await {
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
