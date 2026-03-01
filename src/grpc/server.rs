use std::sync::Arc;

use anyhow::{Context, Result};
use tonic::{Request, Response, Status};
use tracing::info;

use crate::domain::nix_service::NixService;
use crate::domain::node_service::NodeService;

pub mod proto {
    tonic::include_proto!("kindling");
}

use proto::kindling_service_server::{KindlingService, KindlingServiceServer};
use proto::*;

pub struct KindlingGrpc {
    nix: Arc<NixService>,
    node: Arc<NodeService>,
}

#[tonic::async_trait]
impl KindlingService for KindlingGrpc {
    async fn get_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NixStatusResponse>, Status> {
        let s = self.nix.status().await;
        Ok(Response::new(NixStatusResponse {
            installed: s.installed,
            version: s.version.unwrap_or_default(),
            nix_path: s.nix_path.unwrap_or_default(),
            install_method: s.install_method.unwrap_or_default(),
        }))
    }

    async fn get_platform(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<PlatformInfoResponse>, Status> {
        let p = self.nix.platform_info();
        Ok(Response::new(PlatformInfoResponse {
            os: p.os,
            arch: p.arch,
            target_triple: p.target_triple,
            is_wsl: p.is_wsl,
            has_systemd: p.has_systemd,
        }))
    }

    async fn get_store_info(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<StoreInfoResponse>, Status> {
        let s = self
            .nix
            .store_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(StoreInfoResponse {
            store_dir: s.store_dir,
            store_size_bytes: s.store_size_bytes.unwrap_or(0),
            path_count: s.path_count.unwrap_or(0),
            roots_count: s.roots_count.unwrap_or(0),
        }))
    }

    async fn get_nix_config(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NixConfigResponse>, Status> {
        let c = self
            .nix
            .nix_config()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(NixConfigResponse {
            substituters: c.substituters,
            trusted_public_keys: c.trusted_public_keys,
            max_jobs: c.max_jobs.unwrap_or_default(),
            cores: c.cores.unwrap_or_default(),
            experimental_features: c.experimental_features,
            sandbox: c.sandbox.unwrap_or_default(),
        }))
    }

    async fn get_gc_status(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<GcStatusResponse>, Status> {
        let g = self.nix.gc_status().await;
        Ok(Response::new(GcStatusResponse {
            auto_gc_enabled: g.auto_gc_enabled,
            schedule_secs: g.schedule_secs,
            last_gc_at: g.last_gc_at.unwrap_or_default(),
            last_gc_freed_bytes: g.last_gc_freed_bytes.unwrap_or(0),
        }))
    }

    async fn run_gc(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<GcResultResponse>, Status> {
        let r = self
            .nix
            .trigger_gc()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(GcResultResponse {
            freed_bytes: r.freed_bytes,
            freed_paths: r.freed_paths,
            duration_secs: r.duration_secs,
        }))
    }

    async fn optimise_store(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<OptimiseResultResponse>, Status> {
        let r = self
            .nix
            .optimise_store()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(OptimiseResultResponse {
            deduplicated_bytes: r.deduplicated_bytes,
            duration_secs: r.duration_secs,
        }))
    }

    async fn get_caches(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<CachesResponse>, Status> {
        let caches = self
            .nix
            .cache_info()
            .await
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(CachesResponse {
            caches: caches
                .into_iter()
                .map(|c| CacheInfoItem {
                    substituter: c.substituter,
                    reachable: c.reachable,
                    latency_ms: c.latency_ms.unwrap_or(0),
                })
                .collect(),
        }))
    }

    async fn get_health(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<HealthResponse>, Status> {
        let h = self.nix.health().await;
        Ok(Response::new(HealthResponse {
            version: h.version,
            uptime_secs: h.uptime_secs,
            platform: Some(PlatformInfoResponse {
                os: h.platform.os,
                arch: h.platform.arch,
                target_triple: h.platform.target_triple,
                is_wsl: h.platform.is_wsl,
                has_systemd: h.platform.has_systemd,
            }),
            nix: Some(NixStatusResponse {
                installed: h.nix.installed,
                version: h.nix.version.unwrap_or_default(),
                nix_path: h.nix.nix_path.unwrap_or_default(),
                install_method: h.nix.install_method.unwrap_or_default(),
            }),
        }))
    }

    async fn get_identity(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NodeIdentityResponse>, Status> {
        let identity = self
            .node
            .identity()
            .await
            .ok_or_else(|| Status::not_found("no node identity loaded"))?;

        let json = serde_json::to_string(&identity)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(NodeIdentityResponse {
            hostname: identity.hostname,
            profile: identity.profile,
            raw_json: json,
        }))
    }

    async fn get_report(
        &self,
        _request: Request<Empty>,
    ) -> Result<Response<NodeReportResponse>, Status> {
        let stored = self
            .node
            .cached_report()
            .await
            .ok_or_else(|| {
                Status::unavailable("report not yet available (initial collection in progress)")
            })?;

        let json = serde_json::to_string(&stored)
            .map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(NodeReportResponse {
            timestamp: stored.report.timestamp.to_rfc3339(),
            daemon_version: stored.report.daemon_version,
            raw_json: json,
        }))
    }
}

pub async fn serve(nix: Arc<NixService>, node: Arc<NodeService>, addr: &str) -> Result<()> {
    let addr = addr.parse().context("parsing gRPC address")?;

    info!(%addr, "gRPC server listening");

    tonic::transport::Server::builder()
        .add_service(KindlingServiceServer::new(KindlingGrpc { nix, node }))
        .serve(addr)
        .await
        .context("gRPC server error")?;

    Ok(())
}
