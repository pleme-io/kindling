use async_graphql::{Context, EmptySubscription, Object, Schema};
use std::sync::Arc;

use crate::domain::nix_service::NixService;
use crate::domain::node_report::{NodeReport, StoredReport};
use crate::domain::node_service::NodeService;
use crate::domain::types::*;
use crate::node_identity::NodeIdentity;

pub type KindlingSchema = Schema<QueryRoot, MutationRoot, EmptySubscription>;

pub struct QueryRoot;

#[Object]
impl QueryRoot {
    async fn status(&self, ctx: &Context<'_>) -> async_graphql::Result<NixStatus> {
        let svc = ctx.data::<Arc<NixService>>()?;
        Ok(svc.status().await)
    }

    async fn platform(&self, ctx: &Context<'_>) -> async_graphql::Result<PlatformInfo> {
        let svc = ctx.data::<Arc<NixService>>()?;
        Ok(svc.platform_info())
    }

    async fn store(&self, ctx: &Context<'_>) -> async_graphql::Result<StoreInfo> {
        let svc = ctx.data::<Arc<NixService>>()?;
        svc.store_info()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))
    }

    async fn nix_config(&self, ctx: &Context<'_>) -> async_graphql::Result<NixConfig> {
        let svc = ctx.data::<Arc<NixService>>()?;
        svc.nix_config()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))
    }

    async fn gc_status(&self, ctx: &Context<'_>) -> async_graphql::Result<GcStatus> {
        let svc = ctx.data::<Arc<NixService>>()?;
        Ok(svc.gc_status().await)
    }

    async fn caches(&self, ctx: &Context<'_>) -> async_graphql::Result<Vec<CacheInfo>> {
        let svc = ctx.data::<Arc<NixService>>()?;
        svc.cache_info()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))
    }

    async fn health(&self, ctx: &Context<'_>) -> async_graphql::Result<DaemonHealth> {
        let svc = ctx.data::<Arc<NixService>>()?;
        Ok(svc.health().await)
    }

    /// This node's declared identity from node.yaml.
    async fn identity(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<NodeIdentity>> {
        let node = ctx.data::<Arc<NodeService>>()?;
        Ok(node.identity().await)
    }

    /// Get the cached runtime report (from memory). Never triggers collection.
    async fn report(&self, ctx: &Context<'_>) -> async_graphql::Result<Option<NodeReport>> {
        let node = ctx.data::<Arc<NodeService>>()?;
        Ok(node.cached_report().await.map(|s| s.report))
    }

    /// Get the full cached StoredReport with metadata (checksum, collected_at).
    async fn cached_report(
        &self,
        ctx: &Context<'_>,
    ) -> async_graphql::Result<Option<StoredReport>> {
        let node = ctx.data::<Arc<NodeService>>()?;
        Ok(node.cached_report().await)
    }
}

pub struct MutationRoot;

#[Object]
impl MutationRoot {
    async fn run_gc(&self, ctx: &Context<'_>) -> async_graphql::Result<GcResult> {
        let svc = ctx.data::<Arc<NixService>>()?;
        svc.trigger_gc()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))
    }

    async fn optimise_store(&self, ctx: &Context<'_>) -> async_graphql::Result<OptimiseResult> {
        let svc = ctx.data::<Arc<NixService>>()?;
        svc.optimise_store()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))
    }

    /// Trigger a fresh discovery → store → cache cycle and return the result.
    async fn refresh_report(&self, ctx: &Context<'_>) -> async_graphql::Result<StoredReport> {
        let node = ctx.data::<Arc<NodeService>>()?;
        node.refresh()
            .await
            .map_err(|e| async_graphql::Error::new(e.to_string()))
    }
}

pub fn build_schema(nix_service: Arc<NixService>, node_service: Arc<NodeService>) -> KindlingSchema {
    Schema::build(QueryRoot, MutationRoot, EmptySubscription)
        .data(nix_service)
        .data(node_service)
        .finish()
}
