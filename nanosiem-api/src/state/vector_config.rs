// SPDX-License-Identifier: AGPL-3.0-or-later

use super::AppState;
use nanosiem_core::{
    ParserService, PublicationOutcome, SourceConfigService, VectorConfigPublicationError,
};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum VectorConfigReconcileError {
    #[error("publication error: {0}")]
    Publication(#[from] VectorConfigPublicationError),
    #[error("source config render failed: {0}")]
    Source(#[from] nanosiem_core::source_configs::SourceConfigServiceError),
    #[error("parser render failed: {0}")]
    Parser(#[from] nanosiem_core::ParserServiceError),
}

impl AppState {
    /// Render all DB-backed Vector configuration into an isolated directory and
    /// publish it only when the source revision stayed stable for the complete
    /// render. Every API node may run this; the DB pointer CAS provides the
    /// single-writer ordering.
    pub async fn reconcile_vector_config_publication(
        &self,
    ) -> Result<PublicationOutcome, VectorConfigReconcileError> {
        if let Some(outcome) = self.vector_config_publisher.local_current_outcome().await? {
            return Ok(outcome);
        }

        let expected_revision = self.vector_config_publisher.source_revision().await?;
        let render_root = self.vector_config_publisher.create_render_dir().await?;

        let result = async {
            let parser_service =
                ParserService::with_vector_config_dir(self.pool.clone(), &render_root);
            let source_service = SourceConfigService::with_publication_vector_config_dir(
                self.pool.clone(),
                &render_root,
            )
            .with_deploy_lock(parser_service.deploy_lock());

            // Source reconciliation updates the parser-owned dynamic router,
            // so the canonical parser tree must exist before source routes are
            // applied. Reversing this order silently drops every source route.
            parser_service.render_to_vector_config().await?;
            source_service.render_deployed_to_vector_config().await?;

            let snapshot = self
                .vector_config_publisher
                .prepare_snapshot(render_root.join("sources"))
                .await?;
            self.vector_config_publisher
                .publish(expected_revision, &snapshot)
                .await
                .map_err(VectorConfigReconcileError::from)
        }
        .await;

        self.vector_config_publisher
            .cleanup_render_dir(&render_root)
            .await;
        result
    }

    /// NAN-5133: in the role-split topology (`NANO_VECTOR_CONFIG_DELIVERY=generation`)
    /// a deploy's reload is "publish this generation and wait for the ingest
    /// hosts' consumers to acknowledge it". Installed after boot-time source
    /// sync so that sync does not wait on consumers that are still starting.
    pub fn install_generation_delivery(&self) {
        use nanosiem_core::parsers::vector_config_remote_delivery as remote;
        if !remote::generation_delivery_configured() {
            return;
        }
        let publisher: std::sync::Arc<dyn remote::GenerationPublisher> =
            std::sync::Arc::new(StatePublisher(self.clone()));
        if remote::install_generation_publisher(publisher) {
            tracing::info!(
                relays = remote::relay_urls().len(),
                metrics_peers = remote::metrics_peers::configured_target().as_deref().unwrap_or("none"),
                "Vector config generation delivery active: deploys are graded by ingest-host acknowledgement"
            );
        }
    }

    /// Per-instance reconciliation is intentional: a restarted API pod has a
    /// fresh emptyDir and must rematerialize the committed generation for its
    /// own upload sidecar. Reusing a committed hash does not allocate a new
    /// generation.
    pub fn start_vector_config_publication_reconciler(&self) -> tokio::task::JoinHandle<()> {
        let state = self.clone();
        let interval_secs = std::env::var("VECTOR_CONFIG_RECONCILE_INTERVAL_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(5)
            .max(1);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            interval.tick().await;

            loop {
                interval.tick().await;
                match state.reconcile_vector_config_publication().await {
                    Ok(PublicationOutcome::Published {
                        generation,
                        source_revision,
                    }) => tracing::info!(
                        generation,
                        source_revision,
                        "published Vector configuration generation"
                    ),
                    Ok(PublicationOutcome::Reused {
                        generation,
                        source_revision,
                    }) => tracing::debug!(
                        generation,
                        source_revision,
                        "Vector configuration generation already current"
                    ),
                    Ok(PublicationOutcome::Stale {
                        expected_revision,
                        actual_revision,
                    }) => tracing::debug!(
                        expected_revision,
                        actual_revision,
                        "discarded stale Vector configuration render"
                    ),
                    // NAN-1777 (def-4): a superseded renderer WITH pending work
                    // (source advanced past what is published) means parser/source
                    // edits are silently frozen until the renderer catches up — most
                    // commonly an app rollback without bumping
                    // VECTOR_CONFIG_RENDERER_EPOCH. Surface that at WARN so the freeze
                    // is visible; the benign no-pending-work case stays at DEBUG.
                    Ok(PublicationOutcome::SupersededRenderer {
                        running_epoch,
                        running_version,
                        committed_epoch,
                        committed_version,
                        pending_work: true,
                    }) => tracing::warn!(
                        running_epoch,
                        %running_version,
                        committed_epoch,
                        %committed_version,
                        "older API renderer cannot publish pending Vector configuration changes; \
                         parser/source edits are frozen until the renderer is upgraded or \
                         VECTOR_CONFIG_RENDERER_EPOCH is advanced"
                    ),
                    Ok(PublicationOutcome::SupersededRenderer {
                        running_epoch,
                        running_version,
                        committed_epoch,
                        committed_version,
                        pending_work: false,
                    }) => tracing::debug!(
                        running_epoch,
                        %running_version,
                        committed_epoch,
                        %committed_version,
                        "older API renderer cannot replace committed Vector configuration"
                    ),
                    Err(error) => tracing::warn!(
                        %error,
                        "Vector configuration reconciliation failed; retaining committed generation"
                    ),
                }
            }
        })
    }
}

/// [`AppState`] as the generation publisher for role-split deploys.
struct StatePublisher(AppState);

impl nanosiem_core::parsers::vector_config_remote_delivery::GenerationPublisher for StatePublisher {
    fn publish_current(&self) -> futures::future::BoxFuture<'_, Result<i64, String>> {
        Box::pin(async move {
            // A render that raced another revision bump is Stale: render again.
            for _ in 0..5 {
                match self.0.reconcile_vector_config_publication().await {
                    Ok(PublicationOutcome::Published { generation, .. })
                    | Ok(PublicationOutcome::Reused { generation, .. }) => return Ok(generation),
                    Ok(PublicationOutcome::Stale { .. }) => {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                    Ok(PublicationOutcome::SupersededRenderer {
                        committed_version, ..
                    }) => {
                        return Err(format!(
                            "a newer renderer ({committed_version}) owns the committed generation; \
                             upgrade this API or advance VECTOR_CONFIG_RENDERER_EPOCH"
                        ));
                    }
                    Err(error) => return Err(error.to_string()),
                }
            }
            Err("the configuration kept changing while it was rendered; retry the deploy".to_string())
        })
    }
}
