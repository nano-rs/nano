// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity sync service
//!
//! Orchestrates sync operations: load config → decrypt creds → attempt delta sync
//! → fall back to full sync → bulk upsert → soft-delete absent → update status.

use thiserror::Error;
use tracing::{error, info, instrument};

use crate::enrichment::EnrichmentLaneClient;
use super::repository::{IdentityRepository, IdentityRepositoryError};
use super::sync::{
    entra::EntraIdSync, google::GoogleWorkspaceSync, okta::OktaSync, workday::WorkdaySync,
    SyncError, SyncProvider,
};
use super::types::*;

// =============================================================================
// Error
// =============================================================================

#[derive(Error, Debug)]
pub enum IdentityServiceError {
    #[error("Repository error: {0}")]
    Repository(#[from] IdentityRepositoryError),
    #[error("Sync error: {0}")]
    Sync(#[from] SyncError),
    #[error("Provider not found: {0}")]
    ProviderNotFound(String),
    #[error("Invalid provider type: {0}")]
    InvalidProviderType(String),
    #[error("Sync already in progress for provider: {0}")]
    SyncInProgress(String),
}

// =============================================================================
// Service
// =============================================================================

#[derive(Clone)]
pub struct IdentitySyncService {
    repo: IdentityRepository,
    /// NAN-1151: client for emitting raw provider records onto the `nano_enrich`
    /// enrichment lane. Wired now so the provider reroute (P3) can push instead
    /// of writing ClickHouse directly; the per-source normalize VRL in the
    /// parsers repo does the mapping. See [`crate::enrichment::EnrichmentLaneClient`].
    lane_client: EnrichmentLaneClient,
}

impl IdentitySyncService {
    pub fn new(repo: IdentityRepository, lane_client: EnrichmentLaneClient) -> Self {
        if !lane_client.is_configured() {
            // A token-protected Vector rejects unauthenticated pushes — surface
            // the provisioning gap (NAN-1151) rather than discover it as silent
            // 401s once the providers are rerouted.
            tracing::warn!(
                "identity enrichment lane client has no VECTOR_AUTH_TOKEN; \
                 provider pushes to a token-protected Vector will be rejected"
            );
        } else {
            tracing::info!("identity enrichment lane client configured");
        }
        Self { repo, lane_client }
    }

    pub fn repository(&self) -> &IdentityRepository {
        &self.repo
    }

    /// The `nano_enrich` lane client used to emit raw provider records (P3).
    pub fn lane_client(&self) -> &EnrichmentLaneClient {
        &self.lane_client
    }

    // ========================================================================
    // Provider Management (delegates to repository)
    // ========================================================================

    pub async fn list_providers(&self) -> Result<Vec<IdentityProvider>, IdentityServiceError> {
        Ok(self.repo.list_providers().await?)
    }

    pub async fn get_provider(&self, id: &str) -> Result<IdentityProvider, IdentityServiceError> {
        Ok(self.repo.get_provider(id).await?)
    }

    pub async fn create_provider(
        &self,
        req: &CreateIdentityProvider,
    ) -> Result<IdentityProvider, IdentityServiceError> {
        Ok(self.repo.create_provider(req).await?)
    }

    pub async fn update_provider(
        &self,
        id: &str,
        req: &UpdateIdentityProvider,
    ) -> Result<IdentityProvider, IdentityServiceError> {
        Ok(self.repo.update_provider(id, req).await?)
    }

    pub async fn delete_provider(&self, id: &str) -> Result<(), IdentityServiceError> {
        Ok(self.repo.delete_provider(id).await?)
    }

    pub async fn update_credentials(
        &self,
        id: &str,
        credentials: &serde_json::Value,
    ) -> Result<(), IdentityServiceError> {
        Ok(self.repo.update_credentials(id, credentials).await?)
    }

    // ========================================================================
    // Sync Operations
    // ========================================================================

    /// Sync a provider: delta if possible, otherwise full.
    #[instrument(skip(self))]
    pub async fn sync_provider(
        &self,
        provider_id: &str,
    ) -> Result<IdentitySyncResult, IdentityServiceError> {
        let start = std::time::Instant::now();
        let provider = self.repo.get_provider(provider_id).await?;

        // Check if already in progress
        if provider.sync_status.as_deref() == Some("in_progress") {
            return Err(IdentityServiceError::SyncInProgress(
                provider_id.to_string(),
            ));
        }

        // Mark as in_progress
        self.repo
            .update_sync_status(provider_id, "in_progress", None, None, None, None)
            .await?;

        // Decrypt credentials
        let credentials = match self.repo.get_decrypted_credentials(provider_id).await {
            Ok(c) => c,
            Err(e) => {
                let err_msg = e.to_string();
                self.repo
                    .update_sync_status(provider_id, "failed", Some(&err_msg), None, None, None)
                    .await?;
                return Err(IdentityServiceError::Repository(e));
            }
        };

        let config = provider
            .config
            .clone()
            .unwrap_or_else(|| serde_json::json!({}));
        let provider_type: IdentityProviderType = provider.provider_type.parse().map_err(|_| {
            IdentityServiceError::InvalidProviderType(provider.provider_type.clone())
        })?;

        // Get the sync provider implementation
        let sync_impl: Box<dyn SyncProvider> = match provider_type {
            IdentityProviderType::EntraId => Box::new(EntraIdSync::new()),
            IdentityProviderType::GoogleWorkspace => Box::new(GoogleWorkspaceSync::new()),
            IdentityProviderType::Okta => Box::new(OktaSync::new()),
            IdentityProviderType::Workday => Box::new(WorkdaySync::new()),
            IdentityProviderType::ActiveDirectory => {
                // AD is push-based, not pull-based
                self.repo
                    .update_sync_status(provider_id, "completed", None, None, None, None)
                    .await?;
                return Ok(IdentitySyncResult {
                    provider_id: provider_id.to_string(),
                    users_synced: 0,
                    users_created: 0,
                    users_updated: 0,
                    users_disabled: 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    error: None,
                    is_delta: false,
                });
            }
        };

        // Attempt delta sync first, fall back to full
        let result = self
            .do_sync(
                provider_id,
                &provider,
                &credentials,
                &config,
                sync_impl.as_ref(),
            )
            .await;

        let duration_ms = start.elapsed().as_millis() as u64;
        match &result {
            Ok(_sync_result) => {
                let user_count = self.repo.get_user_count(provider_id).await.unwrap_or(0) as i32;
                self.repo
                    .update_sync_status(
                        provider_id,
                        "completed",
                        None,
                        Some(user_count),
                        Some(duration_ms as i64),
                        None,
                    )
                    .await?;
                // sync_result is already populated with duration_ms from below
            }
            Err(e) => {
                let err_msg = e.to_string();
                error!(provider_id, error = %err_msg, "Sync failed");
                self.repo
                    .update_sync_status(
                        provider_id,
                        "failed",
                        Some(&err_msg),
                        None,
                        Some(duration_ms as i64),
                        None,
                    )
                    .await?;
            }
        }

        result
    }

    async fn do_sync(
        &self,
        provider_id: &str,
        provider: &IdentityProvider,
        credentials: &serde_json::Value,
        config: &serde_json::Value,
        sync_impl: &dyn SyncProvider,
    ) -> Result<IdentitySyncResult, IdentityServiceError> {
        let start = std::time::Instant::now();
        // NAN-1151: providers now fetch RAW user objects and we emit them onto
        // the nano_enrich lane (tagged kind=identity, source=<provider>); the
        // repo-sourced per-source VRL maps them into user_registry. The lane is
        // fire-and-forget, so deprovisioning is the staleness reconciler's job
        // (scheduler) — NOT a synchronous mark-absent here, which would race the
        // async writes and false-delete the just-emitted users.
        let source = Self::provider_source(&provider.provider_type);

        // Try delta sync first — delta results are bounded (only changed users).
        if let Some(delta_link) = &provider.delta_link {
            if let Some(delta_result) = sync_impl
                .delta_sync(credentials, config, Some(delta_link))
                .await?
            {
                if let Some(new_link) = &delta_result.new_delta_link {
                    self.repo
                        .update_sync_status(
                            provider_id,
                            "in_progress",
                            None,
                            None,
                            None,
                            Some(new_link),
                        )
                        .await?;
                }

                let users_synced = delta_result.users.len() as u64;
                let records: Vec<serde_json::Value> = delta_result
                    .users
                    .into_iter()
                    .map(|u| Self::tag_enrich_value(u, source, provider_id))
                    .collect();
                self.lane_client.push_records(&records).await.map_err(|e| {
                    IdentityServiceError::Sync(SyncError::StorageError(e.to_string()))
                })?;

                info!(
                    provider_id,
                    users_synced,
                    is_delta = true,
                    "Delta sync emitted to enrichment lane"
                );

                return Ok(IdentitySyncResult {
                    provider_id: provider_id.to_string(),
                    users_synced,
                    users_created: 0,
                    users_updated: 0,
                    users_disabled: 0,
                    duration_ms: start.elapsed().as_millis() as u64,
                    error: None,
                    is_delta: true,
                });
            }
            info!(
                provider_id,
                "Delta sync unavailable, falling back to full sync"
            );
        }

        // Full sync — paged to keep memory bounded; each page is tagged and
        // emitted to the lane, then dropped.
        let lane = self.lane_client.clone();
        let pid = provider_id.to_string();
        let src = source.to_string();

        let users_synced = sync_impl
            .full_sync_paged(credentials, config, &|page: Vec<serde_json::Value>| {
                let count = page.len() as u64;
                let lane = lane.clone();
                let pid = pid.clone();
                let src = src.clone();
                Box::pin(async move {
                    let records: Vec<serde_json::Value> = page
                        .into_iter()
                        .map(|u| IdentitySyncService::tag_enrich_value(u, &src, &pid))
                        .collect();
                    lane.push_records(&records).await.map_err(|e| {
                        SyncError::StorageError(format!("Lane push failed: {}", e))
                    })?;
                    Ok(count)
                })
            })
            .await?;

        info!(
            provider_id,
            users_synced, "Full sync emitted to enrichment lane"
        );

        Ok(IdentitySyncResult {
            provider_id: provider_id.to_string(),
            users_synced,
            users_created: 0,
            users_updated: 0,
            users_disabled: 0, // deprovisioning handled by the staleness reconciler
            duration_ms: start.elapsed().as_millis() as u64,
            error: None,
            is_delta: false,
        })
    }

    /// Map an identity provider_type to its enrichment-lane `source`
    /// discriminator (must match the parsers-repo `enrich_source`). NAN-1151.
    fn provider_source(provider_type: &str) -> &'static str {
        match provider_type {
            "entra_id" => "entra",
            "google_workspace" => "google",
            "okta" => "okta",
            "workday" => "workday",
            // active_directory flows via /push (source=ad), not this pull path.
            _ => "unknown",
        }
    }

    /// Tag a raw provider user object for the `nano_enrich` lane: add the
    /// `kind`/`source` the router keys on + the `provider_id` the VRL stamps.
    fn tag_enrich_value(
        mut value: serde_json::Value,
        source: &str,
        provider_id: &str,
    ) -> serde_json::Value {
        if let Some(obj) = value.as_object_mut() {
            obj.insert("kind".to_string(), serde_json::Value::from("identity"));
            obj.insert("source".to_string(), serde_json::Value::from(source));
            obj.insert(
                "provider_id".to_string(),
                serde_json::Value::from(provider_id),
            );
        }
        value
    }

    // ========================================================================
    // Staleness reconciliation (NAN-1151)
    // ========================================================================

    /// Tombstone directory accounts not seen since `cutoff` — the staleness
    /// deprovisioning model that replaces synchronous per-sync mark-absent once
    /// providers emit through the (fire-and-forget) enrichment lane.
    ///
    /// With synchronous writes, "absent" meant "not in THIS sync" (cutoff =
    /// sync start). Through the lane, emitted records land asynchronously, so a
    /// just-after-sync check would false-delete every active account. Instead we
    /// age out by staleness: an account still being synced keeps a recent
    /// `last_synced_at` (from prior landed syncs), so with a window of N≥2 sync
    /// intervals only genuinely-removed accounts cross `cutoff`. This mirrors how
    /// Google SecOps ages entity context out of its live window rather than
    /// tombstoning per collection. Reuses the existing argMax-safe tombstone
    /// path (`mark_absent_users_by_sync_time`).
    #[instrument(skip(self))]
    pub async fn reconcile_stale_users(
        &self,
        provider_id: &str,
        cutoff: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, IdentityServiceError> {
        let disabled = self
            .repo
            .mark_absent_users_by_sync_time(provider_id, cutoff)
            .await?;
        if disabled > 0 {
            info!(
                provider_id,
                disabled,
                cutoff = %cutoff,
                "Staleness reconciliation tombstoned absent accounts"
            );
        }
        Ok(disabled)
    }

    // ========================================================================
    // Test Connection
    // ========================================================================

    #[instrument(skip(self))]
    pub async fn test_connection(
        &self,
        provider_id: &str,
    ) -> Result<ConnectionTestResult, IdentityServiceError> {
        let provider = self.repo.get_provider(provider_id).await?;

        if !provider.has_credentials() {
            return Ok(ConnectionTestResult {
                success: false,
                response_time_ms: None,
                error: Some("No credentials configured".into()),
                user_count_sample: None,
            });
        }

        let credentials = self.repo.get_decrypted_credentials(provider_id).await?;
        let provider_type: IdentityProviderType = provider.provider_type.parse().map_err(|_| {
            IdentityServiceError::InvalidProviderType(provider.provider_type.clone())
        })?;

        let result = match provider_type {
            IdentityProviderType::EntraId => {
                EntraIdSync::new().test_connection(&credentials).await?
            }
            IdentityProviderType::GoogleWorkspace => {
                GoogleWorkspaceSync::new()
                    .test_connection(&credentials)
                    .await?
            }
            IdentityProviderType::Okta => OktaSync::new().test_connection(&credentials).await?,
            IdentityProviderType::Workday => {
                WorkdaySync::new().test_connection(&credentials).await?
            }
            IdentityProviderType::ActiveDirectory => {
                // AD is push-based — just verify credentials exist
                ConnectionTestResult {
                    success: true,
                    response_time_ms: Some(0),
                    error: None,
                    user_count_sample: None,
                }
            }
        };

        Ok(result)
    }

    // NAN-1151 (3d): `push_users` (the AD /push handler) is retired. AD identity
    // now flows through the nano_enrich lane via the external collector, the
    // same as the pull providers — no in-app AD ingestion path remains.

    // ========================================================================
    // User Queries
    // ========================================================================

    pub async fn lookup_user_by_identifier(
        &self,
        identifier: &str,
    ) -> Result<Option<UserRecord>, IdentityServiceError> {
        Ok(self.repo.lookup_user_by_identifier(identifier).await?)
    }

    pub async fn list_users(
        &self,
        params: &ListUsersParams,
    ) -> Result<UserListResponse, IdentityServiceError> {
        Ok(self.repo.list_users(params).await?)
    }

    pub async fn get_user(&self, id: &str) -> Result<UserRecord, IdentityServiceError> {
        Ok(self.repo.get_user(id).await?)
    }

    pub async fn get_stats(&self) -> Result<IdentityStats, IdentityServiceError> {
        Ok(self.repo.get_stats().await?)
    }
}

