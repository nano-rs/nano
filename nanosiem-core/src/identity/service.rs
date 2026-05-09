// SPDX-License-Identifier: AGPL-3.0-or-later

//! Identity sync service
//!
//! Orchestrates sync operations: load config → decrypt creds → attempt delta sync
//! → fall back to full sync → bulk upsert → soft-delete absent → update status.

use thiserror::Error;
use tracing::{error, info, instrument};

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
}

impl IdentitySyncService {
    pub fn new(repo: IdentityRepository) -> Self {
        Self { repo }
    }

    pub fn repository(&self) -> &IdentityRepository {
        &self.repo
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
        // Capture DB server time for absent-user detection — must come from the same
        // clock that sets last_synced_at to avoid clock skew false deletions.
        let sync_started_at = self.repo.db_now().await?;

        // Try delta sync first — delta results are bounded (only changed users), safe to collect
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
                let (affected, _) = self
                    .repo
                    .upsert_users(provider_id, &delta_result.users)
                    .await?;

                info!(
                    provider_id,
                    users_synced,
                    is_delta = true,
                    "Delta sync completed"
                );

                return Ok(IdentitySyncResult {
                    provider_id: provider_id.to_string(),
                    users_synced,
                    users_created: affected,
                    users_updated: 0,
                    users_disabled: 0, // Delta syncs don't disable absent users
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

        // Full sync — use paged variant to keep memory bounded.
        // Each page is upserted immediately and then dropped.
        let repo = self.repo.clone();
        let pid = provider_id.to_string();

        let users_synced = sync_impl
            .full_sync_paged(credentials, config, &|page: Vec<UserRecordUpsert>| {
                let count = page.len() as u64;
                let repo = repo.clone();
                let pid = pid.clone();
                Box::pin(async move {
                    repo.upsert_users(&pid, &page).await.map_err(|e| {
                        SyncError::StorageError(format!("Paged upsert failed: {}", e))
                    })?;
                    Ok(count)
                })
            })
            .await?;

        // Detect absent users via timestamp: any user whose last_synced_at is before
        // sync_started_at (from DB clock) wasn't in the provider's response.
        let users_disabled = if users_synced > 0 {
            self.repo
                .mark_absent_users_by_sync_time(provider_id, sync_started_at)
                .await
                .unwrap_or(0)
        } else {
            0
        };

        info!(
            provider_id,
            users_synced, users_disabled, "Full sync completed"
        );

        Ok(IdentitySyncResult {
            provider_id: provider_id.to_string(),
            users_synced,
            users_created: 0, // Paged mode doesn't track create vs update
            users_updated: 0,
            users_disabled,
            duration_ms: start.elapsed().as_millis() as u64,
            error: None,
            is_delta: false,
        })
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

    // ========================================================================
    // AD Push
    // ========================================================================

    /// Push users from an AD collector. Validates the collector token.
    #[instrument(skip(self, users))]
    pub async fn push_users(
        &self,
        provider_id: &str,
        bearer_token: &str,
        users: Vec<PushUserRecord>,
    ) -> Result<IdentitySyncResult, IdentityServiceError> {
        let start = std::time::Instant::now();
        let provider = self.repo.get_provider(provider_id).await?;

        // Validate provider type
        if provider.provider_type != "active_directory" {
            return Err(IdentityServiceError::InvalidProviderType(format!(
                "Push endpoint only supports active_directory, got {}",
                provider.provider_type
            )));
        }

        // Validate collector token
        let credentials = self.repo.get_decrypted_credentials(provider_id).await?;
        let ad_creds: ActiveDirectoryCredentials =
            serde_json::from_value(credentials).map_err(|e| {
                IdentityServiceError::Repository(IdentityRepositoryError::EncryptionError(
                    e.to_string(),
                ))
            })?;

        if bearer_token != ad_creds.collector_token {
            return Err(IdentityServiceError::Repository(
                IdentityRepositoryError::ProviderNotFound("Invalid collector token".to_string()),
            ));
        }

        // Convert push records to upsert records
        let upsert_records: Vec<UserRecordUpsert> =
            users.into_iter().map(|u| u.into_upsert()).collect();

        let users_synced = upsert_records.len() as u64;
        let (affected, _) = self.repo.upsert_users(provider_id, &upsert_records).await?;

        let user_count = self.repo.get_user_count(provider_id).await.unwrap_or(0) as i32;
        let duration_ms = start.elapsed().as_millis() as u64;

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

        Ok(IdentitySyncResult {
            provider_id: provider_id.to_string(),
            users_synced,
            users_created: affected,
            users_updated: 0,
            users_disabled: 0,
            duration_ms,
            error: None,
            is_delta: false,
        })
    }

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

    pub async fn get_user(&self, id: i64) -> Result<UserRecord, IdentityServiceError> {
        Ok(self.repo.get_user(id).await?)
    }

    pub async fn get_stats(&self) -> Result<IdentityStats, IdentityServiceError> {
        Ok(self.repo.get_stats().await?)
    }
}
