// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deployment operations for log sources

use sqlx;
use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    DeploymentAction, DeploymentResult, DeploymentStatus, LogSourceDeployment, VrlValidationResult,
};

impl LogSourceService {
    /// Deploy a log source to Vector
    pub async fn deploy(&self, id: Uuid) -> Result<DeploymentResult, LogSourceServiceError> {
        // NAN-2297: stage → validate → backup → promote → reload is ONE critical
        // section against a single on-disk staging directory. Held for the whole
        // sequence, not per-step, so a concurrent deploy cannot clean this one's
        // staging mid-validate, promote a half-built tree, or (since NAN-2296)
        // prune files this deploy just promoted. Shared with ParserService and
        // SourceConfigService via the manager handed in at construction.
        //
        // Everything below must stay on lock-free helpers or `*_locked`
        // variants — the mutex is not reentrant.
        let _deploy_guard = self.vector_config.lock_deploys().await;

        let log_source = self.repository().find_by_id(id).await?;

        tracing::info!(
            "Starting deployment for log source '{}' ({})",
            log_source.name,
            id
        );

        // Step 1: Validate VRL syntax. NAN-1149: an enrichment source carries
        // its logic in `normalize_vrl` (the lane mapping), not the log
        // `parser_vrl` — validate that one instead, or the empty parser_vrl
        // trips "VRL code cannot be empty" and the deploy never reaches the
        // enrichment lane.
        let vrl_to_validate: &str = if log_source.kind == "enrichment" {
            log_source.normalize_vrl.as_deref().unwrap_or("")
        } else {
            &log_source.parser_vrl
        };
        let vrl_result = self
            .vrl_validator
            .validate_vrl(vrl_to_validate)
            .await
            .map_err(|e| LogSourceServiceError::VrlValidationFailed(e.to_string()))?;

        if !vrl_result.valid {
            let error_msg = vrl_result
                .error
                .clone()
                .unwrap_or_else(|| "Unknown VRL error".to_string());
            tracing::warn!(
                "VRL validation failed for log source '{}': {}",
                log_source.name,
                error_msg
            );

            // Record failed deployment
            let _ = self
                .repository()
                .record_deployment(
                    id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    None,
                )
                .await;

            self.repository()
                .set_validation_status(id, false, Some(&error_msg))
                .await?;

            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: format!("VRL validation failed: {}", error_msg),
                validation_result: Some(VrlValidationResult {
                    valid: false,
                    errors: vec![error_msg],
                    diagnostics: vec![],
                }),
                deployment_id: None,
            });
        }

        // Mark as validated
        self.repository()
            .set_validation_status(id, true, None)
            .await?;

        tracing::info!("VRL validation passed for log source '{}'", log_source.name);

        // Step 2: Get all enabled log sources and deploy them all
        // Enable this log source for deployment
        self.repository().enable(id).await?;

        // NAN-928: the helper also resolves dispatch source-config route names
        // so the generator wires fetch-source parsers to the user's
        // source-config route instead of creating a parser-owned Vector source.
        let parsers = self.effective_deployed_parsers().await?;

        // Stage and validate
        if let Err(e) = self.vector_config.stage_parsers(&parsers).await {
            let error_msg = format!("Failed to stage config: {}", e);
            tracing::error!("{}", error_msg);

            let _ = self
                .repository()
                .record_deployment(
                    id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    None,
                )
                .await;

            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: error_msg,
                validation_result: None,
                deployment_id: None,
            });
        }

        // Run vector validate (can be skipped via env var - VRL validation already passed)
        let skip_vector_validation = std::env::var("SKIP_VECTOR_VALIDATION")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(false);

        let validate_result = if skip_vector_validation {
            tracing::info!("Skipping vector validate (SKIP_VECTOR_VALIDATION=true)");
            crate::parsers::ValidationResult {
                success: true,
                errors: vec![],
                warnings: vec!["Vector config validation skipped".to_string()],
                raw_output: String::new(),
            }
        } else {
            match self.vector_config.validate_staged_config().await {
                Ok(result) => result,
                Err(e) => {
                    let error_msg = format!("Vector validation error: {}", e);
                    tracing::error!("{}", error_msg);
                    let _ = self.vector_config.cleanup_staging().await;

                    let _ = self
                        .repository()
                        .record_deployment(
                            id,
                            DeploymentAction::Deploy.as_str(),
                            DeploymentStatus::Failed.as_str(),
                            Some(&error_msg),
                            None,
                        )
                        .await;

                    return Ok(DeploymentResult {
                        success: false,
                        log_source_id: id,
                        action: DeploymentAction::Deploy.as_str().to_string(),
                        message: error_msg,
                        validation_result: None,
                        deployment_id: None,
                    });
                }
            }
        };

        if !validate_result.success {
            let error_msg = validate_result.errors.join("; ");
            tracing::warn!(
                "Vector validation failed for log source '{}': {}",
                log_source.name,
                error_msg
            );
            let _ = self.vector_config.cleanup_staging().await;

            let _ = self
                .repository()
                .record_deployment(
                    id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    None,
                )
                .await;

            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: format!("Vector validation failed: {}", error_msg),
                validation_result: Some(VrlValidationResult {
                    valid: false,
                    errors: validate_result.errors,
                    diagnostics: vec![],
                }),
                deployment_id: None,
            });
        }

        tracing::info!(
            "Vector validation passed for log source '{}'",
            log_source.name
        );

        // Step 3: Backup, promote, and reload.
        //
        // NAN-2301: the failure is non-fatal (an incoherent tree is healed by
        // the very promotion below, so refusing to run it would be a trap) but
        // no longer silent, and no longer falls back to an older snapshot. A
        // leftover backup describes a different starting state; restoring it is
        // an unrelated overwrite, and when the leftover is the empty
        // first-install backup it deletes a live config outright.
        let backup = match self.vector_config.backup_current().await {
            Ok(generation) => Some(generation),
            Err(e) => {
                tracing::warn!(
                    "Failed to back up current config before promoting — this deploy will not be \
                     able to roll back: {}",
                    e
                );
                None
            }
        };

        if let Err(e) = self.vector_config.promote_staged().await {
            let error_msg = format!("Failed to promote staged config: {}", e);
            tracing::error!("{}", error_msg);

            // NAN-2305: restore the snapshot taken directly above — and only
            // that one. A promotion that failed partway leaves the ACTIVE tree
            // mixed: some files replaced, some not, and (since NAN-2296) some
            // pruned. This path used to return straight from here, so the
            // deploy was reported failed while a half-published config stayed
            // live and every later reload rejected it. The parser path has
            // restored since NAN-2300; this is the same sequence.
            match backup.as_ref() {
                Some(generation) => {
                    if let Err(restore_err) = self.vector_config.restore_backup(generation).await {
                        tracing::error!(
                            "Restore after failed promotion also failed: {}. Active config may be \
                             inconsistent — manual intervention required.",
                            restore_err
                        );
                    }
                }
                None => tracing::error!(
                    "Promotion failed with no snapshot from this attempt to restore. The active \
                     config may be partially replaced — manual intervention required."
                ),
            }

            let _ = self
                .repository()
                .record_deployment(
                    id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    None,
                )
                .await;

            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: error_msg,
                validation_result: None,
                deployment_id: None,
            });
        }

        // Reload Vector, confirm it accepted the config, and roll back if not.
        //
        // NAN-2305: this was a bare `reload_vector` plus a hand-rolled rollback
        // that skipped the post-reload health poll the parser path has. Both
        // halves now go through the shared helper, so the two entrypoints agree
        // on what a verified deploy is — and on what gets RECORDED, since the
        // helper is the only thing that knows whether the restore actually ran.
        //
        // `_locked`: this method already holds the deploy guard (NAN-2297).
        if let Err(failure) = self
            .vector_config
            .reload_and_verify_locked(backup.as_ref())
            .await
        {
            let error_msg = format!("{}", failure);
            tracing::error!(
                "Deploy failed for log source '{}': {}",
                log_source.name,
                error_msg
            );

            // A backup existed but nothing was rolled back ⇒ the restore itself
            // failed, which is the one outcome that needs a human. Preserved as
            // a hard error (it was `RollbackFailed` before) rather than folded
            // into the generic failure result.
            if !failure.rolled_back && backup.is_some() {
                let error_msg = format!("Reload failed and rollback also failed: {}", error_msg);
                let _ = self
                    .repository()
                    .record_deployment(
                        id,
                        DeploymentAction::Deploy.as_str(),
                        DeploymentStatus::Failed.as_str(),
                        Some(&error_msg),
                        None,
                    )
                    .await;
                return Err(LogSourceServiceError::RollbackFailed(error_msg));
            }

            let (action, status) = if failure.rolled_back {
                (DeploymentAction::Rollback, DeploymentStatus::RolledBack)
            } else {
                (DeploymentAction::Deploy, DeploymentStatus::Failed)
            };
            let _ = self
                .repository()
                .record_deployment(
                    id,
                    action.as_str(),
                    status.as_str(),
                    Some(&error_msg),
                    None,
                )
                .await;

            let message = if failure.rolled_back {
                format!("Reload failed, rolled back: {}", error_msg)
            } else {
                format!("Reload failed and was NOT rolled back: {}", error_msg)
            };

            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message,
                validation_result: None,
                deployment_id: None,
            });
        }

        // Success! The deploy regenerated the whole Vector config from EVERY
        // enabled source, so they're all live now — mark the explicit target
        // (refreshing its deployed_at) and flip any other enabled-but-never-
        // deployed source to deployed too. Without this, sources included in the
        // config but never individually published (e.g. batch-imported parsers)
        // keep showing "ready" though they're live (NAN-1275). Best-effort: a
        // bookkeeping miss must not fail an otherwise-successful deploy.
        self.repository().mark_deployed(id).await?;
        if let Err(e) = self.repository().mark_enabled_deployed().await {
            tracing::warn!(error = %e, "deploy succeeded but failed to mark sibling enabled sources deployed");
        }
        // NAN-1920: a feed onboarded via the AddFeed wizard persists as a
        // lifecycle 'draft' while it's built. Deploying it makes it a real,
        // live feed — flip it out of draft. Idempotent (no-op for active
        // feeds) and best-effort: a bookkeeping miss must not fail the deploy.
        if let Err(e) = self.repository().mark_lifecycle_active(id).await {
            tracing::warn!(error = %e, "deploy succeeded but failed to flip lifecycle_status to active");
        }

        let deployment_id = self
            .repository()
            .record_deployment(
                id,
                DeploymentAction::Deploy.as_str(),
                DeploymentStatus::Success.as_str(),
                None,
                None,
            )
            .await?;

        tracing::info!(
            "Successfully deployed log source '{}' ({})",
            log_source.name,
            id
        );

        Ok(DeploymentResult {
            success: true,
            log_source_id: id,
            action: DeploymentAction::Deploy.as_str().to_string(),
            message: format!("Log source '{}' deployed successfully", log_source.name),
            validation_result: None,
            deployment_id: Some(deployment_id),
        })
    }

    /// Undeploy a log source from Vector
    pub async fn undeploy(&self, id: Uuid) -> Result<DeploymentResult, LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;

        tracing::info!("Undeploying log source '{}' ({})", log_source.name, id);

        // Disable and mark as undeployed
        self.repository().disable(id).await?;
        self.repository().mark_undeployed(id).await?;

        // Redeploy all remaining enabled log sources (using active versions)
        let parsers = self.effective_deployed_parsers().await?;

        if let Err(e) = self.vector_config.deploy_and_reload(&parsers).await {
            let error_msg = format!("Failed to redeploy after undeploy: {}", e);
            tracing::error!("{}", error_msg);

            let _ = self
                .repository()
                .record_deployment(
                    id,
                    DeploymentAction::Undeploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    None,
                )
                .await;

            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Undeploy.as_str().to_string(),
                message: error_msg,
                validation_result: None,
                deployment_id: None,
            });
        }

        let deployment_id = self
            .repository()
            .record_deployment(
                id,
                DeploymentAction::Undeploy.as_str(),
                DeploymentStatus::Success.as_str(),
                None,
                None,
            )
            .await?;

        // Clean up orphaned routing rules that targeted this log source's source_type.
        // We only delete from the DB — no source config deploy or router update needed.
        // The next explicit source config deploy will regenerate configs without these rules.
        match sqlx::query("DELETE FROM routing_rules WHERE target_source_type = $1")
            .bind(&log_source.source_type)
            .execute(&self.pool)
            .await
        {
            Ok(result) if result.rows_affected() > 0 => {
                tracing::info!(
                    "Removed {} orphaned routing rule(s) targeting source_type '{}'",
                    result.rows_affected(),
                    log_source.source_type
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to clean up routing rules for source_type '{}': {}",
                    log_source.source_type,
                    e
                );
            }
            _ => {}
        }

        tracing::info!(
            "Successfully undeployed log source '{}' ({})",
            log_source.name,
            id
        );

        Ok(DeploymentResult {
            success: true,
            log_source_id: id,
            action: DeploymentAction::Undeploy.as_str().to_string(),
            message: format!("Log source '{}' undeployed successfully", log_source.name),
            validation_result: None,
            deployment_id: Some(deployment_id),
        })
    }

    /// Deploy all enabled log sources (using active version VRL)
    pub async fn deploy_all(&self) -> Result<(), LogSourceServiceError> {
        let parsers = self.effective_deployed_parsers().await?;

        self.vector_config.deploy_and_reload(&parsers).await?;

        // Mark all as deployed
        for ls in self.repository().list_enabled().await? {
            let _ = self.repository().mark_deployed(ls.id).await;
        }

        Ok(())
    }

    /// Get deployment history for a log source, with secrets scrubbed from
    /// every snapshot.
    ///
    /// NAN-2068: `LogSourceService` writes no snapshot, but `ParserService`
    /// writes into the same table, and rows persisted before the NAN-690
    /// redactor landed still hold raw generated TOML. This endpoint serves
    /// them to any `log_sources:view` holder, so scrub at the read boundary —
    /// idempotent, and it covers historical rows without a backfill migration.
    pub async fn get_deployment_history(
        &self,
        id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<LogSourceDeployment>, LogSourceServiceError> {
        let mut deployments = self
            .repository()
            .get_deployment_history(id, limit.unwrap_or(50))
            .await?;
        for deployment in &mut deployments {
            if let Some(snapshot) = deployment.config_snapshot.as_deref() {
                deployment.config_snapshot = Some(crate::parsers::redact_config_snapshot(snapshot));
            }
        }
        Ok(deployments)
    }
}
