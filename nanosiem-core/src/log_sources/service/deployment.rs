// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deployment operations for log sources

use sqlx;
use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::activation::{self, HoldPurpose};
use crate::parsers::vector_config_remote_delivery::{take_delivery, with_delivery};
use crate::parsers::{VectorConfigManager, VrlValidator};
use crate::log_sources::deploy_jobs::{DeployPhase, DeployProgress, NoProgress};
use crate::log_sources::types::{
    DeploymentAction, DeploymentResult, DeploymentStatus, LogSourceDeployment, VrlValidationResult,
};

impl LogSourceService {
    /// Deploy a log source to Vector
    pub async fn deploy(&self, id: Uuid) -> Result<DeploymentResult, LogSourceServiceError> {
        self.deploy_with_progress(id, &NoProgress).await
    }

    /// [`Self::deploy`], reporting each phase to `progress` (NAN-5132: the
    /// deploy job records them for the UI).
    pub async fn deploy_with_progress(
        &self,
        id: Uuid,
        progress: &dyn DeployProgress,
    ) -> Result<DeploymentResult, LogSourceServiceError> {
        progress.phase(DeployPhase::WaitingForLock);
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
        progress.phase(DeployPhase::Validating);

        let log_source = self.repository().find_by_id(id).await?;
        // NAN-5132: a hold on this source can only be left by an earlier
        // deploy of it that died between its phases (deploys hold the lock).
        release_leftover_holds(&self.pool, id).await;

        // NAN-4952: the deploy enables the source before it renders (the
        // render reads the enabled set from the database). If the deploy then
        // fails, a source that was disabled before (a draft, a paused source)
        // must go back to disabled: left enabled, every LATER deploy of any
        // source renders it again and fails the same way, until someone
        // deletes it. That is the second half of the draft-deploy wedge.
        let was_enabled = log_source.enabled;
        // NAN-5132 (PR 5): adding a router-fed source goes out in two
        // generations, staged (parked) then activated. See `activation`.
        let mut two_phase = TwoPhase::new(
            !was_enabled
                && activation::available()
                && activation::eligible(&log_source.kind, &log_source.source_type),
        );
        let result = self.deploy_locked(id, log_source, progress, &mut two_phase).await;
        let live = matches!(&result, Ok(r) if r.success);
        if !live && !was_enabled {
            match self.repository().disable(id).await {
                Ok(_) => tracing::info!(
                    log_source_id = %id,
                    "deploy did not go live; the source is disabled again as it was before"
                ),
                Err(e) => tracing::error!(
                    log_source_id = %id,
                    error = %e,
                    "deploy did not go live and the source could not be disabled again; later \
                     deploys will keep including it"
                ),
            }
        }
        // NAN-5132: released only after the disable above, so no render ever
        // sees the source enabled without its hold (that is the live config).
        two_phase.release(&self.pool, id).await;
        // Role split: the hosts run what the database renders, not this API's
        // tree, so a withdrawn two-phase deploy is republished from the
        // reverted rows instead of waiting for the 5 s reconciler.
        if two_phase.published && !live && VectorConfigManager::generation_delivery_active() {
            progress.phase(DeployPhase::RollingBack);
            if let Err(e) = self.vector_config.reload_vector_after_rollback().await {
                tracing::warn!(
                    log_source_id = %id,
                    error = %e,
                    "could not republish the configuration after withdrawing a two-phase deploy; \
                     the publication reconciler retries"
                );
            }
        }
        result
    }

    /// [`Self::deploy`]'s body, run under the deploy guard.
    async fn deploy_locked(
        &self,
        id: Uuid,
        log_source: crate::log_sources::types::LogSource,
        progress: &dyn DeployProgress,
        two_phase: &mut TwoPhase,
    ) -> Result<DeploymentResult, LogSourceServiceError> {
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
        // NAN-4912 P3: enrichment lanes compile against the enrichment
        // registry (parser allowlist + `log` for dead-letter warnings).
        let enrichment_validator;
        let validator = if log_source.kind == "enrichment" {
            enrichment_validator = VrlValidator::for_enrichment();
            &enrichment_validator
        } else {
            self.vrl_validator.as_ref()
        };
        let vrl_result = validator
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
                delivery: None,
            });
        }

        // Mark as validated
        self.repository()
            .set_validation_status(id, true, None)
            .await?;

        tracing::info!("VRL validation passed for log source '{}'", log_source.name);

        // Step 2: Get all enabled log sources and deploy them all
        // Enable this log source for deployment
        progress.phase(DeployPhase::Rendering);
        // NAN-5132: hold BEFORE enabling, so every render from here on (this
        // one, another app host's, the publication reconciler's) sees the
        // source parked until phase A is verified on every ingest host.
        two_phase.hold(&self.pool, id, HoldPurpose::Deploy).await;
        self.repository().enable(id).await?;

        // NAN-928: the helper also resolves dispatch source-config route names
        // so the generator wires fetch-source parsers to the user's
        // source-config route instead of creating a parser-owned Vector source.
        let parsers = self.effective_deployed_parsers().await?;

        // NAN-4956: a pull parser whose source configuration is not deployed is
        // left out of the render (its route does not exist). Say so instead of
        // reporting a deploy that put nothing live.
        if let Some(target) = parsers.iter().find(|p| p.id == id) {
            if self.vector_config.is_unroutable(target).await {
                let error_msg = format!(
                    "Log source '{}' reads from source configuration route '{}', which is not \
                     deployed. Deploy the source configuration first; the parser goes live with it.",
                    log_source.name,
                    target.dispatch_route_name.as_deref().unwrap_or("<none>")
                );
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
                    delivery: None,
                });
            }
        }

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
                delivery: None,
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
            progress.phase(DeployPhase::ValidatingConfig);
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
                        delivery: None,
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
                delivery: None,
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
        progress.phase(DeployPhase::Promoting);
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
                    progress.phase(DeployPhase::RollingBack);
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
                delivery: None,
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
        progress.phase(DeployPhase::Reloading);
        two_phase.published = two_phase.held;
        if let Err(failure) = self
            .vector_config
            .reload_and_verify_locked(backup.as_ref())
            .await
        {
            return self
                .reload_failure_result(id, &log_source, backup.is_some(), failure, progress)
                .await;
        }

        // NAN-5132 (PR 5): phase A (the parked chain) is live on every host;
        // activate it. A failure here withdraws the whole deploy.
        if two_phase.held {
            if let Some(failed) = self
                .activate_held_deploy(id, &log_source, backup.as_ref(), progress, two_phase)
                .await?
            {
                return Ok(failed);
            }
        }

        // Success! The deploy regenerated the whole Vector config from EVERY
        // enabled source, so they're all live now — mark the explicit target
        // (refreshing its deployed_at) and flip any other enabled-but-never-
        // deployed source to deployed too. Without this, sources included in the
        // config but never individually published (e.g. batch-imported parsers)
        // keep showing "ready" though they're live (NAN-1275). Best-effort: a
        // bookkeeping miss must not fail an otherwise-successful deploy.
        self.finish_successful_deploy(id, &log_source, two_phase.activated).await
    }

    /// The deploy result for a failed [`VectorConfigManager::reload_and_verify_locked`]
    /// (shared by the one-phase reload and both phases of a two-phase one).
    async fn reload_failure_result(
        &self,
        id: Uuid,
        log_source: &crate::log_sources::types::LogSource,
        had_backup: bool,
        failure: crate::parsers::VectorVerifyFailure,
        progress: &dyn DeployProgress,
    ) -> Result<DeploymentResult, LogSourceServiceError> {
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
            // NAN-5133 review M2: role split, published but no ingest host
            // confirmed it. Nothing to roll back; report it as not live.
            let unconfirmed = matches!(
                failure.error,
                crate::parsers::VectorConfigError::ReloadUnconfirmed(_)
            );
            if unconfirmed {
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
                    message: error_msg.clone(),
                    validation_result: None,
                    deployment_id: None,
                    delivery: None,
                });
            }
            if !failure.rolled_back && had_backup {
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

            if failure.rolled_back {
                progress.phase(DeployPhase::RollingBack);
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

            Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message,
                validation_result: None,
                deployment_id: None,
                delivery: None,
            })
        }
    }

    /// NAN-5132 (PR 5): phase B of a two-phase deploy. Phase A (the source
    /// parked) is installed; confirm every ingest host acknowledged it, then
    /// release the hold, render, promote and reload once more. `Some` is the
    /// failed result (the caller withdraws the deploy); `None` means active.
    async fn activate_held_deploy(
        &self,
        id: Uuid,
        log_source: &crate::log_sources::types::LogSource,
        backup: Option<&crate::parsers::VectorBackupGeneration>,
        progress: &dyn DeployProgress,
        two_phase: &mut TwoPhase,
    ) -> Result<Option<DeploymentResult>, LogSourceServiceError> {
        // Role split: "live" includes hosts still installing (NAN-5279). The
        // point of phase A is that EVERY host built the chain, so anything but
        // a full acknowledgement stops here, before routing changes anywhere.
        if VectorConfigManager::generation_delivery_active() {
            if let Err(detail) = activation::staged_on_every_host(take_delivery()) {
                return Ok(Some(
                    self.withdraw_two_phase(
                        id,
                        backup,
                        progress,
                        format!(
                            "Not every ingest host acknowledged the staged configuration, so the \
                             source was not activated anywhere and the deploy was withdrawn: {detail}"
                        ),
                    )
                    .await,
                ));
            }
        }

        progress.phase(DeployPhase::Activating);
        if let Err(e) = activation::release(&self.pool, id).await {
            return Ok(Some(
                self.withdraw_two_phase(
                    id,
                    backup,
                    progress,
                    format!("Could not activate the staged source: {e}"),
                )
                .await,
            ));
        }
        two_phase.held = false;
        let parsers = self.effective_deployed_parsers().await?;
        // Phase A already passed `vector validate` (when enabled) on the same
        // set; B only adds the route and re-points the chain's entry.
        let promoted = match self.vector_config.stage_parsers(&parsers).await {
            Ok(()) => self.vector_config.promote_staged().await,
            Err(e) => {
                let _ = self.vector_config.cleanup_staging().await;
                Err(e)
            }
        };
        if let Err(e) = promoted {
            return Ok(Some(
                self.withdraw_two_phase(
                    id,
                    backup,
                    progress,
                    format!("Could not render the activated configuration: {e}"),
                )
                .await,
            ));
        }
        if let Err(failure) = self.vector_config.reload_and_verify_locked(backup).await {
            return self
                .reload_failure_result(id, log_source, backup.is_some(), failure, progress)
                .await
                .map(Some);
        }
        two_phase.activated = true;
        Ok(None)
    }

    /// NAN-5132: put the pre-deploy configuration back after a two-phase
    /// deploy stopped between its phases. Local install: restore the snapshot
    /// taken before phase A and reload. Role split: the caller republishes
    /// once the database is reverted (the hosts run what it renders).
    async fn withdraw_two_phase(
        &self,
        id: Uuid,
        backup: Option<&crate::parsers::VectorBackupGeneration>,
        progress: &dyn DeployProgress,
        reason: String,
    ) -> DeploymentResult {
        tracing::warn!(log_source_id = %id, "{reason}");
        progress.phase(DeployPhase::RollingBack);
        let mut message = reason;
        if !VectorConfigManager::generation_delivery_active() {
            match backup {
                Some(backup) => match self.vector_config.restore_backup(backup).await {
                    Ok(()) => {
                        if let Err(e) = self.vector_config.reload_vector_after_rollback().await {
                            tracing::error!(error = %e, "reload after withdrawing a two-phase deploy failed");
                        }
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "could not restore the configuration from before the deploy");
                        message.push_str(&format!(
                            ". Restoring the previous configuration also failed ({e}); check the Vector config"
                        ));
                    }
                },
                None => message.push_str(
                    ". No snapshot was taken before the deploy, so the staged (parked) chain stays \
                     installed until the next deploy; it receives no events",
                ),
            }
        }
        let _ = self
            .repository()
            .record_deployment(
                id,
                DeploymentAction::Rollback.as_str(),
                DeploymentStatus::RolledBack.as_str(),
                Some(&message),
                None,
            )
            .await;
        DeploymentResult {
            success: false,
            log_source_id: id,
            action: DeploymentAction::Deploy.as_str().to_string(),
            message,
            validation_result: None,
            deployment_id: None,
            delivery: None,
        }
    }

    /// Bookkeeping and the result for a deploy that went live.
    async fn finish_successful_deploy(
        &self,
        id: Uuid,
        log_source: &crate::log_sources::types::LogSource,
        two_phase: bool,
    ) -> Result<DeploymentResult, LogSourceServiceError> {
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

        // NAN-5279: on a role-split install the note and `delivery` say
        // whether every ingest host installed it or some are still installing.
        let (message, delivery) = with_delivery(if two_phase {
            format!(
                "Log source '{}' deployed successfully (staged on every ingest host, then activated)",
                log_source.name
            )
        } else {
            format!("Log source '{}' deployed successfully", log_source.name)
        });
        Ok(DeploymentResult {
            success: true,
            log_source_id: id,
            action: DeploymentAction::Deploy.as_str().to_string(),
            message,
            validation_result: None,
            deployment_id: Some(deployment_id),
            delivery,
        })
    }

    /// Undeploy a log source from Vector
    pub async fn undeploy(&self, id: Uuid) -> Result<DeploymentResult, LogSourceServiceError> {
        self.undeploy_with_progress(id, &NoProgress).await
    }

    /// [`Self::undeploy`] with phase reports (NAN-5132).
    ///
    /// The deploy lock is taken before the source is disabled, so the render
    /// that drops it reads the database state this call wrote, and a queued
    /// deploy job for the same target has not read anything yet.
    pub async fn undeploy_with_progress(
        &self,
        id: Uuid,
        progress: &dyn DeployProgress,
    ) -> Result<DeploymentResult, LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;

        progress.phase(DeployPhase::WaitingForLock);
        let _deploy_guard = self.vector_config.lock_deploys().await;
        progress.phase(DeployPhase::Rendering);
        release_leftover_holds(&self.pool, id).await;

        tracing::info!("Undeploying log source '{}' ({})", log_source.name, id);

        // NAN-5132 (PR 5): removing a live router-fed source goes out in two
        // generations too. A: unroute it and park its chain (it stops
        // receiving events on every host); B: drop the chain. A failure in A
        // leaves the source deployed and routed, exactly as before the call.
        let mut two_phase = TwoPhase::new(
            log_source.enabled
                && activation::available()
                && activation::eligible(&log_source.kind, &log_source.source_type),
        );
        two_phase.hold(&self.pool, id, HoldPurpose::Undeploy).await;
        if two_phase.held {
            if let Some(stopped) = self.stage_held_undeploy(id, &log_source, progress, &mut two_phase).await {
                return Ok(stopped);
            }
            progress.phase(DeployPhase::Activating);
        }

        // Disable and mark as undeployed. The hold goes only after the
        // disable: in between, the source must never render live again.
        self.repository().disable(id).await?;
        two_phase.release(&self.pool, id).await;
        self.repository().mark_undeployed(id).await?;

        // Redeploy all remaining enabled log sources (using active versions)
        let parsers = self.effective_deployed_parsers().await?;

        if !two_phase.held && !two_phase.published {
            progress.phase(DeployPhase::Reloading);
        }
        if let Err(e) = self.vector_config.deploy_and_reload_locked(&parsers).await {
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
                delivery: None,
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
            delivery: None,
        })
    }

    /// NAN-5132 (PR 5): phase A of a two-phase undeploy: render the held
    /// source parked (unrouted, chain disconnected) and confirm every ingest
    /// host installed it. `Some` is the result of an undeploy that stopped
    /// here: the hold is released and the source stays deployed and routed.
    async fn stage_held_undeploy(
        &self,
        id: Uuid,
        log_source: &crate::log_sources::types::LogSource,
        progress: &dyn DeployProgress,
        two_phase: &mut TwoPhase,
    ) -> Option<DeploymentResult> {
        progress.phase(DeployPhase::Reloading);
        two_phase.published = true;
        let staged = match self.effective_deployed_parsers().await {
            Ok(parsers) => self
                .vector_config
                .deploy_and_reload_locked(&parsers)
                .await
                .map_err(|e| e.to_string()),
            Err(e) => Err(e.to_string()),
        };
        let role_split = VectorConfigManager::generation_delivery_active();
        let verdict = match staged {
            Err(e) => Err(e),
            Ok(()) if role_split => activation::staged_on_every_host(take_delivery()),
            Ok(()) => Ok(()),
        };
        let reason = verdict.err()?;

        progress.phase(DeployPhase::RollingBack);
        two_phase.release(&self.pool, id).await;
        // Local: `deploy_and_reload_locked` already restored its snapshot on a
        // rejection. Role split: republish the routed state from the database.
        if role_split {
            if let Err(e) = self.vector_config.reload_vector_after_rollback().await {
                tracing::warn!(error = %e, "could not republish after a withdrawn undeploy; the reconciler retries");
            }
        } else if let Ok(parsers) = self.effective_deployed_parsers().await {
            // A staged tree Vector accepted but did not stay healthy on is
            // still on disk: render the routed state again.
            if let Err(e) = self.vector_config.deploy_and_reload_locked(&parsers).await {
                tracing::error!(error = %e, "could not restore the routed config after a withdrawn undeploy");
            }
        }
        let message = format!(
            "Undeploy of '{}' stopped before anything was removed: not every ingest host \
             installed the staged (unrouted) configuration, so the source stays deployed and \
             routed. {reason}",
            log_source.name
        );
        tracing::warn!(log_source_id = %id, "{message}");
        let _ = self
            .repository()
            .record_deployment(
                id,
                DeploymentAction::Undeploy.as_str(),
                DeploymentStatus::RolledBack.as_str(),
                Some(&message),
                None,
            )
            .await;
        Some(DeploymentResult {
            success: false,
            log_source_id: id,
            action: DeploymentAction::Undeploy.as_str().to_string(),
            message,
            validation_result: None,
            deployment_id: None,
            delivery: None,
        })
    }

    /// Deploy all enabled log sources (using active version VRL)
    pub async fn deploy_all(&self) -> Result<(), LogSourceServiceError> {
        self.deploy_all_with_progress(&NoProgress).await
    }

    /// [`Self::deploy_all`] with phase reports (NAN-5132). The enabled set is
    /// read under the deploy lock, so a deploy-all job that was queued renders
    /// the state at the time it runs, not the time it was requested.
    pub async fn deploy_all_with_progress(
        &self,
        progress: &dyn DeployProgress,
    ) -> Result<(), LogSourceServiceError> {
        progress.phase(DeployPhase::WaitingForLock);
        let _deploy_guard = self.vector_config.lock_deploys().await;
        progress.phase(DeployPhase::Rendering);

        let parsers = self.effective_deployed_parsers().await?;

        progress.phase(DeployPhase::Reloading);
        self.vector_config.deploy_and_reload_locked(&parsers).await?;

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

/// NAN-5132: release holds a dead deploy left (this source's, and any older
/// than [`activation::STALE_HOLD_AFTER`]). Best effort.
async fn release_leftover_holds(pool: &sqlx::PgPool, id: Uuid) {
    match activation::release(pool, id).await {
        Ok(true) => tracing::warn!(
            log_source_id = %id,
            "released an activation hold left by an interrupted deploy of this source"
        ),
        Ok(false) => {}
        Err(e) => tracing::warn!(log_source_id = %id, error = %e, "could not release a leftover activation hold"),
    }
    if let Err(e) = activation::release_stale(pool).await {
        tracing::warn!(error = %e, "could not release stale log-source activation holds");
    }
}

/// NAN-5132 (PR 5): where a two-phase deploy or undeploy stands.
pub(super) struct TwoPhase {
    /// Eligible and available when the call started.
    enabled: bool,
    /// The source has a hold row (renders parked).
    held: bool,
    /// Phase A was handed to Vector / the ingest hosts.
    published: bool,
    /// Phase B went live.
    activated: bool,
}

impl TwoPhase {
    pub(super) fn new(enabled: bool) -> Self {
        Self { enabled, held: false, published: false, activated: false }
    }

    /// Take the hold. A failure falls back to a one-phase deploy.
    async fn hold(&mut self, pool: &sqlx::PgPool, id: Uuid, purpose: HoldPurpose) {
        if !self.enabled {
            return;
        }
        match activation::hold(pool, id, purpose).await {
            Ok(()) => self.held = true,
            Err(e) => {
                tracing::warn!(
                    log_source_id = %id,
                    error = %e,
                    "could not stage the source for two-phase activation; deploying in one phase"
                );
                self.enabled = false;
            }
        }
    }

    /// Release the hold if this call still has one. Best effort: a stale hold
    /// is released by the next deploy or API start.
    async fn release(&mut self, pool: &sqlx::PgPool, id: Uuid) {
        if !self.held {
            return;
        }
        match activation::release(pool, id).await {
            Ok(_) => self.held = false,
            Err(e) => tracing::error!(
                log_source_id = %id,
                error = %e,
                "could not release the activation hold; the source renders parked until the next deploy"
            ),
        }
    }
}
