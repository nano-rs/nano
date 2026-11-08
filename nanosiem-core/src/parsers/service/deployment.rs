// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser deployment lifecycle (deploy, undeploy, rollback)

use uuid::Uuid;

use super::ParserService;
use super::ParserServiceError;
use crate::parsers::types::{
    DeploymentAction, DeploymentResult, DeploymentStatus, ParserDeployment, ValidationResult,
};
use crate::parsers::vector_config::redact_config_snapshot;

impl ParserService {
    /// Render the canonical parser configuration without reloading Vector.
    /// Publication callers construct this service against an isolated render
    /// root, so no pod-local live tree is treated as shared state.
    ///
    /// NAN-2304: renders the EFFECTIVE deployed set (active versions), not the
    /// parser editor's working copies. This used to call `list()`, which reads
    /// `log_sources.parser_vrl` directly — so saving a draft bumped
    /// `source_revision` and the 5s reconciler published an unvalidated parser
    /// nobody had chosen to deploy, and the extension/sampling transforms that
    /// `list()` does not select vanished from the published config.
    pub async fn render_to_vector_config(&self) -> Result<(), ParserServiceError> {
        let mut parsers = self.repository().list_effective_deployed().await?;
        crate::parsers::resolve_parser_dispatch_routes(&self.pool, &mut parsers)
            .await
            .map_err(|e| ParserServiceError::DeploymentFailed(e.to_string()))?;
        self.vector_config.render_parsers(&parsers).await?;
        Ok(())
    }

    /// Deploy all enabled parsers to Vector
    ///
    /// NAN-2304: same effective-deployed set as `render_to_vector_config` and
    /// as `LogSourceService`, so boot, enable/disable, and publication all
    /// generate identical config from identical inputs.
    pub async fn deploy_to_vector(&self) -> Result<(), ParserServiceError> {
        let mut parsers = self.repository().list_effective_deployed().await?;
        // NAN-2126: resolve every fetch parser to its source-configuration.
        // Missing/orphaned bindings fail closed before config generation.
        crate::parsers::resolve_parser_dispatch_routes(&self.pool, &mut parsers)
            .await
            .map_err(|e| ParserServiceError::DeploymentFailed(e.to_string()))?;
        self.vector_config.deploy_and_reload(&parsers).await?;
        Ok(())
    }

    /// Deploy a single parser with full validation pipeline
    ///
    /// This method implements a safe deployment process:
    /// 1. Validate VRL syntax first
    /// 2. Stage config and run vector validate
    /// 3. Backup current config, promote staged, reload Vector
    /// 4. Rollback on any failure
    ///
    /// Requirements: 4.1, 4.2, 4.4, 4.7, 4.8, 4.10
    pub async fn deploy_parser(
        &self,
        parser_id: Uuid,
    ) -> Result<DeploymentResult, ParserServiceError> {
        // NAN-2297: one critical section for the whole stage → validate →
        // promote → deploy_and_verify sequence. Previously the lock was only
        // taken inside `deploy_and_verify`, i.e. AFTER this method had already
        // staged and promoted unserialized. `deploy_and_verify_locked` below is
        // the non-locking variant — the public wrapper would deadlock here.
        let _deploy_guard = self.vector_config.lock_deploys().await;

        let parser = self.repository().find_by_id(parser_id).await?;
        // Redact secrets at the source — `config_snapshot` is persisted to
        // `log_source_deployments` and returned by GET /api/log-sources/{id}/deployments
        // (gated only on `log_sources:view`). The on-disk Vector TOML written
        // later in this method still uses real values; only this in-memory
        // snapshot variable is sanitised. NAN-690.
        let config_snapshot =
            redact_config_snapshot(&self.vector_config.generate_parser_config_string(&parser));

        tracing::info!(
            "Starting deployment for parser '{}' ({})",
            parser.name,
            parser_id
        );

        // Step 1: Validate VRL syntax
        let vrl_result = self
            .vrl_validator
            .validate_vrl(&parser.parser_vrl)
            .await
            .map_err(|e| ParserServiceError::VrlValidationFailed(e.to_string()))?;

        if !vrl_result.valid {
            let error_msg = vrl_result
                .error
                .clone()
                .unwrap_or_else(|| "Unknown VRL error".to_string());
            tracing::warn!(
                "VRL validation failed for parser '{}': {}",
                parser.name,
                error_msg
            );

            // Record failed deployment
            let _ = self
                .repository()
                .record_deployment(
                    parser_id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    Some(&config_snapshot),
                )
                .await;

            // Mark parser as failed
            self.repository()
                .mark_deployment_failed(parser_id, &error_msg)
                .await?;

            return Ok(DeploymentResult {
                success: false,
                parser_id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: format!("VRL validation failed: {}", error_msg),
                validation_result: Some(ValidationResult {
                    success: false,
                    errors: vec![error_msg],
                    warnings: vrl_result.warnings,
                    raw_output: String::new(),
                }),
                deployment_id: None,
            });
        }

        tracing::info!("VRL validation passed for parser '{}'", parser.name);

        // Step 2: Stage config and run vector validate
        //
        // NAN-2304: every OTHER parser is staged from its effective deployed
        // definition (active version), never from a working draft it happens to
        // have open in the editor. This parser is the one being deployed, so it
        // is substituted with the working copy validated in step 1 — otherwise
        // this method would validate one VRL and stage a different one.
        let mut all_parsers = self.repository().list_effective_deployed().await?;
        for p in &mut all_parsers {
            if p.id == parser_id {
                *p = parser.clone();
                p.enabled = true;
            }
        }

        // Stamp dispatch_route_name on every parser bound to a source-config.
        crate::parsers::resolve_parser_dispatch_routes(&self.pool, &mut all_parsers)
            .await
            .map_err(|e| ParserServiceError::DeploymentFailed(e.to_string()))?;

        // Stage all enabled parsers including this one
        if let Err(e) = self.vector_config.stage_parsers(&all_parsers).await {
            let error_msg = format!("Failed to stage config: {}", e);
            tracing::error!("{}", error_msg);

            let _ = self
                .repository()
                .record_deployment(
                    parser_id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    Some(&config_snapshot),
                )
                .await;

            return Ok(DeploymentResult {
                success: false,
                parser_id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: error_msg,
                validation_result: None,
                deployment_id: None,
            });
        }

        // Run vector validate on staged config (can be skipped via env var when
        // the api container has no docker CLI to shell into the vector container —
        // see log_sources/service/deployment.rs for the mirror knob). NAN-807
        // bug #15a.
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

                    // Cleanup staging
                    let _ = self.vector_config.cleanup_staging().await;

                    let _ = self
                        .repository()
                        .record_deployment(
                            parser_id,
                            DeploymentAction::Deploy.as_str(),
                            DeploymentStatus::Failed.as_str(),
                            Some(&error_msg),
                            Some(&config_snapshot),
                        )
                        .await;

                    return Ok(DeploymentResult {
                        success: false,
                        parser_id,
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
                "Vector validation failed for parser '{}': {}",
                parser.name,
                error_msg
            );

            // Cleanup staging
            let _ = self.vector_config.cleanup_staging().await;

            let _ = self
                .repository()
                .record_deployment(
                    parser_id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    Some(&config_snapshot),
                )
                .await;

            self.repository()
                .mark_deployment_failed(parser_id, &error_msg)
                .await?;

            return Ok(DeploymentResult {
                success: false,
                parser_id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: format!("Vector validation failed: {}", error_msg),
                validation_result: Some(validate_result),
                deployment_id: None,
            });
        }

        tracing::info!("Vector validation passed for parser '{}'", parser.name);

        // Step 3: Back up the CURRENT config, then promote the staged tree.
        //
        // NAN-2300: the backup must be taken before promotion. It used to happen
        // inside the verify helper, i.e. after promote — so it captured the
        // config that had just been published, and a failed health check
        // "rolled back" to the deployment that was failing. Matches what
        // LogSourceService::deploy has always done.
        let backup = match self.vector_config.backup_current().await {
            Ok(generation) => Some(generation),
            Err(e) => {
            // Not fatal, and must not be. Two reasons it fails: a first deploy
            // with nothing to back up, and (NAN-2301) an active tree that is
            // already incoherent, which the backup gate refuses to record as a
            // rollback target. Aborting on the second would be a trap — that
            // deploy is what prunes the stale file and heals the tree, so
            // refusing to run it would leave the pipeline broken permanently.
                // Loud, because it means this deploy has NO rollback target —
                // and deliberately no fallback to whatever older snapshot is
                // lying around, which would restore an unrelated starting state.
                tracing::warn!(
                    "Failed to back up current config before promoting (may be the first deploy) — \
                     this deploy will not be able to roll back: {}",
                    e
                );
                None
            }
        };

        if let Err(e) = self.vector_config.promote_staged().await {
            let error_msg = format!("Failed to promote staged config: {}", e);
            tracing::error!("{}", error_msg);

            // A promotion that failed partway leaves the active tree mixed:
            // some files replaced, some not, and possibly some pruned. Restore
            // the snapshot taken above — and only that one.
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
                    parser_id,
                    DeploymentAction::Deploy.as_str(),
                    DeploymentStatus::Failed.as_str(),
                    Some(&error_msg),
                    Some(&config_snapshot),
                )
                .await;

            return Ok(DeploymentResult {
                success: false,
                parser_id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: error_msg,
                validation_result: Some(validate_result),
                deployment_id: None,
            });
        }

        // Step 4: Reload and verify. Rolls back to the pre-promotion backup
        // taken in step 3 if Vector does not come up healthy.
        //
        // NAN-2300: this no longer re-writes the config tree. The old helper
        // called `deploy_parsers` again here, rebuilding the active tree from
        // `all_parsers` on top of what promotion had just published from the
        // VALIDATED staging snapshot — a second, unvalidated render of the same
        // thing. Promotion is the publish step; this only signals and verifies.
        //
        // `_locked`: this method already holds the deploy guard (NAN-2297).
        if let Err(failure) = self
            .vector_config
            .reload_and_verify_locked(backup.as_ref())
            .await
        {
            let error_msg = format!("{}", failure);
            tracing::error!("Deploy failed for parser '{}': {}", parser.name, error_msg);

            // Record a rollback only when one actually happened. This used to
            // record `rolled_back` for every error out of this path — including
            // a restore that failed and a first deploy with no backup to
            // restore — so the history claimed a recovery that never ran.
            let (action, status) = if failure.rolled_back {
                (DeploymentAction::Rollback, DeploymentStatus::RolledBack)
            } else {
                (DeploymentAction::Deploy, DeploymentStatus::Failed)
            };
            let _ = self
                .repository()
                .record_deployment(
                    parser_id,
                    action.as_str(),
                    status.as_str(),
                    Some(&error_msg),
                    Some(&config_snapshot),
                )
                .await;

            self.repository()
                .mark_deployment_failed(parser_id, &error_msg)
                .await?;

            return Ok(DeploymentResult {
                success: false,
                parser_id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: error_msg,
                validation_result: Some(validate_result),
                deployment_id: None,
            });
        }

        // Step 6: Update parser status in DB
        self.repository().mark_deployed(parser_id).await?;

        // Record successful deployment
        let deployment = self
            .repository()
            .record_deployment(
                parser_id,
                DeploymentAction::Deploy.as_str(),
                DeploymentStatus::Success.as_str(),
                None,
                Some(&config_snapshot),
            )
            .await?;

        tracing::info!(
            "Successfully deployed parser '{}' ({})",
            parser.name,
            parser_id
        );

        Ok(DeploymentResult {
            success: true,
            parser_id,
            action: DeploymentAction::Deploy.as_str().to_string(),
            message: format!("Parser '{}' deployed successfully", parser.name),
            validation_result: Some(validate_result),
            deployment_id: Some(deployment.id),
        })
    }

    /// Get deployment history for a parser
    pub async fn get_deployment_history(
        &self,
        parser_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ParserDeployment>, ParserServiceError> {
        Ok(self
            .repository()
            .get_deployment_history(parser_id, limit)
            .await?)
    }
}
