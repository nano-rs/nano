// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deployment operations for log sources

use sqlx;
use uuid::Uuid;

use super::helpers::log_source_to_parser;
use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    DeploymentAction, DeploymentResult, DeploymentStatus, LogSourceDeployment, VrlValidationResult,
};
use crate::parsers::Parser;

impl LogSourceService {
    /// Deploy a log source to Vector
    pub async fn deploy(&self, id: Uuid) -> Result<DeploymentResult, LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;

        tracing::info!(
            "Starting deployment for log source '{}' ({})",
            log_source.name,
            id
        );

        // Step 1: Validate VRL syntax
        let vrl_result = self
            .vrl_validator
            .validate_vrl(&log_source.parser_vrl)
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

        let all_log_sources = self.list_enabled_for_deploy().await?;

        // Inject credentials for cloud sources
        let log_sources_with_creds = self.inject_credentials_for_all(&all_log_sources).await?;

        // Convert LogSource to Parser for VectorConfigManager compatibility
        let mut parsers: Vec<Parser> = log_sources_with_creds
            .into_iter()
            .map(log_source_to_parser)
            .collect();
        // NAN-928: resolve dispatch source-config route names so the
        // generator wires fetch-source parsers to the user's source-config
        // route instead of creating a parser-owned Vector source.
        self.resolve_dispatch_route_names(&mut parsers).await?;

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

        // Step 3: Backup, promote, and reload
        let _ = self.vector_config.backup_current().await;

        if let Err(e) = self.vector_config.promote_staged().await {
            let error_msg = format!("Failed to promote staged config: {}", e);
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

        // Reload Vector
        if let Err(e) = self.vector_config.reload_vector().await {
            tracing::error!("Vector reload failed, attempting rollback: {}", e);

            if let Err(rollback_err) = self.vector_config.restore_backup().await {
                let error_msg = format!(
                    "Reload failed and rollback also failed: {} / {}",
                    e, rollback_err
                );
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

                return Err(LogSourceServiceError::RollbackFailed(error_msg));
            }

            let _ = self.vector_config.reload_vector().await;

            let _ = self
                .repository()
                .record_deployment(
                    id,
                    DeploymentAction::Rollback.as_str(),
                    DeploymentStatus::RolledBack.as_str(),
                    Some(&format!("Rolled back due to reload failure: {}", e)),
                    None,
                )
                .await;

            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: DeploymentAction::Deploy.as_str().to_string(),
                message: format!("Reload failed, rolled back: {}", e),
                validation_result: None,
                deployment_id: None,
            });
        }

        // Success!
        self.repository().mark_deployed(id).await?;

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
        let enabled = self.list_enabled_for_deploy().await?;
        let with_creds = self.inject_credentials_for_all(&enabled).await?;
        let mut parsers: Vec<Parser> =
            with_creds.into_iter().map(log_source_to_parser).collect();
        self.resolve_dispatch_route_names(&mut parsers).await?;

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
        let enabled = self.list_enabled_for_deploy().await?;
        let with_creds = self.inject_credentials_for_all(&enabled).await?;
        let mut parsers: Vec<Parser> =
            with_creds.into_iter().map(log_source_to_parser).collect();
        self.resolve_dispatch_route_names(&mut parsers).await?;

        self.vector_config.deploy_and_reload(&parsers).await?;

        // Mark all as deployed
        for ls in self.repository().list_enabled().await? {
            let _ = self.repository().mark_deployed(ls.id).await;
        }

        Ok(())
    }

    /// Get deployment history for a log source
    pub async fn get_deployment_history(
        &self,
        id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<LogSourceDeployment>, LogSourceServiceError> {
        Ok(self
            .repository()
            .get_deployment_history(id, limit.unwrap_or(50))
            .await?)
    }
}
