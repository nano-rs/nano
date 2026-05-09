// SPDX-License-Identifier: AGPL-3.0-or-later

//! Versioning operations for log sources

use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    DeploymentResult, LogSource, LogSourceVersion, LogSourceWithDraftStatus, UpdateLogSource,
};

impl LogSourceService {
    /// Get enabled log sources with active version VRL for deployment.
    /// Uses active version parser_vrl instead of working copy.
    /// Falls back to working copy for log sources with no versions (backwards compat).
    pub(super) async fn list_enabled_for_deploy(
        &self,
    ) -> Result<Vec<LogSource>, LogSourceServiceError> {
        let all = self.repository().list_enabled().await?;
        let mut result = Vec::with_capacity(all.len());
        for mut ls in all {
            if let Ok(Some(active)) = self.version_repository().get_active_version(ls.id).await {
                ls.parser_vrl = active.parser_vrl;
                if let Some(fields) = active.output_fields {
                    ls.output_fields = Some(fields);
                }
            }
            result.push(ls);
        }
        Ok(result)
    }

    /// Publish the current working copy as a new active version, then deploy.
    pub async fn publish(
        &self,
        id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<DeploymentResult, LogSourceServiceError> {
        let ls = self.repository().find_by_id(id).await?;

        // Validate working copy VRL
        let validation = self.validate_vrl(&ls.parser_vrl).await;
        if !validation.valid {
            return Ok(DeploymentResult {
                success: false,
                log_source_id: id,
                action: "publish".to_string(),
                message: format!("VRL validation failed: {}", validation.errors.join("; ")),
                validation_result: Some(validation),
                deployment_id: None,
            });
        }

        // Create new active version from working copy
        self.version_repository()
            .create_version(
                id,
                &ls.parser_vrl,
                ls.output_fields.as_ref(),
                true,
                user_id,
                "publish",
                None,
            )
            .await?;

        // Prune old versions (keep 10)
        let _ = self.version_repository().prune_versions(id, 10).await;

        tracing::info!("Published log source '{}' ({}) as new version", ls.name, id);

        // Deploy (now uses active version via list_enabled_for_deploy)
        self.deploy(id).await
    }

    /// Revert to a previous version: creates a NEW version copying the target, then updates working copy.
    pub async fn revert_to_version(
        &self,
        log_source_id: Uuid,
        version_id: i32,
        user_id: Option<Uuid>,
    ) -> Result<LogSourceVersion, LogSourceServiceError> {
        let target = self.version_repository().get_version(version_id).await?;

        if target.log_source_id != log_source_id {
            return Err(LogSourceServiceError::DeploymentFailed(
                "Version does not belong to this log source".to_string(),
            ));
        }

        // Create a NEW active version copying the target
        let new_version = self
            .version_repository()
            .create_version(
                log_source_id,
                &target.parser_vrl,
                target.output_fields.as_ref(),
                true,
                user_id,
                "revert",
                Some(target.version_number),
            )
            .await?;

        // Update working copy to match reverted version
        self.repository()
            .update(
                log_source_id,
                &UpdateLogSource {
                    parser_vrl: Some(target.parser_vrl),
                    output_fields: target.output_fields,
                    ..Default::default()
                },
            )
            .await?;

        // Prune old versions
        let _ = self
            .version_repository()
            .prune_versions(log_source_id, 10)
            .await;

        tracing::info!(
            "Reverted log source {} to version {} (created new version {})",
            log_source_id,
            target.version_number,
            new_version.version_number
        );

        Ok(new_version)
    }

    /// Discard draft: reset working copy to the active version's VRL
    pub async fn discard_draft(&self, id: Uuid) -> Result<LogSource, LogSourceServiceError> {
        let active = self
            .version_repository()
            .get_active_version(id)
            .await?
            .ok_or_else(|| {
                LogSourceServiceError::DeploymentFailed(
                    "No active version to discard to".to_string(),
                )
            })?;

        let updated = self
            .repository()
            .update(
                id,
                &UpdateLogSource {
                    parser_vrl: Some(active.parser_vrl),
                    output_fields: active.output_fields,
                    ..Default::default()
                },
            )
            .await?;

        tracing::info!("Discarded draft for log source {}", id);
        Ok(updated)
    }

    /// Get version history for a log source
    pub async fn get_versions(
        &self,
        id: Uuid,
        limit: Option<i32>,
    ) -> Result<Vec<LogSourceVersion>, LogSourceServiceError> {
        Ok(self
            .version_repository()
            .get_version_history(id, limit.unwrap_or(50))
            .await?)
    }

    /// Get draft status: whether working copy differs from active version
    pub async fn get_draft_status(
        &self,
        id: Uuid,
    ) -> Result<LogSourceWithDraftStatus, LogSourceServiceError> {
        let ls = self.repository().find_by_id(id).await?;
        let active = self.version_repository().get_active_version(id).await?;

        let (has_draft_changes, active_version_number, active_parser_vrl) = match &active {
            Some(v) => (
                ls.parser_vrl != v.parser_vrl,
                Some(v.version_number),
                Some(v.parser_vrl.clone()),
            ),
            // No active version yet — source has never been published.
            // If it has parser VRL, that's an unpublished draft.
            None => (!ls.parser_vrl.is_empty(), None, None),
        };

        Ok(LogSourceWithDraftStatus {
            log_source: ls,
            has_draft_changes,
            active_version_number,
            active_parser_vrl,
        })
    }
}
