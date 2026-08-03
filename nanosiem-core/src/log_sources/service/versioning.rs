// SPDX-License-Identifier: AGPL-3.0-or-later

//! Versioning operations for log sources

use uuid::Uuid;

use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{
    DeploymentResult, LogSource, LogSourceVersion, LogSourceWithDraftStatus, UpdateLogSource,
};

impl LogSourceService {
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

        // NAN-874: when the extension is enabled and non-empty, validate it at the
        // same gate. Otherwise a broken overlay only surfaces at `vector validate`
        // time, after rollback. The deploy-time guard still backs us up, but the
        // user gets clearer feedback here.
        if ls.extension_enabled {
            if let Some(ref ext) = ls.extension_vrl {
                if !ext.trim().is_empty() {
                    let ext_validation = self.validate_vrl(ext).await;
                    if !ext_validation.valid {
                        return Ok(DeploymentResult {
                            success: false,
                            log_source_id: id,
                            action: "publish".to_string(),
                            message: format!(
                                "Extension VRL validation failed: {}",
                                ext_validation.errors.join("; ")
                            ),
                            validation_result: Some(ext_validation),
                            deployment_id: None,
                        });
                    }
                }
            }
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
                ls.extension_vrl.as_deref(),
                ls.extension_enabled,
            )
            .await?;

        // Prune old versions (keep 10)
        let _ = self.version_repository().prune_versions(id, 10).await;

        tracing::info!("Published log source '{}' ({}) as new version", ls.name, id);

        // Deploy — renders the active version just created, via the canonical
        // effective-deployed query shared with publication (NAN-2304).
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
                target.extension_vrl.as_deref(),
                target.extension_enabled,
            )
            .await?;

        // Update working copy to match reverted version
        // Pass empty string for extension_vrl when target had None — the COALESCE
        // pattern in repository::update interprets empty string as "set NULL".
        let extension_vrl_for_update = target.extension_vrl.clone().or_else(|| Some(String::new()));
        self.repository()
            .update(
                log_source_id,
                &UpdateLogSource {
                    parser_vrl: Some(target.parser_vrl),
                    output_fields: target.output_fields,
                    extension_vrl: extension_vrl_for_update,
                    extension_enabled: Some(target.extension_enabled),
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

        // Restore extension state too. None in the snapshot means "no extension on
        // the active version" — use empty string to drive the repository COALESCE
        // pattern that clears the column.
        let extension_vrl_for_update = active.extension_vrl.clone().or_else(|| Some(String::new()));

        let updated = self
            .repository()
            .update(
                id,
                &UpdateLogSource {
                    parser_vrl: Some(active.parser_vrl),
                    output_fields: active.output_fields,
                    extension_vrl: extension_vrl_for_update,
                    extension_enabled: Some(active.extension_enabled),
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
            Some(v) => {
                let parser_changed = ls.parser_vrl != v.parser_vrl;
                let extension_changed = ls.extension_vrl != v.extension_vrl
                    || ls.extension_enabled != v.extension_enabled;
                (
                    parser_changed || extension_changed,
                    Some(v.version_number),
                    Some(v.parser_vrl.clone()),
                )
            }
            // No active version yet — source has never been published.
            // If it has parser VRL or an extension, that's an unpublished draft.
            None => (
                !ls.parser_vrl.is_empty() || ls.extension_vrl.is_some(),
                None,
                None,
            ),
        };

        Ok(LogSourceWithDraftStatus {
            log_source: ls,
            has_draft_changes,
            active_version_number,
            active_parser_vrl,
        })
    }
}
