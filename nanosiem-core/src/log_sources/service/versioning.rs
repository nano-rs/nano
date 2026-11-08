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
    ///
    /// `expected_updated_at` (NAN-4919 release review): when given, the
    /// working copy must still be the one the caller reviewed. The version is
    /// created from the row read here, so what is published is exactly what
    /// was reviewed, or nothing (409).
    pub async fn publish(
        &self,
        id: Uuid,
        user_id: Option<Uuid>,
        expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<DeploymentResult, LogSourceServiceError> {
        let ls = self.repository().find_by_id(id).await?;
        ensure_unchanged(id, ls.updated_at, expected_updated_at)?;

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

        // NAN-4919: a valid Nano Pipe plan may still use a step the
        // deployment's Vector image cannot run (Combine needs reduce + lua).
        // Refuse here, before a version is created, rather than at deploy.
        if let Ok(Some(plan)) = crate::parsers::pipe::stored_plan(&ls.parser_vrl) {
            if let Err(message) = crate::parsers::pipe::native::deployable(&plan) {
                return Ok(DeploymentResult {
                    success: false,
                    log_source_id: id,
                    action: "publish".to_string(),
                    message,
                    validation_result: Some(validation),
                    deployment_id: None,
                });
            }
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

        // Create the active version from the working copy AT THE REVISION
        // VALIDATED ABOVE, under the source row lock (NAN-4919): a save that
        // landed during validation makes this a 409, never a stale publish.
        if self
            .version_repository()
            .publish_revision(id, ls.updated_at, user_id)
            .await?
            .is_none()
        {
            return Err(LogSourceServiceError::RepositoryError(
                crate::log_sources::LogSourceRepositoryError::StaleVersion(id),
            ));
        }

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

    /// Discard draft: reset working copy to the active version's VRL.
    /// `expected_updated_at` (NAN-4919): refuse (409) when the draft changed
    /// since the caller looked at it; the reset itself is a CAS update.
    pub async fn discard_draft(
        &self,
        id: Uuid,
        expected_updated_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<LogSource, LogSourceServiceError> {
        // One transaction (NAN-4919): row lock, revision check, active-version
        // read and the reset, so a concurrent publish cannot slip between them.
        match self
            .version_repository()
            .discard_to_active(id, expected_updated_at)
            .await?
        {
            crate::log_sources::DiscardOutcome::Discarded => {}
            crate::log_sources::DiscardOutcome::Stale => {
                return Err(LogSourceServiceError::RepositoryError(
                    crate::log_sources::LogSourceRepositoryError::StaleVersion(id),
                ))
            }
            crate::log_sources::DiscardOutcome::NoActiveVersion => {
                return Err(LogSourceServiceError::DeploymentFailed(
                    "No active version to discard to".to_string(),
                ))
            }
        }
        tracing::info!("Discarded draft for log source {}", id);
        Ok(self.repository().find_by_id(id).await?)
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

/// Refuse when a caller-observed `updated_at` no longer matches the row.
fn ensure_unchanged(
    id: Uuid,
    actual: chrono::DateTime<chrono::Utc>,
    expected: Option<chrono::DateTime<chrono::Utc>>,
) -> Result<(), LogSourceServiceError> {
    match expected {
        Some(expected) if expected != actual => Err(LogSourceServiceError::RepositoryError(
            crate::log_sources::LogSourceRepositoryError::StaleVersion(id),
        )),
        _ => Ok(()),
    }
}
