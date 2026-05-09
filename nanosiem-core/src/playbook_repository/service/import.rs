// SPDX-License-Identifier: AGPL-3.0-or-later

//! Import repository playbooks into the main `playbooks` table.

use tracing::info;
use uuid::Uuid;

use crate::playbooks::models::{
    CreatePlaybookRequest, PlaybookCategory, PlaybookScope, PlaybookStatus,
};
use crate::playbooks::PlaybookService;

use super::super::error::PlaybookRepositoryError;
use super::super::models::{PlaybookImportRequest, PlaybookImportResponse, PlaybookImportType};
use super::PlaybookRepositoryService;

impl PlaybookRepositoryService {
    /// Import a repository playbook into the main library.
    pub async fn import_playbook(
        &self,
        repo_id: Uuid,
        path: &str,
        req: PlaybookImportRequest,
        user_id: Option<Uuid>,
    ) -> Result<PlaybookImportResponse, PlaybookRepositoryError> {
        let repo = self.get_repository(repo_id).await?;
        let repo_playbook = self.get_repository_playbook(repo_id, path).await?;

        // Check if already imported
        let existing = self
            .imports_repository
            .find_by_repository_playbook(repo_playbook.id)
            .await
            .map_err(PlaybookRepositoryError::from_repo_error)?;
        if !existing.is_empty() {
            return Err(PlaybookRepositoryError::AlreadyImported {
                import_type: existing[0].import_type.clone(),
            });
        }

        // Build the CreatePlaybookRequest from the cached playbook metadata + content
        let category = repo_playbook
            .category
            .as_deref()
            .and_then(PlaybookCategory::parse)
            .unwrap_or(PlaybookCategory::Identity);
        let scope = repo_playbook
            .scope
            .as_deref()
            .and_then(PlaybookScope::parse)
            .unwrap_or(PlaybookScope::Tenant);

        let danger_policy: Option<std::collections::HashMap<String, String>> = repo_playbook
            .danger_policy
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());

        let title = repo_playbook
            .title
            .clone()
            .unwrap_or_else(|| path.rsplit('/').next().unwrap_or(path).to_string());

        let source_linked = matches!(req.import_type, PlaybookImportType::Linked);

        let create = CreatePlaybookRequest {
            title,
            subtitle: repo_playbook.subtitle.clone(),
            category,
            doc: repo_playbook.raw_content.clone(),
            match_signals: repo_playbook.match_signals.clone().unwrap_or_default(),
            danger_policy,
            review_cadence: repo_playbook.review_cadence.clone(),
            scope: Some(scope),
            tags: repo_playbook.tags.clone().unwrap_or_default(),
            owner_team: req.owner_team.or(repo_playbook.owner_team.clone()),
            status: Some(PlaybookStatus::Draft),
            adaptive: Some(false),
            adaptive_source: None,
            source_playbook_path: Some(path.to_string()),
            source_repository_id: Some(repo_id),
            source_linked: Some(source_linked),
        };

        let service = PlaybookService::new(self.pg_pool.clone());
        let playbook = service
            .create(create, user_id)
            .await
            .map_err(|e| PlaybookRepositoryError::Internal(e.to_string()))?;

        // Record the import
        self.imports_repository
            .create(
                repo_playbook.id,
                playbook.id,
                &req.import_type.to_string(),
                user_id,
                repo.last_sync_commit.as_deref(),
            )
            .await
            .map_err(|e| match e {
                super::super::repository::PlaybookImportsRepositoryError::AlreadyExists => {
                    PlaybookRepositoryError::AlreadyImported {
                        import_type: req.import_type.to_string(),
                    }
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })?;

        info!(
            "Imported playbook {} from {}/{} as {}",
            playbook.id, repo.name, path, req.import_type
        );

        Ok(PlaybookImportResponse {
            playbook_id: playbook.id,
            import_type: req.import_type.to_string(),
        })
    }
}
