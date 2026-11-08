// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository CRUD operations for playbook repositories.

use tracing::warn;
use uuid::Uuid;


use super::super::error::PlaybookRepositoryError;
use super::super::models::{
    NewPlaybookRepository, PlaybookRepository, RepositoryPlaybook, RepositoryPlaybookFilter,
    UpdatePlaybookRepository,
};
use super::PlaybookRepositoryService;

impl PlaybookRepositoryService {
    pub async fn list_repositories(
        &self,
    ) -> Result<Vec<PlaybookRepository>, PlaybookRepositoryError> {
        // NAN-4947: third-party rows (disabled on upgrade) are hidden.
        Ok(self
            .repo_repository
            .list()
            .await
            .map_err(PlaybookRepositoryError::from_repo_error)?
            .into_iter()
            .filter(|r| Self::first_party(&r.url))
            .collect())
    }

    pub async fn get_repository(
        &self,
        id: Uuid,
    ) -> Result<PlaybookRepository, PlaybookRepositoryError> {
        let repo = self
            .repo_repository
            .find_by_id(id)
            .await
            .map_err(|e| match e {
                super::super::repository::PlaybookRepoRepositoryError::NotFound(_) => {
                    PlaybookRepositoryError::RepositoryNotFound(id)
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })?;
        // NAN-4947: the chokepoint for sync, browse and import.
        if !Self::first_party(&repo.url) {
            return Err(PlaybookRepositoryError::RepositoryNotAllowed(repo.url));
        }
        Ok(repo)
    }

    pub async fn create_repository(
        &self,
        req: NewPlaybookRepository,
        user_id: Option<Uuid>,
    ) -> Result<PlaybookRepository, PlaybookRepositoryError> {
        // NAN-4947: the same parser and allowlist as every other path, stored
        // in the canonical spelling the sync parses back.
        if !Self::first_party(&req.url) {
            warn!("Attempted to add non-allowlisted playbook repository: {}", req.url);
            return Err(PlaybookRepositoryError::RepositoryNotAllowed(req.url));
        }
        let mut req = req;
        if let Some(canonical) = crate::schema::canonical_github_url(&req.url) {
            req.url = canonical;
        }

        self.repo_repository
            .create(&req, user_id)
            .await
            .map_err(|e| match e {
                super::super::repository::PlaybookRepoRepositoryError::AlreadyExists(name) => {
                    PlaybookRepositoryError::RepositoryAlreadyExists(name)
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })
    }

    pub async fn update_repository(
        &self,
        id: Uuid,
        req: UpdatePlaybookRepository,
    ) -> Result<PlaybookRepository, PlaybookRepositoryError> {
        // NAN-4947: a disabled third-party row can never be re-enabled.
        self.get_repository(id).await?;
        self.repo_repository
            .update(id, &req)
            .await
            .map_err(|e| match e {
                super::super::repository::PlaybookRepoRepositoryError::NotFound(_) => {
                    PlaybookRepositoryError::RepositoryNotFound(id)
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })
    }

    pub async fn delete_repository(&self, id: Uuid) -> Result<(), PlaybookRepositoryError> {
        self.repo_repository
            .delete(id)
            .await
            .map_err(|e| match e {
                super::super::repository::PlaybookRepoRepositoryError::NotFound(_) => {
                    PlaybookRepositoryError::RepositoryNotFound(id)
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })
    }

    pub async fn list_repository_playbooks(
        &self,
        id: Uuid,
        filter: &RepositoryPlaybookFilter,
    ) -> Result<Vec<RepositoryPlaybook>, PlaybookRepositoryError> {
        // Verify repo exists so we return a clean 404.
        let _ = self.get_repository(id).await?;
        self.playbooks_repository
            .list(id, filter)
            .await
            .map_err(PlaybookRepositoryError::from_repo_error)
    }

    pub async fn get_repository_playbook(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<RepositoryPlaybook, PlaybookRepositoryError> {
        self.get_repository(repo_id).await?;
        self.playbooks_repository
            .find_by_path(repo_id, path)
            .await
            .map_err(|e| match e {
                super::super::repository::RepositoryPlaybooksRepositoryError::NotFound(_) => {
                    PlaybookRepositoryError::PlaybookNotFound {
                        repo_id,
                        path: path.to_string(),
                    }
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })
    }
}
