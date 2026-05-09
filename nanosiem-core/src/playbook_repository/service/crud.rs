// SPDX-License-Identifier: AGPL-3.0-or-later

//! Repository CRUD operations for playbook repositories.

use tracing::warn;
use uuid::Uuid;

use crate::rule_repository::GitHubClient;

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
        self.repo_repository
            .list()
            .await
            .map_err(PlaybookRepositoryError::from_repo_error)
    }

    pub async fn get_repository(
        &self,
        id: Uuid,
    ) -> Result<PlaybookRepository, PlaybookRepositoryError> {
        self.repo_repository
            .find_by_id(id)
            .await
            .map_err(|e| match e {
                super::super::repository::PlaybookRepoRepositoryError::NotFound(_) => {
                    PlaybookRepositoryError::RepositoryNotFound(id)
                }
                other => PlaybookRepositoryError::from_repo_error(other),
            })
    }

    pub async fn create_repository(
        &self,
        req: NewPlaybookRepository,
        user_id: Option<Uuid>,
    ) -> Result<PlaybookRepository, PlaybookRepositoryError> {
        let (owner, repo_name) = GitHubClient::parse_url(&req.url)
            .map_err(|_| PlaybookRepositoryError::InvalidUrl(req.url.clone()))?;

        let key = format!("{}/{}", owner.to_lowercase(), repo_name.to_lowercase());
        if !Self::allowed_repos().contains(&key.as_str()) {
            warn!("Attempted to add non-allowlisted playbook repository: {}", key);
            return Err(PlaybookRepositoryError::RepositoryNotAllowed(key));
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
