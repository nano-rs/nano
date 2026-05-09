// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sync operations for playbook repositories.
//!
//! Uses the Tree API for file listing (playbook markdown files are small,
//! unlike the rule_repository pattern we don't need sparse-checkout).

use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

use crate::playbooks::{parse_playbook, split_frontmatter};
use crate::rule_repository::GitHubClient;

use super::super::error::PlaybookRepositoryError;
use super::super::models::{
    PlaybookRepository, PlaybookSyncResult, PlaybookSyncStatus,
};
use super::super::repository::{
    PlaybookImportsRepository, PlaybookRepoRepository, RepositoryPlaybooksRepository,
};
use super::{PlaybookRepositoryService, PlaybookRepositoryServiceConfig};

impl PlaybookRepositoryService {
    /// Start a background sync (non-blocking).
    pub async fn start_sync(&self, id: Uuid) -> Result<(), PlaybookRepositoryError> {
        // Check if sync is already in progress
        {
            let mut syncing = self.syncing_repos.write().await;
            if syncing.contains(&id) {
                return Err(PlaybookRepositoryError::SyncInProgress(id));
            }
            syncing.insert(id);
        }

        let repo = self.get_repository(id).await?;

        if !repo.enabled.unwrap_or(true) {
            let mut syncing = self.syncing_repos.write().await;
            syncing.remove(&id);
            return Err(PlaybookRepositoryError::RepositoryDisabled);
        }

        let _ = self
            .repo_repository
            .update_sync_status(id, "syncing", None, None, None)
            .await;

        let repo_repository = self.repo_repository.clone();
        let playbooks_repository = self.playbooks_repository.clone();
        let imports_repository = self.imports_repository.clone();
        let github_client = self.github_client.clone();
        let config = self.config.clone();
        let syncing_repos = self.syncing_repos.clone();

        tokio::spawn(async move {
            let result = Self::run_sync(
                id,
                repo,
                repo_repository.clone(),
                playbooks_repository,
                imports_repository,
                github_client,
                config,
            )
            .await;

            match result {
                Ok(sync_result) => {
                    let _ = repo_repository
                        .update_sync_status(
                            id,
                            "success",
                            sync_result.commit.as_deref(),
                            Some(sync_result.playbooks_total),
                            None,
                        )
                        .await;
                    info!(
                        "Playbook sync complete for repo {}: {} added, {} updated, {} removed",
                        id,
                        sync_result.playbooks_added,
                        sync_result.playbooks_updated,
                        sync_result.playbooks_removed
                    );
                }
                Err(e) => {
                    let msg = e.to_string();
                    let _ = repo_repository
                        .update_sync_status(id, "failed", None, None, Some(&msg))
                        .await;
                    warn!("Playbook sync failed for repo {}: {}", id, msg);
                }
            }

            let mut syncing = syncing_repos.write().await;
            syncing.remove(&id);
        });

        Ok(())
    }

    /// Blocking sync — waits for completion. Prefer `start_sync` for API handlers.
    pub async fn sync_repository(
        &self,
        id: Uuid,
    ) -> Result<PlaybookSyncResult, PlaybookRepositoryError> {
        {
            let mut syncing = self.syncing_repos.write().await;
            if syncing.contains(&id) {
                return Err(PlaybookRepositoryError::SyncInProgress(id));
            }
            syncing.insert(id);
        }

        let repo = self.get_repository(id).await?;
        if !repo.enabled.unwrap_or(true) {
            let mut syncing = self.syncing_repos.write().await;
            syncing.remove(&id);
            return Err(PlaybookRepositoryError::RepositoryDisabled);
        }

        let _ = self
            .repo_repository
            .update_sync_status(id, "syncing", None, None, None)
            .await;

        let result = Self::run_sync(
            id,
            repo,
            self.repo_repository.clone(),
            self.playbooks_repository.clone(),
            self.imports_repository.clone(),
            self.github_client.clone(),
            self.config.clone(),
        )
        .await;

        match &result {
            Ok(sync_result) => {
                let _ = self
                    .repo_repository
                    .update_sync_status(
                        id,
                        "success",
                        sync_result.commit.as_deref(),
                        Some(sync_result.playbooks_total),
                        None,
                    )
                    .await;
            }
            Err(e) => {
                let _ = self
                    .repo_repository
                    .update_sync_status(id, "failed", None, None, Some(&e.to_string()))
                    .await;
            }
        }

        {
            let mut syncing = self.syncing_repos.write().await;
            syncing.remove(&id);
        }

        result
    }

    /// Internal sync implementation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn run_sync(
        id: Uuid,
        repo: PlaybookRepository,
        _repo_repository: PlaybookRepoRepository,
        playbooks_repository: RepositoryPlaybooksRepository,
        imports_repository: PlaybookImportsRepository,
        github_client: GitHubClient,
        config: PlaybookRepositoryServiceConfig,
    ) -> Result<PlaybookSyncResult, PlaybookRepositoryError> {
        let start = Instant::now();

        let (owner, repo_name) = GitHubClient::parse_url(&repo.url)
            .map_err(|_| PlaybookRepositoryError::InvalidUrl(repo.url.clone()))?;

        info!(
            "Syncing playbook repository {}/{} ({})",
            owner, repo_name, repo.name
        );

        // Check commit changed
        let commit = github_client
            .get_latest_commit(&owner, &repo_name, &repo.branch)
            .await
            .map_err(|e| PlaybookRepositoryError::GitHubApi(e.to_string()))?;

        if repo.last_sync_commit.as_ref() == Some(&commit) {
            info!("Playbook repo {} is up to date at commit {}", repo.name, commit);
            return Ok(PlaybookSyncResult {
                repository_id: id,
                status: PlaybookSyncStatus::Success,
                commit: Some(commit),
                playbooks_added: 0,
                playbooks_updated: 0,
                playbooks_removed: 0,
                playbooks_total: repo.playbook_count.unwrap_or(0),
                duration_ms: start.elapsed().as_millis() as u64,
                error: None,
            });
        }

        let playbooks_path = repo.playbooks_path.as_deref().unwrap_or("");
        let tree_path = if playbooks_path.is_empty() {
            None
        } else {
            Some(playbooks_path)
        };

        let tree = github_client
            .get_tree(&owner, &repo_name, &repo.branch, tree_path)
            .await
            .map_err(|e| PlaybookRepositoryError::GitHubApi(e.to_string()))?;

        let files: Vec<_> = tree
            .into_iter()
            .filter(|e| {
                if e.entry_type != "blob" {
                    return false;
                }
                // NAN-453 / NAN-456: skip repo docs like README.md /
                // CONTRIBUTING.md / CHANGELOG.md at ANY depth — not just
                // the repo root. Some repos ship a README.md inside each
                // category folder (e.g. identity/README.md) and those
                // aren't playbooks either.
                let filename = e.path.rsplit('/').next().unwrap_or("");
                let is_doc = filename.eq_ignore_ascii_case("README.md")
                    || filename.eq_ignore_ascii_case("CONTRIBUTING.md")
                    || filename.eq_ignore_ascii_case("CHANGELOG.md")
                    || filename.eq_ignore_ascii_case("CODE_OF_CONDUCT.md")
                    || filename.eq_ignore_ascii_case("SECURITY.md")
                    || filename.eq_ignore_ascii_case("LICENSE.md");
                if is_doc {
                    return false;
                }
                config
                    .playbook_extensions
                    .iter()
                    .any(|ext| e.path.ends_with(&format!(".{}", ext)))
            })
            .take(config.max_playbooks_per_repo)
            .collect();

        let mut added = 0i32;
        let mut updated = 0i32;
        let mut synced_paths = Vec::new();

        for entry in &files {
            synced_paths.push(entry.path.clone());

            // Skip unchanged files
            let existing = playbooks_repository.find_by_path(id, &entry.path).await.ok();
            if let Some(ref e) = existing {
                if e.file_sha.as_deref() == Some(entry.sha.as_str()) {
                    continue;
                }
            }

            // Fetch raw content
            let content = match github_client
                .get_raw_file(&owner, &repo_name, &entry.path, &commit)
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    warn!("Failed to fetch {}: {}", entry.path, e);
                    continue;
                }
            };

            // Split frontmatter + parse body
            let (fm, body, parse_status, parse_error, step_count) = match split_frontmatter(&content)
            {
                Ok((fm, body)) => {
                    let tree = parse_playbook(body);
                    let steps: i32 = (tree.phases.iter().map(|p| p.steps.len()).sum::<usize>()
                        + tree.steps.len())
                        as i32;
                    (fm, body.to_string(), "success", None, Some(steps))
                }
                Err(e) => (None, content.clone(), "failed", Some(e.to_string()), None),
            };

            let title = fm.as_ref().and_then(|f| f.title.clone());
            let subtitle = fm.as_ref().and_then(|f| f.subtitle.clone());
            let category = fm.as_ref().and_then(|f| f.category.clone());
            let match_signals = fm.as_ref().map(|f| f.match_signals.clone());
            let tags = fm.as_ref().map(|f| f.tags.clone());
            let owner_team = fm.as_ref().and_then(|f| f.owner.clone());
            let authored_date = fm.as_ref().and_then(|f| f.authored);
            let danger_policy = fm
                .as_ref()
                .map(|f| serde_json::to_value(&f.danger_policy).unwrap_or(serde_json::Value::Null));
            let review_cadence = fm.as_ref().and_then(|f| f.review_cadence.clone());
            let scope = fm.as_ref().and_then(|f| f.scope.clone());

            let _ = body; // currently unused; the full raw_content is stored

            let _ = playbooks_repository
                .upsert(
                    id,
                    &entry.path,
                    Some(&entry.sha),
                    &content,
                    title.as_deref(),
                    subtitle.as_deref(),
                    category.as_deref(),
                    match_signals.as_deref(),
                    tags.as_deref(),
                    owner_team.as_deref(),
                    authored_date,
                    danger_policy.as_ref(),
                    review_cadence.as_deref(),
                    scope.as_deref(),
                    parse_status,
                    parse_error.as_deref(),
                    step_count,
                )
                .await;

            if existing.is_some() {
                updated += 1;
                // Mark imports as having upstream changes
                if let Ok(stored) = playbooks_repository.find_by_path(id, &entry.path).await {
                    let _ = imports_repository.mark_upstream_changed(stored.id).await;
                }
            } else {
                added += 1;
            }
        }

        let removed = playbooks_repository
            .delete_not_in_paths(id, &synced_paths)
            .await
            .unwrap_or(0) as i32;

        let total = synced_paths.len() as i32;

        Ok(PlaybookSyncResult {
            repository_id: id,
            status: PlaybookSyncStatus::Success,
            commit: Some(commit),
            playbooks_added: added,
            playbooks_updated: updated,
            playbooks_removed: removed,
            playbooks_total: total,
            duration_ms: start.elapsed().as_millis() as u64,
            error: None,
        })
    }
}
