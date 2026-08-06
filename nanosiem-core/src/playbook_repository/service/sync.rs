// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sync operations for playbook repositories.
//!
//! Uses the Tree API for file listing (playbook markdown files are small,
//! unlike the rule_repository pattern we don't need sparse-checkout).

use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

use crate::playbooks::{
    parse_playbook, split_frontmatter, PlaybookCategory, PlaybookFrontmatter, PlaybookKind,
};
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
                    // NAN-2332: a run that could not write every file is not a
                    // success, and saying otherwise is the bug this change
                    // exists to fix. Persisting "success" here would leave the
                    // repository screen green — it only surfaces
                    // last_sync_error when the status is "failed" — so the
                    // detail threaded into that column would never be read.
                    //
                    // Withholding the commit is the other half. The next sync
                    // takes an early-return fast path when the stored commit
                    // already matches upstream, so recording it after a partial
                    // failure would both clear last_sync_error and skip the
                    // retry, stranding the unwritten file until someone pushed
                    // an unrelated change. Leaving the previous commit in place
                    // makes the next sync try again; files that did land are
                    // skipped cheaply by their own blob SHA.
                    let (status, commit) = match sync_result.error.as_deref() {
                        Some(_) => ("failed", None),
                        None => ("success", sync_result.commit.as_deref()),
                    };
                    let _ = repo_repository
                        .update_sync_status(
                            id,
                            status,
                            commit,
                            Some(sync_result.playbooks_total),
                            sync_result.error.as_deref(),
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
                        // NAN-2332: same reasoning as the background path —
                        // a partial failure persists as "failed" (so the UI
                        // surfaces the reason) and withholds the commit (so
                        // the next sync retries rather than fast-pathing).
                        if sync_result.error.is_some() {
                            "failed"
                        } else {
                            "success"
                        },
                        if sync_result.error.is_some() {
                            None
                        } else {
                            sync_result.commit.as_deref()
                        },
                        Some(sync_result.playbooks_total),
                        sync_result.error.as_deref(),
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
                e.entry_type == "blob"
                    && is_syncable_playbook_file(&e.path, &config.playbook_extensions)
            })
            .take(config.max_playbooks_per_repo)
            .collect();

        let mut added = 0i32;
        let mut updated = 0i32;
        let mut synced_paths = Vec::new();
        let mut kind_refused = 0i32;
        let mut write_failed = 0i32;

        for entry in &files {
            // Presence in `synced_paths` is what protects a cached row from
            // `delete_not_in_paths` below — and deleting one cascades to its
            // `playbook_imports` provenance. So a path is recorded as soon as
            // it is seen in the tree, and only a DELIBERATE refusal removes it:
            // a transient fetch error or an unparseable file must leave the
            // existing catalog row (and its import history) alone.
            synced_paths.push(entry.path.clone());

            // Skip unchanged files
            let existing = playbooks_repository.find_by_path(id, &entry.path).await.ok();
            if let Some(ref e) = existing {
                if e.file_sha.as_deref() == Some(entry.sha.as_str()) {
                    // Re-apply the kind gate to unchanged rows too, using the
                    // kind recorded at their own sync. Narrowing
                    // `allowed_kinds` and re-syncing then actually clears the
                    // catalog of what the repository no longer carries — an
                    // out-of-contract row left behind would still be visible to
                    // browse even though import refuses it.
                    if !repo_accepts_kind(&repo, &e.kind) {
                        drop_from_catalog(&mut synced_paths, &entry.path);
                        kind_refused += 1;
                    }
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

            // The kind comes from the file's own frontmatter — NEVER from the
            // directory it was found in. `playbooks_path` is operator-
            // configurable and a repository can be retargeted at any time, so
            // path inference would silently reclassify a folder of documents
            // into scheduled processes with no diff to review.
            let kind = catalog_kind(fm.as_ref());

            if !repo_accepts_kind(&repo, kind.as_str()) {
                // Not catalogued at all: the repository has declared it does
                // not carry this kind, so the file is outside its contract.
                // Leaving it browsable-but-unimportable would only invite the
                // question of why it cannot be imported.
                drop_from_catalog(&mut synced_paths, &entry.path);
                kind_refused += 1;
                continue;
            }

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

            let (category, parse_status, parse_error) =
                resolve_category(category, parse_status, parse_error);

            let upserted = playbooks_repository
                .upsert(
                    id,
                    &entry.path,
                    Some(&entry.sha),
                    &content,
                    kind.as_str(),
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

            // NAN-2332: never count a write that did not happen. This used to
            // be `let _ = upsert(...)` followed by an unconditional increment,
            // so a failed write was reported to the operator as an added or
            // updated playbook — success reported for a row that never landed.
            if let Err(e) = upserted {
                warn!("Failed to catalog playbook {}: {}", entry.path, e);
                write_failed += 1;
                // The path stays in `synced_paths` deliberately: a transient
                // write error must not delete the existing catalog row and
                // cascade away its import provenance (see the note above).
                continue;
            }

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

        if kind_refused > 0 {
            info!(
                "Playbook repo {} declares allowed_kinds={:?}; {} file(s) of another kind were \
                 not catalogued",
                repo.name, repo.allowed_kinds, kind_refused
            );
        }

        // NAN-2332: surface write failures to the OPERATOR, not just to the
        // server log. A warning in the log is invisible to whoever is looking
        // at the repository in the product, and "the sync said success" is the
        // whole bug this change exists to fix — reporting it only somewhere
        // they will not look reproduces it one layer up.
        let error = if write_failed > 0 {
            warn!(
                "Playbook repo {}: {} file(s) failed to write to the catalog and were not \
                 counted as added or updated; see the per-file warnings above",
                repo.name, write_failed
            );
            Some(format!(
                "{write_failed} playbook(s) could not be written to the catalog and are \
                 missing or stale; see the server log for the affected files"
            ))
        } else {
            None
        };

        Ok(PlaybookSyncResult {
            repository_id: id,
            // Mirrors what gets persisted: a run with unwritten files reports
            // Failed, so an API caller reading this struct and an operator
            // reading the repository row are told the same thing.
            status: if error.is_some() {
                PlaybookSyncStatus::Failed
            } else {
                PlaybookSyncStatus::Success
            },
            commit: Some(commit),
            playbooks_added: added,
            playbooks_updated: updated,
            playbooks_removed: removed,
            // Failed writes stay in `synced_paths` on purpose (it is what keeps
            // `delete_not_in_paths` from dropping the existing row), but they
            // are NOT in the catalog, so they must not inflate the count that
            // is persisted as the repository's playbook_count.
            playbooks_total: total - write_failed,
            duration_ms: start.elapsed().as_millis() as u64,
            error,
        })
    }
}

/// Repository documentation that is never a playbook, at ANY depth.
///
/// NAN-453 / NAN-456 established the list for repo-root docs; the depth matters
/// because some repos ship a README.md inside each category folder. NAN-2238
/// makes it load-bearing rather than cosmetic: `hunts/README.md` documents the
/// hunt authoring contract, and a naive `*.md` walk would hand that
/// documentation to the hunt parser and either fail it noisily or — worse, if
/// the doc ever gained a fenced frontmatter example — catalog prose as a
/// definition. The existing category folders have no READMEs, so this case has
/// simply never arisen before.
fn is_repo_documentation(path: &str) -> bool {
    const DOC_FILENAMES: &[&str] = &[
        "README.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "SECURITY.md",
        "LICENSE.md",
    ];
    let filename = path.rsplit('/').next().unwrap_or("");
    DOC_FILENAMES
        .iter()
        .any(|doc| filename.eq_ignore_ascii_case(doc))
}

/// Whether a repository tree entry should be pulled into the catalog at all.
pub(crate) fn is_syncable_playbook_file(path: &str, extensions: &[String]) -> bool {
    !is_repo_documentation(path)
        && extensions
            .iter()
            .any(|ext| path.ends_with(&format!(".{}", ext)))
}

/// Withdraw a path from the keep-list, so the prune at the end of the sync
/// removes its cached row.
///
/// Deliberately a removal from a list everything starts in, rather than an
/// addition to one everything must earn its way into: the failure modes are not
/// symmetric. Forgetting to add a path silently deletes a catalog row and
/// cascades its import provenance; forgetting to remove one leaves a row that
/// import refuses anyway.
fn drop_from_catalog(synced_paths: &mut Vec<String>, path: &str) {
    synced_paths.retain(|p| p != path);
}

/// Whether this repository is permitted to produce rows of `kind`.
///
/// A repository row that predates migration 9000057 deserializes with both
/// kinds (the column default), so this cannot fail closed on old data — but an
/// empty list would, which is why the column is `NOT NULL` with a
/// `cardinality > 0` CHECK rather than nullable.
pub(crate) fn repo_accepts_kind(repo: &PlaybookRepository, kind: &str) -> bool {
    repo.allowed_kinds.iter().any(|k| k == kind)
}

/// Pull the metadata the catalog stores out of a parsed file.
///
/// Shared by the GitHub sync and the air-gapped bundle sync so the two cannot
/// disagree about what a file is — in particular about its `kind`, which
/// decides whether importing it creates a document or a scheduled process.
pub(crate) fn catalog_kind(fm: Option<&PlaybookFrontmatter>) -> PlaybookKind {
    fm.map(|f| f.kind).unwrap_or(PlaybookKind::Response)
}

/// Resolve the catalog `category` column and the row's parse verdict together.
///
/// NAN-2332. `category` is free-form in frontmatter (`Option<String>`) but the
/// catalog column is CHECK-constrained to the six documented values, so an
/// unrecognised category fails the INSERT outright. Nulling the column and
/// downgrading the row keeps the playbook in the catalog — browsable, and
/// visibly broken with a reason — instead of letting the write fail.
///
/// Letting it fail is strictly worse than it first appears. The statement is
/// `ON CONFLICT … DO UPDATE`, so a failed write leaves the previous row intact:
/// editing an ALREADY-SYNCED playbook into a bad category would silently keep
/// serving its old content, which is harder to diagnose than an absent one.
///
/// An existing parse failure is never masked. `fm` is `None` whenever the
/// frontmatter split failed, so `category` is `None` on that path and the
/// incoming status and error pass through untouched.
pub(crate) fn resolve_category<'a>(
    category: Option<String>,
    parse_status: &'a str,
    parse_error: Option<String>,
) -> (Option<String>, &'a str, Option<String>) {
    match category {
        // Canonicalize to the enum's own lowercase spelling. `parse` folds
        // case, but the CHECK constraint does NOT — it is a literal
        // `IN ('identity', …)`. Writing the author's original casing back
        // would let `category: Identity` parse as valid here and still fail
        // the constraint, which is precisely the silent failure this function
        // exists to prevent.
        Some(ref value) => match PlaybookCategory::parse(value) {
            Some(known) => (
                Some(known.as_str().to_string()),
                parse_status,
                parse_error,
            ),
            None => (
                None,
                "failed",
                Some(format!(
                    "unknown category `{value}` — expected one of: \
                     identity, endpoint, cloud, data, network, email"
                )),
            ),
        },
        None => (None, parse_status, parse_error),
    }
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;
