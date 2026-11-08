// SPDX-License-Identifier: AGPL-3.0-or-later

//! Sync operations for playbook repositories.
//!
//! Uses the Tree API for file listing (playbook markdown files are small,
//! unlike the rule_repository pattern we don't need sparse-checkout).
//!
//! NAN-4947: a sync runs in two phases.
//!
//! 1. **Stage** (no writes): resolve the upstream commit, list the tree,
//!    compare blob SHAs against the cached rows, fetch and parse only the
//!    changed files. This is the slow, network-bound part.
//! 2. **Apply** (one transaction): check the leader fence, then upsert the
//!    changed rows, mark imports whose source changed, prune rows no longer
//!    upstream and record the sync status. Nothing commits unless the fence
//!    holds at that moment, and the fence lock is never held across the
//!    network phase. A leader that was paused mid-sync and evicted therefore
//!    cannot prune rows (and cascade away `playbook_imports` provenance) that
//!    the new leader catalogued meanwhile.
//!
//! A row that fails to write aborts the whole apply: the previous catalog and
//! commit stay in place, the repository is marked failed with the reason, and
//! the next sync retries (NAN-2332: never report success for a write that did
//! not happen).

use std::time::Instant;
use tracing::{info, warn};
use uuid::Uuid;

use crate::playbooks::{
    parse_playbook, split_frontmatter, PlaybookCategory, PlaybookFrontmatter, PlaybookKind,
};
use crate::rule_repository::GitHubClient;

use super::super::error::PlaybookRepositoryError;
use super::super::models::{PlaybookRepository, PlaybookSyncResult, PlaybookSyncStatus};
use super::super::repository::{RepositoryPlaybooksRepository};
use super::{PlaybookRepositoryService, PlaybookRepositoryServiceConfig};

/// One changed file, fetched and parsed, ready to write.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct StagedRow {
    pub path: String,
    pub sha: String,
    pub content: String,
    pub kind: String,
    pub title: Option<String>,
    pub subtitle: Option<String>,
    pub category: Option<String>,
    pub match_signals: Option<Vec<String>>,
    pub tags: Option<Vec<String>>,
    pub owner_team: Option<String>,
    pub authored_date: Option<chrono::NaiveDate>,
    pub danger_policy: Option<serde_json::Value>,
    pub review_cadence: Option<String>,
    pub scope: Option<String>,
    pub parse_status: &'static str,
    pub parse_error: Option<String>,
    pub step_count: Option<i32>,
    /// A cached row already exists (an update, so imports are marked).
    pub existing: bool,
}

/// Everything the network phase learned; applied in one fenced transaction.
#[derive(Debug, Clone)]
#[doc(hidden)]
pub enum StagedSync {
    /// The stored commit is already upstream: only the status is recorded.
    UpToDate { commit: String, total: i32 },
    Changed {
        commit: String,
        rows: Vec<StagedRow>,
        /// Paths that stay catalogued (everything else is pruned).
        keep: Vec<String>,
    },
}

impl PlaybookRepositoryService {
    /// Record a sync status under the leader fence. Returns `Fenced` (and
    /// writes nothing) when this process no longer leads.
    async fn write_status_fenced(
        &self,
        id: Uuid,
        status: &str,
        error: Option<&str>,
    ) -> Result<(), PlaybookRepositoryError> {
        let mut tx = self.pg_pool.begin().await.map_err(db_err)?;
        self.fence.guard(&mut tx).await.map_err(|e| PlaybookRepositoryError::Fenced(e.to_string()))?;
        crate::db::repo_store::update_sync_status(
            &mut *tx, "playbook_repositories", "playbook_count", id, status, None, None, error,
        )
        .await
        .map_err(|e| PlaybookRepositoryError::Internal(e.to_string()))?;
        tx.commit().await.map_err(db_err)?;
        Ok(())
    }

    /// Record a failed sync (e.g. a scheduler timeout) under the leader fence.
    pub async fn record_sync_failure(&self, id: Uuid, message: &str) -> Result<(), PlaybookRepositoryError> {
        self.write_status_fenced(id, "failed", Some(message)).await
    }

    /// Claim the per-service in-progress slot and load an enabled repository.
    async fn begin_sync(&self, id: Uuid) -> Result<PlaybookRepository, PlaybookRepositoryError> {
        {
            let mut syncing = self.syncing_repos.write().await;
            if syncing.contains(&id) {
                return Err(PlaybookRepositoryError::SyncInProgress(id));
            }
            syncing.insert(id);
        }
        let loaded = match self.get_repository(id).await {
            Ok(repo) if !repo.enabled.unwrap_or(true) => Err(PlaybookRepositoryError::RepositoryDisabled),
            other => other,
        };
        let loaded = match loaded {
            Ok(repo) => self.write_status_fenced(id, "syncing", None).await.map(|()| repo),
            Err(e) => Err(e),
        };
        if loaded.is_err() {
            self.syncing_repos.write().await.remove(&id);
        }
        loaded
    }

    /// Run a claimed sync to completion and record a failure (unless fenced).
    async fn finish_sync(
        self,
        id: Uuid,
        repo: PlaybookRepository,
    ) -> Result<PlaybookSyncResult, PlaybookRepositoryError> {
        let result = self.run_sync(id, repo).await;
        match &result {
            Ok(sync) => info!(
                "Playbook sync complete for repo {}: {} added, {} updated, {} removed",
                id, sync.playbooks_added, sync.playbooks_updated, sync.playbooks_removed
            ),
            Err(PlaybookRepositoryError::Fenced(reason)) => {
                warn!("Playbook sync for repo {} abandoned: {}", id, reason)
            }
            Err(e) => {
                let msg = e.to_string();
                warn!("Playbook sync failed for repo {}: {}", id, msg);
                if let Err(err) = self.write_status_fenced(id, "failed", Some(&msg)).await {
                    warn!("Could not record the failed sync for repo {}: {}", id, err);
                }
            }
        }
        self.syncing_repos.write().await.remove(&id);
        result
    }

    /// Start a background sync (non-blocking).
    pub async fn start_sync(&self, id: Uuid) -> Result<(), PlaybookRepositoryError> {
        let repo = self.begin_sync(id).await?;
        let service = self.clone();
        tokio::spawn(async move {
            let _ = service.finish_sync(id, repo).await;
        });
        Ok(())
    }

    /// Blocking sync — waits for completion. Prefer `start_sync` for API handlers.
    pub async fn sync_repository(
        &self,
        id: Uuid,
    ) -> Result<PlaybookSyncResult, PlaybookRepositoryError> {
        let repo = self.begin_sync(id).await?;
        self.clone().finish_sync(id, repo).await
    }

    /// Stage, then apply under the fence.
    pub(crate) async fn run_sync(
        &self,
        id: Uuid,
        repo: PlaybookRepository,
    ) -> Result<PlaybookSyncResult, PlaybookRepositoryError> {
        let start = Instant::now();
        let staged = stage_sync(&repo, &self.playbooks_repository, &self.github_client, &self.config, id).await?;
        self.apply_staged(id, &repo, staged, start).await
    }

    /// Phase 2: one transaction, fence first. Public to the crate so tests can
    /// prove a superseded fence writes nothing.
    #[doc(hidden)]
    pub async fn apply_staged(
        &self,
        id: Uuid,
        repo: &PlaybookRepository,
        staged: StagedSync,
        start: Instant,
    ) -> Result<PlaybookSyncResult, PlaybookRepositoryError> {
        let mut tx = self.pg_pool.begin().await.map_err(db_err)?;
        self.fence.guard(&mut tx).await.map_err(|e| PlaybookRepositoryError::Fenced(e.to_string()))?;
        let (commit, added, updated, removed, total) = match staged {
            StagedSync::UpToDate { commit, total } => {
                info!("Playbook repo {} is up to date at commit {}", repo.name, commit);
                (commit, 0, 0, 0, total)
            }
            StagedSync::Changed { commit, rows, keep } => {
                let (mut added, mut updated) = (0i32, 0i32);
                for row in &rows {
                    let stored = RepositoryPlaybooksRepository::upsert_with(
                        &mut *tx,
                        id,
                        &row.path,
                        Some(&row.sha),
                        &row.content,
                        &row.kind,
                        row.title.as_deref(),
                        row.subtitle.as_deref(),
                        row.category.as_deref(),
                        row.match_signals.as_deref(),
                        row.tags.as_deref(),
                        row.owner_team.as_deref(),
                        row.authored_date,
                        row.danger_policy.as_ref(),
                        row.review_cadence.as_deref(),
                        row.scope.as_deref(),
                        row.parse_status,
                        row.parse_error.as_deref(),
                        row.step_count,
                    )
                    .await
                    .map_err(|e| {
                        PlaybookRepositoryError::Internal(format!(
                            "playbook {} could not be written to the catalog: {e}",
                            row.path
                        ))
                    })?;
                    if row.existing {
                        updated += 1;
                        sqlx::query("UPDATE playbook_imports SET upstream_changed = TRUE WHERE repository_playbook_id = $1")
                            .bind(stored.id)
                            .execute(&mut *tx)
                            .await
                            .map_err(db_err)?;
                    } else {
                        added += 1;
                    }
                }
                let removed = if keep.is_empty() {
                    crate::db::repo_store::delete_by_repository(&mut *tx, "repository_playbooks", id).await
                } else {
                    crate::db::repo_store::prune_not_in_paths(&mut *tx, "repository_playbooks", id, &keep).await
                }
                .map_err(db_err)? as i32;
                (commit, added, updated, removed, keep.len() as i32)
            }
        };
        crate::db::repo_store::update_sync_status(
            &mut *tx,
            "playbook_repositories",
            "playbook_count",
            id,
            "success",
            Some(&commit),
            Some(total),
            None,
        )
        .await
        .map_err(|e| PlaybookRepositoryError::Internal(e.to_string()))?;
        tx.commit().await.map_err(db_err)?;
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

fn db_err(e: sqlx::Error) -> PlaybookRepositoryError {
    PlaybookRepositoryError::Internal(e.to_string())
}

/// Phase 1: network and parse only. Reads the cached rows; writes nothing.
pub(crate) async fn stage_sync(
    repo: &PlaybookRepository,
    playbooks_repository: &RepositoryPlaybooksRepository,
    github_client: &GitHubClient,
    config: &PlaybookRepositoryServiceConfig,
    id: Uuid,
) -> Result<StagedSync, PlaybookRepositoryError> {
    let (owner, repo_name) = crate::schema::github_owner_repo(&repo.url)
        .ok_or_else(|| PlaybookRepositoryError::InvalidUrl(repo.url.clone()))?;
    info!("Syncing playbook repository {}/{} ({})", owner, repo_name, repo.name);

    let commit = github_client
        .get_latest_commit(&owner, &repo_name, &repo.branch)
        .await
        .map_err(|e| PlaybookRepositoryError::GitHubApi(e.to_string()))?;
    if repo.last_sync_commit.as_ref() == Some(&commit) {
        return Ok(StagedSync::UpToDate { commit, total: repo.playbook_count.unwrap_or(0) });
    }

    let playbooks_path = repo.playbooks_path.as_deref().unwrap_or("");
    let tree_path = (!playbooks_path.is_empty()).then_some(playbooks_path);
    let tree = github_client
        .get_tree(&owner, &repo_name, &repo.branch, tree_path)
        .await
        .map_err(|e| PlaybookRepositoryError::GitHubApi(e.to_string()))?;
    let files: Vec<_> = tree
        .into_iter()
        .filter(|e| e.entry_type == "blob" && is_syncable_playbook_file(&e.path, &config.playbook_extensions))
        .take(config.max_playbooks_per_repo)
        .collect();

    let mut keep = Vec::new();
    let mut rows = Vec::new();
    let mut kind_refused = 0i32;
    for entry in &files {
        // Presence in `keep` is what protects a cached row from the prune —
        // and deleting one cascades to its `playbook_imports` provenance. So a
        // path is kept as soon as it is seen in the tree, and only a DELIBERATE
        // refusal removes it: a transient fetch error or an unparseable file
        // must leave the existing catalog row (and its import history) alone.
        keep.push(entry.path.clone());
        let existing = playbooks_repository.find_by_path(id, &entry.path).await.ok();
        if let Some(ref e) = existing {
            if e.file_sha.as_deref() == Some(entry.sha.as_str()) {
                // Re-apply the kind gate to unchanged rows too, so narrowing
                // `allowed_kinds` and re-syncing clears what the repository no
                // longer carries.
                if !repo_accepts_kind(repo, &e.kind) {
                    drop_from_catalog(&mut keep, &entry.path);
                    kind_refused += 1;
                }
                continue;
            }
        }
        let content = match github_client.get_raw_file(&owner, &repo_name, &entry.path, &commit).await {
            Ok(c) => c,
            Err(e) => {
                warn!("Failed to fetch {}: {}", entry.path, e);
                continue;
            }
        };
        let row = staged_row(&entry.path, &entry.sha, content, existing.is_some());
        // The kind comes from the file's own frontmatter — NEVER from the
        // directory it was found in.
        if !repo_accepts_kind(repo, &row.kind) {
            drop_from_catalog(&mut keep, &entry.path);
            kind_refused += 1;
            continue;
        }
        rows.push(row);
    }
    if kind_refused > 0 {
        info!(
            "Playbook repo {} declares allowed_kinds={:?}; {} file(s) of another kind were not catalogued",
            repo.name, repo.allowed_kinds, kind_refused
        );
    }
    Ok(StagedSync::Changed { commit, rows, keep })
}

/// Parse one fetched file into the row the catalog stores.
#[doc(hidden)]
pub fn staged_row(path: &str, sha: &str, content: String, existing: bool) -> StagedRow {
    let (fm, parse_status, parse_error, step_count) = match split_frontmatter(&content) {
        Ok((fm, body)) => {
            let tree = parse_playbook(body);
            let steps = (tree.phases.iter().map(|p| p.steps.len()).sum::<usize>() + tree.steps.len()) as i32;
            (fm, "success", None, Some(steps))
        }
        Err(e) => (None, "failed", Some(e.to_string()), None),
    };
    let kind = catalog_kind(fm.as_ref());
    let category = fm.as_ref().and_then(|f| f.category.clone());
    let (category, parse_status, parse_error) = resolve_category(category, parse_status, parse_error);
    StagedRow {
        path: path.to_owned(),
        sha: sha.to_owned(),
        kind: kind.as_str().to_owned(),
        title: fm.as_ref().and_then(|f| f.title.clone()),
        subtitle: fm.as_ref().and_then(|f| f.subtitle.clone()),
        category,
        match_signals: fm.as_ref().map(|f| f.match_signals.clone()),
        tags: fm.as_ref().map(|f| f.tags.clone()),
        owner_team: fm.as_ref().and_then(|f| f.owner.clone()),
        authored_date: fm.as_ref().and_then(|f| f.authored),
        danger_policy: fm
            .as_ref()
            .map(|f| serde_json::to_value(&f.danger_policy).unwrap_or(serde_json::Value::Null)),
        review_cadence: fm.as_ref().and_then(|f| f.review_cadence.clone()),
        scope: fm.as_ref().and_then(|f| f.scope.clone()),
        parse_status,
        parse_error,
        step_count,
        existing,
        content,
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
