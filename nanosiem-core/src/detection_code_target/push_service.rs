// SPDX-License-Identifier: AGPL-3.0-or-later

//! Composes the repository, serializer, and GitHub write client into a single
//! "open a tuning PR for this proposal" operation.
//!
//! This is the seam both the enterprise autonomous orchestrator and the manual
//! `approve` API handler call, so the "push a tuned rule as a PR" behavior lives
//! in exactly one place.

use async_trait::async_trait;
use thiserror::Error;
use uuid::Uuid;

use super::github_write::{GitHubWriteClient, GitHubWriteError, OpenedPr};
use super::models::DetectionCodeTarget;
use super::repository::{DetectionCodeTargetError, DetectionCodeTargetRepository};
use super::serializer::{self, SerializeError};
use super::validation;
use crate::models::detection_rule::DetectionRule;
use crate::tuning::repository::{
    FrozenPrOperation, PrApprovalProvenance, PrDestinationPayload, PrOperationCheckpoint,
    PrOperationError, PrOperationPhase, TuningRepository,
};
use crate::tuning::TuningProposal;

/// Label applied (best-effort) to every tuning PR nano opens.
const NANO_TUNING_LABEL: &str = "nano-tuning";

/// Which rung of the association cascade (NAN-1764) resolved the PR's target
/// file. Emitted in logs so a duplicate-file report is diagnosable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PathSource {
    /// Recorded provenance (`detection_rules.source_path`) — deterministic.
    Provenance,
    /// GitHub code-search hit on the rule id — found a moved/nano-written file.
    IdSearch,
    /// The name template — the original best-effort convention.
    Template,
}

#[derive(Debug, Error)]
pub enum PushError {
    #[error("push target error: {0}")]
    Target(#[from] DetectionCodeTargetError),
    #[error("GitHub error: {0}")]
    GitHub(#[from] GitHubWriteError),
    #[error("serialization error: {0}")]
    Serialize(#[from] SerializeError),
    #[error("push target has no GitHub token configured")]
    NoToken,
    // F-38: the composed head branch failed git-ref validation before any
    // GitHub call, so a malformed ref (e.g. one with a `.lock` path component)
    // is refused instead of producing a doomed 404/422 mid-flight.
    #[error("invalid branch ref: {0}")]
    InvalidBranch(#[from] validation::TargetValidationError),
}

#[derive(Debug, Error)]
pub enum PrExecutionError {
    #[error("Detection-as-Code remote effect failed: {0}")]
    Remote(#[source] PushError),
    #[error("Detection-as-Code checkpoint failed: {0}")]
    Checkpoint(#[source] PrOperationError),
    #[error("Detection-as-Code operation has invalid staged state: {0}")]
    InvalidState(String),
}

impl PrExecutionError {
    /// Network/API and database failures may be ambiguous after the remote or
    /// transactional side effect. Keep their lease pending so recovery can
    /// discover and reuse the deterministic markers. Configuration/payload
    /// errors are safe to release back to analyst review.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Checkpoint(error) => matches!(error, PrOperationError::Database(_)),
            Self::Remote(PushError::Target(DetectionCodeTargetError::Database(_))) => true,
            Self::Remote(PushError::GitHub(GitHubWriteError::Request(_))) => true,
            Self::Remote(PushError::GitHub(GitHubWriteError::Api { status, message })) => {
                matches!(*status, 408 | 409 | 425 | 429 | 500..=599)
                    || (*status == 403 && message.to_ascii_lowercase().contains("rate limit"))
            }
            Self::Remote(
                PushError::Target(
                    DetectionCodeTargetError::NotFound(_)
                    | DetectionCodeTargetError::DuplicateName(_)
                    | DetectionCodeTargetError::InUse(_)
                    | DetectionCodeTargetError::Encryption(_),
                )
                | PushError::GitHub(
                    GitHubWriteError::NotGitHub(_)
                    | GitHubWriteError::InvalidUrl(_)
                    | GitHubWriteError::BlockedEndpoint(_)
                    | GitHubWriteError::RemoteConflict(_)
                    // F-38: a malformed ref persisted in the target row will
                    // never succeed on retry — surface it to analyst review.
                    | GitHubWriteError::InvalidRef(_),
                )
                | PushError::Serialize(_)
                | PushError::NoToken
                // F-38: same for a composed branch that fails ref validation.
                | PushError::InvalidBranch(_),
            )
            | Self::InvalidState(_) => false,
        }
    }
}

#[async_trait]
trait PrRemoteEffects {
    type Error;

    async fn find_pull_request(&self) -> Result<Option<(OpenedPr, String)>, Self::Error>;
    async fn ensure_branch(&self) -> Result<String, Self::Error>;
    async fn ensure_commit(&self) -> Result<String, Self::Error>;
    async fn verify_commit(&self, expected_sha: &str) -> Result<(), Self::Error>;
    async fn ensure_pull_request(&self) -> Result<OpenedPr, Self::Error>;
}

#[async_trait]
trait PrCheckpointWriter {
    type Error;

    async fn record_branch(&self, sha: &str) -> Result<(), Self::Error>;
    async fn record_commit(&self, sha: &str) -> Result<(), Self::Error>;
    async fn record_pull_request(&self, pr: &OpenedPr) -> Result<(), Self::Error>;
    async fn record_reconciled_pull_request(
        &self,
        pr: &OpenedPr,
        head_sha: &str,
    ) -> Result<(), Self::Error>;
    async fn complete(&self, pr: &OpenedPr) -> Result<(), Self::Error>;
}

#[derive(Debug)]
enum ReconcileError<RemoteError, StoreError> {
    Remote(RemoteError),
    Store(StoreError),
    InvalidState(String),
}

#[derive(Clone)]
pub struct DetectionCodePushService {
    repo: DetectionCodeTargetRepository,
}

struct GitHubPrEffects<'a> {
    client: GitHubWriteClient,
    operation: &'a FrozenPrOperation,
    destination: &'a PrDestinationPayload,
}

#[async_trait]
impl PrRemoteEffects for GitHubPrEffects<'_> {
    type Error = PushError;

    async fn find_pull_request(&self) -> Result<Option<(OpenedPr, String)>, Self::Error> {
        self.client
            .find_existing_pull_request(
                &self.operation.repo_url,
                &self.operation.base_branch,
                &self.operation.branch,
                &self.destination.file_path,
                &self.destination.file_content,
                &self.destination.body,
            )
            .await
            .map_err(PushError::from)
    }

    async fn ensure_branch(&self) -> Result<String, Self::Error> {
        self.client
            .ensure_operation_branch(
                &self.operation.repo_url,
                &self.operation.base_branch,
                &self.operation.branch,
                &self.destination.file_path,
                &self.destination.file_content,
            )
            .await
            .map_err(PushError::from)
    }

    async fn ensure_commit(&self) -> Result<String, Self::Error> {
        self.client
            .ensure_commit(
                &self.operation.repo_url,
                &self.operation.branch,
                &self.destination.file_path,
                &self.destination.file_content,
                &self.destination.commit_message,
            )
            .await
            .map_err(PushError::from)
    }

    async fn verify_commit(&self, expected_sha: &str) -> Result<(), Self::Error> {
        self.client
            .verify_commit(
                &self.operation.repo_url,
                &self.operation.base_branch,
                &self.operation.branch,
                &self.destination.file_path,
                &self.destination.file_content,
                expected_sha,
            )
            .await
            .map_err(PushError::from)
    }

    async fn ensure_pull_request(&self) -> Result<OpenedPr, Self::Error> {
        self.client
            .ensure_pull_request(
                &self.operation.repo_url,
                &self.operation.base_branch,
                &self.operation.branch,
                &self.destination.file_path,
                &self.destination.file_content,
                &self.destination.title,
                &self.destination.body,
            )
            .await
            .map_err(PushError::from)
    }
}

struct RepositoryCheckpoints<'a> {
    repository: &'a TuningRepository,
    proposal_id: Uuid,
    branch: &'a str,
    attempt: i32,
    reviewer_notes: Option<&'a str>,
    approval_provenance: &'a PrApprovalProvenance,
}

#[async_trait]
impl PrCheckpointWriter for RepositoryCheckpoints<'_> {
    type Error = PrOperationError;

    async fn record_branch(&self, sha: &str) -> Result<(), Self::Error> {
        self.repository
            .checkpoint_pr_branch(self.proposal_id, self.branch, self.attempt, sha)
            .await
    }

    async fn record_commit(&self, sha: &str) -> Result<(), Self::Error> {
        self.repository
            .checkpoint_pr_commit(self.proposal_id, self.branch, self.attempt, sha)
            .await
    }

    async fn record_pull_request(&self, pr: &OpenedPr) -> Result<(), Self::Error> {
        self.repository
            .checkpoint_pull_request(
                self.proposal_id,
                self.branch,
                self.attempt,
                &pr.html_url,
                pr.number,
                &pr.state,
            )
            .await
    }

    async fn record_reconciled_pull_request(
        &self,
        pr: &OpenedPr,
        head_sha: &str,
    ) -> Result<(), Self::Error> {
        self.repository
            .checkpoint_reconciled_pull_request(
                self.proposal_id,
                self.branch,
                self.attempt,
                head_sha,
                &pr.html_url,
                pr.number,
                &pr.state,
            )
            .await
    }

    async fn complete(&self, pr: &OpenedPr) -> Result<(), Self::Error> {
        self.repository
            .complete_pr_operation(
                self.proposal_id,
                self.branch,
                self.attempt,
                &pr.html_url,
                pr.number,
                &pr.state,
                self.reviewer_notes,
                self.approval_provenance,
            )
            .await
    }
}

fn pull_request_from_checkpoint(checkpoint: &PrOperationCheckpoint) -> Result<OpenedPr, String> {
    Ok(OpenedPr {
        html_url: checkpoint
            .pr_url
            .clone()
            .ok_or_else(|| "pr_ready checkpoint has no URL".to_string())?,
        number: i64::from(
            checkpoint
                .pr_number
                .ok_or_else(|| "pr_ready checkpoint has no number".to_string())?,
        ),
        state: checkpoint
            .pr_state
            .clone()
            .ok_or_else(|| "pr_ready checkpoint has no state".to_string())?,
    })
}

async fn reconcile_staged_pr<Remote, Store>(
    remote: &Remote,
    store: &Store,
    mut checkpoint: PrOperationCheckpoint,
) -> Result<OpenedPr, ReconcileError<Remote::Error, Store::Error>>
where
    Remote: PrRemoteEffects + Sync,
    Store: PrCheckpointWriter + Sync,
{
    if checkpoint.phase == PrOperationPhase::Cancelled {
        return Err(ReconcileError::InvalidState(
            "cancelled operation cannot be reconciled".to_string(),
        ));
    }
    if checkpoint.phase == PrOperationPhase::Completed {
        return pull_request_from_checkpoint(&checkpoint).map_err(ReconcileError::InvalidState);
    }
    if checkpoint.phase < PrOperationPhase::DestinationReady {
        return Err(ReconcileError::InvalidState(
            "destination payload was not durably frozen".to_string(),
        ));
    }

    if checkpoint.phase <= PrOperationPhase::PrReady {
        match remote
            .find_pull_request()
            .await
            .map_err(ReconcileError::Remote)?
        {
            Some((pr, head_sha)) => {
                store
                    .record_reconciled_pull_request(&pr, &head_sha)
                    .await
                    .map_err(ReconcileError::Store)?;
                store.complete(&pr).await.map_err(ReconcileError::Store)?;
                return Ok(pr);
            }
            None if checkpoint.phase == PrOperationPhase::PrReady => {
                let pr = pull_request_from_checkpoint(&checkpoint)
                    .map_err(ReconcileError::InvalidState)?;
                if !matches!(pr.state.as_str(), "closed" | "merged") {
                    return Err(ReconcileError::InvalidState(
                        "open pr_ready checkpoint is no longer discoverable remotely".to_string(),
                    ));
                }
                store.complete(&pr).await.map_err(ReconcileError::Store)?;
                return Ok(pr);
            }
            None => {}
        }
    }

    if checkpoint.phase < PrOperationPhase::BranchReady {
        let sha = remote
            .ensure_branch()
            .await
            .map_err(ReconcileError::Remote)?;
        store
            .record_branch(&sha)
            .await
            .map_err(ReconcileError::Store)?;
        checkpoint.phase = PrOperationPhase::BranchReady;
        checkpoint.branch_sha = Some(sha);
    }

    if checkpoint.phase < PrOperationPhase::CommitReady {
        let sha = remote
            .ensure_commit()
            .await
            .map_err(ReconcileError::Remote)?;
        store
            .record_commit(&sha)
            .await
            .map_err(ReconcileError::Store)?;
        checkpoint.phase = PrOperationPhase::CommitReady;
        checkpoint.commit_sha = Some(sha);
    }
    if checkpoint.phase < PrOperationPhase::PrReady {
        let expected_sha = checkpoint.commit_sha.as_deref().ok_or_else(|| {
            ReconcileError::InvalidState("commit-ready checkpoint has no commit SHA".to_string())
        })?;
        remote
            .verify_commit(expected_sha)
            .await
            .map_err(ReconcileError::Remote)?;
    }

    let pr = if checkpoint.phase < PrOperationPhase::PrReady {
        let pr = remote
            .ensure_pull_request()
            .await
            .map_err(ReconcileError::Remote)?;
        store
            .record_pull_request(&pr)
            .await
            .map_err(ReconcileError::Store)?;
        pr
    } else {
        pull_request_from_checkpoint(&checkpoint).map_err(ReconcileError::InvalidState)?
    };

    store.complete(&pr).await.map_err(ReconcileError::Store)?;
    Ok(pr)
}

impl DetectionCodePushService {
    pub fn new(repo: DetectionCodeTargetRepository) -> Self {
        Self { repo }
    }

    /// Deterministic idempotency key for a proposal's GitHub side effect.
    ///
    /// F-38: validates the FINAL composed head branch as a complete git ref, so
    /// a `pr_branch_prefix` persisted before per-segment validation existed
    /// cannot compose a doomed ref (e.g. a `refs/`-qualified or `.lock` branch).
    pub fn branch_for_proposal(
        target: &DetectionCodeTarget,
        rule: &DetectionRule,
        proposal: &TuningProposal,
    ) -> Result<String, validation::TargetValidationError> {
        Self::branch_for_identity(&target.pr_branch_prefix, &rule.name, proposal.id)
    }

    pub fn branch_for_identity(
        prefix: &str,
        rule_name: &str,
        proposal_id: Uuid,
    ) -> Result<String, validation::TargetValidationError> {
        let branch = proposal_branch(prefix, rule_name, proposal_id);
        // F-38: validate the composed branch, not just the stored prefix — the
        // segment validator is the same one the manage endpoint applies, so a
        // legal prefix always yields a legal branch and a stale/hostile prefix
        // is rejected here rather than shipped to GitHub as a bad ref.
        validation::validate_git_ref(&branch)?;
        Ok(branch)
    }

    /// Open a Pull Request in `target`'s repo carrying `proposal`'s tuned query
    /// for `rule`. Preserves the existing file's frontmatter when the file is
    /// already present (minimal diff); otherwise creates a fresh nPL file.
    ///
    /// Records the PR on the target (`last_pr_url`) on success. Does NOT mutate
    /// the proposal or detection_rules — the caller owns proposal status.
    pub async fn open_pr_for_proposal(
        &self,
        target: &DetectionCodeTarget,
        rule: &DetectionRule,
        proposal: &TuningProposal,
    ) -> Result<OpenedPr, PushError> {
        let branch = Self::branch_for_proposal(target, rule, proposal)?;
        self.open_pr_for_proposal_on_branch(target, rule, proposal, &branch)
            .await
    }

    /// Resume/open a proposal on the branch frozen by the durable DB claim.
    pub async fn open_pr_for_proposal_on_branch(
        &self,
        target: &DetectionCodeTarget,
        rule: &DetectionRule,
        proposal: &TuningProposal,
        head_branch: &str,
    ) -> Result<OpenedPr, PushError> {
        let operation = FrozenPrOperation {
            proposal_id: proposal.id,
            target_id: target.id,
            repo_url: target.repo_url.clone(),
            base_branch: target.base_branch.clone(),
            path_template: target.path_template.clone(),
            rule_format: target.rule_format.clone(),
            branch: head_branch.to_string(),
            effective_query: proposal.proposed_query.clone(),
            original_query: proposal.original_query.clone(),
            rationale: proposal.rationale.clone(),
            confidence_score: proposal.confidence_score,
            changes_summary: proposal.changes_summary.clone(),
            rule: rule.clone(),
            approval_provenance: Some(PrApprovalProvenance::automated()),
        };
        let destination = self.prepare_pr_operation(&operation).await?;
        self.open_prepared_pr(&operation, &destination).await
    }

    /// Resolve the destination and exact file/PR payload using only the
    /// operation snapshot captured under PostgreSQL locks. This performs reads
    /// against GitHub, but no write; callers persist the result before opening
    /// the PR.
    pub async fn prepare_pr_operation(
        &self,
        operation: &FrozenPrOperation,
    ) -> Result<PrDestinationPayload, PushError> {
        let token = self
            .repo
            .get_decrypted_token(operation.target_id)
            .await?
            .ok_or(PushError::NoToken)?;
        let client = GitHubWriteClient::new(token);

        // NAN-1764: resolve the target file via the association cascade so an
        // existing rule in the customer's repo is updated in place — not
        // duplicated — regardless of their layout:
        //   1. recorded provenance (`source_path`) — deterministic
        //   2. GitHub code-search for the rule id — finds moved/nano-written files
        //   3. the name template — the original best-effort convention
        // Code search is only consulted when provenance is absent (it's the
        // fallback rung, and a network call we can skip when we already know).
        let rule = &operation.rule;
        let rule_id = rule.id;
        let id_hit = if valid_source_path(rule.source_path.as_deref()).is_some() {
            None
        } else {
            match client
                .find_file_by_rule_id(&operation.repo_url, &rule_id.to_string())
                .await
            {
                Ok(hit) => hit,
                Err(e) => {
                    tracing::warn!(rule_id = %rule_id, error = %e, "DaC id-search failed; falling back to path template");
                    None
                }
            }
        };
        let (file_path, path_source) = choose_target_path(
            rule.source_path.as_deref(),
            id_hit.as_deref(),
            &operation.path_template,
            &rule.name,
            rule_id,
        );
        tracing::info!(rule_id = %rule_id, %file_path, ?path_source, "resolved detection-as-code push target path");

        // Prefer a minimal diff: splice the tuned query into the existing file's
        // body, keeping the customer's frontmatter verbatim. Fall back to a full
        // file when the path doesn't exist yet or isn't in nPL frontmatter form.
        let existing = client
            .get_file(&operation.repo_url, &file_path, &operation.base_branch)
            .await?;
        let content = match existing.as_deref() {
            Some(ex) => match serializer::splice_query(ex, &operation.effective_query) {
                Some(spliced) => spliced,
                None => serializer::serialize_rule_to_npl(rule, &operation.effective_query)?,
            },
            None => serializer::serialize_rule_to_npl(rule, &operation.effective_query)?,
        };

        Ok(PrDestinationPayload {
            file_path,
            file_content: content,
            commit_message: format!(
                "tune({}): apply AI tuning proposal\n\nnano-pr-operation: {}",
                rule.name, operation.proposal_id
            ),
            title: format!("Tune detection: {}", rule.name),
            body: build_pr_body(operation),
        })
    }

    /// Reconcile a staged PR operation from its last durable checkpoint. The
    /// repository checkpoint is written after every GitHub effect and before
    /// terminal proposal/log completion.
    #[allow(clippy::too_many_arguments)]
    pub async fn reconcile_prepared_pr(
        &self,
        tuning_repository: &TuningRepository,
        operation: &FrozenPrOperation,
        destination: &PrDestinationPayload,
        checkpoint: PrOperationCheckpoint,
        attempt: i32,
        reviewer_notes: Option<&str>,
    ) -> Result<OpenedPr, PrExecutionError> {
        let approval_provenance = operation.approval_provenance.as_ref().ok_or_else(|| {
            PrExecutionError::InvalidState(
                "frozen PR operation has no durable approval provenance".to_string(),
            )
        })?;
        let token = self
            .repo
            .get_decrypted_token(operation.target_id)
            .await
            .map_err(PushError::from)
            .map_err(PrExecutionError::Remote)?
            .ok_or(PushError::NoToken)
            .map_err(PrExecutionError::Remote)?;
        let client = GitHubWriteClient::new(token);
        let remote = GitHubPrEffects {
            client: client.clone(),
            operation,
            destination,
        };
        let reviewer_notes = operation
            .approval_provenance
            .as_ref()
            .map(|provenance| provenance.reason.as_deref())
            .unwrap_or(reviewer_notes);
        let checkpoints = RepositoryCheckpoints {
            repository: tuning_repository,
            proposal_id: operation.proposal_id,
            branch: &operation.branch,
            attempt,
            reviewer_notes,
            approval_provenance,
        };
        let pr = match reconcile_staged_pr(&remote, &checkpoints, checkpoint).await {
            Ok(pr) => pr,
            Err(error) => {
                let error = match error {
                    ReconcileError::Remote(error) => PrExecutionError::Remote(error),
                    ReconcileError::Store(error) => PrExecutionError::Checkpoint(error),
                    ReconcileError::InvalidState(error) => PrExecutionError::InvalidState(error),
                };
                if error.is_retryable() {
                    tuning_repository
                        .record_pr_operation_error(
                            operation.proposal_id,
                            &operation.branch,
                            attempt,
                            &error.to_string(),
                        )
                        .await
                        .map_err(PrExecutionError::Checkpoint)?;
                }
                return Err(error);
            }
        };
        self.record_pr_best_effort(&client, operation, &pr).await;
        Ok(pr)
    }

    /// Execute a destination payload that was durably frozen before this first
    /// GitHub write. Target edits and rule edits after the claim cannot redirect
    /// the operation.
    pub async fn open_prepared_pr(
        &self,
        operation: &FrozenPrOperation,
        destination: &PrDestinationPayload,
    ) -> Result<OpenedPr, PushError> {
        let token = self
            .repo
            .get_decrypted_token(operation.target_id)
            .await?
            .ok_or(PushError::NoToken)?;
        let client = GitHubWriteClient::new(token);

        let pr = client
            .open_pr(
                &operation.repo_url,
                &operation.base_branch,
                &operation.branch,
                &destination.file_path,
                &destination.file_content,
                &destination.commit_message,
                &destination.title,
                &destination.body,
            )
            .await?;

        self.record_pr_best_effort(&client, operation, &pr).await;
        Ok(pr)
    }

    async fn record_pr_best_effort(
        &self,
        client: &GitHubWriteClient,
        operation: &FrozenPrOperation,
        pr: &OpenedPr,
    ) {
        // Best-effort: tag the PR so it's filterable in GitHub. A repo without
        // the label, or a token lacking issues:write, must not fail a PR we've
        // already opened — the `nano-rule-id` body marker is the reliable link.
        if let Err(e) = client
            .add_labels(&operation.repo_url, pr.number, &[NANO_TUNING_LABEL])
            .await
        {
            tracing::warn!(pr = pr.number, error = %e, "failed to label tuning PR (non-fatal)");
        }

        // Best-effort: record the PR on the target. A telemetry write failing
        // must not lose the PR we already opened.
        if let Err(e) = self
            .repo
            .mark_pr_opened(operation.target_id, &pr.html_url)
            .await
        {
            tracing::warn!(target_id = %operation.target_id, error = %e, "failed to record last_pr_url on push target");
        }
    }
}

/// A `source_path` is usable only if it's a non-empty, traversal-free relative
/// file path (same guard `path_template` gets — NAN-1758). Returns the trimmed
/// path when usable, so an invalid recorded value silently falls through to the
/// cascade's next rung instead of being interpolated into a GitHub URL.
fn valid_source_path(source_path: Option<&str>) -> Option<&str> {
    let sp = source_path?.trim();
    if sp.is_empty() {
        return None;
    }
    validation::validate_path_template(sp).ok().map(|()| sp)
}

/// A code-search hit is a real repo-relative path GitHub handed us, so it can't
/// escape the repo — but guard against the degenerate shapes anyway before it's
/// interpolated into the contents URL.
fn safe_repo_path(path: &str) -> bool {
    !path.is_empty() && !path.starts_with('/') && !path.split('/').any(|seg| seg == "..")
}

/// Pure association cascade (NAN-1764): pick the target file path and report
/// which rung decided it. `id_hit` is the already-fetched code-search result
/// (None when not searched or not found) so this stays free of I/O and unit-
/// testable.
pub(crate) fn choose_target_path(
    source_path: Option<&str>,
    id_hit: Option<&str>,
    template: &str,
    rule_name: &str,
    rule_id: Uuid,
) -> (String, PathSource) {
    if let Some(sp) = valid_source_path(source_path) {
        return (sp.to_string(), PathSource::Provenance);
    }
    if let Some(hit) = id_hit {
        if safe_repo_path(hit) {
            return (hit.to_string(), PathSource::IdSearch);
        }
    }
    (
        render_path(template, rule_name, rule_id),
        PathSource::Template,
    )
}

/// Substitute `{rule_name}` / `{rule_id}` into the configured path template.
fn render_path(template: &str, rule_name: &str, rule_id: Uuid) -> String {
    template
        .replace("{rule_name}", &sanitize_component(rule_name))
        .replace("{rule_id}", &rule_id.simple().to_string())
}

/// Make a rule name safe for use as a single path/branch component: keep
/// filename-safe chars, replace the rest with `_`, and neutralize `..` so the
/// injected value can't traverse out of the templated directory.
fn sanitize_component(s: &str) -> String {
    let mapped: String = s
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let mapped = mapped.replace("..", "_");
    let trimmed = mapped.trim_matches(|c| c == '.' || c == '/' || c == '_');
    if trimmed.is_empty() {
        "rule".to_string()
    } else {
        trimmed.to_string()
    }
}

fn proposal_branch(prefix: &str, rule_name: &str, proposal_id: Uuid) -> String {
    format!(
        "{}{}-{}",
        prefix,
        sanitize_component(rule_name),
        proposal_id.simple()
    )
}

fn build_pr_body(operation: &FrozenPrOperation) -> String {
    let confidence = (operation.confidence_score * 100.0).round() as i64;
    let mut body = String::new();
    body.push_str(&format!(
        "## AI tuning proposal for `{}`\n\n",
        operation.rule.name
    ));
    body.push_str(&operation.rationale);
    body.push_str(&format!("\n\n**Confidence:** {confidence}%\n"));

    if !operation.changes_summary.is_empty() {
        body.push_str("\n### Changes\n");
        for change in &operation.changes_summary {
            body.push_str(&format!("- {change}\n"));
        }
    }

    body.push_str("\n### Query\n```diff\n");
    for line in operation.original_query.lines() {
        body.push_str(&format!("- {line}\n"));
    }
    for line in operation.effective_query.lines() {
        body.push_str(&format!("+ {line}\n"));
    }
    body.push_str("```\n");
    body.push_str(&format!(
        "\n---\nOpened by nano detection-as-code tuning (proposal `{}`). Merging this PR is what applies the change — your DaC pipeline redeploys it to nano.\n",
        operation.proposal_id
    ));
    // Machine-readable link back to the rule (NAN-1764). Invisible in rendered
    // markdown; the operation marker is the idempotency identity and the rule
    // marker lets a future merge webhook associate the resulting deployment.
    body.push_str(&format!(
        "\n<!-- nano-pr-operation: {} -->\n",
        operation.proposal_id
    ));
    body.push_str(&format!("\n<!-- nano-rule-id: {} -->\n", operation.rule.id));
    body
}

#[cfg(test)]
mod tests;
