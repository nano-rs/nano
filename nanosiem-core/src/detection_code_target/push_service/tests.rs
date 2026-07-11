// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the NAN-1764 association cascade. `choose_target_path` is
//! pure (the code-search I/O is lifted into the caller and passed in as
//! `id_hit`), so every rung is exercised here without a GitHub round-trip.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};

use async_trait::async_trait;

use super::{
    choose_target_path, proposal_branch, reconcile_staged_pr, safe_repo_path, valid_source_path,
    GitHubWriteError, OpenedPr, PathSource, PrCheckpointWriter, PrExecutionError, PrRemoteEffects,
    PushError,
};
use crate::tuning::{PrOperationCheckpoint, PrOperationPhase};
use uuid::Uuid;

fn rule_id() -> Uuid {
    Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
}

const TEMPLATE: &str = "detections/{rule_name}.yaml";

#[test]
fn retry_classification_separates_transient_and_terminal_github_failures() {
    let api = |status, message: &str| {
        PrExecutionError::Remote(PushError::GitHub(GitHubWriteError::Api {
            status,
            message: message.to_string(),
        }))
    };

    for status in [401, 404, 422] {
        assert!(!api(status, "terminal").is_retryable(), "status={status}");
    }
    for status in [408, 409, 425, 429, 500, 503] {
        assert!(api(status, "transient").is_retryable(), "status={status}");
    }
    assert!(api(403, "API rate limit exceeded").is_retryable());
    assert!(!api(403, "Resource not accessible by personal access token").is_retryable());

    assert!(
        PrExecutionError::Checkpoint(crate::tuning::PrOperationError::Database(
            sqlx::Error::RowNotFound,
        ))
        .is_retryable()
    );
    assert!(
        !PrExecutionError::Checkpoint(crate::tuning::PrOperationError::InvalidState {
            proposal_id: Uuid::now_v7(),
            status: "checkpoint head drifted".to_string(),
        },)
        .is_retryable()
    );
}

#[test]
fn provenance_wins_over_everything() {
    // Recorded source_path is used verbatim — the template and a code-search
    // hit are both ignored. This is the whole point: no duplicate file.
    let (path, src) = choose_target_path(
        Some("rules/windows/persistence/t1547.yaml"),
        Some("some/other/hit.yaml"),
        TEMPLATE,
        "Registry Run Key Persistence",
        rule_id(),
    );
    assert_eq!(path, "rules/windows/persistence/t1547.yaml");
    assert_eq!(src, PathSource::Provenance);
}

#[test]
fn id_search_used_when_no_provenance() {
    let (path, src) = choose_target_path(
        None,
        Some("threats/moved_rule.yaml"),
        TEMPLATE,
        "Some Rule",
        rule_id(),
    );
    assert_eq!(path, "threats/moved_rule.yaml");
    assert_eq!(src, PathSource::IdSearch);
}

#[test]
fn falls_back_to_template_when_nothing_else() {
    let (path, src) = choose_target_path(None, None, TEMPLATE, "PowerShell Suspicious", rule_id());
    // Name is sanitized into a single filename-safe component.
    assert_eq!(path, "detections/PowerShell_Suspicious.yaml");
    assert_eq!(src, PathSource::Template);
}

#[test]
fn template_can_substitute_rule_id() {
    let (path, src) = choose_target_path(None, None, "d/{rule_id}.yaml", "n", rule_id());
    assert_eq!(path, "d/550e8400e29b41d4a716446655440000.yaml");
    assert_eq!(src, PathSource::Template);
}

#[test]
fn empty_or_whitespace_source_path_is_ignored() {
    let (_, src) = choose_target_path(Some("   "), None, TEMPLATE, "n", rule_id());
    assert_eq!(src, PathSource::Template);
    assert!(valid_source_path(Some("")).is_none());
    assert!(valid_source_path(None).is_none());
}

#[test]
fn traversal_source_path_falls_through_not_interpolated() {
    // A malicious/broken provenance value must never reach the GitHub URL — it
    // falls through to the id-search rung instead.
    let (path, src) = choose_target_path(
        Some("../../.github/workflows/pwn.yml"),
        Some("threats/real.yaml"),
        TEMPLATE,
        "n",
        rule_id(),
    );
    assert_eq!(path, "threats/real.yaml");
    assert_eq!(src, PathSource::IdSearch);
    assert!(valid_source_path(Some("../../etc/passwd")).is_none());
    assert!(valid_source_path(Some("/abs/path.yaml")).is_none());
    assert!(valid_source_path(Some("detections/ok.yaml")).is_some());
}

#[test]
fn unsafe_id_hit_is_rejected_falls_to_template() {
    let (path, src) = choose_target_path(None, Some("../escape.yaml"), TEMPLATE, "Rule", rule_id());
    assert_eq!(path, "detections/Rule.yaml");
    assert_eq!(src, PathSource::Template);
    assert!(!safe_repo_path("../escape.yaml"));
    assert!(!safe_repo_path("/abs.yaml"));
    assert!(safe_repo_path("a/b/c.yaml"));
}

#[test]
fn branch_identity_uses_the_full_proposal_uuid() {
    let first = Uuid::parse_str("01900000-0000-7000-8000-000000000001").unwrap();
    let second = Uuid::parse_str("01900000-0000-7000-8000-000000000002").unwrap();
    assert_eq!(
        &first.simple().to_string()[..8],
        &second.simple().to_string()[..8]
    );

    let first_branch = proposal_branch("nano-tuning/", "Same rule", first);
    let second_branch = proposal_branch("nano-tuning/", "Same rule", second);
    assert_ne!(first_branch, second_branch);
    assert!(first_branch.ends_with(&first.simple().to_string()));
    assert!(second_branch.ends_with(&second.simple().to_string()));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FailureBoundary {
    GithubBranch,
    DatabaseBranch,
    GithubCommit,
    DatabaseCommit,
    GithubPullRequest,
    DatabasePullRequest,
    DatabaseCompletion,
}

struct FailOnce {
    boundary: FailureBoundary,
    fired: AtomicBool,
}

impl FailOnce {
    fn new(boundary: FailureBoundary) -> Self {
        Self {
            boundary,
            fired: AtomicBool::new(false),
        }
    }

    fn after(&self, boundary: FailureBoundary) -> Result<(), &'static str> {
        if self.boundary == boundary && !self.fired.swap(true, Ordering::SeqCst) {
            Err("injected ambiguous boundary failure")
        } else {
            Ok(())
        }
    }
}

#[derive(Default)]
struct FakeRemoteState {
    branch_exists: bool,
    commit_exists: bool,
    pull_request: Option<OpenedPr>,
    branch_creates: usize,
    commit_creates: usize,
    pull_request_creates: usize,
}

struct FakeRemote {
    state: Mutex<FakeRemoteState>,
    failures: Arc<FailOnce>,
}

#[async_trait]
impl PrRemoteEffects for FakeRemote {
    type Error = &'static str;

    async fn find_pull_request(&self) -> Result<Option<(OpenedPr, String)>, Self::Error> {
        Ok(self
            .state
            .lock()
            .unwrap()
            .pull_request
            .clone()
            .map(|pr| (pr, "commit-sha".to_string())))
    }

    async fn ensure_branch(&self) -> Result<String, Self::Error> {
        let mut state = self.state.lock().unwrap();
        if !state.branch_exists {
            state.branch_exists = true;
            state.branch_creates += 1;
        }
        drop(state);
        self.failures.after(FailureBoundary::GithubBranch)?;
        Ok("branch-sha".to_string())
    }

    async fn ensure_commit(&self) -> Result<String, Self::Error> {
        let mut state = self.state.lock().unwrap();
        assert!(state.branch_exists);
        if !state.commit_exists {
            state.commit_exists = true;
            state.commit_creates += 1;
        }
        drop(state);
        self.failures.after(FailureBoundary::GithubCommit)?;
        Ok("commit-sha".to_string())
    }

    async fn verify_commit(&self, expected_sha: &str) -> Result<(), Self::Error> {
        let state = self.state.lock().unwrap();
        if state.commit_exists && expected_sha == "commit-sha" {
            Ok(())
        } else {
            Err("checkpointed commit drifted")
        }
    }

    async fn ensure_pull_request(&self) -> Result<OpenedPr, Self::Error> {
        let mut state = self.state.lock().unwrap();
        assert!(state.commit_exists);
        let pull_request = state.pull_request.get_or_insert_with(|| OpenedPr {
            html_url: "https://github.com/acme/detections/pull/71".to_string(),
            number: 71,
            state: "open".to_string(),
        });
        let pull_request = pull_request.clone();
        if state.pull_request_creates == 0 {
            state.pull_request_creates = 1;
        }
        drop(state);
        self.failures.after(FailureBoundary::GithubPullRequest)?;
        Ok(pull_request)
    }
}

struct FakeCheckpointState {
    checkpoint: PrOperationCheckpoint,
    target_claimed: bool,
}

struct FakeStore {
    state: Mutex<FakeCheckpointState>,
    failures: Arc<FailOnce>,
}

impl FakeStore {
    fn new(failures: Arc<FailOnce>) -> Self {
        Self {
            state: Mutex::new(FakeCheckpointState {
                checkpoint: PrOperationCheckpoint {
                    phase: PrOperationPhase::DestinationReady,
                    branch_sha: None,
                    commit_sha: None,
                    pr_url: None,
                    pr_number: None,
                    pr_state: None,
                },
                target_claimed: true,
            }),
            failures,
        }
    }

    fn checkpoint(&self) -> PrOperationCheckpoint {
        self.state.lock().unwrap().checkpoint.clone()
    }
}

#[async_trait]
impl PrCheckpointWriter for FakeStore {
    type Error = &'static str;

    async fn record_branch(&self, sha: &str) -> Result<(), Self::Error> {
        {
            let mut state = self.state.lock().unwrap();
            state.checkpoint.phase = PrOperationPhase::BranchReady;
            state.checkpoint.branch_sha = Some(sha.to_string());
        }
        self.failures.after(FailureBoundary::DatabaseBranch)
    }

    async fn record_commit(&self, sha: &str) -> Result<(), Self::Error> {
        {
            let mut state = self.state.lock().unwrap();
            state.checkpoint.phase = PrOperationPhase::CommitReady;
            state.checkpoint.commit_sha = Some(sha.to_string());
        }
        self.failures.after(FailureBoundary::DatabaseCommit)
    }

    async fn record_pull_request(&self, pr: &OpenedPr) -> Result<(), Self::Error> {
        {
            let mut state = self.state.lock().unwrap();
            state.checkpoint.phase = PrOperationPhase::PrReady;
            state.checkpoint.pr_url = Some(pr.html_url.clone());
            state.checkpoint.pr_number = Some(pr.number as i32);
            state.checkpoint.pr_state = Some(pr.state.clone());
        }
        self.failures.after(FailureBoundary::DatabasePullRequest)
    }

    async fn record_reconciled_pull_request(
        &self,
        pr: &OpenedPr,
        head_sha: &str,
    ) -> Result<(), Self::Error> {
        {
            let mut state = self.state.lock().unwrap();
            state.checkpoint.phase = PrOperationPhase::PrReady;
            state
                .checkpoint
                .branch_sha
                .get_or_insert_with(|| head_sha.to_string());
            state.checkpoint.commit_sha = Some(head_sha.to_string());
            state.checkpoint.pr_url = Some(pr.html_url.clone());
            state.checkpoint.pr_number = Some(pr.number as i32);
            state.checkpoint.pr_state = Some(pr.state.clone());
        }
        self.failures.after(FailureBoundary::DatabasePullRequest)
    }

    async fn complete(&self, _pr: &OpenedPr) -> Result<(), Self::Error> {
        {
            let mut state = self.state.lock().unwrap();
            state.checkpoint.phase = PrOperationPhase::Completed;
            state.target_claimed = false;
        }
        self.failures.after(FailureBoundary::DatabaseCompletion)
    }
}

#[tokio::test]
async fn every_remote_and_database_boundary_converges_without_duplicate_prs() {
    for boundary in [
        FailureBoundary::GithubBranch,
        FailureBoundary::DatabaseBranch,
        FailureBoundary::GithubCommit,
        FailureBoundary::DatabaseCommit,
        FailureBoundary::GithubPullRequest,
        FailureBoundary::DatabasePullRequest,
        FailureBoundary::DatabaseCompletion,
    ] {
        let failures = Arc::new(FailOnce::new(boundary));
        let remote = FakeRemote {
            state: Mutex::new(FakeRemoteState::default()),
            failures: failures.clone(),
        };
        let store = FakeStore::new(failures);

        let mut completed = false;
        for _ in 0..4 {
            match reconcile_staged_pr(&remote, &store, store.checkpoint()).await {
                Ok(pr) => {
                    assert_eq!(pr.number, 71, "boundary={boundary:?}");
                    completed = true;
                    break;
                }
                Err(_) => continue,
            }
        }
        assert!(completed, "boundary={boundary:?} did not converge");

        let remote_state = remote.state.lock().unwrap();
        assert_eq!(remote_state.branch_creates, 1, "boundary={boundary:?}");
        assert_eq!(remote_state.commit_creates, 1, "boundary={boundary:?}");
        assert_eq!(
            remote_state.pull_request_creates, 1,
            "boundary={boundary:?}"
        );
        drop(remote_state);

        let store_state = store.state.lock().unwrap();
        assert_eq!(
            store_state.checkpoint.phase,
            PrOperationPhase::Completed,
            "boundary={boundary:?}"
        );
        assert!(!store_state.target_claimed, "boundary={boundary:?}");
        assert_eq!(
            store_state.checkpoint.pr_url.as_deref(),
            Some("https://github.com/acme/detections/pull/71")
        );
    }
}

#[tokio::test]
async fn remote_drift_after_commit_checkpoint_blocks_pr_creation() {
    let failures = Arc::new(FailOnce::new(FailureBoundary::DatabaseCommit));
    let remote = FakeRemote {
        state: Mutex::new(FakeRemoteState::default()),
        failures: failures.clone(),
    };
    let store = FakeStore::new(failures);

    assert!(reconcile_staged_pr(&remote, &store, store.checkpoint())
        .await
        .is_err());
    assert_eq!(store.checkpoint().phase, PrOperationPhase::CommitReady);
    remote.state.lock().unwrap().commit_exists = false;

    assert!(reconcile_staged_pr(&remote, &store, store.checkpoint())
        .await
        .is_err());
    assert_eq!(remote.state.lock().unwrap().pull_request_creates, 0);
    assert_eq!(store.checkpoint().phase, PrOperationPhase::CommitReady);
}

#[tokio::test]
async fn marked_merged_pr_converges_after_its_branch_is_deleted() {
    let failures = Arc::new(FailOnce::new(FailureBoundary::DatabasePullRequest));
    let remote = FakeRemote {
        state: Mutex::new(FakeRemoteState {
            branch_exists: false,
            commit_exists: true,
            pull_request: Some(OpenedPr {
                html_url: "https://github.com/acme/detections/pull/71".to_string(),
                number: 71,
                state: "merged".to_string(),
            }),
            branch_creates: 0,
            commit_creates: 0,
            pull_request_creates: 1,
        }),
        failures: failures.clone(),
    };
    let store = FakeStore::new(failures);

    assert!(reconcile_staged_pr(&remote, &store, store.checkpoint())
        .await
        .is_err());
    assert_eq!(store.checkpoint().phase, PrOperationPhase::PrReady);
    let pr = reconcile_staged_pr(&remote, &store, store.checkpoint())
        .await
        .expect("remote PR identity should finish the missing database checkpoints");
    assert_eq!(pr.state, "merged");
    assert_eq!(store.checkpoint().phase, PrOperationPhase::Completed);
    let remote = remote.state.lock().unwrap();
    assert_eq!(remote.branch_creates, 0);
    assert_eq!(remote.commit_creates, 0);
    assert_eq!(remote.pull_request_creates, 1);
}

#[tokio::test]
async fn pr_ready_recovery_refreshes_remote_state_before_completion() {
    let failures = Arc::new(FailOnce::new(FailureBoundary::GithubBranch));
    let remote = FakeRemote {
        state: Mutex::new(FakeRemoteState {
            branch_exists: false,
            commit_exists: true,
            pull_request: Some(OpenedPr {
                html_url: "https://github.com/acme/detections/pull/71".to_string(),
                number: 71,
                state: "merged".to_string(),
            }),
            branch_creates: 0,
            commit_creates: 0,
            pull_request_creates: 1,
        }),
        failures: failures.clone(),
    };
    let store = FakeStore::new(failures);
    {
        let mut state = store.state.lock().unwrap();
        state.checkpoint = PrOperationCheckpoint {
            phase: PrOperationPhase::PrReady,
            branch_sha: Some("branch-sha".to_string()),
            commit_sha: Some("commit-sha".to_string()),
            pr_url: Some("https://github.com/acme/detections/pull/71".to_string()),
            pr_number: Some(71),
            pr_state: Some("open".to_string()),
        };
    }

    let pr = reconcile_staged_pr(&remote, &store, store.checkpoint())
        .await
        .expect("pr_ready recovery");
    assert_eq!(pr.state, "merged");
    assert_eq!(store.checkpoint().phase, PrOperationPhase::Completed);
    assert_eq!(store.checkpoint().pr_state.as_deref(), Some("merged"));
}

#[tokio::test]
async fn terminal_pr_ready_checkpoint_survives_deleted_remote_branch() {
    let failures = Arc::new(FailOnce::new(FailureBoundary::GithubBranch));
    let remote = FakeRemote {
        state: Mutex::new(FakeRemoteState::default()),
        failures: failures.clone(),
    };
    let store = FakeStore::new(failures);
    {
        let mut state = store.state.lock().unwrap();
        state.checkpoint = PrOperationCheckpoint {
            phase: PrOperationPhase::PrReady,
            branch_sha: Some("branch-sha".to_string()),
            commit_sha: Some("commit-sha".to_string()),
            pr_url: Some("https://github.com/acme/detections/pull/71".to_string()),
            pr_number: Some(71),
            pr_state: Some("merged".to_string()),
        };
    }

    let pr = reconcile_staged_pr(&remote, &store, store.checkpoint())
        .await
        .expect("terminal checkpoint fallback");
    assert_eq!(pr.state, "merged");
    assert_eq!(store.checkpoint().phase, PrOperationPhase::Completed);
}

#[tokio::test]
async fn open_pr_ready_checkpoint_must_still_be_discoverable() {
    let failures = Arc::new(FailOnce::new(FailureBoundary::GithubBranch));
    let remote = FakeRemote {
        state: Mutex::new(FakeRemoteState::default()),
        failures: failures.clone(),
    };
    let store = FakeStore::new(failures);
    {
        let mut state = store.state.lock().unwrap();
        state.checkpoint = PrOperationCheckpoint {
            phase: PrOperationPhase::PrReady,
            branch_sha: Some("branch-sha".to_string()),
            commit_sha: Some("commit-sha".to_string()),
            pr_url: Some("https://github.com/acme/detections/pull/71".to_string()),
            pr_number: Some(71),
            pr_state: Some("open".to_string()),
        };
    }

    assert!(reconcile_staged_pr(&remote, &store, store.checkpoint())
        .await
        .is_err());
    assert_eq!(store.checkpoint().phase, PrOperationPhase::PrReady);
}
