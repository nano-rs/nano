// SPDX-License-Identifier: AGPL-3.0-or-later

//! Composes the repository, serializer, and GitHub write client into a single
//! "open a tuning PR for this proposal" operation.
//!
//! This is the seam both the enterprise autonomous orchestrator and the manual
//! `approve` API handler call, so the "push a tuned rule as a PR" behavior lives
//! in exactly one place.

use thiserror::Error;

use super::github_write::{GitHubWriteClient, GitHubWriteError, OpenedPr};
use super::repository::{DetectionCodeTargetError, DetectionCodeTargetRepository};
use super::serializer::{self, SerializeError};
use super::models::DetectionCodeTarget;
use crate::models::detection_rule::DetectionRule;
use crate::tuning::TuningProposal;

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
}

#[derive(Clone)]
pub struct DetectionCodePushService {
    repo: DetectionCodeTargetRepository,
}

impl DetectionCodePushService {
    pub fn new(repo: DetectionCodeTargetRepository) -> Self {
        Self { repo }
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
        let token = self
            .repo
            .get_decrypted_token(target.id)
            .await?
            .ok_or(PushError::NoToken)?;
        let client = GitHubWriteClient::new(token);

        let file_path = render_path(&target.path_template, rule);

        // Prefer a minimal diff: splice the tuned query into the existing file's
        // body, keeping the customer's frontmatter verbatim. Fall back to a full
        // file when the path doesn't exist yet or isn't in nPL frontmatter form.
        let existing = client
            .get_file(&target.repo_url, &file_path, &target.base_branch)
            .await?;
        let content = match existing.as_deref() {
            Some(ex) => match serializer::splice_query(ex, &proposal.proposed_query) {
                Some(spliced) => spliced,
                None => serializer::serialize_rule_to_npl(rule, &proposal.proposed_query)?,
            },
            None => serializer::serialize_rule_to_npl(rule, &proposal.proposed_query)?,
        };

        let head_branch = format!(
            "{}{}-{}",
            target.pr_branch_prefix,
            sanitize_component(&rule.name),
            &proposal.id.simple().to_string()[..8]
        );
        let commit_message = format!("tune({}): apply AI tuning proposal", rule.name);
        let pr_title = format!("Tune detection: {}", rule.name);
        let pr_body = build_pr_body(rule, proposal);

        let pr = client
            .open_pr(
                &target.repo_url,
                &target.base_branch,
                &head_branch,
                &file_path,
                &content,
                &commit_message,
                &pr_title,
                &pr_body,
            )
            .await?;

        // Best-effort: record the PR on the target. A telemetry write failing
        // must not lose the PR we already opened.
        if let Err(e) = self.repo.mark_pr_opened(target.id, &pr.html_url).await {
            tracing::warn!(target_id = %target.id, error = %e, "failed to record last_pr_url on push target");
        }
        Ok(pr)
    }
}

/// Substitute `{rule_name}` / `{rule_id}` into the configured path template.
fn render_path(template: &str, rule: &DetectionRule) -> String {
    template
        .replace("{rule_name}", &sanitize_component(&rule.name))
        .replace("{rule_id}", &rule.id.simple().to_string())
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

fn build_pr_body(rule: &DetectionRule, proposal: &TuningProposal) -> String {
    let confidence = (proposal.confidence_score * 100.0).round() as i64;
    let mut body = String::new();
    body.push_str(&format!("## AI tuning proposal for `{}`\n\n", rule.name));
    body.push_str(&proposal.rationale);
    body.push_str(&format!("\n\n**Confidence:** {confidence}%\n"));

    if !proposal.changes_summary.is_empty() {
        body.push_str("\n### Changes\n");
        for change in &proposal.changes_summary {
            body.push_str(&format!("- {change}\n"));
        }
    }

    body.push_str("\n### Query\n```diff\n");
    for line in proposal.original_query.lines() {
        body.push_str(&format!("- {line}\n"));
    }
    for line in proposal.proposed_query.lines() {
        body.push_str(&format!("+ {line}\n"));
    }
    body.push_str("```\n");
    body.push_str(&format!(
        "\n---\nOpened by nano detection-as-code tuning (proposal `{}`). Merging this PR is what applies the change — your DaC pipeline redeploys it to nano.\n",
        proposal.id
    ));
    body
}
