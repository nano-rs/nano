// SPDX-License-Identifier: AGPL-3.0-or-later

//! Composes the repository, serializer, and GitHub write client into a single
//! "open a tuning PR for this proposal" operation.
//!
//! This is the seam both the enterprise autonomous orchestrator and the manual
//! `approve` API handler call, so the "push a tuned rule as a PR" behavior lives
//! in exactly one place.

use thiserror::Error;
use uuid::Uuid;

use super::github_write::{GitHubWriteClient, GitHubWriteError, OpenedPr};
use super::repository::{DetectionCodeTargetError, DetectionCodeTargetRepository};
use super::serializer::{self, SerializeError};
use super::models::DetectionCodeTarget;
use super::validation;
use crate::models::detection_rule::DetectionRule;
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

        // NAN-1764: resolve the target file via the association cascade so an
        // existing rule in the customer's repo is updated in place — not
        // duplicated — regardless of their layout:
        //   1. recorded provenance (`source_path`) — deterministic
        //   2. GitHub code-search for the rule id — finds moved/nano-written files
        //   3. the name template — the original best-effort convention
        // Code search is only consulted when provenance is absent (it's the
        // fallback rung, and a network call we can skip when we already know).
        let rule_id = rule.id;
        let id_hit = if valid_source_path(rule.source_path.as_deref()).is_some() {
            None
        } else {
            match client
                .find_file_by_rule_id(&target.repo_url, &rule_id.to_string())
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
            &target.path_template,
            &rule.name,
            rule_id,
        );
        tracing::info!(rule_id = %rule_id, %file_path, ?path_source, "resolved detection-as-code push target path");

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

        // Best-effort: tag the PR so it's filterable in GitHub. A repo without
        // the label, or a token lacking issues:write, must not fail a PR we've
        // already opened — the `nano-rule-id` body marker is the reliable link.
        if let Err(e) = client
            .add_labels(&target.repo_url, pr.number, &[NANO_TUNING_LABEL])
            .await
        {
            tracing::warn!(pr = pr.number, error = %e, "failed to label tuning PR (non-fatal)");
        }

        // Best-effort: record the PR on the target. A telemetry write failing
        // must not lose the PR we already opened.
        if let Err(e) = self.repo.mark_pr_opened(target.id, &pr.html_url).await {
            tracing::warn!(target_id = %target.id, error = %e, "failed to record last_pr_url on push target");
        }
        Ok(pr)
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
    !path.is_empty()
        && !path.starts_with('/')
        && !path.split('/').any(|seg| seg == "..")
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
    // Machine-readable link back to the rule (NAN-1764). Invisible in rendered
    // markdown; lets a future merge webhook match this PR to its rule.
    body.push_str(&format!("\n<!-- nano-rule-id: {} -->\n", rule.id));
    body
}

#[cfg(test)]
mod tests;
