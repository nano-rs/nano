// SPDX-License-Identifier: AGPL-3.0-or-later

//! Serialize a detection rule to the nano nPL file format (`---\n<yaml>\n---\n<query>`).
//!
//! Two paths, chosen by the push service:
//! - [`splice_query`] — the common case: the file already exists in the
//!   customer's repo, so we preserve their frontmatter **verbatim** and swap
//!   only the query body. This keeps tuning PR diffs to the single line that
//!   actually changed and never drops fields nano doesn't model.
//! - [`serialize_rule_to_npl`] — first-time creation: generate a full file from
//!   the DB rule.
//!
//! The `rule_format` seam on the target means a Sigma serializer can be added
//! here later without touching the push flow.

use serde::Serialize;
use thiserror::Error;

use crate::models::detection_rule::{AiTriageHints, DetectionMode, DetectionRule, Severity};

#[derive(Debug, Error)]
pub enum SerializeError {
    #[error("YAML serialization failed: {0}")]
    Yaml(#[from] serde_yaml::Error),
}

/// Frontmatter emitted for first-time file creation. Field set mirrors
/// `npl_parser::RawNplFrontmatter` so the file round-trips through pull-sync.
/// Owned rather than borrowed so `skip_serializing_if = "Vec::is_empty"` matches
/// (serde needs `Vec`, not a slice ref); serialization is once-per-PR so the
/// clones are cheap.
#[derive(Serialize)]
struct NplFrontmatterOut {
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    author: Option<String>,
    severity: &'static str,
    mode: String,
    detection_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    schedule: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    lookback: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mitre_tactics: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    mitre_techniques: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ai_triage_hints: Option<AiTriageHints>,
    #[serde(skip_serializing_if = "Option::is_none")]
    folder: Option<String>,
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Critical => "critical",
        Severity::High => "high",
        Severity::Medium => "medium",
        Severity::Low => "low",
        Severity::Informational => "informational",
    }
}

fn detection_mode_str(m: DetectionMode) -> &'static str {
    match m {
        DetectionMode::RealTime => "real-time",
        DetectionMode::Scheduled => "scheduled",
    }
}

fn hints_are_empty(h: &AiTriageHints) -> bool {
    h.ignore_when.is_empty() && h.suspicious_when.is_empty() && h.context.is_none()
}

/// Generate a complete nPL file from a detection rule, using `query` as the
/// body (the *proposed* tuned query — not `rule.query`, which is the current
/// DB value). Used when the target file doesn't exist yet.
pub fn serialize_rule_to_npl(rule: &DetectionRule, query: &str) -> Result<String, SerializeError> {
    let hints = &rule.ai_triage_hints.0;
    let fm = NplFrontmatterOut {
        title: rule.name.clone(),
        description: rule.description.clone(),
        author: rule.author.clone(),
        severity: severity_str(rule.severity),
        mode: rule.mode.to_string(),
        detection_mode: detection_mode_str(rule.detection_mode),
        schedule: rule.schedule_cron.clone(),
        lookback: rule.lookback_minutes.map(|m| format!("{m}m")),
        mitre_tactics: rule.mitre_tactics.clone(),
        mitre_techniques: rule.mitre_techniques.clone(),
        tags: rule.tags.clone(),
        ai_triage_hints: if hints_are_empty(hints) {
            None
        } else {
            Some(hints.clone())
        },
        folder: rule.folder.clone(),
    };
    let yaml = serde_yaml::to_string(&fm)?;
    // serde_yaml emits a trailing newline and no leading `---`.
    Ok(format!("---\n{}---\n{}\n", yaml, query.trim()))
}

/// Replace just the query body of an existing nPL file, keeping its frontmatter
/// byte-for-byte. Returns `None` if `existing` isn't in `---\n<yaml>\n---\n<body>`
/// form (caller then falls back to [`serialize_rule_to_npl`]).
pub fn splice_query(existing: &str, new_query: &str) -> Option<String> {
    let trimmed = existing.trim_start();
    let after_open = trimmed.strip_prefix("---")?;
    let after_open = after_open.strip_prefix('\n').unwrap_or(after_open);
    let end_idx = after_open.find("\n---")?;
    let frontmatter = &after_open[..end_idx];
    Some(format!("---\n{}\n---\n{}\n", frontmatter, new_query.trim()))
}

#[cfg(test)]
mod tests;
