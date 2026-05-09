// SPDX-License-Identifier: AGPL-3.0-or-later

//! Adaptive playbook composer — turns a Shadow Investigator notebook trail into
//! a slash-command markdown doc that round-trips through
//! [`crate::playbooks::parser`]. The result is a stable doc suitable for
//! inserting as a `playbooks` row with `adaptive = TRUE`.

use serde_json::Value;

use crate::models::notebook::NotebookEntryWithCreator;

/// NAN-449 — Phase 5b: compose an adaptive playbook doc from Shadow
/// Investigator notebook entries.
///
/// Emits the same slash-command markdown shape the library's parser round-trips
/// (see `nanosiem-core/src/playbooks/parser.rs`).
pub fn compose_adaptive_playbook_doc(
    entries: &[NotebookEntryWithCreator],
    rule_name: Option<&str>,
) -> Option<String> {
    let shadow_entries: Vec<&NotebookEntryWithCreator> = entries
        .iter()
        .filter(|entry| entry.source.as_deref() == Some("shadow_investigation"))
        .collect();

    if shadow_entries.is_empty() {
        return None;
    }

    let title = shadow_entries
        .iter()
        .find_map(|entry| {
            if entry.entry_type == "ai_suggestion" {
                entry
                    .content
                    .get("pin_label")
                    .and_then(Value::as_str)
                    .map(|v| v.trim_start_matches("plan · ").to_string())
            } else {
                None
            }
        })
        .or_else(|| rule_name.map(ToString::to_string))
        .unwrap_or_else(|| "Adaptive · Shadow Investigator".to_string());

    let mut out = String::new();
    out.push_str(&format!("# {title}\n\n"));
    out.push_str("Agent-composed adaptive playbook from a live case investigation. ");
    out.push_str("Review the steps, prune what doesn't apply, then promote to the library.\n\n");

    // Phase 1 — establish state (queries + rule context)
    out.push_str("## Phase 1 · establish state\n\n");
    let mut phase1_count = 0usize;
    for entry in &shadow_entries {
        match entry.entry_type.as_str() {
            "search_executed" | "search_refined" | "ai_query" => {
                if let Some(q) = entry.content.get("query").and_then(Value::as_str) {
                    let q_trim = q.trim();
                    if !q_trim.is_empty() {
                        let label = entry
                            .content
                            .get("description")
                            .and_then(Value::as_str)
                            .unwrap_or("Run scoped query executed during investigation");
                        out.push_str(&format!("/query: {}\n", sanitize_line(label)));
                        out.push_str(&format!("  npl: {}\n\n", sanitize_value(q_trim)));
                        phase1_count += 1;
                    }
                }
            }
            _ => {}
        }
    }
    if phase1_count == 0 {
        out.push_str("/review: no automatic queries were captured — add manually as needed\n\n");
    }

    // Phase 2 — pivot + enrich (from pivot_suggestions + ai_suggestion)
    let has_pivots = shadow_entries
        .iter()
        .any(|e| e.entry_type == "pivot_suggestions");
    if has_pivots {
        out.push_str("## Phase 2 · pivot and enrich\n\n");
        for entry in &shadow_entries {
            if entry.entry_type == "pivot_suggestions" {
                if let Some(items) = entry.content.get("pivots").and_then(Value::as_array) {
                    for pivot in items.iter().take(6) {
                        let label = pivot
                            .get("label")
                            .or_else(|| pivot.get("reason"))
                            .and_then(Value::as_str)
                            .unwrap_or("Pivot on entity");
                        let field = pivot
                            .get("field")
                            .and_then(Value::as_str)
                            .unwrap_or("entity");
                        out.push_str(&format!("/pivot: {}\n", sanitize_line(label)));
                        out.push_str(&format!("  field: {}\n\n", sanitize_value(field)));
                    }
                }
            }
        }
    }

    // Phase 3 — decide (the review step)
    out.push_str("## Phase 3 · decide\n\n");
    out.push_str("/decision: is this case a true positive?\n");
    out.push_str("  options:\n    - true-positive\n    - false-positive\n    - needs-more-info\n");
    out.push_str("  note_required_on: needs-more-info\n\n");

    // Phase 4 — synthesize (ai_summary)
    if let Some(summary) = shadow_entries.iter().find_map(|e| {
        if e.entry_type == "ai_summary" {
            e.content
                .get("summary")
                .or_else(|| e.content.get("text"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        } else {
            None
        }
    }) {
        out.push_str("## Phase 4 · synthesize\n\n");
        out.push_str("/review: read the agent synthesis and confirm the story\n");
        let summary_clean = sanitize_value(summary.trim());
        out.push_str(&format!("  agent_summary: {summary_clean}\n\n"));
    }

    Some(out)
}

/// Escape characters that would break slash-command parsing when used as a
/// trailing value of a key on a step-body line.
fn sanitize_value(s: &str) -> String {
    // Strip newlines (body-level YAML-ish values are single-line); collapse
    // whitespace; trim to a reasonable cap so a giant summary doesn't bloat.
    let collapsed: String = s
        .chars()
        .map(|c| if c == '\n' || c == '\r' { ' ' } else { c })
        .collect();
    let trimmed = collapsed.split_whitespace().collect::<Vec<_>>().join(" ");
    if trimmed.len() > 280 {
        format!("{}…", &trimmed[..280])
    } else {
        trimmed
    }
}

/// Same, but for the label part of a `/kind: label` line.
fn sanitize_line(s: &str) -> String {
    sanitize_value(s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::notebook::NotebookEntryWithCreator;
    use chrono::Utc;
    use serde_json::json;
    use uuid::Uuid;

    fn mk_entry(kind: &str, content: serde_json::Value) -> NotebookEntryWithCreator {
        NotebookEntryWithCreator {
            id: Uuid::now_v7(),
            notebook_id: Uuid::now_v7(),
            entry_type: kind.to_string(),
            content,
            source_url: None,
            created_by: Uuid::now_v7(),
            created_at: Utc::now(),
            creator_name: Some("test".to_string()),
            merged_from_notebook_id: None,
            merged_from_notebook_title: None,
            original_created_at: None,
            source: Some("shadow_investigation".to_string()),
        }
    }

    #[test]
    fn compose_returns_none_when_no_shadow_entries() {
        assert!(compose_adaptive_playbook_doc(&[], None).is_none());
    }

    #[test]
    fn compose_emits_well_formed_markdown() {
        let entries = vec![
            mk_entry(
                "ai_suggestion",
                json!({
                    "suggestion_type": "rule_context",
                    "pin_label": "plan · Credential reuse probe",
                }),
            ),
            mk_entry(
                "search_executed",
                json!({
                    "query": "source_type=auth | stats count by user",
                    "description": "Pull 24h auth events for the suspect user",
                }),
            ),
            mk_entry(
                "ai_summary",
                json!({ "summary": "Likely offboarding gap: key active 3d post-termination." }),
            ),
        ];
        let doc = compose_adaptive_playbook_doc(&entries, Some("credential_reuse"))
            .expect("should compose");

        assert!(doc.starts_with("# Credential reuse probe"));
        assert!(doc.contains("## Phase 1 · establish state"));
        assert!(doc.contains("/query:"));
        assert!(doc.contains("npl: source_type=auth"));
        assert!(doc.contains("## Phase 3 · decide"));
        assert!(doc.contains("/decision:"));
        assert!(doc.contains("## Phase 4 · synthesize"));
        assert!(doc.contains("Likely offboarding gap"));
    }

    #[test]
    fn compose_survives_entries_without_queries() {
        let entries = vec![mk_entry(
            "ai_suggestion",
            json!({ "suggestion_type": "rule_context" }),
        )];
        let doc = compose_adaptive_playbook_doc(&entries, None).expect("should compose");
        assert!(doc.contains("no automatic queries were captured"));
    }

    #[test]
    fn compose_truncates_long_summaries() {
        let long = "a ".repeat(500);
        let entries = vec![mk_entry("ai_summary", json!({ "summary": long }))];
        let doc = compose_adaptive_playbook_doc(&entries, None).expect("should compose");
        // Truncated marker should appear; no single line should exceed a
        // reasonable cap.
        assert!(doc.contains('…'));
    }
}
