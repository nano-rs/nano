// SPDX-License-Identifier: AGPL-3.0-or-later

//! Unit tests for the NAN-1764 association cascade. `choose_target_path` is
//! pure (the code-search I/O is lifted into the caller and passed in as
//! `id_hit`), so every rung is exercised here without a GitHub round-trip.

use super::{choose_target_path, safe_repo_path, valid_source_path, PathSource};
use uuid::Uuid;

fn rule_id() -> Uuid {
    Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap()
}

const TEMPLATE: &str = "detections/{rule_name}.yaml";

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
    let (path, src) = choose_target_path(
        None,
        Some("../escape.yaml"),
        TEMPLATE,
        "Rule",
        rule_id(),
    );
    assert_eq!(path, "detections/Rule.yaml");
    assert_eq!(src, PathSource::Template);
    assert!(!safe_repo_path("../escape.yaml"));
    assert!(!safe_repo_path("/abs.yaml"));
    assert!(safe_repo_path("a/b/c.yaml"));
}
