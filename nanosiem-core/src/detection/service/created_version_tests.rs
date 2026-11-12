// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5315: creating a rule wrote no version, so the created state was never
//! recoverable and the first edit became v1. Building a `DetectionService`
//! needs both Postgres and ClickHouse, so this guard pins the wiring
//! structurally: every create path in `rules.rs` records the initial version
//! before it returns the new rule.

const SOURCE: &str = include_str!("rules.rs");

fn fn_body(name: &str) -> &'static str {
    let start = SOURCE
        .find(&format!("pub async fn {name}("))
        .unwrap_or_else(|| panic!("{name} exists"));
    let rest = &SOURCE[start + 1..];
    let end = rest
        .find("\n    pub async fn ")
        .map(|i| start + 1 + i)
        .unwrap_or(SOURCE.len());
    &SOURCE[start..end]
}

#[test]
fn every_create_path_records_initial_version() {
    for name in ["create_rule", "create_rule_with_mode"] {
        let body = fn_body(name);
        let creates = body.matches("self.rule_repo.create(").count();
        assert!(creates > 0, "{name} creates a rule");
        // Each successful create path returns through one recording call:
        // create_rule has a stash-archive return plus the normal return;
        // create_rule_with_mode has the real-time (after MV attach) and
        // scheduled returns.
        let records = body.matches("self.record_created_version(").count();
        assert_eq!(
            records, 2,
            "{name}: every successful create return must record v1 (NAN-5315)"
        );
    }
}

#[test]
fn initial_version_uses_initial_creation_reason() {
    let start = SOURCE
        .find("async fn record_created_version(")
        .expect("record_created_version exists");
    let body = &SOURCE[start..start + 400];
    assert!(body.contains("VersionChangeReason::InitialCreation"));
    assert_eq!(
        crate::tuning::types::VersionChangeReason::InitialCreation.to_string(),
        "initial_creation"
    );
}
