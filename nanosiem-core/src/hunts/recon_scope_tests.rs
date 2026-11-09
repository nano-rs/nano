// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5049 — recon responses are narrowed to the caller's source scope.
//!
//! Exploit shape: a narrow agent key (`hunts:profile_write`, no
//! `source_scopes:view_all`) is deny-all-restricted for search, yet the census /
//! surface / run / save responses carried every restricted source's name,
//! volume, sparkline, field population and host/account counts. These tests
//! pin the two pure narrowing points; the service calls them on every path.

use std::collections::{BTreeSet, HashMap};

use chrono::Utc;
use uuid::Uuid;

use super::*;
use crate::auth::{compose_viewer_scope, ArtifactScope, ScopeSet};

const RESTRICTED: &str = "hr_payroll";
const VISIBLE: &str = "syslog";

fn denied() -> BTreeSet<String> {
    BTreeSet::from([RESTRICTED.to_string()])
}

/// An agent key / analyst scope: denied the restricted source, no audit:view.
fn agent_scope() -> ScopeSet {
    compose_viewer_scope(&ScopeSet::from_denied(denied()), false)
}

fn facts_for(sources: &[&str]) -> CensusInputs {
    let mut inputs = CensusInputs {
        observed_at: Utc::now(),
        configured: sources.iter().map(|s| s.to_string()).collect(),
        required_by_hunts: sources.iter().map(|s| s.to_string()).collect(),
        stats: Some(HashMap::new()),
        events_24h: HashMap::new(),
        sparklines: HashMap::new(),
        deep: Some(HashMap::new()),
        history: Some(HashMap::new()),
    };
    for s in sources {
        inputs.events_24h.insert(s.to_string(), 42);
        inputs.sparklines.insert(s.to_string(), vec![1, 2, 3]);
        inputs
            .deep
            .as_mut()
            .unwrap()
            .insert(s.to_string(), DeepSourceFacts::default());
        inputs.history.as_mut().unwrap().insert(s.to_string(), Utc::now());
    }
    inputs
}

#[test]
fn census_inputs_drop_every_fact_about_a_denied_source() {
    let mut inputs = facts_for(&[RESTRICTED, VISIBLE, "audit"]);
    inputs.retain_visible(agent_scope().deny_set());

    for gone in [RESTRICTED, "audit"] {
        assert!(!inputs.configured.contains(gone), "{gone} still configured");
        assert!(!inputs.required_by_hunts.contains(gone));
        assert!(!inputs.events_24h.contains_key(gone));
        assert!(!inputs.sparklines.contains_key(gone));
        assert!(!inputs.deep.as_ref().unwrap().contains_key(gone));
        assert!(!inputs.history.as_ref().unwrap().contains_key(gone));
    }
    let rows = build_census(&inputs, false);
    assert!(rows.iter().all(|r| r.source_type != RESTRICTED && r.source_type != "audit"));
    // Legitimate: the visible source survives with all its facts.
    assert!(rows.iter().any(|r| r.source_type == VISIBLE));
    assert_eq!(inputs.events_24h.get(VISIBLE), Some(&42));
}

#[test]
fn an_unrestricted_caller_gets_the_full_census() {
    let mut inputs = facts_for(&[RESTRICTED, VISIBLE]);
    let before = build_census(&inputs, false).len();
    inputs.retain_visible(ScopeSet::unrestricted().deny_set());
    assert_eq!(build_census(&inputs, false).len(), before);
}

#[test]
fn deny_matching_is_case_and_whitespace_insensitive() {
    let mut inputs = facts_for(&[" HR_Payroll "]);
    inputs.retain_visible(&denied());
    assert!(inputs.configured.is_empty());
}

fn profile(source_types: &[&str], complete: bool) -> HuntProfile {
    HuntProfile {
        id: Uuid::now_v7(),
        census: serde_json::json!([{"source_type": RESTRICTED, "events_24h": 9000}]),
        fingerprint: serde_json::json!({"summary": "payroll exports nightly"}),
        huntable_surface: serde_json::json!({"tactics": []}),
        actor_weighting: serde_json::json!({}),
        degraded: false,
        degraded_detail: Some(format!("{RESTRICTED} unhealthy")),
        agent_notes: None,
        source_types: source_types.iter().map(|s| s.to_string()).collect(),
        source_types_complete: complete,
        generated_by: None,
        runner_id: None,
        created_at: Utc::now(),
    }
}

#[test]
fn a_profile_the_caller_cannot_read_is_returned_without_its_body() {
    let caller = ArtifactScope::from_scope(&agent_scope());
    let mut p = profile(&[RESTRICTED, VISIBLE], true);
    let id = p.id;
    redact_profile_for(&mut p, &caller);
    assert_eq!(p.id, id, "the stored id is still reported");
    assert_eq!(p.census, serde_json::json!([]));
    assert!(p.source_types.is_empty());
    assert!(p.degraded_detail.is_none());
    assert!(!serde_json::to_string(&p).unwrap().contains(RESTRICTED));

    // Incomplete manifests are not readable by a restricted caller either.
    let mut incomplete = profile(&[VISIBLE], false);
    redact_profile_for(&mut incomplete, &caller);
    assert!(incomplete.source_types.is_empty());
}

#[test]
fn readable_profiles_are_returned_unchanged() {
    // Restricted caller, profile disjoint from the deny set.
    let caller = ArtifactScope::from_scope(&agent_scope());
    let mut p = profile(&[VISIBLE], true);
    let before = serde_json::to_value(&p).unwrap();
    redact_profile_for(&mut p, &caller);
    assert_eq!(serde_json::to_value(&p).unwrap(), before);

    // Unrestricted caller sees everything.
    let admin = ArtifactScope::from_scope(&ScopeSet::unrestricted());
    let mut full = profile(&[RESTRICTED, VISIBLE], true);
    let before = serde_json::to_value(&full).unwrap();
    redact_profile_for(&mut full, &admin);
    assert_eq!(serde_json::to_value(&full).unwrap(), before);
}
