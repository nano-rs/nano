// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5789: which fetch sources a render leaves out, and how that is shown.

use std::collections::HashSet;

use uuid::Uuid;

use super::*;
use crate::system_health::{HealthCategory, HealthSeverity};

fn parser(name: &str, source_type: &str, binding: Option<Uuid>, route: Option<&str>) -> Parser {
    let at = chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap();
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: name.to_string(),
        description: None,
        source_type: source_type.to_string(),
        parser_vrl: ".a = 1".to_string(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: binding,
        dispatch_route_name: route.map(str::to_string),
        enabled: true,
        validated: true,
        validation_error: None,
        category: None,
        vendor: None,
        product: None,
        kind: "log".to_string(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        match_values: Some(vec![name.to_string()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        created_at: at,
        updated_at: at,
    }
}

fn set(routes: &[&str]) -> HashSet<String> {
    routes.iter().map(|r| r.to_string()).collect()
}

#[test]
fn every_reason_a_fetch_source_is_left_out_is_named() {
    let missing = Uuid::new_v4();
    let mut enrichment = parser("enrich", "kafka", None, None);
    enrichment.kind = "enrichment".to_string();
    let mut draft = parser("draft", "aws_s3", None, None);
    draft.enabled = false;
    let parsers = vec![
        parser("live_ok", "kafka", Some(Uuid::new_v4()), Some("prod_route")),
        parser("unbound", "kafka", None, None),
        parser("config_deleted", "gcp_pubsub", Some(missing), None),
        parser("config_undeployed", "azure_event_hubs", Some(Uuid::new_v4()), Some("gone_route")),
        parser("shouting", "KAFKA", None, None),
        parser("routed", "routed", None, None),
        parser("routed_with_pull_pick", "routed", Some(Uuid::new_v4()), Some("gone_route")),
        enrichment,
        draft,
    ];
    let out = classify(&parsers, Some(&set(&["prod_route"])));
    let names: Vec<&str> = out.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(names, ["unbound", "config_deleted", "config_undeployed", "shouting", "draft"]);
    assert_eq!(out[0].reason, UnroutedReason::Unbound);
    assert_eq!(out[1].reason, UnroutedReason::ConfigMissing(missing));
    assert_eq!(out[2].reason, UnroutedReason::RouteNotDeployed("gone_route".into()));
    assert!(!out[4].enabled, "a disabled draft is reported, but not as live");
    for u in &out {
        assert!(u.note.starts_with(SOURCE_CONFIG_NOTE_PREFIX), "{}", u.note);
        assert!(u.note.contains("ingests nothing"), "{}", u.note);
    }
    assert!(out[1].note.contains("no longer exists"), "{}", out[1].note);
    assert!(out[2].note.contains("is not deployed"), "{}", out[2].note);
}

#[test]
fn without_disk_knowledge_only_binding_problems_are_reported() {
    // Boot renders the parser tree before the source configurations, so a
    // route missing on disk then says nothing about whether it is deployed.
    let parsers = vec![
        parser("config_undeployed", "kafka", Some(Uuid::new_v4()), Some("gone_route")),
        parser("unbound", "kafka", None, None),
    ];
    let out = classify(&parsers, None);
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].name, "unbound");
}

#[test]
fn a_live_source_left_out_raises_a_high_log_source_condition() {
    let p = parser(&"x".repeat(400), "kafka", None, None);
    let u = classify(std::slice::from_ref(&p), Some(&HashSet::new())).remove(0);
    let event = health_event(&u);
    assert_eq!(event.severity, HealthSeverity::High);
    assert_eq!(event.category, HealthCategory::LogSource);
    assert_eq!(event.dedup_key, health_dedup_key(p.id));
    assert_eq!(event.resource_id.as_deref(), Some(p.id.to_string().as_str()));
    assert!(event.title.len() <= 300, "a long name must not make the event unpublishable");
    assert_eq!(event.summary, u.note);
    assert_eq!(event.diagnostic_context["reason"], "unbound");
    assert!(event.remediation.is_some());
}

#[test]
fn report_modes_say_what_each_caller_can_vouch_for() {
    assert!(ReportMode::FULL.check_routes_on_disk && ReportMode::FULL.health);
    assert!(!ReportMode::BINDINGS.check_routes_on_disk && ReportMode::BINDINGS.health);
    assert!(!ReportMode::BINDINGS_NOTES.check_routes_on_disk && !ReportMode::BINDINGS_NOTES.health);
}
