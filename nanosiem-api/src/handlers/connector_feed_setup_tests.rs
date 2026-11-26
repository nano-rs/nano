// SPDX-License-Identifier: AGPL-3.0-or-later

use nanosiem_core::log_sources::feed_lane_setup::{LaneSetupOutcome, LaneSourceAction, LaneSourceOrigin, LaneSourceStep};

use super::*;

fn key() -> AuthContext {
    AuthContext::from_api_key(&nanosiem_core::auth::ApiKeyInfo {
        id: Uuid::now_v7(),
        name: "fixture".into(),
        permissions: vec!["log_sources:create".into()],
        user_id: Some(Uuid::now_v7()),
    })
}

fn step(action: LaneSourceAction, id: Uuid, lanes: &[&str], added: &[&str]) -> LaneSourceStep {
    LaneSourceStep {
        action,
        log_source_id: Some(id),
        log_source_name: format!("source {id}"),
        lanes: lanes.iter().map(|s| s.to_string()).collect(),
        added_lanes: added.iter().map(|s| s.to_string()).collect(),
        parser: (action != LaneSourceAction::Reuse).then(|| "google_workspace_ocsf".to_string()),
        origin: (action != LaneSourceAction::Reuse).then_some(LaneSourceOrigin::CatalogImport),
    }
}

/// NAN-5903: every source a setup creates is audited as a parser import and
/// a created log source (with the routing rule the import added); a widened
/// source as an update naming the values added; a reused one not at all.
#[test]
fn setup_audits_each_created_and_widened_source() {
    let (created, widened, reused, rule) = (Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7(), Uuid::now_v7());
    let outcome = LaneSetupOutcome {
        steps: vec![
            step(LaneSourceAction::Reuse, reused, &["gws_login"], &[]),
            step(LaneSourceAction::Create, created, &["gws_admin", "gws_saml"], &["gws_admin", "gws_saml"]),
            step(LaneSourceAction::Extend, widened, &["gws_groups"], &["gws_groups"]),
        ],
        routing_rule_id: Some(rule),
        withheld_values: vec!["gws_login".into()],
        deployed: true,
    };
    let auth = key();
    let events = setup_audit_events(&auth, &ClientContext::default(), &outcome, "google_workspace", "Workspace");
    let rows: Vec<(&str, Option<Uuid>)> = events.iter().map(|e| (e.action.as_str(), e.resource_id)).collect();
    assert_eq!(
        rows,
        vec![
            (PARSER_IMPORTED, None),
            (LOG_SOURCE_CREATED, Some(created)),
            (ROUTING_RULE_CREATED, Some(rule)),
            (LOG_SOURCE_UPDATED, Some(widened)),
        ]
    );
    for e in &events {
        assert_eq!(e.actor_id, Some(auth.user_id()));
        assert_eq!(e.api_key_id, auth.api_key_id, "API-key callers are attributed");
        assert_eq!(e.details.as_ref().unwrap()["source"], "connector_feed_setup");
    }
    let created_row = &events[1];
    assert_eq!(created_row.resource_type.as_deref(), Some("log_source"));
    let details = created_row.details.as_ref().unwrap();
    assert_eq!(details["feed"], "Workspace");
    assert_eq!(details["lanes"], serde_json::json!(["gws_admin", "gws_saml"]));
    assert_eq!(details["withheld_match_values"], serde_json::json!(["gws_login"]));
    assert_eq!(events[3].details.as_ref().unwrap()["match_values_added"], serde_json::json!(["gws_groups"]));
}

#[test]
fn nothing_set_up_audits_nothing() {
    let outcome = LaneSetupOutcome {
        steps: vec![step(LaneSourceAction::Reuse, Uuid::now_v7(), &["okta"], &[])],
        ..Default::default()
    };
    assert!(setup_audit_events(&key(), &ClientContext::default(), &outcome, "okta_system_log", "Okta").is_empty());
}

#[test]
fn messages_use_the_short_connector_name() {
    let gws = nano_connector::first_party::get("google_workspace").unwrap();
    assert_eq!(short_name(gws), "Google Workspace audit");
    let okta = nano_connector::first_party::get("okta_system_log").unwrap();
    assert_eq!(short_name(okta), "Okta System Log");
}

/// R2 P2-1: a connector-owned pull source is a plain log source: audited as
/// `log_source_created` under the log source trail, never as a parser import.
#[test]
fn a_pull_source_is_not_audited_as_a_parser_import() {
    let id = Uuid::now_v7();
    let mut created = step(LaneSourceAction::Create, id, &["okta"], &["okta"]);
    created.origin = Some(LaneSourceOrigin::PullSource);
    let outcome = LaneSetupOutcome { steps: vec![created], ..Default::default() };
    let events = setup_audit_events(&key(), &ClientContext::default(), &outcome, "okta_system_log", "Okta");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].action, LOG_SOURCE_CREATED);
    assert_eq!(events[0].resource_id, Some(id));
    assert!(matches!(events[0].source, AuditSource::LogSource));
    assert_eq!(events[0].details.as_ref().unwrap()["origin"], "pull_source");
}
