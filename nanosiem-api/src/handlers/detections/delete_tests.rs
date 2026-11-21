// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5672: the rule delete (archive) contract at the handler layer — the
//! audit record it writes, and the `include_archived` opt-in on
//! `GET /api/rules/{id}` that keeps a deleted rule a 404 by default.

use axum::extract::Query;
use axum::http::Uri;
use nanosiem_core::audit::{AuditSource, ClientContext, RULE_DELETED};
use nanosiem_core::auth::token::{DEFAULT_TOKEN_AUDIENCE, DEFAULT_TOKEN_ISSUER};
use nanosiem_core::auth::TokenClaims;
use nanosiem_core::models::detection_rule::RuleMode;
use uuid::Uuid;

use super::crud::rule_deleted_audit_event;
use super::types::GetDetectionQuery;
use crate::middleware::AuthContext;

fn auth() -> AuthContext {
    AuthContext::from_jwt(TokenClaims {
        iss: DEFAULT_TOKEN_ISSUER.to_string(),
        aud: DEFAULT_TOKEN_AUDIENCE.to_string(),
        sub: Uuid::now_v7(),
        roles: Vec::new(),
        permissions: vec![nanosiem_core::auth::permissions::DETECTIONS_DELETE.to_string()],
        exp: chrono::Utc::now().timestamp() + 60,
        iat: chrono::Utc::now().timestamp(),
        jti: Uuid::now_v7(),
        purpose: "access".to_string(),
    })
}

#[test]
fn rule_delete_writes_a_rule_deleted_audit_record() {
    let auth = auth();
    let client = ClientContext::new(Some("203.0.113.7".into()), Some("e2e".into()));
    let rule_id = Uuid::now_v7();

    let event = rule_deleted_audit_event(
        &auth,
        &client,
        rule_id,
        "brute_force_ssh".into(),
        Some(RuleMode::Alerting),
    );

    assert_eq!(event.action, RULE_DELETED);
    assert_eq!(event.source, AuditSource::Detection);
    assert_eq!(event.actor_id, Some(auth.user_id()));
    assert_eq!(event.resource_type.as_deref(), Some("detection_rule"));
    assert_eq!(event.resource_id, Some(rule_id));
    assert_eq!(event.resource_name.as_deref(), Some("brute_force_ssh"));
    assert_eq!(event.ip_address.as_deref(), Some("203.0.113.7"));
    assert!(event.success);
    let details = event.details.expect("details");
    assert_eq!(details["archived"], serde_json::json!(true), "the record says it was archived");
    assert_eq!(details["mode"], serde_json::json!("alerting"), "the mode it was deleted from");
}

fn get_query(uri: &str) -> GetDetectionQuery {
    let uri: Uri = uri.parse().unwrap();
    Query::<GetDetectionQuery>::try_from_uri(&uri).expect("query").0
}

#[test]
fn get_rule_hides_deleted_rules_unless_asked() {
    assert!(!get_query("/api/rules/rule_x").include_archived, "default: a deleted rule is a 404");
    assert!(!get_query("/api/rules/rule_x?include_archived=false").include_archived);
    assert!(get_query("/api/rules/rule_x?include_archived=true").include_archived);
}

/// Review P1-1: `PUT {"archived": true}` runs the delete teardown, so it may
/// not smuggle other edits (a mode change, a query) along with it.
#[test]
fn an_archive_request_carries_nothing_else() {
    use super::crud::ensure_archive_only;
    use nanosiem_core::UpdateDetectionRule;

    let archive = UpdateDetectionRule { archived: Some(true), ..Default::default() };
    assert!(ensure_archive_only(&archive).is_ok(), "the console's Archive action");
    let with_staging = UpdateDetectionRule {
        archived: Some(true),
        mode: Some(RuleMode::Staging),
        ..Default::default()
    };
    assert!(ensure_archive_only(&with_staging).is_ok(), "the archive parks it in staging anyway");
    for smuggled in [
        UpdateDetectionRule { archived: Some(true), mode: Some(RuleMode::Alerting), ..Default::default() },
        UpdateDetectionRule { archived: Some(true), query: Some("class_uid=1".into()), ..Default::default() },
    ] {
        assert!(ensure_archive_only(&smuggled).is_err(), "{smuggled:?}");
    }
}
