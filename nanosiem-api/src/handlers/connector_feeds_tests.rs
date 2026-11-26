// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use nanosiem_core::log_sources::feed_lane_setup::hec_source_claims as hec_parser_claims;

#[test]
fn readiness_matches_hec_transport_and_claimed_lane() {
    let claims = vec!["okta".to_string()];
    assert!(hec_parser_claims("splunk_hec", "Okta parser", Some(&claims), "okta"));
    assert!(!hec_parser_claims("routed", "okta", Some(&claims), "okta"));
    assert!(!hec_parser_claims("splunk_hec", "Okta parser", Some(&claims), "slack_access_log"));
    assert!(hec_parser_claims("hec", "okta", None, "okta"));
    assert!(hec_parser_claims("splunk", "okta", Some(&[]), "okta"));
    assert!(!hec_parser_claims("splunk_hec", "Other", None, "okta"));
}

#[test]
fn create_request_cannot_select_spec_destination_or_backfill() {
    let body = serde_json::json!({"name": "fixture", "connector": "okta_system_log",
        "config": {"OKTA_DOMAIN": "fixture.okta.com"}, "credentials": {"API_TOKEN": "fixture"}});
    assert!(serde_json::from_value::<CreateConnectorFeed>(body.clone()).is_ok());
    for forbidden in ["tenant_id", "spec_yaml", "ingest_url", "ingest_token", "backfill_from", "source_type"] {
        let mut injected = body.clone();
        injected[forbidden] = "caller-controlled".into();
        assert!(serde_json::from_value::<CreateConnectorFeed>(injected).is_err(), "{forbidden}");
    }
}

#[test]
fn credential_id_is_a_credential_typeid() {
    let id = Uuid::now_v7();
    let ok = serde_json::json!({"name": "f", "connector": "okta_system_log",
        "credential_id": typeid::encode("cred", &id)});
    assert_eq!(serde_json::from_value::<CreateConnectorFeed>(ok).unwrap().credential_id, Some(id));
    let wrong = serde_json::json!({"name": "f", "connector": "okta_system_log",
        "credential_id": typeid::encode("srcfg", &id)});
    assert!(serde_json::from_value::<CreateConnectorFeed>(wrong).is_err());
}

#[test]
fn every_bundled_spec_is_listed_with_its_fields() {
    for s in first_party::SPECS {
        let plan = first_party::plan(s.slug).unwrap();
        assert!(!admin::credential_fields(&plan.spec).unwrap().is_empty(), "{}", s.slug);
        assert!(
            nanosiem_core::parsers::CONNECTOR_CREDENTIAL_PROVIDERS.contains(&s.credential_provider),
            "{} uses provider {} which migration 298 must admit",
            s.slug,
            s.credential_provider
        );
    }
}

#[test]
fn last_error_is_truncated_and_blank_is_none() {
    assert_eq!(truncate_error(Some("  ".into())), None);
    assert_eq!(truncate_error(Some("short".into())).as_deref(), Some("short"));
    let long = truncate_error(Some("é".repeat(1000))).unwrap();
    assert_eq!(long.chars().count(), LAST_ERROR_MAX_CHARS + 1);
}

fn key_with(perms: &[&str]) -> AuthContext {
    AuthContext::from_api_key(&nanosiem_core::auth::ApiKeyInfo {
        id: Uuid::now_v7(),
        name: "fixture".into(),
        permissions: perms.iter().map(|p| p.to_string()).collect(),
        user_id: Some(Uuid::now_v7()),
    })
}

/// NAN-4931 review: identity-feed mutations (create, pause/resume, reset,
/// delete) also need enrichments:configure; collector feeds do not.
#[test]
fn identity_feed_mutations_need_enrichments_configure() {
    let ops = key_with(&["log_sources:create", "log_sources:deploy", "log_sources:edit", "log_sources:delete"]);
    for connector in ["okta_users", "entra_directory"] {
        assert!(is_identity_connector(connector));
        assert!(ensure_identity_permission(&ops, connector).is_err(), "{connector}");
    }
    assert!(ensure_identity_permission(&ops, "okta_system_log").is_ok(), "a collector needs no enrichment permission");
    let admin = key_with(&["log_sources:edit", permissions::ENRICHMENTS_CONFIGURE]);
    assert!(ensure_identity_permission(&admin, "okta_users").is_ok());
}

/// NAN-5903: a start refused for lanes with no log source is structured, so
/// Pull feeds can answer it with Fix setup: code LOG_SOURCES_MISSING, the
/// lanes in `details.missing_lanes`, plain English in the message.
#[test]
fn missing_log_sources_refusal_is_structured() {
    let spec = first_party::get("google_workspace").unwrap();
    let err = log_sources_missing(spec, &["gws_admin".to_string(), "gws_saml".to_string()]);
    assert_eq!(err.code(), LOG_SOURCES_MISSING);
    match err {
        ApiError::BadRequestWithDetails { message, details, .. } => {
            assert!(message.starts_with("Some log sources this feed needs are missing"), "{message}");
            assert!(message.contains("`gws_admin`, `gws_saml`") && message.contains("Fix setup"), "{message}");
            assert!(!message.contains('\u{2014}'));
            assert_eq!(details["missing_lanes"], serde_json::json!(["gws_admin", "gws_saml"]));
            assert_eq!(details["connector"], "google_workspace");
        }
        other => panic!("{other:?}"),
    }
}

/// Resume and adopt take the consent flag; it defaults off.
#[test]
fn resume_and_adopt_take_the_setup_consent() {
    let r: SetConnectorFeedEnabled = serde_json::from_value(serde_json::json!({"enabled": true})).unwrap();
    assert!(!r.set_up_log_sources);
    let r: SetConnectorFeedEnabled =
        serde_json::from_value(serde_json::json!({"enabled": true, "set_up_log_sources": true})).unwrap();
    assert!(r.set_up_log_sources);
    assert!(!AdoptConnectorFeedSpec::default().set_up_log_sources);
    let a: AdoptConnectorFeedSpec = serde_json::from_value(serde_json::json!({"set_up_log_sources": true})).unwrap();
    assert!(a.set_up_log_sources);
    let c: CreateConnectorFeed =
        serde_json::from_value(serde_json::json!({"name": "f", "connector": "okta_system_log"})).unwrap();
    assert!(!c.set_up_log_sources, "consent is never implied");
}
