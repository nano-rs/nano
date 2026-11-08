// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4914: credential providers for pull ingestion (Event Hubs source
//! configs and connector pull-feed vendor credentials).

use super::types::*;
use serde_json::json;

#[test]
fn pull_providers_are_supported_and_legacy_ones_are_not_creatable() {
    for p in ["aws_s3", "gcp_pubsub", "kafka", "smtp", "azure_event_hubs", "okta", "google_workspace", "slack", "saas_api"] {
        assert!(is_supported_credential_provider(p), "{p}");
    }
    for p in ["azure_blob", "splunk_hec", "", "OKTA"] {
        assert!(!is_supported_credential_provider(p), "{p}");
    }
    for p in CONNECTOR_CREDENTIAL_PROVIDERS {
        assert!(SUPPORTED_CREDENTIAL_PROVIDERS.contains(p), "{p}");
    }
}

/// The provider names inside the last `CHECK (provider IN (...))` of a migration.
fn constraint_providers(sql: &str) -> std::collections::BTreeSet<String> {
    let at = sql.rfind("CHECK (provider IN (").expect("provider check");
    let body = &sql[at..sql[at..].find("))").map(|e| at + e).unwrap()];
    body.split('\'').skip(1).step_by(2).map(str::to_string).collect()
}

#[test]
fn migration_298_is_exactly_the_union_the_application_admits() {
    let union = constraint_providers(include_str!("../../../migrations/postgres/298_cloud_credentials_provider_union.sql"));
    let rust: std::collections::BTreeSet<String> = SUPPORTED_CREDENTIAL_PROVIDERS
        .iter()
        .chain(LEGACY_CREDENTIAL_PROVIDERS)
        .map(|p| p.to_string())
        .collect();
    assert_eq!(union, rust);
    // 298 widens every earlier definition, so it is correct in any apply order.
    for (name, sql) in [
        ("091", include_str!("../../../migrations/postgres/091_cloud_credentials_provider_update.sql")),
        ("297", include_str!("../../../migrations/postgres/297_cloud_credentials_smtp_provider.sql")),
    ] {
        let earlier = constraint_providers(sql);
        assert!(earlier.is_subset(&union), "{name}: {earlier:?} not within {union:?}");
    }
    // No other migration of this branch redefines the constraint.
    let feeds = include_str!("../../../migrations/postgres/293_connector_feeds.sql");
    assert!(!feeds.contains("cloud_credentials_provider_check"));
}

#[test]
fn smtp_credentials_need_a_password() {
    assert!(validate_credential_payload("smtp", &json!({"password": "p"})).is_ok());
    assert!(validate_credential_payload("smtp", &json!({})).is_err());
}

#[test]
fn event_hubs_needs_a_connection_string_or_a_whole_service_principal() {
    assert!(validate_credential_payload("azure_event_hubs", &json!({"connection_string": "Endpoint=sb://x.servicebus.windows.net/"})).is_ok());
    assert!(validate_credential_payload(
        "azure_event_hubs",
        &json!({"azure_tenant_id": "t", "azure_client_id": "c", "azure_client_secret": "s"})
    )
    .is_ok());
    assert!(validate_credential_payload("azure_event_hubs", &json!({"azure_tenant_id": "t", "azure_client_id": "c"})).is_err());
    assert!(validate_credential_payload("azure_event_hubs", &json!({"connection_string": "  "})).is_err());
}

#[test]
fn existing_provider_rules_are_unchanged() {
    assert!(validate_credential_payload("aws_s3", &json!({"access_key_id": "a", "secret_access_key": "b"})).is_ok());
    assert!(validate_credential_payload("aws_s3", &json!({"assume_role_arn": "arn:aws:iam::1:role/r"})).is_ok());
    assert!(validate_credential_payload("aws_s3", &json!({"access_key_id": "a"})).is_err());
    assert!(validate_credential_payload("gcp_pubsub", &json!({})).is_err());
    assert!(validate_credential_payload("kafka", &json!({})).is_ok());
}

#[test]
fn connector_credentials_are_a_flat_map_of_non_empty_strings() {
    assert!(validate_credential_payload("okta", &json!({"API_TOKEN": "t"})).is_ok());
    assert!(validate_credential_payload("okta", &json!({})).is_err());
    assert!(validate_credential_payload("slack", &json!({"USER_TOKEN": ""})).is_err());
    assert!(validate_credential_payload("saas_api", &json!({"API_TOKEN": {"nested": 1}})).is_err());
    assert!(validate_credential_payload("saas_api", &json!(["API_TOKEN"])).is_err());
}

#[test]
fn google_workspace_key_file_is_split_into_the_two_fields_the_spec_reads() {
    let key = json!({
        "type": "service_account", "project_id": "p", "private_key_id": "k",
        "private_key": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n",
        "client_email": "sa@p.iam.gserviceaccount.com", "client_id": "1",
    });
    let mut payload = json!({"credentials_json": key.to_string()});
    normalize_credential_payload("google_workspace", &mut payload).unwrap();
    assert_eq!(payload["CLIENT_EMAIL"], "sa@p.iam.gserviceaccount.com");
    assert!(payload["PRIVATE_KEY"].as_str().unwrap().starts_with("-----BEGIN"));
    assert!(payload.get("credentials_json").is_none());
    assert!(payload.get("private_key_id").is_none());
    assert!(validate_credential_payload("google_workspace", &payload).is_ok());

    let mut bad = json!({"credentials_json": "{\"client_email\": \"x\"}"});
    assert!(normalize_credential_payload("google_workspace", &mut bad).is_err());
    // Other providers and payloads without a key file are untouched.
    let mut other = json!({"credentials_json": "{}"});
    normalize_credential_payload("gcp_pubsub", &mut other).unwrap();
    assert_eq!(other, json!({"credentials_json": "{}"}));
}
