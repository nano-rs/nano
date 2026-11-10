// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5223: editing a custom collector definition so its code could send the
//! connections' stored credentials elsewhere requires `credentials:edit`.

use super::*;

fn stored() -> CustomCollectorDefinitionResponse {
    CustomCollectorDefinitionResponse {
        id: Uuid::now_v7(),
        slug: "custom-acme".to_string(),
        name: "Acme".to_string(),
        description: None,
        code: "export default async function collect() {}".to_string(),
        allowed_domains: vec!["api.acme.example".to_string(), "auth.acme.example".to_string()],
        allowed_domain_suffixes: vec![],
        credential_fields: vec![],
        config_fields: vec![],
        auth_type: Some("oauth2_client_credentials".to_string()),
        auth: Some(ManifestAuth {
            token_url: Some("https://auth.acme.example/token".to_string()),
            ..Default::default()
        }),
        streams: vec![],
        poll_schedule: "0 */15 * * * *".to_string(),
        max_run_secs: 60,
        max_events_per_emit: 100,
        max_events_per_run: 1000,
        max_bytes_per_run: 1024,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

fn same_as(existing: &CustomCollectorDefinitionResponse) -> CustomCollectorDefinitionRequest {
    CustomCollectorDefinitionRequest {
        name: "Acme renamed".to_string(),
        description: Some("new description".to_string()),
        code: existing.code.clone(),
        // Reordered and re-cased: the same host set.
        allowed_domains: vec!["AUTH.acme.example".to_string(), "api.acme.example".to_string()],
        allowed_domain_suffixes: existing.allowed_domain_suffixes.clone(),
        credential_fields: vec![],
        config_fields: vec![],
        auth_type: existing.auth_type.clone(),
        auth: existing.auth.clone(),
        streams: vec![],
        poll_schedule: "0 0 * * * *".to_string(),
    }
}

#[test]
fn non_destination_edits_are_not_a_retarget() {
    let existing = stored();
    assert!(!collector_destination_changed(&existing, &same_as(&existing)));
}

#[test]
fn code_domain_suffix_and_auth_changes_are_a_retarget() {
    let existing = stored();

    let mut code = same_as(&existing);
    code.code.push_str("\n// changed");
    assert!(collector_destination_changed(&existing, &code));

    let mut domains = same_as(&existing);
    domains.allowed_domains.push("collector.other.example".to_string());
    assert!(collector_destination_changed(&existing, &domains));

    let mut suffixes = same_as(&existing);
    suffixes.allowed_domain_suffixes = vec![".other.example".to_string()];
    assert!(collector_destination_changed(&existing, &suffixes));

    let mut token = same_as(&existing);
    token.auth = Some(ManifestAuth {
        token_url: Some("https://auth.other.example/token".to_string()),
        ..Default::default()
    });
    assert!(collector_destination_changed(&existing, &token));
}

#[test]
fn retarget_with_stored_credentials_requires_credentials_edit() {
    let err = ensure_collector_retarget(true, true, false).unwrap_err();
    match err {
        ApiError::Forbidden(msg) => assert!(msg.contains("credentials:edit"), "{msg}"),
        other => panic!("expected 403, got {other:?}"),
    }
    assert!(ensure_collector_retarget(true, true, true).is_ok());
}

#[test]
fn no_stored_credentials_or_no_retarget_is_unchanged() {
    assert!(ensure_collector_retarget(true, false, false).is_ok());
    assert!(ensure_collector_retarget(false, true, false).is_ok());
}
