// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4935: gcp_pubsub credential shapes.

use serde_json::json;

use super::gcp_credentials::{
    classify_gcp_credentials_json, credentials_file_contents, validate_credential_source_with,
    validate_gcp_pubsub_payload, GcpCredentialKind, DEFAULT_WIF_FILE_ROOT,
};

const SECRET: &str = "1//SECRET-refresh-token";

fn authorized_user() -> serde_json::Value {
    json!({
        "type": "authorized_user",
        "client_id": "764086051850-x.apps.googleusercontent.com",
        "client_secret": "d-SECRET",
        "refresh_token": SECRET,
        "account": "",
        "universe_domain": "googleapis.com",
    })
}

fn service_account() -> serde_json::Value {
    json!({
        "type": "service_account",
        "project_id": "p",
        "private_key_id": "k",
        "private_key": "-----BEGIN PRIVATE KEY-----\nSECRET\n-----END PRIVATE KEY-----\n",
        "client_email": "sa@p.iam.gserviceaccount.com",
        "client_id": "1",
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/sa",
    })
}

fn external_account(source: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "external_account",
        "audience": "//iam.googleapis.com/projects/1/locations/global/workloadIdentityPools/p/providers/q",
        "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
        "token_url": "https://sts.googleapis.com/v1/token",
        "credential_source": source,
    })
}

fn payload(creds: &serde_json::Value) -> serde_json::Value {
    json!({ "credentials_json": creds.to_string() })
}

#[test]
fn authorized_user_adc_is_accepted_without_project_id() {
    assert_eq!(
        validate_gcp_pubsub_payload(&payload(&authorized_user())),
        Ok(GcpCredentialKind::AuthorizedUser)
    );
}

#[test]
fn service_account_key_still_accepted() {
    assert_eq!(
        validate_gcp_pubsub_payload(&payload(&service_account())),
        Ok(GcpCredentialKind::ServiceAccount)
    );
}

#[test]
fn external_account_file_and_url_sources_accepted() {
    for source in [
        json!({"file": "/var/run/secrets/nano-gcp-wif/token"}),
        json!({"url": "https://idp.example.com/token", "headers": {"Authorization": "Bearer x"},
               "format": {"type": "json", "subject_token_field_name": "access_token"}}),
    ] {
        assert_eq!(
            classify_gcp_credentials_json(&external_account(source).to_string()),
            Ok(GcpCredentialKind::ExternalAccount)
        );
    }
}

#[test]
fn external_account_unsupported_sources_refused() {
    for source in [
        json!({"environment_id": "aws1"}),
        json!({"executable": {"command": "x"}}),
        json!({"file": "/a", "url": "http://b"}),
        json!({}),
        json!({"file": "/a", "format": {"type": "json"}}),
    ] {
        assert!(classify_gcp_credentials_json(&external_account(source).to_string()).is_err());
    }
}

#[test]
fn impersonated_with_authorized_user_source_accepted() {
    let creds = json!({
        "type": "impersonated_service_account",
        "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa@p.iam.gserviceaccount.com:generateAccessToken",
        "source_credentials": authorized_user(),
        "delegates": [],
    });
    assert_eq!(
        classify_gcp_credentials_json(&creds.to_string()),
        Ok(GcpCredentialKind::ImpersonatedServiceAccount)
    );
    let mut bad = creds.clone();
    bad["source_credentials"] = service_account();
    assert!(classify_gcp_credentials_json(&bad.to_string()).is_err());
}

#[test]
fn missing_fields_are_named_and_values_never_echoed() {
    let mut creds = authorized_user();
    creds.as_object_mut().unwrap().remove("client_secret");
    let err = validate_gcp_pubsub_payload(&payload(&creds)).unwrap_err();
    assert!(err.contains("'client_secret'"), "{err}");
    assert!(!err.contains("SECRET"), "{err}");

    let mut sa = service_account();
    sa.as_object_mut().unwrap().remove("client_email");
    let err = validate_gcp_pubsub_payload(&payload(&sa)).unwrap_err();
    assert!(err.contains("'client_email'") && !err.contains("SECRET"), "{err}");
}

#[test]
fn malformed_payloads_refused() {
    assert!(validate_gcp_pubsub_payload(&json!({})).is_err());
    // An object instead of a string would be skipped by the deploy path.
    assert!(validate_gcp_pubsub_payload(&json!({"credentials_json": authorized_user()})).is_err());
    let err = validate_gcp_pubsub_payload(&json!({"credentials_json": format!("{{\"refresh_token\":\"{SECRET}\"")}))
        .unwrap_err();
    assert!(err.contains("not valid JSON") && !err.contains("SECRET"), "{err}");
    let err = classify_gcp_credentials_json(r#"{"type":"gdch_service_account"}"#).unwrap_err();
    assert!(err.contains("unsupported"), "{err}");
}

#[test]
fn non_google_endpoints_refused() {
    let mut ext = external_account(json!({"file": "/var/run/secrets/nano-gcp-wif/token"}));
    for (field, url) in [
        ("token_url", "https://attacker.example/v1/token"),
        ("token_url", "http://sts.googleapis.com/v1/token"),
        ("token_url", "https://sts.googleapis.com.evil.example/v1/token"),
        ("token_url", "https://142.250.64.10/v1/token"),
        ("service_account_impersonation_url", "https://attacker.example/x"),
        (
            "service_account_impersonation_url",
            "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/sa:signJwt",
        ),
    ] {
        let mut bad = ext.clone();
        bad[field] = url.into();
        let err = classify_gcp_credentials_json(&bad.to_string()).unwrap_err();
        assert!(err.contains(field), "{url}: {err}");
    }
    // Regional STS is still Google.
    ext["token_url"] = "https://sts.us-east1.rep.googleapis.com/v1/token".into();
    assert!(classify_gcp_credentials_json(&ext.to_string()).is_ok());

    let mut au = authorized_user();
    au["token_uri"] = "https://attacker.example/token".into();
    assert!(classify_gcp_credentials_json(&au.to_string()).unwrap_err().contains("token_uri"));
    let mut sa = service_account();
    sa["token_uri"] = "http://attacker.example/token".into();
    assert!(classify_gcp_credentials_json(&sa.to_string()).unwrap_err().contains("token_uri"));
}

#[test]
fn credential_source_files_confined_to_the_wif_root() {
    for path in [
        "/proc/self/environ",
        "/dev/zero",
        "/var/run/secrets/kubernetes.io/serviceaccount/token",
        "/var/run/secrets/nano-gcp-wif/../kubernetes.io/serviceaccount/token",
        "/var/run/secrets/nano-gcp-wif-evil/token",
        "token",
    ] {
        assert!(
            validate_credential_source_with(&json!({"file": path}), DEFAULT_WIF_FILE_ROOT, false)
                .is_err(),
            "{path} accepted"
        );
    }
    assert!(validate_credential_source_with(
        &json!({"file": "/var/run/secrets/nano-gcp-wif/token"}),
        DEFAULT_WIF_FILE_ROOT,
        false
    )
    .is_ok());
    // An operator who points the root at /dev opts in explicitly.
    assert!(validate_credential_source_with(&json!({"file": "/dev/zero"}), "/dev", false).is_ok());
}

#[test]
fn credential_source_urls_need_https_public_dns_or_metadata_opt_in() {
    let metadata = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity";
    for url in [
        "http://idp.example.com/token",
        "https://10.0.0.5/token",
        "https://127.0.0.1/token",
        "https://169.254.169.254/token",
        metadata,
    ] {
        assert!(
            validate_credential_source_with(&json!({"url": url}), DEFAULT_WIF_FILE_ROOT, false)
                .is_err(),
            "{url} accepted"
        );
    }
    assert!(
        validate_credential_source_with(&json!({"url": metadata}), DEFAULT_WIF_FILE_ROOT, true)
            .is_ok()
    );
    assert!(validate_credential_source_with(
        &json!({"url": "https://idp.example.com/token"}),
        DEFAULT_WIF_FILE_ROOT,
        false
    )
    .is_ok());
}

#[test]
fn generation_fails_closed_on_legacy_payloads() {
    // Source generation writes exactly what this returns and refuses on Err,
    // so these never deploy a source without credentials_path.
    for legacy in [
        json!({"credentials_json": null}),
        json!({}),
        json!({"credentials_json": ""}),
        json!({"credentials_json": {"type": "authorized_user"}}),
        json!({"credentials_json": "{\"type\":\"gdch_service_account\"}"}),
    ] {
        assert!(credentials_file_contents(&legacy).is_err(), "{legacy}");
    }
    let good = payload(&authorized_user());
    assert_eq!(
        credentials_file_contents(&good).unwrap(),
        good["credentials_json"].as_str().unwrap()
    );
}
