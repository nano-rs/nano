// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5005: CrowdStrike FDR source config validation and rendering.

use super::*;
use serde_json::json;

const QUEUE: &str = "https://sqs.us-west-2.amazonaws.com/123456789012/cs-mav-cannon-queue";

fn table(conn: serde_json::Value, creds: Option<serde_json::Value>) -> toml::Table {
    source_table("fdr_source", &conn, creds.as_ref()).expect("renders")
}

#[test]
fn empty_config_is_accepted_at_create_but_not_rendered() {
    validate_conn(&json!({})).unwrap();
    validate_conn(&serde_json::Value::Null).unwrap();
    let error = source_table("s", &json!({}), None).unwrap_err().to_string();
    assert!(error.contains("queue_url is required"), "{error}");
}

#[test]
fn rejects_bad_values_naming_the_field() {
    for (conn, needle) in [
        (json!({"queue_url": "not a url"}), "queue_url"),
        (json!({"queue_url": "ftp://sqs.us-west-2.amazonaws.com/1/q"}), "queue_url"),
        (json!({"queue_url": "https://sqs.us-west-2.amazonaws.com/"}), "queue_url"),
        (json!({"queue_url": 7}), "queue_url"),
        (json!({"endpoint": "localstack:4566"}), "endpoint"),
        (json!({"start_from": "yesterday"}), "start_from"),
        (json!({"checksum": "md5"}), "checksum"),
        (json!({"file_concurrency": 0}), "file_concurrency"),
        (json!({"file_concurrency": 65}), "file_concurrency"),
        (json!({"max_inflight_manifests": -1}), "max_inflight_manifests"),
        (json!({"visibility_timeout_secs": 43_201}), "visibility_timeout_secs"),
        (json!({"max_hold_secs": 43_201}), "max_hold_secs"),
        (json!({"max_inflight_bytes": 0}), "max_inflight_bytes"),
    ] {
        let error = validate_conn(&conn).unwrap_err().to_string();
        assert!(error.contains(needle), "{conn}: {error}");
    }
}

#[test]
fn accepts_every_start_from_form() {
    for start_from in ["beginning", "now", "cursor", "2026-11-01T00:00:00Z"] {
        validate_conn(&json!({"queue_url": QUEUE, "start_from": start_from})).unwrap();
    }
}

#[test]
fn defaults_hold_until_delivered_from_the_beginning() {
    let t = table(json!({"queue_url": QUEUE}), None);
    assert_eq!(t["type"].as_str(), Some("crowdstrike_fdr"));
    assert_eq!(t["queue_url"].as_str(), Some(QUEUE));
    // Region read from the queue URL when not given.
    assert_eq!(t["region"].as_str(), Some("us-west-2"));
    assert_eq!(t["start_from"].as_str(), Some("beginning"));
    assert_eq!(t["checksum"].as_str(), Some("verify"));
    assert_eq!(t["route_lookups"].as_bool(), Some(true));
    assert_eq!(t["acknowledgements"]["enabled"].as_bool(), Some(true));
    assert_eq!(t["decoding"]["codec"].as_str(), Some("bytes"));
    // Real AWS: access-point aliases are virtual-hosted (the fork default).
    assert!(t.get("force_path_style").is_none());
    assert!(t.get("framing").is_none(), "the fork's source has no framing option");
    // No credential: no auth block, so the deployment's ambient identity.
    assert!(t.get("auth").is_none());
    for key in ["file_concurrency", "max_inflight_manifests", "visibility_timeout_secs", "max_hold_secs", "max_inflight_bytes"] {
        assert!(t.get(key).is_none(), "{key} is left to the fork's default");
    }
}

#[test]
fn tuning_and_endpoint_are_rendered() {
    let t = table(
        json!({
            "queue_url": "http://localhost:4566/000000000000/fdr", "region": "us-east-1",
            "endpoint": "http://localhost:4566", "start_from": "now", "checksum": "warn",
            "file_concurrency": 8, "max_inflight_manifests": 16, "max_inflight_bytes": 1_073_741_824u64,
            "visibility_timeout_secs": 600, "max_hold_secs": 7200
        }),
        None,
    );
    assert_eq!(t["region"].as_str(), Some("us-east-1"));
    assert_eq!(t["endpoint"].as_str(), Some("http://localhost:4566"));
    assert_eq!(t["force_path_style"].as_bool(), Some(true));
    assert_eq!(t["start_from"].as_str(), Some("now"));
    assert_eq!(t["checksum"].as_str(), Some("warn"));
    assert_eq!(t["file_concurrency"].as_integer(), Some(8));
    assert_eq!(t["max_inflight_manifests"].as_integer(), Some(16));
    assert_eq!(t["max_inflight_bytes"].as_integer(), Some(1_073_741_824));
    assert_eq!(t["visibility_timeout_secs"].as_integer(), Some(600));
    assert_eq!(t["max_hold_secs"].as_integer(), Some(7200));
}

#[test]
fn region_falls_back_when_the_queue_url_has_none() {
    let t = table(json!({"queue_url": "https://queue.example.internal/1/fdr"}), None);
    assert_eq!(t["region"].as_str(), Some("us-west-2"));
    assert_eq!(region_from_queue_url(QUEUE).as_deref(), Some("us-west-2"));
    assert_eq!(
        region_from_queue_url("https://sqs.eu-central-1.amazonaws.com/1/q").as_deref(),
        Some("eu-central-1")
    );
    assert_eq!(region_from_queue_url("https://example.com/1/q"), None);
}

#[test]
fn static_keys_from_the_bound_credential() {
    let t = table(
        json!({"queue_url": QUEUE}),
        Some(json!({"access_key_id": "AKIAEXAMPLE", "secret_access_key": "example-secret"})),
    );
    let auth = t["auth"].as_table().expect("auth block");
    assert_eq!(auth["access_key_id"].as_str(), Some("AKIAEXAMPLE"));
    assert_eq!(auth["secret_access_key"].as_str(), Some("example-secret"));
    assert_eq!(auth["region"].as_str(), Some("us-west-2"));
    assert!(auth.get("assume_role").is_none());
}

#[test]
fn role_only_credential_assumes_the_role_from_ambient_identity() {
    let t = table(
        json!({"queue_url": QUEUE}),
        Some(json!({
            "assume_role_arn": "arn:aws:iam::123456789012:role/fdr-reader",
            "external_id": "nano-tenant"
        })),
    );
    let auth = t["auth"].as_table().expect("auth block");
    assert!(auth.get("access_key_id").is_none());
    assert_eq!(auth["assume_role"].as_str(), Some("arn:aws:iam::123456789012:role/fdr-reader"));
    assert_eq!(auth["external_id"].as_str(), Some("nano-tenant"));
    assert!(auth["session_name"].as_str().is_some_and(|s| !s.is_empty()));
}
