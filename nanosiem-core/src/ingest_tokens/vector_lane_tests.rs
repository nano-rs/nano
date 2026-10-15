// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3806: the shipped Vector lanes route on the token, not on what the
//! sender declares. Runs the real `source_type_extract` (HTTP, 00-base.toml)
//! and `hec_normalize` (HEC, 02-hec-source.toml) VRL with the metadata the
//! nano-rs/vector fork stamps for a matched `valid_tokens_file` entry.

use serde_json::{json, Value};
use uuid::Uuid;

use super::{TokenFileEntry, PLATFORM_PULL_CREDENTIAL_ID, PLATFORM_PULL_ROUTE};

const BASE: &str = include_str!("../../../config/vector/00-base.toml");
const HEC: &str = include_str!("../../../config/vector/02-hec-source.toml");

/// Parses a shipped config after Vector's `${VAR:-default}` substitution
/// (unquoted numeric defaults are not TOML until substituted).
fn parse(config: &str) -> toml::Table {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(config, "$1");
    substituted.parse().expect("config parses")
}

fn transform_source(config: &str, name: &str) -> String {
    let table = parse(config);
    table["transforms"][name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a VRL source"))
        .to_string()
}

enum Outcome {
    Kept { event: Value, metadata: Value },
    Aborted,
}

/// Runs `program` over `event` with the fork's credential stamp in metadata.
fn run(program: &str, event: Value, stamp: Option<(&str, &str)>) -> Outcome {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|diagnostics| panic!("VRL compiles: {diagnostics:?}"))
        .program;
    let mut metadata = serde_json::Map::new();
    if let Some((id, route)) = stamp {
        metadata.insert("nano_credential_id".into(), json!(id));
        metadata.insert("nano_credential_name".into(), json!(route));
    }
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(event),
        metadata: vrl::value::Value::from(Value::Object(metadata)),
        secrets: vrl::value::Secrets::new(),
    };
    match vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
    {
        Ok(_) => Outcome::Kept {
            event: target.value.try_into().expect("event is JSON"),
            metadata: target.metadata.try_into().expect("metadata is JSON"),
        },
        Err(vrl::compiler::runtime::Terminate::Abort(_)) => Outcome::Aborted,
        Err(error) => panic!("VRL runtime error: {error:?}"),
    }
}

fn kept(outcome: Outcome) -> (Value, Value) {
    match outcome {
        Outcome::Kept { event, metadata } => (event, metadata),
        Outcome::Aborted => panic!("event was refused"),
    }
}

const TOKEN: &str = "0b9a3c34-4cbb-4c1e-9d0f-6a3bd1f0f7e1";

/// The route the fork stamps is what nano renders into the file.
fn stamped_route(route: &str) -> String {
    let entry = TokenFileEntry {
        sha256: "0".repeat(64),
        id: Uuid::parse_str(TOKEN).unwrap(),
        route: route.into(),
    };
    let rendered: Value =
        serde_json::from_str(&super::render_tokens_file(&[entry], false)).unwrap();
    rendered["tokens"][0]["name"].as_str().unwrap().to_string()
}

#[test]
fn http_spoofed_source_type_lands_in_the_tokens_source() {
    let program = transform_source(BASE, "source_type_extract");
    let route = stamped_route("apache_access");
    // Every way an HTTP sender can declare a type: the X-Source-Type header,
    // a body `source_type` (merged to `.source_type` by parse_content), and
    // `metadata.source_type`.
    for event in [
        json!({"message": "x", "X-Source-Type": "windows_sysmon", "source_type": "unknown"}),
        json!({"message": "x", "source_type": "windows_sysmon"}),
        json!({"message": "x", "source_type": "unknown", "metadata": {"source_type": "windows_sysmon"}}),
    ] {
        let (event, metadata) = kept(run(&program, event, Some((TOKEN, &route))));
        assert_eq!(event["source_type"], "apache_access", "{event}");
        assert_eq!(metadata["source_type"], "apache_access");
        assert_eq!(event["claimed_source_type"], "windows_sysmon", "raw claim kept");
    }
    // No claim, or the right one: no claimed_source_type noise.
    for event in [
        json!({"message": "x", "source_type": "unknown"}),
        json!({"message": "x", "source_type": "apache_access"}),
    ] {
        let (event, _) = kept(run(&program, event, Some((TOKEN, &route))));
        assert_eq!(event["source_type"], "apache_access");
        assert!(event.get("claimed_source_type").is_none(), "{event}");
    }
}

#[test]
fn http_listed_token_without_a_route_is_refused() {
    let program = transform_source(BASE, "source_type_extract");
    for route in ["", "*"] {
        assert!(matches!(
            run(&program, json!({"message": "x", "source_type": "apache_access"}), Some((TOKEN, route))),
            Outcome::Aborted
        ));
    }
}

#[test]
fn platform_pull_credential_keeps_its_declared_type() {
    let platform = PLATFORM_PULL_CREDENTIAL_ID.to_string();
    for config in [BASE, HEC] {
        assert!(config.contains(&platform), "the lanes key on {platform}");
    }
    let program = transform_source(BASE, "source_type_extract");
    let (event, _) = kept(run(
        &program,
        json!({"message": "x", "source_type": "okta"}),
        Some((&platform, PLATFORM_PULL_ROUTE)),
    ));
    assert_eq!(event["source_type"], "okta");
    let (event, _) = kept(run(
        &transform_source(HEC, "hec_normalize"),
        json!({"event": {"a": 1}, "splunk_sourcetype": "okta"}),
        Some((&platform, PLATFORM_PULL_ROUTE)),
    ));
    assert_eq!(event["source_type"], "okta");
}

#[test]
fn hec_spoofed_sourcetype_lands_in_the_tokens_source() {
    let program = transform_source(HEC, "hec_normalize");
    let route = stamped_route("pan_traffic");
    for event in [
        json!({"event": {"msg": "x"}, "splunk_sourcetype": "windows_sysmon"}),
        json!({"event": "raw line", "sourcetype": "windows_sysmon"}),
        // A payload key cannot smuggle a routing field back in.
        json!({"event": {"source_type": "windows_sysmon", "claimed_source_type": "y"}, "splunk_sourcetype": "windows_sysmon"}),
    ] {
        let (event, metadata) = kept(run(&program, event, Some((TOKEN, &route))));
        assert_eq!(event["source_type"], "pan_traffic", "{event}");
        assert_eq!(metadata["source_type"], "pan_traffic");
        assert_eq!(event["claimed_source_type"], "windows_sysmon");
        assert_eq!(event["auth_status"], "authenticated");
    }
    // No sourcetype at all: still the token's source.
    let (event, _) = kept(run(&program, json!({"event": "raw"}), Some((TOKEN, &route))));
    assert_eq!(event["source_type"], "pan_traffic");
    assert!(event.get("claimed_source_type").is_none());
}

#[test]
fn hec_unbound_or_unstamped_token_is_refused() {
    let program = transform_source(HEC, "hec_normalize");
    let event = json!({"event": "raw", "splunk_sourcetype": "apache_access"});
    for route in ["", "*"] {
        assert!(matches!(run(&program, event.clone(), Some((TOKEN, route))), Outcome::Aborted));
    }
    // No credential stamp = the static `valid_tokens` fallback, which nano-api
    // turns off whenever an install token is set. Without the explicit
    // unauthenticated opt-in (unset in tests) nothing routes by sourcetype.
    assert!(matches!(run(&program, event, None), Outcome::Aborted));
}

#[test]
fn http_source_auth_never_accepts_a_static_token() {
    // The source's static `auth` fallback: true only for the explicit
    // unauthenticated opt-in with no install token, never for a bearer.
    let table = parse(BASE);
    let source = table["sources"]["http_ingest"]["auth"]["source"].as_str().unwrap();
    assert!(!source.contains("auth_header"), "{source}");
    assert!(source.contains("expected_token == \"\" && allow_unauthenticated"));
}
