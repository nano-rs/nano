// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4907 (port of main's NAN-3806 lane tests): the shipped Vector lanes
//! route on the token, not on what the sender declares. Runs the real
//! `source_type_extract` (HTTP, 00-base.toml), `hec_normalize` (HEC,
//! 02-hec-source.toml) and `otlp_logs_prep` (03-otlp-source.toml) VRL with the
//! metadata the nano-rs/vector fork stamps for a matched `valid_tokens_file`
//! entry.

use std::time::Duration;

use serde_json::{json, Value};
use uuid::Uuid;

use super::{
    file_extra_entries, BindableSource, IngestTokenSettings, InstallTokenMode, TokenFileEntry,
    INSTALL_CREDENTIAL_ID, MULTIPLEX_ROUTE, PLATFORM_PULL_CREDENTIAL_ID,
};

const BASE: &str = include_str!("../../../config/vector/00-base.toml");
const HEC: &str = include_str!("../../../config/vector/02-hec-source.toml");
const OTLP: &str = include_str!("../../../config/vector/03-otlp-source.toml");

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

/// `program` with `get_env_var(NAME) ?? ""` resolved to `value` (the tests
/// substitute env lookups instead of mutating the process environment).
fn with_env(program: &str, name: &str, value: &str) -> String {
    let lookup = format!(r#"get_env_var("{name}") ?? """#);
    assert!(program.contains(&lookup), "program reads {name}");
    program.replace(&lookup, &format!("{value:?}"))
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
    // `metadata.source_type`. A body `claimed_source_type` is never trusted.
    for event in [
        json!({"message": "x", "X-Source-Type": "windows_sysmon", "source_type": "unknown"}),
        json!({"message": "x", "source_type": "windows_sysmon", "claimed_source_type": "forged"}),
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
        json!({"message": "x", "source_type": "apache_access", "claimed_source_type": "forged"}),
    ] {
        let (event, _) = kept(run(&program, event, Some((TOKEN, &route))));
        assert_eq!(event["source_type"], "apache_access");
        assert!(event.get("claimed_source_type").is_none(), "{event}");
    }
}

#[test]
fn http_listed_token_without_a_route_is_refused() {
    let program = transform_source(BASE, "source_type_extract");
    assert!(matches!(
        run(&program, json!({"message": "x", "source_type": "apache_access"}), Some((TOKEN, ""))),
        Outcome::Aborted
    ));
}

/// The platform pull credential and the install token in legacy multiplex
/// mode are listed with the multiplex route: their declared type routes.
#[test]
fn multiplex_credentials_keep_their_declared_type() {
    for id in [PLATFORM_PULL_CREDENTIAL_ID, INSTALL_CREDENTIAL_ID] {
        let id = id.to_string();
        let (event, _) = kept(run(
            &transform_source(BASE, "source_type_extract"),
            json!({"message": "x", "source_type": "okta"}),
            Some((&id, MULTIPLEX_ROUTE)),
        ));
        assert_eq!(event["source_type"], "okta");
        assert!(event.get("claimed_source_type").is_none());
        let (event, _) = kept(run(
            &transform_source(HEC, "hec_normalize"),
            json!({"message": "{\"a\":1}", "splunk_sourcetype": "okta"}),
            Some((&id, MULTIPLEX_ROUTE)),
        ));
        assert_eq!(event["source_type"], "okta");
    }
}

/// No credential stamp = the static install-token fallback (tokens file
/// missing). It fails closed unless the deployment explicitly opted in with
/// NANO_INGEST_STATIC_FALLBACK=true; then it is today's multiplex behaviour.
#[test]
fn unstamped_events_fail_closed_unless_the_static_fallback_is_explicit() {
    const FLAG: &str = "NANO_INGEST_STATIC_FALLBACK";
    let auth = with_env(&transform_source(BASE, "auth_check"), "VECTOR_AUTH_TOKEN", "install");
    let hec = transform_source(HEC, "hec_normalize");
    let event = json!({"message": "x", "X-Source-Type": "okta"});
    let hec_event = json!({"message": "raw", "splunk_sourcetype": "apache_access"});
    for off in ["", "false", "1"] {
        assert!(matches!(run(&with_env(&auth, FLAG, off), event.clone(), None), Outcome::Aborted), "{off:?}");
        assert!(matches!(run(&with_env(&hec, FLAG, off), hec_event.clone(), None), Outcome::Aborted), "{off:?}");
    }
    let (e, _) = kept(run(&with_env(&auth, FLAG, "true"), event.clone(), None));
    assert_eq!(e["source_type"], "okta");
    assert_eq!(e["auth_status"], "authenticated");
    let (e, _) = kept(run(&with_env(&hec, FLAG, "true"), hec_event, None));
    assert_eq!(e["source_type"], "apache_access");
    // A stamped event never depends on the flag.
    let (e, _) = kept(run(&with_env(&auth, FLAG, ""), event, Some((TOKEN, "apache_access"))));
    assert_eq!(e["auth_status"], "authenticated");
    // The source's static check accepts the install token only with the flag.
    let base = parse(BASE);
    let source = base["sources"]["http_ingest"]["auth"]["source"].as_str().unwrap();
    assert!(source.contains("static_fallback && auth_header == \"Bearer \" + expected_token"), "{source}");
}

/// NAN-4907 P1: the unauthenticated Vector-native listener never selects a
/// parser route; a declared type is kept only as `claimed_source_type`.
#[test]
fn vector_native_events_get_a_fixed_route() {
    const FLAG: &str = "NANO_VECTOR_NATIVE_TRUST_SOURCE_TYPE";
    let program = transform_source(include_str!("../../../config/vector/01-vector-source.toml"), "vector_auth");
    let event = json!({"message": "x", "source_type": "Windows_Sysmon", "claimed_source_type": "forged"});
    let (e, _) = kept(run(&with_env(&program, FLAG, ""), event.clone(), None));
    assert_eq!(e["source_type"], "vector_native");
    assert_eq!(e["claimed_source_type"], "windows_sysmon");
    let (e, _) = kept(run(&with_env(&program, FLAG, ""), json!({"message": "x"}), None));
    assert_eq!(e["source_type"], "vector_native");
    assert!(e.get("claimed_source_type").is_none());
    // Explicit opt-in for a trusted network: the declared type routes.
    let (e, _) = kept(run(&with_env(&program, FLAG, "true"), event, None));
    assert_eq!(e["source_type"], "windows_sysmon");
    assert!(e.get("claimed_source_type").is_none());
}

#[test]
fn hec_spoofed_sourcetype_lands_in_the_tokens_source() {
    let program = transform_source(HEC, "hec_normalize");
    let route = stamped_route("pan_traffic");
    for event in [
        json!({"message": "{\"msg\":\"x\"}", "splunk_sourcetype": "windows_sysmon"}),
        json!({"message": "raw line", "sourcetype": "windows_sysmon"}),
        // A payload key cannot smuggle a routing field back in.
        json!({"event": {"source_type": "windows_sysmon", "claimed_source_type": "y"}, "splunk_sourcetype": "windows_sysmon"}),
    ] {
        let (event, metadata) = kept(run(&program, event, Some((TOKEN, &route))));
        assert_eq!(event["source_type"], "pan_traffic", "{event}");
        assert_eq!(event["claimed_source_type"], "windows_sysmon");
        assert_eq!(event["auth_status"], "authenticated");
        assert_eq!(metadata["nano_credential_id"], TOKEN);
    }
    // No sourcetype at all: still the token's source.
    let (event, _) = kept(run(&program, json!({"message": "raw"}), Some((TOKEN, &route))));
    assert_eq!(event["source_type"], "pan_traffic");
    assert!(event.get("claimed_source_type").is_none());
}

#[test]
fn hec_listed_token_without_a_route_is_refused() {
    let program = transform_source(HEC, "hec_normalize");
    let event = json!({"message": "raw", "splunk_sourcetype": "apache_access"});
    assert!(matches!(run(&program, event, Some((TOKEN, ""))), Outcome::Aborted));
}

/// The sources read the hashed tokens file, and the HTTP source's static
/// fallback accepts only the install token (or the explicit unauthenticated
/// opt-in), never a literal placeholder.
#[test]
fn sources_read_the_tokens_file() {
    let base = parse(BASE);
    let http = &base["sources"]["http_ingest"];
    assert_eq!(
        http["valid_tokens_file"]["path"].as_str(),
        Some(super::DEFAULT_TOKENS_FILE)
    );
    let http_reload_secs = http["valid_tokens_file"]["reload_interval_secs"]
        .as_integer()
        .expect("HTTP token reload interval") as u64;
    assert_eq!(http_reload_secs, 2);
    assert!(
        super::service::SHARED_VOLUME_REMOVAL_SETTLE > Duration::from_secs(http_reload_secs),
        "the destructive API response must settle longer than Vector's HTTP token cache"
    );
    let auth = http["auth"]["source"].as_str().unwrap();
    assert!(auth.contains("auth_header == \"Bearer \" + expected_token"), "{auth}");
    assert!(auth.contains("allow_unauthenticated"), "{auth}");
    // The Authorization header is read by the source, never copied into events.
    let headers: Vec<&str> = http["headers"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|h| h.as_str())
        .collect();
    assert!(!headers.iter().any(|h| h.eq_ignore_ascii_case("authorization")), "{headers:?}");

    let hec = parse(HEC);
    let source = &hec["sources"]["splunk_hec_ingest"];
    assert_eq!(
        source["valid_tokens_file"]["path"].as_str(),
        Some(super::DEFAULT_TOKENS_FILE)
    );
    let hec_reload_secs = source["valid_tokens_file"]["reload_interval_secs"]
        .as_integer()
        .expect("HEC token reload interval") as u64;
    assert_eq!(hec_reload_secs, 2);
    assert!(
        super::service::SHARED_VOLUME_REMOVAL_SETTLE > Duration::from_secs(hec_reload_secs),
        "the destructive API response must settle longer than Vector's HEC token cache"
    );
    assert_eq!(
        source["valid_tokens"][0].as_str(),
        Some("${VECTOR_AUTH_TOKEN}")
    );
}

/// NAN-3646 (ported): `.message` is never left empty for a HEC payload.
#[test]
fn hec_normalize_message_for_string_object_and_missing_events() {
    let program = transform_source(HEC, "hec_normalize");
    let normalize = |log: Value| kept(run(&program, log, Some((TOKEN, "okta")))).0;
    let as_json = |event: &Value| -> Value {
        serde_json::from_str(event["message"].as_str().expect("message is a string")).unwrap()
    };

    assert_eq!(normalize(json!({"event": "raw line", "splunk_sourcetype": "okta"}))["message"], "raw line");

    // Object event with an explicit `message`: that message wins.
    let event = normalize(json!({"event": {"message": "m", "user": "a"}, "splunk_sourcetype": "okta"}));
    assert_eq!(event["message"], "m");

    // Object event still nested under `.event`: serialized whole.
    let payload = json!({"user": "alice", "action": "login", "nested": {"id": 7}});
    let event = normalize(json!({"event": payload, "splunk_sourcetype": "okta"}));
    assert_eq!(as_json(&event), payload);

    // Object event spread over the root: rebuilt from the root without the
    // HEC envelope, deterministically (key-sorted).
    let spread = json!({
        "user": "alice", "action": "login", "nested": {"id": 7},
        "splunk_sourcetype": "okta", "splunk_source": "s", "splunk_index": "main",
        "splunk_channel": "c", "host": "fwd-1", "source_type": "splunk_hec",
        "timestamp": "2026-10-18T00:00:00Z",
    });
    let event = normalize(spread.clone());
    assert_eq!(as_json(&event), payload);
    assert_eq!(
        event["message"],
        r#"{"action":"login","nested":{"id":7},"user":"alice"}"#,
        "key-sorted, byte-stable serialization"
    );
    let event = normalize(json!({"message": "", "user": "alice", "splunk_sourcetype": "okta"}));
    assert_eq!(as_json(&event), json!({"user": "alice"}));

    // A non-string `.message` is serialized, never dropped.
    let event = normalize(json!({"message": {"user": "alice"}, "splunk_sourcetype": "okta"}));
    assert_eq!(as_json(&event), json!({"user": "alice"}));

    // Missing event: only envelope fields, so the message stays empty.
    let event = normalize(json!({"splunk_sourcetype": "okta", "host": "fwd-1"}));
    assert_eq!(event["message"], "");
    assert_eq!(event["source_type"], "okta");
}

fn otlp_program(key: &str) -> String {
    with_env(&transform_source(OTLP, "otlp_logs_prep"), "NANO_OTLP_EDGE_KEY", key)
}

fn now_secs() -> i64 {
    chrono::Utc::now().timestamp()
}

#[test]
fn otlp_logs_use_edge_identity_and_bound_route() {
    let key = "edge-key";
    let program = otlp_program(key);
    let id = Uuid::parse_str(TOKEN).unwrap();
    let fresh = now_secs() + super::OTLP_ASSERTION_TTL_SECS;
    let assertion = super::otlp_identity_assertion(key, &id, "otlp_log", fresh).unwrap();
    let send = |route: &str, assertion: &str, program: &str| {
        kept(run(
            program,
            json!({"message": "x", "x-nano-credential-id": TOKEN,
                   "x-nano-source-route": route, "x-nano-identity-assertion": assertion,
                   "attributes": {"source_type": "forged"}}),
            None,
        ))
    };
    let (event, metadata) = send("otlp_log", &assertion, &program);
    assert_eq!(event["auth_status"], "authenticated");
    assert_eq!(event["source_type"], "otlp_log");
    assert_eq!(metadata["nano_credential_id"], TOKEN);
    assert!(event.get("x-nano-credential-id").is_none());
    assert!(event.get("x-nano-identity-assertion").is_none());

    // Forged / replayed identities keep honest provenance: no assertion, one
    // for another route, under another key, expired, too far in the future,
    // or malformed.
    let other_route = super::otlp_identity_assertion(key, &id, "apache_access", fresh).unwrap();
    let other_key = super::otlp_identity_assertion("install-token", &id, "otlp_log", fresh).unwrap();
    let expired = super::otlp_identity_assertion(key, &id, "otlp_log", now_secs() - 1).unwrap();
    let future = super::otlp_identity_assertion(key, &id, "otlp_log", now_secs() + 3600).unwrap();
    let mac_only = assertion.split_once('.').unwrap().1.to_string();
    for forged in ["", other_route.as_str(), other_key.as_str(), expired.as_str(), future.as_str(), mac_only.as_str(), "x.y"] {
        let (event, metadata) = send("otlp_log", forged, &program);
        assert_eq!(event["auth_status"], "otlp", "{forged}");
        assert_eq!(event["source_type"], "otlp_log");
        assert!(metadata.get("nano_credential_id").is_none());
    }
    // A valid assertion does not carry over to another route.
    let (event, _) = send("apache_access", &assertion, &program);
    assert_eq!(event["source_type"], "otlp_log");
    // Without an edge key nothing can be verified.
    let (event, _) = send("otlp_log", &assertion, &otlp_program(""));
    assert_eq!(event["auth_status"], "otlp");
}

fn source(route: &str) -> BindableSource {
    BindableSource {
        source_id: Uuid::from_u128(7),
        name: "Apache".into(),
        source_type: "routed".into(),
        route_key: route.into(),
        enabled: true,
        deployed: false,
    }
}

fn settings(enabled: bool, mode: InstallTokenMode) -> IngestTokenSettings {
    IngestTokenSettings {
        install_token_enabled: enabled,
        install_token_mode: mode,
        ..IngestTokenSettings::default()
    }
}

/// Which install-token entry nano renders in each mode.
#[test]
fn install_token_entries_by_mode() {
    let bound = source("apache_access");
    let sha = super::sha256_hex("install");

    // Legacy multiplex: listed as a multiplex credential (bound or not).
    for install_source in [None, Some(&bound)] {
        let entries = file_extra_entries(
            Some("install"),
            Some("platform"),
            &settings(true, InstallTokenMode::LegacyMultiplex),
            install_source,
        );
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].id, INSTALL_CREDENTIAL_ID);
        assert_eq!(entries[0].sha256, sha);
        assert_eq!(entries[0].route, MULTIPLEX_ROUTE);
    }

    // Strict and bound: routed on the bound source.
    let entries = file_extra_entries(
        Some("install"),
        Some("platform"),
        &settings(true, InstallTokenMode::Strict),
        Some(&bound),
    );
    assert_eq!(entries[0].id, INSTALL_CREDENTIAL_ID);
    assert_eq!(entries[0].route, "apache_access");
    assert_eq!(entries[1].id, PLATFORM_PULL_CREDENTIAL_ID);
    assert_eq!(entries[1].route, MULTIPLEX_ROUTE);
    assert_eq!(entries[1].sha256, super::sha256_hex("platform"));

    // Strict and unbound, or disabled in any mode: refused (not listed); the
    // platform pull credential stays.
    for entries in [
        file_extra_entries(Some("install"), Some("platform"), &settings(true, InstallTokenMode::Strict), None),
        file_extra_entries(Some("install"), Some("platform"), &settings(false, InstallTokenMode::Strict), Some(&bound)),
        file_extra_entries(Some("install"), Some("platform"), &settings(false, InstallTokenMode::LegacyMultiplex), None),
    ] {
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, PLATFORM_PULL_CREDENTIAL_ID);
    }
    // No install token and no platform credential: nothing to list.
    assert!(file_extra_entries(None, None, &settings(true, InstallTokenMode::LegacyMultiplex), Some(&bound)).is_empty());
    // NAN-4907 P1: the platform credential is its own secret. Without one
    // nothing is derived from the install token; one equal to the install
    // token is refused (it would hand legacy senders the multiplex route).
    let entries = file_extra_entries(Some("install"), None, &settings(true, InstallTokenMode::Strict), None);
    assert!(entries.is_empty());
    let entries = file_extra_entries(Some("install"), Some("install"), &settings(false, InstallTokenMode::Strict), None);
    assert!(entries.is_empty());
}

/// Line numbers of every bare `$name` Vector would env-interpolate in `text`.
fn bare_env_refs(text: &str) -> Vec<(usize, String)> {
    let mut hits = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let bytes = line.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] != b'$' {
                i += 1;
                continue;
            }
            match bytes.get(i + 1) {
                Some(b'$') => i += 2,
                Some(c) if c.is_ascii_alphanumeric() || *c == b'_' || *c == b'.' => {
                    hits.push((index + 1, line.trim().to_string()));
                    break;
                }
                _ => i += 1,
            }
        }
    }
    hits
}

/// The configs this change edits never gain a bare `$name` (Vector would
/// env-interpolate it, even in a comment, and refuse to start).
#[test]
fn edited_vector_configs_have_no_bare_env_refs() {
    for (name, text) in [("00-base", BASE), ("02-hec", HEC), ("03-otlp", OTLP)] {
        let hits = bare_env_refs(text);
        assert!(hits.is_empty(), "{name}: {hits:?}");
    }
}
