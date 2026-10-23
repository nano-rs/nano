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
        json!({"message": "{\"a\":1}", "splunk_sourcetype": "okta"}),
        Some((&platform, PLATFORM_PULL_ROUTE)),
    ));
    assert_eq!(event["source_type"], "okta");
}

#[test]
fn hec_spoofed_sourcetype_lands_in_the_tokens_source() {
    let program = transform_source(HEC, "hec_normalize");
    let route = stamped_route("pan_traffic");
    for event in [
        json!({"message": "{\"msg\":\"x\"}", "splunk_sourcetype": "windows_sysmon"}),
        json!({"message": "raw line", "sourcetype": "windows_sysmon"}),
        // A payload key cannot smuggle a routing field back in.
        json!({"message": "{\"source_type\":\"windows_sysmon\",\"claimed_source_type\":\"y\"}", "splunk_sourcetype": "windows_sysmon"}),
    ] {
        let (event, metadata) = kept(run(&program, event, Some((TOKEN, &route))));
        assert_eq!(event["source_type"], "pan_traffic", "{event}");
        assert_eq!(metadata["source_type"], "pan_traffic");
        assert_eq!(event["claimed_source_type"], "windows_sysmon");
        assert_eq!(event["auth_status"], "authenticated");
    }
    // No sourcetype at all: still the token's source.
    let (event, _) = kept(run(&program, json!({"message": "raw"}), Some((TOKEN, &route))));
    assert_eq!(event["source_type"], "pan_traffic");
    assert!(event.get("claimed_source_type").is_none());
}

#[test]
fn hec_unbound_or_unstamped_token_is_refused() {
    let program = transform_source(HEC, "hec_normalize");
    let event = json!({"message": "raw", "splunk_sourcetype": "apache_access"});
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

#[test]
fn hec_bytes_codec_preserves_string_and_object_payloads() {
    assert_eq!(parse(HEC)["sources"]["splunk_hec_ingest"]["event"]["decoding"]["codec"].as_str(), Some("bytes"));
    let payload = json!({"message": "hello", "nested": {"id": 42}, "source_type": "spoofed"});
    for event in [json!(payload.to_string()), payload.clone()] {
        let log = crate::parsers::tenant_bundle::bronze_row_contract::splunk_hec_log(
            &json!({"event": event, "sourcetype": "okta"})
        ).unwrap();
        let (normalized, metadata) = kept(run(&transform_source(HEC, "hec_normalize"), log, Some((TOKEN, "okta"))));
        assert_eq!(serde_json::from_str::<Value>(normalized["message"].as_str().unwrap()).unwrap(), payload);
        assert_eq!(normalized["source_type"], "okta");
        assert_eq!(metadata["source_type"], "okta");
    }
}

/// NAN-3646: `.message` is never left empty for a HEC payload. Covers a
/// string event, an object event (as the bytes codec delivers it, as an
/// unflattened `.event`, and spread over the root by a Vector without the
/// bytes codec), a non-string `.message`, and an envelope with no event.
#[test]
fn hec_normalize_message_for_string_object_and_missing_events() {
    let program = transform_source(HEC, "hec_normalize");
    let normalize = |log: Value| kept(run(&program, log, Some((TOKEN, "okta")))).0;
    let as_json = |event: &Value| -> Value {
        serde_json::from_str(event["message"].as_str().expect("message is a string")).unwrap()
    };

    // String event: unchanged.
    let log = crate::parsers::tenant_bundle::bronze_row_contract::splunk_hec_log(
        &json!({"event": "raw line", "sourcetype": "okta"}),
    )
    .unwrap();
    assert_eq!(normalize(log)["message"], "raw line");
    assert_eq!(normalize(json!({"event": "raw line", "splunk_sourcetype": "okta"}))["message"], "raw line");

    // Object event with an explicit `message`: that message wins.
    let event = normalize(json!({"event": {"message": "m", "user": "a"}, "splunk_sourcetype": "okta"}));
    assert_eq!(event["message"], "m");

    // Object event still nested under `.event`: serialized whole.
    let payload = json!({"user": "alice", "action": "login", "nested": {"id": 7}});
    let event = normalize(json!({"event": payload, "splunk_sourcetype": "okta"}));
    assert_eq!(as_json(&event), payload);

    // Object event spread over the root (no bytes codec): rebuilt from the
    // root without the HEC envelope, deterministically (key-sorted).
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
    assert_eq!(normalize(spread)["message"], event["message"]);
    // An empty `.message` alongside spread fields is treated the same way.
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

#[test]
fn otlp_logs_use_edge_identity_and_bound_route() {
    let program = transform_source(
        include_str!("../../../config/vector/03-otlp-source.toml"),
        "otlp_logs_prep",
    );
    let (event, metadata) = kept(run(
        &program,
        json!({
            "message": "hello", "x-nano-credential-id": TOKEN,
            "x-nano-source-route": "otlp_log",
            "attributes": {"x-nano-credential-id": "forged", "source_type": "forged"}
        }),
        None,
    ));
    assert_eq!(event["auth_status"], "authenticated");
    assert_eq!(event["source_type"], "otlp_log");
    assert_eq!(metadata["nano_credential_id"], TOKEN);
    assert_eq!(metadata["source_type"], "otlp_log");
    assert!(event.get("x-nano-credential-id").is_none());
    let (_, metadata) = kept(run(
        &program,
        json!({"message": "internal",
        "attributes": {"x-nano-credential-id": "forged"}}),
        None,
    ));
    assert!(metadata.get("nano_credential_id").is_none());
}

/// Line numbers of every bare `$name` Vector would env-interpolate in `text`.
/// Vector substitutes `$name` / `${name}` (name = word chars and `.`) on the
/// raw config text, comments included; `$$` is the escape. A `$` followed by
/// anything else (regex end anchors such as `$'` or `$)`) is left alone.
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

fn collect_vector_configs(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap_or_else(|e| panic!("read {dir:?}: {e}")) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            collect_vector_configs(&path, out);
        } else if matches!(
            path.extension().and_then(|e| e.to_str()),
            Some("toml" | "yaml" | "yml" | "json")
        ) {
            out.push(path);
        }
    }
}

/// NAN-4407: a `$1.4` in a comment of 04-otlp-lake-sink.toml made Vector exit
/// 78 ("Missing environment variable in config. name = \"1.4\"") on every fresh
/// open-core install. Every static Vector config must use `${VAR}` for real
/// references and `$$` (or no `$`) everywhere else.
#[test]
fn static_vector_configs_have_no_bare_env_refs() {
    assert_eq!(
        bare_env_refs("# ~$1.4/day"),
        vec![(1, "# ~$1.4/day".into())]
    );
    assert!(bare_env_refs("a = \"${X:-1}\" # $$1 r'^a$' r'(b)$')").is_empty());

    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../config/vector");
    let mut files = Vec::new();
    collect_vector_configs(&root, &mut files);
    assert!(!files.is_empty(), "no Vector configs found under {root:?}");
    let offenders: Vec<String> = files
        .iter()
        .flat_map(|path| {
            let text =
                std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
            bare_env_refs(&text)
                .into_iter()
                .map(move |(line, src)| format!("{}:{line}: {src}", path.display()))
        })
        .collect();
    assert!(
        offenders.is_empty(),
        "bare `$name` is env-interpolated by Vector (even in comments); use ${{VAR}}, `$$`, or drop the `$`:\n{}",
        offenders.join("\n")
    );
}
