// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4038: HTTP credential headers must never reach a stored event.
//!
//! The `http_ingest` source copies every header named in its `headers` list
//! onto the event as a top-level field, and any field that is not a UDM column
//! ends up in the `ext` JSON column in ClickHouse. The base config used to
//! capture `X-Api-Key` and `X-Webhook-Secret` and only delete `Authorization`,
//! so both secrets were stored verbatim in searchable rows.
//!
//! A header is not the only way in: `parse_content` merges JSON body keys onto
//! the event, HEC merges its `event` object, and an upstream Vector forwards
//! whatever it has. So the pipeline also strips credential-named fields at any
//! depth in the blocks every stored row passes (`prepare_output`,
//! `clickhouse_mapping`, and the OCSF prepare blocks).
//!
//! These tests EXECUTE the real VRL from the embedded configs on events shaped
//! the way each source builds them, rather than pattern-matching the text.

use vrl::compiler::runtime::Runtime;
use vrl::compiler::state::RuntimeState;
use vrl::compiler::{TargetValue, TimeZone, compile};
use vrl::value::{ObjectMap, Secrets, Value};

use super::VectorConfigManager;

const BASE: &str = include_str!("../../../../../config/vector/00-base.toml");
const NATIVE: &str = include_str!("../../../../../config/vector/01-vector-source.toml");
const HEC: &str = include_str!("../../../../../config/vector/02-hec-source.toml");
const TOKEN: &str = "nan4038-ingest-token";
const API_KEY: &str = "nan4038-api-key-secret";
const WEBHOOK: &str = "nan4038-webhook-secret";

/// Every header a sender might use to carry a credential.
const CREDENTIAL_HEADERS: &[&str] = &[
    "authorization",
    "x-api-key",
    "x-webhook-secret",
    "cookie",
    "proxy-authorization",
];

fn base_config() -> toml::Value {
    toml::from_str(BASE).expect("00-base.toml parses")
}

fn captured_headers() -> Vec<String> {
    base_config()["sources"]["http_ingest"]["headers"]
        .as_array()
        .expect("http_ingest.headers is a list")
        .iter()
        .map(|v| v.as_str().expect("header name is a string").to_string())
        .collect()
}

pub(super) fn transform_source(name: &str) -> String {
    transform_in(BASE, name)
}

/// The VRL `source` of transform `name` in a Vector TOML config.
pub(super) fn transform_in(config: &str, name: &str) -> String {
    let parsed: toml::Value = toml::from_str(config).expect("config parses");
    parsed["transforms"][name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("transform {name} has a VRL source"))
        .to_string()
}

/// The type Vector gives the event root (`.`) in remap `name` of `config`.
/// Vector types `.` from the input's schema: `trace_to_log` and
/// `metric_to_log` declare none, so `.` is `any` there and the OTLP trace /
/// metric preps must open with `. = object(.) ?? {}`. A bare `vrl::compile`
/// assumes an object and rejects that line as E651, which Vector
/// 0.61.0-nano.11 accepts (`vector validate`); every other input is an object.
pub(super) fn vector_root_kind(config: &toml::Value, name: &str) -> vrl::value::Kind {
    use vrl::value::{Kind, kind::Collection};
    let transforms = &config["transforms"];
    let inputs = transforms[name]["inputs"].as_array().map(Vec::as_slice).unwrap_or_default();
    let untyped = |input: &toml::Value| {
        let kind = input.as_str().and_then(|i| transforms.get(i)).and_then(|t| t.get("type")).and_then(|t| t.as_str());
        matches!(kind, Some("trace_to_log" | "metric_to_log"))
    };
    if !inputs.is_empty() && inputs.iter().all(untyped) { Kind::any() } else { Kind::object(Collection::any()) }
}

/// `vrl::compile` with the event root typed as Vector types it (see
/// [`vector_root_kind`]).
pub(super) fn compile_with_root(src: &str, root: vrl::value::Kind) -> vrl::compiler::Result {
    use vrl::compiler::{CompileConfig, compile_with_external, state::ExternalEnv};
    use vrl::value::{Kind, kind::Collection};
    let external = ExternalEnv::new_with_kind(root, Kind::object(Collection::any()));
    compile_with_external(src, &vrl::stdlib::all(), &external, CompileConfig::default())
}

/// The pipeline config is not valid TOML until Vector interpolates its
/// `${VAR:-default}` sink settings, so slice the block out textually.
pub(super) fn pipeline(name: &str) -> String {
    let content = VectorConfigManager::pipeline_config_content();
    let header = format!("[transforms.{name}]\n");
    let at = content
        .find(&header)
        .unwrap_or_else(|| panic!("pipeline has transform {name}"));
    let body = &content[at..];
    let open = body.find("source = '''\n").expect("remap source") + "source = '''\n".len();
    let close = body[open..].find("\n'''").expect("source terminator");
    body[open..open + close].to_string()
}

/// Run VRL programs in order on `event`, as Vector would along a chain.
pub(super) fn run_chain(event: Value, programs: &[(&str, String)]) -> Value {
    run_chain_with_metadata(event, Value::Object(ObjectMap::new()), programs)
}

/// Run VRL programs with explicit Vector event metadata. This models protected
/// transport controls that cannot be supplied as ordinary log fields.
pub(super) fn run_chain_with_metadata(
    event: Value,
    metadata: Value,
    programs: &[(&str, String)],
) -> Value {
    let mut target = TargetValue {
        value: event,
        metadata,
        secrets: Secrets::new(),
    };
    let fns = vrl::stdlib::all();
    for (name, src) in programs {
        // Supply the ingest token without mutating the process environment.
        // NAN-4907: no credential stamp here, so model the explicit static
        // install-token fallback (otherwise auth_check fails closed).
        let src = src
            .replace(
                r#"get_env_var("VECTOR_AUTH_TOKEN") ?? """#,
                &format!("{TOKEN:?}"),
            )
            .replace(
                r#"get_env_var("NANO_INGEST_STATIC_FALLBACK") ?? """#,
                r#""true""#,
            );
        let program = match compile(&src, &fns) {
            Ok(compiled) => compiled.program,
            Err(diagnostics) => panic!(
                "{name} failed to compile:\n{}",
                vrl::diagnostic::Formatter::new(&src, diagnostics)
            ),
        };
        let mut runtime = Runtime::new(RuntimeState::default());
        runtime
            .resolve(&mut target, &program, &TimeZone::Local)
            .unwrap_or_else(|e| panic!("{name} failed: {e}"));
    }
    target.value
}

pub(super) fn json(v: serde_json::Value) -> Value {
    Value::from(v)
}

/// No credential-named key at any depth, and no secret value anywhere.
fn assert_no_credentials(stored: &Value, secrets: &[&str], context: &str) {
    fn walk(v: &Value, path: &str, context: &str) {
        if let Value::Object(map) = v {
            for (k, child) in map {
                assert!(
                    !CREDENTIAL_HEADERS.contains(&k.to_ascii_lowercase().as_str()),
                    "{context}: credential field `{path}.{k}` reached storage"
                );
                walk(child, &format!("{path}.{k}"), context);
            }
        }
    }
    walk(stored, "", context);
    let rendered = stored.to_string();
    for secret in secrets {
        assert!(
            !rendered.contains(secret),
            "{context}: credential value `{secret}` reached storage: {rendered}"
        );
    }
}

/// The source captures only headers the pipeline reads. `Authorization` is the
/// one credential header it needs, because `auth_check` authenticates with it.
#[test]
fn http_source_captures_no_credential_header_except_authorization() {
    let leaked: Vec<String> = captured_headers()
        .into_iter()
        .filter(|h| {
            let h = h.to_ascii_lowercase();
            h != "authorization" && CREDENTIAL_HEADERS.contains(&h.as_str())
        })
        .collect();
    assert!(
        leaked.is_empty(),
        "http_ingest must not copy credential headers onto events: {leaked:?}"
    );
}

/// Runs the base chain (`auth_check` -> `rate_limit_prep` -> `parse_content`
/// -> `source_type_extract`) on a request that sends every credential header,
/// and proves no credential name or value is left on the event that continues
/// to the parsers and the ClickHouse sink.
#[test]
fn credential_headers_do_not_reach_the_stored_event() {
    // Build the event the way `http_server` does: the body line in `.message`,
    // plus one field per header named in `headers`, IF the request sent it.
    // Send every credential header, captured or not; also put the API key in
    // a header the source would drop, so a future `headers` edit that re-adds
    // it is caught here too.
    let sent: &[(&str, String)] = &[
        ("Authorization", format!("Bearer {TOKEN}")),
        ("X-Api-Key", API_KEY.to_string()),
        ("X-Webhook-Secret", WEBHOOK.to_string()),
        ("Cookie", format!("session={API_KEY}")),
        ("X-Source-Type", "nan4038_test".to_string()),
        ("Content-Type", "application/json".to_string()),
        ("X-Forwarded-For", "203.0.113.7".to_string()),
    ];
    let captured: Vec<String> = captured_headers()
        .into_iter()
        .map(|h| h.to_ascii_lowercase())
        .collect();

    let mut obj = ObjectMap::new();
    obj.insert(
        "message".into(),
        Value::from(r#"{"message":"hello","user":"alice"}"#),
    );
    obj.insert("path".into(), Value::from("/"));
    for (name, value) in sent {
        if captured.contains(&name.to_ascii_lowercase()) {
            obj.insert((*name).into(), Value::from(value.as_str()));
        }
    }
    let mut target = TargetValue {
        value: Value::Object(obj),
        metadata: Value::Object(ObjectMap::new()),
        secrets: Secrets::new(),
    };

    let fns = vrl::stdlib::all();
    for name in [
        "auth_check",
        "rate_limit_prep",
        "parse_content",
        "source_type_extract",
    ] {
        // Supply the ingest token without mutating the process environment.
        // NAN-4907: no credential stamp here, so model the explicit static
        // install-token fallback (otherwise auth_check fails closed).
        let src = transform_source(name)
            .replace(
                r#"get_env_var("VECTOR_AUTH_TOKEN") ?? """#,
                &format!("{TOKEN:?}"),
            )
            .replace(
                r#"get_env_var("NANO_INGEST_STATIC_FALLBACK") ?? """#,
                r#""true""#,
            );
        let program = compile(&src, &fns)
            .unwrap_or_else(|_| panic!("{name} compiles"))
            .program;
        let mut runtime = Runtime::new(RuntimeState::default());
        runtime
            .resolve(&mut target, &program, &TimeZone::Local)
            .unwrap_or_else(|e| panic!("{name} failed: {e}"));
    }

    let event = target.value.as_object().expect("event is an object");
    assert_eq!(
        event.get("auth_status").and_then(|v| v.as_str()).as_deref(),
        Some("authenticated"),
        "the request must still authenticate with its Authorization header"
    );
    assert_eq!(
        event.get("source_type").and_then(|v| v.as_str()).as_deref(),
        Some("nan4038_test"),
        "non-credential headers must still be read"
    );

    for key in event.keys() {
        assert!(
            !CREDENTIAL_HEADERS.contains(&key.to_ascii_lowercase().as_str()),
            "credential header `{key}` reached the stored event"
        );
    }
    let rendered = target.value.to_string();
    for secret in [TOKEN, API_KEY, WEBHOOK] {
        assert!(
            !rendered.contains(secret),
            "credential value `{secret}` reached the stored event: {rendered}"
        );
    }
}

/// The worst case for each source: the JSON body / HEC event / forwarded event
/// carries credential-named fields at the top level, in different casings, and
/// nested in header maps. Covers both the DB-parser path (the source chain
/// straight into `clickhouse_mapping`, as a parser that keeps every field
/// would) and the generic path (`generic_parser` -> `normalize` ->
/// `prepare_output` -> `clickhouse_mapping`).
#[test]
fn credential_fields_in_any_payload_never_reach_clickhouse() {
    let secrets = [
        "body-bearer",
        "body-api",
        "body-cookie",
        "hdr-webhook",
        "nested-basic",
        "hec-api",
        "hec-cookie",
        "native-bearer",
        "native-cookie",
    ];

    // HTTP (00-base): the body is NDJSON, one line per event.
    let http_body = serde_json::json!({
        "message": "login",
        "user": "alice",
        "Authorization": "Bearer body-bearer",
        "x-api-key": "body-api",
        "COOKIE": "sid=body-cookie",
        "headers": {"X-Webhook-Secret": "hdr-webhook", "Accept": "*/*"},
        "http": {"request": {"headers": {"authorization": "Basic nested-basic"}}}
    });
    let http_event = json(serde_json::json!({
        "message": http_body.to_string(),
        "path": "/",
        "Authorization": format!("Bearer {TOKEN}"),
        "Content-Type": "application/json",
        "X-Source-Type": "nan4038_http",
    }));
    let http_chain = vec![
        ("auth_check", transform_source("auth_check")),
        ("rate_limit_prep", transform_source("rate_limit_prep")),
        ("parse_content", transform_source("parse_content")),
        (
            "source_type_extract",
            transform_source("source_type_extract"),
        ),
    ];

    // HEC: the `splunk_hec` source puts the envelope's `event` on `.event`.
    let hec_event = json(serde_json::json!({
        "splunk_sourcetype": "nan4038_hec",
        "event": {
            "message": "hec login",
            "user": "bob",
            "X-Api-Key": "hec-api",
            "headers": {"Cookie": "hec-cookie", "Accept": "*/*"}
        }
    }));
    let hec_chain = vec![("hec_normalize", transform_in(HEC, "hec_normalize"))];

    // Vector-native: the upstream event arrives as-is, metadata included.
    let native_event = json(serde_json::json!({
        "message": "native login",
        "source_type": "nan4038_native",
        "user": "carol",
        "Authorization": "Bearer native-bearer",
        "metadata": {"headers": {"cookie": "native-cookie", "Accept": "*/*"}}
    }));
    let native_chain = vec![
        ("vector_auth", transform_in(NATIVE, "vector_auth")),
        ("vector_merge", transform_in(NATIVE, "vector_merge")),
        (
            "source_type_extract",
            transform_source("source_type_extract"),
        ),
    ];

    let generic_tail = vec![
        ("generic_parser", pipeline("generic_parser")),
        ("normalize", pipeline("normalize")),
        ("prepare_output", pipeline("prepare_output")),
        ("clickhouse_mapping", pipeline("clickhouse_mapping")),
    ];
    let passthrough_tail = vec![("clickhouse_mapping", pipeline("clickhouse_mapping"))];

    for (source, event, head, user) in [
        ("http", http_event, http_chain, "alice"),
        ("hec", hec_event, hec_chain, "bob"),
        ("vector_native", native_event, native_chain, "carol"),
    ] {
        for (lane, tail) in [("parser", &passthrough_tail), ("generic", &generic_tail)] {
            let chain: Vec<(&str, String)> =
                head.iter().cloned().chain(tail.iter().cloned()).collect();
            let stored = run_chain(event.clone(), &chain);
            let context = format!("{source}/{lane}");
            assert_no_credentials(&stored, &secrets, &context);
            if lane == "parser" {
                // Redaction removes only credential fields: neighbours stay.
                assert_eq!(
                    stored
                        .get(vrl::path!("ext", "user"))
                        .and_then(|v| v.as_str())
                        .as_deref(),
                    None,
                    "{context}: `user` is a column, not ext"
                );
                assert_eq!(
                    stored
                        .get(vrl::path!("user"))
                        .and_then(|v| v.as_str())
                        .as_deref(),
                    Some(user),
                    "{context}: non-credential fields must survive"
                );
            }
        }
    }
}

/// Both OCSF prepare blocks store the whole event in `ocsf_logs.event`.
#[test]
fn credential_fields_never_reach_ocsf_logs() {
    let event = json(serde_json::json!({
        "message": "ocsf login",
        "source_type": "nan4038_ocsf",
        "class_uid": 3002,
        "Authorization": "Bearer ocsf-bearer",
        "http_request": {"headers": {"X-Api-Key": "ocsf-api", "Accept": "*/*"}},
        "metadata": {"version": "1.8.0"}
    }));
    for (name, src) in [
        (
            "generic_ocsf_prepare",
            transform_in(
                VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK,
                "generic_ocsf_prepare",
            ),
        ),
        (
            "ocsf_prepare",
            super::super::parser_config::OCSF_PREPARE_VRL.to_string(),
        ),
    ] {
        let stored = run_chain(event.clone(), &[(name, src)]);
        assert_no_credentials(&stored, &["ocsf-bearer", "ocsf-api"], name);
        // NAN-4903: the generic lane keeps the unparsed record under
        // `event.unmapped` (vendor data, not OCSF); the OCSF prepare stage keeps
        // the parser's OCSF object as `event` itself.
        let accept = if name == "generic_ocsf_prepare" {
            stored.get(vrl::path!(
                "event",
                "unmapped",
                "http_request",
                "headers",
                "Accept"
            ))
        } else {
            stored.get(vrl::path!("event", "http_request", "headers", "Accept"))
        };
        assert_eq!(
            accept.and_then(|v| v.as_str()).as_deref(),
            Some("*/*"),
            "{name}: non-credential headers must survive"
        );
    }
}
