// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5352: no ingest lane stores a credential value written inside the
//! event's TEXT (`raw_data`, `message`, any string), in any column.
//!
//! NAN-4038 removed credential-named FIELDS. On the HTTP text/plain lane the
//! body is never parsed by `parse_content`, so a line such as
//! `{"Authorization": "Bearer ..."}` reached the parser verbatim, and every
//! shipped OCSF parser copies the received line into `raw_data` (and often
//! `message`): the value was stored. The same holds for every lane that hands
//! the parser raw text (HEC raw and string events, OTLP log bodies, pull
//! sources, upstream Vector) and for the NAN-5346 parse-error records that
//! keep the raw text (the shipped `_ocsf_failure` remap, both failure kinds).
//!
//! These tests EXECUTE the shipped VRL on the runtime, lane head to the last
//! remap before each ClickHouse sink (the row that sink serializes into its
//! insert body), and assert no fake secret is left anywhere in the row while
//! the rest of the original text survives in `raw_data` / `message`.

use std::collections::HashMap;

use vrl::compiler::runtime::Runtime;
use vrl::compiler::state::RuntimeState;
use vrl::compiler::{Program, TargetValue, TimeZone};
use vrl::value::{kind::Collection, Kind, Secrets, Value};

use super::credential_header_tests::{
    compile_with_root, json, pipeline, transform_in, transform_source, vector_root_kind,
};
use super::VectorConfigManager;
use crate::parsers::vector_config::parser_config::{OCSF_PARSE_FAILURE_RECORD_VRL, OCSF_PREPARE_VRL};

const NATIVE: &str = include_str!("../../../../../config/vector/01-vector-source.toml");
const HEC: &str = include_str!("../../../../../config/vector/02-hec-source.toml");
const OTLP: &str = include_str!("../../../../../config/vector/03-otlp-source.toml");
const TOKEN: &str = "nan4038-ingest-token";

/// Obvious fakes, one per credential form.
const SECRETS: &[&str] = &["FAKE-NAN5352-BEARER", "FAKE-NAN5352-APIKEY", "FAKE-NAN5352-COOKIE", "FAKE-NAN5352-WEBHOOK"];

/// Credential-bearing log lines in each text form the redaction handles. Each
/// keeps the non-credential context `alice` that must survive.
fn lines() -> Vec<(&'static str, String)> {
    vec![
        (
            "json",
            serde_json::json!({
                "user": "alice",
                "action": "login",
                "Authorization": "Bearer FAKE-NAN5352-BEARER",
                "headers": {"X-Api-Key": "FAKE-NAN5352-APIKEY", "Cookie": "sid=FAKE-NAN5352-COOKIE"},
                "records": [{"x-webhook-secret": "FAKE-NAN5352-WEBHOOK"}]
            })
            .to_string(),
        ),
        (
            "header",
            "user=alice GET /login HTTP/1.1\r\nAuthorization: Bearer FAKE-NAN5352-BEARER\r\nCookie: sid=FAKE-NAN5352-COOKIE\r\nHost: example.test".into(),
        ),
        // The same request line with its line breaks escaped, as a client
        // that logs a request on one line sends it.
        (
            "escaped header",
            r"user=alice GET /login HTTP/1.1\r\nAuthorization: Bearer FAKE-NAN5352-BEARER\r\nCookie: sid=FAKE-NAN5352-COOKIE".into(),
        ),
        // A folded (continued) header line, and a delimited log line.
        (
            "folded header",
            r"user=alice GET /login HTTP/1.1\r\nAuthorization:\r\n Bearer FAKE-NAN5352-BEARER\r\nCookie: sid=FAKE-NAN5352-COOKIE; theme=dark".into(),
        ),
        (
            "delimited",
            "user=alice|x-api-key=FAKE-NAN5352-APIKEY;x-webhook-secret=FAKE-NAN5352-WEBHOOK|status=200".into(),
        ),
        (
            "kv",
            "user=alice action=login x-api-key=FAKE-NAN5352-APIKEY x-webhook-secret=FAKE-NAN5352-WEBHOOK status=200".into(),
        ),
    ]
}

/// What every shipped OCSF parser does with its input (parsers-ocsf: `raw_log
/// = string!(.message)`, then `"raw_data": raw_log`), keeping the line in
/// `message` too, the worst case.
const OCSF_TEXT_PARSER: &str = r#"raw_log = string!(.message)
. = {"class_uid": 0, "category_uid": 0, "activity_id": 0, "type_uid": 0, "time": 1762164000000, "message": raw_log, "raw_data": raw_log, "metadata": {"version": "1.8.0", "product": {"name": "nan5352"}}}"#;

/// NAN-5346: the shipped `_ocsf_failure` remap (class-0 parse-error record:
/// the raw text in `raw_data`, the parser's output under
/// `unmapped.parser_output`), with the identity it is rendered with.
fn ocsf_failure_record() -> String {
    format!(
        "nano_parser_id = \"00000000-0000-0000-0000-000000005352\"\nnano_parser_name = \"nan5352\"\n{OCSF_PARSE_FAILURE_RECORD_VRL}"
    )
}

/// A parser runtime error: Vector reroutes the event to the remap's
/// `.dropped` port with `.metadata.dropped` set.
const RUNTIME_FAILURE: &str = r#"if !is_object(.metadata) { .metadata = {} }
.metadata.dropped = {"message": "function call error", "component_id": "nan5352_parse"}"#;

/// The UDM parse-failure path: the parser keeps the line and marks the error.
const UDM_PARSE_ERROR: &str = r#".parse_error = "bad input"
.metadata.parse_error = "bad input""#;

fn otlp_logs_prep() -> String {
    transform_in(&crate::vector_env::substitute_like_vector(OTLP), "otlp_logs_prep")
}

fn generic_ocsf_prepare() -> String {
    transform_in(VectorConfigManager::GENERIC_OCSF_PREPARE_BLOCK, "generic_ocsf_prepare")
}

/// Lane head: (lane name, event as the source emits it, event metadata,
/// static remaps before the router).
fn lane_heads(line: &str) -> Vec<(String, Value, Value, Vec<(&'static str, String)>)> {
    let http_head = || {
        vec![
            ("auth_check", transform_source("auth_check")),
            ("rate_limit_prep", transform_source("rate_limit_prep")),
            ("parse_content", transform_source("parse_content")),
            ("source_type_extract", transform_source("source_type_extract")),
        ]
    };
    let no_meta = || json(serde_json::json!({}));
    let mut heads = Vec::new();
    for ct in ["text/plain", "application/json", "application/x-ndjson", ""] {
        heads.push((
            format!("http[{ct}]"),
            json(serde_json::json!({
                "message": line, "path": "/", "Authorization": format!("Bearer {TOKEN}"),
                "Content-Type": ct, "X-Source-Type": "nan5352_http"
            })),
            no_meta(),
            http_head(),
        ));
    }
    // A JSON array body: `json_batch_expand` hands each member to
    // `json_batch_normalize` this way.
    if let Ok(member @ serde_json::Value::Object(_)) = serde_json::from_str::<serde_json::Value>(line) {
        heads.push((
            "http[batch member]".into(),
            json(serde_json::json!({"nano_json_batch": member, "source_type": "nan5352_http"})),
            json(serde_json::json!({"nano_json_batch_member": true})),
            vec![
                ("json_batch_normalize", transform_source("json_batch_normalize")),
                ("source_type_extract", transform_source("source_type_extract")),
            ],
        ));
    }
    let hec = || vec![("hec_normalize", transform_in(HEC, "hec_normalize"))];
    heads.push((
        "hec[string event]".into(),
        json(serde_json::json!({"splunk_sourcetype": "nan5352_hec", "event": line})),
        no_meta(),
        hec(),
    ));
    heads.push((
        "hec[raw endpoint]".into(),
        json(serde_json::json!({"splunk_sourcetype": "nan5352_hec", "message": line})),
        no_meta(),
        hec(),
    ));
    // NAN-5340: an object event whose siblings are stashed in metadata and
    // merged under `unmapped` by `_ocsf_prepare` for a text parser.
    heads.push((
        "hec[object event]".into(),
        json(serde_json::json!({
            "splunk_sourcetype": "nan5352_hec",
            "event": {"message": line, "seq": 7, "X-Api-Key": "FAKE-NAN5352-APIKEY", "note": "Cookie: sid=FAKE-NAN5352-COOKIE"}
        })),
        no_meta(),
        hec(),
    ));
    heads.push((
        "otlp[log body]".into(),
        json(serde_json::json!({
            "message": line,
            "attributes": {"note": "Authorization: Bearer FAKE-NAN5352-BEARER"},
            "resources": {"service.name": "nan5352-svc"}
        })),
        no_meta(),
        vec![("otlp_logs_prep", otlp_logs_prep())],
    ));
    heads.push((
        "vector[upstream]".into(),
        json(serde_json::json!({"message": line, "source_type": "nan5352_native"})),
        no_meta(),
        vec![
            ("vector_auth", transform_in(NATIVE, "vector_auth")),
            ("vector_merge", transform_in(NATIVE, "vector_merge")),
            ("source_type_extract", transform_source("source_type_extract")),
        ],
    ));
    // Pull lanes have no remap of their own before the router: the decoded
    // object or line is the event's `message`.
    for pull in ["aws_s3", "aws_sqs", "gcp_pubsub", "azure_event_hubs", "kafka"] {
        heads.push((
            format!("pull[{pull}]"),
            json(serde_json::json!({"message": line, "source_type": pull})),
            no_meta(),
            vec![],
        ));
    }
    heads
}

/// Lane tails: the remaps from the router to the last step before each sink.
fn lane_tails() -> Vec<(&'static str, Vec<(&'static str, String)>)> {
    vec![
        (
            "ocsf parser -> ocsf_logs",
            vec![("parser", OCSF_TEXT_PARSER.into()), ("ocsf_prepare", OCSF_PREPARE_VRL.into())],
        ),
        (
            "ocsf parse-error record (no class_uid) -> ocsf_logs",
            vec![("ocsf_failure", ocsf_failure_record()), ("ocsf_prepare", OCSF_PREPARE_VRL.into())],
        ),
        (
            "ocsf parse-error record (runtime error) -> ocsf_logs",
            vec![
                ("parser", RUNTIME_FAILURE.into()),
                ("ocsf_failure", ocsf_failure_record()),
                ("ocsf_prepare", OCSF_PREPARE_VRL.into()),
            ],
        ),
        ("udm parser -> logs", vec![("clickhouse_mapping", pipeline("clickhouse_mapping"))]),
        (
            "udm parse failure -> logs",
            vec![("parser", UDM_PARSE_ERROR.into()), ("clickhouse_mapping", pipeline("clickhouse_mapping"))],
        ),
        (
            "generic -> logs",
            vec![
                ("generic_parser", pipeline("generic_parser")),
                ("normalize", pipeline("normalize")),
                ("prepare_output", pipeline("prepare_output")),
                ("clickhouse_mapping", pipeline("clickhouse_mapping")),
            ],
        ),
        (
            "generic -> ocsf_logs",
            vec![("generic_parser", pipeline("generic_parser")), ("generic_ocsf_prepare", generic_ocsf_prepare())],
        ),
    ]
}

/// `credential_header_tests::run_chain_with_metadata`, with each program
/// compiled once for the whole matrix (same env substitutions).
struct Chain(HashMap<String, Program>);

impl Chain {
    fn run(&mut self, event: Value, metadata: Value, programs: &[(&str, String)]) -> Value {
        self.run_rooted(event, metadata, programs, Kind::object(Collection::any()))
    }

    /// `run`, with every program compiled against `root` as the event-root
    /// type (see `credential_header_tests::vector_root_kind`).
    fn run_rooted(&mut self, event: Value, metadata: Value, programs: &[(&str, String)], root: Kind) -> Value {
        let mut target = TargetValue { value: event, metadata, secrets: Secrets::new() };
        for (name, src) in programs {
            let src = src
                .replace(r#"get_env_var("VECTOR_AUTH_TOKEN") ?? """#, &format!("{TOKEN:?}"))
                .replace(r#"get_env_var("NANO_INGEST_STATIC_FALLBACK") ?? """#, r#""true""#);
            let program = self.0.entry(format!("{root:?}\n{src}")).or_insert_with(|| match compile_with_root(&src, root.clone()) {
                Ok(c) => c.program,
                Err(d) => panic!("{name} failed to compile:\n{}", vrl::diagnostic::Formatter::new(&src, d)),
            });
            Runtime::new(RuntimeState::default())
                .resolve(&mut target, program, &TimeZone::Local)
                .unwrap_or_else(|e| panic!("{name} failed: {e}"));
        }
        target.value
    }
}

fn text_fields(row: &Value) -> Vec<String> {
    [
        row.get(vrl::path!("message")),
        row.get(vrl::path!("raw_data")),
        row.get(vrl::path!("event", "message")),
        row.get(vrl::path!("event", "raw_data")),
    ]
    .into_iter()
    .flatten()
    .filter_map(|v| v.as_str().map(|s| s.into_owned()))
    .collect()
}

/// Every lane x every text form x every sink path: the row that reaches the
/// ClickHouse sink holds no fake secret anywhere, and its raw text still
/// carries the non-credential context.
#[test]
fn no_lane_stores_a_credential_value_from_text() {
    let mut rows = 0;
    let mut runner = Chain(HashMap::new());
    for (form, line) in lines() {
        for (lane, event, metadata, head) in lane_heads(&line) {
            for (tail_name, tail) in lane_tails() {
                let chain: Vec<(&str, String)> = head.iter().cloned().chain(tail.iter().cloned()).collect();
                let row = runner.run(event.clone(), metadata.clone(), &chain);
                let context = format!("{lane} / {form} / {tail_name}");
                let rendered = row.to_string();
                for secret in SECRETS {
                    assert!(!rendered.contains(secret), "{context}: `{secret}` reached storage: {rendered}");
                }
                assert!(
                    text_fields(&row).iter().any(|t| t.contains("alice")),
                    "{context}: the raw text lost its context: {rendered}"
                );
                rows += 1;
            }
        }
    }
    assert!(rows >= 6 * 14 * 7, "{rows}");
}

/// The original report (NAN-5180 parity capture): a text/plain JSON line with
/// a credential key, through an OCSF parser. `raw_data` keeps the original
/// bytes except the value.
#[test]
fn text_plain_raw_data_keeps_the_line_with_the_value_redacted() {
    let line = r#"{"user": "alice", "Authorization": "Bearer FAKE-NAN5352-BEARER", "action": "login"}"#;
    let (_, event, metadata, head) =
        lane_heads(line).into_iter().find(|(lane, ..)| lane == "http[text/plain]").expect("text/plain lane");
    let chain: Vec<(&str, String)> = head
        .into_iter()
        .chain([("parser", OCSF_TEXT_PARSER.to_string()), ("ocsf_prepare", OCSF_PREPARE_VRL.to_string())])
        .collect();
    let row = Chain(HashMap::new()).run(event, metadata, &chain);
    let want = r#"{"user": "alice", "Authorization": "[REDACTED]", "action": "login"}"#;
    assert_eq!(row.get(vrl::path!("event", "raw_data")), Some(&Value::from(want)));
    assert_eq!(row.get(vrl::path!("event", "message")), Some(&Value::from(want)));
}

/// The Helm copy lives under `deploy/`, which the open-core mirror strips, so
/// read it at runtime and skip only when it is absent (NAN-2169).
fn helm_otlp() -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../deploy/helm/nano/files/vector/03-otlp-source.toml");
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => panic!("{}: {e}", path.display()),
    }
}

/// OTLP traces and metrics go to their own ClickHouse sinks as OTLP
/// `{key, value}` pairs and never pass the parser storage boundary, so both
/// prep remaps start with the same redaction, verbatim (and the Helm copy of
/// the file is the same file).
#[test]
fn otlp_trace_and_metric_preps_embed_the_redaction() {
    if let Some(helm_otlp) = helm_otlp() {
        assert_eq!(OTLP, helm_otlp, "deploy/helm/nano/files/vector/03-otlp-source.toml drifted");
    }
    let otlp = crate::vector_env::substitute_like_vector(OTLP);
    for name in ["otlp_traces_prep", "otlp_metrics_prep"] {
        let src = transform_in(&otlp, name);
        assert!(
            src.contains(crate::parsers::vector_config::CREDENTIAL_FIELD_REDACTION_VRL),
            "{name} lost its verbatim copy of credential_field_redaction_vrl!"
        );
        assert!(src.find("NAN-4038").unwrap() < src.find("encode_json(otlp)").unwrap(), "{name}: redact before the pairs");
    }
}

/// A span with credentials in attributes (also as an OTel dotted header
/// name), in event and link attributes, in resource attributes and in text
/// values; and a metric with credential tags. Nothing reaches the stored row,
/// the other attributes do.
#[test]
fn otlp_traces_and_metrics_store_no_credential() {
    let otlp = crate::vector_env::substitute_like_vector(OTLP);
    let span = json(serde_json::json!({
        "trace_id": "0af7651916cd43dd8448eb211c80319c", "span_id": "b7ad6b7169203331",
        "name": "GET /login", "kind": 2,
        "start_time_unix_nano": 1762164000000000000i64, "end_time_unix_nano": 1762164000100000000i64,
        "status": {"code": 2, "message": "Authorization: Bearer FAKE-NAN5352-BEARER rejected"},
        "attributes": {
            "http.method": "GET",
            "http.request.header.authorization": ["Bearer FAKE-NAN5352-BEARER"],
            "Authorization": "Bearer FAKE-NAN5352-BEARER",
            "http.url": "https://example.test/login?x-api-key=FAKE-NAN5352-APIKEY&page=2"
        },
        "events": [{"name": "retry", "time_unix_nano": 1762164000050000000i64, "attributes": {"cookie": "sid=FAKE-NAN5352-COOKIE", "attempt": 2}}],
        "links": [{"trace_id": "0af7651916cd43dd8448eb211c80319d", "span_id": "b7ad6b7169203332", "attributes": {"x-webhook-secret": "FAKE-NAN5352-WEBHOOK", "kind": "follows"}}],
        "resources": {"service.name": "nan5352", "x-api-key": "FAKE-NAN5352-APIKEY"}
    }));
    let metric = json(serde_json::json!({
        "name": "http.server.requests", "kind": "absolute", "gauge": {"value": 1.0},
        "tags": {
            "http.method": "GET",
            "authorization": "Bearer FAKE-NAN5352-BEARER",
            "resource.x-api-key": "FAKE-NAN5352-APIKEY",
            "http.request.header.cookie": "sid=FAKE-NAN5352-COOKIE",
            "http.url": "/login?x-webhook-secret=FAKE-NAN5352-WEBHOOK"
        }
    }));
    let mut runner = Chain(HashMap::new());
    for (name, event, keep) in [
        ("otlp_traces_prep", span, ["http.method", "attempt", "follows", "service.name"].as_slice()),
        ("otlp_metrics_prep", metric, ["http.method", "http.url"].as_slice()),
    ] {
        let root = vector_root_kind(&toml::from_str(&otlp).expect("OTLP config parses"), name);
        let row = runner.run_rooted(event, json(serde_json::json!({})), &[(name, transform_in(&otlp, name))], root);
        let stored = row.get(vrl::path!("event")).and_then(|v| v.as_str()).expect("event is a JSON string").into_owned();
        for secret in SECRETS {
            assert!(!stored.contains(secret), "{name}: `{secret}` reached storage: {stored}");
        }
        for k in keep {
            assert!(stored.contains(k), "{name}: `{k}` was lost: {stored}");
        }
        assert!(stored.contains("[REDACTED]"), "{name}: {stored}");
    }
}
