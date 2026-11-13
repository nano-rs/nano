// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5340: an HEC object event (`{"event": {"message": "<text>", "seq": 7}}`)
//! keeps every key whatever parser it is bound to. A JSON-input parser
//! receives the whole object (as over HTTP `/ingest`); a text parser keeps
//! `.message` = the log line and the sibling keys land in OCSF `unmapped.*` /
//! UDM `ext.*` without replacing anything the parser set.
//!
//! Runs the shipped `hec_normalize` and the generated parser chain on the VRL
//! runtime.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::hec_payload::{vrl_reads_json_object, HEC_SIBLING_SKIP_KEYS};
use super::VectorConfigManager;
use crate::parsers::types::Parser;

const HEC: &str = include_str!("../../../../config/vector/02-hec-source.toml");

/// Reads a repo file at runtime. `deploy/` and `scripts/tests/` are stripped
/// from the open-core mirror, so an `include_str!` of them would break the
/// mirror build (NAN-2169). `None` only when such a file is genuinely absent;
/// any other error, or a missing file elsewhere, panics.
fn read_stripped_repo_file(rel: &str) -> Option<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(rel);
    match std::fs::read_to_string(&path) {
        Ok(s) => Some(s),
        Err(e)
            if e.kind() == std::io::ErrorKind::NotFound
                && (rel.starts_with("deploy/") || rel.starts_with("scripts/tests/")) =>
        {
            None
        }
        Err(e) => panic!("{rel}: {e}"),
    }
}

fn transform_source(config: &str, name: &str) -> String {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(config, "$1");
    let table: toml::Table = substituted.parse().expect("config parses");
    table["transforms"][name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a VRL source"))
        .to_string()
}

fn transform_inputs(config: &str, name: &str) -> Vec<String> {
    let table: toml::Table = config.parse().expect("config parses");
    table["transforms"][name]["inputs"]
        .as_array()
        .unwrap_or_else(|| panic!("{name} has inputs"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Runs `program`; returns (event, metadata). Panics on abort or error.
fn run(program: &str, event: Value, metadata: Value) -> (Value, Value) {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles: {d:?}\n{program}"))
        .program;
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(event),
        metadata: vrl::value::Value::from(metadata),
        secrets: vrl::value::Secrets::new(),
    };
    vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
    (
        target.value.try_into().expect("event json"),
        target.metadata.try_into().expect("metadata json"),
    )
}

fn stamp(route: &str) -> Value {
    json!({ "nano_credential_id": "0b9a3c34-4cbb-4c1e-9d0f-6a3bd1f0f7e1", "nano_credential_name": route })
}

/// What Vector's `splunk_hec` source emits for `{"event": {...}}`: the object
/// spread over the root, beside the envelope fields.
fn hec_object(event: Value) -> Value {
    let mut root = json!({
        "host": "fwd-01",
        "splunk_channel": "c-1",
        "splunk_sourcetype": "_json",
        "timestamp": "2026-11-12T10:00:00Z",
    });
    for (key, value) in event.as_object().unwrap() {
        root[key] = value.clone();
    }
    root
}

fn hec_normalize(event: Value, route: &str) -> (Value, Value) {
    run(&transform_source(HEC, "hec_normalize"), event, stamp(route))
}

/// The shape of the OCSF Generic JSON parser: decode `.message` as JSON, map
/// `message` to `status_detail`, copy the whole record into `unmapped`.
const JSON_GENERIC_OCSF: &str = r#"raw_log = string!(.message)
p, perr = parse_json(raw_log)
if perr == null && is_object(p) {
    e = object!(p)
    . = { "class_uid": 0, "category_uid": 0, "status_detail": to_string(e.message) ?? "", "metadata": { "version": "1.9.0" }, "unmapped": e }
} else {
    . = { "class_uid": 0, "category_uid": 0, "raw_data": raw_log, "metadata": { "version": "1.9.0" }, "unmapped": { "parse_error": "source record is not a JSON object" } }
}"#;

/// A text (syslog) OCSF parser that also sets one `unmapped` key itself.
const SYSLOG_OCSF: &str = r#"p = parse_syslog!(string!(.message))
. = { "class_uid": 0, "category_uid": 0, "message": p.message, "device": { "hostname": p.hostname }, "metadata": { "version": "1.9.0" }, "unmapped": { "appname": p.appname } }"#;

/// A text UDM parser that replaces the root (like most UDM parsers' output
/// shape: `.udm` + `.ext`).
const SYSLOG_UDM: &str = r#"p = parse_syslog!(string!(.message))
. = { "message": .message, "udm": { "src_host": p.hostname, "user": "parsed-user" }, "ext": { "appname": p.appname } }"#;

/// A UDM JSON parser.
const JSON_UDM: &str = r#"p = object!(parse_json!(string!(.message)))
. = { "message": .message, "udm": { "user": p.user }, "ext": p }"#;

const SYSLOG_LINE: &str = "<34>1 2026-11-12T10:00:00Z edge-01 sshd 77 ID1 - Accepted password";

fn parser(name: &str, vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: name.into(),
        description: None,
        source_type: "routed".into(),
        parser_vrl: vrl.into(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        namespace: "default".into(),
        enabled: true,
        validated: true,
        validation_error: None,
        timezone: "UTC".into(),
        match_values: Some(vec![name.into()]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        extension_vrl: None,
        extension_enabled: false,
        category: None,
        vendor: None,
        product: None,
        kind: "log".into(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

/// hec_normalize, then the generated per-parser chain up to and including
/// `_ocsf_prepare` (OCSF) or `_output` (UDM). Returns the final row.
fn through_parser(p: &Parser, ocsf: bool, event: Value) -> Value {
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(p, ocsf);
    let (mut event, mut meta) = hec_normalize(event, &p.name);
    let mut stages = Vec::new();
    if ocsf {
        stages.push(format!("{}_source_lane", p.name));
    }
    if config.contains(&format!("[transforms.{}_hec_payload]", p.name)) {
        stages.push(format!("{}_hec_payload", p.name));
    }
    stages.push(format!("{}_parse", p.name));
    stages.push(if ocsf { format!("{}_ocsf_prepare", p.name) } else { format!("{}_output", p.name) });
    for stage in stages {
        (event, meta) = run(&transform_source(&config, &stage), event, meta);
    }
    event
}

fn customer_event() -> Value {
    hec_object(json!({ "message": "pm-1 hec seq=7", "probe_mark": "pm-1", "seq": 7 }))
}

#[test]
fn helm_chart_ships_the_same_hec_normalize() {
    let Some(helm_hec) = read_stripped_repo_file("deploy/helm/nano/files/vector/02-hec-source.toml") else {
        return; // open-core mirror: no Helm chart
    };
    assert_eq!(HEC, helm_hec, "run deploy/helm/nano/scripts/sync-files.sh");
}

#[test]
fn input_contract_is_inferred_from_the_first_structural_decoder() {
    assert!(vrl_reads_json_object(JSON_GENERIC_OCSF));
    assert!(vrl_reads_json_object(JSON_UDM));
    assert!(!vrl_reads_json_object(SYSLOG_OCSF));
    // JSON first, a field-level regex later: still a JSON parser (CloudTrail).
    assert!(vrl_reads_json_object(
        "p = parse_json!(.message)\nm = parse_regex(p.arn, r'^arn:(?P<x>.*)$') ?? {}"
    ));
    // A text parser that decodes an embedded JSON body after its header.
    assert!(!vrl_reads_json_object(
        "h = parse_regex!(.message, r'^(?P<hdr>\\S+) (?P<body>.*)$')\nb = parse_json(h.body) ?? {}"
    ));
    // JSON first with a line-format fallback (nginx): a text parser.
    assert!(!vrl_reads_json_object(
        "j, err = parse_json(.message)\nif err != null { j = parse_nginx_log!(.message, \"combined\") }"
    ));
    // Comments never count as code; explicit markers win.
    assert!(!vrl_reads_json_object("# parse_json(.message)\np = parse_syslog!(.message)"));
    assert!(vrl_reads_json_object("# nano:input=json\np = parse_key_value!(.message)"));
    assert!(!vrl_reads_json_object("# nano:input=text\np = parse_json!(.message)"));
    assert!(!vrl_reads_json_object(". = ."));
}

#[test]
fn only_json_input_parsers_get_the_payload_step_before_the_parser() {
    let manager = VectorConfigManager::new("/tmp/nanosiem-test");
    for ocsf in [true, false] {
        let config = manager.generate_parser_config_for(&parser("jg", JSON_GENERIC_OCSF), ocsf);
        assert_eq!(transform_inputs(&config, "jg_parse"), vec!["jg_hec_payload".to_string()]);
        let upstream = if ocsf { "jg_source_lane" } else { "source_router.jg" };
        assert_eq!(transform_inputs(&config, "jg_hec_payload"), vec![upstream.to_string()], "{config}");

        let config = manager.generate_parser_config_for(&parser("sl", SYSLOG_OCSF), ocsf);
        assert!(!config.contains("[transforms.sl_hec_payload]"), "{config}");
    }
    // A stub parser whose logic lives in its extension: the extension decides.
    let mut stub = parser("stub", "");
    stub.extension_vrl = Some(JSON_UDM.into());
    stub.extension_enabled = true;
    let config = manager.generate_parser_config_for(&stub, true);
    assert_eq!(transform_inputs(&config, "stub_extension"), vec!["stub_hec_payload".to_string()]);
}

#[test]
fn hec_normalize_stashes_the_object_only_when_message_has_siblings() {
    let (event, meta) = hec_normalize(customer_event(), "json_generic");
    assert_eq!(event["message"], "pm-1 hec seq=7", "a text parser still reads the line");
    assert_eq!(event["seq"], 7, "siblings stay on the root as before");
    assert_eq!(
        meta["nano_hec_event"],
        json!({ "message": "pm-1 hec seq=7", "probe_mark": "pm-1", "seq": 7 }),
        "envelope keys (host, timestamp, splunk_*) are not part of the event: {meta}"
    );

    // `/services/collector/raw` and a string event: nothing beside `message`.
    let (event, meta) = hec_normalize(hec_object(json!({ "message": SYSLOG_LINE })), "syslog");
    assert_eq!(event["message"], SYSLOG_LINE);
    assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{meta}");

    // An object without `message` is already the whole payload (NAN-3646).
    let (event, meta) = hec_normalize(hec_object(json!({ "seq": 7, "user": "u" })), "json_generic");
    assert_eq!(event["message"], r#"{"seq":7,"user":"u"}"#);
    assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{meta}");

    // A wrapped `.event` without a string message is serialized whole.
    let (event, meta) = hec_normalize(
        hec_object(json!({ "event": { "seq": 9, "user": "w" } })),
        "json_generic",
    );
    assert_eq!(event["message"], r#"{"seq":9,"user":"w"}"#);
    assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{meta}");

    // A non-string message keeps its value in the stash; `.message` is its JSON.
    let (event, meta) = hec_normalize(
        hec_object(json!({ "message": { "k": 1 }, "seq": 3 })),
        "json_generic",
    );
    assert_eq!(event["message"], r#"{"k":1}"#);
    assert_eq!(meta["nano_hec_event"], json!({ "message": { "k": 1 }, "seq": 3 }));

    // A stale stash from an earlier component never survives.
    let mut meta = stamp("syslog");
    meta["nano_hec_event"] = json!({ "forged": true });
    let (_, meta) = run(
        &transform_source(HEC, "hec_normalize"),
        hec_object(json!({ "message": SYSLOG_LINE })),
        meta,
    );
    assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{meta}");
}

/// The NAN-5340 acceptance case: an HEC object event bound to Generic JSON.
#[test]
fn ocsf_json_generic_keeps_every_key_of_an_hec_object_event() {
    let row = through_parser(&parser("json_generic", JSON_GENERIC_OCSF), true, customer_event());
    let event = &row["event"];
    assert!(event["unmapped"].get("parse_error").is_none(), "{row}");
    assert_eq!(event["status_detail"], "pm-1 hec seq=7", "{row}");
    assert_eq!(event["unmapped"]["seq"], 7, "{row}");
    assert_eq!(event["unmapped"]["probe_mark"], "pm-1", "{row}");
    assert_eq!(row["source_type"], "json_generic");
}

/// A string event that is itself vendor JSON, with HEC indexed `fields`
/// beside it (OpenTelemetry-style forwarders): the parser keeps the record and
/// the fields land under `unmapped`.
#[test]
fn ocsf_json_parser_keeps_a_json_message_and_files_the_fields_under_unmapped() {
    let event = hec_object(json!({
        "message": r#"{"message":"vendor text","user":"alice"}"#,
        "k8s_namespace": "prod",
    }));
    let row = through_parser(&parser("json_generic", JSON_GENERIC_OCSF), true, event);
    let event = &row["event"];
    assert_eq!(event["status_detail"], "vendor text", "{row}");
    assert_eq!(event["unmapped"]["user"], "alice", "{row}");
    assert_eq!(event["unmapped"]["message"], "vendor text", "the record's own key wins: {row}");
    assert_eq!(event["unmapped"]["k8s_namespace"], "prod", "{row}");
}

#[test]
fn ocsf_text_parser_parses_as_before_and_keeps_the_siblings_in_unmapped() {
    let event = hec_object(json!({
        "message": SYSLOG_LINE,
        "seq": 7,
        "appname": "sender-claims-this",
        "parse_fallback": true,
        "client_ip": "203.0.113.9",
        "labels": { "env": "prod" },
    }));
    let row = through_parser(&parser("syslog", SYSLOG_OCSF), true, event);
    let event = &row["event"];
    assert_eq!(event["message"], "Accepted password", "the parser read the line: {row}");
    assert_eq!(event["device"]["hostname"], "edge-01");
    assert_eq!(event["unmapped"]["appname"], "sshd", "a parser-set key is never replaced: {row}");
    assert_eq!(event["unmapped"]["seq"], 7, "{row}");
    assert_eq!(event["unmapped"]["labels"]["env"], "prod", "{row}");
    assert!(event["unmapped"].get("message").is_none(), "{row}");
    assert!(event["unmapped"].get("parse_fallback").is_none(), "health markers are not sender-settable: {row}");
    assert!(event["unmapped"].get("client_ip").is_none(), "protected identity is not sender-settable: {row}");
    assert_eq!(row["_nano_parser_fallback"], false);

    // Without siblings the row is exactly what the parser produced.
    let row = through_parser(
        &parser("syslog", SYSLOG_OCSF),
        true,
        hec_object(json!({ "message": SYSLOG_LINE })),
    );
    let unmapped = row["event"]["unmapped"].as_object().unwrap();
    let mut keys: Vec<_> = unmapped.keys().map(String::as_str).collect();
    keys.sort_unstable();
    // `claimed_source_type`: the envelope's `_json` sourcetype (NAN-4912).
    assert_eq!(keys, ["appname", "claimed_source_type"], "{row}");
}

#[test]
fn udm_text_parser_keeps_the_siblings_in_ext_and_json_parser_gets_the_object() {
    let event = hec_object(json!({ "message": SYSLOG_LINE, "seq": 7, "appname": "x", "user": "y" }));
    let row = through_parser(&parser("syslog", SYSLOG_UDM), false, event);
    assert_eq!(row["src_host"], "edge-01", "{row}");
    assert_eq!(row["user"], "parsed-user", "{row}");
    assert_eq!(row["ext"]["seq"], 7, "{row}");
    assert_eq!(row["ext"]["appname"], "sshd", "a parser-set ext key is never replaced: {row}");
    assert!(row["ext"].get("user").is_none(), "a key the parser mapped into udm is not duplicated: {row}");
    assert!(row["ext"].get("message").is_none(), "{row}");

    let event = hec_object(json!({ "message": "hello", "user": "alice", "seq": 7 }));
    let row = through_parser(&parser("jsonudm", JSON_UDM), false, event);
    assert_eq!(row["user"], "alice", "{row}");
    assert_eq!(row["ext"], json!({ "message": "hello", "seq": 7, "user": "alice" }), "{row}");
}

#[test]
fn sibling_skip_keys_match_in_every_merge_site() {
    let manager = VectorConfigManager::new("/tmp/nanosiem-test");
    let ocsf = manager.generate_parser_config_for(&parser("syslog", SYSLOG_OCSF), true);
    let udm = manager.generate_parser_config_for(&parser("syslog", SYSLOG_UDM), false);
    for (label, vrl) in [
        ("ocsf_prepare", transform_source(&ocsf, "syslog_ocsf_prepare")),
        ("udm_output", transform_source(&udm, "syslog_output")),
    ] {
        assert!(vrl.contains(&format!("!includes({HEC_SIBLING_SKIP_KEYS}, nano_key)")), "{label}");
    }
}

/// scripts/tests/json-ingest-envelopes.live.sh runs a copy of the payload step
/// against the real Vector image; it must not drift from the generated one.
#[test]
fn live_envelope_proof_runs_the_shipped_payload_step() {
    let Some(live) = read_stripped_repo_file("scripts/tests/json-ingest-envelopes.live.sh") else {
        return; // open-core mirror: no live scripts
    };
    let code: String = super::hec_payload::HEC_JSON_PAYLOAD_VRL
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    assert!(live.contains(&code), "update the copy in json-ingest-envelopes.live.sh:\n{code}");
}
