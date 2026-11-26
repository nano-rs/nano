// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5340 / NAN-5891 / NAN-5883: what each parser receives for an HEC
//! event. A `json` / `json_or_text` parser receives the sender's record whole
//! and unmodified (as over HTTP `/ingest`); a `text` parser keeps `.message` =
//! the record's log line and the record's other keys land in OCSF
//! `unmapped.*` / UDM `ext.*` without replacing anything the parser set. The
//! HEC envelope is in `%nano_hec`.
//!
//! Runs the shipped `hec_normalize` and the generated parser chain on the VRL
//! runtime. `scripts/tests/hec-record-fields.live.sh` runs the same chain in
//! the pinned Vector image, from the real `splunk_hec` source.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::hec_payload::{input_contract, InputContract, HEC_SIBLING_SKIP_KEYS_OCSF, HEC_SIBLING_SKIP_KEYS_UDM};
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

/// What the `splunk_hec_ingest` source (`event.decoding.codec = "bytes"`)
/// emits for one envelope: `.message` is a string event's text or an object
/// event's JSON; the envelope sits beside it; each indexed field lands on the
/// root unless the root already has that key. An object event is marked
/// `%splunk_hec.event_kind = "object"` (a string event "string") by a source
/// that marks the kind. Returned as `{"root": ..., "kind": ...}`;
/// [`hec_normalize`] splits it. (The live script checks the root shape
/// against the real source.)
fn hec_envelope(event: &Value, fields: Value) -> Value {
    let (message, kind) = match event {
        Value::String(s) => (s.clone(), "string"),
        other => (serde_json::to_string(other).unwrap(), if other.is_object() { "object" } else { "other" }),
    };
    let mut root = json!({
        "message": message,
        "host": "fwd-01",
        "splunk_channel": "c-1",
        "splunk_sourcetype": "_json",
        "source_type": "splunk_hec",
        "timestamp": "2026-11-12T10:00:00Z",
    });
    for (key, value) in fields.as_object().unwrap() {
        if root.get(key).is_none() {
            root[key] = value.clone();
        }
    }
    json!({ "root": root, "kind": kind })
}

/// An object event without indexed fields.
fn hec_object(event: Value) -> Value {
    hec_envelope(&event, json!({}))
}

/// The same object event from a source that does not mark the kind.
fn unmarked(mut input: Value) -> Value {
    input["kind"] = Value::Null;
    input
}

/// A `/services/collector/raw` body: no codec, marked `raw`.
fn hec_raw(body: &str) -> Value {
    json!({ "root": { "message": body, "splunk_channel": "c-1", "source_type": "splunk_hec", "timestamp": "2026-11-12T10:00:05Z" }, "kind": "raw" })
}

fn hec_normalize_with(input: Value, mut meta: Value) -> (Value, Value) {
    if let Some(kind) = input["kind"].as_str() {
        meta["splunk_hec"] = json!({ "event_kind": kind });
    }
    run(&transform_source(HEC, "hec_normalize"), input["root"].clone(), meta)
}

fn hec_normalize(input: Value, route: &str) -> (Value, Value) {
    hec_normalize_with(input, stamp(route))
}

/// The record as one JSON value, for comparisons that ignore key order.
fn parsed(text: &Value) -> Value {
    serde_json::from_str(text.as_str().expect("a JSON string")).expect("JSON")
}

/// The shape of the OCSF Generic JSON parser: decode `.message` as JSON, map
/// `message` to `status_detail`, copy the whole record into `unmapped`.
const JSON_GENERIC_OCSF: &str = r#"# nano:input=json
raw_log = string!(.message)
p, perr = parse_json(raw_log)
if perr == null && is_object(p) {
    e = object!(p)
    . = { "class_uid": 0, "category_uid": 0, "status_detail": to_string(e.message) ?? "", "metadata": { "version": "1.9.0" }, "unmapped": e }
} else {
    . = { "class_uid": 0, "category_uid": 0, "raw_data": raw_log, "metadata": { "version": "1.9.0" }, "unmapped": { "parse_error": "source record is not a JSON object" } }
}"#;

/// A mixed parser: a JSON record, else a syslog line. Records its input so a
/// test can see what it received.
const MIXED_OCSF: &str = r#"# nano:input=json_or_text
raw_log = string!(.message)
p, perr = parse_json(raw_log)
if perr == null && is_object(p) {
    . = { "class_uid": 0, "category_uid": 0, "raw_data": raw_log, "metadata": { "version": "1.9.0" }, "unmapped": object!(p) }
} else {
    s = parse_syslog!(raw_log)
    . = { "class_uid": 0, "category_uid": 0, "raw_data": raw_log, "message": s.message, "metadata": { "version": "1.9.0" }, "unmapped": { "appname": s.appname } }
}"#;

/// NAN-5902: the NAN-5891 view a declared parser and the no-parser lanes get.
const VIEW: &str = hec_record_view_vrl!();

/// NAN-5902: the e2e (`test_siem_engineer_journey`) custom parser: no
/// declared contract, `parse_json!` on `.message` first.
const UNDECLARED_JSON_OCSF: &str = r#"p = object!(parse_json!(string!(.message)))
. = { "class_uid": 0, "category_uid": 0, "metadata": { "version": "1.9.0" }, "message": string(p.msg) ?? "", "unmapped": p }"#;

/// NAN-5902: the live proof's undeclared parser (JSON first, tolerant of
/// text so every probe yields a row).
const LIVE_UNDECLARED_OCSF: &str = r#"raw_log = string(.message) ?? encode_json(.message)
p, perr = parse_json(raw_log)
if perr == null && is_object(p) {
    e = object!(p)
    . = { "class_uid": 0, "category_uid": 0, "message": to_string(e.msg) ?? "", "raw_data": raw_log, "metadata": { "version": "1.9.0" }, "unmapped": e }
} else {
    . = { "class_uid": 0, "category_uid": 0, "raw_data": raw_log, "metadata": { "version": "1.9.0" }, "unmapped": { "parse_error": true } }
}"#;

/// A text (syslog) OCSF parser that also sets one `unmapped` key itself.
const SYSLOG_OCSF: &str = r#"p = parse_syslog!(string!(.message))
. = { "class_uid": 0, "category_uid": 0, "message": p.message, "device": { "hostname": p.hostname }, "metadata": { "version": "1.9.0" }, "unmapped": { "appname": p.appname } }"#;

/// A text OCSF parser that keeps whatever line it got, verbatim.
const LINE_OCSF: &str = r#"# nano:input=text
. = { "class_uid": 0, "category_uid": 0, "raw_data": string!(.message), "metadata": { "version": "1.9.0" } }"#;

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
    if ocsf {
        stages.push(format!("{}_source_tz", p.name));
    }
    stages.push(format!("{}_parse", p.name));
    stages.push(if ocsf { format!("{}_ocsf_prepare", p.name) } else { format!("{}_output", p.name) });
    for stage in stages {
        (event, meta) = run(&transform_source(&config, &stage), event, meta);
    }
    event
}

/// The records the parsers-repo reviews found losing fields over HEC object
/// delivery (NAN-5891): a top-level `event`, `timestamp`, `host`, `metadata`,
/// null values, `line`, and an object `message`.
fn repro_records() -> Vec<(&'static str, Value)> {
    vec![
        (
            "zoom_webhook",
            json!({ "event": "meeting.started", "event_ts": 1_763_000_000_000_i64,
                    "payload": { "account_id": "acc-1", "object": { "id": "85", "topic": "standup", "host_id": "u-1" } } }),
        ),
        (
            "mysql_enterprise_audit",
            json!({ "timestamp": "2026-11-12 10:00:00", "id": 0, "class": "connection", "event": "connect",
                    "connection_id": 7, "account": { "user": "root", "host": "localhost" },
                    "login": { "user": "root", "os": "", "ip": "10.0.0.5", "proxy": "" },
                    "connection_data": { "connection_type": "ssl", "status": 0, "db": "app" } }),
        ),
        (
            "cloudwatch_flat",
            json!({ "timestamp": 1_763_000_000_000_i64, "message": "START RequestId: 1f2e Version: $LATEST",
                    "logGroup": "/aws/lambda/checkout", "logStream": "2026/11/12/[$LATEST]ab", "id": "3871" }),
        ),
        (
            "keycloak_quarkus",
            json!({ "timestamp": "2026-11-12T10:00:00.123Z", "sequence": 42, "loggerName": "org.keycloak.events",
                    "level": "WARN", "message": "type=LOGIN_ERROR, realmId=master, error=invalid_user_credentials",
                    "threadName": "executor-thread-1", "mdc": {}, "ndc": "", "hostName": "kc-0", "host": "kc-0",
                    "processId": 1, "exception": null }),
        ),
        (
            "postgresql_jsonlog",
            json!({ "timestamp": "2026-11-12 10:00:00.123 UTC", "user": "app", "dbname": "orders", "pid": 4021,
                    "remote_host": "10.0.0.9", "session_id": "6573.fb5", "line_num": 1, "ps": "authentication",
                    "error_severity": "LOG", "message": "connection authorized: user=app database=orders",
                    "backend_type": "client backend", "application_name": null, "query_id": 0 }),
        ),
        (
            "atlassian_audit",
            json!({ "message": { "key": "atlassian.audit.event.action.user.login", "translation": "User login" },
                    "timestamp": { "epochSecond": 1_763_000_000_i64, "nano": 0 },
                    "author": { "id": "u-9", "name": "admin", "type": "user" },
                    "type": { "category": "Security", "action": "User login" },
                    "metadata": { "node": "jira-1" }, "method": "Browser", "source": "10.1.2.3" }),
        ),
        (
            "docker_logging_driver",
            json!({ "line": "GET /healthz 200", "source": "stdout", "tag": "web/abc123" }),
        ),
    ]
}

#[test]
fn helm_chart_ships_the_same_hec_normalize() {
    let Some(helm_hec) = read_stripped_repo_file("deploy/helm/nano/files/vector/02-hec-source.toml") else {
        return; // open-core mirror: no Helm chart
    };
    assert_eq!(HEC, helm_hec, "run deploy/helm/nano/scripts/sync-files.sh");
}

/// NAN-5891: the source hands `hec_normalize` the `event` exactly as sent;
/// `/services/collector/raw` keeps its default (no codec).
#[test]
fn the_hec_source_decodes_the_event_as_bytes() {
    let table: toml::Table = HEC.parse().expect("02-hec-source parses");
    let source = &table["sources"]["splunk_hec_ingest"];
    assert_eq!(source["event"]["decoding"]["codec"].as_str(), Some("bytes"), "{source:?}");
    assert!(source.get("raw").is_none() && source.get("log_namespace").is_none(), "{source:?}");
}

#[test]
fn a_declared_input_contract_wins() {
    for (vrl, want) in [
        ("# nano:input=json\np = parse_key_value!(.message)", InputContract::Json),
        ("# nano:input=text\np = parse_json!(.message)", InputContract::Text),
        ("# nano:input=text\n# nano:input-v2=json_or_text\nj, e = parse_json(.message)\nif e != null { j = parse_syslog!(.message) }", InputContract::JsonOrText),
        // v2 wins over v1 (in either order); older nano reads only v1.
        ("# nano:input-v2=json\n# nano:input=text\np = parse_json!(.message)", InputContract::Json),
        ("  #  NANO:INPUT=JSON  \n. = .", InputContract::Json),
    ] {
        let v = input_contract(vrl);
        assert_eq!(v.contract, want, "{vrl}");
        assert!(v.declared, "{vrl}");
        assert!(v.warnings.is_empty(), "{vrl}: {:?}", v.warnings);
    }
    // `json_or_text` gets the whole record, like `json`.
    assert!(InputContract::JsonOrText.reads_record());
    assert!(InputContract::Json.reads_record());
    assert!(!InputContract::Text.reads_record());

    // The v1 line keeps the pre-v2.0.36 answer; `legacy` reports it.
    let v = input_contract("# nano:input=text\n# nano:input-v2=json_or_text\nj = parse_json!(.message)");
    assert_eq!((v.declared_v1, v.declared_v2, v.legacy), (Some(InputContract::Text), Some(InputContract::JsonOrText), InputContract::Text));
    // Undeclared, pre-v2.0.36 nano counted generated code; `legacy` does too.
    let v = input_contract("# NAN source timezone.\nx = parse_regex(\"\", r'a') ?? {}\n# END NAN source timezone\np = parse_json!(.message)");
    assert_eq!((v.contract, v.legacy), (InputContract::Json, InputContract::Text));
    // A bare v1 `json_or_text` is honoured here but flagged: older nano reads
    // it as undeclared and infers.
    let v = input_contract("# nano:input=json_or_text\nj = parse_json!(.message)");
    assert_eq!((v.contract, v.legacy), (InputContract::JsonOrText, InputContract::Json));
    assert_eq!(v.warnings.len(), 1, "{:?}", v.warnings);

    // A bad value is reported and ignored; two different values: the first.
    let v = input_contract("# nano:input=jsonish\np = parse_json!(.message)");
    assert_eq!((v.contract, v.declared), (InputContract::Json, false));
    assert_eq!(v.warnings.len(), 1, "{:?}", v.warnings);
    let v = input_contract("# nano:input=text\n# nano:input=json\np = parse_json!(.message)");
    assert_eq!((v.contract, v.declared, v.inferred), (InputContract::Text, true, InputContract::Json));
    assert_eq!(v.warnings.len(), 1, "{:?}", v.warnings);

    // A `text` parser that tries JSON first is flagged: it should say
    // `json_or_text` (the parsers#74 / #84 mixed shape).
    let mixed = "# nano:input=text\nj, e = parse_json(.message)\nif e != null { j = parse_key_value!(.message) }";
    assert!(input_contract(mixed).reads_json_first);
    assert!(!input_contract(&format!("# nano:input-v2=json_or_text\n{mixed}")).reads_json_first);
    assert!(!input_contract(SYSLOG_OCSF).reads_json_first);
}

#[test]
fn input_contract_is_inferred_from_the_first_structural_decoder_as_a_fallback() {
    let json = |vrl: &str| {
        let v = input_contract(vrl);
        assert!(!v.declared, "{vrl}");
        assert_eq!(v.contract, v.inferred);
        v.contract == InputContract::Json
    };
    assert!(json(JSON_UDM));
    assert!(!json(SYSLOG_OCSF));
    // JSON first, a field-level regex later: still a JSON parser (CloudTrail).
    assert!(json("p = parse_json!(.message)\nm = parse_regex(p.arn, r'^arn:(?P<x>.*)$') ?? {}"));
    // A text parser that decodes an embedded JSON body after its header.
    assert!(!json("h = parse_regex!(.message, r'^(?P<hdr>\\S+) (?P<body>.*)$')\nb = parse_json(h.body) ?? {}"));
    // JSON first with a line-format fallback (nginx): text, unless declared.
    assert!(!json("j, err = parse_json(.message)\nif err != null { j = parse_nginx_log!(.message, \"combined\") }"));
    // Comments never count as code.
    assert!(!json("# parse_json(.message)\np = parse_syslog!(.message)"));
    assert!(!json(". = ."));
}

/// NAN-5883: the blocks the parsers repo generates into a parser never decide
/// its contract (parsers#87: a prelude `parse_regex` turned 65 JSON parsers
/// into text parsers).
#[test]
fn generated_blocks_never_count_for_inference() {
    let prelude = "# NAN source timezone. Generated by scripts/residual_spill.py; edit scripts/residual/source_tz.vrl.\n\
                   tz = parse_regex(\"x\", r'(?P<z>.*)') ?? {}\n\
                   # END NAN source timezone\n";
    let clock = "# NAN local clock: ts noyear\nx = parse_regex(ts, r'^(?P<a>.*)$') ?? {}\n# END NAN local clock\n";
    let spill = "# NAN-2421 residual spill. Generated by scripts/residual_spill.py; edit the template.\n\
                 # NAN-5351: a comment inside the block\n\
                 sp = parse_json(\"{}\") ?? {}\n\
                 # END NAN-2421 residual spill\n";
    let own_json = "p = parse_json!(.message)\n";
    let own_text = "p = parse_syslog!(.message)\n";
    for (vrl, want) in [
        (format!("{prelude}{own_json}{spill}"), InputContract::Json),
        (format!("{prelude}{clock}{own_json}{spill}"), InputContract::Json),
        (format!("{prelude}{own_text}{spill}"), InputContract::Text),
        // A parser with no decoder of its own: the spill's parse_json is not one.
        (format!("{prelude}. = .\n{spill}"), InputContract::Text),
    ] {
        assert_eq!(input_contract(&vrl).contract, want, "{vrl}");
    }
    // `# NAN mixed input merge` is closed by its own END, not by
    // `# END NAN mixed input`; an unclosed `# NAN-...` is just a comment.
    let vrl = "# NAN mixed input\nm = parse_regex(\"\", r'x') ?? {}\n# END NAN mixed input\n\
               p = parse_json!(.message)\n\
               # NAN mixed input merge\nq = parse_regex(\"\", r'y') ?? {}\n# END NAN mixed input merge\n\
               # NAN-5264: explicit fallback marker\nz = 1\n";
    assert_eq!(input_contract(vrl).contract, InputContract::Json, "{vrl}");
    let vrl = "# NAN-5264: no END for this one\np = parse_json!(.message)\n";
    assert_eq!(input_contract(vrl).contract, InputContract::Json);
}

#[test]
fn only_record_reading_parsers_get_the_payload_step_before_the_parser() {
    let manager = VectorConfigManager::new("/tmp/nanosiem-test");
    for vrl in [JSON_GENERIC_OCSF, MIXED_OCSF] {
        for ocsf in [true, false] {
            let config = manager.generate_parser_config_for(&parser("jg", vrl), ocsf);
            // NAN-5839: under OCSF the control-field step sits between them.
            if ocsf {
                assert_eq!(transform_inputs(&config, "jg_parse"), vec!["jg_source_tz".to_string()]);
                assert_eq!(transform_inputs(&config, "jg_source_tz"), vec!["jg_hec_payload".to_string()]);
            } else {
                assert_eq!(transform_inputs(&config, "jg_parse"), vec!["jg_hec_payload".to_string()]);
            }
            let upstream = if ocsf { "jg_source_lane" } else { "source_router.jg" };
            assert_eq!(transform_inputs(&config, "jg_hec_payload"), vec![upstream.to_string()], "{config}");
        }
    }
    // NAN-5902: an undeclared parser's step is v2.0.35's (none for text, the
    // JSON step for JSON) and drops the lossless record before the parser
    // without reading it (review P1-1); a declared text parser gets the
    // NAN-5891 view.
    let config = manager.generate_parser_config_for(&parser("sl", SYSLOG_OCSF), true);
    assert!(!config.contains("[transforms.sl_hec_payload]"), "{config}");
    assert!(transform_source(&config, "sl_source_tz").contains("del(%nano_hec_record)"), "{config}");
    let config = manager.generate_parser_config_for(&parser("uj", UNDECLARED_JSON_OCSF), true);
    let step = transform_source(&config, "uj_hec_payload");
    assert!(!step.contains("nano_hecv_") && step.trim_end().ends_with("del(%nano_hec_record)"), "{step}");
    let config = manager.generate_parser_config_for(&parser("sl", LINE_OCSF), true);
    assert!(transform_source(&config, "sl_hec_payload").contains("nano_hecv_record"), "{config}");
    // A stub parser whose logic lives in its extension: the extension decides.
    let mut stub = parser("stub", "");
    stub.extension_vrl = Some(JSON_UDM.into());
    stub.extension_enabled = true;
    let config = manager.generate_parser_config_for(&stub, true);
    assert_eq!(transform_inputs(&config, "stub_extension"), vec!["stub_source_tz".to_string()]);
    assert_eq!(transform_inputs(&config, "stub_source_tz"), vec!["stub_hec_payload".to_string()]);
}

#[test]
fn hec_normalize_keeps_the_envelope_in_metadata_and_the_record_whole() {
    let record = json!({ "message": "pm-1 hec seq=7", "probe_mark": "pm-1", "seq": 7, "host": "rec-host", "timestamp": "rec-ts" });
    let (event, meta) = hec_normalize(hec_envelope(&record, json!({ "k8s_ns": "prod" })), "syslog");
    assert_eq!(event["message"], "pm-1 hec seq=7", "a text parser reads the line");
    assert_eq!(event["seq"], 7, "the record is spread over the root, as on v2.0.35: {event}");
    assert_eq!(event["host"], "fwd-01", "the envelope host wins, as on v2.0.35");
    assert_eq!(event["timestamp"], "2026-11-12T10:00:00Z", "{event}");
    assert_eq!(event["k8s_ns"], "prod", "indexed fields stay on the root as before");
    assert!(meta.get("splunk_hec").map_or(true, Value::is_null), "the source's kind marker is consumed: {meta}");
    let hec = &meta["nano_hec"];
    assert_eq!(hec["host"], "fwd-01");
    assert_eq!(hec["time"], "2026-11-12T10:00:00Z");
    assert_eq!(hec["sourcetype"], "_json");
    assert_eq!(hec["channel"], "c-1");
    assert_eq!(hec["fields"], json!({ "k8s_ns": "prod" }));
    assert_eq!(hec["record"], true);
    assert_eq!(hec["message_was_object"], false);
    // NAN-5902: the stash an undeclared parser reads is the v2.0.35 one (the
    // record spread under the envelope); a declared text parser's NAN-5891
    // view keeps the record's own host / timestamp.
    assert_eq!(
        meta["nano_hec_event"],
        json!({ "message": "pm-1 hec seq=7", "probe_mark": "pm-1", "seq": 7, "k8s_ns": "prod" }),
        "{meta}"
    );
    let (view, view_meta) = run(VIEW, event.clone(), meta.clone());
    assert_eq!(view["message"], "pm-1 hec seq=7", "{view}");
    assert_eq!(view["host"], "fwd-01", "{view}");
    assert_eq!(
        view_meta["nano_hec_event"],
        json!({ "probe_mark": "pm-1", "seq": 7, "host": "rec-host", "timestamp": "rec-ts", "k8s_ns": "prod" }),
        "{view_meta}"
    );
    assert_eq!(parsed(&meta["nano_hec_record"]["text"]), record);
    assert_eq!(meta["nano_hec_record"]["unfiled"], json!({ "k8s_ns": "prod" }));

    // A string event: `.message` is its text, nothing stashed.
    let (event, meta) = hec_normalize(hec_envelope(&json!(SYSLOG_LINE), json!({})), "syslog");
    assert_eq!(event["message"], SYSLOG_LINE);
    assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{meta}");
    assert!(meta.get("nano_hec_record").map_or(true, Value::is_null), "{meta}");
    assert_eq!(meta["nano_hec"]["record"], false);

    // A string event with indexed fields: the NAN-5340 stash (fields + message).
    let (event, meta) = hec_normalize(hec_envelope(&json!("plain line"), json!({ "k8s_ns": "prod" })), "syslog");
    assert_eq!(event["message"], "plain line");
    assert_eq!(meta["nano_hec_event"], json!({ "k8s_ns": "prod", "message": "plain line" }));

    // An object without a line: `.message` is the v2.0.35 payload (the spread
    // record without its nulls); the record itself, whole, waits in metadata.
    let record = json!({ "seq": 7, "user": "u", "nothing": null });
    let (event, meta) = hec_normalize(hec_object(record.clone()), "json_generic");
    assert_eq!(parsed(&event["message"]), json!({ "seq": 7, "user": "u" }));
    assert_eq!(parsed(&meta["nano_hec_record"]["text"]), record);
    assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{meta}");

    // An object `message` (Atlassian audit) does not hide the record.
    let record = json!({ "message": { "k": 1 }, "seq": 3 });
    let (event, meta) = hec_normalize(hec_object(record.clone()), "json_generic");
    assert_eq!(parsed(&event["message"]), json!({ "k": 1 }), "v2.0.35: the object message");
    assert_eq!(parsed(&meta["nano_hec_record"]["text"]), record);
    assert_eq!(meta["nano_hec"]["message_was_object"], true);

    // `{"message": {...}}` alone is a wrapper: the inner object is the record.
    let (event, meta) = hec_normalize(hec_object(json!({ "message": { "event_type": "login", "id": 115 } })), "json_generic");
    assert_eq!(parsed(&event["message"]), json!({ "event_type": "login", "id": 115 }));
    assert_eq!(meta["nano_hec"]["message_was_object"], true);

    // An indexed field whose name the record has: on v2.0.35 (and for an
    // undeclared parser) the field overwrote the record key; a declared
    // parser's view files both.
    let record = json!({ "message": "m", "env": "record-env" });
    let (event, meta) = hec_normalize(hec_envelope(&record, json!({ "env": "field-env" })), "syslog");
    assert_eq!(meta["nano_hec_event"], json!({ "env": "field-env", "message": "m" }));
    let (_, view_meta) = run(VIEW, event, meta);
    assert_eq!(view_meta["nano_hec_event"], json!({ "env": "record-env", "hec_fields": { "env": "field-env" } }));

    // A stale stash from an earlier component never survives.
    let mut meta = stamp("syslog");
    meta["nano_hec_event"] = json!({ "forged": true });
    meta["nano_hec_record"] = json!({ "text": "{\"forged\":true}" });
    let (_, meta) = hec_normalize_with(hec_envelope(&json!(SYSLOG_LINE), json!({})), meta);
    assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{meta}");
    assert!(meta.get("nano_hec_record").map_or(true, Value::is_null), "{meta}");
}

/// NAN-5891 acceptance: every repro record reaches a JSON parser whole and
/// unmodified, and a text parser loses none of its keys.
#[test]
fn every_record_field_survives_hec_object_delivery() {
    let fields = json!({ "k8s_ns": "prod" });
    for (name, record) in repro_records() {
        // JSON parser: the record, byte for byte, and every key in unmapped.
        let row = through_parser(&parser("json_generic", JSON_GENERIC_OCSF), true, hec_envelope(&record, fields.clone()));
        let unmapped = &row["event"]["unmapped"];
        assert!(unmapped.get("parse_error").is_none(), "{name}: {row}");
        for (key, value) in record.as_object().unwrap() {
            assert_eq!(&unmapped[key], value, "{name}: record key `{key}` changed or lost: {row}");
        }
        assert_eq!(unmapped["k8s_ns"], "prod", "{name}: indexed field filed: {row}");

        // json_or_text gets the same record.
        let row = through_parser(&parser("mixed", MIXED_OCSF), true, hec_envelope(&record, fields.clone()));
        assert_eq!(parsed(&row["event"]["raw_data"]), record, "{name}: {row}");

        // A text parser: its line (or the whole record), and every other key
        // under unmapped.
        let row = through_parser(&parser("line", LINE_OCSF), true, hec_envelope(&record, fields.clone()));
        let obj = record.as_object().unwrap();
        let line_key = if obj.get("message").is_some_and(Value::is_string) {
            Some("message")
        } else if obj.get("message").is_none() && obj.get("line").is_some_and(Value::is_string) {
            Some("line")
        } else {
            None
        };
        match line_key {
            Some(k) => {
                assert_eq!(row["event"]["raw_data"], obj[k], "{name}: {row}");
                for (key, value) in obj.iter().filter(|(key, _)| key.as_str() != k) {
                    assert_eq!(&row["event"]["unmapped"][key], value, "{name}: text-parser sibling `{key}`: {row}");
                }
            }
            None => assert_eq!(parsed(&row["event"]["raw_data"]), record, "{name}: {row}"),
        }
    }
}

/// The NAN-5340 acceptance case: an HEC object event bound to Generic JSON.
#[test]
fn ocsf_json_generic_keeps_every_key_of_an_hec_object_event() {
    let event = hec_object(json!({ "message": "pm-1 hec seq=7", "probe_mark": "pm-1", "seq": 7 }));
    let row = through_parser(&parser("json_generic", JSON_GENERIC_OCSF), true, event);
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
    let event = hec_envelope(&json!(r#"{"message":"vendor text","user":"alice"}"#), json!({ "k8s_namespace": "prod" }));
    let row = through_parser(&parser("json_generic", JSON_GENERIC_OCSF), true, event);
    let event = &row["event"];
    assert_eq!(event["status_detail"], "vendor text", "{row}");
    assert_eq!(event["unmapped"]["user"], "alice", "{row}");
    assert_eq!(event["unmapped"]["message"], "vendor text", "the record's own key wins: {row}");
    assert_eq!(event["unmapped"]["k8s_namespace"], "prod", "{row}");
}

/// A non-JSON string event with indexed fields bound to a JSON parser: the
/// fields and the line as one object (unchanged since NAN-5340).
#[test]
fn ocsf_json_parser_gets_a_text_string_event_with_fields_as_one_object() {
    let event = hec_envelope(&json!("plain line"), json!({ "k8s_namespace": "prod" }));
    let row = through_parser(&parser("json_generic", JSON_GENERIC_OCSF), true, event);
    assert_eq!(row["event"]["status_detail"], "plain line", "{row}");
    assert_eq!(row["event"]["unmapped"]["k8s_namespace"], "prod", "{row}");
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
    // NAN-5846: a `client_ip` sibling is vendor data and is kept verbatim;
    // nano's ingest provenance lives under `unmapped.nano.ingest` instead.
    assert_eq!(event["unmapped"]["client_ip"], "203.0.113.9", "{row}");
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

/// A mixed parser gets a plain string event as the line it is.
#[test]
fn ocsf_mixed_parser_gets_a_string_line_unchanged() {
    let row = through_parser(&parser("mixed", MIXED_OCSF), true, hec_envelope(&json!(SYSLOG_LINE), json!({})));
    assert_eq!(row["event"]["message"], "Accepted password", "{row}");
    assert_eq!(row["event"]["raw_data"], SYSLOG_LINE, "{row}");
}

/// NAN-5846: HEC siblings merged into `unmapped` for a text parser cannot
/// carry nano's provenance namespace in any spelling (nested, flat dotted,
/// mixed). Direct HEC has no ingest address, so nothing under `nano` remains;
/// every sender key is kept, whole, in the one string `source_nano_json`.
#[test]
fn ocsf_text_parser_siblings_cannot_spell_the_nano_namespace() {
    let event = hec_object(json!({
        "message": SYSLOG_LINE,
        "nano": { "ingest": { "client_ip": "6.6.6.6" }, "ingest.peer": "6.6.6.6" },
        "nano.ingest": { "peer": "6.6.6.6" },
        "nano.ingest.client_ip": "6.6.6.6",
        "client_ip": "203.0.113.9",
    }));
    let row = through_parser(&parser("syslog", SYSLOG_OCSF), true, event);
    let unmapped = row["event"]["unmapped"].as_object().unwrap();
    assert!(
        unmapped.keys().all(|k| k != "nano" && !k.starts_with("nano.")),
        "a sender spelled the nano namespace: {row}"
    );
    assert_eq!(unmapped["client_ip"], "203.0.113.9", "vendor sibling kept: {row}");
    let moved: serde_json::Value =
        serde_json::from_str(unmapped["source_nano_json"].as_str().expect("one string leaf")).unwrap();
    assert_eq!(
        moved,
        json!({
            "nano": { "ingest": { "client_ip": "6.6.6.6" }, "ingest.peer": "6.6.6.6" },
            "nano.ingest": { "peer": "6.6.6.6" },
            "nano.ingest.client_ip": "6.6.6.6",
        }),
        "every sender key kept whole: {row}"
    );
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
    for (label, vrl, keys) in [
        ("ocsf_prepare", transform_source(&ocsf, "syslog_ocsf_prepare"), HEC_SIBLING_SKIP_KEYS_OCSF),
        ("udm_output", transform_source(&udm, "syslog_output"), HEC_SIBLING_SKIP_KEYS_UDM),
    ] {
        assert!(vrl.contains(&format!("!includes({keys}, nano_key)")), "{label}");
    }
}

/// NAN-5891 (review P1-1): an HEC STRING event and a `/services/collector/raw`
/// body take exactly the pre-NAN-5891 path, whatever their text holds.
#[test]
fn string_events_and_raw_bodies_are_handled_as_before() {
    let json_line = r#"{"message":"raw-json-msg","extra":"keep-me","timestamp":"2026-01-01T00:00:00Z","host":"app-1"}"#;
    for (label, input) in [
        ("string event", hec_envelope(&json!(json_line), json!({}))),
        ("raw body", hec_raw(json_line)),
        ("string wrapper", hec_envelope(&json!(r#"{"message":{"inner":1}}"#), json!({}))),
        ("raw wrapper", hec_raw(r#"{"message":{"inner":1}}"#)),
    ] {
        let text = input["root"]["message"].as_str().unwrap().to_string();
        let (event, meta) = hec_normalize(input, "syslog");
        assert_eq!(event["message"], text, "{label}: the text is kept verbatim: {event}");
        assert!(event.get("extra").is_none() && event.get("inner").is_none(), "{label}: nothing spread: {event}");
        assert!(meta.get("nano_hec_record").map_or(true, Value::is_null), "{label}: {meta}");
        assert!(meta.get("nano_hec_event").map_or(true, Value::is_null), "{label}: {meta}");
        assert_eq!(meta["nano_hec"]["record"], false, "{label}");
    }
    // A source that marks nothing (an older image): see
    // `an_unmarked_source_gets_the_legacy_object_handling`.

    // A text parser reads a JSON string event whole, as before.
    let row = through_parser(&parser("line", LINE_OCSF), true, hec_envelope(&json!(json_line), json!({})));
    assert_eq!(row["event"]["raw_data"], json_line, "{row}");
}

/// Review round 2 P1-1 (defense in depth): on a Vector that marks nothing,
/// compact JSON-object text is an object event handled exactly as the legacy
/// source and the pre-NAN-5891 hec_normalize did; other text is a string event.
#[test]
fn an_unmarked_source_gets_the_legacy_object_handling() {
    // A wrapper around a text line: a text parser reads the line, the other
    // keys spread onto the root and are filed under unmapped (as on main).
    let wrapper = json!({ "message": SYSLOG_LINE, "attrs": { "k": "v" }, "seq": 7, "timestamp": "rec-ts", "host": "rec-host" });
    let (event, meta) = hec_normalize(unmarked(hec_object(wrapper.clone())), "syslog");
    assert_eq!(event["message"], SYSLOG_LINE, "{event}");
    assert_eq!(event["seq"], 7, "spread onto the root: {event}");
    assert_eq!(event["host"], "fwd-01", "the envelope host wins, as in the legacy source: {event}");
    assert_eq!(event["timestamp"], "2026-11-12T10:00:00Z", "{event}");
    assert_eq!(meta["nano_hec"]["record"], false);
    assert!(meta.get("nano_hec_record").map_or(true, Value::is_null), "{meta}");
    let row = through_parser(&parser("syslog", SYSLOG_OCSF), true, unmarked(hec_object(wrapper)));
    assert_eq!(row["event"]["message"], "Accepted password", "{row}");
    assert_eq!(row["event"]["unmapped"]["seq"], 7, "{row}");
    assert_eq!(row["event"]["unmapped"]["attrs"]["k"], "v", "{row}");

    // The Docker logging driver's `line` becomes the message, as before.
    let (event, _) = hec_normalize(unmarked(hec_object(json!({ "line": "GET /", "tag": "web" }))), "syslog");
    assert_eq!(event["message"], "GET /", "{event}");
    assert_eq!(event["tag"], "web", "{event}");

    // `{"message": {...}}` alone: the inner object is the payload, as before.
    let (event, _) = hec_normalize(unmarked(hec_object(json!({ "message": { "id": 1 } }))), "json_generic");
    assert_eq!(parsed(&event["message"]), json!({ "id": 1 }));

    // Pretty-printed JSON (not what the source's re-serialization looks like)
    // and a text line stay string events.
    for text in ["{ \"message\": \"m\", \"k\": 1 }", SYSLOG_LINE] {
        let (event, _) = hec_normalize(unmarked(hec_envelope(&json!(text), json!({}))), "syslog");
        assert_eq!(event["message"], text);
        assert!(event.get("k").is_none(), "{event}");
    }
}

/// Review round 2 P1-2: a marked object event's record reaches a JSON parser
/// as received, the sender's key order included.
#[test]
fn a_marked_record_keeps_its_bytes() {
    let text = r#"{"timestamp":"2026-10-08T15:24:35Z","message":"m","src_ip":"10.0.0.14","marker":"hec-event"}"#;
    let mut input = hec_object(serde_json::from_str(text).unwrap());
    input["root"]["message"] = json!(text);
    let p = parser("json_generic", JSON_GENERIC_OCSF);
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(&p, true);
    let (event, meta) = hec_normalize(input, "json_generic");
    let (event, _) = run(&transform_source(&config, "json_generic_hec_payload"), event, meta);
    assert_eq!(event["message"], text, "byte for byte");
}

/// Review round 2 P2-1: the no-parser OCSF lane keeps every key of an object
/// record once: keys the root has with the same value are not repeated, and a
/// genuinely colliding one goes under `hec_record` (or a free name).
#[test]
fn the_no_parser_lane_keeps_each_record_key_once() {
    let pipe = VectorConfigManager::pipeline_config_content_for(true);
    let stages = ["generic_parser", "generic_ocsf_prepare"].map(|n| transform_source(&pipe, n));
    let lane = |record: Value| {
        let (mut event, mut meta) = hec_normalize(hec_envelope(&record, json!({ "k8s_ns": "prod" })), "unrouted_src");
        for stage in &stages {
            (event, meta) = run(stage, event, meta);
        }
        event["event"]["unmapped"].clone()
    };
    let unmapped = lane(json!({ "message": "hello line", "extra": "keep", "seq": 7, "timestamp": "rec-ts", "host": "rec-host" }));
    assert_eq!(unmapped["extra"], "keep", "{unmapped}");
    assert_eq!(unmapped["k8s_ns"], "prod", "{unmapped}");
    assert_eq!(unmapped["hec_record"], json!({ "timestamp": "rec-ts", "host": "rec-host" }), "only the colliding keys: {unmapped}");

    // Review r3 P1-1: a LINELESS record (no string `message` / `line`) keeps
    // every key too: its own `id`, `sourcetype` and null values at the top
    // (as main kept them), and every colliding key, an object `message`
    // included, under `hec_record`. A record `"hec_record": null` is not
    // replaced: the collisions take the next free name.
    let unmapped = lane(json!({
        "id": "evt-1", "sourcetype": "vendor", "timestamp": "rec-ts", "host": "rec-host",
        "metadata": { "node": "n1" }, "gone": null, "message": { "k": 1 }, "detail": { "a": 2 },
    }));
    assert_eq!(unmapped["id"], "evt-1", "{unmapped}");
    assert_eq!(unmapped["sourcetype"], "vendor", "{unmapped}");
    assert!(unmapped.as_object().unwrap().contains_key("gone") && unmapped["gone"].is_null(), "{unmapped}");
    assert_eq!(unmapped["detail"]["a"], 2, "{unmapped}");
    let kept = &unmapped["hec_record"];
    assert_eq!(kept["timestamp"], "rec-ts", "{unmapped}");
    assert_eq!(kept["host"], "rec-host", "{unmapped}");
    assert_eq!(kept["metadata"], json!({ "node": "n1" }), "{unmapped}");
    assert_eq!(kept["message"], json!({ "k": 1 }), "{unmapped}");
    let unmapped = lane(json!({ "message": { "k": 1 }, "hec_record": null, "host": "rec-host" }));
    assert!(unmapped["hec_record"].is_null(), "the record's own null is kept: {unmapped}");
    assert_eq!(unmapped["hec_record_kept"]["host"], "rec-host", "{unmapped}");

    // The record has its own `hec_record`: the colliding keys move to a free name.
    let unmapped = lane(json!({ "message": "m", "hec_record": "mine", "host": "rec-host" }));
    assert_eq!(unmapped["hec_record"], "mine", "{unmapped}");
    assert_eq!(unmapped["hec_record_kept"], json!({ "host": "rec-host" }), "{unmapped}");
}

/// NAN-5902: the e2e case. An undeclared parser starting with
/// `parse_json!(string!(.message))` gets, for `{"event": {"message": "<json
/// text>"}}`, the JSON text in `.message` (as on v2.0.35) and parses it.
#[test]
fn an_undeclared_json_parser_gets_the_v2_0_35_message() {
    let inner = r#"{"msg":"journey","user":"alice","n":3}"#;
    let row = through_parser(&parser("uj", UNDECLARED_JSON_OCSF), true, hec_object(json!({ "message": inner })));
    assert_eq!(row["event"]["message"], "journey", "{row}");
    assert_eq!(row["event"]["unmapped"]["user"], "alice", "{row}");
    // With indexed fields too (the v2.0.35 stash: .message is JSON, kept).
    let row = through_parser(&parser("uj", UNDECLARED_JSON_OCSF), true, hec_envelope(&json!({ "message": inner }), json!({ "k8s_ns": "prod" })));
    assert_eq!(row["event"]["message"], "journey", "{row}");
    assert_eq!(row["event"]["unmapped"]["k8s_ns"], "prod", "{row}");
    // A declared json parser gets the whole record instead (NAN-5891).
    let declared = format!("# nano:input=json\n{UNDECLARED_JSON_OCSF}");
    let row = through_parser(&parser("dj", &declared), true, hec_object(json!({ "message": inner })));
    assert_eq!(row["event"]["unmapped"]["message"], inner, "the record, whole: {row}");
}

/// Review P2-1: a record cannot plant envelope routing keys on the root.
#[test]
fn a_record_cannot_set_envelope_keys_on_the_root() {
    let mut input = hec_object(json!({ "message": "m", "splunk_source": "spoof-src", "splunk_index": "spoof-idx", "splunk_channel": "spoof-ch" }));
    input["root"].as_object_mut().unwrap().remove("splunk_channel");
    let (event, meta) = hec_normalize(input, "syslog");
    for key in ["splunk_source", "splunk_index", "splunk_channel"] {
        assert!(event.get(key).is_none(), "{key} copied onto the root: {event}");
        assert!(meta["nano_hec"].get(key.trim_start_matches("splunk_")).map_or(true, Value::is_null), "{meta}");
    }
    assert_eq!(parsed(&meta["nano_hec_record"]["text"])["splunk_source"], "spoof-src", "the value is kept as record data");
    let (view, view_meta) = run(VIEW, event, meta);
    assert!(view.get("splunk_source").is_none(), "{view}");
    assert_eq!(view_meta["nano_hec_event"]["splunk_source"], "spoof-src", "{view_meta}");
}

/// Review P1-1: no HEC metadata is carried past the storage step.
#[test]
fn hec_metadata_ends_at_the_storage_step() {
    let p = parser("line", LINE_OCSF);
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(&p, true);
    let (event, meta) = hec_normalize(hec_object(json!({ "message": "m", "seq": 1 })), "line");
    assert!(meta.get("nano_hec_record").is_some_and(Value::is_object));
    let mut state = (event, meta);
    for stage in ["line_source_lane", "line_hec_payload", "line_source_tz", "line_parse", "line_ocsf_prepare"] {
        state = run(&transform_source(&config, stage), state.0, state.1);
    }
    for key in ["nano_hec", "nano_hec_record", "nano_hec_event"] {
        assert!(state.1.get(key).map_or(true, Value::is_null), "{key} survived: {}", state.1);
    }
}

/// The live scripts run copies of the payload step against the real Vector
/// image; they must not drift from the generated one.
#[test]
fn live_envelope_proofs_run_the_shipped_payload_step() {
    let code: String = super::hec_payload::HEC_JSON_PAYLOAD_VRL
        .lines()
        .filter(|l| !l.trim_start().starts_with('#'))
        .map(|l| format!("{l}\n"))
        .collect();
    for script in ["scripts/tests/json-ingest-envelopes.live.sh"] {
        // (hec-record-fields.live.sh renders the real chain instead.)
        let Some(live) = read_stripped_repo_file(script) else {
            return; // open-core mirror: no live scripts
        };
        assert!(live.contains(&code), "update the copy in {script}:\n{code}");
    }
}

/// `scripts/tests/hec-record-fields.live.sh` loads the REAL generated chain:
/// this writes it (with a console sink per parser) when
/// `NANO_HEC_LIVE_CHAIN_OUT` names a directory. A no-op otherwise.
#[test]
fn write_the_live_hec_chain_when_asked() {
    let Ok(dir) = std::env::var("NANO_HEC_LIVE_CHAIN_OUT") else {
        return;
    };
    let manager = VectorConfigManager::new("/tmp/nanosiem-test");
    let mut routes = String::from("[transforms.source_router]\ntype = \"route\"\ninputs = [\"hec_normalize\"]\n");
    let mut sinks = String::new();
    for (name, vrl) in [
        ("live_json", format!("{JSON_GENERIC_OCSF}\n.unmapped.nano_hec_seen = %nano_hec")),
        ("live_mixed", format!("{MIXED_OCSF}\n.unmapped.nano_hec_seen = %nano_hec")),
        ("live_text", format!("{LINE_OCSF}\n.unmapped = {{ \"nano_hec_seen\": %nano_hec }}")),
        // NAN-5902: no declared contract, JSON first: the v2.0.35 delivery.
        ("live_undeclared", format!("{LIVE_UNDECLARED_OCSF}\n.unmapped.nano_hec_seen = %nano_hec")),
    ] {
        let config = manager.generate_parser_config_for(&parser(name, &vrl), true);
        std::fs::write(format!("{dir}/{name}.toml"), crate::vector_env::escape_file(&config)).unwrap();
        routes.push_str(&format!("route.{name} = '.source_type == \"{name}\"'\n"));
        sinks.push_str(&format!(
            "\n[sinks.{name}_out]\ntype = \"console\"\ninputs = [\"{name}_ocsf_prepare\"]\nencoding.codec = \"json\"\n"
        ));
    }
    std::fs::write(format!("{dir}/00-live-router.toml"), format!("{routes}{sinks}")).unwrap();
}

/// The v2.0.35 hec_normalize, verbatim (the NAN-5902 reference).
const HEC_V2_0_35: &str = include_str!("testdata/v2_0_35_hec_normalize.vrl");

/// What the v2.0.35 (legacy-namespace, no codec) `splunk_hec` source emitted
/// for an envelope: an object event spread over the root (`line` -> message),
/// then the indexed fields, `timestamp` and `host` overwriting; a string event
/// as `.message`. `None`: the source refused it (an array or scalar event).
fn v2_0_35_source(event: &Value, fields: &Value) -> Option<Value> {
    let mut root = serde_json::Map::new();
    match event {
        Value::String(s) => {
            root.insert("message".into(), json!(s));
        }
        Value::Object(o) => {
            let mut o = o.clone();
            if let Some(line) = o.remove("line") {
                let key = if line.is_object() || line.is_array() { "line" } else { "message" };
                root.insert(key.into(), line);
            }
            root.extend(o);
        }
        _ => return None,
    }
    root.insert("source_type".into(), json!("splunk_hec"));
    root.insert("splunk_channel".into(), json!("c-1"));
    for (k, v) in fields.as_object().unwrap() {
        root.insert(k.clone(), v.clone());
    }
    root.insert("timestamp".into(), json!("2026-11-12T10:00:00Z"));
    root.insert("host".into(), json!("fwd-01"));
    root.insert("splunk_sourcetype".into(), json!("_json"));
    Some(Value::Object(root))
}

/// [`run`], with a runtime error returned instead of a panic.
fn try_run(program: &str, event: Value, metadata: Value) -> Result<(Value, Value), String> {
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
        .map_err(|e| format!("{e:?}"))?;
    Ok((target.value.try_into().expect("event json"), target.metadata.try_into().expect("metadata json")))
}

/// The row `p` stores for `root` after `hec_toml_source` (the v2.0.35 or the
/// current hec_normalize), through the generated chain. `legacy` replaces the
/// generated payload step with the v2.0.35 one (as v2.0.35 rendered it).
fn row_through(p: &Parser, ocsf: bool, normalize: &str, root: Value, meta: Value, legacy: bool) -> Value {
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(p, ocsf);
    let (mut event, mut meta) = run(normalize, root, meta);
    let mut stages: Vec<String> = Vec::new();
    if ocsf {
        stages.push(transform_source(&config, &format!("{}_source_lane", p.name)));
    }
    if legacy {
        if super::hec_payload::input_contract(&p.parser_vrl).legacy == InputContract::Json {
            stages.push(super::hec_payload::HEC_LEGACY_JSON_PAYLOAD_VRL.to_string());
        }
    } else if config.contains(&format!("[transforms.{}_hec_payload]", p.name)) {
        stages.push(transform_source(&config, &format!("{}_hec_payload", p.name)));
    }
    if ocsf {
        stages.push(transform_source(&config, &format!("{}_source_tz", p.name)));
    }
    stages.push(transform_source(&config, &format!("{}_parse", p.name)));
    stages.push(transform_source(&config, &format!("{}_{}", p.name, if ocsf { "ocsf_prepare" } else { "output" })));
    for stage in stages.iter() {
        match try_run(stage, event, meta) {
            Ok(next) => (event, meta) = next,
            // A parser that aborts on its input aborts the same way on both.
            // (The same error; the stage index moves with the added step.)
            Err(e) => return json!({ "error": e }),
        }
    }
    // The storage timestamp is `now()` when the parser sets no time.
    if let Some(o) = event.as_object_mut() {
        o.remove("timestamp");
        o.remove("id");
    }
    event
}

/// NAN-5902: a parser that declares NO input contract receives exactly what
/// v2.0.35 delivered, for every HEC event kind (object, object with indexed
/// fields, string, string with fields, `/raw`), on the OCSF and the legacy
/// UDM lane. (An array or scalar event, which v2.0.35's source refused, gets
/// the string handling.)
#[test]
fn undeclared_parsers_get_the_v2_0_35_delivery() {
    let parsers = [
        ("uj", UNDECLARED_JSON_OCSF.to_string(), true),
        ("ug", JSON_GENERIC_OCSF.replace("# nano:input=json\n", ""), true),
        ("us", SYSLOG_OCSF.to_string(), true),
        ("uju", JSON_UDM.to_string(), false),
        ("usu", SYSLOG_UDM.to_string(), false),
    ];
    let inner = r#"{"msg":"journey","user":"alice","n":3}"#;
    let records = [
        json!({ "message": inner }),
        json!({ "message": inner, "seq": 7 }),
        json!({ "message": SYSLOG_LINE, "seq": 7, "host": "rec-host", "timestamp": "rec-ts", "gone": null }),
        json!({ "msg": "no message", "user": "bob", "id": "e1", "metadata": { "node": "n1" }, "timestamp": "rec-ts" }),
        json!({ "line": SYSLOG_LINE, "tag": "web" }),
        json!({ "line": { "nested": 1 }, "tag": "web" }),
        json!({ "message": { "msg": "inner", "k": 1 } }),
        json!({ "message": { "msg": "inner" }, "author": "x" }),
        json!({ "event": "meeting.started", "payload": { "id": "1" } }),
        json!({ "event": { "msg": "lifted", "src": "a" }, "routing": { "h": "w" } }),
        json!({ "splunk_source": "spoof", "message": "m" }),
    ];
    let texts = [SYSLOG_LINE, inner, "plain text", r#"{ "msg": "pretty", "user": "carol" }"#];
    let mut compared = 0;
    for (name, vrl, ocsf) in &parsers {
        assert!(!super::hec_payload::input_contract(vrl).declared, "{name} must be undeclared");
        let p = parser(name, vrl);
        let meta = |kind: Option<&str>| {
            let mut m = stamp(name);
            if let Some(kind) = kind {
                m["splunk_hec"] = json!({ "event_kind": kind });
            }
            m
        };
        let mut cases: Vec<(String, Value, Value, Value)> = Vec::new();
        for fields in [json!({}), json!({ "k8s_ns": "prod" })] {
            for r in &records {
                let new = hec_envelope(r, fields.clone())["root"].clone();
                cases.push((format!("object {r} {fields}"), v2_0_35_source(r, &fields).unwrap(), new, meta(Some("object"))));
            }
            for t in texts {
                let new = hec_envelope(&json!(t), fields.clone())["root"].clone();
                cases.push((format!("string {t} {fields}"), v2_0_35_source(&json!(t), &fields).unwrap(), new, meta(Some("string"))));
            }
        }
        for t in texts {
            let raw = hec_raw(t)["root"].clone();
            cases.push((format!("raw {t}"), raw.clone(), raw, meta(Some("raw"))));
        }
        for (label, old_root, new_root, new_meta) in cases {
            let want = row_through(&p, *ocsf, HEC_V2_0_35, old_root, stamp(name), true);
            let got = row_through(&p, *ocsf, &transform_source(HEC, "hec_normalize"), new_root, new_meta, false);
            assert_eq!(got, want, "{name} / {label}: undeclared delivery differs from v2.0.35");
            compared += 1;
        }
    }
    assert!(compared >= 5 * 33, "{compared}");
}

/// The #10462 (NAN-5891, ee6783e170) hec_normalize and JSON payload step,
/// verbatim: the reference for declared parsers and the no-parser lanes.
const HEC_NAN5891: &str = include_str!("testdata/v2_0_36_nan5891_hec_normalize.vrl");
const JSON_PAYLOAD_NAN5891: &str = include_str!("testdata/v2_0_36_nan5891_json_payload.vrl");

/// Values that depend on the run (`now()`), replaced so two runs compare.
fn without_now(v: &mut Value) {
    let now = chrono::Utc::now();
    let (ms, today) = (now.timestamp_millis(), now.format("%Y-%m-%d").to_string());
    match v {
        Value::Object(o) => {
            o.remove("id");
            o.values_mut().for_each(without_now)
        }
        Value::Array(a) => a.iter_mut().for_each(without_now),
        Value::String(s) if s.contains(&today) => *s = "<now>".into(),
        Value::Number(n) if n.as_i64().is_some_and(|i| (i - ms).abs() < 86_400_000 || (i - ms / 1000).abs() < 86_400) => {
            *v = json!("<now>")
        }
        _ => {}
    }
}

/// Runs `stages` after `normalize` on one source event; a stage that aborts
/// is part of the result.
fn chain_row(normalize: &str, stages: &[String], root: Value, meta: Value) -> Value {
    let (mut event, mut meta) = run(normalize, root, meta);
    for stage in stages.iter() {
        match try_run(stage, event, meta) {
            Ok(next) => (event, meta) = next,
            // (The same error; the stage index moves with the added step.)
            Err(e) => return json!({ "error": e }),
        }
    }
    let leftover: Vec<&String> = meta.as_object().map(|o| o.keys().filter(|k| k.starts_with("nano_hec")).collect()).unwrap_or_default();
    assert!(leftover.is_empty(), "HEC metadata survived the storage step: {leftover:?}");
    without_now(&mut event);
    event
}

/// The marked HEC object events the review named (NAN-5902 P1-2 / P2-1) and
/// the NAN-5891 repro shapes, each with and without indexed fields and with
/// and without an envelope `host`.
fn review_cases() -> Vec<(String, Value)> {
    let records = [
        json!({ "event": "meeting.started", "event_ts": 1763000000000_i64, "payload": { "id": "85" } }),
        json!({ "message": "real-msg", "event": { "inner_k": "polluted", "other": 1 }, "top": "ok" }),
        json!({ "event": null, "msg": "hi" }),
        json!({ "message": { "key": "atlassian.audit.login" }, "author": { "id": "u-9" }, "metadata": { "node": "jira-1" } }),
        json!({ "metadata": { "parse_error": "vendor says so" }, "m": 1 }),
        json!({ "host": { "name": "ecs-host-1", "ip": "10.0.0.1" }, "message": "hi" }),
        json!({ "host": "record-inner-host", "msg": "hi" }),
        json!({ "message": SYSLOG_LINE, "seq": 7, "timestamp": "rec-ts", "gone": null }),
        json!({ "line": SYSLOG_LINE, "tag": "web" }),
        json!({ "message": { "msg": "inner", "k": 1 } }),
        json!({ "message": "collides", "k8s_ns": "record-ns" }),
        json!({ "splunk_source": "spoof", "sourcetype": "rec-st", "message": "m" }),
        json!({ "msg": "no message", "user": "bob", "id": "e1", "timestamp": "rec-ts" }),
    ];
    let mut cases = Vec::new();
    for r in &records {
        for fields in [json!({}), json!({ "k8s_ns": "prod" })] {
            for with_host in [true, false] {
                let mut input = hec_envelope(r, fields.clone());
                if !with_host {
                    input["root"].as_object_mut().unwrap().remove("host");
                }
                cases.push((format!("{r} fields={fields} host={with_host}"), input));
            }
        }
    }
    cases
}

/// NAN-5902 review P1-2 / P2-1: a parser that DECLARES a contract, and the
/// no-parser lanes (OCSF `generic_ocsf_prepare`, UDM `prepare_output`), get
/// exactly what #10462 (NAN-5891) gave them, for every marked object event.
#[test]
fn declared_parsers_and_no_parser_lanes_get_the_nan5891_delivery() {
    let hec_now = transform_source(HEC, "hec_normalize");
    let manager = VectorConfigManager::new("/tmp/nanosiem-test");
    let mut compared = 0;
    // Declared parsers: #10462's step (the JSON step for json / json_or_text,
    // none for text) vs the generated chain.
    let declared = [
        ("dj", JSON_GENERIC_OCSF.to_string(), true, true),
        ("dm", MIXED_OCSF.to_string(), true, true),
        ("dt", LINE_OCSF.to_string(), true, false),
        ("dju", format!("# nano:input=json\n{JSON_UDM}"), false, true),
        ("dsu", format!("# nano:input=text\n{SYSLOG_UDM}"), false, false),
    ];
    for (name, vrl, ocsf, reads_record) in &declared {
        let p = parser(name, vrl);
        let config = manager.generate_parser_config_for(&p, *ocsf);
        let stage = |s: &str| transform_source(&config, &format!("{name}_{s}"));
        let (lane, prepare) = if *ocsf { (vec![stage("source_lane")], stage("ocsf_prepare")) } else { (vec![], stage("output")) };
        let tz = if *ocsf { vec![stage("source_tz")] } else { vec![] };
        let mut old: Vec<String> = lane.clone();
        if *reads_record {
            old.push(JSON_PAYLOAD_NAN5891.to_string());
        }
        old.extend(tz.clone());
        old.push(stage("parse"));
        old.push(prepare.clone());
        let mut new: Vec<String> = lane;
        new.push(stage("hec_payload"));
        new.extend(tz);
        new.push(stage("parse"));
        new.push(prepare);
        for (label, input) in review_cases() {
            let meta = || {
                let mut m = stamp(name);
                m["splunk_hec"] = json!({ "event_kind": "object" });
                m
            };
            let want = chain_row(HEC_NAN5891, &old, input["root"].clone(), meta());
            let got = chain_row(&hec_now, &new, input["root"].clone(), meta());
            assert_eq!(got, want, "{name} / {label}: declared delivery differs from #10462");
            compared += 1;
        }
    }
    // The no-parser lanes: #10462's generic_parser had no view step.
    for ocsf in [true, false] {
        let pipeline = VectorConfigManager::pipeline_config_content_for(ocsf);
        let generic = transform_source(&pipeline, "generic_parser");
        assert!(generic.starts_with(VIEW), "{generic}");
        let prepare = transform_source(&pipeline, if ocsf { "generic_ocsf_prepare" } else { "prepare_output" });
        let old = vec![generic.replacen(VIEW, "", 1), prepare.clone()];
        let new = vec![generic.clone(), prepare];
        for (label, input) in review_cases() {
            let mut meta = stamp("*");
            meta["splunk_hec"] = json!({ "event_kind": "object" });
            let want = chain_row(HEC_NAN5891, &old, input["root"].clone(), meta.clone());
            let got = chain_row(&hec_now, &new, input["root"].clone(), meta);
            assert_eq!(got, want, "no-parser ocsf={ocsf} / {label}: differs from #10462");
            compared += 1;
        }
    }
    assert_eq!(compared, 7 * 13 * 4);
}

/// NAN-5902 review P2-1: `%nano_hec` is the envelope as sent, never the
/// record's (an envelope without `host` keeps `host` null).
#[test]
fn nano_hec_is_the_envelope_only() {
    let mut input = hec_object(json!({ "host": { "name": "ecs-host-1" }, "timestamp": "rec-ts", "message": "hi" }));
    input["root"].as_object_mut().unwrap().remove("host");
    let (event, meta) = hec_normalize(input, "syslog");
    assert!(meta["nano_hec"]["host"].is_null(), "{meta}");
    assert_eq!(meta["nano_hec"]["time"], "2026-11-12T10:00:00Z", "{meta}");
    // (The v2.0.35 root, for an undeclared parser, still has the record's.)
    assert_eq!(event["host"]["name"], "ecs-host-1", "{event}");
    // The NAN-5891 root copies a record key the envelope lacks (#10462).
    let (view, _) = run(VIEW, event, meta);
    assert_eq!(view["host"]["name"], "ecs-host-1", "{view}");
}

/// NAN-5902 review P2-2: the warn-once set dedupes per parser and stays
/// bounded.
#[test]
fn contract_warnings_are_deduped_and_bounded() {
    use super::hec_payload::{first_warning, MAX_CONTRACT_WARNED};
    let id = Uuid::new_v4();
    assert!(first_warning(id, "note"));
    assert!(!first_warning(id, "note"));
    assert!(first_warning(Uuid::new_v4(), "note"), "per parser");
    for i in 0..(MAX_CONTRACT_WARNED + 10) {
        first_warning(id, &format!("n{i}"));
    }
    // Past the cap the set started over: memory is bounded, a warning repeats.
    assert!(first_warning(id, "note"));
    // An oversized declaration is quoted truncated.
    let verdict = input_contract(&format!("# nano:input={}\n.", "x".repeat(10_000)));
    assert!(verdict.warnings.iter().all(|w| w.len() < 200), "{:?}", verdict.warnings);
}

/// NAN-5902 review r2 P1-1: routing takes the sourcetype from the envelope
/// (or the token binding), never from the record, when the envelope sends
/// none or an empty one; the undeclared parser's v2.0.35 root keeps the key.
#[test]
fn a_record_sourcetype_never_routes_the_event() {
    let record = json!({ "sourcetype": "evil_or_vendor_st", "message": "hello world", "seq": 1 });
    for envelope_st in [None, Some("")] {
        let mut input = hec_object(record.clone());
        match envelope_st {
            None => {
                input["root"].as_object_mut().unwrap().remove("splunk_sourcetype");
            }
            Some(st) => input["root"]["splunk_sourcetype"] = json!(st),
        }
        // A source-bound token: the binding, no claim recorded.
        let (event, meta) = hec_normalize(input.clone(), "syslog");
        assert_eq!(event["source_type"], "syslog", "{envelope_st:?}: {event}");
        assert!(event.get("claimed_source_type").map_or(true, Value::is_null), "{envelope_st:?}: {event}");
        assert!(meta.get("nano_claimed_source_type").map_or(true, Value::is_null), "{envelope_st:?}: {meta}");
        assert_eq!(event["sourcetype"], "evil_or_vendor_st", "the v2.0.35 root keeps the record key");
        // A multiplex token: nothing declared, so `unknown`.
        let (event, _) = hec_normalize(input, "*");
        assert_eq!(event["source_type"], "unknown", "{envelope_st:?}: {event}");
    }
    // The envelope's own (legacy-spelled) sourcetype still routes.
    let mut input = hec_object(record);
    let root = input["root"].as_object_mut().unwrap();
    root.remove("splunk_sourcetype");
    root.insert("sourcetype".into(), json!("Env_ST"));
    let (event, _) = hec_normalize(input, "*");
    assert_eq!(event["source_type"], "env_st", "{event}");
}

/// NAN-5902 review r2 P2-2: source-config routing rules (`splunk_hec_route`,
/// between hec_normalize and the parsers) match the v2.0.35 root, so rules
/// written for v2.0.35 keep matching; their `.source_type` rewrite carries
/// into what a declared parser and the no-parser lanes see (the NAN-5891
/// view), and into an undeclared parser's v2.0.35 root.
#[test]
fn routing_rules_match_the_v2_0_35_root_and_their_rewrite_survives() {
    // A rule as `source_configs` renders it: on a key v2.0.35 spread onto the
    // root, and on `.event`, which v2.0.35 lifted away.
    let rule = r#"if .source_type == "_json" && exists(.event_ts) { .source_type = "zoom" }
if exists(.event) { .source_type = "never_on_v2_0_35" }"#;
    let input = hec_object(json!({ "event": "meeting.started", "event_ts": 1763000000000_i64, "payload": { "id": "85" } }));
    let (event, meta) = hec_normalize(input, "*");
    let (routed, meta) = run(rule, event, meta);
    assert_eq!(routed["source_type"], "zoom", "{routed}");
    // Undeclared parser: no view, the v2.0.35 root with the rewrite.
    assert_eq!(routed["message"], "meeting.started", "{routed}");
    // Declared parser / no-parser lane: the NAN-5891 view keeps the rewrite.
    let (view, _) = run(VIEW, routed.clone(), meta.clone());
    assert_eq!(view["source_type"], "zoom", "{view}");
    assert_eq!(view["event"], "meeting.started", "the record's own `event` is back: {view}");
    for ocsf in [true, false] {
        let pipeline = VectorConfigManager::pipeline_config_content_for(ocsf);
        let (generic, _) = run(&transform_source(&pipeline, "generic_parser"), routed.clone(), meta.clone());
        assert_eq!(generic["source_type"], "zoom", "ocsf={ocsf}: {generic}");
    }
    let p = parser("zoom", JSON_GENERIC_OCSF);
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(&p, true);
    let (declared, _) = run(&transform_source(&config, "zoom_hec_payload"), routed, meta);
    assert_eq!(declared["source_type"], "zoom", "{declared}");
}

/// NAN-5902 review r2 P2-1: on the UDM lane (no `_source_tz`), an undeclared
/// text parser gets a step that only drops the lossless record before
/// `_parse`; under OCSF it gets none (as on v2.0.35).
#[test]
fn udm_undeclared_text_parsers_drop_the_record_before_the_parser() {
    let manager = VectorConfigManager::new("/tmp/nanosiem-test");
    let config = manager.generate_parser_config_for(&parser("su", SYSLOG_UDM), false);
    let step = transform_source(&config, "su_hec_payload");
    assert_eq!(step.trim(), super::parser_config::HEC_RECORD_DROP_VRL, "{config}");
    assert_eq!(transform_inputs(&config, "su_parse"), vec!["su_hec_payload".to_string()]);
    let (event, meta) = hec_normalize(hec_object(json!({ "message": SYSLOG_LINE, "seq": 1 })), "su");
    let (event2, meta2) = run(&step, event.clone(), meta.clone());
    assert_eq!(event2, event, "the event is untouched");
    assert!(meta2.get("nano_hec_record").map_or(true, Value::is_null), "{meta2}");
    assert_eq!(meta2["nano_hec_event"], meta["nano_hec_event"]);
    let config = manager.generate_parser_config_for(&parser("so", SYSLOG_OCSF), true);
    assert!(!config.contains("[transforms.so_hec_payload]"), "{config}");
}
