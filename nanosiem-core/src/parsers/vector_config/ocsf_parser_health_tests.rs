// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5070: on the OCSF profile a failed OCSF parse reaches parser health.
//!
//! First-party OCSF parsers (json_generic, okta, m365, duo, github_audit, ...)
//! report a failed parse in `unmapped.parse_error` and still emit `class_uid`
//! 0, so the raw record lands in `ocsf_logs`. `_ocsf_prepare` used to
//! hard-code `_nano_parser_failure = false`, so `parser_health_5m` counted the
//! record as a success and a failing parser showed a 0% failure rate.
//!
//! The scenario runs the generated per-parser chain (`_source_lane` stamp,
//! `_parse`, the `_ocsf_split` route condition, `_ocsf_failure` for anything
//! the split does not take, then `_ocsf_prepare`)
//! and the generated `db_parser_health` reducer on the VRL runtime, so the row
//! that would reach `parser_health_ingest` is asserted directly.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::parser_config::{
    OCSF_LANE_STAMP_SUFFIX, OCSF_PARSER_FAILURE_VRL, OCSF_PARSER_FALLBACK_VRL,
};
use super::VectorConfigManager;
use crate::parsers::types::Parser;

/// A cut-down `json_generic` (OCSF): the shape of the first-party failure
/// branch, `class_uid` 0 with `unmapped.parse_error`.
const JSON_GENERIC_LIKE_VRL: &str = r#"raw_log = to_string(.message) ?? ""
parsed, perr = parse_json(raw_log)
ok = perr == null && is_object(parsed)
. = {
    "class_uid": 0,
    "category_uid": 0,
    "activity_id": 99,
    "type_uid": 99,
    "time": 1762164000000,
    "raw_data": raw_log,
    "metadata": { "product": { "name": "Generic JSON" } }
}
if ok {
    .unmapped = parsed
} else {
    .metadata.log_level = "error"
    .unmapped = { "parse_error": to_string(perr) }
}"#;

fn parser(id: Uuid, vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id,
        name: "json_generic".into(),
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
        match_values: Some(vec!["json_generic".into()]),
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

fn transforms(config: &str) -> toml::Table {
    let doc: toml::Table = config.parse().expect("generated config is valid TOML");
    doc["transforms"].as_table().unwrap().clone()
}

fn source(t: &toml::Table, name: &str) -> String {
    t[name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a VRL source"))
        .to_string()
}

/// Runs `program`; returns (result, event, metadata). Panics on error.
/// An `abort` yields `None`.
fn run(program: &str, event: Value, metadata: Value) -> Option<(Value, Value, Value)> {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles: {d:?}\n{program}"))
        .program;
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(event),
        metadata: vrl::value::Value::from(metadata),
        secrets: vrl::value::Secrets::new(),
    };
    let result = match vrl::compiler::runtime::Runtime::new(
        vrl::compiler::state::RuntimeState::default(),
    )
    .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
    {
        Ok(v) => v,
        Err(vrl::compiler::runtime::Terminate::Abort(_)) => return None,
        Err(e) => panic!("VRL runtime: {e:?}"),
    };
    Some((
        result.try_into().expect("result json"),
        target.value.try_into().expect("event json"),
        target.metadata.try_into().expect("metadata json"),
    ))
}

/// The OCSF route condition of `{name}_ocsf_split`, evaluated on `event`.
fn takes_ocsf_lane(t: &toml::Table, name: &str, event: &Value) -> bool {
    let cond = t[&format!("{name}_ocsf_split")]["route"]["ocsf"]
        .as_str()
        .expect("ocsf route condition")
        .to_string();
    let (result, _, _) = run(&cond, event.clone(), json!({})).expect("condition runs");
    result.as_bool().expect("condition is boolean")
}

/// Every lane a record can leave the parser on, with the parser-health row
/// it produces. Exactly one lane runs per record.
struct Outcome {
    ocsf_lane: bool,
    health: Value,
}

fn through(parser_cfg: &str, combiner: &str, message: &str) -> Outcome {
    through_named(parser_cfg, combiner, "json_generic", message, json!({}))
}

/// [`through`] for a parser named `name`, starting from event `metadata`
/// (where the ingest lanes stash e.g. `nano_claimed_source_type`).
fn through_named(
    parser_cfg: &str,
    combiner: &str,
    name: &str,
    message: &str,
    metadata: Value,
) -> Outcome {
    let t = transforms(parser_cfg);
    let c = transforms(combiner);
    let event = json!({ "message": message, "source_type": name });
    let stamp = format!("{name}{OCSF_LANE_STAMP_SUFFIX}");
    let (_, event, meta) = run(&source(&t, &stamp), event, metadata).unwrap();
    let (_, parsed, meta) = run(&source(&t, &format!("{name}_parse")), event, meta).unwrap();

    let ocsf_lane = takes_ocsf_lane(&t, name, &parsed);
    // NAN-5346: the unmatched port feeds `_ocsf_failure`, then `_ocsf_prepare`.
    let (parsed, meta) = if ocsf_lane {
        (parsed, meta)
    } else {
        let (_, record, meta) = run(&source(&t, &format!("{name}_ocsf_failure")), parsed, meta).unwrap();
        (record, meta)
    };
    let (_, row, meta) = run(&source(&t, &format!("{name}_ocsf_prepare")), parsed, meta).unwrap();
    let (_, health, _) = run(&source(&c, "db_parser_health"), row, meta)
        .expect("the health reducer keeps every attributed parser row");
    Outcome { ocsf_lane, health }
}

#[test]
fn a_failed_ocsf_parse_counts_as_a_parse_error() {
    let id = Uuid::new_v4();
    let p = parser(id, JSON_GENERIC_LIKE_VRL);
    let m = VectorConfigManager::new("/tmp/nanosiem-test");
    let cfg = m.generate_parser_config_for(&p, true);
    let combiner = VectorConfigManager::combiner_config_content_for(std::slice::from_ref(&p), true);

    let good = through(&cfg, &combiner, r#"{"user":"alice","action":"login"}"#);
    assert!(good.ocsf_lane, "a parsed record stays on the OCSF lane");
    assert_eq!(good.health["parse_failure"], 0, "{}", good.health);
    assert_eq!(good.health["parser_id"], id.to_string());

    let bad = through(&cfg, &combiner, r#"{"oca_mark":"x","unterminated":"#);
    assert!(bad.ocsf_lane, "the malformed record still lands in ocsf_logs with its raw body");
    assert_eq!(bad.health["parse_failure"], 1, "{}", bad.health);
    assert_eq!(bad.health["parser_id"], id.to_string());
    assert_eq!(bad.health["source_type"], "json_generic");

    // The defect: the pre-fix render hard-coded `false`.
    let pre_fix = cfg.replace(OCSF_PARSER_FAILURE_VRL, "._nano_parser_failure = false");
    assert_ne!(pre_fix, cfg);
    let bad = through(&pre_fix, &combiner, r#"{"oca_mark":"x","unterminated":"#);
    assert_eq!(bad.health["parse_failure"], 0, "pre-fix render undercounts");
}

/// A root `.parse_error` leaves the OCSF split and becomes the parse-error
/// record (NAN-5346), which `_ocsf_prepare` counts once.
#[test]
fn a_root_parse_error_counts_once_on_the_parse_error_record_path() {
    let vrl = format!("{JSON_GENERIC_LIKE_VRL}\nif exists(.unmapped.parse_error) {{ .parse_error = .unmapped.parse_error }}");
    let p = parser(Uuid::new_v4(), &vrl);
    let m = VectorConfigManager::new("/tmp/nanosiem-test");
    let cfg = m.generate_parser_config_for(&p, true);
    let combiner = VectorConfigManager::combiner_config_content_for(std::slice::from_ref(&p), true);

    let bad = through(&cfg, &combiner, "not json");
    assert!(!bad.ocsf_lane);
    assert_eq!(bad.health["parse_failure"], 1, "{}", bad.health);
}

/// An empty or null `unmapped.parse_error` is not a failure; a parser that
/// keeps vendor data under `unmapped` without the key is unaffected.
#[test]
fn only_a_present_parse_error_is_a_failure() {
    for (unmapped, failed) in [
        (json!({ "vendor_field": "x" }), false),
        (json!({ "parse_error": "" }), false),
        (json!({ "parse_error": null }), false),
        (json!("flattened string"), false),
        (json!({ "parse_error": "EOF while parsing" }), true),
    ] {
        let row = json!({ "event": { "class_uid": 0, "unmapped": unmapped }, "source_type": "x" });
        let (_, out, _) = run(OCSF_PARSER_FAILURE_VRL, row, json!({})).unwrap();
        assert_eq!(out["_nano_parser_failure"], failed, "unmapped={unmapped}");
    }
}

// ---------------------------------------------------------------------------
// NAN-5264: a fallback parse is degraded, not healthy.
// ---------------------------------------------------------------------------

/// The shape of the first-party Apache (OCSF) parser: HTTP Activity on a
/// matching line, a Base Event with no event time on anything else.
const APACHE_LIKE_VRL: &str = r#"raw_log = to_string(.message) ?? ""
parsed, err = parse_regex(raw_log, r'^(?P<host>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>\S+)')
if err == null {
    t = parse_timestamp(parsed.ts, "%d/%b/%Y:%H:%M:%S %z") ?? now()
    . = {
        "class_uid": 4002,
        "activity_id": 3,
        "time": to_unix_timestamp(t, unit: "milliseconds"),
        "http_request": { "http_method": parsed.method, "url": { "path": parsed.path } },
        "metadata": { "product": { "name": "Apache HTTP Server" } }
    }
} else {
    . = {
        "class_uid": 0,
        "class_name": "Base Event",
        "activity_id": 99,
        "time": 0,
        "raw_data": raw_log,
        "metadata": { "product": { "name": "Apache HTTP Server" }, "log_level": "error" },
        "unmapped": { "parse_fallback": "unparsable input" }
    }
}"#;

/// The shape of the first-party Sysmon (OCSF) parser: it accepts any JSON
/// object, so an envelope it does not understand lands as Process Activity /
/// Other with no event time and no process name.
const SYSMON_LIKE_VRL: &str = r#"raw_log = to_string(.message) ?? ""
parsed, err = parse_json(raw_log)
if err != null || !is_object(parsed) {
    . = { "class_uid": 1007, "activity_id": 99, "time": 0, "raw_data": raw_log, "metadata": { "log_level": "error" } }
} else {
    p = object!(parsed)
    eid = to_int(p.event_id) ?? 0
    time_ms = 0
    ts = string(p.timestamp) ?? ""
    if ts != "" {
        t, terr = parse_timestamp(ts, "%+")
        if terr == null { time_ms = to_unix_timestamp(t, unit: "milliseconds") }
    }
    activity = if eid == 1 { 1 } else { 99 }
    . = {
        "class_uid": 1007,
        "activity_id": activity,
        "time": time_ms,
        "process": { "name": string(p.event_data.Image) ?? "" },
        "metadata": { "product": { "name": "Sysmon" } }
    }
}"#;

fn rendered(name: &str, vrl: &str) -> (String, String) {
    let mut p = parser(Uuid::new_v4(), vrl);
    p.name = name.into();
    p.match_values = Some(vec![name.into()]);
    let m = VectorConfigManager::new("/tmp/nanosiem-test");
    let cfg = m.generate_parser_config_for(&p, true);
    let combiner = VectorConfigManager::combiner_config_content_for(std::slice::from_ref(&p), true);
    (cfg, combiner)
}

#[test]
fn an_apache_base_event_fallback_counts_as_a_fallback_not_a_success() {
    let (cfg, combiner) = rendered("apache_access", APACHE_LIKE_VRL);
    let good = r#"127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326"#;
    let ok = through_named(&cfg, &combiner, "apache_access", good, json!({}));
    assert!(ok.ocsf_lane);
    assert_eq!(ok.health["parse_failure"], 0, "{}", ok.health);
    assert_eq!(ok.health["parse_fallback"], 0, "{}", ok.health);

    // The reported input: the raw line wrapped in a JSON envelope.
    let wrapped = format!(r#"{{"message":"{}","host":"web-1"}}"#, good.replace('"', "\\\""));
    let fell_back = through_named(&cfg, &combiner, "apache_access", &wrapped, json!({}));
    assert!(fell_back.ocsf_lane, "a fallback still lands in ocsf_logs");
    assert_eq!(fell_back.health["parse_failure"], 0, "not a runtime failure: {}", fell_back.health);
    assert_eq!(fell_back.health["parse_fallback"], 1, "{}", fell_back.health);

    // The defect: before NAN-5264 the prepare step stamped no fallback marker.
    let pre_fix = cfg.replace(OCSF_PARSER_FALLBACK_VRL, "");
    assert_ne!(pre_fix, cfg);
    let silent = through_named(&pre_fix, &combiner, "apache_access", &wrapped, json!({}));
    assert_eq!(silent.health["parse_failure"], 0);
    assert_eq!(silent.health["parse_fallback"], 0, "pre-fix render reports the fallback as healthy");
}

/// NAN-5264 review: a record with no event time is NOT a fallback by itself.
/// Every year-less RFC3164 syslog line (and well-formed Proofpoint DLP,
/// Qualys and Rapid7 records) parses correctly with `time` 0; the first rule
/// flagged them all. Only the parser's explicit marker counts.
#[test]
fn a_correct_parse_without_an_event_time_is_healthy() {
    let (cfg, combiner) = rendered("windows_sysmon", SYSMON_LIKE_VRL);
    let event = r#"{"event_id":1,"timestamp":"2026-08-18T10:15:00Z","event_data":{"Image":"C:\\Windows\\System32\\cmd.exe"}}"#;
    let ok = through_named(&cfg, &combiner, "windows_sysmon", event, json!({}));
    assert_eq!(ok.health["parse_fallback"], 0, "{}", ok.health);

    let no_time = r#"{"event_id":1,"event_data":{"Image":"C:\\Windows\\System32\\cmd.exe"}}"#;
    let out = through_named(&cfg, &combiner, "windows_sysmon", no_time, json!({}));
    assert!(out.ocsf_lane);
    assert_eq!(out.health["parse_failure"], 0, "{}", out.health);
    assert_eq!(out.health["parse_fallback"], 0, "no event time alone is not a fallback: {}", out.health);
}

#[test]
fn a_failed_parse_is_not_also_a_fallback() {
    // json_generic's failure branch is class 0 too; it must count once.
    let p = parser(Uuid::new_v4(), JSON_GENERIC_LIKE_VRL);
    let m = VectorConfigManager::new("/tmp/nanosiem-test");
    let cfg = m.generate_parser_config_for(&p, true);
    let combiner = VectorConfigManager::combiner_config_content_for(std::slice::from_ref(&p), true);
    let bad = through(&cfg, &combiner, r#"{"unterminated":"#);
    assert_eq!(bad.health["parse_failure"], 1, "{}", bad.health);
    assert_eq!(bad.health["parse_fallback"], 0, "{}", bad.health);
}

#[test]
fn the_fallback_rule_reads_only_the_marker() {
    let t = 1762164000000_i64;
    for (event, fallback) in [
        (json!({ "class_uid": 4002, "time": t }), false),
        // A correctly parsed Base Event (windows_event_xml's unmapped EventIDs,
        // journald, nano's own logs) is NOT a fallback.
        (json!({ "class_uid": 0, "time": t }), false),
        (json!({ "class_uid": 0, "time": t, "metadata": { "log_level": "error" } }), false),
        // The explicit marker the first-party fallback branches set.
        (json!({ "class_uid": 0, "time": t, "unmapped": { "parse_fallback": "unparsable input" } }), true),
        (json!({ "class_uid": 4001, "time": t, "unmapped": { "parse_fallback": true } }), true),
        (json!({ "class_uid": 4001, "time": t, "unmapped": { "parse_fallback": false } }), false),
        (json!({ "class_uid": 4001, "time": t, "unmapped": { "parse_fallback": null } }), false),
        // No event time alone is NOT a fallback (year-less RFC3164 syslog).
        (json!({ "class_uid": 3002, "time": 0 }), false),
        (json!({ "class_uid": 1007 }), false),
        (json!({ "class_uid": 1007, "time": 0, "unmapped": { "parse_fallback": "unparsable input" } }), true),
        // A failure is counted once, as a failure.
        (json!({ "class_uid": 0, "time": 0, "unmapped": { "parse_error": "bad", "parse_fallback": "x" } }), false),
    ] {
        let row = json!({ "event": event, "source_type": "x" });
        let (_, out, _) = run(OCSF_PARSER_FALLBACK_VRL, row, json!({})).unwrap();
        assert_eq!(out["_nano_parser_fallback"], fallback, "event={event}");
    }
}

#[test]
fn an_ignored_source_claim_is_counted_on_the_bound_source() {
    let (cfg, combiner) = rendered("apache_access", APACHE_LIKE_VRL);
    let line = r#"10.1.2.3 - - [12/Aug/2026:09:15:22 +0000] "POST /wp-login.php HTTP/1.1" 500 0"#;
    let honest = through_named(&cfg, &combiner, "apache_access", line, json!({}));
    assert_eq!(honest.health["source_claim_ignored"], 0, "{}", honest.health);
    // source_type_extract / the HEC lane stash a differing claim here.
    let claimed = through_named(
        &cfg,
        &combiner,
        "apache_access",
        line,
        json!({ "nano_claimed_source_type": "nginx" }),
    );
    assert_eq!(claimed.health["source_claim_ignored"], 1, "{}", claimed.health);
    assert_eq!(claimed.health["source_type"], "apache_access");
}

/// The shape of windows_event_xml: unmapped EventIDs become a Base Event with
/// the event's real time. That is a correct parse and must stay healthy
/// (NAN-5264 review: the first rule flagged every class 0 record).
const BASE_EVENT_BY_DESIGN_VRL: &str = r#"raw_log = to_string(.message) ?? ""
parsed = parse_json(raw_log) ?? {}
eid = to_int(parsed.EventID) ?? 0
t = parse_timestamp(to_string(parsed.TimeCreated) ?? "", "%+") ?? now()
cls = if eid == 4624 { 3002 } else { 0 }
. = {
    "class_uid": cls,
    "activity_id": 99,
    "time": to_unix_timestamp(t, unit: "milliseconds"),
    "raw_data": raw_log,
    "metadata": { "product": { "name": "Windows" } }
}"#;

/// A parser that keeps the real event time on its fallback branch, so only
/// the explicit marker can report it.
const MARKED_FALLBACK_VRL: &str = r#"raw_log = to_string(.message) ?? ""
parsed, err = parse_json(raw_log)
. = { "class_uid": 0, "activity_id": 99, "time": 1762164000000, "raw_data": raw_log, "metadata": { "log_level": "error" } }
if err == null && is_object(parsed) {
    .class_uid = 4001
} else {
    . = set!(., ["unmapped", "parse_fallback"], "unparsable input")
}"#;

#[test]
fn a_correctly_parsed_base_event_is_healthy() {
    let (cfg, combiner) = rendered("windows_event", BASE_EVENT_BY_DESIGN_VRL);
    let unmapped_eid = r#"{"EventID":5156,"TimeCreated":"2026-11-10T10:00:00Z"}"#;
    let out = through_named(&cfg, &combiner, "windows_event", unmapped_eid, json!({}));
    assert!(out.ocsf_lane);
    assert_eq!(out.health["parse_failure"], 0, "{}", out.health);
    assert_eq!(out.health["parse_fallback"], 0, "Base Event by design: {}", out.health);
}

#[test]
fn the_explicit_fallback_marker_is_counted() {
    let (cfg, combiner) = rendered("marked_source", MARKED_FALLBACK_VRL);
    let ok = through_named(&cfg, &combiner, "marked_source", r#"{"a":1}"#, json!({}));
    assert_eq!(ok.health["parse_fallback"], 0, "{}", ok.health);
    let bad = through_named(&cfg, &combiner, "marked_source", "not json", json!({}));
    assert_eq!(bad.health["parse_failure"], 0, "{}", bad.health);
    assert_eq!(bad.health["parse_fallback"], 1, "{}", bad.health);
}
