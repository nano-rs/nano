// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5839: a log source's timezone reaches its parser as
//! `.nano.source_timezone`, so an offset-less device clock is stored in true
//! UTC.
//!
//! Render tests pin the `<name>_source_tz` step (OCSF only, non-default and
//! valid settings only, immediately before the parser on every shape). Chain
//! tests run the generated components on the VRL runtime with a parser that
//! follows the parsers#87 contract (`scripts/residual/source_tz.vrl`, round 2): it reads
//! and removes `.nano.source_timezone`, reads an offset-less PAN-OS-style
//! clock in that zone, and records `unmapped.nano_time_assumed_tz`.

use chrono::{TimeZone, Utc};
use serde_json::{json, Value};
use uuid::Uuid;

use super::parser_config::{
    source_timezone_vrl, OCSF_LANE_STAMP_SUFFIX, SOURCE_TIMEZONE_SUFFIX,
};
use super::VectorConfigManager;
use crate::parsers::types::Parser;

/// The parsers#87 prelude (trimmed to what the contract needs: the IANA and
/// fixed-offset branches) plus a PAN-OS-style body: `receive_time` is
/// `YYYY/MM/DD HH:MM:SS` with no offset.
const CONTRACT_PARSER_VRL: &str = r#"__src_tz_in = ""
if is_object(.nano) {
    __src_tz_in = strip_whitespace(to_string(del(.nano.source_timezone)) ?? "")
    if is_empty(object!(.nano)) { __discard = del(.nano) }
}
__src_tz = "UTC"
__src_shift_ms = 0
__src_tz_label = "UTC"
__time_assumed = false
__src_off = parse_regex(__src_tz_in, r'^(?P<sign>[+-])(?P<h>\d{2}):?(?P<m>\d{2})$') ?? {}
if !is_empty(__src_off) {
    __src_h = to_int(__src_off.h) ?? 99
    __src_m = to_int(__src_off.m) ?? 99
    if __src_h <= 14 && __src_m <= 59 {
        __src_shift_ms = (__src_h * 3600 + __src_m * 60) * 1000
        if __src_off.sign == "-" { __src_shift_ms = 0 - __src_shift_ms }
        if __src_shift_ms != 0 { __src_tz_label = string!(__src_off.sign) + string!(__src_off.h) + ":" + string!(__src_off.m) }
    }
} else if __src_tz_in != "" {
    __src_probe, __src_probe_err = parse_timestamp("2000-01-01 00:00:00", "%Y-%m-%d %H:%M:%S", timezone: __src_tz_in)
    if __src_probe_err == null { __src_tz = __src_tz_in; __src_tz_label = __src_tz_in }
}
fields = parse_csv!(string!(.message))
ts, ts_err = parse_timestamp(fields[0], "%Y/%m/%d %H:%M:%S", timezone: __src_tz)
time_ms = to_unix_timestamp(ts, unit: "milliseconds")
if ts_err == null { __time_assumed = true; time_ms = time_ms - __src_shift_ms }
__unmapped = {}
if __time_assumed { __unmapped = set!(__unmapped, ["nano_time_assumed_tz"], __src_tz_label) }
. = {
  "class_uid": 4001,
  "category_uid": 4,
  "activity_id": 6,
  "time": time_ms,
  "metadata": { "product": { "name": "PAN-OS", "vendor_name": "Palo Alto Networks" } },
  "unmapped": __unmapped
}"#;

/// A custom parser that keeps the root and never reads `.nano`.
const KEEP_ROOT_VRL: &str = r#".class_uid = 0
.time = 0"#;

fn parser(name: &str, source_type: &str, timezone: &str, vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: name.into(),
        description: None,
        source_type: source_type.into(),
        parser_vrl: vrl.into(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        namespace: "default".into(),
        enabled: true,
        validated: true,
        validation_error: None,
        timezone: timezone.into(),
        match_values: Some(vec![name.to_string()]),
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

fn render(p: &Parser, ocsf: bool) -> String {
    let dir = tempfile::tempdir().expect("tempdir");
    VectorConfigManager::new(dir.path()).generate_parser_config_for(p, ocsf)
}

fn transforms(config: &str) -> toml::Table {
    let doc: toml::Table = config.parse().expect("generated config is valid TOML");
    doc["transforms"].as_table().unwrap().clone()
}

fn inputs(t: &toml::Table, name: &str) -> Vec<String> {
    t[name]["inputs"]
        .as_array()
        .unwrap_or_else(|| panic!("{name} has inputs"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

fn source(t: &toml::Table, name: &str) -> String {
    t[name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a VRL source"))
        .to_string()
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
    // The Vector host's zone must never matter: run as if it were far from UTC.
    let host = vrl::compiler::TimeZone::parse("Asia/Tokyo").expect("zone");
    vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &host)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}\n{program}"));
    (
        target.value.try_into().expect("event json"),
        target.metadata.try_into().expect("metadata json"),
    )
}

/// The rendered components a routed event passes: lane stamp, source
/// timezone (when rendered), parse, OCSF prepare. Returns the stored row.
fn through_parser(p: &Parser, event: Value) -> Value {
    let config = render(p, true);
    let t = transforms(&config);
    let name = &p.name;
    let mut state = (event, json!({ "source_type": name }));
    for step in [
        format!("{name}{OCSF_LANE_STAMP_SUFFIX}"),
        format!("{name}{SOURCE_TIMEZONE_SUFFIX}"),
        format!("{name}_parse"),
        format!("{name}_ocsf_prepare"),
    ] {
        if t.contains_key(&step) {
            state = run(&source(&t, &step), state.0, state.1);
        }
    }
    state.0
}

fn pan_event() -> Value {
    json!({ "message": "2026/01/15 10:00:00,001801000001,TRAFFIC", "source_type": "pan_fw" })
}

fn stored_utc(row: &Value) -> String {
    row["timestamp"].as_str().expect("row timestamp").to_string()
}

#[test]
fn default_and_invalid_settings_render_the_strip_only() {
    for tz in ["UTC", "", "utc", "Bogus/Zone", "+01:30"] {
        let p = parser("pan_fw", "routed", tz, CONTRACT_PARSER_VRL);
        let t = transforms(&render(&p, true));
        let step = format!("pan_fw{SOURCE_TIMEZONE_SUFFIX}");
        assert_eq!(source(&t, &step).trim(), source_timezone_vrl(None).trim(), "{tz:?}");
        assert!(!source(&t, &step).contains(".nano.source_timezone ="), "{tz:?}: nothing injected");
        assert_eq!(inputs(&t, "pan_fw_parse"), vec![step], "{tz:?}");
    }
}

#[test]
fn udm_render_never_injects() {
    let p = parser("pan_fw", "routed", "America/New_York", CONTRACT_PARSER_VRL);
    assert!(!render(&p, false).contains(SOURCE_TIMEZONE_SUFFIX));
}

#[test]
fn configured_zone_renders_between_the_lane_stamp_and_the_parser() {
    let p = parser("pan_fw", "routed", "America/New_York", CONTRACT_PARSER_VRL);
    let config = render(&p, true);
    let t = transforms(&config);
    let tz = format!("pan_fw{SOURCE_TIMEZONE_SUFFIX}");
    assert_eq!(t[&tz]["type"].as_str(), Some("remap"));
    assert_eq!(inputs(&t, &tz), vec![format!("pan_fw{OCSF_LANE_STAMP_SUFFIX}")]);
    assert_eq!(inputs(&t, "pan_fw_parse"), vec![tz.clone()]);
    assert_eq!(source(&t, &tz).trim(), source_timezone_vrl(Some("America/New_York")).trim());
    // The lane stamp has exactly one reader: the timezone step (no bypass).
    let stamp = format!("pan_fw{OCSF_LANE_STAMP_SUFFIX}");
    let readers: Vec<_> = t
        .iter()
        .filter(|(_, b)| {
            b.get("inputs")
                .and_then(|i| i.as_array())
                .is_some_and(|i| i.iter().any(|v| v.as_str() == Some(stamp.as_str())))
        })
        .map(|(k, _)| k.clone())
        .collect();
    assert_eq!(readers, vec![tz]);
    // The NAN-4919 deploy guard accepts the document.
    crate::parsers::pipe::guard::check_document(
        "pan_fw",
        &p.parser_vrl,
        &config,
        &crate::parsers::pipe::native::runtime_transforms(),
    )
    .unwrap_or_else(|e| panic!("guard refused the render: {e}\n{config}"));
}

#[test]
fn stored_spelling_is_normalized_before_injection() {
    let p = parser("pan_fw", "routed", "-0500", CONTRACT_PARSER_VRL);
    let t = transforms(&render(&p, true));
    assert!(source(&t, &format!("pan_fw{SOURCE_TIMEZONE_SUFFIX}")).contains("\"-05:00\""));
}

#[test]
fn json_input_parser_receives_it_after_the_hec_payload_step() {
    let vrl = "raw = object!(parse_json!(.message))\n.class_uid = 0\n.time = 0\n.unmapped = raw";
    let p = parser("json_app", "splunk_hec", "Asia/Tokyo", vrl);
    let t = transforms(&render(&p, true));
    let tz = format!("json_app{SOURCE_TIMEZONE_SUFFIX}");
    assert_eq!(inputs(&t, &tz), vec!["json_app_hec_payload".to_string()]);
    assert_eq!(inputs(&t, "json_app_parse"), vec![tz]);
}

#[test]
fn stub_extension_receives_it() {
    let mut stub = parser("stub_app", "routed", "Europe/Berlin", "");
    stub.extension_vrl = Some(".class_uid = 0".into());
    stub.extension_enabled = true;
    let t = transforms(&render(&stub, true));
    assert_eq!(
        inputs(&t, "stub_app_extension"),
        vec![format!("stub_app{SOURCE_TIMEZONE_SUFFIX}")]
    );
}

/// The acceptance criterion: a PAN-OS `receive_time` of 10:00 local on a
/// source set to America/New_York is stored as 15:00 UTC (EST, January) and
/// 14:00 UTC (EDT, July).
#[test]
fn new_york_source_stores_true_utc() {
    let p = parser("pan_fw", "routed", "America/New_York", CONTRACT_PARSER_VRL);
    let row = through_parser(&p, pan_event());
    assert_eq!(stored_utc(&row), "2026-01-15 15:00:00.000", "{row}");
    assert_eq!(row["event"]["unmapped"]["nano_time_assumed_tz"], "America/New_York");
    assert!(row["event"].get("nano").is_none(), "{row}");

    let summer = json!({ "message": "2026/07/15 10:00:00,001801000001,TRAFFIC" });
    let row = through_parser(&p, summer);
    assert_eq!(stored_utc(&row), "2026-07-15 14:00:00.000", "{row}");
}

#[test]
fn fixed_offset_and_default_settings() {
    let p = parser("pan_fw", "routed", "+05:30", CONTRACT_PARSER_VRL);
    let row = through_parser(&p, pan_event());
    assert_eq!(stored_utc(&row), "2026-01-15 04:30:00.000", "{row}");
    // parsers#87 round 2: a fixed offset is a shift, recorded verbatim.
    assert_eq!(row["event"]["unmapped"]["nano_time_assumed_tz"], "+05:30");

    let p = parser("pan_fw", "routed", "-0500", CONTRACT_PARSER_VRL);
    let row = through_parser(&p, pan_event());
    assert_eq!(stored_utc(&row), "2026-01-15 15:00:00.000", "{row}");
    assert_eq!(row["event"]["unmapped"]["nano_time_assumed_tz"], "-05:00");

    // No setting: read as UTC (never the Vector host's zone) and marked, which
    // is what SIEM Health's clock-skew finding watches.
    let p = parser("pan_fw", "routed", "UTC", CONTRACT_PARSER_VRL);
    let row = through_parser(&p, pan_event());
    assert_eq!(stored_utc(&row), "2026-01-15 10:00:00.000", "{row}");
    assert_eq!(row["event"]["unmapped"]["nano_time_assumed_tz"], "UTC");
}

#[test]
fn a_parser_that_never_reads_it_does_not_store_it() {
    let p = parser("keep_root", "routed", "America/Chicago", KEEP_ROOT_VRL);
    let row = through_parser(&p, json!({ "message": "hello" }));
    assert!(row["event"].get("nano").is_none(), "{row}");

    // A sender's own `nano` object keeps its other keys.
    let row = through_parser(&p, json!({ "message": "hello", "nano": { "build": "7" } }));
    assert_eq!(row["event"]["nano"], json!({ "build": "7" }), "{row}");
}

/// NAN-5846: ClickHouse reads `.` in a key as a path separator, so a
/// sender's flat `"nano.source_timezone"` is the same stored path as the
/// injected nested field. A root-keeping parser would store both spellings
/// (Code 117, the whole batch); the step moves the flat one to metadata and
/// the storage boundary keeps it in `unmapped.source_nano_json`. It is sender
/// data: kept, never dropped, and nothing the sender sent is overwritten.
#[test]
fn a_flat_dotted_source_timezone_is_moved_never_dropped() {
    let (event, meta) = run(
        &source_timezone_vrl(Some("America/Chicago")),
        json!({ "message": "x", "nano.source_timezone": "+14:00" }),
        json!({}),
    );
    assert_eq!(event["nano"], json!({ "source_timezone": "America/Chicago" }), "{event}");
    assert!(event.get("nano.source_timezone").is_none(), "{event}");
    assert_eq!(meta["nano_reserved_spill"], json!({ "root:nano.source_timezone": "+14:00" }), "{meta}");

    let p = parser("keep_root", "routed", "America/Chicago", KEEP_ROOT_VRL);
    let sender = json!({
        "message": "hello",
        "nano.source_timezone": "+14:00",
        "source_nano": { "source_timezone": "Europe/Paris" },
        "source_nano.other": "kept",
    });
    let row = through_parser(&p, sender);
    let event = &row["event"];
    assert!(event.get("nano.source_timezone").is_none(), "{row}");
    assert_eq!(event["unmapped"]["source_nano_json"], r#"{"root:nano.source_timezone":"+14:00"}"#, "{row}");
    assert_eq!(event["source_nano"], json!({ "source_timezone": "Europe/Paris" }), "untouched: {row}");
    assert_eq!(event["source_nano.other"], "kept", "{row}");

    // Review r4: the same name in `unmapped` as well: both values are kept.
    let row = through_parser(
        &p,
        json!({
            "message": "hello",
            "nano.source_timezone": "+14:00",
            "unmapped": { "nano.source_timezone": "Europe/Paris" },
        }),
    );
    assert_eq!(
        row["event"]["unmapped"]["source_nano_json"],
        r#"{"nano.source_timezone":"Europe/Paris","root:nano.source_timezone":"+14:00"}"#,
        "{row}"
    );
}

#[test]
fn a_vendor_nano_scalar_is_left_alone_without_a_setting() {
    let (event, meta) = run(
        &source_timezone_vrl(None),
        json!({ "message": "x", "nano": "vendor value" }),
        json!({}),
    );
    assert_eq!(event["nano"], "vendor value");
    assert!(meta["nano_source_timezone"].is_null(), "{meta}");
}

/// Review r2: a hostile non-object `.nano` cannot defeat a configured zone.
#[test]
fn a_hostile_non_object_nano_cannot_defeat_the_setting() {
    let p = parser("pan_fw", "routed", "America/New_York", CONTRACT_PARSER_VRL);
    for hostile in [json!("x"), json!([1, 2]), json!(7), json!(true)] {
        let event = json!({ "message": "2026/01/15 10:00:00,001801000001,TRAFFIC", "nano": hostile });
        let row = through_parser(&p, event);
        assert_eq!(stored_utc(&row), "2026-01-15 15:00:00.000", "{hostile}: {row}");
        assert_eq!(row["event"]["unmapped"]["nano_time_assumed_tz"], "America/New_York", "{hostile}");
    }
}

/// Review r2: a sender cannot supply the parser's `unmapped.nano_*` markers
/// (SIEM Health trusts `nano_time_assumed_tz`), whether at the root, in a
/// root `unmapped`, or as a Splunk HEC sibling field.
#[test]
fn a_sender_cannot_inject_parser_markers() {
    let (event, meta) = run(
        &source_timezone_vrl(None),
        json!({
            "message": "x",
            "nano_time_assumed_tz": "Asia/Tokyo",
            "unmapped": { "nano_time_assumed_tz": "Asia/Tokyo", "nano_time_source": "x", "keep": 1 }
        }),
        json!({ "nano_hec_event": { "nano_time_assumed_tz": "Asia/Tokyo", "nano_operational": true, "host": "h1" } }),
    );
    assert!(event.get("nano_time_assumed_tz").is_none(), "{event}");
    assert_eq!(event["unmapped"], json!({ "keep": 1 }));
    assert_eq!(meta["nano_hec_event"], json!({ "host": "h1" }));

    // End to end: a parser that reads an offset-carrying clock sets no
    // marker, and the HEC sibling one never reaches the stored row.
    let vrl = r#". = { "class_uid": 0, "time": 1768471200000, "unmapped": {} }"#;
    let p = parser("iso_app", "splunk_hec", "UTC", vrl);
    let t = transforms(&render(&p, true));
    let mut state = (
        json!({ "message": "2026-01-15T10:00:00Z ok" }),
        json!({ "source_type": "iso_app", "nano_hec_event": { "nano_time_assumed_tz": "+14:00", "host": "h1" } }),
    );
    for step in ["iso_app_source_lane", "iso_app_source_tz", "iso_app_parse", "iso_app_ocsf_prepare"] {
        if t.contains_key(step) {
            state = run(&source(&t, step), state.0, state.1);
        }
    }
    let row = state.0;
    assert!(row["event"]["unmapped"].get("nano_time_assumed_tz").is_none(), "{row}");
    assert_eq!(row["event"]["unmapped"]["host"], "h1", "other siblings still land: {row}");
}

#[test]
fn the_step_sets_the_field_and_its_metadata_twin() {
    let (event, meta) = run(
        &source_timezone_vrl(Some("America/New_York")),
        json!({ "message": "x", "nano": { "other": 1 } }),
        json!({}),
    );
    assert_eq!(event["nano"], json!({ "other": 1, "source_timezone": "America/New_York" }));
    assert_eq!(meta["nano_source_timezone"], "America/New_York");
    // Sanity on the expected wall clock used above.
    let ny = chrono_tz::America::New_York.with_ymd_and_hms(2026, 1, 15, 10, 0, 0).unwrap();
    assert_eq!(ny.with_timezone(&Utc).to_rfc3339(), "2026-01-15T15:00:00+00:00");
}

/// Review P1: a sender cannot choose the zone its own clock is read in. A
/// hostile `.nano.source_timezone` (HTTP / HEC / Vector payloads put it at
/// the event root) is deleted on a default-UTC source and overridden on a
/// configured one.
#[test]
fn a_hostile_payload_cannot_spoof_the_source_timezone() {
    let hostile = || {
        json!({
            "message": "2026/01/15 10:00:00,001801000001,TRAFFIC",
            "nano": { "source_timezone": "+14:00" }
        })
    };
    let p = parser("pan_fw", "routed", "UTC", CONTRACT_PARSER_VRL);
    let row = through_parser(&p, hostile());
    assert_eq!(stored_utc(&row), "2026-01-15 10:00:00.000", "{row}");
    assert_eq!(row["event"]["unmapped"]["nano_time_assumed_tz"], "UTC");
    assert!(row["event"].get("nano").is_none(), "{row}");

    let p = parser("pan_fw", "routed", "America/New_York", CONTRACT_PARSER_VRL);
    let row = through_parser(&p, hostile());
    assert_eq!(stored_utc(&row), "2026-01-15 15:00:00.000", "{row}");
    assert_eq!(row["event"]["unmapped"]["nano_time_assumed_tz"], "America/New_York");

    // A hostile value next to other sender keys: only the control field goes.
    let (event, meta) = run(
        &source_timezone_vrl(None),
        json!({ "nano": { "source_timezone": "Asia/Tokyo", "build": "7" } }),
        json!({ "nano_source_timezone": "Asia/Tokyo" }),
    );
    assert_eq!(event["nano"], json!({ "build": "7" }));
    assert!(meta["nano_source_timezone"].is_null(), "{meta}");
}

/// Every lane (HTTP routed, HEC, Vector-native, syslog, OTLP, fetch) renders
/// the step, default UTC included, as the parser's only input.
#[test]
fn every_lane_owns_the_control_fields_before_the_parser() {
    let lanes = [
        ("routed_app", "routed"),
        ("hec_app", "splunk_hec"),
        ("fwd_app", "vector"),
        ("syslog_app", "syslog_rfc5424"),
        ("syslog_app2", "syslog"),
        ("otel_app", "opentelemetry"),
    ];
    for (name, lane) in lanes {
        let p = parser(name, lane, "UTC", ".class_uid = 0\n.time = 0");
        let t = transforms(&render(&p, true));
        let step = format!("{name}{SOURCE_TIMEZONE_SUFFIX}");
        assert!(t.contains_key(&step), "{lane}: no {step}");
        assert_eq!(inputs(&t, &format!("{name}_parse")), vec![step.clone()], "{lane}");
        assert_eq!(
            inputs(&t, &step),
            vec![format!("{name}{OCSF_LANE_STAMP_SUFFIX}")],
            "{lane}: right after the lane stamp"
        );
    }
}
