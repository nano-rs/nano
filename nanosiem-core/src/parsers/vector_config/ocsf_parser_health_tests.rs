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
//! `_parse`, the `_ocsf_split` route condition, `_ocsf_prepare` or `_output`)
//! and the generated `db_parser_health` reducer on the VRL runtime, so the row
//! that would reach `parser_health_ingest` is asserted directly.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::parser_config::{OCSF_LANE_STAMP_SUFFIX, OCSF_PARSER_FAILURE_VRL};
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
    let t = transforms(parser_cfg);
    let c = transforms(combiner);
    let name = "json_generic";
    let event = json!({ "message": message, "source_type": "json_generic" });
    let stamp = format!("{name}{OCSF_LANE_STAMP_SUFFIX}");
    let (_, event, meta) = run(&source(&t, &stamp), event, json!({})).unwrap();
    let (_, parsed, meta) = run(&source(&t, &format!("{name}_parse")), event, meta).unwrap();

    let ocsf_lane = takes_ocsf_lane(&t, name, &parsed);
    let step = if ocsf_lane { format!("{name}_ocsf_prepare") } else { format!("{name}_output") };
    let (_, row, meta) = run(&source(&t, &step), parsed, meta).unwrap();
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

/// A root `.parse_error` still takes the UDM recovery path, where `_output`
/// counts it. It never also reaches `_ocsf_prepare`, so it counts once.
#[test]
fn a_root_parse_error_counts_once_on_the_udm_recovery_path() {
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
