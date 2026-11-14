// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5346: on the OCSF profile nothing a parser emits goes to UDM `logs`.
//!
//! A parser runtime failure (Vector reroutes the input event to the remap's
//! `.dropped` port with `.metadata.dropped`) and any output without a
//! `class_uid` become a class-0 parse-error record on the `ocsf_logs` path,
//! with the raw text in `raw_data` and the error under `unmapped`, and parser
//! health still counts it as a failure (NAN-5070). Unparsed events
//! (`generic_parser`) are written once, to `ocsf_logs`.
//!
//! The scenarios run the generated per-parser chain and the generated
//! `db_parser_health` reducer on the VRL runtime. Vector's `.dropped`
//! annotation is reproduced from its documented shape.

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::fanin_slots::resolved_inputs;
use super::parser_config::{OCSF_FAILURE_SUFFIX, OCSF_LANE_STAMP_SUFFIX};
use super::VectorConfigManager;
use crate::parsers::types::Parser;

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

fn transforms(config: &str) -> toml::Table {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(config, "$1");
    let doc: toml::Table = substituted.parse().expect("generated config is valid TOML");
    doc["transforms"].as_table().unwrap().clone()
}

fn source(t: &toml::Table, name: &str) -> String {
    t[name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("{name} has a VRL source"))
        .to_string()
}

fn inputs(t: &toml::Table, name: &str) -> Vec<String> {
    t[name]["inputs"]
        .as_array()
        .unwrap_or_else(|| panic!("{name} has inputs"))
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect()
}

/// Runs `program`. `Err` carries the runtime error (what makes Vector reroute
/// the event to `.dropped`); an `abort` is also an `Err`.
fn run(program: &str, event: Value, metadata: Value) -> Result<(Value, Value), String> {
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
        .map_err(|e| e.to_string())?;
    Ok((
        target.value.try_into().expect("event json"),
        target.metadata.try_into().expect("metadata json"),
    ))
}

/// The row a parser's chain writes to `ocsf_logs`, and its parser-health row.
struct Landed {
    row: Value,
    health: Value,
}

/// Lane stamp → `_parse` → (OCSF split | `.dropped`) → `_ocsf_failure` when
/// the split does not take the event → `_ocsf_prepare` → `db_parser_health`.
fn land(p: &Parser, input: Value) -> Landed {
    let name = &p.name;
    let cfg = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(p, true);
    let combiner = VectorConfigManager::combiner_config_content_for(std::slice::from_ref(p), true);
    let t = transforms(&cfg);
    let c = transforms(&combiner);

    let (event, meta) = run(&source(&t, &format!("{name}{OCSF_LANE_STAMP_SUFFIX}")), input, json!({})).unwrap();
    let parse = format!("{name}_parse");
    let (record, meta) = match run(&source(&t, &parse), event.clone(), meta.clone()) {
        Ok((parsed, meta)) => {
            let cond = t[&format!("{name}_ocsf_split")]["route"]["ocsf"].as_str().unwrap();
            let (takes_ocsf, _) = run(&format!(". = {cond}"), parsed.clone(), json!({})).unwrap();
            if takes_ocsf == json!(true) {
                (parsed, meta)
            } else {
                failure_record(&t, name, parsed, meta)
            }
        }
        Err(error) => {
            // Vector's `reroute_dropped`: the INPUT event, annotated.
            let mut dropped = event;
            dropped["metadata"] = json!({ "dropped": {
                "reason": "error",
                "message": error,
                "component_id": parse,
                "component_type": "remap",
                "component_kind": "transform",
            }});
            assert!(
                inputs(&t, &format!("{name}{OCSF_FAILURE_SUFFIX}")).contains(&format!("{parse}.dropped")),
                "the failure record reads the parse step's dropped port"
            );
            failure_record(&t, name, dropped, meta)
        }
    };
    let (row, meta) = run(&source(&t, &format!("{name}_ocsf_prepare")), record, meta).unwrap();
    let (health, _) = run(&source(&c, "db_parser_health"), row.clone(), meta).unwrap();
    Landed { row, health }
}

fn failure_record(t: &toml::Table, name: &str, event: Value, meta: Value) -> (Value, Value) {
    run(&source(t, &format!("{name}{OCSF_FAILURE_SUFFIX}")), event, meta).unwrap()
}

/// An OCSF parser that aborts on input it cannot decode.
const STRICT_JSON_OCSF: &str = r#"p = object!(parse_json!(string!(.message)))
. = { "class_uid": 6003, "category_uid": 6, "activity_id": 1, "time": 1762164000000, "actor": { "user": { "name": p.user } } }"#;

#[test]
fn a_runtime_parse_failure_lands_in_ocsf_logs_with_its_raw_text_and_error() {
    let p = parser("strict_json", STRICT_JSON_OCSF);
    let raw = "pm-5346 not json at all";
    let landed = land(
        &p,
        json!({ "message": raw, "source_type": "strict_json", "timestamp": "2026-11-12T10:00:00Z" }),
    );
    let event = &landed.row["event"];
    assert_eq!(event["class_uid"], 0, "{}", landed.row);
    assert_eq!(event["raw_data"], raw, "the raw text is searchable: {}", landed.row);
    let error = event["unmapped"]["parse_error"].as_str().unwrap_or_default();
    assert!(error.contains("parse_json"), "the runtime error is kept: {}", landed.row);
    assert_eq!(event["unmapped"]["parse_stage"], "strict_json_parse");
    assert_eq!(event["unmapped"]["parser_id"], p.id.to_string());
    assert_eq!(event["unmapped"]["parser_name"], "strict_json");
    assert!(event["unmapped"].get("parser_output").is_none(), "{}", landed.row);
    assert!(
        event["message"].as_str().unwrap().starts_with("Parse failure (strict_json): "),
        "{}",
        landed.row
    );
    assert_eq!(event["time"], 1_794_477_600_000_i64, "the input event's time: {}", landed.row);
    assert_eq!(event["metadata"]["log_source"], "strict_json");
    assert_eq!(landed.row["source_type"], "strict_json");

    assert_eq!(landed.health["parse_failure"], 1, "{}", landed.health);
    assert_eq!(landed.health["parse_fallback"], 0);
    assert_eq!(landed.health["parser_id"], p.id.to_string());
    assert_eq!(landed.health["source_type"], "strict_json");

    // A record the parser does parse is untouched and healthy.
    let ok = land(&p, json!({ "message": r#"{"user":"alice"}"#, "source_type": "strict_json" }));
    assert_eq!(ok.row["event"]["class_uid"], 6003, "{}", ok.row);
    assert!(ok.row["event"].get("unmapped").map_or(true, |u| u.get("parse_error").is_none()));
    assert_eq!(ok.health["parse_failure"], 0);
}

#[test]
fn output_without_a_class_uid_lands_as_a_parse_error_record() {
    // A UDM-shaped parser deployed on an OCSF install.
    let p = parser("udm_shaped", r#". = { "message": .message, "udm": { "user": "alice" }, "ext": { "k": 1 } }"#);
    let landed = land(&p, json!({ "message": "pm-5346 udm line", "source_type": "udm_shaped" }));
    let event = &landed.row["event"];
    assert_eq!(event["class_uid"], 0, "{}", landed.row);
    assert_eq!(event["raw_data"], "pm-5346 udm line");
    assert_eq!(event["unmapped"]["parse_error"], "parser output has no OCSF class_uid");
    assert_eq!(event["unmapped"]["parse_stage"], "ocsf_mapping");
    assert_eq!(
        event["unmapped"]["parser_output"]["udm"]["user"], "alice",
        "what the parser produced is kept: {}",
        landed.row
    );
    assert_eq!(landed.health["parse_failure"], 1, "{}", landed.health);
}

#[test]
fn a_parser_reported_root_parse_error_keeps_its_message() {
    let p = parser(
        "reports_error",
        r#". = { "class_uid": 0, "message": .message, "parse_error": "unsupported record version 9" }"#,
    );
    let landed = land(&p, json!({ "message": "v9|x|y", "source_type": "reports_error" }));
    let event = &landed.row["event"];
    assert_eq!(event["unmapped"]["parse_error"], "unsupported record version 9", "{}", landed.row);
    assert_eq!(event["unmapped"]["parse_stage"], "parser");
    assert_eq!(event["raw_data"], "v9|x|y");
    assert_eq!(landed.health["parse_failure"], 1);
}

#[test]
fn a_non_string_message_is_kept_as_json() {
    let p = parser("udm_shaped", r#". = { "udm": { "user": "alice" } }"#);
    let landed = land(&p, json!({ "message": "dropped by the parser", "source_type": "udm_shaped" }));
    let raw = landed.row["event"]["raw_data"].as_str().unwrap();
    assert!(raw.contains("\"alice\""), "the output is serialized when no message survives: {raw}");
}

/// Rendered-config contract for both profiles.
#[test]
fn ocsf_parser_output_never_reaches_the_udm_logs_stream() {
    let p = parser("strict_json", STRICT_JSON_OCSF);
    for slots in [false, true] {
        let ocsf = VectorConfigManager::combiner_config_content_with(std::slice::from_ref(&p), true, slots);
        assert_eq!(
            resolved_inputs(&[&ocsf], "db_parsers_combined"),
            vec!["prepare_output".to_string()],
            "only the never-matching parked filter (slots={slots}): {ocsf}"
        );
        assert_eq!(
            resolved_inputs(&[&ocsf], "db_parser_health"),
            vec!["strict_json_ocsf_prepare".to_string()],
            "slots={slots}"
        );
        let sink_inputs = VectorConfigManager::ocsf_sink_inputs_with(true, slots, std::slice::from_ref(&p));
        let sink = VectorConfigManager::ocsf_sink_content(&sink_inputs);
        let mut ocsf_sink = resolved_inputs(&[&ocsf, &sink], "clickhouse_ocsf_logs");
        ocsf_sink.sort();
        assert_eq!(ocsf_sink, vec!["generic_ocsf_prepare", "strict_json_ocsf_prepare"], "slots={slots}");

        let udm = VectorConfigManager::combiner_config_content_with(std::slice::from_ref(&p), false, slots);
        assert_eq!(resolved_inputs(&[&udm], "db_parsers_combined"), vec!["strict_json_output".to_string()]);
        assert_eq!(resolved_inputs(&[&udm], "db_parser_health"), vec!["strict_json_output".to_string()]);
        assert!(!udm.contains("_ocsf_"), "{udm}");
    }
}

/// `generic_parser` feeds `logs` only under UDM and `ocsf_logs` only under
/// OCSF. Every other static component keeps its definition, so the
/// disk-buffered `clickhouse_logs` sink is not rebuilt on upgrade.
#[test]
fn unparsed_events_are_written_once_per_profile() {
    let udm = VectorConfigManager::pipeline_config_content_for(false);
    let ocsf = VectorConfigManager::pipeline_config_content_for(true);
    let (u, o) = (transforms(&udm), transforms(&ocsf));

    assert_eq!(inputs(&u, "normalize"), ["placeholder_combiner", "generic_parser"]);
    assert!(u.get("generic_ocsf_prepare").is_none());

    assert_eq!(inputs(&o, "normalize"), ["placeholder_combiner"]);
    assert_eq!(inputs(&o, "generic_ocsf_prepare"), ["generic_parser"]);
    let readers: Vec<&String> = o
        .iter()
        .filter(|(_, def)| {
            def.get("inputs")
                .and_then(|i| i.as_array())
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some("generic_parser")))
        })
        .map(|(name, _)| name)
        .collect();
    assert_eq!(readers, ["generic_ocsf_prepare"], "generic_parser has one reader under OCSF");

    for (name, def) in &u {
        if name != "normalize" {
            assert_eq!(o.get(name), Some(def), "{name} differs between profiles");
        }
    }
    let sinks = |doc: &str| -> toml::Value {
        let raw = crate::parsers::vector_config::fanin_slots::without_env(doc);
        toml::from_str::<toml::Table>(&raw).unwrap()["sinks"].clone()
    };
    assert_eq!(sinks(&udm), sinks(&ocsf), "no sink changes with the profile");
}

/// A source-flagged parse failure on the generic lane is findable as
/// `unmapped.parse_error`.
#[test]
fn a_generic_lane_parse_failure_is_findable_in_ocsf() {
    let ocsf = transforms(&VectorConfigManager::pipeline_config_content_for(true));
    let event = json!({ "message": "pm-5346 garbled", "source_type": "edge_fw", "parse_error": "bad header" });
    let (event, meta) = run(&source(&ocsf, "generic_parser"), event, json!({})).unwrap();
    let (row, _) = run(&source(&ocsf, "generic_ocsf_prepare"), event, meta).unwrap();
    assert_eq!(row["event"]["class_uid"], 0, "{row}");
    assert_eq!(row["event"]["message"], "pm-5346 garbled");
    assert_eq!(row["event"]["unmapped"]["parse_error"], "bad header", "{row}");
    assert_eq!(row["source_type"], "edge_fw");
}

/// Review P1: a parser that emits credential fields and no `class_uid` or
/// `message`. The failure record snapshots the event into `raw_data` and
/// `parser_output`; neither may carry the secret.
#[test]
fn credential_fields_never_reach_a_parse_error_record() {
    let p = parser(
        "leaky",
        r#". = { "Authorization": "Bearer pm5346-secret-a", "nested": { "X-Api-Key": "pm5346-secret-b", "keep": "visible" } }"#,
    );
    let landed = land(&p, json!({ "message": "ignored", "source_type": "leaky" }));
    let row = landed.row.to_string();
    assert!(!row.contains("pm5346-secret"), "a credential leaked into the stored row: {row}");
    let event = &landed.row["event"];
    assert!(event["raw_data"].as_str().unwrap().contains("visible"), "{row}");
    assert_eq!(event["unmapped"]["parser_output"]["nested"]["keep"], "visible", "{row}");
    assert_eq!(event["unmapped"]["parse_error"], "parser output has no OCSF class_uid");
    assert_eq!(landed.health["parse_failure"], 1);

    // A runtime failure keeps the input event: its credential fields go too.
    let strict = parser("strict_json", STRICT_JSON_OCSF);
    let landed = land(
        &strict,
        json!({ "message": "not json", "source_type": "strict_json", "headers": { "authorization": "Bearer pm5346-secret-c" } }),
    );
    let row = landed.row.to_string();
    assert!(!row.contains("pm5346-secret"), "{row}");
    assert_eq!(landed.row["event"]["raw_data"], "not json");
}
