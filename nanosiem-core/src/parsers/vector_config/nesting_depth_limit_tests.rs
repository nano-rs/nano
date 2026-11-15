// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5431: values nested past Vector's disk-buffer encoding limit are stored
//! as JSON text instead of being discarded after ingest acknowledged them.
//! Runs the shipped VRL on the VRL runtime.

use serde_json::{json, Value};

use super::parser_config::OCSF_PREPARE_VRL;
use super::{VectorConfigManager, MAX_STORED_NESTING_DEPTH, NESTING_DEPTH_LIMIT_TEST_VRL};

fn compile(program: &str) -> vrl::compiler::Program {
    vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| {
            panic!("VRL compiles:\n{}", vrl::diagnostic::Formatter::new(program, d))
        })
        .program
}

fn run(program: &str, event: Value) -> Value {
    let compiled = compile(program);
    let mut target = vrl::compiler::TargetValue {
        value: vrl::value::Value::from(event),
        metadata: vrl::value::Value::from(json!({ "source_type": "acme" })),
        secrets: vrl::value::Secrets::new(),
    };
    vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
        .resolve(&mut target, &compiled, &vrl::compiler::TimeZone::Local)
        .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
    target.value.try_into().expect("event json")
}

/// Container depth: a scalar is 0, `{}` is 1, `{"a": {}}` is 2.
fn depth(v: &Value) -> usize {
    match v {
        Value::Object(m) => 1 + m.values().map(depth).max().unwrap_or(0),
        Value::Array(a) => 1 + a.iter().map(depth).max().unwrap_or(0),
        _ => 0,
    }
}

fn nested_objects(levels: usize) -> Value {
    let mut v = json!({ "leaf": levels });
    for _ in 0..levels {
        v = json!({ "k": v });
    }
    v
}

fn limit(value: Value) -> Value {
    let program = format!(
        "nano_test_value = .value\n{NESTING_DEPTH_LIMIT_TEST_VRL}. = {{ \"value\": nano_test_value }}\n"
    );
    run(&program, json!({ "value": value }))["value"].clone()
}

#[test]
fn the_level_count_matches_the_documented_limit() {
    assert_eq!(
        NESTING_DEPTH_LIMIT_TEST_VRL.matches("nano_depth_frontier = nano_depth_next").count(),
        MAX_STORED_NESTING_DEPTH
    );
    assert!(NESTING_DEPTH_LIMIT_TEST_VRL.contains(&format!("{{{}}}", MAX_STORED_NESTING_DEPTH + 1)));
    assert!(!NESTING_DEPTH_LIMIT_TEST_VRL.contains('$'), "pipeline files are env-interpolated");
}

#[test]
fn values_within_the_limit_are_untouched() {
    for levels in [0, 5, 20, MAX_STORED_NESTING_DEPTH - 1] {
        let v = nested_objects(levels);
        assert_eq!(limit(v.clone()), v, "{levels} levels");
    }
    // Wide, not deep: many containers pass the bracket gate but stay as-is.
    let wide = json!({ "items": (0..60).map(|i| json!({ "i": i, "tags": [i] })).collect::<Vec<_>>() });
    assert_eq!(limit(wide.clone()), wide);
}

#[test]
fn deeper_values_are_kept_as_json_text_at_the_limit() {
    for levels in [MAX_STORED_NESTING_DEPTH, 30, 60, 125] {
        let original = nested_objects(levels);
        let out = limit(original.clone());
        assert!(depth(&out) <= MAX_STORED_NESTING_DEPTH, "{levels}: depth {}", depth(&out));
        assert_eq!(out["nano_nesting_truncated"], true);
        // Walk down to the stored text and check it is the original subtree.
        let mut cursor = &out;
        let mut expected = &original;
        for _ in 0..MAX_STORED_NESTING_DEPTH - 1 {
            cursor = &cursor["k"];
            expected = &expected["k"];
        }
        let text = cursor["k"].as_str().expect("the deep subtree is stored as text");
        assert_eq!(&serde_json::from_str::<Value>(text).unwrap(), &expected["k"]);
    }
}

#[test]
fn nesting_through_arrays_is_limited_too() {
    let mut arrays = json!([1]);
    for _ in 0..40 {
        arrays = json!([arrays]);
    }
    let mut mixed = json!({ "x": 1 });
    for _ in 0..40 {
        mixed = json!([{ "a": mixed }]);
    }
    for v in [arrays, mixed] {
        let out = limit(json!({ "v": v, "flat": [{ "a": 1 }, { "b": [1, 2] }] }));
        assert!(depth(&out) <= MAX_STORED_NESTING_DEPTH, "depth {}", depth(&out));
        assert_eq!(out["flat"], json!([{ "a": 1 }, { "b": [1, 2] }]), "shallow siblings are kept");
    }
}

#[test]
fn the_ocsf_row_fits_and_marks_the_event() {
    let deep = json!({ "class_uid": 0, "time": 0, "unmapped": { "extra": nested_objects(120) } });
    let row = run(OCSF_PREPARE_VRL, deep);
    assert!(depth(&row["event"]) <= MAX_STORED_NESTING_DEPTH, "depth {}", depth(&row["event"]));
    assert_eq!(row["event"]["unmapped"]["nano_nesting_truncated"], true);

    let shallow = json!({ "class_uid": 0, "time": 0, "unmapped": { "extra": nested_objects(10) } });
    let row = run(OCSF_PREPARE_VRL, shallow);
    assert_eq!(row["event"]["unmapped"]["extra"], nested_objects(10));
    assert!(row["event"]["unmapped"].get("nano_nesting_truncated").is_none());
}

/// The generic OCSF lane and the UDM `clickhouse_mapping` carry the limit and
/// still compile (Vector refuses a config with any VRL diagnostic).
#[test]
fn every_storage_boundary_carries_the_limit_and_compiles() {
    let full = VectorConfigManager::pipeline_config_content_for(true);
    for (transform, var) in [
        ("generic_ocsf_prepare", "ocsf_event"),
        ("clickhouse_mapping", "ext_existing"),
    ] {
        let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
            .unwrap()
            .replace_all(&full, "$1")
            .into_owned();
        let table: toml::Table = substituted.parse().expect("config parses");
        let source = table["transforms"][transform]["source"]
            .as_str()
            .unwrap_or_else(|| panic!("{transform} has a VRL source"));
        assert!(
            source.contains(&format!("nano_depth_value = get({var}, nano_depth_path)")),
            "{transform} lost the nesting limit"
        );
        compile(source);
    }
}
