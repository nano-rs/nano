// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5849: a stored OCSF event never spells one ClickHouse `JSON` path twice,
//! and no value is lost doing so. See `json_path_collision.rs` for the scheme.
//!
//! [`collisions`] models how ClickHouse resolves keys into paths (verified on
//! ClickHouse 26.10: keys are joined with `.` with no escaping, a null and an
//! empty object occupy no path, an array is one path and each object inside
//! it is its own document). `scripts/tests/json-path-collision-ch.live.sh`
//! inserts the rows written by [`dump_rows_for_clickhouse`] into a real
//! ClickHouse `JSON` column and hands the stored rows back to
//! [`verify_rows_from_clickhouse`].

use std::collections::BTreeMap;

use chrono::Utc;
use serde_json::{json, Value};
use uuid::Uuid;

use super::json_path_collision::JSON_PATH_COLLISION_TEST_VRL;
use super::parser_config::OCSF_PREPARE_VRL;
use super::{VectorConfigManager, MAX_STORED_NESTING_DEPTH, NESTING_DEPTH_LIMIT_TEST_VRL};
use crate::parsers::types::Parser;

fn run(program: &str, event: Value, metadata: Value) -> (Value, Value) {
    let compiled = vrl::compiler::compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles:\n{}", vrl::diagnostic::Formatter::new(program, d)))
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

/// The macro alone on an event whose `unmapped` is `value`; returns the
/// stored `unmapped`. Compiled once per thread.
fn normalize(value: Value) -> Value {
    normalize_event(json!({ "class_uid": 0, "unmapped": value }))["unmapped"].clone()
}

/// The macro alone on `event`.
fn normalize_event(event: Value) -> Value {
    thread_local! {
        static PROGRAM: vrl::compiler::Program = {
            let program = format!("nano_test_value = .value\nnano_depth_json = encode_json(nano_test_value)\n{JSON_PATH_COLLISION_TEST_VRL}. = {{ \"value\": nano_test_value }}\n");
            vrl::compiler::compile(&program, &vrl::stdlib::all())
                .unwrap_or_else(|d| panic!("VRL compiles:\n{}", vrl::diagnostic::Formatter::new(&program, d)))
                .program
        };
    }
    PROGRAM.with(|compiled| {
        let mut target = vrl::compiler::TargetValue {
            value: vrl::value::Value::from(json!({ "value": event })),
            metadata: vrl::value::Value::from(json!({})),
            secrets: vrl::value::Secrets::new(),
        };
        vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
            .resolve(&mut target, compiled, &vrl::compiler::TimeZone::Local)
            .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
        let out: Value = target.value.try_into().expect("event json");
        out["value"].clone()
    })
}

// ---- the ClickHouse model ---------------------------------------------------

fn collect_paths(prefix: &str, value: &Value, out: &mut BTreeMap<String, usize>, docs: &mut Vec<Value>) {
    match value {
        Value::Null => {}
        Value::Object(map) => {
            for (k, v) in map {
                // `prefix` is never the document root (a key "" is a segment).
                collect_paths(&format!("{prefix}.{k}"), v, out, docs);
            }
        }
        Value::Array(items) => {
            *out.entry(prefix.to_string()).or_default() += 1;
            collect_array_docs(items, docs);
        }
        _ => *out.entry(prefix.to_string()).or_default() += 1,
    }
}

fn collect_array_docs(items: &[Value], docs: &mut Vec<Value>) {
    for item in items {
        match item {
            Value::Object(_) => docs.push(item.clone()),
            Value::Array(inner) => collect_array_docs(inner, docs),
            _ => {}
        }
    }
}

/// Every stored path that two values share, in any JSON document of `value`
/// (the root object, and each object inside an array). Empty = ClickHouse
/// accepts the row.
fn collisions(value: &Value) -> Vec<String> {
    let mut found = Vec::new();
    let mut docs = vec![value.clone()];
    while let Some(doc) = docs.pop() {
        let mut paths = BTreeMap::new();
        let Value::Object(map) = &doc else { continue };
        for (k, v) in map {
            collect_paths(k, v, &mut paths, &mut docs);
        }
        found.extend(paths.into_iter().filter(|(_, n)| *n > 1).map(|(p, _)| p));
    }
    found
}

/// Every non-null scalar, with multiplicity, as JSON text. An array stored as
/// its JSON text (scheme step 4) is read back as the array.
fn leaves(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::Null => {}
        Value::String(text) if text.starts_with('[') => match serde_json::from_str::<Value>(text) {
            Ok(array @ Value::Array(_)) => leaves(&array, out),
            _ => out.push(value.to_string()),
        },
        Value::Object(map) => map.values().for_each(|v| leaves(v, out)),
        Value::Array(items) => items.iter().for_each(|v| leaves(v, out)),
        scalar => out.push(scalar.to_string()),
    }
}

fn sorted_leaves(value: &Value) -> Vec<String> {
    let mut out = Vec::new();
    leaves(value, &mut out);
    out.sort();
    out
}

/// Asserts the normalized value is accepted and lost nothing.
fn assert_stored_losslessly(input: &Value, output: &Value) {
    assert!(collisions(output).is_empty(), "still collides {:?}: {output}", collisions(output));
    assert_eq!(sorted_leaves(input), sorted_leaves(output), "a value was lost or changed: {input} -> {output}");
}

#[test]
fn the_model_matches_what_clickhouse_refuses() {
    // Each refused (Code 117) or accepted on ClickHouse 26.10.4.207.
    assert_eq!(collisions(&json!({ "a.b": 1, "a": { "b": 2 } })), ["a.b"]);
    assert_eq!(collisions(&json!({ "a": { "b.c": 1 }, "a.b": { "c": 2 } })), ["a.b.c"]);
    assert_eq!(collisions(&json!({ "x": [{ "a.b": 1, "a": { "b": 2 } }] })), ["a.b"]);
    assert_eq!(collisions(&json!({ "x": [[{ "a.b": 1, "a": { "b": 2 } }]] })), ["a.b"]);
    assert_eq!(collisions(&json!({ "a.b": [1], "a": { "b": 2 } })), ["a.b"]);
    assert_eq!(collisions(&json!({ "a\\.b": 1, "a\\": { "b": 2 } })), ["a\\.b"]);
    assert_eq!(collisions(&json!({ "a..b": 1, "a": { "": { "b": 2 } } })), ["a..b"]);
    assert!(collisions(&json!({ "a.b": 1, "a": { "c": 2 } })).is_empty());
    assert!(collisions(&json!({ "a": 1, "a.b": 2 })).is_empty(), "a leaf and a longer path coexist");
    assert!(collisions(&json!({ "a.b": 1, "a": { "b": {} } })).is_empty(), "an empty object is no path");
    assert!(collisions(&json!({ "a.b": null, "a": { "b": 2 } })).is_empty(), "a null is not stored");
    assert!(collisions(&json!({ "x": [{ "a.b": 1 }, { "a": { "b": 2 } }] })).is_empty(), "array members are separate");
}

// ---- the macro ----------------------------------------------------------------

#[test]
fn the_program_compiles_and_reads_the_depth_limit_text() {
    assert!(JSON_PATH_COLLISION_TEST_VRL.contains("match(nano_depth_json,"), "no extra encode on a plain event");
    assert!(!JSON_PATH_COLLISION_TEST_VRL.contains('$'), "pipeline files are env-interpolated");
    assert!(!JSON_PATH_COLLISION_TEST_VRL.contains("'''"), "embedded in a TOML literal string");
    assert!(JSON_PATH_COLLISION_TEST_VRL.len() < 6144, "small: it is compiled once per parser");
    normalize(json!({}));
    // Anything but an object is left alone.
    assert_eq!(normalize_event(json!("a.b\":")), json!("a.b\":"));
}

#[test]
fn data_without_a_collision_is_stored_unchanged() {
    for value in [
        json!({}),
        json!({ "message": "plain", "n": 1, "nested": { "k": [1, 2, { "x": "y" }] }, "empty": {} }),
        // ECS-style flat keys: dotted, sharing a head, no shared path.
        json!({ "host.name": "web-1", "host.ip": "10.0.0.1", "event.code": 4624, "event": { "kind": "x" }, "e": {} }),
        json!({ "a.b": 1, "a": { "c": 2 } }),
        json!({ "a": 1, "a.b": 2, "a.b.c": 3 }),
        json!({ "a.b": 1, "a": { "b": {} } }),
        json!({ "a.b": null, "a": { "b": 2 } }),
        json!({ "a": { "b": null }, "a.b": 2 }),
        json!({ "x": [{ "a.b": 1 }, { "a": { "b": 2 } }] }),
        json!({ "version": "1.2.3", "url": "https://example.com/a.b\":", "tilde~key": "x" }),
    ] {
        assert_eq!(normalize(value.clone()), value);
    }
}

#[test]
fn the_nested_spelling_keeps_the_path_and_the_flat_one_is_escaped() {
    let input = json!({ "a.b": "flat", "a": { "b": "nested" } });
    let out = normalize(input.clone());
    assert_eq!(out, json!({ "a": { "b": "nested" }, "a~1b": "flat" }));
    assert_stored_losslessly(&input, &out);
}

#[test]
fn mixed_spellings_are_all_kept() {
    let input = json!({ "a.b": { "c": "partly" }, "a.b.c": "flat" });
    let out = normalize(input.clone());
    assert_eq!(out, json!({ "a~1b": { "c": "partly" }, "a~1b~1c": "flat" }));
    assert_stored_losslessly(&input, &out);

    let input = json!({ "a": { "b.c": "inner" }, "a.b": { "c": "outer" } });
    let out = normalize(input.clone());
    // Both colliding spellings hold a dotted key, so both heads are escaped.
    assert_eq!(out, json!({ "a": { "b~1c": "inner" }, "a~1b": { "c": "outer" } }));
    assert_stored_losslessly(&input, &out);

    // Four spellings of one path: all kept, none collide.
    let input = json!({ "a.b.c": "f1", "a.b": { "c": "f2" }, "a": { "b": { "c": "n" }, "b.c": "f3" } });
    let out = normalize(input.clone());
    assert_eq!(out["a"]["b"]["c"], "n", "{out}");
    assert_stored_losslessly(&input, &out);
}

#[test]
fn an_escaped_name_never_clashes_with_an_existing_key() {
    // A key already spelled like an escaped one: every `~` key is escaped too.
    let input = json!({ "a.b": "flat", "a": { "b": "nested" }, "a~1b": "literal", "x~y": "z" });
    let out = normalize(input.clone());
    assert_eq!(out, json!({ "a": { "b": "nested" }, "a~1b": "flat", "a~01b": "literal", "x~0y": "z" }));
    assert_stored_losslessly(&input, &out);
}

#[test]
fn only_heads_that_can_collide_are_escaped() {
    // Spill-style flat keys next to a collision keep their dots.
    let input = json!({ "a.b": "flat", "a": { "b": "nested" }, "request.id": "r", "tls.cipher": "c" });
    let out = normalize(input.clone());
    assert_eq!(out, json!({ "a": { "b": "nested" }, "a~1b": "flat", "request.id": "r", "tls.cipher": "c" }));
    assert_stored_losslessly(&input, &out);

    // A head that is an object elsewhere in the event does not count: only
    // heads on a colliding path are escaped.
    let event = json!({ "metadata": { "foo": "m" }, "unmapped": { "a.b": "flat", "a": { "b": "nested" }, "metadata.foo": "u" } });
    let out = normalize_event(event.clone());
    assert_eq!(out["unmapped"]["metadata.foo"], "u", "{out}");
    assert_eq!(out["unmapped"]["a~1b"], "flat", "{out}");
    assert_stored_losslessly(&event, &out);

    // More than 64 colliding paths: every dotted key is escaped.
    let mut map = serde_json::Map::new();
    for n in 0..70 {
        map.insert(format!("h{n}"), json!({ "x": format!("n{n}") }));
        map.insert(format!("h{n}.x"), json!(format!("f{n}")));
    }
    map.insert("other.y".into(), json!("o"));
    let input = Value::Object(map);
    let out = normalize(input.clone());
    assert_eq!(out["h7~1x"], "f7", "{out}");
    assert_eq!(out["other~1y"], "o", "{out}");
    assert_stored_losslessly(&input, &out);
}

/// Review round 3: a flat dotted null on an array's path must not hide the
/// array from the check (it used to, through a "."-flattened map in which
/// the null overwrote the array).
fn null_shadowed_arrays() -> Vec<Value> {
    vec![
        json!({ "a": { "b": [{ "c.d": "flat1", "c": { "d": "nested1" } }] }, "a.b": null }),
        json!({ "list": [{ "a": { "b": [{ "c.d": "flat2", "c": { "d": "nested2" } }] }, "a.b": null }] }),
        json!({ "x": { "y": { "z": [{ "c.d": "flat3", "c": { "d": "nested3" } }] } }, "x.y.z": null }),
        json!({ "a.b": { "c": [{ "d.e": "flat5", "d": { "e": "nested5" } }] }, "a.b.c": null }),
        json!({ "a": { "b": [[{ "c.d": "flat11", "c": { "d": "nested11" } }]] }, "a.b": null }),
    ]
}

#[test]
fn a_null_shadowing_an_array_path_does_not_hide_its_collisions() {
    for input in null_shadowed_arrays() {
        let out = normalize(input.clone());
        assert!(collisions(&json!({ "unmapped": out.clone() })).is_empty(), "{input} -> {out}");
        assert_stored_losslessly(&input, &out);
    }
}

#[test]
fn collisions_anywhere_in_the_event_are_resolved() {
    // A parser can spell an OCSF path twice outside unmapped.
    let event = json!({ "class_uid": 0, "src_endpoint.ip": "flat", "src_endpoint": { "ip": "nested" } });
    let out = normalize_event(event.clone());
    assert_eq!(out["src_endpoint"]["ip"], "nested", "{out}");
    assert_eq!(out["src_endpoint~1ip"], "flat", "{out}");
    assert_stored_losslessly(&event, &out);
}

#[test]
fn collisions_inside_arrays_are_resolved() {
    for input in [
        json!({ "x": [{ "a.b": "f", "a": { "b": "n" } }, "s", { "k": "v" }] }),
        json!({ "x": [[{ "a.b": "f", "a": { "b": "n" } }]] }),
        json!({ "x": { "y": [{ "z": { "a.b": "f", "a": { "b": "n" } } }] } }),
        json!({ "x": [{ "deeper": [{ "a.b": "f", "a": { "b": "n" } }] }] }),
        json!({ "a.b": [{ "c.d": "f1", "c": { "d": "n1" } }], "a": { "b": "n" } }),
        json!({ "a.b": ["f"], "a": { "b": "n" } }),
    ] {
        let out = normalize(input.clone());
        assert_stored_losslessly(&input, &out);
    }
    let out = normalize(json!({ "x": [{ "a.b": "f", "a": { "b": "n" } }] }));
    assert_eq!(out, json!({ "x": [{ "a": { "b": "n" }, "a~1b": "f" }] }));
}

#[test]
fn keys_with_escaped_or_empty_segments_follow_clickhouse() {
    // ClickHouse does not treat a backslash as an escape: "a\.b" is the path
    // segments `a\` and `b`, the same path as {"a\": {"b": ...}}.
    for input in [
        json!({ "a\\.b": "f", "a\\": { "b": "n" } }),
        json!({ "a..b": "f", "a": { "": { "b": "n" } } }),
        json!({ "a.": "f", "a": { "": "n" } }),
        json!({ ".a": "f", "": { "a": "n" } }),
        json!({ "a\\\"q.b": "f", "a\\\"q": { "b": "n" } }),
        json!({ "a~1b": "tilde", "a.b": "f", "a": { "b": "n" } }),
    ] {
        let out = normalize(input.clone());
        assert_stored_losslessly(&input, &out);
    }
    let input = json!({ "a\\.b": "kept", "a": { "b": "also kept" } });
    assert_eq!(normalize(input.clone()), input, "not the same path, so nothing moves");
    let out = normalize(json!({ "a\\.b": "f", "a\\": { "b": "n" } }));
    assert_eq!(out["a\\~1b"], "f", "{out}");
}

#[test]
fn deep_nesting_is_handled_up_to_the_depth_limit() {
    // A collision at every level of a chain as deep as the depth limit keeps.
    let mut value = json!({ "a.b": "f0", "a": { "b": "n0" } });
    for i in 1..(MAX_STORED_NESTING_DEPTH - 3) {
        value = json!({ "k": value, "a.b": format!("f{i}"), "a": { "b": format!("n{i}") } });
    }
    let out = normalize(value.clone());
    assert_stored_losslessly(&value, &out);

    // Deeper than the limit: the depth limit stores the deep part as text
    // first, and the step resolves what is left.
    let mut deep = json!({ "a.b": "deep-f", "a": { "b": "deep-n" } });
    for _ in 0..40 {
        deep = json!({ "k": deep });
    }
    deep["a.b"] = json!("top-f");
    deep["a"] = json!({ "b": "top-n" });
    let program = format!(
        "nano_test_value = .value\n{NESTING_DEPTH_LIMIT_TEST_VRL}{JSON_PATH_COLLISION_TEST_VRL}. = {{ \"value\": nano_test_value }}\n"
    );
    let out = run(&program, json!({ "value": { "unmapped": deep } }), json!({})).0["value"].clone();
    assert!(collisions(&out).is_empty(), "{out}");
    assert_eq!(out["unmapped"]["a~1b"], "top-f");
}

/// Thousands of collisions in one event cost about what a plain event of the
/// same size does: every step is a builtin over the whole event.
#[test]
fn a_hostile_event_with_thousands_of_collisions_stays_cheap() {
    let mut map = serde_json::Map::new();
    for i in 0..4000 {
        map.insert(format!("k{i}"), json!({ "x": format!("n{i}") }));
        map.insert(format!("k{i}.x"), json!(format!("f{i}")));
    }
    let input = Value::Object(map);
    normalize(json!({}));
    let started = std::time::Instant::now();
    let out = normalize(input.clone());
    let took = started.elapsed();
    eprintln!("hostile 4000 collisions: {took:?}");
    assert_stored_losslessly(&input, &out);
    // A quadratic step takes about a minute here in a debug build.
    assert!(took < std::time::Duration::from_secs(10), "{took:?}");
}

/// A small deterministic PRNG (xorshift64*), so the fuzz case is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_value(rng: &mut Rng, depth: usize, counter: &mut usize) -> Value {
    const KEYS: [&str; 12] = ["a", "b", "a.b", "b.a", "a.b.c", "a!1b", "a~1b", "c", "a.", "", "a\\", "a\\.b"];
    let kind = if depth == 0 { rng.below(2) * 6 } else { rng.below(7) };
    *counter += 1;
    match kind {
        0 | 1 => json!(format!("v{counter}")),
        6 => Value::Null,
        2 => Value::Array((0..rng.below(3)).map(|_| random_value(rng, depth - 1, counter)).collect()),
        _ => {
            let mut map = serde_json::Map::new();
            for _ in 0..rng.below(6) {
                let key = KEYS[rng.below(KEYS.len() as u64) as usize];
                map.insert(key.to_string(), random_value(rng, depth - 1, counter));
            }
            Value::Object(map)
        }
    }
}

#[test]
fn random_spellings_always_store_and_keep_every_value() {
    let mut rng = Rng(0x5849_5849_5849_5849);
    let mut colliding = 0;
    for _ in 0..400 {
        let mut counter = 0;
        let mut map = serde_json::Map::new();
        for _ in 0..(1 + rng.below(6)) {
            let key = ["a", "a.b", "a.b.c", "b", "a~1b", "x"][rng.below(6) as usize];
            map.insert(key.to_string(), random_value(&mut rng, 4, &mut counter));
        }
        if rng.below(2) == 0 {
            // A guaranteed collision next to the random keys.
            map.insert("a.b".into(), json!("forced-flat"));
            map.insert("a".into(), json!({ "b": "forced-nested", "r": random_value(&mut rng, 3, &mut counter) }));
        }
        let input = Value::Object(map);
        if !collisions(&input).is_empty() {
            colliding += 1;
        }
        let out = normalize(input.clone());
        assert_stored_losslessly(&input, &out);
        assert_eq!(normalize(out.clone()), out, "normalizing twice changes nothing");
    }
    eprintln!("fuzz: {colliding}/400 inputs collided");
    assert!(colliding > 150, "the fuzz must exercise collisions: {colliding}");
}

// ---- the lanes ------------------------------------------------------------------

fn transforms(config: &str) -> toml::Table {
    let substituted = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(config, "$1");
    let doc: toml::Table = substituted.parse().expect("generated config is valid TOML");
    doc["transforms"].as_table().unwrap().clone()
}

fn source(t: &toml::Table, name: &str) -> String {
    t[name]["source"].as_str().unwrap_or_else(|| panic!("{name} has a VRL source")).to_string()
}

/// The generic Base Event lane (no parser): `generic_parser`, then
/// `generic_ocsf_prepare`; with `fixed = false`, the same lane without the
/// NAN-5849 step (what it stored before).
fn generic_lane(fixed: bool, record: &Value) -> Value {
    let t = transforms(&VectorConfigManager::pipeline_config_content_for(true));
    let mut event = record.clone();
    event["source_type"] = json!("probe_5849");
    let (event, meta) = run(&source(&t, "generic_parser"), event, json!({}));
    let mut prepare = source(&t, "generic_ocsf_prepare");
    if !fixed {
        let step = super::json_path_collision::JSON_PATH_COLLISION_OCSF_EVENT_VRL;
        assert!(prepare.contains(step), "the generic lane runs the step on ocsf_event");
        prepare = prepare.replacen(step, "", 1);
    }
    run(&prepare, event, meta).0
}

fn parser(name: &str, vrl: &str) -> Parser {
    Parser {
        activation_parked: false,
        id: Uuid::new_v4(),
        name: name.into(),
        description: None,
        source_type: name.into(),
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

/// Payloads mixing every spelling. Values are distinct strings so a lost one
/// is visible.
fn collision_payloads() -> Vec<(&'static str, Value)> {
    vec![
        ("flat_vs_nested", json!({ "a.b": "c1-flat", "a": { "b": "c1-nested" } })),
        ("mixed_inner_outer", json!({ "a": { "b.c": "c2-inner" }, "a.b": { "c": "c2-outer" } })),
        ("deep", json!({ "x": { "y": { "z": { "a.b": "c3-flat", "a": { "b": "c3-nested" } } } }, "x.y.z.a.b": "c3-top" })),
        ("array_of_objects", json!({ "list": [{ "a.b": "c4-flat", "a": { "b": "c4-nested" } }, { "k": "c4-other" }] })),
        ("array_of_arrays", json!({ "m": [[{ "p.q": "c5-flat", "p": { "q": "c5-nested" } }]] })),
        ("array_vs_scalar", json!({ "a.b": ["c6-arr"], "a": { "b": "c6-nested" } })),
        ("escaped_dot", json!({ "a\\.b": "c7-flat", "a\\": { "b": "c7-nested" } })),
        ("empty_segment", json!({ "a..b": "c8-flat", "a": { "": { "b": "c8-nested" } } })),
        ("taken_name", json!({ "a.b": "c9-flat", "a": { "b": "c9-nested" }, "a~1b": "c9-taken" })),
        ("four_spellings", json!({ "a.b.c": "c10-f1", "a.b": { "c": "c10-f2" }, "a": { "b": { "c": "c10-n" }, "b.c": "c10-f3" } })),
        ("null_shadow_root", null_shadowed_arrays()[0].clone()),
        ("null_shadow_in_array", null_shadowed_arrays()[1].clone()),
        ("null_shadow_deep", null_shadowed_arrays()[2].clone()),
        ("null_shadow_dotted", null_shadowed_arrays()[3].clone()),
        ("null_shadow_nested_arrays", null_shadowed_arrays()[4].clone()),
        ("ecs_no_collision", json!({ "host.name": "c11-host", "host": { "ip": "c11-ip" }, "event.code": "c11-code" })),
    ]
}

fn normal_payloads() -> Vec<Value> {
    (0..8)
        .map(|i| json!({ "message": format!("normal event {i}"), "user": { "name": format!("u{i}") }, "seq": format!("s{i}") }))
        .collect()
}

#[test]
fn the_generic_lane_stores_every_collision_payload_losslessly() {
    for (label, payload) in collision_payloads() {
        let before = generic_lane(false, &payload);
        let after = generic_lane(true, &payload);
        let unmapped = &after["event"]["unmapped"];
        assert!(collisions(&after).is_empty(), "{label}: {after}");
        let mut want = sorted_leaves(&payload);
        let mut have = Vec::new();
        leaves(unmapped, &mut have);
        for leaf in &mut want.drain(..) {
            let at = have.iter().position(|h| *h == leaf).unwrap_or_else(|| panic!("{label}: lost {leaf}: {after}"));
            have.swap_remove(at);
        }
        if label == "ecs_no_collision" {
            assert_eq!(before["event"], after["event"], "data without a collision is unchanged");
        } else {
            assert!(!collisions(&before).is_empty(), "{label}: the old lane collides: {before}");
        }
    }
    let after = generic_lane(true, &collision_payloads()[0].1);
    assert_eq!(after["event"]["unmapped"]["a"]["b"], "c1-nested", "{after}");
    assert_eq!(after["event"]["unmapped"]["a~1b"], "c1-flat", "{after}");
}

/// A JSON parser that keeps the record under `unmapped`, as the OCSF Generic
/// JSON parser does, and an HEC sibling spelling the same path flat.
#[test]
fn the_parser_lane_resolves_an_hec_sibling_that_spells_a_parser_path() {
    const RECORD_PARSER: &str = r#"e = object!(parse_json!(string!(.message)))
. = { "class_uid": 0, "category_uid": 0, "metadata": { "version": "1.9.0" }, "unmapped": e }"#;
    let p = parser("probe_json", RECORD_PARSER);
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(&p, true);
    let t = transforms(&config);
    let parsed = json!({ "class_uid": 0, "category_uid": 0, "metadata": { "version": "1.9.0" },
        "unmapped": { "a": { "b": "parser-nested" } } });
    let meta = json!({ "source_type": "probe_json", "nano_hec_event": { "a.b": "sibling-flat", "seq": "7" } });
    let (row, _) = run(&source(&t, "probe_json_ocsf_prepare"), parsed, meta);
    assert!(collisions(&row).is_empty(), "{row}");
    assert_eq!(row["event"]["unmapped"]["a"]["b"], "parser-nested", "{row}");
    assert_eq!(row["event"]["unmapped"]["a~1b"], "sibling-flat", "{row}");
    assert!(OCSF_PREPARE_VRL.contains(super::json_path_collision::JSON_PATH_COLLISION_OCSF_EVENT_VRL));
    assert_eq!(row["event"]["unmapped"]["seq"], "7", "{row}");
}

/// The stored ClickHouse path of every value in `value` (path -> leaf JSON).
fn stored_paths(value: &Value) -> BTreeMap<String, String> {
    fn walk(prefix: &str, value: &Value, out: &mut BTreeMap<String, String>) {
        match value {
            Value::Object(map) => {
                for (k, v) in map {
                    walk(&if prefix.is_empty() { k.clone() } else { format!("{prefix}.{k}") }, v, out);
                }
            }
            Value::Null => {}
            leaf => {
                out.insert(prefix.to_string(), leaf.to_string());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk("", value, &mut out);
    out
}

/// NAN-5894: a flat key that clashes with a nested path has ONE stored name
/// on every ingest path. With no parser the NAN-5849 step escapes it; a
/// nano-rs/parsers residual spill (as of NAN-5894) already writes it escaped,
/// as a flat `"a.b"` key beside `"a~1b"`, and the NAN-5849 step must then
/// leave both names alone (no second escape to `a~01b`, no `a.b_2`).
#[test]
fn a_clashing_flat_key_has_one_name_with_or_without_a_parser() {
    let record = json!({ "a.b": "flat", "a": { "b": "nested" }, "seq": "7" });
    let no_parser = generic_lane(true, &record);

    // What the parser hands its `_ocsf_prepare` (the spill's output for `record`).
    let p = parser("probe_spill", ". = .");
    let config = VectorConfigManager::new("/tmp/nanosiem-test").generate_parser_config_for(&p, true);
    let t = transforms(&config);
    let parsed = json!({ "class_uid": 0, "category_uid": 0, "metadata": { "version": "1.9.0" },
        "unmapped": { "a.b": "nested", "a~1b": "flat", "seq": "7" } });
    let (with_parser, _) = run(&source(&t, "probe_spill_ocsf_prepare"), parsed, json!({ "source_type": "probe_spill" }));

    for (lane, row) in [("no parser", &no_parser), ("parser", &with_parser)] {
        let unmapped = &row["event"]["unmapped"];
        assert!(collisions(row).is_empty(), "{lane}: {row}");
        let paths = stored_paths(unmapped);
        assert_eq!(paths.get("a.b").map(String::as_str), Some("\"nested\""), "{lane}: {paths:?}");
        assert_eq!(paths.get("a~1b").map(String::as_str), Some("\"flat\""), "{lane}: {paths:?}");
        assert!(!paths.keys().any(|k| k.ends_with("_2") || k.contains("~0")), "{lane}: {paths:?}");
    }
}

// ---- the live ClickHouse proof (scripts/tests/json-path-collision-ch.live.sh) ----

fn live_rows(fixed: bool) -> Vec<Value> {
    let mut rows = Vec::new();
    let normals = normal_payloads();
    let mut normals = normals.iter();
    for (label, payload) in collision_payloads() {
        // Interleaved, as a sink batch mixes sources.
        if let Some(normal) = normals.next() {
            rows.push(json!({ "label": "normal", "event": generic_lane(fixed, normal)["event"] }));
        }
        rows.push(json!({ "label": label, "event": generic_lane(fixed, &payload)["event"] }));
    }
    for normal in normals {
        rows.push(json!({ "label": "normal", "event": generic_lane(fixed, normal)["event"] }));
    }
    rows
}

/// Each row gets its position as `row`, so the stored rows read back in order.
fn write_ndjson(path: &str, rows: &[Value]) {
    let text: String = rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let mut r = r.clone();
            r["row"] = json!(i);
            format!("{r}\n")
        })
        .collect();
    std::fs::write(path, text).unwrap_or_else(|e| panic!("write {path}: {e}"));
}

/// Writes `$NANO_JSON_PATH_ROWS_OUT` (rows from the current generic lane),
/// `.before` (the same payloads through the lane without the step) and
/// `.expect` (each row's sender values). A no-op without the variable.
#[test]
fn dump_rows_for_clickhouse() {
    let Ok(out) = std::env::var("NANO_JSON_PATH_ROWS_OUT") else { return };
    write_ndjson(&out, &live_rows(true));
    write_ndjson(&format!("{out}.before"), &live_rows(false));
    let mut expect = Vec::new();
    let normals = normal_payloads();
    let mut normals = normals.iter();
    for (label, payload) in collision_payloads() {
        if let Some(normal) = normals.next() {
            expect.push(json!({ "label": "normal", "leaves": sorted_leaves(normal) }));
        }
        expect.push(json!({ "label": label, "leaves": sorted_leaves(&payload) }));
    }
    for normal in normals {
        expect.push(json!({ "label": "normal", "leaves": sorted_leaves(normal) }));
    }
    write_ndjson(&format!("{out}.expect"), &expect);
    // How nPL reads an escaped key (`unmapped.a~1b`) on the promoted column.
    let accessor = crate::query::json_tail_access_sql("unmapped", &["a~1b".to_string()], "String");
    std::fs::write(format!("{out}.accessor"), accessor).unwrap();
}

/// Reads `$NANO_JSON_PATH_CH_OUT` (`toJSONString(event)` per stored row,
/// ordered by `row`) and checks every sender value is retrievable from its row.
#[test]
fn verify_rows_from_clickhouse() {
    let Ok(stored) = std::env::var("NANO_JSON_PATH_CH_OUT") else { return };
    let expect = std::env::var("NANO_JSON_PATH_EXPECT").expect("NANO_JSON_PATH_EXPECT");
    let stored: Vec<Value> = std::fs::read_to_string(&stored)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).expect("stored row json"))
        .collect();
    let expect: Vec<Value> = std::fs::read_to_string(&expect)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(stored.len(), expect.len(), "every row was stored");
    for (row, want) in stored.iter().zip(&expect) {
        let mut have = Vec::new();
        leaves(&row["unmapped"], &mut have);
        for leaf in want["leaves"].as_array().unwrap() {
            let leaf = leaf.as_str().unwrap();
            let at = have
                .iter()
                .position(|h| h == leaf)
                .unwrap_or_else(|| panic!("{}: {leaf} is not retrievable from {row}", want["label"]));
            have.swap_remove(at);
        }
    }
}

// ---- the gate and the shared step ------------------------------------------------

/// Whether the macro's gate sends `unmapped = value` to the full check.
fn gate(value: Value) -> bool {
    thread_local! {
        static PROGRAM: vrl::compiler::Program = {
            let program = format!("nano_test_value = .value\nnano_depth_json = encode_json(nano_test_value)\n{JSON_PATH_COLLISION_TEST_VRL}. = {{ \"maybe\": nano_jp_maybe }}\n");
            vrl::compiler::compile(&program, &vrl::stdlib::all())
                .unwrap_or_else(|d| panic!("VRL compiles:\n{}", vrl::diagnostic::Formatter::new(&program, d)))
                .program
        };
    }
    PROGRAM.with(|compiled| {
        let mut target = vrl::compiler::TargetValue {
            value: vrl::value::Value::from(json!({ "value": { "class_uid": 0, "unmapped": value } })),
            metadata: vrl::value::Value::from(json!({})),
            secrets: vrl::value::Secrets::new(),
        };
        vrl::compiler::runtime::Runtime::new(vrl::compiler::state::RuntimeState::default())
            .resolve(&mut target, compiled, &vrl::compiler::TimeZone::Local)
            .unwrap_or_else(|e| panic!("VRL runtime: {e:?}"));
        let out: Value = target.value.try_into().expect("event json");
        out["maybe"] == json!(true)
    })
}

#[test]
fn the_gate_skips_flat_dotted_keys_that_cannot_collide() {
    // What the parsers' residual spill writes: flat dotted scalar keys next
    // to nested objects with other heads.
    for value in [
        json!({ "message": "plain", "user": { "name": "u" } }),
        json!({ "request_parameters.bucket_name": "b", "request_parameters.key": "k", "user_identity.arn": "a",
                "tls_details": { "cipher": "c" }, "nano": { "ingest": { "client_ip": "1.2.3.4" } } }),
        json!({ "a.b": 1, "a": 2 }),
        json!({ "a.b": [1, 2], "a.c": "x", "b": { "c": 1 } }),
        json!({ "a.b": { "c": 1 }, "x": { "y": 2 } }),
        json!({ "msg": "{\"a.b\":1,\"a\":{\"b\":2}}" }),
    ] {
        assert!(!gate(value.clone()), "{value}");
    }
    for value in [
        json!({ "a.b": 1, "a": { "b": 2 } }),
        json!({ "a.b": { "c": 1 }, "a.b.c": 2 }),
        json!({ "x": [{ "a.b": 1, "a": { "b": 2 } }] }),
        json!({ "a\\\"q.b": 1, "a\\\"q": { "b": 2 } }),
    ] {
        assert!(gate(value.clone()), "{value}");
    }
}

#[test]
fn the_gate_never_misses_a_collision() {
    let mut rng = Rng(0x0005_8490_5849_0001);
    for _ in 0..600 {
        let mut counter = 0;
        let mut map = serde_json::Map::new();
        for _ in 0..(1 + rng.below(6)) {
            let key = ["a", "a.b", "a.b.c", "b", "a~1b", "x"][rng.below(6) as usize];
            map.insert(key.to_string(), random_value(&mut rng, 4, &mut counter));
        }
        let value = Value::Object(map);
        let event = json!({ "class_uid": 0, "unmapped": value.clone() });
        if !collisions(&event).is_empty() {
            assert!(gate(value.clone()), "missed {value}");
        }
    }
}

#[test]
fn the_sink_wiring_is_unchanged() {
    // NAN-5849 adds no component: a hot reload never rewires the disk-buffered
    // sink (rewiring during a reload can drop events already acknowledged).
    let config = VectorConfigManager::ocsf_sink_content(&["\"a_ocsf_prepare\"".to_string(), "\"generic_ocsf_prepare\"".to_string()]);
    let doc: toml::Table = regex::Regex::new(r"\$\{[A-Z0-9_]+:-([^}]*)\}")
        .unwrap()
        .replace_all(&config, "$1")
        .parse()
        .expect("valid TOML");
    assert!(doc.get("transforms").is_none(), "{config}");
    assert_eq!(
        doc["sinks"]["clickhouse_ocsf_logs"]["inputs"],
        toml::Value::try_from(["a_ocsf_prepare", "generic_ocsf_prepare"]).unwrap()
    );
}
