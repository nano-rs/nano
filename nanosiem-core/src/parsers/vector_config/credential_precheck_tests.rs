// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5180: the credential-key gate in front of the NAN-4038 path walk.
//!
//! The walk (`flatten` + split + downcase per segment) cost 35-60 us per event
//! on the OCSF lane and ~10 us in `parse_content`, almost always to remove
//! nothing. It now runs only when `credential_key_precheck_vrl!` matches the
//! event's `encode_json` text. These tests hold the gate to "output unchanged":
//!
//! * the gate's name list is the redaction name list, and every walk is gated;
//! * every key that downcases to a credential name (any Unicode spelling)
//!   matches the gate;
//! * on a golden corpus (three records from each of the 16 shipped OCSF
//!   parsers, as `_parse` emits them, plus adversarial records) the gated
//!   programs produce exactly what the same programs produce with the gate
//!   forced open, which is the pre-NAN-5180 behavior.

use regex::Regex;
use serde_json::{json, Value as Json};
use vrl::compiler::runtime::{Runtime, Terminate};
use vrl::compiler::state::RuntimeState;
use vrl::compiler::{compile, TargetValue, TimeZone};
use vrl::value::{Secrets, Value};

use super::parser_config::OCSF_PREPARE_VRL;
use super::{VectorConfigManager, CREDENTIAL_FIELD_REDACTION_VRL, CREDENTIAL_KEY_PRECHECK_VRL};
use crate::parsers::pipe::tap::CREDENTIAL_FIELD_NAMES;

const BASE: &str = include_str!("../../../../config/vector/00-base.toml");
/// `_parse` output (event + metadata) of the first three samples of each of
/// the 16 shipped OCSF parsers: the input of `<parser>_ocsf_prepare`.
const PREPARE_INPUTS: &str = include_str!("../../../tests/fixtures/nan5180/ocsf_prepare_inputs.ndjson");
/// The first three raw sample lines of each of the 16 shipped OCSF parsers.
const HTTP_LINES: &str = include_str!("../../../tests/fixtures/nan5180/http_lines.ndjson");

const WALK: &str = "for_each(keys(flatten(";

/// The gate's regex, without the VRL raw-string quoting.
fn precheck_regex() -> Regex {
    let body = CREDENTIAL_KEY_PRECHECK_VRL
        .strip_prefix("r'")
        .and_then(|s| s.strip_suffix('\''))
        .expect("precheck is a VRL raw string");
    Regex::new(body).expect("precheck regex compiles")
}

/// `src` with every gate forced open: the program as it ran before NAN-5180.
fn open_gate(src: &str) -> String {
    let call = Regex::new(&format!(
        r"match\(encode_json\((?:[^()]|\([^()]*\))*\), {}\)",
        regex::escape(CREDENTIAL_KEY_PRECHECK_VRL)
    ))
    .unwrap();
    let open = call.replace_all(src, "true").into_owned();
    assert_ne!(open, src, "no gate found to open");
    open
}

fn transform(config: &str, name: &str) -> String {
    let parsed: toml::Value = toml::from_str(config).expect("config parses");
    parsed["transforms"][name]["source"]
        .as_str()
        .unwrap_or_else(|| panic!("transform {name} has a VRL source"))
        .to_string()
}

/// Runs `program`; `None` on abort. Returns (event, metadata).
fn run(program: &str, event: &Json, metadata: &Json) -> Option<(Json, Json)> {
    let compiled = compile(program, &vrl::stdlib::all())
        .unwrap_or_else(|d| panic!("VRL compiles: {d:?}\n{program}"))
        .program;
    let mut target = TargetValue {
        value: Value::from(event.clone()),
        metadata: Value::from(metadata.clone()),
        secrets: Secrets::new(),
    };
    match Runtime::new(RuntimeState::default()).resolve(&mut target, &compiled, &TimeZone::Local) {
        Ok(_) => {}
        Err(Terminate::Abort(_)) => return None,
        Err(e) => panic!("VRL runtime: {e:?}"),
    }
    Some((target.value.try_into().unwrap(), target.metadata.try_into().unwrap()))
}

fn lines(fixture: &str) -> Vec<Json> {
    fixture
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("fixture line is JSON"))
        .collect()
}

/// Records that DO carry credential keys, in every shape the walk handles,
/// and near misses the gate must not confuse with one.
fn adversarial() -> Vec<Json> {
    vec![
        json!({"user": "a", "Authorization": "Bearer x"}),
        json!({"http": {"request": {"headers": {"COOKIE": "c=1", "Accept": "*/*"}}}}),
        json!({"a": {"b": {"Proxy-Authorization": {"nested": "object"}}}}),
        json!({"x-api-\u{212A}ey": "kelvin-sign key"}),
        json!({"X-Webhook-Secret": "s", "set-cookie": ["a", "b"]}),
        json!({"records": [{"Authorization": "inside an array"}]}),
        json!({"msg": "{\"cookie\":\"in a string value\"}", "k\"ey": "quote"}),
        json!({"cookies": 1, "authorization_header": 2, "xcookie": 3}),
        json!({"unmapped": {"Cookie": "c"}, "class_uid": 0, "time": 1762164000000i64}),
        json!({"\u{17f}et-cookie": "long s folds to s; downcase does not"}),
    ]
}

#[test]
fn precheck_alternation_is_the_credential_name_list() {
    let alternation = Regex::new(r"\(\?:([^)]*)\)").unwrap();
    let names = &alternation.captures(CREDENTIAL_KEY_PRECHECK_VRL).expect("alternation")[1];
    let mut gate: Vec<&str> = names.split('|').collect();
    let mut want: Vec<&str> = CREDENTIAL_FIELD_NAMES.to_vec();
    gate.sort_unstable();
    want.sort_unstable();
    assert_eq!(gate, want, "gate names drifted from the redaction names");
    for name in CREDENTIAL_FIELD_NAMES {
        assert!(CREDENTIAL_FIELD_REDACTION_VRL.contains(&format!("\"{name}\"")));
    }
}

#[test]
fn every_credential_walk_is_gated() {
    let gated = |src: &str, what: &str| {
        let walks = src.matches(WALK).count();
        let gates = src.matches(CREDENTIAL_KEY_PRECHECK_VRL).count();
        assert!(walks > 0, "{what}: no walk found");
        assert_eq!(walks, gates, "{what}: {walks} walks, {gates} gates");
    };
    gated(CREDENTIAL_FIELD_REDACTION_VRL, "credential_field_redaction_vrl!");
    gated(BASE, "config/vector/00-base.toml");
    gated(OCSF_PREPARE_VRL, "OCSF_PREPARE_VRL");
    gated(&VectorConfigManager::pipeline_config_content(), "pipeline");
    assert_eq!(BASE.matches(WALK).count(), 3, "parse_content (x2), json_batch_normalize");
}

/// Every key the walk removes is `"<key>":` in `encode_json` text, where
/// `downcase(key)` is a credential name. Try every Unicode scalar that
/// downcases to each letter of each name, at each position.
#[test]
fn precheck_matches_every_spelling_the_walk_removes() {
    let re = precheck_regex();
    let mut spellings: std::collections::BTreeMap<char, Vec<char>> = Default::default();
    for c in (0u32..=0x10FFFF).filter_map(char::from_u32) {
        let lower: String = c.to_lowercase().collect();
        let mut it = lower.chars();
        if let (Some(l), None) = (it.next(), it.next()) {
            if l.is_ascii() {
                spellings.entry(l).or_default().push(c);
            }
        }
    }
    let mut checked = 0;
    for name in CREDENTIAL_FIELD_NAMES {
        let chars: Vec<char> = name.chars().collect();
        for (i, base) in chars.iter().enumerate() {
            for alt in &spellings[base] {
                let mut key = chars.clone();
                key[i] = *alt;
                let key: String = key.into_iter().collect();
                assert_eq!(key.to_lowercase(), *name);
                for doc in [json!({ key.clone(): 1 }), json!({"a": [{"b": { key.clone(): {"c": 1} }}]})] {
                    let text = serde_json::to_string(&doc).unwrap();
                    assert!(re.is_match(&text), "gate misses {key:?} in {text}");
                    checked += 1;
                }
            }
        }
        let upper = name.to_uppercase();
        assert!(re.is_match(&serde_json::to_string(&json!({ upper: 1 })).unwrap()));
    }
    assert!(checked > 100, "{checked}");
    // VRL's own encode_json agrees with serde_json on key spelling.
    let program = format!(".t = encode_json({{\"x-api-{}ey\": 1}})", '\u{212A}');
    let (out, _) = run(&program, &json!({}), &json!({})).unwrap();
    assert!(re.is_match(out["t"].as_str().unwrap()), "{out}");
}

#[test]
fn redaction_macro_output_unchanged() {
    let gated = CREDENTIAL_FIELD_REDACTION_VRL.to_string();
    let open = open_gate(&gated);
    let mut events: Vec<Json> = lines(PREPARE_INPUTS).into_iter().map(|r| r["event"].clone()).collect();
    events.extend(adversarial());
    let mut removed = 0;
    for event in &events {
        let a = run(&gated, event, &json!({})).unwrap();
        let b = run(&open, event, &json!({})).unwrap();
        assert_eq!(a, b, "gate changed the redaction of {event}");
        removed += usize::from(a.0 != *event);
    }
    assert!(removed >= 6, "the adversarial records must exercise the walk ({removed})");
}

/// The full `_ocsf_prepare` row (what reaches `ocsf_logs_raw`) is unchanged
/// for every parser in the golden corpus.
#[test]
fn ocsf_prepare_rows_unchanged_on_golden_corpus() {
    let open = open_gate(OCSF_PREPARE_VRL);
    let mut records = lines(PREPARE_INPUTS);
    let parsers: std::collections::BTreeSet<String> =
        records.iter().map(|r| r["parser"].as_str().unwrap().to_string()).collect();
    assert_eq!(parsers.len(), 16, "{parsers:?}");
    let meta = json!({"source_type": "adversarial", "nano_ingest_client_ip": "192.0.2.1"});
    records.extend(adversarial().into_iter().map(|e| json!({"event": e, "metadata": meta})));
    for r in &records {
        let (a, am) = run(OCSF_PREPARE_VRL, &r["event"], &r["metadata"]).unwrap();
        let (b, bm) = run(&open, &r["event"], &r["metadata"]).unwrap();
        let (a, b) = (without_clock(a, &r["event"]), without_clock(b, &r["event"]));
        assert_eq!(a, b, "{}: prepared row changed", r["parser"]);
        assert_eq!(am, bm, "{}: metadata changed", r["parser"]);
    }
}

/// `timestamp` falls back to `now()` when the record has no usable `time`;
/// two runs may straddle a millisecond, so compare it only when it is derived.
fn without_clock(mut row: Json, input: &Json) -> Json {
    if input["time"].as_i64().unwrap_or(0) <= 0 {
        row.as_object_mut().unwrap().remove("timestamp");
    }
    row
}

/// `parse_content` and `json_batch_normalize` (00-base.toml) on every HTTP
/// body shape: each sample line as text, JSON and NDJSON, and as a batch member.
#[test]
fn http_ingest_redaction_unchanged() {
    let parse = transform(BASE, "parse_content");
    let normalize = transform(BASE, "json_batch_normalize");
    let (parse_open, normalize_open) = (open_gate(&parse), open_gate(&normalize));
    let mut bodies: Vec<String> =
        lines(HTTP_LINES).iter().map(|r| r["line"].as_str().unwrap().to_string()).collect();
    bodies.extend(adversarial().iter().map(|e| e.to_string()));
    let mut redacted = 0;
    for body in &bodies {
        for ct in ["text/plain", "application/json", "application/x-ndjson", ""] {
            let event = json!({
                "message": body, "Content-Type": ct, "source_type": "unknown",
                "request_path": "/", "client_ip": "192.0.2.1", "auth_status": "authenticated"
            });
            let meta = json!({"nano_ingest_client_ip": "192.0.2.1", "nano_ingest_peer": "192.0.2.1"});
            let a = run(&parse, &event, &meta).unwrap();
            let b = run(&parse_open, &event, &meta).unwrap();
            assert_eq!(a, b, "parse_content changed for {ct} {body}");
            redacted += usize::from(a.0["message"] != json!(body));
        }
        if let Ok(parsed @ Json::Object(_)) = serde_json::from_str::<Json>(body) {
            let event = json!({"nano_json_batch": parsed, "source_type": "unknown"});
            let meta = json!({"nano_json_batch_member": true});
            let a = run(&normalize, &event, &meta).unwrap();
            let b = run(&normalize_open, &event, &meta).unwrap();
            assert_eq!(a, b, "json_batch_normalize changed for {body}");
        }
    }
    assert!(redacted > 0, "the adversarial bodies must exercise the message rewrite");
}
