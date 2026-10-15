//! Shadow-run uid check: run a first-party parser's `parser_vrl` over the
//! events a connector shipped and report each event's `metadata.uid`.
//!
//! The lake dedupes on the parser's `metadata.uid` and drops a later row
//! that reuses an earlier uid, so a collector is only safe to re-read when
//! its parser derives the uid from the vendor's own identity. The harness
//! parses every event twice and fails when a uid differs between the passes
//! (a random uid) or when two distinct events share one.
//!
//! Dev and CI only. Parsers are first-party content, so this runs them with
//! the full VRL stdlib, in process, which the connector sandbox never does.

use std::collections::BTreeMap;

use serde_json::{Value, json};

/// Compile `parser_vrl` from a parser.yaml.
pub fn compile_parser(parser_yaml: &str) -> Result<vrl::compiler::Program, String> {
    let doc: serde_yaml::Value = serde_yaml::from_str(parser_yaml).map_err(|e| format!("parser.yaml: {e}"))?;
    let src = doc.get("parser_vrl").and_then(|v| v.as_str()).ok_or("parser.yaml has no parser_vrl")?;
    vrl::compiler::compile(src, &vrl::stdlib::all())
        .map(|r| r.program)
        .map_err(|d| d.into_iter().map(|d| vrl::diagnostic::Formatter::new(src, d).to_string()).collect::<Vec<_>>().join("\n"))
}

/// Parse one raw event the way ingest delivers it: the vendor JSON as
/// `.message`, plus `.source_type`.
pub fn parse_event(program: &vrl::compiler::Program, source_type: &str, event: &Value) -> Result<Value, String> {
    use vrl::compiler::TargetValue;
    use vrl::value::{Secrets, Value as V};
    let input = json!({ "message": event.to_string(), "source_type": source_type });
    let mut target = TargetValue {
        value: V::from(input),
        metadata: V::Object(BTreeMap::from([("source_type".into(), V::from(source_type))])),
        secrets: Secrets::default(),
    };
    let mut rt = vrl::compiler::runtime::Runtime::default();
    rt.resolve(&mut target, program, &vrl::compiler::TimeZone::parse("UTC").unwrap_or_default())
        .map_err(|e| e.to_string())?;
    let json: Result<Value, _> = target.value.try_into();
    json.map_err(|e| e.to_string())
}

/// Check uids for `batches` (`[[source_type, [events]]]`). Returns a report;
/// `ok` is false on any parse failure, missing uid, unstable uid or collision.
pub fn check_uids(program: &vrl::compiler::Program, batches: &[(String, Vec<Value>)]) -> Value {
    let mut by_uid: BTreeMap<String, String> = BTreeMap::new();
    let (mut events, mut failures) = (0usize, Vec::<Value>::new());
    for (st, evs) in batches {
        for e in evs {
            events += 1;
            // The engine's stamp is not vendor content; ingest strips it.
            let mut raw = e.clone();
            if let Some(o) = raw.as_object_mut() {
                o.remove(crate::engine::INGEST_ID_FIELD);
            }
            let uid = |r: Result<Value, String>| -> Result<String, String> {
                let v = r?;
                v.pointer("/metadata/uid").and_then(Value::as_str).map(str::to_string).ok_or_else(|| "no metadata.uid".into())
            };
            let (a, b) = (uid(parse_event(program, st, &raw)), uid(parse_event(program, st, &raw)));
            match (a, b) {
                (Ok(a), Ok(b)) if a != b => failures.push(json!({ "source_type": st, "error": "unstable uid (differs between two parses)", "uid": a })),
                (Ok(a), Ok(_)) => {
                    let canon = raw.to_string();
                    match by_uid.get(&a) {
                        Some(prev) if *prev != canon => failures.push(json!({ "source_type": st, "error": "two distinct events share a uid", "uid": a })),
                        _ => {
                            by_uid.insert(a, canon);
                        }
                    }
                }
                (Err(e), _) | (_, Err(e)) => failures.push(json!({ "source_type": st, "error": e })),
            }
        }
    }
    json!({
        "ok": failures.is_empty(),
        "events": events,
        "distinct_uids": by_uid.len(),
        "failures": failures.into_iter().take(20).collect::<Vec<_>>(),
    })
}
