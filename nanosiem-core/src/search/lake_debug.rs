// SPDX-License-Identifier: AGPL-3.0-or-later

//! Opt-in per-request search evidence (NAN-3077).
//!
//! A search handler that was asked for debug evidence (and whose caller may
//! see it) runs the search inside [`collect`]. Every query[T] call made by
//! that request, the rows query and each histogram / rollup companion, then
//! records one compact entry: the route, the request-id suffix, the
//! round-trip time this process observed, and query[T]'s own `planner`
//! evidence (`phases_s`, file / row-group / token-count counters) and
//! engine timings. Service-side phases (admission wait) are recorded too.
//!
//! Nothing here is collected unless the task-local is installed, so ordinary
//! requests pay one failed task-local lookup per lake call. The entries carry
//! counts and timings, plus opt-in redacted native SQL/settings and selected object keys.
//! No rows, parameter values or credentials are collected.

use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Bound on the entries one request may collect (an adaptive histogram can
/// split into many calls; the evidence stays small).
const MAX_ENTRIES: usize = 256;

#[derive(Default)]
pub struct LakeDebug {
    started: Option<Instant>,
    entries: Mutex<Vec<Value>>,
    /// NAN-3406: this request's canonical [`PERF_OVERRIDES_HEADER`] value,
    /// forwarded on its query[T] calls. Only a debug-authorized request has
    /// a collector at all, so only it can carry overrides.
    perf_overrides: Option<String>,
}

/// NAN-3406: per-request A/B overrides of query[T]'s speed switches
/// (`flat_filter_leaves`, `lane_routing_v2`, `identity_merged_index`,
/// NAN-4190's `entity_index`, and
/// NAN-3411's numeric `payload_threads` / `payload_block_rows`; see
/// `nanosiem_lake_worker::perf_overrides`). Honoured only for a request that
/// already gets debug evidence (`x-nano-search-debug: 1` with `search:sql`).
pub const PERF_OVERRIDES_HEADER: &str = "x-nano-perf-overrides";

/// Per-request switches query[T] applies.
const PERF_SWITCHES: &[&str] = &["flat_filter_leaves", "lane_routing_v2", "identity_merged_index", "entity_index"];
/// NAN-3411: numeric per-request knobs query[T] applies (and clamps):
/// the full-event payload statement's reader threads and block rows.
const PERF_NUMERIC: &[&str] = &["payload_block_rows", "payload_threads"];
/// Longest numeric value forwarded (query[T] clamps far below it).
const PERF_NUMERIC_MAX_DIGITS: usize = 6;
/// Process-level switches: forwarded only so query[T]'s evidence says they
/// were ignored.
const PERF_PROCESS_LEVEL: &[&str] =
    &["prewarm_throttle", "prewarm_min_interval_seconds", "dns_refresh", "large_lane_split", "identity_merged_build"];
/// Longest accepted header value.
const PERF_OVERRIDES_MAX_BYTES: usize = 512;

/// The canonical form of a [`PERF_OVERRIDES_HEADER`] value: known names only
/// (lowercase, last value wins), each switch `=0` or `=1` and each numeric
/// knob a positive decimal (NAN-3411), sorted. `None` when nothing valid
/// remains. Nothing the caller typed is forwarded verbatim.
pub fn canonical_perf_overrides(text: &str) -> Option<String> {
    if text.len() > PERF_OVERRIDES_MAX_BYTES {
        return None;
    }
    let mut chosen = std::collections::BTreeMap::new();
    for entry in text.split(',') {
        let Some((name, value)) = entry.split_once('=') else { continue };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim().to_ascii_lowercase();
        if let Some(name) = PERF_NUMERIC.iter().find(|known| **known == name) {
            let number = (value.len() <= PERF_NUMERIC_MAX_DIGITS && value.bytes().all(|b| b.is_ascii_digit()))
                .then(|| value.parse::<u64>().ok())
                .flatten()
                .filter(|number| *number > 0);
            if let Some(number) = number {
                chosen.insert(*name, number.to_string());
            }
            continue;
        }
        let Some(name) = PERF_SWITCHES.iter().chain(PERF_PROCESS_LEVEL).find(|known| **known == name) else { continue };
        let value = match value.as_str() {
            "1" | "on" | "true" => "1",
            "0" | "off" | "false" => "0",
            _ => continue,
        };
        chosen.insert(*name, value.to_string());
    }
    (!chosen.is_empty()).then(|| chosen.iter().map(|(name, value)| format!("{name}={value}")).collect::<Vec<_>>().join(","))
}

/// This request's canonical overrides (none outside a debug collector).
pub fn perf_overrides() -> Option<String> {
    LAKE_DEBUG.try_with(|debug| debug.perf_overrides.clone()).ok().flatten()
}

/// Add the debug headers query[T] reads to one of this request's lake calls:
/// with overrides, [`PERF_OVERRIDES_HEADER`] and `x-nano-search-debug: 1`
/// (query[T] honours an override only beside it); without, `debug_too`
/// adds the debug header alone (the rows query's existing behaviour).
/// Outside a debug collector the builder is unchanged.
pub(crate) fn lake_call_headers(builder: reqwest::RequestBuilder, debug_too: bool) -> reqwest::RequestBuilder {
    if !enabled() {
        return builder;
    }
    match perf_overrides() {
        Some(overrides) => builder.header(PERF_OVERRIDES_HEADER, overrides).header("x-nano-search-debug", "1"),
        None if debug_too => builder.header("x-nano-search-debug", "1"),
        None => builder,
    }
}

tokio::task_local! {
    static LAKE_DEBUG: Arc<LakeDebug>;
}

/// Run `future` collecting lake evidence; returns its output and the
/// evidence document.
pub async fn collect<F: Future>(future: F) -> (F::Output, Value) {
    collect_with_perf_overrides(None, future).await
}

/// [`collect`] for a request whose (authorized) caller asked for
/// `perf_overrides` (a [`canonical_perf_overrides`] value). A nested call
/// keeps the outer collector's overrides.
pub async fn collect_with_perf_overrides<F: Future>(perf_overrides: Option<String>, future: F) -> (F::Output, Value) {
    // Already collecting (the route-wide middleware): record into that
    // collector and report what it holds so far.
    if let Some(debug) = current() {
        let output = future.await;
        return (output, document(&debug));
    }
    let perf_overrides = perf_overrides.as_deref().and_then(canonical_perf_overrides);
    let debug = Arc::new(LakeDebug { started: Some(Instant::now()), entries: Mutex::default(), perf_overrides });
    let output = LAKE_DEBUG.scope(debug.clone(), future).await;
    (output, document(&debug))
}

fn document(debug: &LakeDebug) -> Value {
    let entries = debug.entries.lock().map(|entries| entries.clone()).unwrap_or_default();
    // NAN-3406: what this request asked query[T] for; each lake call's
    // `planner.perf_switches` says what query[T] ran with (env vs override).
    json!({ "schema": 1, "perf_overrides": debug.perf_overrides, "lake_calls": entries })
}

/// The evidence as a response-header value (NAN-3077 route-wide debug):
/// compact JSON, at most `max_bytes`; past it the per-call entries are
/// replaced by their count and the summed round trip.
pub fn header_value(mut evidence: Value, max_bytes: usize) -> String {
    let text = evidence.to_string();
    if text.len() <= max_bytes {
        return text;
    }
    let calls = evidence["lake_calls"].as_array().cloned().unwrap_or_default();
    let round_trip: f64 = calls.iter().filter_map(|call| call["round_trip_ms"].as_f64()).sum();
    let worker: f64 = calls.iter().filter_map(|call| call["worker_wall_s"].as_f64()).sum();
    evidence["lake_calls"] = json!({ "count": calls.len(), "round_trip_ms_sum": round_trip, "worker_wall_s_sum": worker, "truncated": true });
    evidence.to_string()
}

/// The active collector, for carrying across a `tokio::spawn`.
pub(crate) fn current() -> Option<Arc<LakeDebug>> {
    LAKE_DEBUG.try_with(Arc::clone).ok()
}

/// Run `future` under `debug` (the spawned half of [`current`]).
pub(crate) async fn scoped<F: Future>(debug: Arc<LakeDebug>, future: F) -> F::Output {
    LAKE_DEBUG.scope(debug, future).await
}

/// Whether this request collects evidence.
pub fn enabled() -> bool {
    LAKE_DEBUG.try_with(|_| ()).is_ok()
}

fn push(entry: Value) {
    let _ = LAKE_DEBUG.try_with(|debug| {
        let Ok(mut entries) = debug.entries.lock() else { return };
        if entries.len() < MAX_ENTRIES {
            let mut entry = entry;
            if let (Some(started), Some(object)) = (debug.started, entry.as_object_mut()) {
                object.insert("at_ms".to_string(), json!(started.elapsed().as_secs_f64() * 1_000.0));
            }
            entries.push(entry);
        }
    });
}

/// A service-side phase (e.g. the admission wait).
pub fn phase(name: &str, elapsed: std::time::Duration) {
    if enabled() {
        push(json!({ "phase": name, "ms": elapsed.as_secs_f64() * 1_000.0 }));
    }
}

/// The histogram companion suffix of a request id (`-hist`, `-hist-rollup`,
/// `-hist-rl`, …), so an entry says which call it was without echoing the id.
/// Empty for the rows query.
fn companion(request_id: &str) -> &str {
    request_id
        .rfind("-hist")
        .map(|at| &request_id[at..])
        .filter(|suffix| suffix.len() <= 32)
        .unwrap_or("")
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    ok: Option<bool>,
    #[serde(default)]
    error_code: Option<String>,
    #[serde(default)]
    wall_seconds: Option<f64>,
    #[serde(default)]
    planner: Option<Value>,
    #[serde(default)]
    result: Option<EnvelopeResult>,
}

#[derive(Deserialize)]
struct EnvelopeResult {
    #[serde(default)]
    result_rows: Option<u64>,
    #[serde(default)]
    engine_seconds: Option<f64>,
    #[serde(default)]
    storage_rows: Option<u64>,
    #[serde(default)]
    storage_bytes: Option<u64>,
    #[serde(default)]
    query_result_cache_hit: Option<bool>,
    #[serde(default)]
    page_has_more: Option<bool>,
}

/// Keep only numbers, booleans and short strings (phase names), recursively:
/// the planner document is counters and timings, and nothing else leaves.
fn numeric_only(value: &Value) -> Option<Value> {
    match value {
        Value::Number(_) | Value::Bool(_) | Value::Null => Some(value.clone()),
        Value::String(text) if text.len() <= 32 && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') => {
            Some(value.clone())
        }
        Value::Array(items) => Some(Value::Array(items.iter().filter_map(numeric_only).collect())),
        Value::Object(object) => Some(Value::Object(
            object
                .iter()
                .filter_map(|(key, value)| numeric_only(value).map(|value| (key.clone(), value)))
                .collect::<Map<_, _>>(),
        )),
        Value::String(_) => None,
    }
}

/// Record one query[T] response (`body` as received) for `route`.
pub(crate) fn record_response(route: &str, request_id: &str, started: Instant, status: u16, body: &[u8]) {
    if !enabled() {
        return;
    }
    let round_trip_ms = started.elapsed().as_secs_f64() * 1_000.0;
    let envelope = serde_json::from_slice::<Envelope>(body).ok();
    let mut entry = json!({
        "route": route,
        "companion": companion(request_id),
        "status": status,
        "round_trip_ms": round_trip_ms,
        "response_bytes": body.len(),
    });
    if let (Some(envelope), Some(object)) = (envelope, entry.as_object_mut()) {
        object.insert("ok".to_string(), json!(envelope.ok));
        if let Some(code) = envelope.error_code.filter(|code| code.len() <= 64) {
            object.insert("error_code".to_string(), json!(code));
        }
        object.insert("worker_wall_s".to_string(), json!(envelope.wall_seconds));
        if let Some(result) = envelope.result {
            object.insert(
                "result".to_string(),
                json!({
                    "rows": result.result_rows,
                    "engine_s": result.engine_seconds,
                    "storage_rows": result.storage_rows,
                    "storage_bytes": result.storage_bytes,
                    "result_cache_hit": result.query_result_cache_hit,
                    "page_has_more": result.page_has_more,
                }),
            );
        }
        if let Some(raw) = envelope.planner.as_ref() {
            let mut planner = numeric_only(raw).unwrap_or_else(|| json!({}));
            if let Some(debug) = raw.get("native_debug") {
                // Produced only by the authenticated cell query path; SQL is
                // redacted there and parameters are never included.
                planner["native_debug"] = debug.clone();
            }
            object.insert("planner".to_string(), planner);
        }
    }
    push(entry);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_only_inside_collect_and_strips_non_numeric_evidence() {
        record_response("broad_npl", "x", Instant::now(), 200, b"{}");
        assert!(!enabled());
        let body = serde_json::to_vec(&json!({
            "ok": true, "wall_seconds": 0.5,
            "planner": {"time_files": 12, "phases_s": [{"phase": "select", "s": 0.1}],
                        "secret_path": "s3://bucket/key?X-Amz-Signature=abc"},
            "result": {"result_rows": 3, "engine_seconds": 0.2, "rows": [{"message": "hello"}]},
        }))
        .unwrap();
        let ((), evidence) = collect(async {
            record_response("broad_npl", "0192d2a0-0000-7000-8000-000000000000-hist", Instant::now(), 200, &body);
            phase("admission", std::time::Duration::from_millis(3));
        })
        .await;
        let calls = evidence["lake_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0]["companion"], "-hist");
        assert_eq!(calls[0]["planner"]["time_files"], 12);
        assert_eq!(calls[0]["planner"]["phases_s"][0]["phase"], "select");
        assert!(calls[0]["planner"].get("secret_path").is_none());
        assert_eq!(calls[0]["result"]["rows"], 3);
        assert!(!serde_json::to_string(&evidence).unwrap().contains("hello"));
        assert_eq!(calls[1]["phase"], "admission");
    }

    #[tokio::test]
    async fn preserves_native_diagnostics_only_in_debug_collection() {
        let native = json!({"files":[{"key":"s3://bucket/h/data-00000.parquet","tier":"h","bytes":123}],
            "statements":[{"sql":"SELECT {filter:String}","native_settings":{"max_threads":2},"storage_rows":10,"storage_bytes":20}]});
        let body = serde_json::to_vec(&json!({"planner":{"native_debug":native, "secret_path":"secret://value"}})).unwrap();
        let (_, evidence) = collect(async { record_response("broad_npl", "x", Instant::now(), 200, &body); }).await;
        assert_eq!(evidence["lake_calls"][0]["planner"]["native_debug"], native);
        assert!(evidence["lake_calls"][0]["planner"].get("secret_path").is_none());
        assert!(!enabled());
    }

    #[tokio::test]
    async fn nested_collect_records_into_the_outer_collector() {
        let (inner, outer) = collect(async {
            phase("outer", std::time::Duration::ZERO);
            collect(async { phase("inner", std::time::Duration::ZERO) }).await.1
        })
        .await;
        assert_eq!(inner["lake_calls"].as_array().unwrap().len(), 2);
        assert_eq!(outer["lake_calls"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn header_value_stays_bounded() {
        let calls = (0..500).map(|i| json!({"route": "broad_npl", "round_trip_ms": 1.0, "worker_wall_s": 0.5, "n": i})).collect::<Vec<_>>();
        let text = header_value(json!({"schema": 1, "lake_calls": calls}), 4096);
        assert!(text.len() <= 4096);
        let parsed: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed["lake_calls"]["count"], 500);
        assert!(text.is_ascii());
    }

    #[test]
    fn perf_overrides_are_canonicalized_to_known_switches() {
        assert_eq!(
            canonical_perf_overrides(" lane_routing_v2=off,FLAT_FILTER_LEAVES=1, bogus=1, identity_merged_index=maybe,prewarm_throttle=0").as_deref(),
            Some("flat_filter_leaves=1,lane_routing_v2=0,prewarm_throttle=0")
        );
        assert_eq!(canonical_perf_overrides("flat_filter_leaves=0,flat_filter_leaves=1").as_deref(), Some("flat_filter_leaves=1"));
        // NAN-4211: the window entity index A/B (query[T] reads it per lookup).
        assert_eq!(canonical_perf_overrides("entity_index=off").as_deref(), Some("entity_index=0"));
        assert_eq!(canonical_perf_overrides("x=1\r\nx-evil: 1"), None);
        assert_eq!(canonical_perf_overrides(""), None);
        assert_eq!(canonical_perf_overrides(&format!("flat_filter_leaves=1,{}", " ".repeat(PERF_OVERRIDES_MAX_BYTES))), None);
    }

    /// NAN-3411: numeric payload knobs forward as canonical positive decimals.
    #[test]
    fn perf_overrides_canonicalize_numeric_payload_knobs() {
        assert_eq!(
            canonical_perf_overrides("PAYLOAD_THREADS= 004 ,payload_block_rows=1024,flat_filter_leaves=1").as_deref(),
            Some("flat_filter_leaves=1,payload_block_rows=1024,payload_threads=4")
        );
        for bad in ["payload_threads=0", "payload_threads=-1", "payload_threads=on", "payload_threads=1e3", "payload_threads=1234567"] {
            assert_eq!(canonical_perf_overrides(bad), None, "{bad}");
        }
        assert_eq!(canonical_perf_overrides("payload_threads=2,payload_threads=3").as_deref(), Some("payload_threads=3"));
    }

    /// Outside a debug collector nothing is forwarded; inside one, the
    /// canonical overrides ride beside the debug header.
    #[tokio::test]
    async fn perf_overrides_are_forwarded_only_from_a_debug_collector() {
        let client = reqwest::Client::new();
        let plain = lake_call_headers(client.post("http://cell/v1/query"), true).build().unwrap();
        assert!(plain.headers().get(PERF_OVERRIDES_HEADER).is_none());
        assert!(plain.headers().get("x-nano-search-debug").is_none());
        assert_eq!(perf_overrides(), None);
        let ((), evidence) = collect_with_perf_overrides(Some("lane_routing_v2=0,flat_filter_leaves=on".into()), async {
            let call = lake_call_headers(client.post("http://cell/v1/identity/resolve"), false).build().unwrap();
            assert_eq!(call.headers().get(PERF_OVERRIDES_HEADER).unwrap(), "flat_filter_leaves=1,lane_routing_v2=0");
            assert_eq!(call.headers().get("x-nano-search-debug").unwrap(), "1");
            // A nested collect keeps the outer request's overrides.
            let ((), _) = collect(async {
                assert_eq!(perf_overrides().as_deref(), Some("flat_filter_leaves=1,lane_routing_v2=0"));
            }).await;
        })
        .await;
        assert_eq!(evidence["perf_overrides"], "flat_filter_leaves=1,lane_routing_v2=0");
        // A debug request without overrides: unchanged headers (debug only where asked).
        let ((), evidence) = collect(async {
            let rows = lake_call_headers(client.post("http://cell/v1/query"), true).build().unwrap();
            assert_eq!(rows.headers().get("x-nano-search-debug").unwrap(), "1");
            assert!(rows.headers().get(PERF_OVERRIDES_HEADER).is_none());
            let other = lake_call_headers(client.post("http://cell/v1/entity/ranges"), false).build().unwrap();
            assert!(other.headers().is_empty());
        })
        .await;
        assert!(evidence["perf_overrides"].is_null());
    }

    #[tokio::test]
    async fn carries_across_spawn_only_when_scoped() {
        let ((), evidence) = collect(async {
            let debug = current().unwrap();
            tokio::spawn(scoped(debug, async { phase("spawned", std::time::Duration::ZERO) })).await.unwrap();
            tokio::spawn(async { phase("bare", std::time::Duration::ZERO) }).await.unwrap();
        })
        .await;
        let calls = evidence["lake_calls"].as_array().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0]["phase"], "spawned");
    }
}
