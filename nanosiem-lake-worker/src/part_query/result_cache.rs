// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact `broad_npl` result reuse over immutable parts.
//!
//! A `logs` answer is a function of the request (query, window, page,
//! cursor, deny set), the verified parts that overlap its window, and the
//! read schema the compiler typed it against (enrichment is fixed at ingest,
//! NAN-4168). Parts never change after they are added: a merge, late data,
//! retention or an erasure retires parts and adds new ones, which changes the
//! overlapping set. So an answer keyed on all three is the answer a fresh run
//! would compute, without the gen1 serving-generation pin the search result
//! cache requires (lean cells have none, so that cache never admitted them).
//!
//! Bounds: entries live [`TTL`], an entry is at most [`MAX_ENTRY_BYTES`] of JSON,
//! and the cache holds at most [`MAX_TOTAL_BYTES`].
//!
//! NAN-3809: a *settled* answer lives [`SETTLED_TTL`]. Settled means the
//! window ends at least the platform's late-arrival grace before now
//! ([`nanosiem_core::search::settled_reuse`]), the query reads nothing but
//! the window's events, and the answer is complete and non-empty. The key is
//! unchanged, so a late part, a merge, an erasure, a schema change, a new
//! query image or a different deny set still misses. Enrichment is fixed at
//! ingest (NAN-4168), so no enrichment authority is part of the key.

use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use super::engine::BroadNplRequest;
use crate::parts::part_log::PartRef;

pub const TTL: Duration = Duration::from_secs(60);
/// NAN-3809: how long a settled answer is kept (see the module docs).
pub const SETTLED_TTL: Duration = Duration::from_secs(30 * 60);

/// A query whose text calls a clock or random function is not a function of
/// its parts alone, so it is never cached.
pub fn cacheable(request: &BroadNplRequest) -> bool {
    static VOLATILE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let volatile = VOLATILE.get_or_init(|| {
        regex::Regex::new(r"(?i)\b(now|today|yesterday|relative_time|time|random|rand|randomize|uuid|generateuuidv4)\s*\(")
            .expect("static regex")
    });
    // NAN-3406: a request with a perf override never reads or writes a
    // result (or fragment) cache: one A/B mode must not answer the other.
    request.use_cache && request.dataset == "logs" && !volatile.is_match(&request.query)
        && !crate::perf_overrides::active()
}
pub const MAX_ENTRY_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_TOTAL_BYTES: usize = 64 * 1024 * 1024;

struct Entry {
    key: [u8; 32],
    stored: Instant,
    ttl: Duration,
    bytes: usize,
    value: Value,
}

#[derive(Default)]
pub struct ResultCache {
    entries: Mutex<VecDeque<Entry>>,
}

/// The cache identity of one request over one part set.
pub fn key(
    request: &BroadNplRequest,
    parts: &[PartRef],
    schema_fingerprint: Option<&str>,
    execution_identity: &str,
) -> [u8; 32] {
    let mut identity = request.clone();
    identity.request_id = String::new();
    let mut hasher = Sha256::new();
    hasher.update(b"nano.part-query-result.v3\0");
    hasher.update(serde_json::to_vec(&identity).expect("request serializes"));
    hasher.update(b"\0schema\0");
    hasher.update(schema_fingerprint.unwrap_or("-").as_bytes());
    hasher.update(b"\0execution\0");
    hasher.update(execution_identity.as_bytes());
    let mut parts = parts.iter().map(|part| (part.part_id.to_string(), &part.provenance_sha256, &part.merkle_root)).collect::<Vec<_>>();
    parts.sort();
    for (id, provenance, merkle) in parts {
        hasher.update(b"\0part\0");
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
        hasher.update(provenance.as_bytes());
        hasher.update(b"\0");
        hasher.update(merkle.as_bytes());
    }
    hasher.finalize().into()
}

/// NAN-3809: the data identity of a window, independent of any one request:
/// the overlapping parts, the read schema and the query artifacts. A durable job records it next to its result pages;
/// the job is re-served only while the current identity is the same.
pub fn window_identity(parts: &[PartRef], schema_fingerprint: Option<&str>, execution_identity: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"nano.part-query-window.v2\0schema\0");
    hasher.update(schema_fingerprint.unwrap_or("-").as_bytes());
    hasher.update(b"\0execution\0");
    hasher.update(execution_identity.as_bytes());
    let mut parts = parts.iter().map(|part| (part.part_id.to_string(), &part.provenance_sha256, &part.merkle_root)).collect::<Vec<_>>();
    parts.sort();
    for (id, provenance, merkle) in parts {
        hasher.update(b"\0part\0");
        hasher.update(id.as_bytes());
        hasher.update(b"\0");
        hasher.update(provenance.as_bytes());
        hasher.update(b"\0");
        hasher.update(merkle.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// NAN-3809: whether `answer` to `request` may be kept for [`SETTLED_TTL`]:
/// a settled absolute window, a query over events only, and a complete,
/// non-empty answer (no byte-cut page, no completeness envelope).
pub fn settled_answer(request: &BroadNplRequest, window_end_us: i64, answer: &Value, now: chrono::DateTime<chrono::Utc>) -> bool {
    use nanosiem_core::search::settled_reuse::{is_settled_end_us, query_allows_settled_reuse};
    let result = &answer["result"];
    is_settled_end_us(window_end_us, now)
        && query_allows_settled_reuse(&request.query)
        && request.cursor_time.is_none()
        && answer["ok"] == Value::Bool(true)
        && answer.get("completeness").is_none_or(Value::is_null)
        && result["result_rows"].as_u64().is_some_and(|rows| rows > 0)
        && result["page_byte_cut"] != Value::Bool(true)
}

impl ResultCache {
    /// A stored answer, re-bound to this request id.
    pub fn get(&self, key: &[u8; 32], request_id: &str) -> Option<Value> {
        self.get_at(key, request_id, Instant::now())
    }

    fn get_at(&self, key: &[u8; 32], request_id: &str, now: Instant) -> Option<Value> {
        let mut entries = self.entries.lock().ok()?;
        entries.retain(|entry| now.saturating_duration_since(entry.stored) < entry.ttl);
        let mut value = entries.iter().find(|entry| &entry.key == key)?.value.clone();
        value["request_id"] = Value::from(request_id);
        value["wall_seconds"] = Value::from(0.0);
        if let Some(result) = value.get_mut("result").and_then(Value::as_object_mut) {
            result.insert("query_result_cache_hit".into(), Value::Bool(true));
            result.insert("wall_seconds".into(), Value::from(0.0));
        }
        Some(value)
    }

    pub fn insert(&self, key: [u8; 32], value: &Value) {
        self.insert_at(key, value, TTL, Instant::now());
    }

    /// NAN-3809: store an answer [`settled_answer`] admitted.
    pub fn insert_settled(&self, key: [u8; 32], value: &Value) {
        self.insert_at(key, value, SETTLED_TTL, Instant::now());
    }

    fn insert_at(&self, key: [u8; 32], value: &Value, ttl: Duration, now: Instant) {
        let Ok(bytes) = serde_json::to_vec(value).map(|bytes| bytes.len()) else { return };
        if bytes > MAX_ENTRY_BYTES {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else { return };
        entries.retain(|entry| entry.key != key && now.saturating_duration_since(entry.stored) < entry.ttl);
        entries.push_back(Entry { key, stored: now, ttl, bytes, value: value.clone() });
        let mut total = entries.iter().map(|entry| entry.bytes).sum::<usize>();
        while total > MAX_TOTAL_BYTES {
            let Some(evicted) = entries.pop_front() else { break };
            total -= evicted.bytes;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(query: &str) -> BroadNplRequest {
        serde_json::from_value(json!({
            "request_id": "r1", "tenant_id": "t", "dataset": "logs", "query": query,
            "start": "2026-09-29T00:00:00Z", "end": "2026-09-29T01:00:00Z", "limit": 100, "table_view": true, "use_cache": true,
        }))
        .unwrap()
    }

    #[test]
    fn identity_ignores_request_id_but_binds_everything_else() {
        let a = request("powershell");
        let mut b = a.clone();
        b.request_id = "r2".into();
        assert_eq!(key(&a, &[], Some("s"), "compiler/native/config-v1"), key(&b, &[], Some("s"), "compiler/native/config-v1"));
        assert_ne!(key(&a, &[], Some("s"), "compiler/native/config-v1"), key(&request("cmd"), &[], Some("s"), "compiler/native/config-v1"));
        assert_ne!(key(&a, &[], Some("s"), "compiler/native/config-v1"), key(&a, &[], Some("s2"), "compiler/native/config-v1"));
        assert_ne!(key(&a, &[], Some("s"), "compiler-v1"), key(&a, &[], Some("s"), "compiler-v2"));
        let mut other_tenant = a.clone();
        other_tenant.tenant_id = "other-tenant".into();
        assert_ne!(key(&a, &[], Some("s"), "config"), key(&other_tenant, &[], Some("s"), "config"));
        let mut denied = a.clone();
        denied.deny_source_types.insert("windows_sysmon".into());
        assert_ne!(key(&a, &[], Some("s"), "config"), key(&denied, &[], Some("s"), "config"));
        let mut paged = a.clone();
        paged.offset = 100;
        assert_ne!(key(&a, &[], Some("s"), "compiler/native/config-v1"), key(&paged, &[], Some("s"), "compiler/native/config-v1"));
    }

    #[test]
    fn explicit_opt_out_never_reads_or_populates_results() {
        let mut r = request("powershell");
        assert!(cacheable(&r));
        r.use_cache = false;
        assert!(!cacheable(&r));
    }

    /// NAN-3406: a request with any perf override never reads or writes the
    /// result or fragment caches (both gate on `cacheable`), so one A/B
    /// mode's answer is never served to the other; a debug scope without
    /// overrides changes nothing.
    #[test]
    fn perf_overrides_bypass_result_caches() {
        use crate::perf_overrides::{sync_scoped, Overrides};
        let r = request("powershell");
        for overrides in [
            Overrides { flat_filter_leaves: Some(false), ..Overrides::default() },
            Overrides { lane_routing_v2: Some(true), ..Overrides::default() },
            Overrides { identity_merged_index: Some(false), ..Overrides::default() },
        ] {
            assert!(!sync_scoped(overrides, || cacheable(&r)), "{overrides:?}");
        }
        assert!(sync_scoped(Overrides::default(), || cacheable(&r)));
        assert!(cacheable(&r));
    }

    #[test]
    fn clock_and_random_queries_are_never_cached() {
        assert!(cacheable(&request("powershell | stats count by device.hostname")));
        for volatile in ["* | eval age=now()-time", "* | where time > relative_time(now(), \"-1h\")", "* | eval r=random()", "* | eval t=time()"] {
            assert!(!cacheable(&request(volatile)), "{volatile}");
        }
    }

    #[test]
    fn hits_are_rebound_to_the_caller_and_bounded() {
        let cache = ResultCache::default();
        let k = key(&request("x"), &[], None, "compiler/native/config-v1");
        cache.insert(k, &json!({"ok": true, "request_id": "r1", "wall_seconds": 3.0, "result": {"rows": [1], "query_result_cache_hit": false}}));
        let hit = cache.get(&k, "r9").unwrap();
        assert_eq!(hit["request_id"], "r9");
        assert_eq!(hit["result"]["query_result_cache_hit"], true);
        assert_eq!(hit["result"]["rows"], json!([1]));
        assert!(cache.get(&[0; 32], "r9").is_none());
        let huge = json!({"result": {"rows": ["x".repeat(MAX_ENTRY_BYTES)]}});
        let big = key(&request("big"), &[], None, "compiler/native/config-v1");
        cache.insert(big, &huge);
        assert!(cache.get(&big, "r").is_none());
    }

    // ---- NAN-3809: settled reuse ----

    fn part(n: u64) -> PartRef {
        PartRef {
            request_hours: None,
            part_id: crate::parts::format::PartId::parse(&format!("{:013}-{:016x}", 1_000 + n, n)).unwrap(),
            level: crate::parts::levels::Level::L0,
            event_hour: 10,
            event_day: None,
            rows: 5,
            min_time_us: 1,
            max_time_us: 2,
            schema_fingerprint: "a".repeat(64),
            provenance_sha256: "b".repeat(64),
            merkle_root: "c".repeat(64),
            sorted: true,
            data_bytes: 10,
            row_groups: 1,
            data_files: 1,
        }
    }

    fn fresh_answer(rows: usize) -> Value {
        json!({"ok": true, "request_id": "r1", "wall_seconds": 4.2, "result": {
            "result_rows": rows, "rows": (0..rows).collect::<Vec<_>>(), "page_has_more": false,
            "page_byte_cut": false, "query_result_cache_hit": false}})
    }

    fn now_utc() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-09-29T03:00:00Z").unwrap().with_timezone(&chrono::Utc)
    }

    fn end_us(request: &BroadNplRequest) -> i64 {
        chrono::DateTime::parse_from_rfc3339(&request.end).unwrap().timestamp_micros()
    }

    /// Past the plain TTL, inside the settled TTL.
    fn later(at: Instant) -> Instant {
        at + TTL + Duration::from_secs(1)
    }

    #[test]
    fn an_identical_settled_query_hits_with_the_fresh_count() {
        let cache = ResultCache::default();
        let request = request("powershell");
        let parts = [part(1), part(2)];
        let fresh = fresh_answer(3);
        assert!(settled_answer(&request, end_us(&request), &fresh, now_utc()));
        let k = key(&request, &parts, Some("s"), "config");
        let stored = Instant::now();
        cache.insert_at(k, &fresh, SETTLED_TTL, stored);
        let mut again = request.clone();
        again.request_id = "second-tab".into();
        let hit = cache.get_at(&key(&again, &parts, Some("s"), "config"), "second-tab", later(stored)).expect("settled hit");
        assert_eq!(hit["result"]["result_rows"], fresh["result"]["result_rows"]);
        assert_eq!(hit["result"]["rows"], fresh["result"]["rows"]);
        assert_eq!(hit["result"]["query_result_cache_hit"], true);
        assert!(cache.get_at(&k, "late", stored + SETTLED_TTL + Duration::from_secs(1)).is_none(), "settled entries still expire");
    }

    #[test]
    fn a_deny_set_or_generation_change_misses_a_settled_entry() {
        let cache = ResultCache::default();
        let request = request("powershell");
        let parts = [part(1), part(2)];
        let stored = Instant::now();
        cache.insert_at(key(&request, &parts, Some("s"), "config"), &fresh_answer(3), SETTLED_TTL, stored);
        let at = later(stored);
        let mut denied = request.clone();
        denied.deny_source_types.insert("windows_sysmon".into());
        assert!(cache.get_at(&key(&denied, &parts, Some("s"), "config"), "r", at).is_none(), "deny set");
        // A late part, a merge or an erasure changes the overlapping part set.
        assert!(cache.get_at(&key(&request, &[part(1), part(2), part(3)], Some("s"), "config"), "r", at).is_none(), "late part");
        assert!(cache.get_at(&key(&request, &[part(4)], Some("s"), "config"), "r", at).is_none(), "merge");
        assert!(cache.get_at(&key(&request, &parts, Some("s2"), "config"), "r", at).is_none(), "schema");
        assert!(cache.get_at(&key(&request, &parts, Some("s"), "config"), "r", at).is_some());
    }

    #[test]
    fn relative_hot_or_partial_answers_never_get_the_settled_tier() {
        let now = now_utc();
        let settled = request("powershell");
        assert!(settled_answer(&settled, end_us(&settled), &fresh_answer(3), now));
        // A relative "last 1h" ends at about now; a range overlapping the
        // late-arrival window is still settling.
        let mut relative = settled.clone();
        relative.end = now.to_rfc3339();
        assert!(!settled_answer(&relative, now.timestamp_micros(), &fresh_answer(3), now));
        let overlapping = (now - chrono::Duration::seconds(60)).timestamp_micros();
        assert!(!settled_answer(&settled, overlapping, &fresh_answer(3), now));
        // Partial, empty, failed or stateful answers.
        let mut cut = fresh_answer(3);
        cut["result"]["page_byte_cut"] = Value::Bool(true);
        assert!(!settled_answer(&settled, end_us(&settled), &cut, now));
        let mut enveloped = fresh_answer(3);
        enveloped["completeness"] = json!({"status": "partial"});
        assert!(!settled_answer(&settled, end_us(&settled), &enveloped, now));
        assert!(!settled_answer(&settled, end_us(&settled), &fresh_answer(0), now));
        assert!(!settled_answer(&request("* | lookup assets host"), end_us(&settled), &fresh_answer(3), now));
        let mut cursor = settled.clone();
        cursor.cursor_time = Some("2026-09-29T00:30:00Z".into());
        assert!(!settled_answer(&cursor, end_us(&settled), &fresh_answer(3), now));

        // Such answers keep the plain 60 s tier: gone once it passes.
        let cache = ResultCache::default();
        let k = key(&relative, &[part(1)], Some("s"), "config");
        let stored = Instant::now();
        cache.insert_at(k, &fresh_answer(3), TTL, stored);
        assert!(cache.get_at(&k, "r", stored).is_some());
        assert!(cache.get_at(&k, "r", later(stored)).is_none());
    }

    #[test]
    fn window_identity_binds_parts_schema_and_artifacts() {
        let base = window_identity(&[part(1), part(2)], Some("s"), "c/n");
        assert_eq!(base, window_identity(&[part(2), part(1)], Some("s"), "c/n"), "order-free");
        assert_ne!(base, window_identity(&[part(1), part(2), part(3)], Some("s"), "c/n"));
        assert_ne!(base, window_identity(&[part(1)], Some("s"), "c/n"));
        assert_ne!(base, window_identity(&[part(1), part(2)], Some("s2"), "c/n"));
        assert_ne!(base, window_identity(&[part(1), part(2)], Some("s"), "c2/n"));
    }
}
