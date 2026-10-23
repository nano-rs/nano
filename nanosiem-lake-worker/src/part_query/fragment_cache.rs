// SPDX-License-Identifier: AGPL-3.0-or-later
//! Bounded process-local immutable-part answers. No payload or masked fields.
use crate::parts::{format::PartId, part_log::PartRef};
use crate::planner::CompiledQuery;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Mutex;

pub fn enabled() -> bool {
    std::env::var("NANO_LAKE_PART_RESULT_CACHE").as_deref() == Ok("1")
}

#[cfg(test)]
mod tests {
    use super::*;
    fn part() -> PartRef {
        serde_json::from_value(serde_json::json!({
            "part_id":"1790872183150-34c916be72234829", "level":"l0", "event_hour":1,
            "event_day":null, "rows":2, "min_time_us":10, "max_time_us":20,
            "schema_fingerprint":"schema", "provenance_sha256":"digest", "merkle_root":"root",
            "sorted":true, "data_bytes":100, "row_groups":1, "data_files":1
        }))
        .unwrap()
    }

    #[test]
    fn normalization_binds_kind_cursor_and_schema() {
        let sql = "SELECT time FROM __nano_lake_source__ WHERE time >= '2026-10-01 16:00:00.000000' AND time < '2026-10-01 17:00:00.000000' AND message='2026-10-01 16:00:00.000000'";
        let a: CompiledQuery = serde_json::from_value(serde_json::json!({
            "schema_version":1,"profile":"ocsf","dataset":"logs","source_placeholder":"__nano_lake_source__",
            "query_sha256":"a","start":"2026-10-01T16:00:00Z","end":"2026-10-01T17:00:00Z","limit":101,
            "table_view":true,"required_columns":[],"sql":sql
        })).unwrap();
        let mut b = a.clone();
        b.end = "2026-10-01T18:00:00Z".into();
        b.sql = sql.replace("17:00:00.000000", "18:00:00.000000");
        let key = Context::new(&a, None).identity;
        assert_eq!(key, Context::new(&b, None).identity);
        assert!(normalized_sql(&a).contains("message='2026-10-01 16:00:00.000000'"));
        // NAN-4280: the compiler's half-open bound is recognized (the fast
        // path engages), and the retired inclusive form is not.
        assert!(normalized_sql(&a).contains("WHERE __nano_part_window__ AND message="), "{}", normalized_sql(&a));
        let mut inclusive = a.clone();
        inclusive.sql = sql.replace(
            "time >= '2026-10-01 16:00:00.000000' AND time < '2026-10-01 17:00:00.000000'",
            "time BETWEEN '2026-10-01 16:00:00.000000' AND '2026-10-01 17:00:00.000000'",
        );
        assert_eq!(normalized_sql(&inclusive), inclusive.sql);
        assert_ne!(
            key,
            Context::new(&a, Some(("time", "uid"))).identity
        );
        assert_ne!(
            key,
            Context::for_statement("histogram", &a, None).identity
        );
        b.required_columns =
            serde_json::from_value(serde_json::json!([{"name":"x","field_type":"string"}]))
                .unwrap();
        assert_ne!(key, Context::new(&b, None).identity);
    }

    #[test]
    fn identity_isolates_tenants_digests_windows_and_predicates() {
        let context = Context { identity: [1; 32] };
        let part = part();
        let key = context.key("a", &part, 0, 30);
        assert_ne!(key, context.key("b", &part, 0, 30));
        assert_eq!(key, context.key("a", &part, 10, 20));
        assert_ne!(key, context.key("a", &part, 11, 20));
        assert_ne!(key, Context { identity: [2; 32] }.key("a", &part, 0, 30));
        let mut changed = part.clone();
        changed.provenance_sha256 = "changed".into();
        assert_ne!(key, context.key("a", &changed, 0, 30));
        changed = part.clone();
        changed.merkle_root = "changed".into();
        assert_ne!(key, context.key("a", &changed, 0, 30));
        changed = part.clone();
        changed.part_id = PartId::new(1).unwrap();
        assert_ne!(key, context.key("a", &changed, 0, 30));
    }

    #[test]
    fn negatives_positives_lru_and_retirement_are_bounded() {
        let cache = FragmentCache::new(1 << 30);
        let part = part().part_id;
        cache.insert([1; 32], part.clone(), vec![]);
        cache.insert([2; 32], part.clone(), vec!["time".into()]);
        assert!(cache.negative(&[1; 32]));
        assert!(!cache.negative(&[2; 32]));
        assert_eq!(cache.get(&[2; 32]), Some(vec!["time".into()]));
        assert!(cache.get(&[3; 32]).is_none());
        assert_eq!(cache.counters().negative_hits, 1);
        assert_eq!(cache.counters().misses, 1);
        let charge = cache.counters().bytes;
        let small = FragmentCache::new((charge * 64) as u64);
        small.insert([1; 32], part.clone(), vec![]);
        small.insert([2; 32], part.clone(), vec!["time".into()]);
        small.get(&[1; 32]); // Promote negative, evict positive next.
        small.insert([3; 32], part.clone(), vec!["time".into()]);
        assert!(small.get(&[2; 32]).is_none());
        assert!(small.negative(&[1; 32]));
        assert!(small.counters().bytes <= charge);
        small.retain_live(&BTreeSet::new());
        assert_eq!(small.counters().bytes, 0);
        assert!(small.get(&[1; 32]).is_none());
        cache.insert([4; 32], part, vec!["x".repeat(1024 * 1024)]);
        assert!(cache.get(&[4; 32]).is_none());
    }
}

/// Conservative identity: compiler SQL, typed missing-column defaults,
/// projection and cursor. Only the compiler-owned source time
/// bounds are normalized; edge windows remain in the per-part key.
#[derive(Clone)]
pub(super) struct Context {
    identity: [u8; 32],
}

impl Context {
    pub fn new(query: &CompiledQuery, cursor: Option<(&str, &str)>) -> Self {
        Self::for_statement("locator", query, cursor)
    }

    pub fn for_statement(
        kind: &str,
        query: &CompiledQuery,
        cursor: Option<(&str, &str)>,
    ) -> Self {
        let normalized = normalized_sql(query);
        let mut hash = Sha256::new();
        hash.update(format!(
            "fragment-v2\0{kind}\0{}\0{:?}\0{:?}\0{}\0{:?}",
            normalized,
            query.required_columns,
            query.projected_scan_columns,
            query.limit,
            cursor,
        ));
        Self {
            identity: hash.finalize().into(),
        }
    }

    /// The cache key of one part's answer over `[from, last]`, both
    /// INCLUSIVE µs (NAN-4280: a caller holding a half-open compiled window
    /// passes `end - 1`). The window is clamped to the part, so windows that
    /// cover the same rows of it share the answer: clamping an exclusive end
    /// would map `[a, T)` and `[a, T + 5)` over a part ending at `T` to one
    /// key although only the second holds the row at `T`.
    pub fn key(&self, tenant: &str, part: &PartRef, from: i64, last: i64) -> [u8; 32] {
        let mut hash = Sha256::new();
        hash.update(self.identity);
        // Length-delimited identity fields prevent concatenation ambiguity.
        for field in [
            tenant,
            &part.part_id.to_string(),
            &part.provenance_sha256,
            &part.merkle_root,
        ] {
            hash.update((field.len() as u64).to_le_bytes());
            hash.update(field.as_bytes());
        }
        hash.update(from.max(part.min_time_us).to_le_bytes());
        hash.update(last.min(part.max_time_us).to_le_bytes());
        hash.finalize().into()
    }
}

fn normalized_sql(query: &CompiledQuery) -> String {
    let literal = |value: &str| {
        chrono::DateTime::parse_from_rfc3339(value)
            .ok()
            .map(|time| {
                time.with_timezone(&chrono::Utc)
                    .format("%Y-%m-%d %H:%M:%S%.6f")
                    .to_string()
            })
    };
    let (Some(start), Some(end)) = (literal(&query.start), literal(&query.end)) else {
        return query.sql.clone();
    };
    static WINDOW: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let pattern = WINDOW.get_or_init(|| {
        // NAN-4280: built from the compiler's own half-open bound text.
        regex::Regex::new(&format!(
            r"FROM __nano_lake_source__\s+WHERE {}",
            nanosiem_core::sql_hygiene::half_open_time_bound_pattern("time", "[^']+")
        ))
        .expect("static window regex")
    });
    let Some(captures) = pattern.captures(&query.sql) else {
        return query.sql.clone();
    };
    if captures[1] != start || captures[2] != end {
        return query.sql.clone();
    }
    let matched = captures.get(0).expect("window match");
    let mut sql = query.sql.clone();
    sql.replace_range(
        matched.range(),
        "FROM __nano_lake_source__ WHERE __nano_part_window__",
    );
    sql
}

tokio::task_local! {
    pub(super) static CONTEXT: Option<Context>;
}

#[derive(Default, Clone, Serialize)]
pub struct Counters {
    pub hits: u64,
    pub misses: u64,
    pub negative_hits: u64,
    pub bytes: usize,
    pub evictions: u64,
}

struct Entry {
    key: [u8; 32],
    part: PartId,
    answer: Answer,
    bytes: usize,
}

#[derive(Clone)]
enum Answer {
    Locator(Vec<String>),
    Partial(Box<[u8]>),
}

impl Answer {
    fn negative(&self) -> bool {
        matches!(self, Self::Locator(times) if times.is_empty())
    }
    fn bytes(&self) -> usize {
        match self {
            Self::Locator(times) => {
                times.capacity() * std::mem::size_of::<String>()
                    + times.iter().map(String::capacity).sum::<usize>()
            }
            Self::Partial(bytes) => bytes.len(),
        }
    }
}

struct State {
    entries: BTreeMap<u64, Entry>,
    index: HashMap<[u8; 32], u64>,
    clock: u64,
    counters: Counters,
}

pub struct FragmentCache {
    cap: usize,
    state: Mutex<State>,
}

impl FragmentCache {
    pub fn new(query_memory_bytes: u64) -> Self {
        // At most 1/64 of the role's statement budget, capped at 64 MiB.
        // Count resident strings and entry/container overhead, not JSON size.
        let cap = (query_memory_bytes / 64).min(64 << 20) as usize;
        Self {
            cap,
            state: Mutex::new(State {
                entries: BTreeMap::new(),
                index: HashMap::new(),
                clock: 0,
                counters: Counters::default(),
            }),
        }
    }

    pub fn counters(&self) -> Counters {
        self.state.lock().expect("fragment cache").counters.clone()
    }

    fn lookup(&self, key: &[u8; 32], negative_only: bool) -> Option<Answer> {
        let mut state = self.state.lock().expect("fragment cache");
        let index = state
            .index
            .get(key)
            .copied()
            .filter(|tick| !negative_only || state.entries[tick].answer.negative());
        let Some(index) = index else {
            if !negative_only {
                state.counters.misses += 1;
            }
            return None;
        };
        let entry = state.entries.remove(&index).expect("located entry");
        state.counters.hits += 1;
        state.counters.negative_hits += u64::from(entry.answer.negative());
        let answer = entry.answer.clone();
        state.clock += 1;
        let tick = state.clock;
        state.index.insert(entry.key, tick);
        state.entries.insert(tick, entry);
        Some(answer)
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<Vec<String>> {
        match self.lookup(key, false)? {
            Answer::Locator(times) => Some(times),
            _ => None,
        }
    }
    pub fn get_partial(&self, key: &[u8; 32]) -> Option<Box<[u8]>> {
        match self.lookup(key, false)? {
            Answer::Partial(bytes) => Some(bytes),
            _ => None,
        }
    }
    pub fn insert_partial(&self, key: [u8; 32], part: PartId, bytes: Box<[u8]>) {
        self.store(key, part, Answer::Partial(bytes));
    }
    pub fn negative(&self, key: &[u8; 32]) -> bool {
        self.lookup(key, true).is_some()
    }

    pub fn insert(&self, key: [u8; 32], part: PartId, times: Vec<String>) {
        self.store(key, part, Answer::Locator(times));
    }

    fn store(&self, key: [u8; 32], part: PartId, answer: Answer) {
        let bytes = 2 * std::mem::size_of::<Entry>() + 128 + answer.bytes();
        if bytes > self.cap || bytes > 1024 * 1024 {
            return;
        }
        let mut state = self.state.lock().expect("fragment cache");
        if let Some(index) = state.index.remove(&key) {
            let removed = state.entries.remove(&index).unwrap();
            state.counters.bytes -= removed.bytes;
        }
        while state.counters.bytes + bytes > self.cap {
            let Some((_, removed)) = state.entries.pop_first() else {
                break;
            };
            state.counters.bytes -= removed.bytes;
            state.counters.evictions += 1;
            state.index.remove(&removed.key);
        }
        state.counters.bytes += bytes;
        state.clock += 1;
        let tick = state.clock;
        state.index.insert(key, tick);
        state.entries.insert(
            tick,
            Entry {
                key,
                part,
                answer,
                bytes,
            },
        );
    }

    /// Purge on membership removals, including supersede and GC receipts.
    pub fn retain_live(&self, live: &BTreeSet<PartId>) {
        let mut state = self.state.lock().expect("fragment cache");
        state.entries.retain(|_, entry| live.contains(&entry.part));
        state.index = state
            .entries
            .iter()
            .map(|(tick, entry)| (entry.key, *tick))
            .collect();
        state.counters.bytes = state.entries.values().map(|entry| entry.bytes).sum();
    }
}
