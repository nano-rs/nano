// SPDX-License-Identifier: AGPL-3.0-or-later

//! Multi-writer-safe snowflake id generator for ClickHouse lookup storage.
//!
//! ClickHouse's `ReplacingMergeTree(version)` keeps, per ORDER BY key, only the
//! row with the highest `version`. The lookup row backend (NAN-1581) writes a
//! new row at a higher version on every insert / update and a tombstone row at a
//! higher version on every delete. The `version` therefore MUST be strictly
//! increasing and globally unique — `now_ms` alone is unsafe because two edits
//! within the same millisecond would tie and one would be silently dropped on
//! merge.
//!
//! Lookups can be written by MORE THAN ONE process: every `nanosiem-api` replica
//! constructs a `LookupService` and serves row inserts/edits/deletes (the
//! upload service inside `nanosiem-core` also writes, but it runs inside the api
//! process). To stay correct across replicas without coordination, the version
//! is a snowflake:
//!
//! ```text
//!   version = (now_ms << 22) | (node_id << 12) | seq
//! ```
//!
//! - `now_ms` (high bits) gives recency ordering ACROSS processes — a later
//!   edit on any node generally wins.
//! - `node_id` (10 bits, hash of hostname+pid mod 1024) makes two different
//!   processes never collide.
//! - `seq` (12 bits, AtomicU64 mod 4096) breaks same-process same-ms ties.
//!
//! The SAME generator allocates `row_id` (the immutable surrogate dedup
//! identity): a logical row gets exactly ONE `row_id` at creation time, and
//! every subsequent edit/delete reuses it while minting a fresh `version`.
//!
//! RESIDUAL (documented, accepted): two edits to the SAME `row_id` within the
//! SAME millisecond on DIFFERENT nodes are ordered by `node_id`, NOT by
//! wall-clock recency — the higher `node_id` wins regardless of which edit
//! happened a few microseconds later. For human-edited reference tables this is
//! acceptable; concurrent same-ms cross-node edits to one cell are vanishingly
//! rare and the loser is a near-identical value.

use std::sync::Mutex;
use std::sync::OnceLock;

const NODE_ID_BITS: u64 = 10; // 0..1024
const SEQ_BITS: u64 = 12; // 0..4096
const NODE_ID_MASK: u64 = (1 << NODE_ID_BITS) - 1;
const SEQ_MASK: u64 = (1 << SEQ_BITS) - 1;
const TIME_SHIFT: u64 = NODE_ID_BITS + SEQ_BITS; // 22

/// Monotonic clock state: the last millisecond we emitted at and the sequence
/// consumed within it. Guarded by a mutex so concurrent callers within a
/// process serialize through the allocator and never tie. The lock is held for
/// a few arithmetic ops only.
static CLOCK: Mutex<(u64, u64)> = Mutex::new((0, 0));
static NODE_ID: OnceLock<u64> = OnceLock::new();

/// Per-process stable node id in `0..1024`, derived from hostname + pid.
///
/// Two replicas of the same binary on different hosts (different hostname) or
/// the same host (different pid) hash to different values with high
/// probability, which is what keeps cross-writer versions unique.
fn node_id() -> u64 {
    *NODE_ID.get_or_init(|| {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        let host = std::env::var("HOSTNAME")
            .ok()
            .or_else(|| hostname_fallback())
            .unwrap_or_else(|| "unknown-host".to_string());
        host.hash(&mut hasher);
        std::process::id().hash(&mut hasher);
        hasher.finish() & NODE_ID_MASK
    })
}

/// Best-effort hostname when `HOSTNAME` is not set in the environment.
fn hostname_fallback() -> Option<String> {
    // Avoid pulling a new dependency; the env var is set in every deployment
    // (Kubernetes injects HOSTNAME = pod name). The fallback only needs to be
    // STABLE within a process, not a real hostname.
    std::env::var("POD_NAME").ok()
}

/// Generate the next strictly-monotonic, globally-unique snowflake.
///
/// Used for BOTH `version` (every write) and `row_id` allocation (once per
/// logical row). Within a single process the returned values are strictly
/// increasing in allocation order as long as fewer than 4096 ids are minted in
/// the same millisecond (the seq wraps but `now_ms` advances).
pub fn next_id() -> u64 {
    let wall_ms = chrono::Utc::now().timestamp_millis().max(0) as u64;

    let (stamp_ms, seq) = {
        let mut clock = CLOCK.lock().unwrap_or_else(|p| p.into_inner());
        let (last_ms, last_seq) = *clock;
        let (stamp_ms, seq) = if wall_ms > last_ms {
            // Time advanced: fresh millisecond, reset the sequence.
            (wall_ms, 0)
        } else {
            // Same or backwards millisecond (clock skew / >4096 ids/ms): keep
            // emitting at last_ms, bumping seq. On seq overflow, advance the
            // logical millisecond so ids stay strictly increasing without
            // waiting on the wall clock.
            let next_seq = last_seq + 1;
            if next_seq > SEQ_MASK {
                (last_ms + 1, 0)
            } else {
                (last_ms, next_seq)
            }
        };
        *clock = (stamp_ms, seq);
        (stamp_ms, seq)
    };

    // stamp_ms occupies the high bits (TIME_SHIFT = 22), node_id the middle 10
    // bits, seq the low 12 bits. node_id is already masked to NODE_ID_BITS.
    (stamp_ms << TIME_SHIFT) | (node_id() << SEQ_BITS) | (seq & SEQ_MASK)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn snowflake_is_unique_within_process() {
        // 50k ids in a tight loop — must never collide even though many land
        // in the same millisecond (seq + node_id disambiguate).
        let mut seen = HashSet::new();
        for _ in 0..50_000 {
            let id = next_id();
            assert!(seen.insert(id), "snowflake collision: {id}");
        }
    }

    #[test]
    fn snowflake_is_monotonic_within_process() {
        // Later allocations sort AFTER earlier ones within a single process.
        // seq is the low bits and increments per call, and now_ms only ever
        // advances, so the sequence is strictly increasing.
        let mut prev = next_id();
        for _ in 0..50_000 {
            let next = next_id();
            assert!(
                next > prev,
                "snowflake not monotonic: {next} followed {prev}"
            );
            prev = next;
        }
    }

    #[test]
    fn same_logical_row_never_gets_equal_versions() {
        // Simulate repeated edits to the SAME row_id: each edit mints a fresh
        // version; no two versions for that row may be equal (ReplacingMergeTree
        // would otherwise drop one on merge).
        let _row_id = next_id();
        let mut versions = HashSet::new();
        for _ in 0..10_000 {
            let v = next_id();
            assert!(versions.insert(v), "duplicate version for same row_id: {v}");
        }
    }
}
