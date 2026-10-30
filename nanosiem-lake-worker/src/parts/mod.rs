// SPDX-License-Identifier: AGPL-3.0-or-later

//! The lean-lake part contract (NAN-2865 / NAN-2868).
//!
//! This module is the Rust source of truth for
//! `docs-internal/NAN-2865-part-contract.md`. Phase 2 (ingest), phase 3
//! (query over parts) and phase 4 (adopt history) all code against these
//! types. Change them only together with the contract document.
//!
//! - [`format`]: R2 key layout, Parquet settings, sort order, bloom columns.
//! - [`sidecar`]: the per-row-group token index and the aggregate partials.
//! - [`provenance`]: the signed per-part provenance record and Merkle root.
//! - [`part_log`]: the per-tenant, hash-chained, signed part log.
//! - [`levels`]: merge levels, triggers and supersession.
//! - [`DedupPolicy`]: the uid window semantics (contract section 7).

pub mod block_index;
pub mod count_record;
pub mod format;
pub mod indicators;
pub mod entity_locators;
pub mod entity_counts;
pub mod levels;
pub mod part_log;
pub mod provenance;
pub mod parquet_ranges;
pub mod refusal_tally;
pub mod request_dedup;
pub mod sidecar;
pub mod token_counts;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub use format::{LogKeys, PartId, PartKeys};
pub use levels::Level;
pub use part_log::{LogEntry, LogOp, PartRef};
pub use provenance::{
    edge_log_genesis, edge_log_next_chain, edge_log_seq_of_version, EdgeLogRange, EdgeSkipReason, EdgeSkippedSegment,
    MerkleBuilder, PartSigner, ProvenanceRecord, SignedProvenance, EDGE_LOG_CONTRACT, EDGE_LOG_VERSION_PREFIX,
};

/// Contract version carried in every record, entry and checkpoint.
pub const CONTRACT_VERSION: u32 = 1;

/// Microseconds in one hour / day.
pub const HOUR_US: i64 = 3_600_000_000;
pub const DAY_US: i64 = 86_400_000_000;

/// Hours since the Unix epoch for an event time in microseconds (UTC).
pub fn event_hour_of(time_us: i64) -> i32 {
    i32::try_from(time_us.div_euclid(HOUR_US)).unwrap_or(i32::MAX)
}

/// Days since the Unix epoch for an event time in microseconds (UTC).
pub fn event_day_of(time_us: i64) -> i32 {
    i32::try_from(time_us.div_euclid(DAY_US)).unwrap_or(i32::MAX)
}

/// Lowercase hex SHA-256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// True for a 64-char lowercase hex SHA-256.
pub fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Dedup semantics (contract section 7).
///
/// The key is `(event_hour, metadata.uid)`. Inside the exact window a
/// committed uid is held as [`uid_hash`] in a per-hour set; outside it the
/// `metadata.uid` Parquet bloom of each live part of the row's hour is
/// checked, then that part's uid column on a bloom hit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DedupPolicy {
    /// An event hour keeps its exact in-memory set while it received rows
    /// within this much arrival time.
    pub exact_window_ms: i64,
}

impl Default for DedupPolicy {
    fn default() -> Self {
        Self { exact_window_ms: 6 * 3_600_000 }
    }
}

/// How a row was found to be a duplicate. Recorded in counters only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DedupWindow {
    /// Only the exact in-memory window was consulted.
    Exact,
    /// At least one row was checked against part blooms / uid columns.
    ExactAndParts,
}

/// The 128-bit uid hash held in the exact window. Tenant-keyed so no two
/// tenants' windows are ever comparable.
pub fn uid_hash(tenant_id: &str, uid: &str) -> u128 {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.as_bytes());
    hasher.update([0_u8]);
    hasher.update(uid.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    u128::from_be_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_hour_and_day_floor_negative_times() {
        assert_eq!(event_hour_of(0), 0);
        assert_eq!(event_hour_of(HOUR_US - 1), 0);
        assert_eq!(event_hour_of(-1), -1);
        assert_eq!(event_day_of(DAY_US), 1);
    }

    #[test]
    fn uid_hash_is_tenant_keyed() {
        assert_ne!(uid_hash("a", "u1"), uid_hash("b", "u1"));
        assert_eq!(uid_hash("a", "u1"), uid_hash("a", "u1"));
        // The separator prevents ("ab","c") == ("a","bc").
        assert_ne!(uid_hash("ab", "c"), uid_hash("a", "bc"));
    }
}
