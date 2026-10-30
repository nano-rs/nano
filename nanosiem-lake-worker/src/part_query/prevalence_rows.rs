// SPDX-License-Identifier: AGPL-3.0-or-later
//! Exact whole-part prevalence states derived only from leased signed partials.
//! The caller selects live parts on every read. Edge parts are never memoized,
//! and tenant, normalized source scope, requested artifacts and signed content
//! bind reuse. No coverage or authority is inferred from a cache entry.
use anyhow::{Context, Result, ensure};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use crate::parts::part_log::PartRef;
use crate::prevalence::PrevalenceResult;

const MAX_BYTES: usize = 16 * 1024 * 1024;
const MAX_ENTRIES: usize = 4_096;
const HOST_CAP: usize = 1_000;
const MAX_FOLD_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
#[error("prevalence summary fold exceeds its resident bound")]
pub(super) struct FoldTooWide;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Summary {
    kind: String,
    entity: String,
    hosts: Vec<u64>,
    saturated: bool,
    private: bool,
    first_us: i64,
    last_us: i64,
    total: u64,
}

impl Summary {
    pub fn decode(row: &Value) -> Result<Self> {
        fn u64_value(value: &Value) -> Result<u64> {
            value
                .as_u64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                .context("invalid prevalence unsigned value")
        }
        fn i64_value(value: &Value) -> Result<i64> {
            value
                .as_i64()
                .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
                .context("invalid prevalence timestamp")
        }
        let hosts = row["hosts"]
            .as_array()
            .context("invalid prevalence host set")?
            .iter()
            .map(u64_value)
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            hosts.len() <= HOST_CAP && hosts.windows(2).all(|pair| pair[0] < pair[1]),
            "invalid prevalence host ordering"
        );
        let first_us = i64_value(&row["first_us"])?;
        let last_us = i64_value(&row["last_us"])?;
        ensure!(first_us <= last_us, "reversed prevalence observation range");
        let saturated = u64_value(&row["saturated"])?;
        let private = u64_value(&row["private"])?;
        ensure!(saturated <= 1 && private <= 1, "invalid prevalence flags");
        Ok(Self {
            kind: row["kind"]
                .as_str()
                .context("missing prevalence kind")?
                .into(),
            entity: row["entity"]
                .as_str()
                .context("missing prevalence entity")?
                .into(),
            hosts,
            saturated: saturated != 0,
            private: private != 0,
            first_us,
            last_us,
            total: u64_value(&row["total"])?,
        })
    }

    fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>()
            + self.kind.capacity()
            + self.entity.capacity()
            + self.hosts.capacity() * std::mem::size_of::<u64>()
    }
}

pub(super) fn shape(
    tenant: &str,
    artifacts: &[(String, String)],
    deny: &[String],
) -> [u8; 32] {
    let deny = deny
        .iter()
        .map(|source| source.trim().to_ascii_lowercase())
        .collect::<BTreeSet<_>>();
    let mut hash = Sha256::new();
    hash.update(b"nano.part-prevalence.v2\0");
    hash.update(
        serde_json::to_vec(&(tenant, artifacts, deny))
            .expect("prevalence shape serializes"),
    );
    hash.finalize().into()
}

pub(super) fn key(shape: &[u8; 32], part: &PartRef, digest: &str) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(shape);
    hash.update(serde_json::to_vec(&(part, digest)).expect("signed part identity serializes"));
    hash.finalize().into()
}

#[derive(Default)]
struct Inner {
    entries: HashMap<[u8; 32], (usize, Arc<Vec<Summary>>)>,
    order: VecDeque<[u8; 32]>,
    bytes: usize,
}

#[derive(Default)]
pub(super) struct PrevalenceRowsMemo {
    inner: Mutex<Inner>,
}

impl PrevalenceRowsMemo {
    pub fn get(&self, key: &[u8; 32]) -> Option<Arc<Vec<Summary>>> {
        self.inner
            .lock()
            .ok()?
            .entries
            .get(key)
            .map(|(_, rows)| rows.clone())
    }

    pub fn insert(&self, key: [u8; 32], rows: Arc<Vec<Summary>>) {
        // Count vector capacity, strings, host sets and conservative map/queue
        // overhead. Empty misses consume space and are bounded by entry count.
        let bytes = 256
            + rows.capacity() * std::mem::size_of::<Summary>()
            + rows
                .iter()
                .map(|row| row.resident_bytes() - std::mem::size_of::<Summary>())
                .sum::<usize>();
        if bytes > MAX_BYTES {
            return;
        }
        let Ok(mut inner) = self.inner.lock() else {
            return;
        };
        if inner.entries.contains_key(&key) {
            return;
        }
        while inner.bytes + bytes > MAX_BYTES || inner.entries.len() >= MAX_ENTRIES {
            let Some(oldest) = inner.order.pop_front() else {
                return;
            };
            if let Some((bytes, _)) = inner.entries.remove(&oldest) {
                inner.bytes -= bytes;
            }
        }
        inner.bytes += bytes;
        inner.order.push_back(key);
        inner.entries.insert(key, (bytes, rows));
    }
}

pub(super) fn fold(parts: &[Arc<Vec<Summary>>], threshold: u64) -> Result<Vec<PrevalenceResult>> {
    let mut merged = BTreeMap::<(&str, &str), (BTreeSet<u64>, bool, bool, i64, i64, u64)>::new();
    let mut fold_bytes = 0_usize;
    for row in parts.iter().flat_map(|rows| rows.iter()) {
        if !merged.contains_key(&(row.kind.as_str(), row.entity.as_str())) {
            fold_bytes += 256 + row.kind.len() + row.entity.len();
            if fold_bytes > MAX_FOLD_BYTES {
                return Err(FoldTooWide.into());
            }
        }
        let entry = merged
            .entry((&row.kind, &row.entity))
            .or_insert_with(|| (BTreeSet::new(), false, false, row.first_us, row.last_us, 0));
        for host in &row.hosts {
            if entry.0.len() < HOST_CAP {
                if entry.0.insert(*host) {
                    fold_bytes += 64;
                }
                if fold_bytes > MAX_FOLD_BYTES {
                    return Err(FoldTooWide.into());
                }
            }
        }
        entry.1 |= row.saturated || entry.0.len() == HOST_CAP;
        entry.2 |= row.private;
        entry.3 = entry.3.min(row.first_us);
        entry.4 = entry.4.max(row.last_us);
        entry.5 = entry
            .5
            .checked_add(row.total)
            .context("prevalence occurrence count overflow")?;
    }
    merged
        .into_iter()
        .map(
            |((kind, entity), (hosts, saturated, private, first, last, total))| {
                crate::prevalence::prevalence_result(
                    kind,
                    entity,
                    hosts.len() as u64,
                    saturated,
                    private,
                    first,
                    last,
                    total,
                    threshold,
                )
                .map_err(Into::into)
            },
        )
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(hosts: Vec<u64>, total: u64, first: i64, last: i64) -> Summary {
        Summary {
            kind: "domain".into(),
            entity: "example.test".into(),
            hosts,
            saturated: false,
            private: false,
            first_us: first,
            last_us: last,
            total,
        }
    }

    #[test]
    fn exact_host_union_counts_and_recency_match_120_independent_partitions() {
        for seed in 0..120_u64 {
            let count = (seed as usize % 7) + 1;
            let mut parts = vec![Vec::new(); count];
            let mut hosts = BTreeSet::new();
            for offset in 0..2_048_u64 {
                let host = (offset * (seed + 1)) % (seed * 17 + 1);
                hosts.insert(host);
                parts[offset as usize % count].push(row(
                    vec![host],
                    1,
                    offset as i64,
                    offset as i64,
                ));
            }
            let parts = parts.into_iter().map(Arc::new).collect::<Vec<_>>();
            let memo = PrevalenceRowsMemo::default();
            for (index, rows) in parts.iter().enumerate() {
                memo.insert([index as u8; 32], rows.clone());
            }
            let cached = (0..count)
                .map(|index| memo.get(&[index as u8; 32]).unwrap())
                .collect::<Vec<_>>();
            let actual = fold(&cached, 5).unwrap();
            assert_eq!(actual.len(), 1);
            assert_eq!(actual[0].host_count, (hosts.len().min(HOST_CAP)) as u64);
            assert_eq!(actual[0].host_count_saturated, hosts.len() >= HOST_CAP);
            assert_eq!(actual[0].total_occurrences, 2_048);
            assert_eq!(actual[0].first_seen, crate::prevalence::format_micros(0));
            assert_eq!(actual[0].last_seen, crate::prevalence::format_micros(2_047));
            assert_eq!(
                serde_json::to_value(actual).unwrap(),
                serde_json::to_value(fold(&parts, 5).unwrap()).unwrap()
            );
        }
    }

    #[test]
    fn shapes_bind_tenant_artifacts_and_normalized_source_scope() {
        let artifacts = vec![("domain".into(), "example.test".into())];
        let base = shape("tenant-a", &artifacts, &["HIDDEN".into()]);
        assert_eq!(
            base,
            shape("tenant-a", &artifacts, &[" hidden ".into()])
        );
        assert_ne!(
            base,
            shape("tenant-b", &artifacts, &["hidden".into()])
        );
        assert_ne!(base, shape("tenant-a", &artifacts, &[]));
        assert_ne!(
            base,
            shape(
                "tenant-a",
                &[("ip".into(), "10.0.0.1".into())],
                &["hidden".into()],
            )
        );
    }

    #[test]
    fn signed_content_shape_changes_invalidate_reuse() {
        let part = PartRef {
            request_hours: None,
            part_id: crate::parts::format::PartId::new(1_790_000_000_000).unwrap(),
            level: crate::parts::levels::Level::L0,
            event_hour: 1,
            event_day: None,
            rows: 1,
            min_time_us: 0,
            max_time_us: 1,
            schema_fingerprint: "a".repeat(64),
            provenance_sha256: "b".repeat(64),
            merkle_root: "c".repeat(64),
            sorted: true,
            data_bytes: 1,
            row_groups: 1,
            data_files: 1,
        };
        let shape = [0; 32];
        let base = key(&shape, &part, "partial-a");
        assert_ne!(base, key(&shape, &part, "partial-b"));
        let mut changed = part.clone();
        changed.provenance_sha256 = "d".repeat(64);
        assert_ne!(base, key(&shape, &changed, "partial-a"));
        changed = part.clone();
        changed.merkle_root = "e".repeat(64);
        assert_ne!(base, key(&shape, &changed, "partial-a"));
        changed = part.clone();
        changed.rows = 2;
        assert_ne!(base, key(&shape, &changed, "partial-a"));
        changed = part.clone();
        changed.schema_fingerprint = "f".repeat(64);
        assert_ne!(base, key(&shape, &changed, "partial-a"));
    }

    #[test]
    fn memory_and_empty_negative_entries_are_bounded() {
        let memo = PrevalenceRowsMemo::default();
        for index in 0..MAX_ENTRIES + 1 {
            let key = Sha256::digest(index.to_le_bytes()).into();
            memo.insert(key, Arc::new(Vec::new()));
        }
        let inner = memo.inner.lock().unwrap();
        assert_eq!(inner.entries.len(), MAX_ENTRIES);
        assert!(inner.bytes <= MAX_BYTES);
        drop(inner);
        let oversized = Arc::new(vec![row(vec![0; MAX_BYTES / 8], 1, 0, 1)]);
        memo.insert([255; 32], oversized);
        assert!(memo.get(&[255; 32]).is_none());
    }

    #[test]
    fn wide_host_folds_request_the_exact_fallback() {
        let rows = (0..200)
            .map(|index| {
                let mut value = row((0..1_000).collect(), 1_000, 0, 1);
                value.entity = format!("entity{index}.test");
                value
            })
            .collect::<Vec<_>>();
        let error = fold(&[Arc::new(rows)], 5).unwrap_err();
        assert!(error.downcast_ref::<FoldTooWide>().is_some());
    }

    #[test]
    fn malformed_native_states_fail_closed() {
        let mut value = json!({"kind":"domain", "entity":"example.test", "hosts":["1","2"], "saturated":0, "private":0, "first_us":"0", "last_us":"1", "total":"2"});
        assert!(Summary::decode(&value).is_ok());
        value["hosts"] = json!([1, 1]);
        assert!(Summary::decode(&value).is_err());
        value["hosts"] = json!([1]);
        value["total"] = json!("bad");
        assert!(Summary::decode(&value).is_err());
    }
}
