// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4445: when the tenant's current prevalence degraded spell began, kept
//! in the tenant bucket so a cell roll does not restart it.
//!
//! The large tenant (2026-10-21..23) sat degraded for about 41 h. Every roll (the cell's
//! PVC is ephemeral, and the spell's start lived only in process memory)
//! reported 0, which resolved the platform's `prevalence_degraded` alert; it
//! re-fired minutes later as a flap, which never pages. Now the spell's start
//! is an immutable record under the tenant's `log/checkpoints/` (named and
//! bound like the NAN-3864 restamp snapshots): `{written_ms:013}-{sha256[..16]}.json`
//! holding `{"since_ms":…,"cleared_ms":null|…}`. The newest valid record is
//! the state: an open spell (`cleared_ms` null) is continued by the next
//! process, a cleared one is history. Written only when a spell starts or
//! ends (plus a refresh every half horizon while one lasts), so a few small
//! objects per incident.

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use crate::parts::format::LogKeys;
use crate::parts::part_log::ObjectStore;
use crate::parts::sha256_hex;

pub(crate) const PREVALENCE_DEGRADED_DIR: &str = "prevalence-degraded-v1/";

/// Records older than this are never read. An open spell is rewritten every
/// half horizon, so its newest record is always inside it.
pub(crate) const SPELL_RECORD_HORIZON_MS: i64 = 30 * 86_400_000;
/// Keys per listing page and pages per call of the bounded scan.
const SPELL_SCAN_PAGE_KEYS: usize = 256;
const SPELL_SCAN_PAGES_PER_CALL: usize = 4;
/// Newest names kept as candidates while the scan pages forward.
const SPELL_SCAN_TAIL: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SpellRecord {
    pub since_ms: i64,
    pub cleared_ms: Option<i64>,
}

impl SpellRecord {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let record: Self = serde_json::from_slice(bytes)?;
        ensure!(record.since_ms >= 0, "spell start is negative");
        ensure!(record.cleared_ms.is_none_or(|cleared| cleared >= record.since_ms), "spell cleared before it began");
        Ok(record)
    }
}

pub(crate) fn spell_prefix(tenant_id: &str) -> Result<String> {
    Ok(format!("{}{PREVALENCE_DEGRADED_DIR}", LogKeys::new(tenant_id)?.checkpoints_prefix()))
}

fn record_matches(prefix: &str, key: &str, bytes: &[u8]) -> bool {
    key.strip_prefix(prefix).is_some_and(|name| name.len() == 35
        && name.as_bytes()[..13].iter().all(u8::is_ascii_digit)
        && name[13..] == format!("-{}.json", &sha256_hex(bytes)[..16]))
}

/// Write `record` as of `written_ms` (strictly after every earlier record of
/// this process: the newest name is the state).
pub(crate) async fn persist_spell(store: &dyn ObjectStore, tenant_id: &str, record: SpellRecord, written_ms: i64) -> Result<()> {
    ensure!((0..=9_999_999_999_999).contains(&written_ms), "spell record time out of range");
    let bytes = serde_json::to_vec(&record)?;
    let key = format!("{}{written_ms:013}-{}.json", spell_prefix(tenant_id)?, &sha256_hex(&bytes)[..16]);
    if !store.put_if_absent(&key, &bytes).await? {
        ensure!(store.get(&key).await?.as_deref() == Some(bytes.as_slice()), "spell record differs");
    }
    Ok(())
}

/// The continuation of a bounded scan for the newest spell record. Records
/// are never deleted (ingest holds no delete authority under
/// `log/checkpoints/`), so the scan starts at the horizon and pages forward.
#[derive(Debug, Default)]
pub(crate) struct SpellScan {
    after: Option<String>,
    tail: std::collections::VecDeque<String>,
}

/// One bounded step. `Ok(None)`: more pages remain (call again).
/// `Ok(Some(newest))`: done; the newest valid record (its write time and
/// content), if any. An unreadable or foreign record is skipped.
pub(crate) async fn scan_spell(store: &dyn ObjectStore, tenant_id: &str, scan: &mut SpellScan, now_ms: i64)
    -> Result<Option<Option<(i64, SpellRecord)>>> {
    let prefix = spell_prefix(tenant_id)?;
    if scan.after.is_none() {
        scan.after = Some(format!("{prefix}{:013}", now_ms.saturating_sub(SPELL_RECORD_HORIZON_MS).max(0)));
    }
    let mut done = false;
    for _ in 0..SPELL_SCAN_PAGES_PER_CALL {
        let page = store.list_page(&prefix, scan.after.as_deref(), SPELL_SCAN_PAGE_KEYS).await?;
        for key in &page {
            ensure!(key.starts_with(&prefix), "spell record listing escaped its prefix");
            scan.tail.push_back(key.clone());
            if scan.tail.len() > SPELL_SCAN_TAIL { scan.tail.pop_front(); }
        }
        if let Some(last) = page.last() { scan.after = Some(last.clone()); }
        if page.len() < SPELL_SCAN_PAGE_KEYS {
            done = true;
            break;
        }
    }
    if !done {
        return Ok(None);
    }
    let tail = std::mem::take(&mut scan.tail);
    *scan = SpellScan::default();
    for key in tail.iter().rev() {
        let Some(bytes) = store.get(key).await? else { continue };
        match SpellRecord::parse(&bytes) {
            Ok(record) if record_matches(&prefix, key, &bytes) => {
                let written_ms = key[prefix.len()..prefix.len() + 13].parse::<i64>()?;
                return Ok(Some(Some((written_ms, record))));
            }
            _ => tracing::warn!(tenant = %tenant_id, %key, "skipping unreadable prevalence degraded spell record"),
        }
    }
    Ok(Some(None))
}

/// Where this process stands with the persisted spell.
#[derive(Debug, Default)]
pub(crate) struct SpellSync {
    /// The stored record was read (or there was none).
    pub loaded: bool,
    /// The start of a spell an earlier process left open, until this
    /// process's first open settles it (continued or cleared).
    pub inherited_since_ms: Option<i64>,
    /// The last record read or written, and when.
    pub saved: Option<SpellRecord>,
    pub saved_ms: i64,
    /// No store call before this (a failed or slow call waits a minute).
    pub retry_ms: i64,
    pub scan: SpellScan,
}

impl SpellSync {
    /// What should be stored for the in-process state `since_ms` (the
    /// ongoing spell's start, `None` while healthy), or `None` when the
    /// stored record already says it. An open spell is rewritten every half
    /// horizon so the scan always finds it.
    pub fn wanted(&self, since_ms: Option<i64>, now_ms: i64) -> Option<SpellRecord> {
        match (since_ms, self.saved) {
            (Some(since), Some(SpellRecord { since_ms: saved, cleared_ms: None }))
                if saved == since && now_ms.saturating_sub(self.saved_ms) < SPELL_RECORD_HORIZON_MS / 2 => None,
            (Some(since), _) => Some(SpellRecord { since_ms: since, cleared_ms: None }),
            (None, Some(SpellRecord { since_ms: saved, cleared_ms: None })) =>
                Some(SpellRecord { since_ms: saved, cleared_ms: Some(now_ms.max(saved)) }),
            (None, _) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::part_log::LocalObjectStore;

    const TENANT: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";

    async fn load(store: &dyn ObjectStore, now_ms: i64) -> Option<(i64, SpellRecord)> {
        let mut scan = SpellScan::default();
        loop {
            if let Some(found) = scan_spell(store, TENANT, &mut scan, now_ms).await.unwrap() {
                return found;
            }
        }
    }

    #[tokio::test]
    async fn the_newest_record_is_the_spell_and_survives_a_new_process() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let t0 = 1_800_000_000_000;
        assert_eq!(load(&store, t0).await, None);
        persist_spell(&store, TENANT, SpellRecord { since_ms: t0, cleared_ms: None }, t0).await.unwrap();
        // Idempotent for identical bytes.
        persist_spell(&store, TENANT, SpellRecord { since_ms: t0, cleared_ms: None }, t0).await.unwrap();
        // A "new process" reads the open spell back from the bucket.
        assert_eq!(load(&store, t0 + 3_600_000).await, Some((t0, SpellRecord { since_ms: t0, cleared_ms: None })));
        persist_spell(&store, TENANT, SpellRecord { since_ms: t0, cleared_ms: Some(t0 + 7_200_000) }, t0 + 7_200_000).await.unwrap();
        assert_eq!(load(&store, t0 + 7_300_000).await.unwrap().1.cleared_ms, Some(t0 + 7_200_000));
        // Past the horizon nothing is read.
        assert_eq!(load(&store, t0 + 7_200_000 + SPELL_RECORD_HORIZON_MS + 1).await, None);
    }

    #[tokio::test]
    async fn unreadable_and_mismatched_records_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::new(dir.path()).unwrap();
        let t0 = 1_800_000_000_000;
        persist_spell(&store, TENANT, SpellRecord { since_ms: t0, cleared_ms: None }, t0).await.unwrap();
        let prefix = spell_prefix(TENANT).unwrap();
        store.put_if_absent(&format!("{prefix}{:013}-0123456789abcdef.json", t0 + 1), b"{\"since_ms\":5,\"cleared_ms\":null}").await.unwrap();
        store.put_if_absent(&format!("{prefix}{:013}-garbage.json", t0 + 2), b"nope").await.unwrap();
        assert_eq!(load(&store, t0 + 10).await, Some((t0, SpellRecord { since_ms: t0, cleared_ms: None })));
    }

    #[test]
    fn writes_only_on_start_end_and_refresh() {
        let mut sync = SpellSync::default();
        let t0 = 1_800_000_000_000;
        assert_eq!(sync.wanted(None, t0), None, "healthy, nothing stored");
        let open = SpellRecord { since_ms: t0, cleared_ms: None };
        assert_eq!(sync.wanted(Some(t0), t0), Some(open));
        sync.saved = Some(open);
        sync.saved_ms = t0;
        assert_eq!(sync.wanted(Some(t0), t0 + 60_000), None, "unchanged spell");
        assert_eq!(sync.wanted(Some(t0), t0 + SPELL_RECORD_HORIZON_MS / 2), Some(open), "refresh");
        assert_eq!(sync.wanted(None, t0 + 5), Some(SpellRecord { since_ms: t0, cleared_ms: Some(t0 + 5) }), "spell ended");
        sync.saved = Some(SpellRecord { since_ms: t0, cleared_ms: Some(t0 + 5) });
        assert_eq!(sync.wanted(None, t0 + 10), None, "already cleared");
        assert_eq!(sync.wanted(Some(t0 + 20), t0 + 20), Some(SpellRecord { since_ms: t0 + 20, cleared_ms: None }), "a new spell");
    }
}
