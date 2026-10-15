// SPDX-License-Identifier: AGPL-3.0-or-later

//! The uid window (contract section 7).
//!
//! Exact per-event-hour sets of 128-bit uid hashes for hours that received
//! rows within the window; for an hour outside it, the hour's live parts are
//! consulted (Parquet `metadata.uid` bloom first, then the uid column) and
//! the hour is re-hydrated into the window.
//!
//! NAN-3704: each held uid also carries a 64-bit hash of the first admitted
//! row's source identity ([`payload_hash64`] of
//! `bronze::source_identity_digest`, the in-batch admission normalisation).
//! A later duplicate with a different payload hash is still dropped (the
//! first row wins), but is reported as [`Seen::PayloadDiff`] so it can be
//! counted instead of vanishing silently. Uids re-hydrated from parts carry
//! [`PAYLOAD_UNKNOWN`]: a part stores the normalized, enriched row, not the
//! pre-normalisation source event the digest covers, so their duplicates are
//! never compared.

use anyhow::{Context, Result};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ProjectionMask;
use parquet::bloom_filter::Sbbf;
use parquet::file::reader::{FileReader, SerializedFileReader};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::fs::File;
use std::path::Path;

use crate::parts::format::UID_PATH;
use crate::parts::{uid_hash, DedupPolicy};

/// Most uid hashes held, covering a 300-eps tenant's 6 h window (≈6.5M)
/// plus late-data hours.
pub const MAX_WINDOW_UIDS: usize = 12_000_000;
/// Resident bytes per held uid (a 24 B entry: the 128-bit uid hash as two
/// u64 words plus the 64-bit payload hash, one control byte, and hashbrown's
/// worst-case load factor just after a resize: 25 × 16/7 ≈ 57), for sizing
/// the cap from a memory budget. Was 40 (16 B entry) before NAN-3704.
pub const WINDOW_BYTES_PER_UID: u64 = 58;
/// A cap below this would thrash a 20-eps tenant's window.
pub const MIN_WINDOW_UIDS: usize = 500_000;

/// The window cap for a process memory budget: 30% of it, within
/// `[MIN_WINDOW_UIDS, MAX_WINDOW_UIDS]`.
pub fn window_cap_for(memory_bytes: u64) -> usize {
    let uids = (memory_bytes.saturating_mul(3) / 10) / WINDOW_BYTES_PER_UID;
    (uids as usize).clamp(MIN_WINDOW_UIDS, MAX_WINDOW_UIDS)
}

/// Payload hash of a uid whose first row's payload is not known (loaded from
/// a part). Never compared.
pub const PAYLOAD_UNKNOWN: u64 = 0;

/// The 64-bit payload hash held per uid: the first 8 bytes of the source
/// identity digest (`bronze::source_identity_digest`, which already excludes
/// `logged_time`, `processed_time` and `original_event_uid`). Never
/// [`PAYLOAD_UNKNOWN`].
pub fn payload_hash64(source_identity_digest: &[u8; 32]) -> u64 {
    let mut bytes = [0_u8; 8];
    bytes.copy_from_slice(&source_identity_digest[..8]);
    match u64::from_be_bytes(bytes) {
        PAYLOAD_UNKNOWN => 1,
        hash => hash,
    }
}

/// A 128-bit uid hash stored as two u64 words: with a u64 value the map
/// entry is 24 B (a `u128` key is 16-aligned and would pad it to 32 B).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug)]
pub struct UidKey(pub [u64; 2]);

impl UidKey {
    pub fn of(tenant_id: &str, uid: &str) -> Self {
        let hash = uid_hash(tenant_id, uid);
        Self([(hash >> 64) as u64, hash as u64])
    }
}

/// An hour [`UidWindow::evict_into`] dropped: its uid hashes and the parts
/// they cover, handed to the late-hour tier (NAN-3703).
pub struct EvictedHour {
    pub hour: i32,
    pub uids: HashMap<UidKey, u64>,
    pub parts: HashSet<String>,
}

/// What [`UidWindow::observe`] found for one admitted row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// The uid is new: it was inserted and the row is kept.
    New,
    /// A duplicate whose payload matches the first row's, or whose payload
    /// cannot be compared (either side [`PAYLOAD_UNKNOWN`]). Dropped.
    Duplicate,
    /// A duplicate whose payload differs from the first row's. Dropped all
    /// the same (the first row wins); `first` is the held payload hash.
    PayloadDiff { first: u64 },
}

#[derive(Default)]
struct HourSet {
    /// uid → payload hash of the first row admitted for it.
    uids: HashMap<UidKey, u64>,
    touched_ms: i64,
    /// True when every live part of the hour is loaded: absence from `uids`
    /// then proves the uid is new. Otherwise the caller must also consult
    /// the hour's unloaded parts.
    complete: bool,
    loaded_parts: HashSet<String>,
}

/// Exact dedup state for one tenant.
pub struct UidWindow {
    tenant_id: String,
    policy: DedupPolicy,
    hours: HashMap<i32, HourSet>,
    max_uids: usize,
}

impl UidWindow {
    pub fn new(tenant_id: &str, policy: DedupPolicy) -> Self {
        Self::with_cap(tenant_id, policy, MAX_WINDOW_UIDS)
    }

    pub fn with_cap(tenant_id: &str, policy: DedupPolicy, max_uids: usize) -> Self {
        Self { tenant_id: tenant_id.to_string(), policy, hours: HashMap::new(), max_uids: max_uids.max(1) }
    }

    /// True when `hour` has an exact, complete in-memory set.
    pub fn is_complete(&self, hour: i32) -> bool {
        self.hours.get(&hour).is_some_and(|set| set.complete)
    }

    pub fn has_loaded(&self, hour: i32, part_id: &str) -> bool {
        self.hours.get(&hour).is_some_and(|set| set.loaded_parts.contains(part_id))
    }

    /// Was the uid already committed or buffered (as far as the set knows)?
    pub fn contains(&self, hour: i32, uid: &str) -> bool {
        self.contains_key(hour, &UidKey::of(&self.tenant_id, uid))
    }

    /// [`Self::contains`] for a key already hashed with [`Self::key`].
    pub fn contains_key(&self, hour: i32, key: &UidKey) -> bool {
        self.hours.get(&hour).is_some_and(|set| set.uids.contains_key(key))
    }

    /// The window's hash of `uid` (tenant-scoped).
    pub fn key(&self, uid: &str) -> UidKey {
        UidKey::of(&self.tenant_id, uid)
    }

    /// Insert with an unknown payload; returns false when the uid was already
    /// in the set (its held payload hash is then left as it was).
    pub fn insert(&mut self, hour: i32, uid: &str, now_ms: i64) -> bool {
        self.insert_with_payload(hour, uid, PAYLOAD_UNKNOWN, now_ms)
    }

    fn insert_with_payload(&mut self, hour: i32, uid: &str, payload: u64, now_ms: i64) -> bool {
        let key = UidKey::of(&self.tenant_id, uid);
        let set = self.hours.entry(hour).or_default();
        set.touched_ms = set.touched_ms.max(now_ms);
        match set.uids.entry(key) {
            std::collections::hash_map::Entry::Occupied(_) => false,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(payload);
                true
            }
        }
    }

    /// Admit one row: a new uid is inserted with its payload hash ([`Seen::New`]);
    /// a held uid is a duplicate, classified by comparing payload hashes.
    /// Exactly the old `contains` + `insert` sequence otherwise: a duplicate
    /// does not touch the hour.
    pub fn observe(&mut self, hour: i32, uid: &str, payload: u64, now_ms: i64) -> Seen {
        self.observe_key(hour, UidKey::of(&self.tenant_id, uid), payload, now_ms)
    }

    /// [`Self::observe`] for a key already hashed with [`Self::key`].
    pub fn observe_key(&mut self, hour: i32, key: UidKey, payload: u64, now_ms: i64) -> Seen {
        if let Some(&first) = self.hours.get(&hour).and_then(|set| set.uids.get(&key)) {
            if first == PAYLOAD_UNKNOWN || payload == PAYLOAD_UNKNOWN || first == payload {
                return Seen::Duplicate;
            }
            return Seen::PayloadDiff { first };
        }
        let set = self.hours.entry(hour).or_default();
        set.touched_ms = set.touched_ms.max(now_ms);
        set.uids.insert(key, payload);
        Seen::New
    }

    /// Mark whether the hour's set now reflects every live part.
    pub fn set_complete(&mut self, hour: i32, complete: bool, now_ms: i64) {
        let set = self.hours.entry(hour).or_default();
        set.touched_ms = set.touched_ms.max(now_ms);
        set.complete = complete;
    }

    /// Load the uids of one local part (all its data files) that fall in `hour`.
    pub fn load_part(&mut self, hour: i32, part_id: &str, part_dir: &Path, now_ms: i64) -> Result<u64> {
        let mut rows = Vec::new();
        for file in super::writer::local_data_files(part_dir)? {
            rows.extend(read_time_uids_in_hour(&file, Some(hour))?);
        }
        let tenant = self.tenant_id.clone();
        let set = self.hours.entry(hour).or_default();
        set.touched_ms = set.touched_ms.max(now_ms);
        set.loaded_parts.insert(part_id.to_string());
        let mut loaded = 0;
        for (_, uid) in &rows {
            // A uid already held keeps its known payload hash.
            set.uids.entry(UidKey::of(&tenant, uid)).or_insert(PAYLOAD_UNKNOWN);
            loaded += 1;
        }
        Ok(loaded)
    }

    /// Record that `part_id`'s uids for `hour` are already in the set (a part
    /// this process just wrote from buffered, already-inserted uids).
    pub fn load_marker(&mut self, hour: i32, part_id: &str, now_ms: i64) {
        let set = self.hours.entry(hour).or_default();
        set.touched_ms = set.touched_ms.max(now_ms);
        set.loaded_parts.insert(part_id.to_string());
    }

    /// Drop hours untouched for longer than the window, then, while the
    /// window holds more than its cap, the least recently touched hours
    /// (late-data hours loaded for dedup). An evicted hour is simply not
    /// complete: its next late row goes back to the part blooms. Hours in
    /// `protected` (holding buffered, uncommitted rows, whose uids exist
    /// nowhere else) are never evicted.
    pub fn evict(&mut self, now_ms: i64, protected: &BTreeSet<i32>) -> usize {
        self.evict_into(now_ms, protected, &mut Vec::new())
    }

    /// [`Self::evict`], handing every evicted hour that covers at least one
    /// committed part to `spilled` (NAN-3703: the late-hour tier keeps it).
    pub fn evict_into(&mut self, now_ms: i64, protected: &BTreeSet<i32>, spilled: &mut Vec<EvictedHour>) -> usize {
        let cutoff = now_ms - self.policy.exact_window_ms;
        let before = self.hours.len();
        let expired = self.hours.iter()
            .filter(|(hour, set)| set.touched_ms < cutoff && !protected.contains(hour))
            .map(|(hour, _)| *hour)
            .collect::<Vec<_>>();
        for hour in expired {
            if let Some(set) = self.hours.remove(&hour) {
                spill(hour, set, spilled);
            }
        }
        let mut total = self.len();
        while total > self.max_uids {
            let Some(oldest) = self
                .hours
                .iter()
                .filter(|(hour, _)| !protected.contains(hour))
                .min_by_key(|(_, set)| set.touched_ms)
                .map(|(hour, _)| *hour)
            else {
                break;
            };
            if let Some(set) = self.hours.remove(&oldest) {
                total -= set.uids.len();
                spill(oldest, set, spilled);
            }
        }
        before - self.hours.len()
    }

    pub fn len(&self) -> usize {
        self.hours.values().map(|set| set.uids.len()).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn hours(&self) -> usize {
        self.hours.len()
    }
}

/// Hand an evicted hour to the late tier when it covers a committed part
/// (an hour with no loaded part holds no committed uid).
fn spill(hour: i32, set: HourSet, spilled: &mut Vec<EvictedHour>) {
    if !set.loaded_parts.is_empty() {
        spilled.push(EvictedHour { hour, uids: set.uids, parts: set.loaded_parts });
    }
}

/// Does any data file of a local part admit any of `uids` by its uid bloom?
pub fn part_may_contain_any(part_dir: &Path, uids: &[&str]) -> Result<bool> {
    for file in super::writer::local_data_files(part_dir)? {
        if bloom_may_contain_any(&file, uids)? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Does any row group's `metadata.uid` bloom admit any of `uids`? A missing
/// bloom counts as "maybe".
pub fn bloom_may_contain_any(data_parquet: &Path, uids: &[&str]) -> Result<bool> {
    let file = File::open(data_parquet)?;
    let reader = SerializedFileReader::new(file.try_clone()?)?;
    let schema = reader.metadata().file_metadata().schema_descr();
    let Some(column) = (0..schema.num_columns()).find(|i| schema.column(*i).path().string() == UID_PATH) else {
        return Ok(true);
    };
    for group in reader.metadata().row_groups() {
        let chunk = group.column(column);
        match Sbbf::read_from_column_chunk(chunk, &file).ok().flatten() {
            Some(bloom) => {
                if uids.iter().any(|uid| bloom.check(uid.as_bytes())) {
                    return Ok(true);
                }
            }
            None => return Ok(true),
        }
    }
    Ok(false)
}

/// Read only the `time` and `metadata.uid` leaves of a part.
pub fn read_time_uids(data_parquet: &Path) -> Result<Vec<(i64, String)>> {
    read_time_uids_in_hour(data_parquet, None)
}

/// [`read_time_uids`] restricted to one event hour: row groups whose `time`
/// statistics miss the hour are skipped, and rows outside it are dropped
/// while streaming, so a day part costs about one hour of uids.
pub fn read_time_uids_in_hour(data_parquet: &Path, hour: Option<i32>) -> Result<Vec<(i64, String)>> {
    use arrow_array::Array as _;
    use parquet::file::statistics::Statistics;
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(data_parquet)?)?;
    let schema = builder.parquet_schema();
    let find = |path: &str| (0..schema.num_columns()).find(|i| schema.column(*i).path().string() == path);
    let uid_leaf = find(UID_PATH).context("part has no metadata.uid column")?;
    let time_leaf = find("time").context("part has no time column")?;
    let mask = ProjectionMask::leaves(schema, [time_leaf, uid_leaf]);
    let bounds = hour.map(crate::parts::format::hour_bounds_us);
    let groups = (0..builder.metadata().num_row_groups())
        .filter(|&g| {
            let Some((from, to)) = bounds else { return true };
            match builder.metadata().row_group(g).column(time_leaf).statistics() {
                Some(Statistics::Int64(stats)) => match (stats.min_opt(), stats.max_opt()) {
                    (Some(min), Some(max)) => *min <= to && *max >= from,
                    _ => true,
                },
                _ => true,
            }
        })
        .collect::<Vec<_>>();
    let reader = builder.with_projection(mask).with_row_groups(groups).with_batch_size(65_536).build()?;
    let mut out = Vec::new();
    for batch in reader {
        let batch = batch?;
        let values = super::writer::uid_strings(&batch)?;
        let time = batch.column_by_name("time").context("projected time")?;
        for i in 0..values.len() {
            if values.is_null(i) {
                continue;
            }
            let t = crate::generation::event_time_us_from_array(time.as_ref(), i).context("part row has no time")?;
            if bounds.is_some_and(|(from, to)| t < from || t > to) {
                continue;
            }
            out.push((t, values.value(i).to_string()));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_is_exact_per_hour_and_evicts() {
        let mut window = UidWindow::new("t", DedupPolicy { exact_window_ms: 1_000 });
        window.set_complete(1, true, 0);
        assert!(window.insert(1, "a", 0));
        assert!(!window.insert(1, "a", 10));
        assert!(window.contains(1, "a"));
        assert!(window.insert(2, "a", 10));
        assert!(!window.is_complete(2));
        assert_eq!(window.evict(1_005, &BTreeSet::new()), 0);
        assert_eq!(window.evict(2_000, &BTreeSet::new()), 2);
    }

    #[test]
    fn buffered_hours_are_never_evicted_and_the_cap_follows_memory() {
        let mut window = UidWindow::with_cap("t", DedupPolicy { exact_window_ms: 1_000 }, 2);
        window.insert(1, "a", 1_000);
        window.insert(1, "b", 1_000);
        window.insert(2, "c", 1_500);
        // Over the cap: hour 1 (oldest) is buffered, so hour 2 goes.
        assert_eq!(window.evict(1_600, &BTreeSet::from([1])), 1);
        assert!(window.contains(1, "a"));
        // Past the window, but still buffered.
        assert_eq!(window.evict(9_000, &BTreeSet::from([1])), 0);
        assert!(window.contains(1, "b"));
        assert_eq!(window.evict(9_000, &BTreeSet::new()), 1);
        assert_eq!(window_cap_for(1 << 30), 5_553_837);
        assert_eq!(window_cap_for(128 << 20), 694_229);
        assert_eq!(window_cap_for(64 << 20), MIN_WINDOW_UIDS);
        assert_eq!(window_cap_for(32 << 20), MIN_WINDOW_UIDS);
        assert_eq!(window_cap_for(64 << 30), MAX_WINDOW_UIDS);
        assert!(!window.is_complete(1));
    }

    #[test]
    fn a_window_entry_stays_24_bytes() {
        assert_eq!(std::mem::size_of::<(UidKey, u64)>(), 24);
    }

    #[test]
    fn same_uid_identical_payload_is_a_plain_duplicate() {
        let mut window = UidWindow::new("t", DedupPolicy::default());
        let payload = payload_hash64(&[7; 32]);
        assert_eq!(window.observe(1, "a", payload, 0), Seen::New);
        assert_eq!(window.observe(1, "a", payload, 10), Seen::Duplicate);
        assert_eq!(window.len(), 1);
    }

    #[test]
    fn same_uid_different_payload_is_reported_and_the_first_row_is_kept() {
        let mut window = UidWindow::new("t", DedupPolicy::default());
        let first = payload_hash64(&[1; 32]);
        let second = payload_hash64(&[2; 32]);
        assert_eq!(window.observe(1, "a", first, 0), Seen::New);
        assert_eq!(window.observe(1, "a", second, 10), Seen::PayloadDiff { first });
        // The held hash is still the first row's: a third copy equal to the
        // first is a plain duplicate, one equal to the second is a diff.
        assert_eq!(window.observe(1, "a", first, 20), Seen::Duplicate);
        assert_eq!(window.observe(1, "a", second, 30), Seen::PayloadDiff { first });
        // Same uid in another hour is a different key.
        assert_eq!(window.observe(2, "a", second, 30), Seen::New);
    }

    #[test]
    fn uids_without_a_known_payload_are_never_compared() {
        let mut window = UidWindow::new("t", DedupPolicy::default());
        let payload = payload_hash64(&[3; 32]);
        // As re-hydrated from a part: no payload hash.
        window.insert(1, "a", 0);
        assert_eq!(window.observe(1, "a", payload, 10), Seen::Duplicate);
        // A part load never erases a known payload hash.
        assert_eq!(window.observe(1, "b", payload, 10), Seen::New);
        assert!(!window.insert(1, "b", 20));
        assert_eq!(window.observe(1, "b", payload_hash64(&[4; 32]), 30), Seen::PayloadDiff { first: payload });
        assert_eq!(payload_hash64(&[0; 32]), 1, "a real payload never reads as unknown");
    }

    #[test]
    fn a_duplicate_does_not_touch_its_hour() {
        let mut window = UidWindow::new("t", DedupPolicy { exact_window_ms: 1_000 });
        assert_eq!(window.observe(1, "a", 5, 0), Seen::New);
        assert_eq!(window.observe(1, "a", 6, 900), Seen::PayloadDiff { first: 5 });
        // Untouched since 0: past the window at 1_005.
        assert_eq!(window.evict(1_005, &BTreeSet::new()), 1);
    }
}
