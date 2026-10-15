// SPDX-License-Identifier: AGPL-3.0-or-later

//! The late-hour uid tier (NAN-3703).
//!
//! The uid window ([`super::dedup::UidWindow`]) holds exact uid sets for the
//! event hours touched in the last 6 h of arrival time. Past that, NAN-3387
//! stopped fetching an old hour's parts inline (a backfill's downloads
//! stalled live ingest), so a redelivery of an hour that ended 6–72 h ago
//! was admitted again until the hour's next merge.
//!
//! This tier keeps those hours' uids locally and compactly, so they are
//! deduped before they are written, without any store I/O on the
//! admission path:
//!
//! * **Spill.** When the window evicts an hour, its exact uid hashes go to
//!   a *run*: a sorted file of 128-bit uid hashes (the window's own hash),
//!   plus an in-memory bloom over it (10 bits/uid, 7 probes, ~0.8% false
//!   positives). The run records which live parts it covers. The sort and
//!   write run on the blocking pool; the tick only moves the evicted set.
//! * **Check.** An admitted row of an hour the tier holds probes each run's
//!   bloom (no I/O); only on a bloom hit is the run file binary-searched
//!   (~log2(n) 16-byte local reads) to confirm the exact uid hash.
//! * **Coverage.** A part the tier covers is not loaded into the window. A
//!   merge output whose inputs are all covered is covered too, without
//!   reading it. A live part of a 6–72 h hour that is neither covered nor
//!   in the local cache is queued for a background fold (download, extract
//!   uids, write a run), one at a time and never awaited by admission. Until
//!   then its hour's rows are admitted and counted; merge still drops the
//!   copy on `(time, uid)`.
//! * **Restart.** Runs persist under `work_dir/late-uids/<tenant>/<hour>/`.
//!   They are re-read in the background at open; until that finishes the
//!   tier answers nothing and late rows are admitted and counted.
//! * **Bounds.** Hours whose end is more than [`HORIZON_MS`] old are dropped
//!   (memory and disk). Blooms are held within a byte budget (see
//!   [`bloom_budget_for`]); past it the oldest hours are dropped, which only
//!   shortens the horizon.
//!
//! The runs are worker-local cache, never part of a signed part or the part
//! log: no reader, owner or Worker sees them, and old parts need nothing.

use anyhow::{ensure, Context, Result};
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fs::File;
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use super::dedup::{EvictedHour, UidKey, WINDOW_BYTES_PER_UID};
use crate::parts::part_log::PartRef;

/// Rows of an event hour that ended more than this long ago are admitted
/// without late-hour dedup (counted); merge still drops duplicates.
pub const HORIZON_MS: i64 = 72 * 3_600_000;
/// Bloom bits per held uid and probes per lookup: ~0.8% false positives.
/// A false positive costs one local binary search, never a wrong drop.
const BLOOM_BITS_PER_UID: u64 = 10;
const BLOOM_PROBES: u64 = 7;
/// Bytes per uid in a run file (the window's 128-bit uid hash).
pub const RUN_BYTES_PER_UID: u64 = 16;
/// Floor of the bloom budget: 16 MiB holds ~13M uids (a 50-eps tenant's
/// 72 h).
pub const MIN_BLOOM_BUDGET_BYTES: u64 = 16 << 20;
/// Parts waiting for a background fold, at most.
const MAX_FOLD_QUEUE: usize = 256;
const COVERED_FILE: &str = "covered.log";

/// Bloom budget for a uid-window cap: a sixth of the window's own budget
/// (the window takes 30% of the assignment's memory, so this is 5%), at
/// least [`MIN_BLOOM_BUDGET_BYTES`]. At the window's 12M-uid ceiling: 116
/// MB, ~93M uids, 72 h of a ~360-eps tenant.
pub fn bloom_budget_for(max_window_uids: usize) -> u64 {
    (max_window_uids as u64 * WINDOW_BYTES_PER_UID / 6).max(MIN_BLOOM_BUDGET_BYTES)
}

struct Bloom {
    words: Vec<u64>,
}

impl Bloom {
    fn with_capacity(uids: usize) -> Self {
        let bits = (uids as u64 * BLOOM_BITS_PER_UID).max(64);
        Self {
            words: vec![0; bits.div_ceil(64) as usize],
        }
    }

    /// Probe `i` by double hashing the two halves of the uid hash (SHA-256
    /// output, already uniform).
    fn position(&self, key: &UidKey, i: u64) -> usize {
        let bits = self.words.len() as u64 * 64;
        (key.0[0].wrapping_add(i.wrapping_mul(key.0[1] | 1)) % bits) as usize
    }

    fn insert(&mut self, key: &UidKey) {
        for i in 0..BLOOM_PROBES {
            let bit = self.position(key, i);
            self.words[bit / 64] |= 1 << (bit % 64);
        }
    }

    fn may_contain(&self, key: &UidKey) -> bool {
        (0..BLOOM_PROBES).all(|i| {
            let bit = self.position(key, i);
            self.words[bit / 64] & (1 << (bit % 64)) != 0
        })
    }

    fn bytes(&self) -> u64 {
        self.words.len() as u64 * 8
    }
}

/// One sorted run file of an hour plus its bloom.
pub struct Run {
    path: PathBuf,
    len: u64,
    bloom: Bloom,
}

fn encode(key: &UidKey) -> [u8; 16] {
    let mut bytes = [0_u8; 16];
    bytes[..8].copy_from_slice(&key.0[0].to_be_bytes());
    bytes[8..].copy_from_slice(&key.0[1].to_be_bytes());
    bytes
}

fn decode(bytes: &[u8]) -> UidKey {
    let mut a = [0_u8; 8];
    let mut b = [0_u8; 8];
    a.copy_from_slice(&bytes[..8]);
    b.copy_from_slice(&bytes[8..16]);
    UidKey([u64::from_be_bytes(a), u64::from_be_bytes(b)])
}

impl Run {
    /// Sort, dedup and write `keys` as a new run of the hour directory.
    fn write(hour_dir: &Path, mut keys: Vec<UidKey>) -> Result<Self> {
        std::fs::create_dir_all(hour_dir)?;
        keys.sort_unstable();
        keys.dedup();
        let name = format!("run-{}.bin", uuid::Uuid::new_v4().simple());
        let path = hour_dir.join(&name);
        let temporary = hour_dir.join(format!("{name}.tmp"));
        let mut bloom = Bloom::with_capacity(keys.len());
        {
            let mut out = BufWriter::new(File::create(&temporary)?);
            for key in &keys {
                out.write_all(&encode(key))?;
                bloom.insert(key);
            }
            out.flush()?;
        }
        std::fs::rename(&temporary, &path)?;
        Ok(Self {
            path,
            len: keys.len() as u64,
            bloom,
        })
    }

    /// Re-read a run written by an earlier process.
    fn load(path: &Path) -> Result<Self> {
        let mut bytes = Vec::new();
        let mut file = File::open(path)?;
        file.read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 % RUN_BYTES_PER_UID == 0,
            "late uid run {} is truncated",
            path.display()
        );
        let len = bytes.len() / RUN_BYTES_PER_UID as usize;
        let mut bloom = Bloom::with_capacity(len);
        for chunk in bytes.chunks_exact(RUN_BYTES_PER_UID as usize) {
            bloom.insert(&decode(chunk));
        }
        Ok(Self {
            path: path.to_path_buf(),
            len: len as u64,
            bloom,
        })
    }

    /// Bloom first; a hit is confirmed by a binary search of the file.
    fn contains(&self, key: &UidKey) -> Result<bool> {
        if self.len == 0 || !self.bloom.may_contain(key) {
            return Ok(false);
        }
        use std::os::unix::fs::FileExt;
        // Opened per bloom hit, not held: a tenant can hold hundreds of
        // runs, and a hit already costs ~20 reads.
        let file = File::open(&self.path)?;
        let (mut low, mut high) = (0_u64, self.len);
        let mut buf = [0_u8; 16];
        while low < high {
            let mid = low + (high - low) / 2;
            file.read_exact_at(&mut buf, mid * RUN_BYTES_PER_UID)?;
            match decode(&buf).cmp(key) {
                std::cmp::Ordering::Equal => return Ok(true),
                std::cmp::Ordering::Less => low = mid + 1,
                std::cmp::Ordering::Greater => high = mid,
            }
        }
        Ok(false)
    }
}

#[derive(Default)]
struct HourTier {
    runs: Vec<Run>,
    covered: HashSet<String>,
}

impl HourTier {
    fn bloom_bytes(&self) -> u64 {
        self.runs.iter().map(|run| run.bloom.bytes()).sum()
    }
}

/// What a background spill or fold produced for one hour.
pub struct Built {
    pub hour: i32,
    run: Option<Run>,
    parts: Vec<String>,
}

type Loaded = BTreeMap<i32, HourTier>;

/// Counters for health.
#[derive(Debug, Default, Clone, Copy)]
pub struct TierStats {
    pub hours: usize,
    pub uids: u64,
    pub bloom_bytes: u64,
    pub ready: bool,
    pub folds_total: u64,
    pub fold_failures_total: u64,
    pub hours_dropped_over_budget_total: u64,
    pub spills_total: u64,
}

/// The late-hour tier of one tenant.
pub struct LateUidTier {
    dir: PathBuf,
    hours: BTreeMap<i32, HourTier>,
    loading: Option<tokio::task::JoinHandle<Result<Loaded>>>,
    writes: Vec<tokio::task::JoinHandle<Result<Vec<Built>>>>,
    fold_queue: VecDeque<PartRef>,
    fold_queued: HashSet<String>,
    fold: Option<(PartRef, tokio::task::JoinHandle<Result<Vec<Built>>>)>,
    budget_bytes: u64,
    stats: TierStats,
}

/// The hour's end, in ms.
pub fn hour_end_ms(hour: i32) -> i64 {
    (i64::from(hour) + 1) * 3_600_000
}

/// Is `hour` inside the late-dedup horizon?
pub fn within_horizon(hour: i32, now_ms: i64) -> bool {
    hour_end_ms(hour) > now_ms.saturating_sub(HORIZON_MS)
}

impl LateUidTier {
    /// Open the tier and start re-reading its runs in the background. Must
    /// run inside a tokio runtime.
    pub fn open(work_dir: &Path, tenant_id: &str, budget_bytes: u64, now_ms: i64) -> Self {
        let dir = work_dir.join("late-uids").join(tenant_id);
        let load_dir = dir.clone();
        let loading = tokio::task::spawn_blocking(move || load_all(&load_dir, now_ms));
        Self {
            dir,
            hours: BTreeMap::new(),
            loading: Some(loading),
            writes: Vec::new(),
            fold_queue: VecDeque::new(),
            fold_queued: HashSet::new(),
            fold: None,
            budget_bytes,
            stats: TierStats::default(),
        }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// True once the runs of the previous process are loaded.
    pub fn ready(&self) -> bool {
        self.loading.is_none()
    }

    pub fn has_hour(&self, hour: i32) -> bool {
        self.hours.contains_key(&hour)
    }

    /// Does the tier hold every uid of `part` for `hour`?
    pub fn covers(&self, hour: i32, part_id: &str) -> bool {
        self.hours
            .get(&hour)
            .is_some_and(|tier| tier.covered.contains(part_id))
    }

    /// Exact membership of a uid hash in the hour's runs (bloom, then a
    /// local binary search). An unreadable run answers "absent": the row is
    /// admitted and merge drops any copy.
    pub fn contains(&self, hour: i32, key: &UidKey) -> bool {
        let Some(tier) = self.hours.get(&hour) else {
            return false;
        };
        tier.runs.iter().any(|run| match run.contains(key) {
            Ok(found) => found,
            Err(error) => {
                tracing::warn!(hour, run = %run.path.display(), error = %format!("{error:#}"), "late uid run unreadable; admitting");
                false
            }
        })
    }

    /// Persist an evicted window hour in the background (no-op past the
    /// horizon).
    pub fn spill(&mut self, evicted: EvictedHour, now_ms: i64) {
        if !within_horizon(evicted.hour, now_ms) {
            return;
        }
        self.stats.spills_total += 1;
        let hour_dir = self.dir.join(evicted.hour.to_string());
        self.writes.push(tokio::task::spawn_blocking(move || {
            let keys = evicted.uids.into_keys().collect::<Vec<_>>();
            let parts = evicted.parts.into_iter().collect::<Vec<_>>();
            let run = Run::write(&hour_dir, keys)?;
            append_covered(&hour_dir, &parts)?;
            Ok(vec![Built {
                hour: evicted.hour,
                run: Some(run),
                parts,
            }])
        }));
    }

    /// A merge output whose inputs (those holding `hour`) the tier all
    /// covers holds no other uid: cover it without reading it.
    pub fn inherit(&mut self, hour: i32, inputs: &[&str], output: &str) -> bool {
        let Some(tier) = self.hours.get_mut(&hour) else {
            return false;
        };
        if inputs.is_empty() || !inputs.iter().all(|part| tier.covered.contains(*part)) {
            return false;
        }
        if tier.covered.insert(output.to_string()) {
            let hour_dir = self.dir.join(hour.to_string());
            let parts = vec![output.to_string()];
            // A lost line only means a later fold of the output.
            drop(tokio::task::spawn_blocking(move || {
                append_covered(&hour_dir, &parts)
            }));
        }
        true
    }

    /// Queue a live part of a late hour for a background fold.
    pub fn request_fold(&mut self, part: &PartRef) {
        let id = part.part_id.as_str();
        let busy = self
            .fold
            .as_ref()
            .is_some_and(|(p, _)| p.part_id == part.part_id);
        if busy || self.fold_queued.contains(id) || self.fold_queue.len() >= MAX_FOLD_QUEUE {
            return;
        }
        self.fold_queued.insert(id.to_string());
        self.fold_queue.push_back(part.clone());
    }

    /// The part a background fold is fetching now, if any (the cache keeps
    /// it).
    pub fn folding(&self) -> Option<&PartRef> {
        self.fold.as_ref().map(|(part, _)| part)
    }

    /// The next queued part still worth folding, if no fold is running.
    /// `live` tells whether a part is still live.
    pub fn next_fold(&mut self, now_ms: i64, live: impl Fn(&PartRef) -> bool) -> Option<PartRef> {
        if self.fold.is_some() || !self.ready() {
            return None;
        }
        while let Some(part) = self.fold_queue.pop_front() {
            self.fold_queued.remove(part.part_id.as_str());
            let hours = part_hours(&part);
            let needed = hours.iter().any(|hour| {
                within_horizon(*hour, now_ms) && !self.covers(*hour, part.part_id.as_str())
            });
            if needed && live(&part) {
                return Some(part);
            }
        }
        None
    }

    pub fn start_fold(&mut self, part: PartRef, task: tokio::task::JoinHandle<Result<Vec<Built>>>) {
        self.fold = Some((part, task));
    }

    /// Apply finished background work, drop hours past the horizon, keep
    /// blooms within budget. Never waits.
    pub async fn poll(&mut self, now_ms: i64) {
        if self.loading.as_ref().is_some_and(|task| task.is_finished()) {
            let task = self.loading.take().expect("checked");
            match task.await {
                Ok(Ok(loaded)) => {
                    for (hour, tier) in loaded {
                        let held = self.hours.entry(hour).or_default();
                        held.runs.extend(tier.runs);
                        held.covered.extend(tier.covered);
                    }
                }
                Ok(Err(error)) => {
                    tracing::warn!(error = %format!("{error:#}"), "late uid tier reload failed; starting empty")
                }
                Err(error) => {
                    tracing::warn!(error = %error, "late uid tier reload task failed; starting empty")
                }
            }
        }
        let mut finished = Vec::new();
        let mut index = 0;
        while index < self.writes.len() {
            if self.writes[index].is_finished() {
                finished.push(self.writes.swap_remove(index));
            } else {
                index += 1;
            }
        }
        for task in finished {
            match task.await {
                Ok(Ok(built)) => self.apply(built),
                Ok(Err(error)) => {
                    tracing::warn!(error = %format!("{error:#}"), "late uid spill failed")
                }
                Err(error) => tracing::warn!(error = %error, "late uid spill task failed"),
            }
        }
        if self
            .fold
            .as_ref()
            .is_some_and(|(_, task)| task.is_finished())
        {
            let (part, task) = self.fold.take().expect("checked");
            match task.await {
                Ok(Ok(built)) => {
                    self.stats.folds_total += 1;
                    self.apply(built);
                }
                Ok(Err(error)) => {
                    self.stats.fold_failures_total += 1;
                    tracing::warn!(part = %part.part_id.as_str(), error = %format!("{error:#}"), "late uid fold failed");
                }
                Err(error) => {
                    self.stats.fold_failures_total += 1;
                    tracing::warn!(part = %part.part_id.as_str(), error = %error, "late uid fold task failed");
                }
            }
        }
        self.prune(now_ms);
    }

    fn apply(&mut self, built: Vec<Built>) {
        for Built { hour, run, parts } in built {
            let tier = self.hours.entry(hour).or_default();
            tier.runs.extend(run);
            tier.covered.extend(parts);
        }
    }

    fn prune(&mut self, now_ms: i64) {
        let mut dropped = Vec::new();
        while let Some((&hour, _)) = self.hours.first_key_value() {
            if within_horizon(hour, now_ms) {
                break;
            }
            self.hours.remove(&hour);
            dropped.push(hour);
        }
        let mut bloom_bytes = self.hours.values().map(HourTier::bloom_bytes).sum::<u64>();
        while bloom_bytes > self.budget_bytes {
            let Some((hour, tier)) = self.hours.pop_first() else {
                break;
            };
            bloom_bytes -= tier.bloom_bytes();
            self.stats.hours_dropped_over_budget_total += 1;
            tracing::warn!(
                hour,
                budget_bytes = self.budget_bytes,
                "late uid tier over its bloom budget; dropped the oldest hour"
            );
            dropped.push(hour);
        }
        if !dropped.is_empty() {
            let dir = self.dir.clone();
            drop(tokio::task::spawn_blocking(move || {
                for hour in dropped {
                    let _ = std::fs::remove_dir_all(dir.join(hour.to_string()));
                }
            }));
        }
        self.stats.hours = self.hours.len();
        self.stats.uids = self
            .hours
            .values()
            .flat_map(|tier| tier.runs.iter().map(|run| run.len))
            .sum();
        self.stats.bloom_bytes = bloom_bytes;
        self.stats.ready = self.ready();
    }

    pub fn stats(&self) -> TierStats {
        self.stats
    }
}

/// The event hours a part holds.
pub fn part_hours(part: &PartRef) -> Vec<i32> {
    match part.level {
        crate::parts::levels::Level::Day => (crate::parts::event_hour_of(part.min_time_us)
            ..=crate::parts::event_hour_of(part.max_time_us))
            .collect(),
        _ => vec![part.event_hour],
    }
}

fn append_covered(hour_dir: &Path, parts: &[String]) -> Result<()> {
    std::fs::create_dir_all(hour_dir)?;
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(hour_dir.join(COVERED_FILE))?;
    let mut lines = String::new();
    for part in parts {
        lines.push_str(part);
        lines.push('\n');
    }
    file.write_all(lines.as_bytes())?;
    Ok(())
}

/// Re-read every hour still inside the horizon; delete the rest.
fn load_all(dir: &Path, now_ms: i64) -> Result<Loaded> {
    let mut loaded = Loaded::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Ok(loaded);
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Some(hour) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<i32>().ok())
        else {
            let _ = std::fs::remove_dir_all(&path);
            continue;
        };
        if !within_horizon(hour, now_ms) {
            let _ = std::fs::remove_dir_all(&path);
            continue;
        }
        let mut tier = HourTier::default();
        let mut torn = false;
        for file in std::fs::read_dir(&path)?.flatten() {
            let file_path = file.path();
            let name = file.file_name().to_string_lossy().into_owned();
            if name == COVERED_FILE {
                let text = std::fs::read_to_string(&file_path).unwrap_or_default();
                tier.covered.extend(
                    text.lines()
                        .filter(|line| !line.is_empty())
                        .map(str::to_owned),
                );
            } else if name.starts_with("run-") && name.ends_with(".bin") {
                match Run::load(&file_path) {
                    Ok(run) => tier.runs.push(run),
                    Err(error) => {
                        // A torn run: its parts are re-folded on demand.
                        tracing::warn!(error = %format!("{error:#}"), "dropping an unreadable late uid run");
                        let _ = std::fs::remove_file(&file_path);
                        torn = true;
                    }
                }
            } else {
                let _ = std::fs::remove_file(&file_path);
            }
        }
        if torn {
            // Which parts the torn run covered is unknown: re-fold on demand.
            tier.covered.clear();
            let _ = std::fs::remove_file(path.join(COVERED_FILE));
        }
        loaded.insert(hour, tier);
    }
    Ok(loaded)
}

/// Fold a local part's uids into runs of its hours inside the horizon
/// (blocking: Parquet reads). Hours of the part with no row still count as
/// covered.
pub fn fold_part(
    tier_dir: &Path,
    tenant_id: &str,
    part: &PartRef,
    part_dir: &Path,
    now_ms: i64,
) -> Result<Vec<Built>> {
    let hours = part_hours(part)
        .into_iter()
        .filter(|hour| within_horizon(*hour, now_ms))
        .collect::<Vec<_>>();
    let mut by_hour: HashMap<i32, Vec<UidKey>> =
        hours.iter().map(|hour| (*hour, Vec::new())).collect();
    for file in super::writer::local_data_files(part_dir)? {
        for (time_us, uid) in super::dedup::read_time_uids(&file).context("read part uids")? {
            if let Some(keys) = by_hour.get_mut(&crate::parts::event_hour_of(time_us)) {
                keys.push(UidKey::of(tenant_id, &uid));
            }
        }
    }
    let id = part.part_id.as_str().to_string();
    let mut built = Vec::new();
    for (hour, keys) in by_hour {
        let hour_dir = tier_dir.join(hour.to_string());
        let run = if keys.is_empty() {
            None
        } else {
            Some(Run::write(&hour_dir, keys)?)
        };
        append_covered(&hour_dir, std::slice::from_ref(&id))?;
        built.push(Built {
            hour,
            run,
            parts: vec![id.clone()],
        });
    }
    Ok(built)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(n: u64) -> UidKey {
        UidKey::of("t", &format!("uid-{n}"))
    }

    #[test]
    fn a_run_answers_exactly_and_its_bloom_is_ten_bits_per_uid() {
        let dir = tempfile::tempdir().unwrap();
        let keys = (0..10_000).map(key).collect::<Vec<_>>();
        let run = Run::write(dir.path(), keys.clone()).unwrap();
        assert_eq!(run.len, 10_000);
        // 10 bits per uid, rounded up to whole 64-bit words.
        assert_eq!(
            run.bloom.bytes(),
            (10_000 * BLOOM_BITS_PER_UID).div_ceil(64) * 8
        );
        assert!(keys.iter().all(|k| run.contains(k).unwrap()));
        let mut bloom_hits = 0;
        for n in 10_000..30_000 {
            let k = key(n);
            assert!(
                !run.contains(&k).unwrap(),
                "an absent uid is never confirmed"
            );
            bloom_hits += usize::from(run.bloom.may_contain(&k));
        }
        // ~0.8% expected; well under 2%.
        assert!(bloom_hits < 400, "bloom false positives {bloom_hits}/20000");
        let reloaded = Run::load(&run.path).unwrap();
        assert!(keys.iter().all(|k| reloaded.contains(k).unwrap()));
    }

    /// Latency/memory probe for the PR budget (run with `--ignored
    /// --nocapture`): one hour of a 300-eps tenant (1.08M uids).
    #[test]
    #[ignore]
    fn late_tier_latency_probe() {
        let dir = tempfile::tempdir().unwrap();
        let n = 1_080_000_u64;
        let keys = (0..n).map(key).collect::<Vec<_>>();
        let started = std::time::Instant::now();
        let run = Run::write(dir.path(), keys.clone()).unwrap();
        let write = started.elapsed();
        let started = std::time::Instant::now();
        let reloaded = Run::load(&run.path).unwrap();
        let load = started.elapsed();
        let probes = 100_000_u64;
        let started = std::time::Instant::now();
        let misses = (n..n + probes)
            .filter(|i| reloaded.contains(&key(*i)).unwrap())
            .count();
        let miss = started.elapsed();
        let started = std::time::Instant::now();
        let hits = (0..probes)
            .filter(|i| reloaded.contains(&keys[*i as usize]).unwrap())
            .count();
        let hit = started.elapsed();
        assert_eq!((misses, hits), (0, probes as usize));
        eprintln!(
            "uids={n} bloom_bytes={} run_bytes={} write={write:?} reload={load:?} miss={:?}/lookup hit={:?}/lookup (miss includes the SHA-256 of the probe key)",
            reloaded.bloom.bytes(),
            n * RUN_BYTES_PER_UID,
            miss / probes as u32,
            hit / probes as u32,
        );
    }

    #[tokio::test]
    async fn spilled_hours_reload_and_age_out() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000 * 3_600_000_i64;
        let hour = 1_000 - 10;
        let mut tier = LateUidTier::open(dir.path(), "t", MIN_BLOOM_BUDGET_BYTES, now);
        while !tier.ready() {
            tier.poll(now).await;
            tokio::task::yield_now().await;
        }
        let uids = (0..100).map(|n| (key(n), 0_u64)).collect::<HashMap<_, _>>();
        tier.spill(
            EvictedHour {
                hour,
                uids,
                parts: HashSet::from(["p1".to_string()]),
            },
            now,
        );
        while !tier.has_hour(hour) {
            tier.poll(now).await;
            tokio::task::yield_now().await;
        }
        assert!(tier.covers(hour, "p1") && !tier.covers(hour, "p2"));
        assert!(tier.contains(hour, &key(5)) && !tier.contains(hour, &key(500)));
        assert!(tier.inherit(hour, &["p1"], "p3"));
        assert!(!tier.inherit(hour, &["p1", "p2"], "p4"));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // A new process re-reads the runs and the inherited coverage.
        let mut again = LateUidTier::open(dir.path(), "t", MIN_BLOOM_BUDGET_BYTES, now);
        assert!(
            !again.contains(hour, &key(5)),
            "nothing answers before the reload"
        );
        while !again.ready() {
            again.poll(now).await;
            tokio::task::yield_now().await;
        }
        assert!(again.contains(hour, &key(5)) && again.covers(hour, "p3"));

        // Past the horizon the hour is gone, memory and disk.
        let later = hour_end_ms(hour) + HORIZON_MS + 1;
        again.poll(later).await;
        assert!(!again.has_hour(hour));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!dir
            .path()
            .join("late-uids/t")
            .join(hour.to_string())
            .exists());
    }

    #[tokio::test]
    async fn over_budget_drops_the_oldest_hour() {
        let dir = tempfile::tempdir().unwrap();
        let now = 1_000 * 3_600_000_i64;
        let mut tier = LateUidTier::open(dir.path(), "t", 2_000, now);
        for (hour, base) in [(990, 0_u64), (995, 10_000)] {
            let uids = (base..base + 1_000)
                .map(|n| (key(n), 0_u64))
                .collect::<HashMap<_, _>>();
            tier.spill(
                EvictedHour {
                    hour,
                    uids,
                    parts: HashSet::from([format!("p{hour}")]),
                },
                now,
            );
        }
        for _ in 0..1_000 {
            tier.poll(now).await;
            if tier.stats().spills_total == 2 && tier.writes.is_empty() && tier.ready() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
        assert!(!tier.has_hour(990) && tier.has_hour(995));
        assert_eq!(tier.stats().hours_dropped_over_budget_total, 1);
        assert!(tier.stats().bloom_bytes <= 2_000);
    }
}
