// SPDX-License-Identifier: AGPL-3.0-or-later

//! Durable exact OCSF UID claims across independent Bronze publish cycles.
//!
//! Vector delivers Bronze with at-least-once semantics. Batch-local admission
//! removes retries that happen to land together, but a lost HTTP response can
//! place the same stable `metadata.uid` in two later objects and therefore two
//! different Iceberg packs. This ledger makes the first source identity claim
//! durable before staged bytes become visible. It is sharded by the same stable
//! UID hash as Vector, so one publisher owns one exact keyspace.

use anyhow::{bail, Context, Result};
use futures::{StreamExt, TryStreamExt};
use sha2::{Digest, Sha256};
use slatedb::config::{
    CompressionCodec, FlushOptions, FlushType, ObjectStoreCacheOptions, ScanOptions, Settings,
    WriteOptions,
};
use slatedb::db_cache::foyer::{FoyerCache, FoyerCacheOptions};
use slatedb::db_cache::{DbCache, SplitCache};
use slatedb::object_store::ObjectStore;
use slatedb::{Db, WriteBatch};
use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const CLAIM_SCHEMA: u8 = 1;
const CLAIM_VALUE_BYTES: usize = 1 + 32 + 32;
const LEDGER_METADATA_KEY: &[u8] = b"nano:bronze-uid-ledger:metadata";
const LEDGER_METADATA_VALUE: &[u8] = b"v1";
pub const MAX_UID_LEDGER_READ_CONCURRENCY: usize = 1_024;
pub const MAX_UID_LEDGER_NEGATIVE_CACHE_CAPACITY: u64 = 2_000_000_000;
const CLAIM_ACCOUNTED_BYTES: u64 = (32 + CLAIM_VALUE_BYTES) as u64;
const MEMTABLE_FLUSH_BYTES: u64 = 32 * 1024 * 1024;
const UID_NEGATIVE_CACHE_BITS_PER_KEY: u64 = 10;
const UID_NEGATIVE_CACHE_HASHES: u64 = 7;

/// The tenant's whole object namespace under the `uid_ledger_rw` credential:
/// exactly the `canonical_prefix` control mints that class with
/// (`EnterpriseSharedR2CredentialClass::UidLedgerRw` and the recovery issuer),
/// derived from the same logical tenant key. Everything the publisher writes
/// with the UID-ledger credential -- the SlateDB ledger and the platform
/// stamping journal (NAN-2786) -- must live under it, or the provider refuses
/// the request once a properly scoped credential is installed.
pub fn uid_ledger_tenant_prefix(logical_tenant_key: &str) -> String {
    format!(
        "bronze-uid-ledger-v1/tenant_sha256={}/",
        hex::encode(Sha256::digest(logical_tenant_key.as_bytes()))
    )
}

// NAN-2361 fast restart: the complete-accelerator rebuild is a full ledger scan
// (~10 M claims, ~1.5 GB of SSTs after six days at 300 eps). It used to run
// as one serial iterator with SlateDB's default one-block read-ahead, and it
// blocked the publisher for ~250 s on every pod start. Now it runs beside
// publishing (see `UidNegativeCache`), in parallel. Claim keys are SHA-256
// digests, so equal-width key-prefix partitions carry equal work. Peak scan
// prefetch is bounded by partitions x open SSTs x fetch tasks x read-ahead
// (8 x SSTs x 2 MiB), well under the second full-size bitset the old swap-in
// rebuild allocated and this one no longer needs.
const UID_REBUILD_PARTITIONS: usize = 8;
const UID_REBUILD_READ_AHEAD_BYTES: usize = 1024 * 1024;
const UID_REBUILD_FETCH_TASKS: usize = 2;
const UID_REBUILD_INSERT_CHUNK: usize = 8_192;
const UID_REBUILD_RETRY_DELAY: Duration = Duration::from_secs(30);
// Do not inherit SlateDB's 640-MiB decoded-cache default invisibly. Most UID
// claims are negative point lookups, so every lookup consults SST Bloom/index
// metadata while almost never reading a data block. Keep the proven 320-MiB
// per-shard total, but reserve most of it for metadata. A 64-MiB metadata cache
// crossed its working-set boundary in the sustained NAN-2361 gate: old shards
// fell below their routed input rate while young shards with the same CPU and
// object store remained healthy. Spending the same bytes on blocks merely
// hid that history-dependent service-rate failure.
const UID_LEDGER_BLOCK_CACHE_BYTES: u64 = 64 * 1024 * 1024;
const UID_LEDGER_META_CACHE_BYTES: u64 = 256 * 1024 * 1024;
const UID_LEDGER_DECODED_CACHE_BYTES: u64 = 320 * 1024 * 1024;
const UID_LEDGER_CACHE_SHARDS: usize = 8;
const _: () = assert!(
    UID_LEDGER_BLOCK_CACHE_BYTES + UID_LEDGER_META_CACHE_BYTES == UID_LEDGER_DECODED_CACHE_BYTES
);

#[derive(Debug)]
pub struct BronzeUidClaimResult {
    pub claimed_uids: BTreeSet<String>,
    /// Existing UIDs whose preserved semantic digest differs from this row.
    /// They remain owned by the first claimant and are never overwritten, but
    /// do not prevent independent rows in the same immutable source object
    /// from being claimed and published.
    pub conflicting_uids: BTreeSet<String>,
    pub new_claims: usize,
    pub duplicate_rows_removed: u64,
    /// Exact SlateDB point reads that remained after the complete negative
    /// accelerator ruled out definitely-absent keys. Until the accelerator
    /// is complete every UID is an exact ledger read.
    pub ledger_reads: usize,
    /// History-independent point reads skipped without weakening exactness.
    pub negative_cache_misses_avoided: usize,
    /// Whether the negative accelerator was authoritative for this batch.
    pub negative_cache_complete: bool,
}

/// Where one complete accelerator rebuild spent its time.
#[derive(Debug, Clone, Copy)]
pub struct UidNegativeCacheRebuild {
    pub rebuilt_claims: u64,
    pub partitions: usize,
    pub wall_ms: u64,
    /// Summed across partitions: time awaiting SlateDB's iterator (object
    /// store I/O, block decompression and the k-way merge).
    pub scan_wait_ms: u64,
    /// Summed across partitions: time hashing keys into the Bloom bitset.
    pub insert_ms: u64,
}

pub struct BronzeUidLedger {
    database: Db,
    read_concurrency: usize,
    negative_cache: Arc<UidNegativeCache>,
    initialized: AtomicBool,
    unflushed_claim_bytes: AtomicU64,
}

/// A Bloom accelerator for exact negative lookups.
///
/// Bits are only ever set, never cleared. A negative result is definitive
/// only once `complete` is set, and `complete` is set only after one full
/// successful scan that began after this writer opened the ledger. Until then
/// every UID is an exact ledger read, so the publisher can serve immediately
/// after a restart while the scan runs in the background.
///
/// Why a complete accelerator never misses a durable claim `k`:
/// * `k` durable before this writer opened the ledger: SlateDB's open replays
///   every durable WAL entry, so every later scan observes `k`; the rebuild
///   partitions cover the whole key space; the rebuild sets `k`'s bits before
///   `complete` is published (Release, observed with Acquire).
/// * `k` claimed by this writer: `claim_batch` sets `k`'s bits before the
///   durable write, whether or not a rebuild is running, and a rebuild never
///   clears bits. Merging the scan into this same bitset is what makes a
///   concurrent claim safe; building a separate bitset and swapping it in
///   would lose claims made during the scan.
/// * A previous writer cannot add claims after this open: SlateDB fences it
///   and the PostgreSQL advisory lock admits one publisher per shard.
///
/// Positive results always fall through to SlateDB, so false positives,
/// partial scans and a failed rebuild cost only latency. A filter answer can
/// never drop an event: only a ledger read that returns the key can.
struct UidNegativeCache {
    bits: Vec<AtomicU64>,
    bit_count: u64,
    capacity: u64,
    inserted: AtomicU64,
    complete: AtomicBool,
    capacity_warning_emitted: AtomicBool,
}

impl UidNegativeCache {
    fn new(capacity: u64) -> Result<Self> {
        if !(1..=MAX_UID_LEDGER_NEGATIVE_CACHE_CAPACITY).contains(&capacity) {
            bail!("Bronze UID negative-cache capacity is outside its safety ceiling");
        }
        let bit_count = capacity
            .checked_mul(UID_NEGATIVE_CACHE_BITS_PER_KEY)
            .context("Bronze UID negative-cache bit count overflow")?;
        let words = usize::try_from(bit_count.div_ceil(64))?;
        let mut bits = Vec::new();
        bits.try_reserve_exact(words)
            .context("reserve Bronze UID negative-cache memory")?;
        bits.resize_with(words, || AtomicU64::new(0));
        Ok(Self {
            bits,
            bit_count,
            capacity,
            inserted: AtomicU64::new(0),
            complete: AtomicBool::new(false),
            capacity_warning_emitted: AtomicBool::new(false),
        })
    }

    /// True when a ledger read is required: either the accelerator is not yet
    /// complete, or the key may be present.
    fn must_read(&self, key: &[u8; 32], complete: bool) -> bool {
        !complete || self.might_contain(key)
    }

    fn is_complete(&self) -> bool {
        self.complete.load(Ordering::Acquire)
    }

    fn might_contain(&self, key: &[u8; 32]) -> bool {
        let (first, step) = bloom_hashes(key);
        (0..UID_NEGATIVE_CACHE_HASHES).all(|index| {
            let bit = first.wrapping_add(index.wrapping_mul(step)) % self.bit_count;
            self.bits[(bit / 64) as usize].load(Ordering::Relaxed) & (1_u64 << (bit % 64)) != 0
        })
    }

    fn insert(&self, key: &[u8; 32]) {
        let (first, step) = bloom_hashes(key);
        for index in 0..UID_NEGATIVE_CACHE_HASHES {
            let bit = first.wrapping_add(index.wrapping_mul(step)) % self.bit_count;
            self.bits[(bit / 64) as usize].fetch_or(1_u64 << (bit % 64), Ordering::Relaxed);
        }
    }

    /// Count claims for the capacity warning. The count may double-count a
    /// claim that both the rebuild scan and a concurrent `claim_batch` saw;
    /// it is advisory only and never consulted for exactness.
    fn account(&self, claims: u64) {
        let inserted = self
            .inserted
            .fetch_add(claims, Ordering::Relaxed)
            .saturating_add(claims);
        if inserted > self.capacity && !self.capacity_warning_emitted.swap(true, Ordering::Relaxed)
        {
            tracing::warn!(
                inserted_claims = inserted,
                negative_cache_capacity = self.capacity,
                "Bronze UID negative lookup accelerator exceeds its planned capacity; exactness is preserved but false-positive ledger reads will rise"
            );
        }
    }

    fn bytes(&self) -> usize {
        self.bits.len() * std::mem::size_of::<u64>()
    }
}

/// Drain one partition scan into the shared bitset. Returns claims inserted,
/// time awaiting the iterator, and time hashing.
async fn rebuild_partition(
    mut scan: slatedb::DbIterator,
    cache: Arc<UidNegativeCache>,
) -> Result<(u64, Duration, Duration)> {
    let (mut claims, mut wait, mut insert) = (0_u64, Duration::ZERO, Duration::ZERO);
    let mut chunk = Vec::with_capacity(UID_REBUILD_INSERT_CHUNK);
    loop {
        let waited = Instant::now();
        let entry = scan
            .next()
            .await
            .context("read durable Bronze UID claim during negative-cache rebuild")?;
        wait += waited.elapsed();
        let done = entry.is_none();
        if let Some(entry) = entry {
            if entry.key.as_ref() != LEDGER_METADATA_KEY {
                let key: [u8; 32] = entry.key.as_ref().try_into().map_err(|_| {
                    anyhow::anyhow!("Bronze UID ledger contains an unsupported key schema")
                })?;
                chunk.push(key);
            }
        }
        if chunk.len() >= UID_REBUILD_INSERT_CHUNK || (done && !chunk.is_empty()) {
            let inserting = Instant::now();
            for key in &chunk {
                cache.insert(key);
            }
            insert += inserting.elapsed();
            claims += chunk.len() as u64;
            chunk.clear();
        }
        if done {
            return Ok((claims, wait, insert));
        }
    }
}

/// Contiguous key ranges that together cover every possible key exactly once:
/// the first is unbounded below, the last unbounded above, and each boundary
/// is the excluded end of one range and the included start of the next.
type KeyRange = (Bound<Vec<u8>>, Bound<Vec<u8>>);

fn rebuild_partitions(partitions: usize) -> Vec<KeyRange> {
    assert!((1..=65_536).contains(&partitions));
    let boundaries = (1..partitions)
        .map(|index| {
            let prefix = u16::try_from(index * 65_536 / partitions).expect("prefix fits u16");
            prefix.to_be_bytes().to_vec()
        })
        .collect::<Vec<_>>();
    (0..partitions)
        .map(|index| {
            let start = match index {
                0 => Bound::Unbounded,
                _ => Bound::Included(boundaries[index - 1].clone()),
            };
            let end = match boundaries.get(index) {
                Some(boundary) => Bound::Excluded(boundary.clone()),
                None => Bound::Unbounded,
            };
            (start, end)
        })
        .collect()
}

fn bloom_hashes(key: &[u8; 32]) -> (u64, u64) {
    let mut first = [0_u8; 8];
    first.copy_from_slice(&key[..8]);
    let mut second = [0_u8; 8];
    second.copy_from_slice(&key[8..16]);
    // Keep the second hash non-zero so the seven probes cannot collapse onto
    // one bit even for an adversarially chosen digest.
    (u64::from_le_bytes(first), u64::from_le_bytes(second) | 1)
}

impl BronzeUidLedger {
    pub async fn open(
        database_path: &str,
        object_store: Arc<dyn ObjectStore>,
        cache_directory: Option<&Path>,
        cache_bytes: usize,
        read_concurrency: usize,
        negative_cache_capacity: u64,
    ) -> Result<Self> {
        if database_path.is_empty()
            || database_path.len() > 1_024
            || database_path.starts_with('/')
            || database_path.chars().any(char::is_control)
            || database_path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || cache_directory.is_some() != (cache_bytes > 0)
            || !(1..=MAX_UID_LEDGER_READ_CONCURRENCY).contains(&read_concurrency)
            || !(1..=MAX_UID_LEDGER_NEGATIVE_CACHE_CAPACITY).contains(&negative_cache_capacity)
        {
            bail!("Bronze UID ledger storage boundary is invalid");
        }
        if let Some(directory) = cache_directory {
            if !directory.is_absolute() {
                bail!("Bronze UID ledger cache must be an absolute path");
            }
            std::fs::create_dir_all(directory).with_context(|| {
                format!("create Bronze UID ledger cache {}", directory.display())
            })?;
        }
        let mut settings = Settings {
            // Durability is one explicit WAL flush per non-empty Bronze
            // transaction. A 100-ms background flusher across every idle
            // shard would turn an implementation default into hidden S3
            // request spend without improving this protocol's acknowledgement
            // boundary.
            flush_interval: None,
            manifest_poll_interval: std::time::Duration::from_secs(30),
            idle_manifest_poll_interval: Some(std::time::Duration::from_secs(300)),
            l0_sst_size_bytes: MEMTABLE_FLUSH_BYTES as usize,
            max_unflushed_bytes: 256 * 1024 * 1024,
            compression_codec: Some(CompressionCodec::Zstd),
            object_store_max_retries: Some(8),
            ..Settings::default()
        };
        configure_uid_background_polling(&mut settings);
        settings.object_store_cache_options = ObjectStoreCacheOptions {
            root_folder: cache_directory.map(PathBuf::from),
            max_cache_size_bytes: (cache_bytes > 0).then_some(cache_bytes),
            cache_on_flush: cache_bytes > 0,
            cache_on_compaction: cache_bytes > 0,
            ..ObjectStoreCacheOptions::default()
        };
        tracing::info!(
            decoded_block_cache_bytes = UID_LEDGER_BLOCK_CACHE_BYTES,
            decoded_meta_cache_bytes = UID_LEDGER_META_CACHE_BYTES,
            decoded_cache_shards = UID_LEDGER_CACHE_SHARDS,
            disk_object_cache_bytes = cache_bytes,
            read_concurrency,
            negative_cache_capacity,
            "opening Bronze UID ledger with explicit cache bounds"
        );
        let database = Db::builder(database_path, object_store)
            .with_settings(settings)
            .with_db_cache(uid_ledger_db_cache())
            .build()
            .await
            .context("open durable Bronze UID claim ledger")?;
        Ok(Self {
            database,
            read_concurrency,
            negative_cache: Arc::new(UidNegativeCache::new(negative_cache_capacity)?),
            initialized: AtomicBool::new(false),
            unflushed_claim_bytes: AtomicU64::new(0),
        })
    }

    /// Establish the ledger only for a tenant/store with no published Bronze
    /// history. A missing marker beside existing PostgreSQL receipts means the
    /// object-store ledger was deleted or this is an unsafe in-place upgrade;
    /// proceeding would admit a replay of any historical UID as new.
    pub async fn verify_or_initialize(&self, published_history_exists: bool) -> Result<()> {
        match self
            .database
            .get(LEDGER_METADATA_KEY)
            .await
            .context("read Bronze UID ledger initialization marker")?
        {
            Some(value) if value.as_ref() == LEDGER_METADATA_VALUE => {}
            Some(_) => bail!("Bronze UID ledger initialization marker has an unsupported schema"),
            None if published_history_exists => bail!(
                "Bronze UID ledger is absent beside published history; clean-bootstrap or backfill the tenant/store before starting this publisher"
            ),
            None => {
                let mut writes = WriteBatch::new();
                writes.put(LEDGER_METADATA_KEY, LEDGER_METADATA_VALUE);
                self.database
                    .write_with_options(
                        writes,
                        &WriteOptions {
                            await_durable: false,
                            ..WriteOptions::default()
                        },
                    )
                    .await
                    .context("buffer Bronze UID ledger initialization marker")?;
                self.database
                    .flush()
                    .await
                    .context("durably flush Bronze UID ledger initialization marker")?;
            }
        }
        // The accelerator stays incomplete (every UID an exact ledger read)
        // until `rebuild_negative_cache` finishes; the publisher need not wait.
        self.initialized.store(true, Ordering::Release);
        Ok(())
    }

    /// Whether negative accelerator answers are currently authoritative.
    pub fn negative_cache_complete(&self) -> bool {
        self.negative_cache.is_complete()
    }

    /// Rebuild the negative accelerator from every durable claim, retrying
    /// until it succeeds. Safe to run concurrently with `claim_batch`; see
    /// `UidNegativeCache` for the exactness argument.
    pub async fn complete_negative_cache(&self) {
        // Checked each pass so an already-complete accelerator ends the loop
        // instead of retrying the "already complete" refusal forever.
        while !self.negative_cache.is_complete() {
            match self.rebuild_negative_cache().await {
                Ok(_) => return,
                Err(error) => {
                    tracing::warn!(
                        error = format!("{error:#}"),
                        retry_after_s = UID_REBUILD_RETRY_DELAY.as_secs(),
                        "Bronze UID negative lookup accelerator rebuild failed; every UID stays an exact ledger read until a rebuild completes"
                    );
                    tokio::time::sleep(UID_REBUILD_RETRY_DELAY).await;
                }
            }
        }
    }

    /// One full parallel scan of the durable ledger into the live bitset.
    /// Marks the accelerator complete only when every partition succeeded.
    pub async fn rebuild_negative_cache(&self) -> Result<UidNegativeCacheRebuild> {
        self.rebuild_negative_cache_with_hook(async {}).await
    }

    /// `after_scans_open` runs once every partition iterator exists and before
    /// any is drained, so tests can claim keys a scan snapshot cannot see.
    async fn rebuild_negative_cache_with_hook(
        &self,
        after_scans_open: impl std::future::Future<Output = ()>,
    ) -> Result<UidNegativeCacheRebuild> {
        if !self.initialized.load(Ordering::Acquire) {
            bail!("Bronze UID ledger was not verified against publication history");
        }
        if self.negative_cache.is_complete() {
            bail!("Bronze UID negative lookup accelerator is already complete");
        }
        let started = Instant::now();
        let options = ScanOptions {
            read_ahead_bytes: UID_REBUILD_READ_AHEAD_BYTES,
            max_fetch_tasks: UID_REBUILD_FETCH_TASKS,
            // One pass over history must not evict the point-lookup working set.
            cache_blocks: false,
            ..ScanOptions::default()
        };
        let partitions = rebuild_partitions(UID_REBUILD_PARTITIONS);
        let mut scans = Vec::with_capacity(partitions.len());
        for range in partitions {
            scans.push(
                self.database
                    .scan_with_options(range, &options)
                    .await
                    .context("scan durable Bronze UID claims for negative-cache rebuild")?,
            );
        }
        after_scans_open.await;
        // One task per partition so block decompression and the k-way merge
        // use every core the pod is granted. Dropping the JoinSet (an aborted
        // rebuild or an early error) aborts every partition task.
        let mut tasks = tokio::task::JoinSet::new();
        for scan in scans {
            tasks.spawn(rebuild_partition(scan, Arc::clone(&self.negative_cache)));
        }
        let mut totals = Vec::with_capacity(UID_REBUILD_PARTITIONS);
        while let Some(joined) = tasks.join_next().await {
            totals.push(joined.context("join Bronze UID negative-cache rebuild partition")??);
        }
        let cache = &self.negative_cache;
        let rebuilt_claims = totals.iter().map(|(claims, _, _)| claims).sum::<u64>();
        cache.account(rebuilt_claims);
        // Every partition task was joined successfully, so each bit it set
        // happens-before this Release store.
        cache.complete.store(true, Ordering::Release);
        let report = UidNegativeCacheRebuild {
            rebuilt_claims,
            partitions: totals.len(),
            wall_ms: started.elapsed().as_millis() as u64,
            scan_wait_ms: totals
                .iter()
                .map(|(_, wait, _)| wait.as_millis() as u64)
                .sum(),
            insert_ms: totals
                .iter()
                .map(|(_, _, insert)| insert.as_millis() as u64)
                .sum(),
        };
        tracing::info!(
            rebuilt_claims = report.rebuilt_claims,
            rebuild_partitions = report.partitions,
            negative_cache_capacity = cache.capacity,
            negative_cache_bytes = cache.bytes(),
            rebuild_ms = report.wall_ms,
            rebuild_scan_wait_ms = report.scan_wait_ms,
            rebuild_insert_ms = report.insert_ms,
            "rebuilt complete Bronze UID negative lookup accelerator"
        );
        Ok(report)
    }

    /// Claim every previously unseen UID for one already-reserved source
    /// batch. Reopening the same pending batch retains its own claims; an
    /// identical UID owned by an earlier batch is omitted; a changed source
    /// identity remains fail-closed for that UID while independent rows in the
    /// same immutable source object continue through the normal claim path.
    ///
    /// The publisher's PostgreSQL lifetime advisory lock guarantees a single
    /// caller for this shard. One atomic SlateDB write followed by an explicit
    /// WAL flush therefore closes the read-before-write gap without one
    /// PostgreSQL row per event.
    pub async fn claim_batch(
        &self,
        claim_owner_sha256: &str,
        identities: &BTreeMap<String, [u8; 32]>,
    ) -> Result<BronzeUidClaimResult> {
        if !self.initialized.load(Ordering::Acquire) {
            bail!("Bronze UID ledger was not verified against publication history");
        }
        let owner = decode_digest(claim_owner_sha256, "claim owner")?;
        if identities.is_empty() || identities.len() > crate::bronze::MAX_BRONZE_ROWS {
            bail!("Bronze UID claim batch cardinality is invalid");
        }

        // Read once per batch: a rebuild completing mid-batch only means this
        // batch conservatively reads the ledger for more keys.
        let negative_cache_complete = self.negative_cache.is_complete();
        let candidates = identities
            .iter()
            .map(|(uid, semantic)| {
                let key = claim_key(uid);
                let must_read = self.negative_cache.must_read(&key, negative_cache_complete);
                (uid.clone(), *semantic, key, must_read)
            })
            .collect::<Vec<_>>();
        let ledger_reads = candidates
            .iter()
            .filter(|(_, _, _, might_contain)| *might_contain)
            .count();
        let reads = futures::stream::iter(candidates.into_iter().map(
            |(uid, semantic, key, might_contain)| async move {
                let existing = if might_contain {
                    self.database
                        .get(key)
                        .await
                        .context("read durable Bronze UID claim")?
                } else {
                    None
                };
                Ok::<_, anyhow::Error>((uid, semantic, key, existing))
            },
        ))
        .buffer_unordered(self.read_concurrency)
        .try_collect::<Vec<_>>()
        .await?;

        let mut writes = WriteBatch::new();
        let mut claimed_uids = BTreeSet::new();
        let mut conflicting_uids = BTreeSet::new();
        let mut duplicate_rows_removed = 0_u64;
        let mut new_claims = 0_usize;
        let mut new_keys = Vec::new();
        for (uid, semantic, key, existing) in reads {
            match existing {
                None => {
                    writes.put(key, encode_claim(semantic, owner));
                    new_keys.push(key);
                    claimed_uids.insert(uid);
                    new_claims += 1;
                }
                Some(value) => {
                    let (existing_semantic, existing_owner) = decode_claim(&value)?;
                    if existing_semantic != semantic {
                        conflicting_uids.insert(uid);
                        continue;
                    }
                    if existing_owner == owner {
                        // The process failed after the durable claim but before
                        // PostgreSQL acknowledged this exact source batch.
                        claimed_uids.insert(uid);
                    } else {
                        duplicate_rows_removed = duplicate_rows_removed
                            .checked_add(1)
                            .context("cross-cycle duplicate row count overflow")?;
                    }
                }
            }
        }
        if new_claims > 0 {
            // Insert before the durable write, also while a rebuild is still
            // scanning. A failed write can then create only a safe false
            // positive on retry; inserting afterward could create a false
            // negative if the durability result were ambiguous.
            for key in &new_keys {
                self.negative_cache.insert(key);
            }
            self.negative_cache.account(u64::try_from(new_keys.len())?);
            self.database
                .write_with_options(
                    writes,
                    &WriteOptions {
                        await_durable: false,
                        ..WriteOptions::default()
                    },
                )
                .await
                .context("buffer Bronze UID claims")?;
            self.database
                .flush()
                .await
                .context("durably flush Bronze UID claim WAL")?;
            let added = u64::try_from(new_claims)?
                .checked_mul(CLAIM_ACCOUNTED_BYTES)
                .context("Bronze UID claim memory accounting overflow")?;
            let unflushed = self
                .unflushed_claim_bytes
                .fetch_add(added, Ordering::Relaxed)
                .saturating_add(added);
            if unflushed >= MEMTABLE_FLUSH_BYTES {
                self.database
                    .flush_with_options(FlushOptions {
                        flush_type: FlushType::MemTable,
                    })
                    .await
                    .context("flush Bronze UID claims into a compactable SST")?;
                self.unflushed_claim_bytes.store(0, Ordering::Relaxed);
            }
        }
        Ok(BronzeUidClaimResult {
            claimed_uids,
            conflicting_uids,
            new_claims,
            duplicate_rows_removed,
            ledger_reads,
            negative_cache_misses_avoided: identities.len().saturating_sub(ledger_reads),
            negative_cache_complete,
        })
    }

    pub async fn close(&self) -> Result<()> {
        self.database
            .close()
            .await
            .context("close durable Bronze UID claim ledger")
    }
}

fn configure_uid_background_polling(settings: &mut Settings) {
    if let Some(compactor) = settings.compactor_options.as_mut() {
        compactor.idle_poll_interval = Some(std::time::Duration::from_secs(60));
        if let Some(worker) = compactor.worker.as_mut() {
            worker.idle_compactions_poll_interval = Some(std::time::Duration::from_secs(60));
        }
    }
    if let Some(gc) = settings.garbage_collector_options.as_mut() {
        for directory in [
            &mut gc.manifest_options,
            &mut gc.wal_options,
            &mut gc.wal_fence_options,
            &mut gc.compacted_options,
            &mut gc.compactions_options,
        ] {
            if let Some(options) = directory.as_mut() {
                options.interval = Some(std::time::Duration::from_secs(600));
            }
        }
        if let Some(options) = gc.detach_options.as_mut() {
            options.interval = Some(std::time::Duration::from_secs(600));
        }
    }
}

fn uid_ledger_db_cache() -> Arc<dyn DbCache> {
    let block_cache: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
        max_capacity: UID_LEDGER_BLOCK_CACHE_BYTES,
        shards: UID_LEDGER_CACHE_SHARDS,
    }));
    let meta_cache: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
        max_capacity: UID_LEDGER_META_CACHE_BYTES,
        shards: UID_LEDGER_CACHE_SHARDS,
    }));
    Arc::new(
        SplitCache::new()
            .with_block_cache(Some(block_cache))
            .with_meta_cache(Some(meta_cache))
            .build(),
    )
}

fn claim_key(uid: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"nano:bronze-uid-claim:v1\0");
    digest.update(uid.as_bytes());
    digest.finalize().into()
}

fn encode_claim(semantic: [u8; 32], owner: [u8; 32]) -> [u8; CLAIM_VALUE_BYTES] {
    let mut value = [0_u8; CLAIM_VALUE_BYTES];
    value[0] = CLAIM_SCHEMA;
    value[1..33].copy_from_slice(&semantic);
    value[33..].copy_from_slice(&owner);
    value
}

fn decode_claim(value: &[u8]) -> Result<([u8; 32], [u8; 32])> {
    if value.len() != CLAIM_VALUE_BYTES || value[0] != CLAIM_SCHEMA {
        bail!("durable Bronze UID claim has an unsupported schema");
    }
    let mut semantic = [0_u8; 32];
    semantic.copy_from_slice(&value[1..33]);
    let mut owner = [0_u8; 32];
    owner.copy_from_slice(&value[33..]);
    Ok((semantic, owner))
}

fn decode_digest(value: &str, name: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("Bronze UID ledger {name} digest is invalid");
    }
    let decoded = hex::decode(value)?;
    let mut digest = [0_u8; 32];
    digest.copy_from_slice(&decoded);
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use slatedb::object_store::memory::InMemory;

    #[test]
    fn background_polling_preserves_active_intervals_and_gc_safety() {
        let mut settings = Settings::default();
        let before = settings.clone();
        configure_uid_background_polling(&mut settings);
        let compactor = settings.compactor_options.unwrap();
        assert_eq!(compactor.poll_interval.as_secs(), 5);
        assert_eq!(compactor.idle_poll_interval.unwrap().as_secs(), 60);
        assert_eq!(
            compactor.worker_heartbeat_timeout,
            before.compactor_options.unwrap().worker_heartbeat_timeout
        );
        let worker = compactor.worker.unwrap();
        assert_eq!(worker.compactions_poll_interval.as_secs(), 5);
        assert_eq!(worker.idle_compactions_poll_interval.unwrap().as_secs(), 60);
        assert_eq!(worker.heartbeat_interval.as_secs(), 10);
        let gc = settings.garbage_collector_options.unwrap();
        let old = before.garbage_collector_options.unwrap();
        for (new, old) in [
            (gc.manifest_options, old.manifest_options),
            (gc.wal_options, old.wal_options),
            (gc.wal_fence_options, old.wal_fence_options),
            (gc.compacted_options, old.compacted_options),
            (gc.compactions_options, old.compactions_options),
        ] {
            let (new, old) = (new.unwrap(), old.unwrap());
            assert_eq!(new.interval.unwrap().as_secs(), 600);
            assert_eq!(new.min_age, old.min_age);
            assert_eq!(new.dry_run, old.dry_run);
        }
        assert_eq!(gc.detach_options.unwrap().interval.unwrap().as_secs(), 600);
    }

    fn identities(values: &[(&str, u8)]) -> BTreeMap<String, [u8; 32]> {
        values
            .iter()
            .map(|(uid, digest)| ((*uid).to_string(), [*digest; 32]))
            .collect()
    }

    #[tokio::test]
    async fn exact_replay_across_cycles_is_removed_but_owner_retry_is_retained() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let ledger = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        ledger.verify_or_initialize(false).await.unwrap();
        ledger.rebuild_negative_cache().await.unwrap();
        let first = ledger
            .claim_batch(&"11".repeat(32), &identities(&[("a", 1), ("b", 2)]))
            .await
            .unwrap();
        assert_eq!(first.claimed_uids.len(), 2);
        assert!(first.conflicting_uids.is_empty());
        assert_eq!(first.duplicate_rows_removed, 0);
        assert_eq!(first.ledger_reads, 0);
        assert_eq!(first.negative_cache_misses_avoided, 2);

        let retry = ledger
            .claim_batch(&"11".repeat(32), &identities(&[("a", 1), ("b", 2)]))
            .await
            .unwrap();
        assert_eq!(retry.claimed_uids.len(), 2);
        assert!(retry.conflicting_uids.is_empty());
        assert_eq!(retry.duplicate_rows_removed, 0);
        assert_eq!(retry.ledger_reads, 2);
        assert_eq!(retry.negative_cache_misses_avoided, 0);

        let later = ledger
            .claim_batch(&"22".repeat(32), &identities(&[("a", 1), ("c", 3)]))
            .await
            .unwrap();
        assert_eq!(later.claimed_uids, BTreeSet::from(["c".to_string()]));
        assert!(later.conflicting_uids.is_empty());
        assert_eq!(later.duplicate_rows_removed, 1);
        assert_eq!(later.ledger_reads, 1);
        assert_eq!(later.negative_cache_misses_avoided, 1);
        ledger.close().await.unwrap();
    }

    #[tokio::test]
    async fn conflicting_cross_cycle_replay_is_excluded_without_blocking_new_rows() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let ledger = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        ledger.verify_or_initialize(false).await.unwrap();
        ledger
            .claim_batch(&"11".repeat(32), &identities(&[("a", 1)]))
            .await
            .unwrap();
        let result = ledger
            .claim_batch(&"22".repeat(32), &identities(&[("a", 2), ("new", 3)]))
            .await
            .unwrap();
        assert_eq!(result.conflicting_uids, BTreeSet::from(["a".to_string()]));
        assert_eq!(result.claimed_uids, BTreeSet::from(["new".to_string()]));
        assert_eq!(result.new_claims, 1);
        assert_eq!(result.duplicate_rows_removed, 0);

        let retry = ledger
            .claim_batch(&"22".repeat(32), &identities(&[("a", 2), ("new", 3)]))
            .await
            .unwrap();
        assert_eq!(retry.conflicting_uids, BTreeSet::from(["a".to_string()]));
        assert_eq!(retry.claimed_uids, BTreeSet::from(["new".to_string()]));
        assert_eq!(retry.new_claims, 0);
        ledger.close().await.unwrap();
    }

    #[tokio::test]
    async fn durable_claim_survives_writer_reopen() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let first = BronzeUidLedger::open("uid-ledger", store.clone(), None, 0, 32, 1_024)
            .await
            .unwrap();
        first.verify_or_initialize(false).await.unwrap();
        first
            .claim_batch(&"11".repeat(32), &identities(&[("a", 1)]))
            .await
            .unwrap();
        first.close().await.unwrap();

        let reopened = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        reopened.verify_or_initialize(true).await.unwrap();
        reopened.rebuild_negative_cache().await.unwrap();
        let result = reopened
            .claim_batch(&"22".repeat(32), &identities(&[("a", 1)]))
            .await
            .unwrap();
        assert!(result.claimed_uids.is_empty());
        assert!(result.conflicting_uids.is_empty());
        assert_eq!(result.duplicate_rows_removed, 1);
        assert_eq!(result.ledger_reads, 1);
        assert_eq!(result.negative_cache_misses_avoided, 0);
        reopened.close().await.unwrap();
    }

    #[test]
    fn negative_cache_never_reports_an_inserted_key_absent() {
        let cache = UidNegativeCache::new(1_024).unwrap();
        let absent = claim_key("not-yet-inserted");
        assert!(!cache.might_contain(&absent));
        let inserted = (0_u16..512)
            .map(|value| claim_key(&format!("uid-{value}")))
            .collect::<Vec<_>>();
        for key in &inserted {
            cache.insert(key);
        }
        assert!(inserted.iter().all(|key| cache.might_contain(key)));
        assert_eq!(cache.bytes(), 1_280);
    }

    fn process_cpu_ms() -> u64 {
        // SAFETY: getrusage only writes into the zeroed struct we own.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
        let ms = |tv: libc::timeval| tv.tv_sec as u64 * 1_000 + tv.tv_usec as u64 / 1_000;
        ms(usage.ru_utime) + ms(usage.ru_stime)
    }

    /// Restart-rebuild profile. Not a correctness test: run explicitly with
    /// `NANO_UID_BENCH_CLAIMS=2000000 cargo test --release -p nanosiem-lake-worker
    /// --lib uid_rebuild_profile -- --ignored --nocapture`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[ignore]
    async fn uid_rebuild_profile() {
        use slatedb::object_store::throttle::{ThrottleConfig, ThrottledStore};
        let claims: usize = std::env::var("NANO_UID_BENCH_CLAIMS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(1_000_000);
        let latency_ms: u64 = std::env::var("NANO_UID_BENCH_GET_MS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let byte_ns: u64 = std::env::var("NANO_UID_BENCH_GET_BYTE_NS")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(0);
        let memory: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let writer = BronzeUidLedger::open("uid-ledger", memory.clone(), None, 0, 64, 1 << 24)
            .await
            .unwrap();
        writer.verify_or_initialize(false).await.unwrap();
        let mut next = 0_usize;
        while next < claims {
            let end = (next + 100_000).min(claims);
            let batch = (next..end)
                .map(|value| (format!("uid-{value}"), [7_u8; 32]))
                .collect::<BTreeMap<_, _>>();
            writer
                .claim_batch(&format!("{:064x}", next), &batch)
                .await
                .unwrap();
            next = end;
        }
        writer.close().await.unwrap();
        let stored_bytes = memory
            .list(None)
            .map_ok(|meta| meta.size)
            .try_fold(0_u64, |total, size| async move { Ok(total + size) })
            .await
            .unwrap();
        eprintln!("PROFILE stored_bytes={stored_bytes}");
        for disk_cache in [false, true] {
            if latency_ms > 0 && !disk_cache {
                continue;
            }
            let throttled: Arc<dyn ObjectStore> = Arc::new(ThrottledStore::new(
                memory.clone(),
                ThrottleConfig {
                    wait_get_per_call: std::time::Duration::from_millis(latency_ms),
                    wait_get_per_byte: std::time::Duration::from_nanos(byte_ns),
                    ..ThrottleConfig::default()
                },
            ));
            let cache = tempfile::tempdir().unwrap();
            let (directory, bytes) = if disk_cache {
                (Some(cache.path()), 1_usize << 30)
            } else {
                (None, 0)
            };
            let ledger =
                BronzeUidLedger::open("uid-ledger", throttled, directory, bytes, 64, 1 << 25)
                    .await
                    .unwrap();
            let (wall, cpu) = (Instant::now(), process_cpu_ms());
            ledger.verify_or_initialize(true).await.unwrap();
            // Serving before the accelerator exists: every UID a ledger read.
            let owner = format!("{:064x}", u64::MAX - u64::from(disk_cache));
            let fresh = (0..10_000)
                .map(|value| (format!("fresh-{disk_cache}-{value}"), [9_u8; 32]))
                .collect::<BTreeMap<_, _>>();
            let replay = (0..10_000)
                .map(|value| (format!("uid-{}", value * 97 % claims), [7_u8; 32]))
                .collect::<BTreeMap<_, _>>();
            for (name, batch) in [("fresh", &fresh), ("replay", &replay)] {
                let started = Instant::now();
                let result = ledger.claim_batch(&owner, batch).await.unwrap();
                eprintln!(
                    "PROFILE incomplete_claim batch={name} rows={} ledger_reads={} ms={}",
                    batch.len(),
                    result.ledger_reads,
                    started.elapsed().as_millis()
                );
            }
            let report = ledger.rebuild_negative_cache().await.unwrap();
            eprintln!("PROFILE rebuild={report:?}");
            eprintln!(
                "PROFILE claims={claims} get_latency_ms={latency_ms} byte_ns={byte_ns} disk_cache={disk_cache} wall_ms={} cpu_ms={}",
                wall.elapsed().as_millis(),
                process_cpu_ms() - cpu
            );
            ledger.close().await.unwrap();
        }
    }

    async fn ledger_with_history(store: Arc<dyn ObjectStore>, uids: &[(&str, u8)]) {
        let writer = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        writer.verify_or_initialize(false).await.unwrap();
        writer
            .claim_batch(&"11".repeat(32), &identities(uids))
            .await
            .unwrap();
        writer.close().await.unwrap();
    }

    /// NAN-2361 fast restart: the publisher serves before the accelerator
    /// rebuild finishes. An incomplete accelerator must never answer
    /// "absent": a replay of a historical UID would be claimed a second time
    /// and published twice.
    #[tokio::test]
    async fn claims_before_the_rebuild_completes_read_the_ledger_for_every_uid() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        ledger_with_history(store.clone(), &[("a", 1), ("b", 2)]).await;

        let ledger = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        ledger.verify_or_initialize(true).await.unwrap();
        assert!(!ledger.negative_cache_complete());
        let early = ledger
            .claim_batch(
                &"22".repeat(32),
                &identities(&[("a", 1), ("b", 9), ("fresh", 3)]),
            )
            .await
            .unwrap();
        assert!(!early.negative_cache_complete);
        assert_eq!(
            early.ledger_reads, 3,
            "incomplete accelerator must not skip reads"
        );
        assert_eq!(early.negative_cache_misses_avoided, 0);
        assert_eq!(early.duplicate_rows_removed, 1, "historical replay removed");
        assert_eq!(early.conflicting_uids, BTreeSet::from(["b".to_string()]));
        assert_eq!(early.claimed_uids, BTreeSet::from(["fresh".to_string()]));

        let report = ledger.rebuild_negative_cache().await.unwrap();
        assert!(ledger.negative_cache_complete());
        // "a", "b" from history; "fresh" may or may not be in the scan
        // snapshot, but it is in the bitset either way.
        assert!(report.rebuilt_claims >= 2);
        assert_eq!(report.partitions, UID_REBUILD_PARTITIONS);
        let later = ledger
            .claim_batch(
                &"33".repeat(32),
                &identities(&[("a", 1), ("fresh", 3), ("never-seen", 4)]),
            )
            .await
            .unwrap();
        assert!(later.negative_cache_complete);
        assert_eq!(later.duplicate_rows_removed, 2);
        assert_eq!(
            later.claimed_uids,
            BTreeSet::from(["never-seen".to_string()])
        );
        assert_eq!(later.ledger_reads, 2);
        assert_eq!(later.negative_cache_misses_avoided, 1);
        assert!(
            ledger.rebuild_negative_cache().await.is_err(),
            "rebuild runs once"
        );
        ledger.close().await.unwrap();
    }

    /// Claims committed while the rebuild scans are open (and possibly
    /// outside their snapshots) must be in the accelerator once it is
    /// declared complete; otherwise their replays would be admitted.
    #[tokio::test]
    async fn claims_made_during_the_rebuild_are_in_the_complete_accelerator() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let history = (0..2_000)
            .map(|value| format!("history-{value}"))
            .collect::<Vec<_>>();
        let history_refs = history
            .iter()
            .map(|uid| (uid.as_str(), 1_u8))
            .collect::<Vec<_>>();
        ledger_with_history(store.clone(), &history_refs).await;

        let ledger = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        ledger.verify_or_initialize(true).await.unwrap();
        let late = (0..500)
            .map(|value| (format!("late-{value}"), [5_u8; 32]))
            .collect::<BTreeMap<_, _>>();
        let report = ledger
            .rebuild_negative_cache_with_hook(async {
                let claimed = ledger.claim_batch(&"44".repeat(32), &late).await.unwrap();
                assert!(!claimed.negative_cache_complete);
                assert_eq!(claimed.new_claims, 500);
            })
            .await
            .unwrap();
        assert!(report.rebuilt_claims >= 2_000);
        assert!(ledger.negative_cache_complete());
        for uid in history.iter().chain(late.keys()) {
            assert!(
                ledger.negative_cache.might_contain(&claim_key(uid)),
                "complete accelerator misses durable claim {uid}"
            );
        }
        let replay = ledger.claim_batch(&"55".repeat(32), &late).await.unwrap();
        assert!(replay.negative_cache_complete);
        assert_eq!(replay.new_claims, 0, "a late claim was re-admitted");
        assert_eq!(replay.duplicate_rows_removed, 500);
        ledger.close().await.unwrap();
    }

    #[test]
    fn rebuild_partitions_cover_every_key_exactly_once() {
        use std::ops::RangeBounds;
        for count in [1, 2, 3, 7, UID_REBUILD_PARTITIONS, 16, 64, 255] {
            let partitions = rebuild_partitions(count);
            assert_eq!(partitions.len(), count);
            let mut probes = vec![
                vec![],
                vec![0x00; 32],
                vec![0xff; 32],
                LEDGER_METADATA_KEY.to_vec(),
            ];
            for (start, end) in &partitions {
                for bound in [start, end] {
                    if let Bound::Included(key) | Bound::Excluded(key) = bound {
                        let mut below = key.clone();
                        // The largest key that sorts before the boundary.
                        let prefix = u16::from_be_bytes([below[0], below[1]]) - 1;
                        below = prefix.to_be_bytes().to_vec();
                        below.extend([0xff; 30]);
                        probes.extend([key.clone(), below, [key.clone(), vec![0; 30]].concat()]);
                    }
                }
            }
            probes.extend((0..512_u32).map(|value| claim_key(&value.to_string()).to_vec()));
            for probe in probes {
                let owners = partitions
                    .iter()
                    .filter(|(start, end)| {
                        RangeBounds::<Vec<u8>>::contains(&(start.clone(), end.clone()), &probe)
                    })
                    .count();
                assert_eq!(
                    owners, 1,
                    "key {probe:02x?} owned by {owners} of {count} partitions"
                );
            }
        }
    }

    #[tokio::test]
    async fn rebuild_covers_claims_at_the_edges_of_the_keyspace() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        ledger_with_history(store.clone(), &[("a", 1)]).await;
        let mut edges = vec![[0x00_u8; 32], [0xff_u8; 32]];
        for (start, _) in rebuild_partitions(UID_REBUILD_PARTITIONS).iter().skip(1) {
            let Bound::Included(boundary) = start else {
                unreachable!()
            };
            let mut at = [0_u8; 32];
            at[..2].copy_from_slice(boundary);
            let mut below = [0xff_u8; 32];
            below[..2].copy_from_slice(
                &(u16::from_be_bytes([boundary[0], boundary[1]]) - 1).to_be_bytes(),
            );
            edges.extend([at, below]);
        }
        {
            let raw = Db::builder("uid-ledger", store.clone())
                .build()
                .await
                .unwrap();
            for key in &edges {
                raw.put(key, encode_claim([1; 32], [1; 32])).await.unwrap();
            }
            raw.close().await.unwrap();
        }
        let ledger = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        ledger.verify_or_initialize(true).await.unwrap();
        let report = ledger.rebuild_negative_cache().await.unwrap();
        assert_eq!(report.rebuilt_claims, edges.len() as u64 + 1);
        for key in edges.iter().chain([&claim_key("a")]) {
            assert!(
                ledger.negative_cache.might_contain(key),
                "edge key {key:02x?} missed"
            );
        }
        ledger.close().await.unwrap();
    }

    #[tokio::test]
    async fn missing_ledger_beside_published_history_fails_closed() {
        let store: Arc<dyn ObjectStore> = Arc::new(InMemory::new());
        let ledger = BronzeUidLedger::open("uid-ledger", store, None, 0, 32, 1_024)
            .await
            .unwrap();
        let error = ledger.verify_or_initialize(true).await.unwrap_err();
        assert!(error
            .to_string()
            .contains("absent beside published history"));
        assert!(ledger
            .claim_batch(&"11".repeat(32), &identities(&[("a", 1)]))
            .await
            .unwrap_err()
            .to_string()
            .contains("not verified"));
        assert!(ledger
            .rebuild_negative_cache()
            .await
            .unwrap_err()
            .to_string()
            .contains("not verified"));
        ledger.close().await.unwrap();
    }
}
