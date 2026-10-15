// SPDX-License-Identifier: AGPL-3.0-or-later

//! Block-granular token index: the v2 section of `tokens-NNNNN.nti`
//! (NAN-3032, `lean_keyword_index_v1`).
//!
//! A v1 index answers "may this 65,536-row group hold the token?". A token
//! found in 20 events a day is then in ~17 of ~430 daily groups, and each
//! kept group is decoded and tokenized in full. The v2 section answers the
//! same question per [`BLOCK_ROWS`]-row block inside each group and records
//! every block's exact event-time range, so the planner can hand chDB a
//! `time` guard. chDB's Parquet v3 reader turns that guard into page skipping
//! (measured on real parts: a single-hit hour goes from 0.27 s to 0.008 s).
//!
//! Per row group:
//! - `times`: `[min, max]` event time (µs) of every block;
//! - `common`: tokens in more than 1/[`COMMON_DIVISOR`] of the group's
//!   blocks. They are useless for block pruning and would dominate the
//!   filter, so a hit means "keep every block of the group";
//! - `fine`: every other `(token, block)` pair.
//!
//! Filters are binary fuse filters (xorf, deterministic seed): 8-bit
//! fingerprints for `fine` (~9 bits/key, FPR ~0.39%; a v1 group bloom must
//! also pass, so a false block costs ~1% × 0.39%), 16-bit for the small
//! `common` set. Tiny sets are stored exactly. Every answer is a candidate
//! superset: `All` (a saturated or unknown filter) keeps everything.

use anyhow::{bail, ensure, Result};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use xorf::{BinaryFuse16, BinaryFuse8, Descriptor, Filter};

use super::sidecar::Cursor;

/// Rows per block. ~One `raw_data` data page (1 MiB uncompressed at ~1 KB a
/// row), the granularity chDB's page index can skip.
pub const BLOCK_ROWS: u32 = 1_024;
/// A token in more than `blocks / COMMON_DIVISOR` blocks of a group is common.
pub const COMMON_DIVISOR: usize = 4;
/// Key sets up to this size are stored as sorted exact keys (no FPR).
const EXACT_MAX: usize = 512;
/// `(token, block)` pairs one group may collect; past this the group's fine
/// filter is `All` (memory bound: 16 B a pair ≈ 256 MiB worst case).
const PAIR_CAP: usize = 16_000_000;
/// Seed of the token key hash; part of the on-disk format.
const KEY_SEED: u64 = 0x6e61_6e6f_6b77_6931; // "nanokwi1"

static ENABLED: AtomicBool = AtomicBool::new(false);

/// Turn v2 writing on for this process (cell flag `lean_keyword_index_v1`,
/// assignment `ingest_keyword_index`). Readers always understand v2.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether writers in this process emit the v2 block section.
pub fn enabled() -> bool {
    ENABLED.load(Ordering::Relaxed)
}

/// Key of one token (already `nano_split_lower_v1`-normalized).
pub fn token_key(token: &str) -> u64 {
    twox_hash::XxHash64::oneshot(KEY_SEED, token.as_bytes())
}

/// Key of a `(token, block)` pair: a splitmix64 finalizer over the token key
/// and the block number. Distinct pairs may collide; that only adds a false
/// candidate.
pub fn pair_key(token_key: u64, block: u32) -> u64 {
    let mut z = token_key ^ (u64::from(block) + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// A static set of 64-bit keys.
#[derive(Debug, Clone)]
pub enum KeySet {
    /// Holds no key.
    Empty,
    /// Unknown or saturated: holds every key.
    All,
    /// Sorted, distinct keys.
    Exact(Vec<u64>),
    Fuse8(BinaryFuse8),
    Fuse16(BinaryFuse16),
}

impl PartialEq for KeySet {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Empty, Self::Empty) | (Self::All, Self::All) => true,
            (Self::Exact(a), Self::Exact(b)) => a == b,
            (Self::Fuse8(a), Self::Fuse8(b)) => a.descriptor == b.descriptor && a.fingerprints == b.fingerprints,
            (Self::Fuse16(a), Self::Fuse16(b)) => a.descriptor == b.descriptor && a.fingerprints == b.fingerprints,
            _ => false,
        }
    }
}
impl Eq for KeySet {}

const TAG_EMPTY: u8 = 0;
const TAG_ALL: u8 = 1;
const TAG_EXACT: u8 = 2;
const TAG_FUSE8: u8 = 3;
const TAG_FUSE16: u8 = 4;

impl KeySet {
    pub fn resident_bytes(&self) -> usize {
        match self {
            Self::Empty | Self::All => 0,
            Self::Exact(keys) => keys.capacity() * 8,
            Self::Fuse8(filter) => filter.fingerprints.len(),
            Self::Fuse16(filter) => filter.fingerprints.len() * 2,
        }
    }

    /// Build from keys (any order, duplicates allowed). `wide` selects 16-bit
    /// fingerprints. A failed fuse construction degrades to `All`.
    pub fn build(mut keys: Vec<u64>, wide: bool) -> Self {
        keys.sort_unstable();
        keys.dedup();
        if keys.is_empty() {
            return Self::Empty;
        }
        if keys.len() <= EXACT_MAX {
            return Self::Exact(keys);
        }
        let built = if wide {
            BinaryFuse16::try_from(&keys).map(Self::Fuse16)
        } else {
            BinaryFuse8::try_from(&keys).map(Self::Fuse8)
        };
        built.unwrap_or(Self::All)
    }

    pub fn contains(&self, key: u64) -> bool {
        match self {
            Self::Empty => false,
            Self::All => true,
            Self::Exact(keys) => keys.binary_search(&key).is_ok(),
            Self::Fuse8(filter) => filter.contains(&key),
            Self::Fuse16(filter) => filter.contains(&key),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Empty => out.push(TAG_EMPTY),
            Self::All => out.push(TAG_ALL),
            Self::Exact(keys) => {
                out.push(TAG_EXACT);
                out.extend_from_slice(&u32::try_from(keys.len())?.to_le_bytes());
                for key in keys {
                    out.extend_from_slice(&key.to_le_bytes());
                }
            }
            Self::Fuse8(filter) => {
                out.push(TAG_FUSE8);
                encode_descriptor(&filter.descriptor, out);
                out.extend_from_slice(&u32::try_from(filter.fingerprints.len())?.to_le_bytes());
                out.extend_from_slice(&filter.fingerprints);
            }
            Self::Fuse16(filter) => {
                out.push(TAG_FUSE16);
                encode_descriptor(&filter.descriptor, out);
                out.extend_from_slice(&u32::try_from(filter.fingerprints.len())?.to_le_bytes());
                for fingerprint in filter.fingerprints.iter() {
                    out.extend_from_slice(&fingerprint.to_le_bytes());
                }
            }
        }
        Ok(())
    }

    fn decode(cursor: &mut Cursor<'_>) -> Result<Self> {
        Ok(match cursor.take(1)?[0] {
            TAG_EMPTY => Self::Empty,
            TAG_ALL => Self::All,
            TAG_EXACT => {
                let n = cursor.u32()? as usize;
                let bytes = cursor.take(n.checked_mul(8).ok_or_else(|| anyhow::anyhow!("key set overflow"))?)?;
                let keys = bytes.chunks_exact(8).map(|c| u64::from_le_bytes(c.try_into().expect("8 bytes"))).collect::<Vec<_>>();
                ensure!(keys.windows(2).all(|w| w[0] < w[1]), "exact key set is not sorted");
                Self::Exact(keys)
            }
            tag @ (TAG_FUSE8 | TAG_FUSE16) => {
                let descriptor = decode_descriptor(cursor)?;
                let n = cursor.u32()? as usize;
                // Every probe index is below segment_count_length + 2 ×
                // segment_length (arity 3); refuse anything shorter so a
                // probe can never go out of bounds.
                let needed = u64::from(descriptor.segment_count_length) + 2 * u64::from(descriptor.segment_length);
                ensure!(n as u64 >= needed, "fuse filter is shorter than its descriptor");
                if tag == TAG_FUSE8 {
                    let fingerprints = cursor.take(n)?.to_vec().into_boxed_slice();
                    Self::Fuse8(BinaryFuse8 { descriptor, fingerprints })
                } else {
                    let bytes = cursor.take(n.checked_mul(2).ok_or_else(|| anyhow::anyhow!("key set overflow"))?)?;
                    let fingerprints = bytes
                        .chunks_exact(2)
                        .map(|c| u16::from_le_bytes([c[0], c[1]]))
                        .collect::<Vec<_>>()
                        .into_boxed_slice();
                    Self::Fuse16(BinaryFuse16 { descriptor, fingerprints })
                }
            }
            other => bail!("unknown key set tag {other}"),
        })
    }
}

fn encode_descriptor(descriptor: &Descriptor, out: &mut Vec<u8>) {
    out.extend_from_slice(&descriptor.seed.to_le_bytes());
    out.extend_from_slice(&descriptor.segment_length.to_le_bytes());
    out.extend_from_slice(&descriptor.segment_length_mask.to_le_bytes());
    out.extend_from_slice(&descriptor.segment_count_length.to_le_bytes());
}

fn decode_descriptor(cursor: &mut Cursor<'_>) -> Result<Descriptor> {
    let descriptor = Descriptor {
        seed: cursor.u64()?,
        segment_length: cursor.u32()?,
        segment_length_mask: cursor.u32()?,
        segment_count_length: cursor.u32()?,
    };
    ensure!(
        descriptor.segment_length.is_power_of_two()
            && descriptor.segment_length_mask == descriptor.segment_length - 1
            && descriptor.segment_count_length > 0
            && descriptor.segment_count_length % descriptor.segment_length == 0,
        "fuse filter descriptor is invalid"
    );
    Ok(descriptor)
}

/// One row group's block index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockIndex {
    pub block_rows: u32,
    /// Exact `[min, max]` event time (µs) of every block, in block order.
    pub times: Vec<(i64, i64)>,
    pub common: KeySet,
    pub fine: KeySet,
}

impl BlockIndex {
    pub fn blocks(&self) -> usize {
        self.times.len()
    }

    /// Blocks that may hold every one of `tokens` (normalized). `None` = no
    /// block can be excluded. An empty token list decides nothing.
    pub fn blocks_with_all(&self, tokens: &[String]) -> Option<Vec<bool>> {
        if tokens.is_empty() || matches!(self.fine, KeySet::All) {
            return None;
        }
        let mut keep: Option<Vec<bool>> = None;
        for token in tokens {
            let key = token_key(token);
            if self.common.contains(key) {
                continue;
            }
            let blocks = (0..self.blocks() as u32).map(|block| self.fine.contains(pair_key(key, block)));
            keep = Some(match keep {
                None => blocks.collect(),
                Some(prior) => prior.iter().zip(blocks).map(|(a, b)| *a && b).collect(),
            });
        }
        keep
    }

    /// Row range `[start, end)` of `block` inside a group of `rows` rows.
    pub fn block_rows_range(&self, block: usize, rows: u64) -> (u64, u64) {
        let size = u64::from(self.block_rows);
        let start = (block as u64 * size).min(rows);
        (start, (start + size).min(rows))
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        out.extend_from_slice(&u32::try_from(self.times.len())?.to_le_bytes());
        for (min, max) in &self.times {
            out.extend_from_slice(&min.to_le_bytes());
            out.extend_from_slice(&max.to_le_bytes());
        }
        self.common.encode(out)?;
        self.fine.encode(out)
    }

    pub(crate) fn decode(cursor: &mut Cursor<'_>, block_rows: u32, rows: u64) -> Result<Self> {
        let blocks = cursor.u32()? as usize;
        let expected = rows.div_ceil(u64::from(block_rows));
        ensure!(blocks as u64 == expected, "block index covers {blocks} blocks, group needs {expected}");
        let mut times = Vec::with_capacity(blocks);
        for _ in 0..blocks {
            let min = i64::from_le_bytes(cursor.take(8)?.try_into()?);
            let max = i64::from_le_bytes(cursor.take(8)?.try_into()?);
            ensure!(min <= max, "block time range is inverted");
            times.push((min, max));
        }
        let common = KeySet::decode(cursor)?;
        let fine = KeySet::decode(cursor)?;
        Ok(Self { block_rows, times, common, fine })
    }
}

/// Collects one row group's `(token, block)` pairs and block times.
#[derive(Debug)]
pub struct BlockBuilder {
    block_rows: u32,
    rows_in_block: u32,
    current: HashSet<u64>,
    pairs: Vec<(u64, u32)>,
    times: Vec<(i64, i64)>,
    overflow: bool,
}

impl BlockBuilder {
    pub fn new(block_rows: u32) -> Self {
        assert!(block_rows > 0, "block rows must be positive");
        Self { block_rows, rows_in_block: 0, current: HashSet::new(), pairs: Vec::new(), times: Vec::new(), overflow: false }
    }

    /// Start the next row, whose event time is `time_us`.
    pub fn start_row(&mut self, time_us: i64) {
        if self.times.is_empty() || self.rows_in_block == self.block_rows {
            self.seal_block();
            self.times.push((time_us, time_us));
            self.rows_in_block = 0;
        }
        let last = self.times.last_mut().expect("block open");
        last.0 = last.0.min(time_us);
        last.1 = last.1.max(time_us);
        self.rows_in_block += 1;
    }

    /// Add one normalized token of the current row.
    pub fn add_token(&mut self, token: &str) {
        debug_assert!(!self.times.is_empty(), "token before the first row");
        if self.overflow {
            return;
        }
        self.current.insert(token_key(token));
    }

    fn seal_block(&mut self) {
        if self.times.is_empty() {
            return;
        }
        let block = (self.times.len() - 1) as u32;
        if !self.overflow && self.pairs.len() + self.current.len() > PAIR_CAP {
            self.overflow = true;
            self.pairs = Vec::new();
        }
        if self.overflow {
            self.current.clear();
            return;
        }
        self.pairs.extend(self.current.drain().map(|key| (key, block)));
    }

    pub fn finish(mut self) -> BlockIndex {
        self.seal_block();
        let blocks = self.times.len();
        if self.overflow {
            return BlockIndex { block_rows: self.block_rows, times: self.times, common: KeySet::Empty, fine: KeySet::All };
        }
        // Group pairs by token: block frequency decides common vs fine.
        self.pairs.sort_unstable();
        let common_threshold = blocks / COMMON_DIVISOR;
        let mut common = Vec::new();
        let mut fine = Vec::with_capacity(self.pairs.len());
        let mut start = 0;
        while start < self.pairs.len() {
            let key = self.pairs[start].0;
            let mut end = start;
            while end < self.pairs.len() && self.pairs[end].0 == key {
                end += 1;
            }
            if end - start > common_threshold && blocks >= COMMON_DIVISOR {
                common.push(key);
            } else {
                fine.extend(self.pairs[start..end].iter().map(|(key, block)| pair_key(*key, *block)));
            }
            start = end;
        }
        drop(self.pairs);
        BlockIndex {
            block_rows: self.block_rows,
            times: self.times,
            common: KeySet::build(common, true),
            fine: KeySet::build(fine, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index_of(rows: &[(i64, &str)], block_rows: u32) -> BlockIndex {
        let mut builder = BlockBuilder::new(block_rows);
        for (time, text) in rows {
            builder.start_row(*time);
            crate::parts::sidecar::tokenize(text, |token| builder.add_token(token));
        }
        builder.finish()
    }

    #[test]
    fn key_sets_round_trip_and_have_no_false_negatives() {
        for n in [0_usize, 1, 7, EXACT_MAX, EXACT_MAX + 1, 50_000] {
            let keys = (0..n as u64).map(|k| pair_key(k, 3)).collect::<Vec<_>>();
            for wide in [false, true] {
                let set = KeySet::build(keys.clone(), wide);
                assert!(keys.iter().all(|key| set.contains(*key)), "n={n} wide={wide}");
                let mut bytes = Vec::new();
                set.encode(&mut bytes).unwrap();
                let decoded = KeySet::decode(&mut Cursor { bytes: &bytes, at: 0 }).unwrap();
                assert_eq!(decoded, set);
                assert!(keys.iter().all(|key| decoded.contains(*key)));
            }
        }
    }

    #[test]
    fn fuse8_false_positive_rate_is_under_half_a_percent() {
        let keys = (0..200_000_u64).map(|k| pair_key(k, 0)).collect::<Vec<_>>();
        let set = KeySet::build(keys, false);
        assert!(matches!(set, KeySet::Fuse8(_)));
        let false_hits = (0..200_000_u64).filter(|k| set.contains(pair_key(*k, 1))).count();
        assert!(false_hits < 1_000, "{false_hits} false hits");
    }

    #[test]
    fn a_corrupt_descriptor_is_refused_not_probed() {
        let keys = (0..10_000_u64).collect::<Vec<_>>();
        let set = KeySet::build(keys, false);
        let mut bytes = Vec::new();
        set.encode(&mut bytes).unwrap();
        // segment_count_length (bytes 17..21 after the tag + seed + len + mask).
        let mut long = bytes.clone();
        long[17..21].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(KeySet::decode(&mut Cursor { bytes: &long, at: 0 }).is_err());
        let mut mask = bytes;
        mask[13] ^= 1;
        assert!(KeySet::decode(&mut Cursor { bytes: &mask, at: 0 }).is_err());
    }

    #[test]
    fn blocks_hold_their_tokens_and_times() {
        let rows = (0..5_000)
            .map(|i| (1_000 + i as i64, if i == 3_100 { "rare mimikatz here".to_string() } else { format!("common noise {i}") }))
            .collect::<Vec<_>>();
        let refs = rows.iter().map(|(t, s)| (*t, s.as_str())).collect::<Vec<_>>();
        let index = index_of(&refs, 1_024);
        assert_eq!(index.blocks(), 5);
        assert_eq!(index.times[0], (1_000, 2_023));
        assert_eq!(index.times[4], (1_000 + 4_096, 1_000 + 4_999));
        assert_eq!(index.blocks_with_all(&["mimikatz".into()]), Some(vec![false, false, false, true, false]));
        assert_eq!(index.blocks_with_all(&["mimikatz".into(), "rare".into()]), Some(vec![false, false, false, true, false]));
        // `common` is in every block: no block decision.
        assert_eq!(index.blocks_with_all(&["common".into()]), None);
        assert_eq!(index.blocks_with_all(&["common".into(), "mimikatz".into()]), Some(vec![false, false, false, true, false]));
        // A number seen once is fine-grained.
        assert_eq!(index.blocks_with_all(&["17".into()]).unwrap()[0], true);
        assert!(index.blocks_with_all(&["zzqx".into()]).unwrap().iter().all(|keep| !keep));
        assert_eq!(index.block_rows_range(4, 5_000), (4_096, 5_000));
    }

    #[test]
    fn overflow_keeps_everything() {
        let mut builder = BlockBuilder::new(4);
        builder.start_row(1);
        builder.overflow = true;
        builder.add_token("x");
        let index = builder.finish();
        assert_eq!(index.fine, KeySet::All);
        assert_eq!(index.blocks_with_all(&["y".into()]), None);
    }
    /// NAN-3032 benchmark over real part files (not a CI test):
    /// `NAN3032_PARTS_DIR=<dir with data-*.parquet> NAN3032_OUT=<dir>
    /// NAN3032_KEYWORDS="kw1 kw2" cargo test -p nanosiem-lake-worker --lib
    /// parts::block_index::tests::bench_real_parts -- --ignored --nocapture`.
    /// Rebuilds v1 and v2 token indexes exactly as the part writer does, and
    /// writes per keyword the row-group and block fences the engine would
    /// choose (`<out>/fences.json`) for the chDB harness to execute.
    #[test]
    #[ignore = "benchmark over local real part files"]
    fn bench_real_parts() {
        use crate::generation::CompiledStringPath;
        use crate::parts::sidecar::{encode_token_index, TokenGroupBuilder, TOKEN_FIELDS};
        use crate::part_query::prune;
        use crate::planner::CandidateHint;
        use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
        use std::time::Instant;

        let dir = std::path::PathBuf::from(std::env::var("NAN3032_PARTS_DIR").expect("NAN3032_PARTS_DIR"));
        let out = std::path::PathBuf::from(std::env::var("NAN3032_OUT").expect("NAN3032_OUT"));
        std::fs::create_dir_all(&out).unwrap();
        let keywords = std::env::var("NAN3032_KEYWORDS").unwrap_or_default();
        let mut files = std::fs::read_dir(&dir).unwrap().filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|e| e == "parquet") && p.file_name().unwrap().to_string_lossy().contains("data-"))
            .collect::<Vec<_>>();
        files.sort();
        let mut report = Vec::new();
        for file in files {
            let builder = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&file).unwrap()).unwrap();
            let groups_meta = builder.metadata().row_groups().iter().map(|g| g.num_rows() as u64).collect::<Vec<_>>();
            let data_bytes = std::fs::metadata(&file).unwrap().len();
            let mut v1 = Vec::new();
            let mut v2 = Vec::new();
            let mut v3 = Vec::new();
            let (mut v1_s, mut v2_s, mut v3_s) = (0.0_f64, 0.0_f64, 0.0_f64);
            for group in 0..groups_meta.len() {
                let reader = ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(&file).unwrap()).unwrap()
                    .with_row_groups(vec![group]).with_batch_size(8_192).build().unwrap();
                let mut a = TokenGroupBuilder::new();
                let mut b = TokenGroupBuilder::with_blocks(BLOCK_ROWS);
                let mut c = TokenGroupBuilder::with_blocks_and_counts(BLOCK_ROWS);
                for batch in reader {
                    let batch = batch.unwrap();
                    let time = batch.column_by_name("time").unwrap().clone();
                    let paths = TOKEN_FIELDS.iter().filter_map(|p| CompiledStringPath::new(&batch, p).map(|c| (c, crate::parts::token_counts::BODY_COLUMNS.contains(p)))).collect::<Vec<_>>();
                    let texts = (0..batch.num_rows())
                        .map(|row| paths.iter().flat_map(|(p, body)| p.strings(row).into_iter().map(move |t| (t, *body))).collect::<Vec<_>>())
                        .collect::<Vec<_>>();
                    let times = (0..batch.num_rows())
                        .map(|row| crate::generation::event_time_us_from_array(time.as_ref(), row).unwrap())
                        .collect::<Vec<_>>();
                    let t = Instant::now();
                    for row in texts.iter() {
                        a.add_row();
                        for (text, _) in row { a.add_text(text); }
                    }
                    v1_s += t.elapsed().as_secs_f64();
                    let t = Instant::now();
                    for (row, time_us) in texts.iter().zip(&times) {
                        b.add_row_at(*time_us);
                        for (text, _) in row { b.add_text(text); }
                    }
                    v2_s += t.elapsed().as_secs_f64();
                    let t = Instant::now();
                    for (row, time_us) in texts.iter().zip(&times) {
                        c.add_row_at(*time_us);
                        for (text, body) in row {
                            c.add_text(text);
                            if *body { c.add_body(text); }
                        }
                    }
                    v3_s += t.elapsed().as_secs_f64();
                }
                let t = Instant::now();
                v1.push(a.finish().unwrap());
                v1_s += t.elapsed().as_secs_f64();
                let t = Instant::now();
                v2.push(b.finish().unwrap());
                v2_s += t.elapsed().as_secs_f64();
                let t = Instant::now();
                v3.push(c.finish().unwrap());
                v3_s += t.elapsed().as_secs_f64();
            }
            let v1_bytes = encode_token_index(&v1).unwrap();
            let v2_bytes = encode_token_index(&v2).unwrap();
            let v3_bytes = encode_token_index(&v3).unwrap();
            let t = Instant::now();
            let v3_decoded = crate::parts::sidecar::decode_token_index(&v3_bytes).unwrap();
            let v3_decode_s = t.elapsed().as_secs_f64();
            let v3_tokens = v3_decoded.iter().map(|g| g.counts.as_ref().map_or(0, |c| c.tokens())).sum::<usize>();
            let name = file.file_name().unwrap().to_string_lossy().to_string();
            std::fs::write(out.join(format!("{name}.nti2")), &v2_bytes).unwrap();
            let t = Instant::now();
            let decoded = crate::parts::sidecar::decode_token_index(&v2_bytes).unwrap();
            let decode_s = t.elapsed().as_secs_f64();
            let fine_keys = decoded.iter().map(|g| match &g.blocks.as_ref().unwrap().fine {
                KeySet::Exact(k) => k.len(), KeySet::Fuse8(f) => f.fingerprints.len(), _ => 0 }).sum::<usize>();
            let mut starts = vec![0_u64];
            for rows in &groups_meta { starts.push(starts.last().unwrap() + rows); }
            let group_time = |g: usize| {
                let t = &decoded[g].blocks.as_ref().unwrap().times;
                (t.iter().map(|x| x.0).min().unwrap(), t.iter().map(|x| x.1).max().unwrap())
            };
            let mut fences = serde_json::Map::new();
            for keyword in keywords.split_whitespace() {
                let hints = vec![CandidateHint::Keyword { mode: "token".into(), value: keyword.into() }];
                let t = Instant::now();
                let (mask, fine) = prune::token_evidence(Some(&v2_bytes), groups_meta.len(), &hints);
                let probe_s = t.elapsed().as_secs_f64();
                let (v1_mask, _) = prune::token_evidence(Some(&v1_bytes), groups_meta.len(), &hints);
                let coarse = (0..groups_meta.len()).filter(|g| v1_mask.as_ref().is_none_or(|m| m[*g]))
                    .map(|g| serde_json::json!([starts[g], starts[g + 1], group_time(g).0, group_time(g).1])).collect::<Vec<_>>();
                let mut runs = Vec::new();
                for g in 0..groups_meta.len() {
                    if mask.as_ref().is_some_and(|m| !m[g]) { continue; }
                    match fine.as_ref().and_then(|f| f[g].as_ref()) {
                        Some(r) => runs.extend(r.iter().map(|(s, e, (a, b))| serde_json::json!([starts[g] + s, starts[g] + e, a, b]))),
                        None => runs.push(serde_json::json!([starts[g], starts[g + 1], group_time(g).0, group_time(g).1])),
                    }
                }
                fences.insert(keyword.into(), serde_json::json!({"coarse": coarse, "fine": runs, "probe_s": probe_s}));
            }
            let entry = serde_json::json!({
                "file": name, "rows": starts.last(), "row_groups": groups_meta.len(), "data_bytes": data_bytes,
                "v1_bytes": v1_bytes.len(), "v2_bytes": v2_bytes.len(), "v1_build_s": v1_s, "v2_build_s": v2_s,
                "v2_decode_s": decode_s, "fine_fingerprints": fine_keys, "fences": fences,
            });
            println!("{}", serde_json::json!({"file": name, "rows": starts.last(), "data_bytes": data_bytes, "v1_bytes": v1_bytes.len(), "v2_bytes": v2_bytes.len(), "v3_bytes": v3_bytes.len(), "v1_build_s": v1_s, "v2_build_s": v2_s, "v3_build_s": v3_s, "v2_decode_s": decode_s, "v3_decode_s": v3_decode_s, "v3_counted_tokens": v3_tokens}));
            report.push(entry);
        }
        std::fs::write(out.join("fences.json"), serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    }
}
