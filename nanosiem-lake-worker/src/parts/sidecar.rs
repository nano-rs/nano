// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-part sidecars (contract section 3): the per-row-group token index
//! (`tokens.nti`) and the aggregate partial schemas.

use anyhow::{bail, ensure, Context, Result};
use arrow_schema::{DataType, Field, Schema, TimeUnit};
use parquet::bloom_filter::Sbbf;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::Arc;

use super::block_index::{BlockBuilder, BlockIndex};
use super::token_counts::{CountBuilder, TokenCounts};

pub const TOKEN_INDEX_MAGIC: &[u8; 8] = b"NANOTKI1";
pub const TOKEN_INDEX_VERSION: u32 = 1;
/// v2 (NAN-3032): v1's per-group blooms plus a per-group block index
/// ([`super::block_index`]). Same file name, same signed record entry.
pub const TOKEN_INDEX_MAGIC_V2: &[u8; 8] = b"NANOTKI2";
pub const TOKEN_INDEX_VERSION_V2: u32 = 2;
/// v3: v2 plus, per group, exact per-minute row counts of its dense keyword
/// tokens ([`super::token_counts`]). Same file name and record entry.
pub const TOKEN_INDEX_MAGIC_V3: &[u8; 8] = b"NANOTKI3";
pub const TOKEN_INDEX_VERSION_V3: u32 = 3;
/// v4 adds a bounded ASCII trigram bloom to each v3 group. The existing
/// signed tokens digest covers it; no provenance fields or filenames change.
pub const TOKEN_INDEX_MAGIC_V4: &[u8; 8] = b"NANOTKI4";
pub const TOKEN_INDEX_VERSION_V4: u32 = 4;
pub const TRIGRAM_FILTER_BYTES: usize = 32 * 1024;
pub const TRIGRAM_ENABLE_ENV: &str = "NANO_LAKE_TRIGRAM_INDEX";

pub fn trigrams_enabled() -> bool {
    std::env::var(TRIGRAM_ENABLE_ENV).ok().as_deref() == Some("1")
}

/// ASCII-only windows: Unicode and LIKE/wildcard metacharacters cannot
/// establish absence. The writer uses the same function, including across
/// punctuation; no window crosses a field or row boundary.
pub fn ascii_trigrams(text: &str, mut emit: impl FnMut([u8; 3])) {
    for window in text.as_bytes().windows(3) {
        if window.iter().all(|b| b.is_ascii() && !matches!(b, b'*' | b'?' | b'%' | b'_' | b'\\')) {
            emit([window[0].to_ascii_lowercase(), window[1].to_ascii_lowercase(), window[2].to_ascii_lowercase()]);
        }
    }
}

pub const TOKENIZER: &str = "nano_split_lower_v1";
pub const TOKEN_MAX_BYTES: usize = 128;
pub const TOKEN_FPP: f64 = 0.01;
pub const TOKEN_FILTER_MAX_BYTES: usize = 4 * 1024 * 1024;
/// Distinct tokens remembered per row group before sizing its filter. Past
/// this, the filter is sized at the cap and still receives every token.
const TOKEN_DISTINCT_CAP: usize = 1_000_000;

/// Fields tokenized into the index (a leaf absent from the schema is skipped).
pub const TOKEN_FIELDS: &[&str] = crate::text_sidecar::KEYWORD_BODY_FIELDS;

/// Split on every char that is not alphanumeric, lowercase, keep 1..=128
/// byte tokens. Shared by ingest and query.
pub fn tokenize(text: &str, mut emit: impl FnMut(&str)) {
    for piece in text.split(|c: char| !c.is_alphanumeric()) {
        if piece.is_empty() {
            continue;
        }
        if piece.chars().all(|c| !c.is_uppercase()) {
            if piece.len() <= TOKEN_MAX_BYTES {
                emit(piece);
            }
        } else {
            let lower = piece.to_lowercase();
            if lower.len() <= TOKEN_MAX_BYTES {
                emit(&lower);
            }
        }
    }
}

/// Builds one row group's token filter. Memory is bounded by the distinct
/// tokens of one row group (plus, for v2, its `(token, block)` pairs).
#[derive(Default)]
pub struct TokenGroupBuilder {
    rows: u64,
    tokens: HashSet<Box<str>>,
    overflow: bool,
    blocks: Option<BlockBuilder>,
    counts: Option<CountBuilder>,
    trigrams: Option<Sbbf>,
}

impl TokenGroupBuilder {
    /// A v1 builder (row-group bloom only).
    pub fn new() -> Self {
        Self::default()
    }

    /// A v2 builder: v1's bloom plus a block index. Rows must then be
    /// started with [`Self::add_row_at`].
    pub fn with_blocks(block_rows: u32) -> Self {
        Self { blocks: Some(BlockBuilder::new(block_rows)), ..Self::default() }
    }

    /// A v3 builder: v2 plus per-minute counts of dense body tokens. Body
    /// column values go through [`Self::add_body`] as well as `add_text`.
    pub fn with_blocks_and_counts(block_rows: u32) -> Self {
        Self { blocks: Some(BlockBuilder::new(block_rows)), counts: Some(CountBuilder::new()), ..Self::default() }
    }

    /// A v4 builder. Fixed 32 KiB per group, with no distinct-set allocation;
    /// saturation only creates false positives.
    pub fn with_trigrams(block_rows: u32) -> Self {
        let mut builder = Self::with_blocks_and_counts(block_rows);
        builder.trigrams = Some(Sbbf::new(&vec![0; TRIGRAM_FILTER_BYTES]));
        builder
    }

    /// The v2/v3 builder the writers use for `block_rows` (`None`: v1).
    pub fn for_writer(block_rows: Option<u32>) -> Self {
        match block_rows {
            Some(block_rows) if super::token_counts::enabled() && trigrams_enabled() => Self::with_trigrams(block_rows),
            Some(block_rows) if super::token_counts::enabled() => Self::with_blocks_and_counts(block_rows),
            Some(block_rows) => Self::with_blocks(block_rows),
            None => Self::new(),
        }
    }

    pub fn has_counts(&self) -> bool {
        self.counts.is_some()
    }

    pub fn has_blocks(&self) -> bool {
        self.blocks.is_some()
    }

    pub fn add_row(&mut self) {
        debug_assert!(self.blocks.is_none(), "a v2 builder needs row times");
        self.rows += 1;
    }

    /// Start a row whose event time is `time_us` (v1 ignores the time).
    pub fn add_row_at(&mut self, time_us: i64) {
        self.rows += 1;
        if let Some(blocks) = &mut self.blocks {
            blocks.start_row(time_us);
        }
        if let Some(counts) = &mut self.counts {
            counts.start_row(time_us);
        }
    }

    /// One value of a keyword body column (`message`, `raw_data`) of the
    /// current row, for the v3 counts (a no-op otherwise).
    pub fn add_body(&mut self, text: &str) {
        if let Some(counts) = &mut self.counts {
            counts.add_text(text);
        }
    }

    pub fn add_text(&mut self, text: &str) {
        if let Some(filter) = &mut self.trigrams {
            ascii_trigrams(text, |gram| filter.insert(gram.as_slice()));
            // RE2 Unicode simple folding includes long-s and Kelvin-sign
            // equivalents of ASCII s/k. Keep their candidates as well.
            if !text.is_ascii() {
                let folded = text.to_lowercase().replace('ſ', "s");
                ascii_trigrams(&folded, |gram| filter.insert(gram.as_slice()));
            }
        }
        tokenize(text, |token| {
            if let Some(blocks) = &mut self.blocks {
                blocks.add_token(token);
            }
            if self.tokens.len() < TOKEN_DISTINCT_CAP {
                if !self.tokens.contains(token) {
                    self.tokens.insert(token.into());
                }
            } else {
                self.overflow = true;
            }
        });
    }

    /// Finish into (rows, distinct tokens, bitset bytes[, block index]).
    pub fn finish(self) -> Result<TokenGroup> {
        let trigrams = self.trigrams.map(|filter| {
            let mut bytes = Vec::new();
            filter.write_bitset(&mut bytes).expect("writing a bloom to Vec");
            bytes
        });
        let blocks = self.blocks.map(BlockBuilder::finish);
        if let Some(index) = &blocks {
            ensure!(index.blocks() as u64 == self.rows.div_ceil(u64::from(index.block_rows)), "block index does not cover its rows");
        }
        let counts = self.counts.map(CountBuilder::finish);
        if let Some(counts) = &counts {
            ensure!(u64::from(counts.rows) == self.rows, "token counts do not cover the group's rows");
        }
        if self.tokens.is_empty() {
            return Ok(TokenGroup { rows: self.rows, tokens: 0, bitset: Vec::new(), saturated: false, blocks, counts, trigrams });
        }
        let distinct = self.tokens.len() as u64;
        let mut filter = Sbbf::new_with_ndv_fpp(distinct.max(64), TOKEN_FPP)?;
        for token in &self.tokens {
            filter.insert(token.as_bytes());
        }
        let mut bitset = Vec::new();
        filter.write_bitset(&mut bitset)?;
        // Past the distinct cap we cannot represent every token: store an
        // all-ones filter, which matches everything (a correct superset).
        let saturated = self.overflow || bitset.len() > TOKEN_FILTER_MAX_BYTES;
        if saturated {
            bitset = vec![0xff; 32];
        }
        Ok(TokenGroup { rows: self.rows, tokens: distinct, bitset, saturated, blocks, counts, trigrams })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenGroup {
    pub rows: u64,
    pub tokens: u64,
    /// Empty = the group has no tokens and matches no keyword.
    pub bitset: Vec<u8>,
    pub saturated: bool,
    /// v2 and v3: the group's block index.
    pub blocks: Option<BlockIndex>,
    /// v3/v4: exact per-minute counts of the group's dense body tokens.
    pub counts: Option<TokenCounts>,
    /// v4 only, bounded candidate bloom; never exact count evidence.
    pub trigrams: Option<Vec<u8>>,
}

impl TokenGroup {
    pub fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.bitset.capacity()
            + self.blocks.as_ref().map_or(0, |blocks| blocks.times.capacity() * 16
                + blocks.common.resident_bytes() + blocks.fine.resident_bytes())
            + self.counts.as_ref().map_or(0, TokenCounts::resident_bytes)
            + self.trigrams.as_ref().map_or(0, Vec::capacity)
    }

    /// May every token be present in this group?
    pub fn may_contain_all(&self, tokens: &[String]) -> bool {
        if self.bitset.is_empty() {
            return tokens.is_empty();
        }
        let filter = Sbbf::new(&self.bitset);
        tokens.iter().all(|token| filter.check(token.as_bytes()))
    }
}

/// Encode `tokens.nti` (contract 3.1). v1 when no group has a block index,
/// v2 when every group has one, v3 when every group also has counts, v4
/// when every group additionally has trigrams (mixing is refused).
pub fn encode_token_index(groups: &[TokenGroup]) -> Result<Vec<u8>> {
    let with_blocks = groups.iter().filter(|group| group.blocks.is_some()).count();
    ensure!(with_blocks == 0 || with_blocks == groups.len(), "token groups mix v1 and v2");
    let with_counts = groups.iter().filter(|group| group.counts.is_some()).count();
    ensure!(with_counts == 0 || (with_counts == groups.len() && with_blocks == groups.len()), "token groups mix v2 and v3");
    let v3 = with_counts > 0;
    let with_trigrams = groups.iter().filter(|group| group.trigrams.is_some()).count();
    ensure!(with_trigrams == 0 || (with_trigrams == groups.len() && v3), "token groups mix v3 and v4");
    let v4 = with_trigrams > 0;
    let block_rows = groups.first().and_then(|group| group.blocks.as_ref()).map(|blocks| blocks.block_rows);
    ensure!(
        groups.iter().all(|group| group.blocks.as_ref().map(|blocks| blocks.block_rows) == block_rows),
        "token groups disagree on block rows"
    );
    let mut out = Vec::with_capacity(64 + groups.iter().map(|g| g.bitset.len() + 20).sum::<usize>());
    match block_rows {
        None => {
            out.extend_from_slice(TOKEN_INDEX_MAGIC);
            out.extend_from_slice(&TOKEN_INDEX_VERSION.to_le_bytes());
        }
        Some(_) if v4 => {
            out.extend_from_slice(TOKEN_INDEX_MAGIC_V4);
            out.extend_from_slice(&TOKEN_INDEX_VERSION_V4.to_le_bytes());
        }
        Some(_) if v3 => {
            out.extend_from_slice(TOKEN_INDEX_MAGIC_V3);
            out.extend_from_slice(&TOKEN_INDEX_VERSION_V3.to_le_bytes());
        }
        Some(_) => {
            out.extend_from_slice(TOKEN_INDEX_MAGIC_V2);
            out.extend_from_slice(&TOKEN_INDEX_VERSION_V2.to_le_bytes());
        }
    }
    out.extend_from_slice(&(TOKENIZER.len() as u16).to_le_bytes());
    out.extend_from_slice(TOKENIZER.as_bytes());
    if let Some(block_rows) = block_rows {
        out.extend_from_slice(&block_rows.to_le_bytes());
    }
    out.extend_from_slice(&u32::try_from(groups.len())?.to_le_bytes());
    for group in groups {
        if group.bitset.len() % 32 != 0 {
            bail!("token filter bitset is not a whole number of blocks");
        }
        out.extend_from_slice(&group.rows.to_le_bytes());
        out.extend_from_slice(&group.tokens.to_le_bytes());
        out.extend_from_slice(&u32::try_from(group.bitset.len())?.to_le_bytes());
        out.extend_from_slice(&group.bitset);
        if let Some(blocks) = &group.blocks {
            blocks.encode(&mut out)?;
        }
        if let Some(counts) = &group.counts {
            counts.encode(&mut out)?;
        }
        if let Some(grams) = &group.trigrams {
            ensure!(grams.len() == TRIGRAM_FILTER_BYTES, "invalid trigram bloom size");
            out.extend_from_slice(grams);
        }
    }
    let digest = Sha256::digest(&out);
    out.extend_from_slice(&digest);
    Ok(out)
}

/// Decode and integrity-check `tokens.nti`.
pub fn decode_token_index(bytes: &[u8]) -> Result<Vec<TokenGroup>> {
    if bytes.len() < 8 + 4 + 2 + 4 + 32 {
        bail!("token index is truncated");
    }
    let (body, trailer) = bytes.split_at(bytes.len() - 32);
    if Sha256::digest(body).as_slice() != trailer {
        bail!("token index trailer does not match");
    }
    decode_token_index_body(body)
}

/// [`decode_token_index`] for a file leased through the part fetcher, whose
/// whole content (trailer included) was already checked against the
/// owner-signed SHA-256 of its record: in place per inode stamp, or by the
/// content-addressed reader cache. The structure is still fully validated;
/// only the redundant trailer re-hash is skipped (NAN-3077: at ~10 MB of
/// index per hour of data that re-hash cost ~1 s of CPU per 24 h keyword
/// selection on the cell's SHA-NI-less cores, on every query).
pub fn decode_leased_token_index(bytes: &[u8]) -> Result<Vec<TokenGroup>> {
    if bytes.len() < 8 + 4 + 2 + 4 + 32 {
        bail!("token index is truncated");
    }
    decode_token_index_body(&bytes[..bytes.len() - 32])
}

fn decode_token_index_body(body: &[u8]) -> Result<Vec<TokenGroup>> {
    let mut cursor = Cursor { bytes: body, at: 0 };
    let version = match cursor.take(8)? {
        magic if magic == TOKEN_INDEX_MAGIC => TOKEN_INDEX_VERSION,
        magic if magic == TOKEN_INDEX_MAGIC_V2 => TOKEN_INDEX_VERSION_V2,
        magic if magic == TOKEN_INDEX_MAGIC_V3 => TOKEN_INDEX_VERSION_V3,
        magic if magic == TOKEN_INDEX_MAGIC_V4 => TOKEN_INDEX_VERSION_V4,
        _ => bail!("token index magic is wrong"),
    };
    if cursor.u32()? != version {
        bail!("token index version is unsupported");
    }
    let v2 = version >= TOKEN_INDEX_VERSION_V2;
    let v3 = version >= TOKEN_INDEX_VERSION_V3;
    let tokenizer_len = cursor.u16()? as usize;
    if cursor.take(tokenizer_len)? != TOKENIZER.as_bytes() {
        bail!("token index tokenizer is unsupported");
    }
    let block_rows = if v2 {
        let block_rows = cursor.u32()?;
        ensure!(block_rows > 0, "token index block rows is zero");
        Some(block_rows)
    } else {
        None
    };
    let groups = cursor.u32()? as usize;
    let mut out = Vec::with_capacity(groups.min(1 << 16));
    for _ in 0..groups {
        let rows = cursor.u64()?;
        let tokens = cursor.u64()?;
        let len = cursor.u32()? as usize;
        if len % 32 != 0 || len > TOKEN_FILTER_MAX_BYTES {
            bail!("token filter length is invalid");
        }
        let bitset = cursor.take(len)?.to_vec();
        let saturated = bitset.len() == 32 && bitset.iter().all(|b| *b == 0xff);
        let blocks = match block_rows {
            Some(block_rows) => Some(BlockIndex::decode(&mut cursor, block_rows, rows)?),
            None => None,
        };
        let counts = if v3 { Some(TokenCounts::decode(&mut cursor, rows)?) } else { None };
        let trigrams = if version == TOKEN_INDEX_VERSION_V4 { Some(cursor.take(TRIGRAM_FILTER_BYTES)?.to_vec()) } else { None };
        out.push(TokenGroup { rows, tokens, bitset, saturated, blocks, counts, trigrams });
    }
    if cursor.at != body.len() {
        bail!("token index has trailing bytes");
    }
    Ok(out)
}

pub(crate) struct Cursor<'a> {
    pub(crate) bytes: &'a [u8],
    pub(crate) at: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.at.checked_add(n).context("token index offset overflow")?;
        let slice = self.bytes.get(self.at..end).context("token index is truncated")?;
        self.at = end;
        Ok(slice)
    }
    pub(crate) fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into()?))
    }
    pub(crate) fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into()?))
    }
    pub(crate) fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into()?))
    }
}

// ---------------------------------------------------------------------------
// Aggregate partials (3.2–3.5)
// ---------------------------------------------------------------------------

/// Exact, mergeable distinct-host sample. At 1,000 hosts the persisted scalar
/// saturates, so keeping any additional fingerprints cannot change the stamp.
pub const PREVALENCE_HOST_CAP: usize = 1_000;

/// `xxHash64(lower(trim(host)))`, seed 0: equal to chDB `xxHash64(...)`.
pub fn host_fingerprint(host: &str) -> u64 {
    twox_hash::XxHash64::oneshot(0, host.trim().to_lowercase().as_bytes())
}

fn ts() -> DataType {
    DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into()))
}

/// `partials/rollup.parquet` (3.2).
pub fn rollup_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("bucket_start_us", DataType::Int64, false),
        Field::new("field_id", DataType::UInt16, false),
        Field::new("source_type", DataType::Utf8, false),
        Field::new("value", DataType::Utf8, true),
        Field::new("events", DataType::UInt64, false),
    ]))
}

/// `partials/prevalence.parquet` (3.3).
pub fn prevalence_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("kind", DataType::Utf8, false),
        Field::new("scope", DataType::Utf8, false),
        Field::new("entity", DataType::Utf8, false),
        Field::new("day", DataType::Date32, false),
        Field::new(
            "host_fingerprints",
            DataType::List(Arc::new(Field::new("item", DataType::UInt64, false))),
            false,
        ),
        Field::new("host_cap", DataType::UInt16, false),
        Field::new("is_private", DataType::UInt8, false),
        Field::new("first_seen", ts(), false),
        Field::new("last_seen", ts(), false),
        Field::new("daily_count", DataType::UInt64, false),
    ]))
}

/// `partials/entity_ranges.parquet` (3.4).
pub fn entity_ranges_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("path", DataType::Utf8, false),
        Field::new("value", DataType::Utf8, false),
        Field::new("first_time", ts(), false),
        Field::new("last_time", ts(), false),
        Field::new("events", DataType::UInt64, false),
    ]))
}

/// `partials/risk.parquet` (3.5).
pub fn risk_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("entity", DataType::Utf8, false),
        Field::new("entity_type", DataType::Utf8, false),
        Field::new("rule_id", DataType::Utf8, false),
        Field::new("bucket_start_us", DataType::Int64, false),
        Field::new("findings", DataType::UInt64, false),
        Field::new("risk_score_sum", DataType::Int64, false),
        Field::new("max_severity_id", DataType::Int32, false),
    ]))
}

/// Merge two sorted, capped host-fingerprint sets (sorted union, re-capped).
pub fn merge_host_fingerprints(left: &[u64], right: &[u64]) -> Vec<u64> {
    let mut out = Vec::with_capacity((left.len() + right.len()).min(PREVALENCE_HOST_CAP));
    let (mut i, mut j) = (0, 0);
    while out.len() < PREVALENCE_HOST_CAP && (i < left.len() || j < right.len()) {
        let next = match (left.get(i), right.get(j)) {
            (Some(a), Some(b)) if a == b => {
                i += 1;
                j += 1;
                *a
            }
            (Some(a), Some(b)) if a < b => {
                i += 1;
                *a
            }
            (Some(_), Some(b)) => {
                j += 1;
                *b
            }
            (Some(a), None) => {
                i += 1;
                *a
            }
            (None, Some(b)) => {
                j += 1;
                *b
            }
            (None, None) => break,
        };
        out.push(next);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tokenizer_splits_and_lowercases() {
        let mut tokens = Vec::new();
        tokenize("Failed LOGIN for admin@Corp.local from 10.0.0.1 -- Ünïcode", |t| tokens.push(t.to_string()));
        assert_eq!(tokens, ["failed", "login", "for", "admin", "corp", "local", "from", "10", "0", "0", "1", "ünïcode"]);
    }

    #[test]
    fn v4_preserves_v3_counts_and_rejects_mixed_or_truncated_groups() {
        let mut builder = TokenGroupBuilder::with_trigrams(4);
        builder.add_row_at(0);
        builder.add_text("caſe Kase PowerShell");
        builder.add_body("PowerShell");
        let group = builder.finish().unwrap();
        let bytes = encode_token_index(&[group.clone()]).unwrap();
        assert!(bytes.starts_with(TOKEN_INDEX_MAGIC_V4));
        assert_eq!(decode_token_index(&bytes).unwrap(), vec![group.clone()]);
        assert_eq!(decode_leased_token_index(&bytes).unwrap(), vec![group.clone()]);
        let filter = Sbbf::new(group.trigrams.as_ref().unwrap());
        for text in ["case", "kase", "shell"] {
            ascii_trigrams(text, |gram| assert!(filter.check(gram.as_slice())));
        }
        let mut legacy = group.clone();
        let with_trigrams = legacy.resident_bytes();
        legacy.trigrams = None;
        assert_eq!(with_trigrams - legacy.resident_bytes(), TRIGRAM_FILTER_BYTES);
        assert!(encode_token_index(&[group, legacy.clone()]).is_err());
        assert!(encode_token_index(&[legacy]).unwrap().starts_with(TOKEN_INDEX_MAGIC_V3));
        assert!(decode_leased_token_index(&bytes[..bytes.len() - 1]).is_err());
        let mut unknown = bytes;
        unknown[7] = b'9';
        assert!(decode_leased_token_index(&unknown).is_err());
    }

    #[test]
    fn token_index_round_trips_and_prunes() {
        let mut a = TokenGroupBuilder::new();
        a.add_row();
        a.add_text("mimikatz sekurlsa logonpasswords");
        let mut b = TokenGroupBuilder::new();
        b.add_row();
        b.add_text("GET /index.html 200");
        let empty = TokenGroupBuilder::new();
        let groups = vec![a.finish().unwrap(), b.finish().unwrap(), empty.finish().unwrap()];
        let bytes = encode_token_index(&groups).unwrap();
        let decoded = decode_token_index(&bytes).unwrap();
        assert_eq!(decoded, groups);
        let hunt = vec!["mimikatz".to_string(), "sekurlsa".to_string()];
        assert!(decoded[0].may_contain_all(&hunt));
        assert!(!decoded[1].may_contain_all(&hunt));
        assert!(!decoded[2].may_contain_all(&hunt));
        let mut corrupt = bytes.clone();
        corrupt[20] ^= 1;
        assert!(decode_token_index(&corrupt).is_err());
        // NAN-3077: a leased file decodes identically without the trailer
        // re-hash, and structural damage is still refused.
        assert_eq!(decode_leased_token_index(&bytes).unwrap(), groups);
        let mut magic = bytes.clone();
        magic[0] ^= 1;
        assert!(decode_leased_token_index(&magic).is_err());
        assert!(decode_leased_token_index(&bytes[..bytes.len() - 33]).is_err());
        assert!(decode_leased_token_index(&bytes[..40]).is_err());
    }

    #[test]
    fn host_fingerprint_matches_chdb_xxhash64() {
        // Reference XXH64 of the empty input; phase 3 pins chDB `xxHash64` parity.
        assert_eq!(host_fingerprint(" Host-A "), host_fingerprint("host-a"));
        assert_eq!(twox_hash::XxHash64::oneshot(0, b""), 0xef46_db37_51d8_e999);
    }

    #[test]
    fn host_sets_merge_sorted_and_capped() {
        assert_eq!(merge_host_fingerprints(&[1, 3, 5], &[2, 3, 6]), vec![1, 2, 3, 5, 6]);
        let a = (0..PREVALENCE_HOST_CAP as u64).map(|i| i * 2).collect::<Vec<_>>();
        let b = (0..PREVALENCE_HOST_CAP as u64).map(|i| i * 2 + 1).collect::<Vec<_>>();
        let merged = merge_host_fingerprints(&a, &b);
        assert_eq!(merged.len(), PREVALENCE_HOST_CAP);
        assert!(merged.windows(2).all(|w| w[0] < w[1]));
    }
}
