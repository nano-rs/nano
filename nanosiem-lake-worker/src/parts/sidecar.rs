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
/// v5 (NAN-4164) adds, per v4 group, a bloom of adjacent token pairs
/// ([`adjacent_pairs`]), so a bare keyword that splits into several tokens
/// (`10.1.4.20`, `ws-fin-095`, `"failed password"`) prunes on its pairs
/// instead of on pieces that occur in nearly every row. Same file name and
/// signed record entry. Readers of v5 went live before any writer emitted
/// it; the writer is on by default ([`pairs_enabled`]).
pub const TOKEN_INDEX_MAGIC_V5: &[u8; 8] = b"NANOTKI5";
pub const TOKEN_INDEX_VERSION_V5: u32 = 5;
pub const PAIR_ENABLE_ENV: &str = "NANO_LAKE_PAIR_INDEX";
/// v6 (NAN-4217): the v5 layout, unchanged, whose token bloom and block
/// index ALSO hold every IP address of the text as one whole token
/// ([`address_tokens`]: `48.170.34.111`, `fe80::1`). A bare IP splits into
/// number tokens (48, 170, 34, 111) found in nearly every row group, so on
/// v4/v5 it prunes little; its whole-address token is as rare as the IP.
/// Only the magic differs, so a v6 file never answers an address question
/// for a reader that does not know the version: an older reader refuses
/// the magic, keeps every group and scans (correct, slower). Writer behind
/// [`ip_tokens_enabled`] (default off): readers roll first.
pub const TOKEN_INDEX_MAGIC_V6: &[u8; 8] = b"NANOTKI6";
pub const TOKEN_INDEX_VERSION_V6: u32 = 6;
pub const IP_TOKEN_ENABLE_ENV: &str = "NANO_LAKE_IP_TOKEN_INDEX";
/// Pair bloom size cap per group ([`pair_filter_bytes`]). A full large-tenant group
/// (~650k distinct pairs) lands at the cap with a per-pair false-positive
/// rate of ~6%, and a needle needs ALL of its pairs, so a three-pair IP
/// needle passes a non-matching group ~0.02% of the time.
pub const PAIR_FILTER_MAX_BYTES: usize = 512 * 1024;
/// Distinct pair hashes remembered per group (8 bytes each) before the
/// group's pair bloom is stored saturated (matches everything).
const PAIR_DISTINCT_CAP: usize = 2_000_000;

/// Pair bloom bytes for `pairs` distinct pairs: the power of two at or
/// BELOW the 1% size (the token bloom rounds up; at up to 2x the false
/// positives per pair, a small group's pair bloom stays near its token
/// bloom instead of doubling past it), between 32 bytes and the cap.
pub fn pair_filter_bytes(pairs: usize) -> usize {
    let bits = -8.0 * pairs as f64 / (1.0 - TOKEN_FPP.powf(1.0 / 8.0)).ln();
    let bytes = (bits / 8.0) as usize;
    let floor = if bytes.is_power_of_two() { bytes } else { bytes.next_power_of_two() / 2 };
    floor.clamp(32, PAIR_FILTER_MAX_BYTES)
}

/// On wherever the v4 writer is on (token counts and trigrams). Readers of
/// v5 shipped first (#7262); exact "0" is the kill switch back to v4.
pub fn pairs_enabled() -> bool {
    pairs_enabled_from(std::env::var(PAIR_ENABLE_ENV).ok().as_deref())
}

fn pairs_enabled_from(value: Option<&str>) -> bool {
    value != Some("0")
}

/// NAN-4217: emit whole-address tokens (v6) where the v5 writer is on and
/// `NANO_LAKE_IP_TOKEN_INDEX` is exactly "1". Off by default until every
/// reader understands v6.
pub fn ip_tokens_enabled() -> bool {
    ip_tokens_enabled_from(std::env::var(IP_TOKEN_ENABLE_ENV).ok().as_deref())
}

fn ip_tokens_enabled_from(value: Option<&str>) -> bool {
    value == Some("1")
}

/// An IPv4 octet as the address token writes it: 1-3 ASCII digits, at most
/// 255 (leading zeros are kept literally, `010` is its own spelling).
fn ipv4_octet(piece: &[u8]) -> bool {
    (1..=3).contains(&piece.len())
        && piece.iter().all(u8::is_ascii_digit)
        && piece.iter().fold(0_u32, |n, b| n * 10 + u32::from(b - b'0')) <= 255
}

/// `text` is exactly `a.b.c.d` of [`ipv4_octet`]s.
fn is_ipv4_address(text: &[u8]) -> bool {
    let mut octets = 0;
    for piece in text.split(|b| *b == b'.') {
        if !ipv4_octet(piece) {
            return false;
        }
        octets += 1;
    }
    octets == 4
}

/// `text` (ASCII hex digits and `:` only) parses as an IPv6 address.
fn is_ipv6_address(text: &[u8]) -> bool {
    text.iter().filter(|b| **b == b':').count() >= 2
        && std::str::from_utf8(text).is_ok_and(|text| text.parse::<std::net::Ipv6Addr>().is_ok())
}

/// IPv6 candidates: runs of ASCII hex digits and `:`. A run that holds
/// neither `::` nor seven colons cannot contain an address, so timestamps
/// (`10:34:48`) and MACs (`00:1a:2b:3c:4d:5e`) cost one scan of the run.
fn is_hex_or_colon(b: u8) -> bool {
    b.is_ascii_hexdigit() || b == b':'
}

/// NAN-4217: the whole-address tokens of `text` (v6), lowercased, shared by
/// ingest. A bare IP needle is matched by the lake term regex: the needle's
/// characters in order, ASCII case folded, with no ASCII alphanumeric (and
/// no non-ASCII character) touching an alphanumeric end. So in any value it
/// matches, the needle occurs as a substring whose edges are:
///
/// - IPv4 `a.b.c.d`: each octet is a WHOLE maximal run of ASCII digits (its
///   neighbours are `.` inside the needle, non-digits at the ends). Every
///   four consecutive digit runs joined by single dots, each an
///   [`ipv4_octet`], are therefore emitted: `1.48.170.34.111` yields
///   `1.48.170.34` and `48.170.34.111`.
/// - IPv6: a substring of one maximal run of hex digits and colons that
///   starts at the run start, after a `:` or on a `:`, and ends likewise.
///   Every such substring that parses as an IPv6 address is emitted
///   (`fe80::1` yields `fe80::1`, `::1`, `fe80::` ...; bounded by the run
///   length, at most 45 bytes per address).
///
/// Superset by construction: an emitted token may be an occurrence the term
/// regex then rejects (`x48.170.34.111`), never the reverse.
pub fn address_tokens(text: &str, mut emit: impl FnMut(&str)) {
    let bytes = text.as_bytes();
    // IPv4: walk maximal digit runs, remembering the last three that were
    // joined to their successor by exactly one '.'.
    let mut chain: [(usize, usize); 4] = [(0, 0); 4];
    let mut chained = 0_usize;
    let mut at = 0;
    while at < bytes.len() {
        if !bytes[at].is_ascii_digit() {
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
        let joined = chained > 0 && start >= 1 && bytes[start - 1] == b'.' && chain[(chained - 1) % 4].1 + 1 == start;
        if !joined {
            chained = 0;
        }
        if ipv4_octet(&bytes[start..at]) {
            chain[chained % 4] = (start, at);
            chained += 1;
            if chained >= 4 {
                let first = chain[(chained - 4) % 4].0;
                // ASCII digits and dots: always valid UTF-8 boundaries.
                emit(&text[first..at]);
            }
        } else {
            chained = 0;
        }
    }
    // IPv6: maximal runs of hex digits and colons.
    let mut lowered = String::new();
    let mut at = 0;
    while at < bytes.len() {
        if !is_hex_or_colon(bytes[at]) {
            at += 1;
            continue;
        }
        let start = at;
        while at < bytes.len() && is_hex_or_colon(bytes[at]) {
            at += 1;
        }
        let run = &bytes[start..at];
        let colons = run.iter().filter(|b| **b == b':').count();
        if colons < 2 || (colons < 7 && !run.windows(2).any(|w| w == b"::")) {
            continue;
        }
        let edge_start = |i: usize| i == 0 || run[i - 1] == b':' || run[i] == b':';
        let edge_end = |j: usize| j == run.len() || run[j] == b':' || run[j - 1] == b':';
        // Prefix counts of colons and of `::` starts, so a window is parsed
        // only when it can be an address: seven colons and no `::`, or one
        // `::` and at most eight colons (`::2:3:4:5:6:7:8`). Long colon runs (certificate
        // fingerprints `AB:CD:...`) then cost a few parses per start, not
        // one per (start, end) pair.
        let mut colons_before = Vec::with_capacity(run.len() + 1);
        let mut doubles_before = Vec::with_capacity(run.len() + 1);
        let (mut c, mut d) = (0_usize, 0_usize);
        for k in 0..run.len() {
            colons_before.push(c);
            doubles_before.push(d);
            c += usize::from(run[k] == b':');
            d += usize::from(run[k] == b':' && run.get(k + 1) == Some(&b':'));
        }
        colons_before.push(c);
        doubles_before.push(d);
        for i in (0..run.len()).filter(|i| edge_start(*i)) {
            // An address is at most 39 hex/colon bytes (`ffff:...` x8).
            for j in (i + 2..=run.len().min(i + 39)).filter(|j| edge_end(*j)) {
                let colons = colons_before[j] - colons_before[i];
                // `::` pairs starting inside the window (the last byte's
                // pair would reach past it).
                let doubles = doubles_before[j - 1] - doubles_before[i];
                if colons > 8 {
                    break;
                }
                if !((doubles == 0 && colons == 7) || doubles == 1) {
                    continue;
                }
                let candidate = &run[i..j];
                if is_ipv6_address(candidate) {
                    lowered.clear();
                    lowered.extend(candidate.iter().map(|b| b.to_ascii_lowercase() as char));
                    emit(&lowered);
                }
            }
        }
    }
}

/// NAN-4217: the whole-address token a bare keyword `value` requires in any
/// row it matches, or `None` when it is not exactly one IPv4 (four
/// [`ipv4_octet`]s) or IPv6 address (hex digits and colons only; an
/// embedded dotted IPv4 tail is left to the other evidence). See
/// [`address_tokens`] for why every matching value holds it.
pub fn address_needle(value: &str) -> Option<String> {
    let trimmed = value.trim().as_bytes();
    if is_ipv4_address(trimmed) || (trimmed.iter().all(|b| is_hex_or_colon(*b)) && is_ipv6_address(trimmed)) {
        return Some(trimmed.iter().map(|b| b.to_ascii_lowercase() as char).collect());
    }
    None
}

/// The bloom key of adjacent tokens `a`, `b` (already lowercased).
pub fn pair_key(a: &str, b: &str) -> [u8; 8] {
    let mut hasher = twox_hash::XxHash64::with_seed(0x4e41_4e4f_5041_4952);
    std::hash::Hasher::write(&mut hasher, a.as_bytes());
    std::hash::Hasher::write(&mut hasher, &[0x1f]);
    std::hash::Hasher::write(&mut hasher, b.as_bytes());
    std::hash::Hasher::finish(&hasher).to_le_bytes()
}

/// Adjacent token pairs of `text` under [`tokenize`]: two tokens with only
/// separators between them. A piece over [`TOKEN_MAX_BYTES`] is not a token
/// and breaks adjacency on both sides. Shared by ingest and query.
pub fn adjacent_pairs(text: &str, mut emit: impl FnMut(&str, &str)) {
    let mut previous: Option<std::borrow::Cow<'_, str>> = None;
    for piece in text.split(|c: char| !c.is_alphanumeric()) {
        if piece.is_empty() {
            continue;
        }
        let token: std::borrow::Cow<'_, str> =
            if piece.chars().all(|c| !c.is_uppercase()) { piece.into() } else { piece.to_lowercase().into() };
        if token.len() > TOKEN_MAX_BYTES {
            previous = None;
            continue;
        }
        if let Some(previous) = &previous {
            emit(previous, &token);
        }
        previous = Some(token);
    }
}
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
    pairs: Option<HashSet<u64>>,
    pairs_overflow: bool,
    /// v6: whole-address tokens join the token bloom and block index.
    addresses: bool,
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

    /// A v5 builder: v4 plus the adjacent-pair bloom.
    pub fn with_pairs(block_rows: u32) -> Self {
        let mut builder = Self::with_trigrams(block_rows);
        builder.pairs = Some(HashSet::new());
        builder
    }

    /// A v6 builder: v5 whose token bloom and block index also hold every
    /// whole IP address of the text ([`address_tokens`]).
    pub fn with_addresses(block_rows: u32) -> Self {
        let mut builder = Self::with_pairs(block_rows);
        builder.addresses = true;
        builder
    }

    /// The v2/v3 builder the writers use for `block_rows` (`None`: v1).
    pub fn for_writer(block_rows: Option<u32>) -> Self {
        match block_rows {
            Some(block_rows) if super::token_counts::enabled() && trigrams_enabled() && pairs_enabled() && ip_tokens_enabled() =>
                Self::with_addresses(block_rows),
            Some(block_rows) if super::token_counts::enabled() && trigrams_enabled() && pairs_enabled() => Self::with_pairs(block_rows),
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
        if let Some(pairs) = &mut self.pairs {
            let overflow = &mut self.pairs_overflow;
            let mut add = |a: &str, b: &str| {
                if pairs.len() < PAIR_DISTINCT_CAP {
                    pairs.insert(u64::from_le_bytes(pair_key(a, b)));
                } else {
                    *overflow = true;
                }
            };
            adjacent_pairs(text, &mut add);
            // The keyword SQL matches case-insensitively under RE2 simple
            // folding, where long-s and the Kelvin sign equal ASCII s/k
            // (`to_lowercase` maps only the Kelvin sign). Index the folded
            // spelling too, as the trigram bloom does.
            if !text.is_ascii() {
                let folded = text.to_lowercase().replace('ſ', "s");
                adjacent_pairs(&folded, &mut add);
            }
        }
        let mut add = |token: &str| {
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
        };
        tokenize(text, &mut add);
        // A whole address holds `.`/`:`, which no split token does, so it
        // never collides with one.
        if self.addresses {
            address_tokens(text, &mut add);
        }
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
        let pairs = match self.pairs {
            None => None,
            Some(_) if self.pairs_overflow => Some(PairBloom { pairs: 0, bitset: vec![0xff; 32] }),
            Some(pairs) if pairs.is_empty() => Some(PairBloom { pairs: 0, bitset: Vec::new() }),
            Some(pairs) => {
                let mut filter = Sbbf::new_with_num_of_bytes(pair_filter_bytes(pairs.len()));
                for pair in &pairs {
                    filter.insert(pair.to_le_bytes().as_slice());
                }
                let mut bitset = Vec::new();
                filter.write_bitset(&mut bitset)?;
                Some(PairBloom { pairs: pairs.len() as u64, bitset })
            }
        };
        if self.tokens.is_empty() {
            return Ok(TokenGroup { rows: self.rows, tokens: 0, bitset: Vec::new(), saturated: false, blocks, counts, trigrams, pairs, addresses: self.addresses });
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
        Ok(TokenGroup { rows: self.rows, tokens: distinct, bitset, saturated, blocks, counts, trigrams, pairs, addresses: self.addresses })
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
    /// v5 only: the adjacent-pair bloom.
    pub pairs: Option<PairBloom>,
    /// v6: the token bloom and block index also hold every whole address
    /// ([`address_tokens`]), so an address needle may require its token.
    pub addresses: bool,
}

/// One group's adjacent-pair bloom (v5). Empty = the group holds no pair;
/// a saturated (all-ones, 32-byte) bloom matches every pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PairBloom {
    /// Distinct pairs inserted (0 when saturated).
    pub pairs: u64,
    pub bitset: Vec<u8>,
}

impl PairBloom {
    /// May every pair be adjacent somewhere in this group?
    pub fn may_contain_all(&self, pairs: &[[u8; 8]]) -> bool {
        if self.bitset.is_empty() {
            return pairs.is_empty();
        }
        let filter = Sbbf::new(&self.bitset);
        pairs.iter().all(|pair| filter.check(pair.as_slice()))
    }
}

impl TokenGroup {
    pub fn resident_bytes(&self) -> usize {
        std::mem::size_of::<Self>() + self.bitset.capacity()
            + self.blocks.as_ref().map_or(0, |blocks| blocks.times.capacity() * 16
                + blocks.common.resident_bytes() + blocks.fine.resident_bytes())
            + self.counts.as_ref().map_or(0, TokenCounts::resident_bytes)
            + self.trigrams.as_ref().map_or(0, Vec::capacity)
            + self.pairs.as_ref().map_or(0, |pairs| pairs.bitset.capacity())
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
    let with_pairs = groups.iter().filter(|group| group.pairs.is_some()).count();
    ensure!(with_pairs == 0 || (with_pairs == groups.len() && v4), "token groups mix v4 and v5");
    let v5 = with_pairs > 0;
    let with_addresses = groups.iter().filter(|group| group.addresses).count();
    ensure!(with_addresses == 0 || (with_addresses == groups.len() && v5), "token groups mix v5 and v6");
    let v6 = with_addresses > 0;
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
        Some(_) if v6 => {
            out.extend_from_slice(TOKEN_INDEX_MAGIC_V6);
            out.extend_from_slice(&TOKEN_INDEX_VERSION_V6.to_le_bytes());
        }
        Some(_) if v5 => {
            out.extend_from_slice(TOKEN_INDEX_MAGIC_V5);
            out.extend_from_slice(&TOKEN_INDEX_VERSION_V5.to_le_bytes());
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
        if let Some(pairs) = &group.pairs {
            ensure!(pairs.bitset.len() % 32 == 0 && pairs.bitset.len() <= PAIR_FILTER_MAX_BYTES, "invalid pair bloom size");
            out.extend_from_slice(&pairs.pairs.to_le_bytes());
            out.extend_from_slice(&u32::try_from(pairs.bitset.len())?.to_le_bytes());
            out.extend_from_slice(&pairs.bitset);
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
        magic if magic == TOKEN_INDEX_MAGIC_V5 => TOKEN_INDEX_VERSION_V5,
        magic if magic == TOKEN_INDEX_MAGIC_V6 => TOKEN_INDEX_VERSION_V6,
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
        let trigrams = if version >= TOKEN_INDEX_VERSION_V4 { Some(cursor.take(TRIGRAM_FILTER_BYTES)?.to_vec()) } else { None };
        let pairs = if version >= TOKEN_INDEX_VERSION_V5 {
            let pairs = cursor.u64()?;
            let len = cursor.u32()? as usize;
            if len % 32 != 0 || len > PAIR_FILTER_MAX_BYTES {
                bail!("pair filter length is invalid");
            }
            Some(PairBloom { pairs, bitset: cursor.take(len)?.to_vec() })
        } else {
            None
        };
        let addresses = version >= TOKEN_INDEX_VERSION_V6;
        out.push(TokenGroup { rows, tokens, bitset, saturated, blocks, counts, trigrams, pairs, addresses });
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

    /// NAN-4164 follow-up: the pair writer is on unless exactly "0".
    #[test]
    fn pair_index_is_on_unless_killed() {
        assert!(pairs_enabled_from(None));
        assert!(pairs_enabled_from(Some("1")));
        assert!(pairs_enabled_from(Some("")));
        assert!(!pairs_enabled_from(Some("0")));
    }

    /// NAN-4164: v5 carries an adjacent-pair bloom per group; pairs break
    /// at over-long pieces, fold like the trigram bloom, and round-trip.
    #[test]
    fn v5_pair_bloom_round_trips_and_answers_adjacency() {
        let mut seen = Vec::new();
        adjacent_pairs("src=10.1.4.20, Failed  password", |a, b| seen.push(format!("{a} {b}")));
        assert_eq!(seen, ["src 10", "10 1", "1 4", "4 20", "20 failed", "failed password"]);
        let long = "x".repeat(TOKEN_MAX_BYTES + 1);
        seen.clear();
        adjacent_pairs(&format!("a {long} b c"), |a, b| seen.push(format!("{a} {b}")));
        assert_eq!(seen, ["b c"]);

        let mut builder = TokenGroupBuilder::with_pairs(4);
        builder.add_row_at(0);
        builder.add_text("src=10.1.4.20 at 2026-10-01T04:20:00");
        builder.add_text("ſysmon-x \u{212A}erberos.y");
        builder.add_row_at(1);
        builder.add_text("Computer: WS-FIN-095.corp");
        let group = builder.finish().unwrap();
        let bloom = group.pairs.clone().unwrap();
        assert!(bloom.pairs > 0 && !bloom.bitset.is_empty() && bloom.bitset.len() <= PAIR_FILTER_MAX_BYTES);
        let has = |a: &str, b: &str| bloom.may_contain_all(&[pair_key(a, b)]);
        for (a, b) in [("10", "1"), ("1", "4"), ("4", "20"), ("ws", "fin"), ("fin", "095"), ("sysmon", "x"), ("kerberos", "y")] {
            assert!(has(a, b), "{a} {b}");
        }
        // Pieces present, never adjacent in this order (bloom false
        // positives are possible in general, not at these sizes).
        assert!(!has("20", "10") || !has("095", "fin") || !has("1", "10"));

        let bytes = encode_token_index(&[group.clone()]).unwrap();
        assert!(bytes.starts_with(TOKEN_INDEX_MAGIC_V5));
        assert_eq!(decode_token_index(&bytes).unwrap(), vec![group.clone()]);
        assert_eq!(decode_leased_token_index(&bytes).unwrap(), vec![group.clone()]);
        let mut v4 = group.clone();
        v4.pairs = None;
        assert!(encode_token_index(&[group.clone(), v4.clone()]).is_err(), "v4 and v5 groups never mix");
        assert!(encode_token_index(&[v4]).unwrap().starts_with(TOKEN_INDEX_MAGIC_V4));
        assert!(decode_leased_token_index(&bytes[..bytes.len() - 40]).is_err());

        assert_eq!(pair_filter_bytes(1), 32);
        assert_eq!(pair_filter_bytes(231_292), 256 * 1024, "a 14k-row large-tenant group");
        assert_eq!(pair_filter_bytes(647_194), PAIR_FILTER_MAX_BYTES, "a full large-tenant group");
        assert_eq!(pair_filter_bytes(50_000_000), PAIR_FILTER_MAX_BYTES);

        let empty = TokenGroupBuilder::with_pairs(4).finish().unwrap();
        assert_eq!(empty.pairs, Some(PairBloom { pairs: 0, bitset: Vec::new() }));
        assert!(!empty.pairs.as_ref().unwrap().may_contain_all(&[pair_key("a", "b")]));
        assert!(empty.pairs.as_ref().unwrap().may_contain_all(&[]));
    }

    fn addresses_of(text: &str) -> Vec<String> {
        let mut out = Vec::new();
        address_tokens(text, |t| out.push(t.to_string()));
        out
    }

    /// NAN-4217: whole-address tokens: every dotted window of four octets,
    /// IPv6 substrings on colon edges, lowercased; near misses yield nothing
    /// that a different needle could take for its own.
    #[test]
    fn address_tokens_cover_dotted_windows_and_ipv6() {
        assert_eq!(addresses_of("src=48.170.34.111:443 dst=48.170.34.11"), ["48.170.34.111", "48.170.34.11"]);
        assert_eq!(addresses_of("148.170.34.1119 1.48.170.34.111.5"), ["1.48.170.34", "48.170.34.111", "170.34.111.5"]);
        assert_eq!(addresses_of("256.1.1.1 1..2.3.4 1.2.3 01.002.3.4"), ["01.002.3.4"]);
        assert_eq!(addresses_of("v1.2.3.4-beta x10.0.0.5y"), ["1.2.3.4", "10.0.0.5"], "superset: letters do not block");
        assert!(addresses_of("2026-10-20T10:34:48.123Z 00:1a:2b:3c:4d:5e").is_empty());
        let v6 = addresses_of("from FE80::1%eth0 to 2001:db8:0:0:0:0:0:1.");
        for want in ["fe80::1", "fe80::", "::1", "2001:db8:0:0:0:0:0:1"] {
            assert!(v6.iter().any(|t| t == want), "{want} in {v6:?}");
        }
        assert!(v6.iter().all(|t| t.parse::<std::net::Ipv6Addr>().is_ok() && *t == t.to_ascii_lowercase()));
        // A long colon run (certificate fingerprint) holds 8-group windows.
        let fingerprint = (0..32).map(|i| format!("{:02X}", i * 7 % 256)).collect::<Vec<_>>().join(":");
        let windows = addresses_of(&fingerprint);
        assert_eq!(windows.len(), 32 - 7, "{windows:?}");
        assert_eq!(windows[0], "00:07:0e:15:1c:23:2a:31");

        assert_eq!(address_needle(" 48.170.34.111 ").as_deref(), Some("48.170.34.111"));
        assert_eq!(address_needle("FE80::1").as_deref(), Some("fe80::1"));
        assert!(addresses_of("x ::2:3:4:5:6:7:8 y").iter().any(|t| t == "::2:3:4:5:6:7:8"));
        assert!(addresses_of("1:2:3:4:5:6:7:: z").iter().any(|t| t == "1:2:3:4:5:6:7::"));
        for not in ["48.170.34", "48.170.34.1119", "256.0.0.1", "10.0.0.5:443", "fe80::1%eth0", "::ffff:1.2.3.4", "host-1", "a:b"] {
            assert_eq!(address_needle(not), None, "{not}");
        }
    }

    /// NAN-4217: no false negatives. For every haystack built from address
    /// fragments, separators, letters and non-ASCII characters, a needle the
    /// lake term regex matches (its characters, ASCII case-insensitive, with
    /// no ASCII alphanumeric or non-ASCII character touching an alphanumeric
    /// end) is among the haystack's address tokens.
    #[test]
    fn address_tokens_hold_every_term_match() {
        fn term_matches(haystack: &str, needle: &str) -> bool {
            let (hay, needle) = (haystack.to_ascii_lowercase(), needle.to_ascii_lowercase());
            let token_char = |c: Option<char>| c.is_some_and(|c| c.is_ascii_alphanumeric() || !c.is_ascii());
            hay.match_indices(&needle).any(|(at, _)| {
                let starts = needle.chars().next().is_some_and(|c| c.is_ascii_alphanumeric());
                let ends = needle.chars().last().is_some_and(|c| c.is_ascii_alphanumeric());
                (!starts || !token_char(hay[..at].chars().last()))
                    && (!ends || !token_char(hay[at + needle.len()..].chars().next()))
            })
        }
        const FRAGMENTS: [&str; 21] = [
            "48.170.34.111", "148.170.34.1119", "48.170.34.11", "1.", ".5", ".", ":", "::", "1", "x", " ", "é",
            "FE80::1", "fe80:0:0:0:0:0:0:1", "::1", "2001:DB8::", "a", "0", "10.0.0.5", "-", "::2:3:4:5:6:7:8",
        ];
        const NEEDLES: [&str; 11] = [
            "48.170.34.111", "48.170.34.11", "1.48.170.34", "170.34.111.5", "10.0.0.5", "fe80::1", "2001:db8::", "1::1",
            "fe80::", "0.0.5.1", "::2:3:4:5:6:7:8",
        ];
        let mut haystacks = Vec::new();
        for a in FRAGMENTS {
            for b in FRAGMENTS {
                for c in FRAGMENTS {
                    haystacks.push(format!("{a}{b}{c}"));
                }
            }
        }
        let mut matched = 0;
        for haystack in &haystacks {
            let tokens = addresses_of(haystack);
            for needle in NEEDLES {
                let address = address_needle(needle).expect("an address needle");
                if term_matches(haystack, needle) {
                    matched += 1;
                    assert!(tokens.contains(&address), "{needle:?} matches {haystack:?} but tokens are {tokens:?}");
                }
            }
        }
        assert!(matched > 1_000, "{matched}");
    }

    /// NAN-4217: v6 = the v5 layout with address tokens in the token bloom
    /// and block index; never mixed with v5; off by default.
    #[test]
    fn v6_round_trips_and_holds_addresses() {
        assert!(!ip_tokens_enabled_from(None));
        assert!(!ip_tokens_enabled_from(Some("0")));
        assert!(!ip_tokens_enabled_from(Some("")));
        assert!(ip_tokens_enabled_from(Some("1")));

        let mut builder = TokenGroupBuilder::with_addresses(4);
        builder.add_row_at(0);
        builder.add_text("src=48.170.34.111 dst=FE80::1");
        builder.add_row_at(1);
        builder.add_text("148.170.34.1119 48.170.34.11");
        let group = builder.finish().unwrap();
        assert!(group.addresses);
        assert!(group.may_contain_all(&["48.170.34.111".into(), "fe80::1".into(), "48".into(), "170".into()]));
        let blocks = group.blocks.as_ref().unwrap();
        assert_eq!(blocks.blocks_with_all(&["48.170.34.111".into()]), Some(vec![true]));

        let bytes = encode_token_index(&[group.clone()]).unwrap();
        assert!(bytes.starts_with(TOKEN_INDEX_MAGIC_V6));
        assert_eq!(decode_token_index(&bytes).unwrap(), vec![group.clone()]);
        assert_eq!(decode_leased_token_index(&bytes).unwrap(), vec![group.clone()]);
        let mut v5 = group.clone();
        v5.addresses = false;
        assert!(encode_token_index(&[group.clone(), v5.clone()]).is_err(), "v5 and v6 groups never mix");
        let v5_bytes = encode_token_index(&[v5]).unwrap();
        assert!(v5_bytes.starts_with(TOKEN_INDEX_MAGIC_V5));
        assert!(!decode_token_index(&v5_bytes).unwrap()[0].addresses);
        // Same layout: only the magic and version differ.
        assert_eq!(bytes[12..bytes.len() - 32], v5_bytes[12..v5_bytes.len() - 32]);
    }

    /// NAN-4164/NAN-4217 sizing probe: `tokens.nti` bytes (and builder
    /// time) of v4 vs v5 vs v6 over a JSONL
    /// sample of body fields (one object per row, as `* | table <body
    /// fields>` returns them), in 65,536-row groups.
    /// `NANO_PAIR_SAMPLE=rows.jsonl cargo test -p nanosiem-lake-worker --lib
    /// v5_size_probe -- --ignored --nocapture`
    #[test]
    #[ignore = "needs NANO_PAIR_SAMPLE"]
    fn v5_size_probe() {
        let path = std::env::var("NANO_PAIR_SAMPLE").expect("NANO_PAIR_SAMPLE");
        let rows = std::fs::read_to_string(path).unwrap().lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(line).ok())
            .collect::<Vec<_>>();
        for chunk in rows.chunks(65_536) {
            let (mut v4, mut v5, mut v6) =
                (TokenGroupBuilder::with_trigrams(1_024), TokenGroupBuilder::with_pairs(1_024), TokenGroupBuilder::with_addresses(1_024));
            let feed = |builder: &mut TokenGroupBuilder| {
                for (i, row) in chunk.iter().enumerate() {
                    builder.add_row_at(i as i64 * 15_000);
                    for (field, value) in row {
                        let Some(text) = value.as_str() else { continue };
                        builder.add_text(text);
                        if field == "message" || field == "raw_data" {
                            builder.add_body(text);
                        }
                    }
                }
            };
            let started = std::time::Instant::now();
            feed(&mut v4);
            let v4_ms = started.elapsed().as_secs_f64() * 1e3;
            let started = std::time::Instant::now();
            feed(&mut v5);
            let v5_ms = started.elapsed().as_secs_f64() * 1e3;
            let started = std::time::Instant::now();
            feed(&mut v6);
            let v6_ms = started.elapsed().as_secs_f64() * 1e3;
            let (v4, v5, v6) = (v4.finish().unwrap(), v5.finish().unwrap(), v6.finish().unwrap());
            let pairs = v5.pairs.clone().unwrap();
            println!(
                "rows={} tokens={} token_bloom={} pairs={} pair_bloom={} v4_bytes={} v5_bytes={} v6_tokens={} v6_token_bloom={} v6_bytes={} feed_ms v4={v4_ms:.0} v5={v5_ms:.0} v6={v6_ms:.0}",
                chunk.len(), v4.tokens, v4.bitset.len(), pairs.pairs, pairs.bitset.len(),
                encode_token_index(std::slice::from_ref(&v4)).unwrap().len(), encode_token_index(std::slice::from_ref(&v5)).unwrap().len(),
                v6.tokens, v6.bitset.len(), encode_token_index(std::slice::from_ref(&v6)).unwrap().len(),
            );
        }
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
