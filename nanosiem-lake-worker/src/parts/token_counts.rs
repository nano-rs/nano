// SPDX-License-Identifier: AGPL-3.0-or-later

//! Exact per-minute row counts of a row group's dense keyword tokens
//! (`tokens-NNNNN.nti` v3, NANOTKI3).
//!
//! A bare keyword compiles to
//! `(hasAllTokens(lower(message), 't') OR hasAllTokens(lower(raw_data), 't'))`.
//! For a single-token needle a row matches exactly when `t` is one of the
//! ClickHouse tokens of `lower(message)` or of `lower(raw_data)`. This module
//! reproduces that tokenization byte for byte ([`ch_tokens`]: ClickHouse
//! `lower` folds ASCII only, and `splitByNonAlpha` splits on ASCII
//! non-alphanumerics while every byte >= 0x80 is a token byte). For every
//! token that matches at least [`COUNT_THRESHOLD`] rows of the group it stores
//! how many rows match in each minute.
//!
//! The table is a cache, never a proof of absence: a token that is not listed
//! may still match rows, and the reader then scans that group as before. A
//! listed token's counts cover every row of the group (a token is either
//! tracked from its first row or never), so for a group that lies entirely
//! inside a query window the histogram and total of a single-token keyword
//! come from here without reading the group. Counts are rows, not token
//! occurrences: a row that holds the token several times, or in both
//! columns, counts once.

use anyhow::{bail, ensure, Result};
use std::collections::HashMap;
use std::hash::BuildHasherDefault;

use super::sidecar::Cursor;

/// Tokens matching fewer rows than this in a group are not listed; their
/// rows sit in at most this many blocks, which the v2 block index already
/// finds cheaply.
pub const COUNT_THRESHOLD: u32 = 16;
/// Longer tokens are never listed (and never answered from the table).
pub const COUNT_TOKEN_MAX_BYTES: usize = 128;
/// Distinct tokens tracked per group; later new tokens are not listed.
/// Bounds builder memory at ~100 MiB for one group.
const DISTINCT_CAP: usize = 1_000_000;
/// A full (not front-coded) token every this many entries, for binary search.
const RESTART_INTERVAL: usize = 32;
const MINUTE_US: i64 = 60_000_000;

/// The columns a bare keyword tests.
pub const BODY_COLUMNS: [&str; 2] = ["message", "raw_data"];

static ENABLED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Turn v3 writing on for this process (with the v2 block index: cell flag
/// `lean_keyword_index_v1`). Readers always understand v3.
pub fn set_enabled(enabled: bool) {
    ENABLED.store(enabled, std::sync::atomic::Ordering::Relaxed);
}

/// Whether v2 writers in this process also emit the v3 counts.
pub fn enabled() -> bool {
    ENABLED.load(std::sync::atomic::Ordering::Relaxed)
}

/// ClickHouse `tokens(lower(text))` with the default `splitByNonAlpha`
/// tokenizer: maximal runs of ASCII alphanumerics and non-ASCII bytes, with
/// ASCII letters lowered. `scratch` holds each emitted token.
pub fn ch_tokens(text: &str, scratch: &mut Vec<u8>, mut emit: impl FnMut(&[u8])) {
    scratch.clear();
    for &byte in text.as_bytes() {
        if byte.is_ascii_alphanumeric() || byte >= 0x80 {
            scratch.push(byte.to_ascii_lowercase());
        } else if !scratch.is_empty() {
            emit(scratch);
            scratch.clear();
        }
    }
    if !scratch.is_empty() {
        emit(scratch);
        scratch.clear();
    }
}

/// The single ClickHouse token of a keyword needle, when the needle is
/// exactly one token of ASCII alphanumerics (the only needles the table
/// answers). `hasAllTokens(lower(col), n)` with such a needle is true exactly
/// when that token is a token of `lower(col)`.
pub fn single_token(needle: &str) -> Option<String> {
    let lowered = needle.to_ascii_lowercase();
    (!lowered.is_empty()
        && lowered.len() <= COUNT_TOKEN_MAX_BYTES
        && lowered.bytes().all(|byte| byte.is_ascii_alphanumeric()))
    .then_some(lowered)
}

/// FxHash (rustc's hasher) with a murmur3 finalizer: a multiply-rotate over
/// 8-byte words. Keys are
/// short tokens hashed tens of millions of times an hour, where SipHash and
/// xxHash cost more than the table work. Not DoS-resistant, which does not
/// matter for a builder bounded by `DISTINCT_CAP`.
#[derive(Default, Clone, Copy)]
struct FxHasher(u64);

impl std::hash::Hasher for FxHasher {
    fn write(&mut self, bytes: &[u8]) {
        const SEED: u64 = 0x51_7c_c1_b7_27_22_0a_95;
        let mut hash = self.0;
        let mut chunks = bytes.chunks_exact(8);
        for chunk in &mut chunks {
            hash = (hash.rotate_left(5) ^ u64::from_le_bytes(chunk.try_into().expect("8 bytes"))).wrapping_mul(SEED);
        }
        let rest = chunks.remainder();
        if !rest.is_empty() {
            let mut word = [0_u8; 8];
            word[..rest.len()].copy_from_slice(rest);
            hash = (hash.rotate_left(5) ^ u64::from_le_bytes(word)).wrapping_mul(SEED);
        }
        self.0 = hash;
    }
    fn write_usize(&mut self, value: usize) {
        self.0 = (self.0.rotate_left(5) ^ value as u64).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95);
    }
    fn finish(&self) -> u64 {
        // The multiply leaves the low bits (the table index) depending only
        // on the first bytes; fold the high bits down (murmur3 finalizer).
        let mut hash = self.0;
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
        hash ^ (hash >> 33)
    }
}

type Hasher = BuildHasherDefault<FxHasher>;

struct Acc {
    rows: u32,
    /// Row index of the last row counted (a row counts once).
    last_row: u32,
    /// The first `(minute, rows)`, inline: most tokens occur in one row.
    first: (i64, u32),
    /// Later minutes, sorted (rows arrive time-sorted).
    rest: Vec<(i64, u32)>,
}

impl Acc {
    fn new(row: u32, minute: i64) -> Self {
        Self { rows: 1, last_row: row, first: (minute, 1), rest: Vec::new() }
    }

    fn add(&mut self, row: u32, minute: i64) {
        if self.last_row == row {
            return;
        }
        self.last_row = row;
        self.rows += 1;
        match self.rest.last_mut() {
            Some((last, count)) if *last == minute => *count += 1,
            None if self.first.0 == minute => self.first.1 += 1,
            _ if minute < self.first.0 => {
                self.rest.insert(0, self.first);
                self.first = (minute, 1);
            }
            _ if minute == self.first.0 => self.first.1 += 1,
            _ => match self.rest.binary_search_by_key(&minute, |(m, _)| *m) {
                Ok(at) => self.rest[at].1 += 1,
                Err(at) => self.rest.insert(at, (minute, 1)),
            },
        }
    }

    fn minutes(self) -> Vec<(i64, u32)> {
        let mut out = Vec::with_capacity(self.rest.len() + 1);
        out.push(self.first);
        out.extend(self.rest);
        out
    }
}

/// Collects one row group's token counts. Rows must be started in order
/// with [`Self::start_row`]; body texts follow with [`Self::add_text`].
pub struct CountBuilder {
    tokens: HashMap<Box<[u8]>, Acc, Hasher>,
    rows: u32,
    minute: i64,
    min_time_us: i64,
    max_time_us: i64,
    scratch: Vec<u8>,
}

impl Default for CountBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl CountBuilder {
    pub fn new() -> Self {
        Self {
            tokens: HashMap::default(),
            rows: 0,
            minute: 0,
            min_time_us: i64::MAX,
            max_time_us: i64::MIN,
            scratch: Vec::with_capacity(64),
        }
    }

    pub fn start_row(&mut self, time_us: i64) {
        self.rows += 1;
        self.minute = time_us.div_euclid(MINUTE_US);
        self.min_time_us = self.min_time_us.min(time_us);
        self.max_time_us = self.max_time_us.max(time_us);
    }

    /// One body column value of the current row.
    pub fn add_text(&mut self, text: &str) {
        debug_assert!(self.rows > 0, "add_text before start_row");
        let row = self.rows;
        let minute = self.minute;
        let tokens = &mut self.tokens;
        let mut scratch = std::mem::take(&mut self.scratch);
        ch_tokens(text, &mut scratch, |token| {
            if token.len() > COUNT_TOKEN_MAX_BYTES {
                return;
            }
            if let Some(acc) = tokens.get_mut(token) {
                acc.add(row, minute);
            } else if tokens.len() < DISTINCT_CAP {
                tokens.insert(token.into(), Acc::new(row, minute));
            }
        });
        self.scratch = scratch;
    }

    pub fn finish(self) -> TokenCounts {
        let mut listed = self
            .tokens
            .into_iter()
            .filter(|(_, acc)| acc.rows >= COUNT_THRESHOLD)
            .map(|(token, acc)| (token, acc.minutes()))
            .collect::<Vec<_>>();
        listed.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        let (min_time_us, max_time_us) = if self.rows == 0 { (0, 0) } else { (self.min_time_us, self.max_time_us) };
        let base_minute = min_time_us.div_euclid(MINUTE_US);
        let mut entries = Vec::new();
        let mut restarts = Vec::new();
        let mut previous: &[u8] = &[];
        for (index, (token, minutes)) in listed.iter().enumerate() {
            let shared = if index % RESTART_INTERVAL == 0 {
                restarts.push(entries.len() as u32);
                0
            } else {
                shared_prefix(previous, token)
            };
            put_varint(&mut entries, shared as u64);
            put_varint(&mut entries, (token.len() - shared) as u64);
            entries.extend_from_slice(&token[shared..]);
            put_varint(&mut entries, minutes.len() as u64);
            let mut at = base_minute;
            for (minute, count) in minutes {
                put_varint(&mut entries, (minute - at) as u64);
                put_varint(&mut entries, u64::from(*count));
                at = *minute;
            }
            previous = token;
        }
        TokenCounts {
            threshold: COUNT_THRESHOLD,
            rows: self.rows,
            min_time_us,
            max_time_us,
            base_minute,
            tokens: listed.len() as u32,
            restarts,
            entries,
        }
    }
}

fn shared_prefix(a: &[u8], b: &[u8]) -> usize {
    a.iter().zip(b).take_while(|(x, y)| x == y).count()
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn get_varint(bytes: &[u8], at: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..64).step_by(7) {
        let Some(&byte) = bytes.get(*at) else { bail!("token counts are truncated") };
        *at += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    bail!("token count varint is too long")
}

/// One row group's listed tokens and their per-minute row counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenCounts {
    pub threshold: u32,
    pub rows: u32,
    /// Exact `[min, max]` event time (µs) of the group's rows.
    pub min_time_us: i64,
    pub max_time_us: i64,
    base_minute: i64,
    tokens: u32,
    restarts: Vec<u32>,
    entries: Vec<u8>,
}

impl TokenCounts {
    pub fn resident_bytes(&self) -> usize {
        self.restarts.capacity() * 4 + self.entries.capacity()
    }

    pub fn tokens(&self) -> usize {
        self.tokens as usize
    }

    pub fn encoded_len(&self) -> usize {
        4 + 4 + 4 + 8 + 8 + 8 + 4 + 4 + self.restarts.len() * 4 + 4 + self.entries.len()
    }

    /// `(minute, rows)` of `token`, or `None` when it is not listed.
    pub fn lookup(&self, token: &[u8]) -> Result<Option<Vec<(i64, u32)>>> {
        if self.restarts.is_empty() {
            return Ok(None);
        }
        // The last restart whose full token is <= the needle.
        let full_at = |restart: u32| -> Result<&[u8]> {
            let mut at = restart as usize;
            ensure!(get_varint(&self.entries, &mut at)? == 0, "restart token is front-coded");
            let len = get_varint(&self.entries, &mut at)? as usize;
            self.entries.get(at..at.checked_add(len).ok_or_else(|| anyhow::anyhow!("token count length overflows"))?).ok_or_else(|| anyhow::anyhow!("token counts are truncated"))
        };
        let (mut low, mut high) = (0_usize, self.restarts.len());
        while high - low > 1 {
            let mid = (low + high) / 2;
            if full_at(self.restarts[mid])? <= token {
                low = mid;
            } else {
                high = mid;
            }
        }
        let mut at = self.restarts[low] as usize;
        let end = self.restarts.get(low + 1).map_or(self.entries.len(), |next| *next as usize);
        let mut current: Vec<u8> = Vec::new();
        while at < end {
            let shared = get_varint(&self.entries, &mut at)? as usize;
            let len = get_varint(&self.entries, &mut at)? as usize;
            ensure!(shared <= current.len(), "token counts front coding is invalid");
            current.truncate(shared);
            let end_at = at.checked_add(len).ok_or_else(|| anyhow::anyhow!("token count length overflows"))?;
            current.extend_from_slice(self.entries.get(at..end_at).ok_or_else(|| anyhow::anyhow!("token counts are truncated"))?);
            at += len;
            let minutes = get_varint(&self.entries, &mut at)? as usize;
            ensure!(minutes <= self.rows as usize, "token counts list more minutes than rows");
            match current.as_slice().cmp(token) {
                std::cmp::Ordering::Less => {
                    for _ in 0..minutes * 2 {
                        get_varint(&self.entries, &mut at)?;
                    }
                }
                std::cmp::Ordering::Equal => {
                    let mut out = Vec::with_capacity(minutes);
                    let mut minute = self.base_minute;
                    for _ in 0..minutes {
                        minute = minute.checked_add(get_varint(&self.entries, &mut at)? as i64).ok_or_else(|| anyhow::anyhow!("token count minute overflows"))?;
                        let count = u32::try_from(get_varint(&self.entries, &mut at)?)?;
                        out.push((minute, count));
                    }
                    ensure!(out.iter().map(|(_, c)| u64::from(*c)).sum::<u64>() <= u64::from(self.rows), "token counts exceed the group's rows");
                    return Ok(Some(out));
                }
                std::cmp::Ordering::Greater => return Ok(None),
            }
        }
        Ok(None)
    }

    pub(crate) fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        let mut body = Vec::with_capacity(self.encoded_len());
        body.extend_from_slice(&self.threshold.to_le_bytes());
        body.extend_from_slice(&self.rows.to_le_bytes());
        body.extend_from_slice(&self.min_time_us.to_le_bytes());
        body.extend_from_slice(&self.max_time_us.to_le_bytes());
        body.extend_from_slice(&self.base_minute.to_le_bytes());
        body.extend_from_slice(&self.tokens.to_le_bytes());
        body.extend_from_slice(&u32::try_from(self.restarts.len())?.to_le_bytes());
        for restart in &self.restarts {
            body.extend_from_slice(&restart.to_le_bytes());
        }
        body.extend_from_slice(&u32::try_from(self.entries.len())?.to_le_bytes());
        body.extend_from_slice(&self.entries);
        out.extend_from_slice(&u32::try_from(body.len())?.to_le_bytes());
        out.extend_from_slice(&body);
        Ok(())
    }

    pub(crate) fn decode(cursor: &mut Cursor<'_>, group_rows: u64) -> Result<Self> {
        let len = cursor.u32()? as usize;
        let body = cursor.take(len)?;
        let mut inner = Cursor { bytes: body, at: 0 };
        let threshold = inner.u32()?;
        let rows = inner.u32()?;
        ensure!(u64::from(rows) == group_rows, "token counts disagree with the group's rows");
        let min_time_us = inner.u64()? as i64;
        let max_time_us = inner.u64()? as i64;
        let base_minute = inner.u64()? as i64;
        ensure!(rows == 0 || (min_time_us <= max_time_us && base_minute == min_time_us.div_euclid(MINUTE_US)), "token count times are invalid");
        let tokens = inner.u32()?;
        let restart_count = inner.u32()? as usize;
        ensure!(restart_count == (tokens as usize).div_ceil(RESTART_INTERVAL), "token count restarts are invalid");
        let restarts = inner
            .take(restart_count.checked_mul(4).ok_or_else(|| anyhow::anyhow!("token count overflow"))?)?
            .chunks_exact(4)
            .map(|chunk| u32::from_le_bytes(chunk.try_into().expect("4 bytes")))
            .collect::<Vec<_>>();
        let entries_len = inner.u32()? as usize;
        let entries = inner.take(entries_len)?.to_vec();
        ensure!(inner.at == body.len(), "token counts have trailing bytes");
        ensure!(
            restarts.first().is_none_or(|first| *first == 0)
                && restarts.windows(2).all(|pair| pair[0] < pair[1])
                && restarts.last().is_none_or(|last| (*last as usize) < entries.len()),
            "token count restarts are out of order"
        );
        Ok(Self { threshold, rows, min_time_us, max_time_us, base_minute, tokens, restarts, entries })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn build(rows: &[(i64, &[&str])]) -> TokenCounts {
        let mut builder = CountBuilder::new();
        for (time, texts) in rows {
            builder.start_row(*time);
            for text in *texts {
                builder.add_text(text);
            }
        }
        builder.finish()
    }

    #[test]
    fn tokenizer_matches_clickhouse_split_by_non_alpha_over_ascii_lower() {
        // chDB 26.7: tokens(lower('Ünïcode-ABC über x_y 12.5 ÄÖ\tTab'))
        //   = ['Ünïcode','abc','über','x','y','12','5','ÄÖ','tab']
        let mut out = Vec::new();
        let mut scratch = Vec::new();
        ch_tokens("Ünïcode-ABC über x_y 12.5 ÄÖ\tTab", &mut scratch, |t| out.push(String::from_utf8(t.to_vec()).unwrap()));
        assert_eq!(out, ["Ünïcode", "abc", "über", "x", "y", "12", "5", "ÄÖ", "tab"]);
        out.clear();
        ch_tokens("a€b", &mut scratch, |t| out.push(String::from_utf8(t.to_vec()).unwrap()));
        assert_eq!(out, ["a€b"]);
    }

    #[test]
    fn single_token_needles_only() {
        assert_eq!(single_token("PowerShell").as_deref(), Some("powershell"));
        assert_eq!(single_token("svchost.exe"), None);
        assert_eq!(single_token("über"), None);
        assert_eq!(single_token(""), None);
        assert_eq!(single_token(&"a".repeat(129)), None);
    }

    #[test]
    fn counts_rows_per_minute_once_per_row_and_round_trip() {
        let mut rows = Vec::new();
        for i in 0..40_i64 {
            // Twice in one row and in both columns: one row.
            rows.push((i * 10_000_000, vec!["PowerShell powershell", "x POWERSHELL"]));
        }
        for i in 0..5_i64 {
            rows.push((400_000_000 + i, vec!["rare token", ""]));
        }
        let rows = rows.iter().map(|(t, v)| (*t, v.as_slice())).collect::<Vec<_>>();
        let counts = build(&rows);
        let minutes = counts.lookup(b"powershell").unwrap().unwrap();
        assert_eq!(minutes.iter().map(|(_, c)| *c).sum::<u32>(), 40);
        assert_eq!(minutes, vec![(0, 6), (1, 6), (2, 6), (3, 6), (4, 6), (5, 6), (6, 4)]);
        assert_eq!(counts.lookup(b"rare").unwrap(), None, "below the threshold");
        assert_eq!(counts.lookup(b"x").unwrap().unwrap().iter().map(|(_, c)| *c).sum::<u32>(), 40);
        let mut bytes = Vec::new();
        counts.encode(&mut bytes).unwrap();
        let decoded = TokenCounts::decode(&mut Cursor { bytes: &bytes, at: 0 }, 45).unwrap();
        assert_eq!(decoded, counts);
        assert!(TokenCounts::decode(&mut Cursor { bytes: &bytes, at: 0 }, 44).is_err());
    }

    #[test]
    fn minutes_stay_exact_when_rows_arrive_out_of_time_order() {
        // Minutes 5, 3, 3, 9, 1, 5, 1, ... (a merge input is time-sorted, but
        // the counts must not depend on it).
        let order = [5_i64, 3, 3, 9, 1, 5, 1, 7, 9, 9, 3, 2, 8, 8, 5, 1];
        let rows = order.iter().map(|m| (m * MINUTE_US + 17, ["svchost"])).collect::<Vec<_>>();
        let rows = rows.iter().map(|(t, v)| (*t, v.as_slice())).collect::<Vec<_>>();
        let minutes = build(&rows).lookup(b"svchost").unwrap().unwrap();
        let mut want = BTreeMap::new();
        for m in order {
            *want.entry(m).or_insert(0_u32) += 1;
        }
        assert_eq!(minutes, want.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn lookup_finds_every_listed_token_across_restarts() {
        let words = (0..500).map(|i| format!("tok{i:04}x")).collect::<Vec<_>>();
        let text = words.join(" ");
        let rows = (0..20_i64).map(|i| (i * MINUTE_US / 2, [text.as_str()])).collect::<Vec<_>>();
        let rows = rows.iter().map(|(t, v)| (*t, v.as_slice())).collect::<Vec<_>>();
        let counts = build(&rows);
        assert_eq!(counts.tokens(), 500);
        for word in &words {
            let minutes = counts.lookup(word.as_bytes()).unwrap().unwrap();
            assert_eq!(minutes.iter().map(|(_, c)| *c).sum::<u32>(), 20, "{word}");
        }
        assert_eq!(counts.lookup(b"tok").unwrap(), None);
        assert_eq!(counts.lookup(b"tok0000").unwrap(), None);
        assert_eq!(counts.lookup(b"zzz").unwrap(), None);
        assert_eq!(counts.lookup(b"a").unwrap(), None);
    }
}
