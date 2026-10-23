// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4164: decode-free token evidence for files the blooms exclude.
//!
//! A 7 d bare-keyword search on a large tenant selects ~2,300 data files. Their
//! `tokens.nti` are local (hot window), but the decoded-index cache holds
//! 32 MiB and one file decodes to ~1 MB per row group (token bloom, block
//! fuse filters, minute counts, trigram bloom), so every such query re-read
//! and fully decoded every file: 11-28 s of `select_token` on a warm pod for
//! a token in two files. A rare needle is decided by a few 32-byte bloom
//! blocks per row group. This walks the file's section headers with
//! positioned reads, checks exactly those blocks in place, and reports
//! whether every group is excluded. Anything it cannot parse, or any group a
//! bloom keeps, falls back to the full decode (which also yields the fine
//! block runs); it never decides that a group is kept or skipped on its own.

use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;

use crate::parts::sidecar::{
    TOKENIZER, TOKEN_FILTER_MAX_BYTES, TOKEN_INDEX_MAGIC, TOKEN_INDEX_MAGIC_V2, TOKEN_INDEX_MAGIC_V3,
    TOKEN_INDEX_MAGIC_V4, TOKEN_INDEX_MAGIC_V5, TOKEN_INDEX_MAGIC_V6, TRIGRAM_FILTER_BYTES, PAIR_FILTER_MAX_BYTES,
};
use crate::planner::CandidateHint;

use super::prune::GroupBlooms;

/// `parquet::bloom_filter` split-block salt (Parquet spec).
pub(super) const SALT: [u32; 8] = [
    0x47b6_137b, 0x4497_4d91, 0x8824_ad5b, 0xa2b7_289d, 0x7054_95c7, 0x2df1_424b, 0x9efc_4947, 0x5c6b_fb31,
];

/// `Sbbf::check(value)` over a bitset stored at `offset..offset + len` of
/// `file`, reading only the one 32-byte block the value hashes to. A read
/// error answers "may contain" (keep).
fn sbbf_may_contain(file: &File, offset: u64, len: u64, value: &[u8]) -> bool {
    let blocks = len / 32;
    if blocks == 0 {
        return false;
    }
    let hash = twox_hash::XxHash64::oneshot(0, value);
    let block = ((hash >> 32).saturating_mul(blocks)) >> 32;
    let mut bytes = [0_u8; 32];
    if file.read_exact_at(&mut bytes, offset + block * 32).is_err() {
        return true;
    }
    let x = hash as u32;
    (0..8).all(|i| {
        let word = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        word & (1_u32 << (x.wrapping_mul(SALT[i]) >> 27)) != 0
    })
}

/// One group's bloom locations inside the file.
struct ProbeGroup<'a> {
    file: &'a File,
    tokens: (u64, u64),
    trigrams: Option<u64>,
    pairs: Option<(u64, u64)>,
    addresses: bool,
}

impl GroupBlooms for ProbeGroup<'_> {
    fn tokens_may_contain_all(&self, tokens: &[String]) -> bool {
        let (offset, len) = self.tokens;
        if len == 0 {
            return tokens.is_empty();
        }
        tokens.iter().all(|token| sbbf_may_contain(self.file, offset, len, token.as_bytes()))
    }

    fn trigrams_may_contain_all(&self, grams: &[[u8; 3]]) -> Option<bool> {
        let offset = self.trigrams?;
        Some(grams.iter().all(|gram| sbbf_may_contain(self.file, offset, TRIGRAM_FILTER_BYTES as u64, gram)))
    }

    fn pairs_may_contain_all(&self, pairs: &[[u8; 8]]) -> Option<bool> {
        let (offset, len) = self.pairs?;
        if len == 0 {
            return Some(pairs.is_empty());
        }
        Some(pairs.iter().all(|pair| sbbf_may_contain(self.file, offset, len, pair)))
    }

    fn holds_addresses(&self) -> bool {
        self.addresses
    }
}

/// Positioned reader over a file of known length.
struct Walk<'a> {
    file: &'a File,
    at: u64,
    end: u64,
}

impl Walk<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let next = self.at.checked_add(N as u64)?;
        if next > self.end {
            return None;
        }
        let mut bytes = [0_u8; N];
        self.file.read_exact_at(&mut bytes, self.at).ok()?;
        self.at = next;
        Some(bytes)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take::<1>()?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take()?))
    }
    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take()?))
    }
    /// Skip `n` bytes, returning where they start.
    fn skip(&mut self, n: u64) -> Option<u64> {
        let start = self.at;
        let next = start.checked_add(n)?;
        if next > self.end {
            return None;
        }
        self.at = next;
        Some(start)
    }
    /// A `block_index::KeySet` (tag, then its encoded body).
    fn skip_key_set(&mut self) -> Option<()> {
        match self.u8()? {
            0 | 1 => Some(()),
            2 => {
                let n = u64::from(self.u32()?);
                self.skip(n.checked_mul(8)?).map(drop)
            }
            tag @ (3 | 4) => {
                self.skip(8 + 4 + 4 + 4)?;
                let n = u64::from(self.u32()?);
                self.skip(if tag == 3 { n } else { n.checked_mul(2)? }).map(drop)
            }
            _ => None,
        }
    }
}

/// Does the token index at `path` (a leased, signed-digest verified file)
/// exclude EVERY one of its `expected_groups` groups for `hints`, judged by
/// its blooms alone? `false` = unknown or some group may match: decode it.
pub fn excludes_every_group(path: &Path, expected_groups: usize, hints: &[CandidateHint]) -> bool {
    let Ok(file) = File::open(path) else { return false };
    let Ok(meta) = file.metadata() else { return false };
    // The 32-byte SHA-256 trailer follows the body.
    let Some(end) = meta.len().checked_sub(32) else { return false };
    let mut walk = Walk { file: &file, at: 0, end };
    walk_excludes(&mut walk, expected_groups, hints).unwrap_or(false)
}

fn walk_excludes(walk: &mut Walk<'_>, expected_groups: usize, hints: &[CandidateHint]) -> Option<bool> {
    // A group may match: the full decode decides (and finds its runs).
    walk_groups(walk, expected_groups, |group| !hints.iter().all(|hint| super::prune::token_hint(group, hint)))
}

/// NAN-4164: where each group's blooms sit in a token index: what a probe
/// needs besides the bloom blocks themselves. Keyword-independent and
/// small (~50 bytes a group), so [`super::token_cache::TokenCache`] keeps it
/// per verified digest and the warm gate loads it before Ready.
///
/// Why: walking to a group's blooms reads its section headers, spread
/// between multi-kilobyte sections, so a cold probe faulted several pages
/// per group from the network hot volume before its one bloom block. On a
/// large hosted tenant the page cache does not keep them: the cell runs at its cgroup memory
/// limit (`memory.events max` 25k, 8 GB of file pages refaulted), and a
/// 1.55 GB page-cache warm of these ranges before Ready (T64) left the first
/// 7 d keyword at 3.6 s of select_token. With the layout in memory a cold
/// probe reads one bloom block per group and token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupLayout {
    tokens: (u64, u64),
    trigrams: Option<u64>,
    pairs: Option<(u64, u64)>,
    addresses: bool,
}

impl GroupLayout {
    /// Resident bytes of one group's layout.
    pub const BYTES: usize = std::mem::size_of::<Self>();
}

/// The layout of every group of the token index at `path` (a leased,
/// verified file), or `None` when it does not parse with `expected_groups`
/// groups. Reads only the section headers.
pub fn layout(path: &Path, expected_groups: usize) -> Option<Vec<GroupLayout>> {
    let file = File::open(path).ok()?;
    let end = file.metadata().ok()?.len().checked_sub(32)?;
    let mut walk = Walk { file: &file, at: 0, end };
    let mut groups = Vec::with_capacity(expected_groups);
    let complete = walk_groups(&mut walk, expected_groups, |group| {
        groups.push(GroupLayout { tokens: group.tokens, trigrams: group.trigrams, pairs: group.pairs, addresses: group.addresses });
        true
    })?;
    (complete && groups.len() == expected_groups).then_some(groups)
}

/// [`excludes_every_group`] with the groups' `layout` known: reads only the
/// bloom blocks the hints hash to (random access: no readahead).
pub fn excludes_with_layout(path: &Path, layout: &[GroupLayout], hints: &[CandidateHint]) -> bool {
    use std::os::fd::AsRawFd;
    let Ok(file) = File::open(path) else { return false };
    // SAFETY: an advisory hint on a descriptor this function owns.
    unsafe { libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_RANDOM) };
    layout.iter().all(|group| {
        let group = ProbeGroup { file: &file, tokens: group.tokens, trigrams: group.trigrams, pairs: group.pairs, addresses: group.addresses };
        !hints.iter().all(|hint| super::prune::token_hint(&group, hint))
    })
}

/// Walk the index's header and groups, calling `visit` with each group's
/// bloom locations until it returns `false` (answered `Some(false)`).
/// `Some(true)`: every group visited and the body fully walked.
fn walk_groups(walk: &mut Walk<'_>, expected_groups: usize, mut visit: impl FnMut(&ProbeGroup<'_>) -> bool) -> Option<bool> {
    let magic = walk.take::<8>()?;
    let version = match &magic {
        m if m == TOKEN_INDEX_MAGIC => 1,
        m if m == TOKEN_INDEX_MAGIC_V2 => 2,
        m if m == TOKEN_INDEX_MAGIC_V3 => 3,
        m if m == TOKEN_INDEX_MAGIC_V4 => 4,
        m if m == TOKEN_INDEX_MAGIC_V5 => 5,
        m if m == TOKEN_INDEX_MAGIC_V6 => 6,
        _ => return None,
    };
    if walk.u32()? != version {
        return None;
    }
    let tokenizer_len = u64::from(walk.u16()?);
    let tokenizer_at = walk.skip(tokenizer_len)?;
    let mut tokenizer = vec![0_u8; tokenizer_len as usize];
    walk.file.read_exact_at(&mut tokenizer, tokenizer_at).ok()?;
    if tokenizer != TOKENIZER.as_bytes() {
        return None;
    }
    if version >= 2 && walk.u32()? == 0 {
        return None;
    }
    if walk.u32()? as usize != expected_groups {
        return None;
    }
    for _ in 0..expected_groups {
        let _rows = walk.u64()?;
        let _tokens = walk.u64()?;
        let len = u64::from(walk.u32()?);
        if len % 32 != 0 || len > TOKEN_FILTER_MAX_BYTES as u64 {
            return None;
        }
        let tokens = (walk.skip(len)?, len);
        if version >= 2 {
            let blocks = u64::from(walk.u32()?);
            walk.skip(blocks.checked_mul(16)?)?;
            walk.skip_key_set()?;
            walk.skip_key_set()?;
        }
        if version >= 3 {
            let len = u64::from(walk.u32()?);
            walk.skip(len)?;
        }
        let trigrams = if version >= 4 { Some(walk.skip(TRIGRAM_FILTER_BYTES as u64)?) } else { None };
        let pairs = if version >= 5 {
            let _pairs = walk.u64()?;
            let len = u64::from(walk.u32()?);
            if len % 32 != 0 || len > PAIR_FILTER_MAX_BYTES as u64 {
                return None;
            }
            Some((walk.skip(len)?, len))
        } else {
            None
        };
        let group = ProbeGroup { file: walk.file, tokens, trigrams, pairs, addresses: version >= 6 };
        if !visit(&group) {
            return Some(false);
        }
    }
    (walk.at == walk.end).then_some(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::sidecar::{encode_token_index, TokenGroupBuilder};
    use parquet::bloom_filter::Sbbf;

    fn keyword(value: &str) -> CandidateHint {
        CandidateHint::Keyword { mode: "token".into(), value: value.into() }
    }

    #[test]
    fn in_place_check_matches_parquet_sbbf() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        for bytes in [32_usize, 64, 1024, 32 * 1024] {
            let mut filter = Sbbf::new_with_num_of_bytes(bytes);
            for i in 0..(bytes / 4) {
                filter.insert(format!("in-{i}").as_str());
            }
            let mut bitset = Vec::new();
            filter.write_bitset(&mut bitset).unwrap();
            assert_eq!(bitset.len(), bytes);
            std::io::Write::write_all(&mut file, &[7_u8; 5]).unwrap();
            std::io::Write::write_all(&mut file, &bitset).unwrap();
            std::io::Write::flush(&mut file).unwrap();
            let offset = file.as_file().metadata().unwrap().len() - bytes as u64;
            for i in 0..2_000 {
                for value in [format!("in-{i}"), format!("out-{i}")] {
                    assert_eq!(
                        sbbf_may_contain(file.as_file(), offset, bytes as u64, value.as_bytes()),
                        filter.check(value.as_str()),
                        "{bytes} {value}"
                    );
                }
            }
        }
    }

    /// The probe agrees with the full decode on every version, never
    /// excludes a file the decoded evidence keeps, and refuses damage.
    #[test]
    fn excludes_exactly_what_the_decoded_blooms_exclude() {
        let texts = ["mimikatz sekurlsa::logonpasswords", "src=10.1.4.20 dst=8.8.8.8", "2026-10-01T04:20:10 10.1.9.4"];
        let builders: [fn() -> TokenGroupBuilder; 6] = [
            TokenGroupBuilder::new,
            || TokenGroupBuilder::with_blocks(4),
            || TokenGroupBuilder::with_blocks_and_counts(4),
            || TokenGroupBuilder::with_trigrams(4),
            || TokenGroupBuilder::with_pairs(4),
            || TokenGroupBuilder::with_addresses(4),
        ];
        let dir = tempfile::tempdir().unwrap();
        for (version, builder) in builders.iter().enumerate() {
            let groups = texts.iter().map(|text| {
                let mut b = builder();
                if version == 0 { b.add_row() } else { b.add_row_at(0) }
                b.add_text(text);
                b.finish().unwrap()
            }).collect::<Vec<_>>();
            let bytes = encode_token_index(&groups).unwrap();
            let path = dir.path().join(format!("v{version}.nti"));
            std::fs::write(&path, &bytes).unwrap();
            for hints in [
                vec![keyword("absentzz")],
                vec![keyword("mimikatz")],
                vec![keyword("10.1.4.20")],
                vec![keyword("4.20.99")],
                vec![keyword("1.4.20")],
                vec![keyword("10.1.9.4")],
                vec![keyword("10.1.4.2")],
                vec![keyword("8.8.4.20")],
                vec![CandidateHint::Keyword { mode: "contains".into(), value: "zzqq".into() }],
                vec![CandidateHint::Any { alternatives: vec![keyword("absentzz"), keyword("mimikatz")] }],
                vec![keyword("mimikatz"), keyword("10")],
            ] {
                let (mask, _) = super::super::prune::token_evidence_of(&groups, groups.len(), &hints);
                // Fine block runs may exclude more than the blooms; the probe
                // only has to be a subset of the decoded exclusion.
                let decoded_excludes = mask.as_ref().is_some_and(|mask| !mask.iter().any(|keep| *keep));
                let probe = excludes_every_group(&path, groups.len(), &hints);
                if probe {
                    assert!(decoded_excludes, "v{version} {hints:?}: probe excluded a file the decode keeps");
                }
                let bloom_only = groups.iter().all(|group| !hints.iter().all(|hint| super::super::prune::token_hint(group, hint)));
                assert_eq!(probe, bloom_only, "v{version} {hints:?}");
            }
            assert!(excludes_every_group(&path, groups.len(), &[keyword("absentzz")]));
            assert!(!excludes_every_group(&path, groups.len() + 1, &[keyword("absentzz")]), "group count mismatch");
            std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
            assert!(!excludes_every_group(&path, groups.len(), &[keyword("absentzz")]), "truncated");
            let mut bad = bytes.clone();
            bad[0] ^= 1;
            std::fs::write(&path, &bad).unwrap();
            assert!(!excludes_every_group(&path, groups.len(), &[keyword("absentzz")]), "bad magic");
        }
        assert!(!excludes_every_group(&dir.path().join("missing.nti"), 1, &[keyword("absentzz")]));
    }

    /// NAN-4164: a probe with the cached layout answers exactly as the
    /// walking probe, in every index version, and a layout exists only for
    /// a file that parses with its group count.
    #[test]
    fn layout_probe_answers_exactly_as_the_walk() {
        let texts = ["mimikatz sekurlsa::logonpasswords", "src=10.1.4.20 dst=8.8.8.8", "2026-10-01T04:20:10 10.1.9.4"];
        let builders: [fn() -> TokenGroupBuilder; 6] = [
            TokenGroupBuilder::new,
            || TokenGroupBuilder::with_blocks(4),
            || TokenGroupBuilder::with_blocks_and_counts(4),
            || TokenGroupBuilder::with_trigrams(4),
            || TokenGroupBuilder::with_pairs(4),
            || TokenGroupBuilder::with_addresses(4),
        ];
        let dir = tempfile::tempdir().unwrap();
        for (version, builder) in builders.iter().enumerate() {
            let groups = texts.iter().map(|text| {
                let mut b = builder();
                if version == 0 { b.add_row() } else { b.add_row_at(0) }
                b.add_text(text);
                b.finish().unwrap()
            }).collect::<Vec<_>>();
            let bytes = encode_token_index(&groups).unwrap();
            let path = dir.path().join(format!("v{version}.nti"));
            std::fs::write(&path, &bytes).unwrap();
            let held = layout(&path, groups.len()).unwrap_or_else(|| panic!("v{version} parses"));
            assert_eq!(held.len(), groups.len());
            for hints in [
                vec![keyword("absentzz")],
                vec![keyword("mimikatz")],
                vec![keyword("10.1.4.20")],
                vec![keyword("4.20.99")],
                vec![keyword("10.1.9.4")],
                vec![keyword("10.1.4.2")],
                vec![keyword("8.8.4.20")],
                vec![CandidateHint::Keyword { mode: "contains".into(), value: "zzqq".into() }],
                vec![CandidateHint::Any { alternatives: vec![keyword("absentzz"), keyword("mimikatz")] }],
                vec![keyword("mimikatz"), keyword("10")],
            ] {
                assert_eq!(
                    excludes_with_layout(&path, &held, &hints),
                    excludes_every_group(&path, groups.len(), &hints),
                    "v{version} {hints:?}"
                );
            }
            assert_eq!(layout(&path, groups.len() + 1), None, "group count mismatch");
            std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
            assert_eq!(layout(&path, groups.len()), None, "truncated");
        }
        assert_eq!(layout(&dir.path().join("missing.nti"), 1), None);
        assert!(!excludes_with_layout(&dir.path().join("missing.nti"), &[], &[keyword("absentzz")]), "unreadable keeps");
    }

    /// Timing probe on real-shaped files: `NANO_PAIR_SAMPLE=rows.jsonl cargo
    /// test -p nanosiem-lake-worker --release --lib token_probe_timing --
    /// --ignored --nocapture`. 300 copies of a one-group v4 index built from
    /// the sample, judged for an absent keyword by full decode and by probe.
    #[test]
    #[ignore = "needs NANO_PAIR_SAMPLE"]
    fn token_probe_timing() {
        let rows = std::fs::read_to_string(std::env::var("NANO_PAIR_SAMPLE").unwrap()).unwrap();
        let mut builder = TokenGroupBuilder::with_trigrams(1_024);
        for (i, line) in rows.lines().take(65_536).enumerate() {
            let Ok(row) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(line) else { continue };
            builder.add_row_at(i as i64 * 15_000);
            for (field, value) in &row {
                let Some(text) = value.as_str() else { continue };
                builder.add_text(text);
                if field == "message" || field == "raw_data" {
                    builder.add_body(text);
                }
            }
        }
        let bytes = encode_token_index(&[builder.finish().unwrap()]).unwrap();
        let dir = tempfile::tempdir().unwrap();
        let paths = (0..300).map(|i| {
            let path = dir.path().join(format!("{i}.nti"));
            std::fs::write(&path, &bytes).unwrap();
            path
        }).collect::<Vec<_>>();
        let hints = vec![keyword("zzqxnotatoken")];
        let started = std::time::Instant::now();
        for path in &paths {
            let groups = crate::parts::sidecar::decode_leased_token_index(&std::fs::read(path).unwrap()).unwrap();
            let (mask, _) = super::super::prune::token_evidence_of(&groups, 1, &hints);
            assert_eq!(mask, Some(vec![false]));
        }
        let decode = started.elapsed();
        let started = std::time::Instant::now();
        for path in &paths {
            assert!(excludes_every_group(path, 1, &hints));
        }
        let probe = started.elapsed();
        println!("file_bytes={} files=300 decode_ms={:.1} probe_ms={:.1}", bytes.len(), decode.as_secs_f64() * 1e3, probe.as_secs_f64() * 1e3);
    }

}
