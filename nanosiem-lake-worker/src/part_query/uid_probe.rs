// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4292: decode-free `metadata.uid` bloom checks.
//!
//! Every data file carries `uids-NNNNN.json`: a JSON array with one
//! hex-encoded split-block bloom (SBBF) of `metadata.uid` per row group
//! (about 160 KB of bitset per full group, ~0.5 MB of hex per file). An
//! event-id lookup (`fetch_log`, a UI row expansion, `metadata.uid=` search)
//! used to read each candidate file's sidecar through the 64 MiB metadata
//! cache (which a 7 d window thrashes, evicting every other sidecar),
//! JSON-decode it into owned strings and hex-decode every group's whole
//! bitset, then check ONE 32-byte block per group: ~10 ms a file,
//! sequentially, so 22 s for the 2,233 files of a 7 d window on a large tenant.
//!
//! This keeps each verified sidecar's group layout (where each hex string
//! sits, and whether it is a usable bitset) keyed by its signed digest, and
//! answers a lookup with one positioned 64-hex-char read per group. The
//! answer is exactly [`super::prune::uid_summary_mask`]'s: a `null`,
//! malformed, short or non-power-of-two bloom keeps its group, and a file
//! whose array does not parse or does not have one entry per group is
//! unknown (every group kept). Only a parse the zero-copy reader cannot do
//! (a string with JSON escapes, which the writer never emits) falls back to
//! the full decode.

use std::collections::{HashMap, VecDeque};
use std::fs::File;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use super::prune::Mask;
use crate::planner::CandidateHint;

use super::token_probe::SALT;

/// Layouts kept (one per data file; ~2,300 files a week on a large tenant, a few
/// dozen bytes each).
const MAX_LAYOUTS: usize = 16_384;

/// One row group's bloom in the sidecar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GroupBloom {
    /// Unknown (null, malformed, short or non-power-of-two): keep the group.
    Keep,
    /// A usable bitset: its hex digits start at byte `offset` of the file
    /// and encode `blocks` 32-byte blocks.
    Bitset { offset: u64, blocks: u64 },
}

/// A sidecar's parsed layout: `None` when the file does not parse as an
/// array of nullable strings (every group unknown).
type Layout = Option<Arc<[GroupBloom]>>;

/// Verified-digest-keyed uid sidecar layouts.
#[derive(Default)]
pub struct UidLayouts {
    entries: Mutex<(HashMap<String, Layout>, VecDeque<String>)>,
}

/// What [`UidLayouts::layout`] found for one file.
enum Parsed {
    Layout(Layout),
    /// The zero-copy reader could not parse it (escaped strings): decide it
    /// with the full decode.
    Fallback(Vec<u8>),
}

impl UidLayouts {
    /// The group mask of the leased, digest-verified uid sidecar at `path`
    /// for the uid hint in `hints`, exactly as
    /// [`super::prune::uid_summary_mask`] decides it over the decoded file.
    /// `None` = unknown (no uid hint, unreadable file, or a group count that
    /// disagrees with `groups`).
    pub fn mask(&self, path: &Path, digest: &str, groups: usize, hints: &[CandidateHint]) -> Mask {
        let id = uid_hint(hints)?;
        let layout = match self.cached(digest) {
            Some(layout) => layout,
            None => match parse_file(path)? {
                Parsed::Layout(layout) => {
                    self.insert(digest, layout.clone());
                    layout
                }
                Parsed::Fallback(bytes) => {
                    let blooms = serde_json::from_slice::<Vec<Option<String>>>(&bytes).ok();
                    return super::prune::uid_summary_mask(blooms.as_deref(), groups, hints);
                }
            },
        };
        let layout = layout.filter(|layout| layout.len() == groups)?;
        let file = File::open(path).ok();
        let hash = twox_hash::XxHash64::oneshot(0, id.as_bytes());
        Some(layout.iter().map(|group| match (group, &file) {
            (GroupBloom::Keep, _) | (_, None) => true,
            (GroupBloom::Bitset { offset, blocks }, Some(file)) => bitset_may_contain(file, *offset, *blocks, hash),
        }).collect())
    }

    fn cached(&self, digest: &str) -> Option<Layout> {
        self.entries.lock().ok()?.0.get(digest).cloned()
    }

    fn insert(&self, digest: &str, layout: Layout) {
        let Ok(mut entries) = self.entries.lock() else { return };
        let (map, order) = &mut *entries;
        if map.contains_key(digest) {
            return;
        }
        while map.len() >= MAX_LAYOUTS {
            let Some(oldest) = order.pop_front() else { break };
            map.remove(&oldest);
        }
        order.push_back(digest.to_owned());
        map.insert(digest.to_owned(), layout);
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.lock().unwrap().0.len()
    }
}

/// The `metadata.uid` value of the first uid entity hint (the one
/// [`super::prune::uid_summary_mask`] checks).
fn uid_hint(hints: &[CandidateHint]) -> Option<&str> {
    hints.iter().find_map(|hint| match hint {
        CandidateHint::Entity { source_path, value } if source_path == crate::parts::format::UID_PATH => Some(value.as_str()),
        _ => None,
    })
}

/// Read and lay out one sidecar; `None` when the file cannot be read.
fn parse_file(path: &Path) -> Option<Parsed> {
    let bytes = std::fs::read(path).ok()?;
    Some(parse(bytes))
}

fn parse(bytes: Vec<u8>) -> Parsed {
    let layout = match serde_json::from_slice::<Vec<Option<&str>>>(&bytes) {
        Ok(groups) => Some(groups.iter().map(|group| match group {
            None => GroupBloom::Keep,
            Some(hex) => {
                // The borrowed string lies inside `bytes` (no escapes).
                let offset = hex.as_ptr() as usize - bytes.as_ptr() as usize;
                group_bloom(hex.as_bytes(), offset as u64)
            }
        }).collect::<Arc<[_]>>()),
        // An escaped string cannot be borrowed: decide this file the slow
        // way. Any other error is a file the full decode rejects too.
        Err(error) if error.is_data() => return Parsed::Fallback(bytes),
        Err(_) => None,
    };
    Parsed::Layout(layout)
}

/// How [`super::prune::uid_summary_mask`] would treat this hex string:
/// usable only when it hex-decodes to a power-of-two length of at least 32.
fn group_bloom(hex: &[u8], offset: u64) -> GroupBloom {
    let bytes = hex.len() / 2;
    if hex.len() % 2 != 0 || bytes < 32 || !bytes.is_power_of_two() || !hex.iter().all(u8::is_ascii_hexdigit) {
        return GroupBloom::Keep;
    }
    GroupBloom::Bitset { offset, blocks: (bytes / 32) as u64 }
}

/// `Sbbf::check` of `hash` over the hex bitset at `offset`, reading only the
/// one block it hashes to. A read error answers "may contain" (keep).
fn bitset_may_contain(file: &File, offset: u64, blocks: u64, hash: u64) -> bool {
    let block = ((hash >> 32).saturating_mul(blocks)) >> 32;
    let mut hex = [0_u8; 64];
    if file.read_exact_at(&mut hex, offset + block * 64).is_err() {
        return true;
    }
    let mut bytes = [0_u8; 32];
    if hex::decode_to_slice(hex, &mut bytes).is_err() {
        return true;
    }
    let x = hash as u32;
    (0..8).all(|i| {
        let word = u32::from_le_bytes(bytes[i * 4..i * 4 + 4].try_into().expect("4 bytes"));
        word & (1_u32 << (x.wrapping_mul(SALT[i]) >> 27)) != 0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use parquet::bloom_filter::Sbbf;

    fn hint(value: &str) -> Vec<CandidateHint> {
        vec![CandidateHint::Entity { source_path: crate::parts::format::UID_PATH.into(), value: value.into() }]
    }

    fn bloom_hex(values: &[String], ndv: u64) -> String {
        let mut bloom = Sbbf::new_with_ndv_fpp(ndv, 0.01).unwrap();
        for value in values {
            bloom.insert(value.as_str());
        }
        let mut bytes = Vec::new();
        bloom.write_bitset(&mut bytes).unwrap();
        hex::encode(bytes)
    }

    fn write(dir: &tempfile::TempDir, name: &str, groups: &[Option<String>]) -> std::path::PathBuf {
        let path = dir.path().join(name);
        std::fs::write(&path, serde_json::to_vec(groups).unwrap()).unwrap();
        path
    }

    fn reference(path: &Path, groups: usize, hints: &[CandidateHint]) -> Mask {
        let blooms = serde_json::from_slice::<Vec<Option<String>>>(&std::fs::read(path).unwrap()).ok();
        super::super::prune::uid_summary_mask(blooms.as_deref(), groups, hints)
    }

    /// The probe answers exactly what the full decode answers, for present
    /// and absent ids, over many filter sizes, warm and cold.
    #[test]
    fn matches_full_decode_on_random_blooms() {
        let dir = tempfile::tempdir().unwrap();
        let layouts = UidLayouts::default();
        let mut seed = 0x9e37_79b9_7f4a_7c15_u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let mut checked = 0;
        for file in 0..12 {
            let groups = (file % 4) + 1;
            let mut members = Vec::new();
            let blooms = (0..groups).map(|group| {
                let rows = 1 + (next() % 3_000) as usize;
                let values = (0..rows).map(|row| format!("{file}-{group}-{row}-{:x}", next())).collect::<Vec<_>>();
                members.extend(values.iter().cloned());
                Some(bloom_hex(&values, rows as u64))
            }).collect::<Vec<_>>();
            let path = write(&dir, &format!("uids-{file:05}.json"), &blooms);
            let digest = format!("digest-{file}");
            let probes = members.iter().step_by(37).cloned()
                .chain((0..400).map(|_| format!("absent-{:x}", next())));
            for id in probes {
                let expected = reference(&path, groups, &hint(&id));
                assert_eq!(layouts.mask(&path, &digest, groups, &hint(&id)), expected, "{id}");
                checked += 1;
            }
            // A member is never excluded from its own group.
            assert!(layouts.mask(&path, &digest, groups, &hint(&members[0])).unwrap().iter().any(|keep| *keep));
        }
        assert!(checked > 4_000);
        assert_eq!(layouts.len(), 12, "one layout per verified digest");
    }

    #[test]
    fn unknown_and_malformed_groups_keep_like_the_full_decode() {
        let dir = tempfile::tempdir().unwrap();
        let layouts = UidLayouts::default();
        let good = bloom_hex(&["a".into()], 1);
        let cases: Vec<(&str, Vec<Option<String>>)> = vec![
            ("null", vec![None, Some(good.clone())]),
            ("short", vec![Some("00".repeat(16)), Some(good.clone())]),
            ("odd", vec![Some(format!("{good}0"))]),
            ("not-pow2", vec![Some("00".repeat(96))]),
            ("bad-hex", vec![Some(good.replacen('0', "z", 1))]),
            ("empty-bitset", vec![Some("00".repeat(32)), Some("00".repeat(64))]),
            ("uppercase", vec![Some(good.to_uppercase())]),
        ];
        for (name, blooms) in cases {
            let path = write(&dir, name, &blooms);
            for id in ["a", "b", "zz"] {
                for groups in [blooms.len(), blooms.len() + 1] {
                    assert_eq!(layouts.mask(&path, name, groups, &hint(id)), reference(&path, groups, &hint(id)), "{name} {id} {groups}");
                }
            }
        }
        // Not an array of nullable strings: unknown, like the full decode.
        for (name, body) in [("garbage", &b"not json"[..]), ("numbers", b"[1,2]"), ("truncated", b"[\"00")] {
            let path = dir.path().join(name);
            std::fs::write(&path, body).unwrap();
            assert_eq!(layouts.mask(&path, name, 2, &hint("a")), None, "{name}");
            assert_eq!(reference(&path, 2, &hint("a")), None, "{name}");
        }
        // No uid hint, or no file: unknown.
        let path = write(&dir, "plain", &[Some(good.clone())]);
        assert_eq!(layouts.mask(&path, "plain", 1, &[]), None);
        assert_eq!(layouts.mask(&dir.path().join("missing"), "missing", 1, &hint("a")), None);
    }

    /// A string with JSON escapes cannot be borrowed; it is decided by the
    /// full decode (and never cached as a layout).
    #[test]
    fn escaped_strings_fall_back_to_the_full_decode() {
        let dir = tempfile::tempdir().unwrap();
        let layouts = UidLayouts::default();
        let good = bloom_hex(&["needle".into()], 1);
        let escaped = format!("\\u0030{}", &good[1..]);
        let path = dir.path().join("escaped");
        std::fs::write(&path, format!("[\"{escaped}\", \"{good}\"]")).unwrap();
        for id in ["needle", "other"] {
            assert_eq!(layouts.mask(&path, "escaped", 2, &hint(id)), reference(&path, 2, &hint(id)), "{id}");
        }
        assert_eq!(layouts.len(), 0);
    }

    /// NAN-4292 before/after: a 7 d large-tenant window's shape (2,233 files, 2,707
    /// full 65,536-row groups at the writer's bloom size), one lookup of an
    /// absent id, the full decode vs the probe cold (layouts built) and warm.
    /// `NAN4292_BENCH_DIR` puts the ~1 GB of sidecars off tmpfs.
    #[test]
    #[ignore = "bench: cargo test -p nanosiem-lake-worker --release --lib uid_probe::tests::bench -- --ignored --nocapture"]
    fn bench_week_window_lookup() {
        let base = std::env::var("NAN4292_BENCH_DIR").map(std::path::PathBuf::from).unwrap_or_else(|_| std::env::temp_dir());
        let dir = tempfile::tempdir_in(base).unwrap();
        let ndv = 65_536_u64;
        let mut groups_hex = Vec::new();
        for g in 0..4 {
            let values = (0..ndv).map(|row| format!("{g:02}-{row:08}-0123456789abcdef0123456789abcdef")).collect::<Vec<_>>();
            let mut bloom = Sbbf::new_with_ndv_fpp(ndv, crate::parts::format::BLOOM_FPP).unwrap();
            for value in &values {
                bloom.insert(value.as_str());
            }
            let mut bytes = Vec::new();
            bloom.write_bitset(&mut bytes).unwrap();
            groups_hex.push(hex::encode(bytes));
        }
        let files = (0..2_233).map(|file| {
            let groups = if file < 474 { 2 } else { 1 };
            let blooms = (0..groups).map(|g| Some(groups_hex[(file + g) % 4].clone())).collect::<Vec<_>>();
            (write(&dir, &format!("uids-{file:05}.json"), &blooms), format!("d{file}"), groups)
        }).collect::<Vec<_>>();
        let bytes = files.iter().map(|(path, ..)| std::fs::metadata(path).unwrap().len()).sum::<u64>();
        let hints = hint("absent-0123456789abcdef");
        let started = std::time::Instant::now();
        let old = files.iter().map(|(path, _, groups)| reference(path, *groups, &hints)).collect::<Vec<_>>();
        let old_ms = started.elapsed().as_secs_f64() * 1000.0;
        let layouts = UidLayouts::default();
        let mut runs = Vec::new();
        for _ in 0..2 {
            let started = std::time::Instant::now();
            let new = files.iter().map(|(path, digest, groups)| layouts.mask(path, digest, *groups, &hints)).collect::<Vec<_>>();
            runs.push(started.elapsed().as_secs_f64() * 1000.0);
            assert_eq!(new, old);
        }
        eprintln!("nan4292 bench: {} files, {:.0} MB of sidecars, bitset {} KiB/group; full decode {old_ms:.0} ms ({:.2} ms/file); probe cold {:.0} ms, warm {:.0} ms ({:.3} ms/file)",
            files.len(), bytes as f64 / 1e6, groups_hex[0].len() / 2048, old_ms / files.len() as f64, runs[0], runs[1], runs[1] / files.len() as f64);
    }
}
