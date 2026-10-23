// SPDX-License-Identifier: AGPL-3.0-or-later
//! Decoded immutable token indexes. Callers must hold a verified file lease
//! before consulting this cache; a hit never replaces signed verification.
use super::prune::{self, FineBlocks, Mask};
use crate::parts::sidecar::{decode_leased_token_index, TokenGroup};
use crate::planner::CandidateHint;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};
const MAX_BYTES: usize = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 16_384;
const MAX_EVIDENCE_BYTES: usize = 8 * 1024 * 1024;
#[derive(Default)]
struct Decoded {
    entries: HashMap<String, (usize, Arc<Vec<TokenGroup>>)>,
    order: VecDeque<String>,
    bytes: usize,
}
#[derive(Default)]
struct Evidence {
    entries: HashMap<[u8; 32], (usize, (Mask, Option<FineBlocks>))>,
    order: VecDeque<[u8; 32]>,
    bytes: usize,
}
#[derive(Default)]
pub struct TokenCache {
    decoded: Mutex<Decoded>,
    evidence: Mutex<Evidence>,
    layouts: Mutex<Layouts>,
    counters: Counters,
}

/// NAN-4164: per-digest group layouts ([`super::token_probe::GroupLayout`]),
/// oldest evicted first past [`MAX_LAYOUT_ENTRIES`] files.
#[derive(Default)]
struct Layouts {
    entries: HashMap<String, Arc<[super::token_probe::GroupLayout]>>,
    order: VecDeque<String>,
}
/// ~3 weeks of a large tenant's token files (2,260 a week); at ~8 groups a file of
/// ~50 bytes each, ~4 MB.
const MAX_LAYOUT_ENTRIES: usize = 8_192;

/// NAN-4164: process-wide token-evidence work, for per-request deltas
/// (`query_timing`): which of probe, whole-file read or decode a cold
/// select_token pays for. Concurrent requests share the counters.
#[derive(Default)]
struct Counters {
    evidence_hits: AtomicU64,
    probes: AtomicU64,
    probe_excluded: AtomicU64,
    probe_ns: AtomicU64,
    decodes: AtomicU64,
    decode_bytes: AtomicU64,
    read_ns: AtomicU64,
    decode_ns: AtomicU64,
}

/// A snapshot of [`TokenCache`]'s counters.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TokenCacheStats {
    pub evidence_hits: u64,
    pub probes: u64,
    pub probe_excluded: u64,
    pub probe_ns: u64,
    pub decodes: u64,
    pub decode_bytes: u64,
    pub read_ns: u64,
    pub decode_ns: u64,
}

impl std::ops::Sub for TokenCacheStats {
    type Output = Self;
    fn sub(self, before: Self) -> Self {
        Self {
            evidence_hits: self.evidence_hits.saturating_sub(before.evidence_hits),
            probes: self.probes.saturating_sub(before.probes),
            probe_excluded: self.probe_excluded.saturating_sub(before.probe_excluded),
            probe_ns: self.probe_ns.saturating_sub(before.probe_ns),
            decodes: self.decodes.saturating_sub(before.decodes),
            decode_bytes: self.decode_bytes.saturating_sub(before.decode_bytes),
            read_ns: self.read_ns.saturating_sub(before.read_ns),
            decode_ns: self.decode_ns.saturating_sub(before.decode_ns),
        }
    }
}

fn elapsed_ns(started: std::time::Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

impl TokenCache {
    pub fn stats(&self) -> TokenCacheStats {
        let c = &self.counters;
        TokenCacheStats {
            evidence_hits: c.evidence_hits.load(Ordering::Relaxed),
            probes: c.probes.load(Ordering::Relaxed),
            probe_excluded: c.probe_excluded.load(Ordering::Relaxed),
            probe_ns: c.probe_ns.load(Ordering::Relaxed),
            decodes: c.decodes.load(Ordering::Relaxed),
            decode_bytes: c.decode_bytes.load(Ordering::Relaxed),
            read_ns: c.read_ns.load(Ordering::Relaxed),
            decode_ns: c.decode_ns.load(Ordering::Relaxed),
        }
    }

    /// NAN-4164: the group layout of the verified token index `digest` at
    /// `path`, read once (section headers only) and kept.
    pub fn layout(&self, path: &Path, digest: &str, groups: usize) -> Option<Arc<[super::token_probe::GroupLayout]>> {
        if let Some(layout) = self.layouts.lock().ok()?.entries.get(digest).filter(|layout| layout.len() == groups) {
            return Some(layout.clone());
        }
        let layout: Arc<[_]> = super::token_probe::layout(path, groups)?.into();
        let mut cache = self.layouts.lock().ok()?;
        if !cache.entries.contains_key(digest) {
            while cache.entries.len() >= MAX_LAYOUT_ENTRIES {
                let Some(oldest) = cache.order.pop_front() else { break };
                cache.entries.remove(&oldest);
            }
            cache.order.push_back(digest.to_owned());
        }
        cache.entries.insert(digest.to_owned(), layout.clone());
        Some(layout)
    }

    /// NAN-4164: whether `digest`'s layout is held (the warm skips it).
    pub fn has_layout(&self, digest: &str) -> bool {
        self.layouts.lock().is_ok_and(|cache| cache.entries.contains_key(digest))
    }

    pub fn get(&self, path: &Path, digest: &str) -> Option<Arc<Vec<TokenGroup>>> {
        if let Some((_, groups)) = self.decoded.lock().ok()?.entries.get(digest) {
            return Some(groups.clone());
        }
        let started = std::time::Instant::now();
        let raw = std::fs::read(path).ok()?;
        self.counters.read_ns.fetch_add(elapsed_ns(started), Ordering::Relaxed);
        let started = std::time::Instant::now();
        let decoded = decode_leased_token_index(&raw);
        self.counters.decode_ns.fetch_add(elapsed_ns(started), Ordering::Relaxed);
        self.counters.decodes.fetch_add(1, Ordering::Relaxed);
        self.counters.decode_bytes.fetch_add(raw.len() as u64, Ordering::Relaxed);
        let groups = Arc::new(decoded.ok()?);
        let bytes = groups.iter().map(TokenGroup::resident_bytes).sum::<usize>()
            + (groups.capacity() - groups.len()) * std::mem::size_of::<TokenGroup>()
            + 256
            + digest.len() * 2;
        if bytes > MAX_BYTES {
            return Some(groups);
        }
        let mut cache = self.decoded.lock().ok()?;
        // Another concurrent decoder may have populated the same digest.
        if let Some((_, existing)) = cache.entries.get(digest) {
            return Some(existing.clone());
        }
        while cache.bytes + bytes > MAX_BYTES || cache.entries.len() >= MAX_ENTRIES {
            let oldest = cache.order.pop_front()?;
            cache.bytes -= cache.entries.remove(&oldest)?.0;
        }
        cache.bytes += bytes;
        cache.order.push_back(digest.to_owned());
        cache
            .entries
            .insert(digest.to_owned(), (bytes, groups.clone()));
        Some(groups)
    }

    /// Exact predicate evidence, including reusable negative row groups. The
    /// signed token digest transitively binds it to the verified part record;
    /// tokenizer and predicate normalization are versioned in the namespace.
    /// Unknown/malformed evidence is never retained as a negative answer.
    pub fn evidence(
        &self,
        path: &Path,
        digest: &str,
        groups: usize,
        hints: &[CandidateHint],
    ) -> (Mask, Option<FineBlocks>) {
        let mut hash = Sha256::new();
        hash.update(b"nano.token-predicate.nano_split_lower_v1.v1\0");
        hash.update(digest.as_bytes());
        hash.update((groups as u64).to_le_bytes());
        hash.update(format!("{hints:?}").as_bytes());
        let key: [u8; 32] = hash.finalize().into();
        if let Ok(cache) = self.evidence.lock() {
            if let Some((_, value)) = cache.entries.get(&key) {
                self.counters.evidence_hits.fetch_add(1, Ordering::Relaxed);
                return value.clone();
            }
        }
        // NAN-4164: a file the decoded cache does not hold is first judged by
        // its blooms in place (its group layout kept in memory). When they exclude every group (a rare or
        // absent keyword: almost every file of a long window) it is never
        // read whole or decoded; the 32 MiB decoded cache cannot hold a 7 d
        // window, so before this every such query re-decoded every file.
        let decoded = self.decoded.lock().is_ok_and(|cache| cache.entries.contains_key(digest));
        // An excluded file has no candidate block in any group: fine evidence
        // of empty runs, as the decode yields, so the token seed (which needs
        // both) counts it as consulted instead of stopping its estimate there.
        let excluded = !decoded && prune::uses_tokens(hints) && {
            let started = std::time::Instant::now();
            // With the layout held, only the bloom blocks are read.
            let excluded = match self.layout(path, digest, groups) {
                Some(layout) => super::token_probe::excludes_with_layout(path, &layout, hints),
                None => super::token_probe::excludes_every_group(path, groups, hints),
            };
            self.counters.probe_ns.fetch_add(elapsed_ns(started), Ordering::Relaxed);
            self.counters.probes.fetch_add(1, Ordering::Relaxed);
            self.counters.probe_excluded.fetch_add(u64::from(excluded), Ordering::Relaxed);
            excluded
        };
        let value = if excluded {
            (Some(vec![false; groups]), Some(vec![Some(Vec::new()); groups]))
        } else {
            self.get(path, digest).map_or((None, None), |tokens| {
                prune::token_evidence_of(&tokens, groups, hints)
            })
        };
        let Some(mask) = &value.0 else { return value };
        let bytes = 256
            + mask.capacity()
            + value.1.as_ref().map_or(0, |fine| {
                fine.capacity() * std::mem::size_of::<Option<prune::BlockRuns>>()
                    + fine
                        .iter()
                        .flatten()
                        .map(|runs| runs.capacity() * std::mem::size_of::<(u64, u64, (i64, i64))>())
                        .sum::<usize>()
            });
        if bytes > MAX_EVIDENCE_BYTES {
            return value;
        }
        if let Ok(mut cache) = self.evidence.lock() {
            if !cache.entries.contains_key(&key) {
                while cache.bytes + bytes > MAX_EVIDENCE_BYTES || cache.entries.len() >= MAX_ENTRIES
                {
                    let Some(oldest) = cache.order.pop_front() else {
                        break;
                    };
                    if let Some((size, _)) = cache.entries.remove(&oldest) {
                        cache.bytes -= size;
                    }
                }
                cache.bytes += bytes;
                cache.order.push_back(key);
                cache.entries.insert(key, (bytes, value.clone()));
            }
        }
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn verified_digest_reuses_decode_but_unknown_or_invalid_never_becomes_negative() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        use std::io::Write;
        let groups = vec![TokenGroup {
            rows: 2,
            tokens: 0,
            bitset: vec![],
            saturated: false,
            blocks: None,
            counts: None,
            trigrams: None,
            pairs: None,
            addresses: false,
        }];
        file.write_all(&crate::parts::sidecar::encode_token_index(&groups).unwrap())
            .unwrap();
        let cache = TokenCache::default();
        let cold = cache.get(file.path(), "verified-digest").unwrap();
        let warm = cache.get(file.path(), "verified-digest").unwrap();
        assert!(Arc::ptr_eq(&cold, &warm));
        assert_eq!(*cold, groups);
        let hints = vec![CandidateHint::Keyword {
            mode: "token".into(),
            value: "absent".into(),
        }];
        let negative = cache.evidence(file.path(), "verified-digest", 1, &hints);
        assert_eq!(negative.0, Some(vec![false]));
        assert_eq!(
            cache.evidence(file.path(), "verified-digest", 1, &hints),
            negative
        );
        assert_eq!(
            cache.evidence(file.path(), "verified-digest", 2, &hints),
            (None, None)
        );
        std::fs::write(file.path(), b"invalid").unwrap();
        assert!(cache.get(file.path(), "new-digest").is_none());
        assert_eq!(
            cache.evidence(file.path(), "new-digest", 1, &hints),
            (None, None)
        );
        assert_eq!(cache.evidence.lock().unwrap().entries.len(), 1);
        assert!(cache
            .decoded
            .lock()
            .unwrap()
            .entries
            .keys()
            .all(|key| key != "new-digest"));
    }
    /// NAN-4164: a file whose blooms exclude every group is answered without
    /// a decode (nothing enters the decoded cache); a kept group decodes.
    #[test]
    fn bloom_excluded_files_are_never_decoded() {
        use crate::parts::sidecar::{encode_token_index, TokenGroupBuilder};
        let groups = ["powershell -enc", "curl 10.1.4.20"].iter().map(|text| {
            let mut builder = TokenGroupBuilder::with_trigrams(32);
            builder.add_row_at(0);
            builder.add_text(text);
            builder.finish().unwrap()
        }).collect::<Vec<_>>();
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), encode_token_index(&groups).unwrap()).unwrap();
        let cache = TokenCache::default();
        let hint = |value: &str| vec![CandidateHint::Keyword { mode: "token".into(), value: value.into() }];
        let excluded = cache.evidence(file.path(), "d", 2, &hint("mimikatz"));
        assert_eq!(excluded.0, Some(vec![false, false]));
        // NAN-4164: with fine evidence (no candidate blocks), so the token
        // seed counts the file as consulted (it stopped at it before).
        assert_eq!(excluded.1, Some(vec![Some(Vec::new()), Some(Vec::new())]));
        assert!(cache.decoded.lock().unwrap().entries.is_empty(), "excluded by blooms, not decoded");
        assert_eq!(cache.evidence(file.path(), "d", 2, &hint("10.1.4.20")).0, Some(vec![false, true]));
        assert_eq!(cache.decoded.lock().unwrap().entries.len(), 1, "a kept group decodes");
    }

    #[test]
    fn fixture_cache_phases_preserve_rows_counts_and_masks() {
        use crate::parts::sidecar::{encode_token_index, TokenGroupBuilder};
        use std::{io::Write, time::Instant};
        let mut groups = Vec::new();
        let mut rows = Vec::new();
        for group in 0..64 {
            let mut builder = TokenGroupBuilder::with_blocks_and_counts(32);
            for row in 0..128 {
                let text = format!(
                    "{} process{row} powers{group}",
                    if group % 2 == 0 {
                        "powershell error"
                    } else {
                        "curl success"
                    }
                );
                builder.add_row_at(1_790_000_000_000_000 + group * 60_000_000 + row);
                builder.add_text(&text);
                builder.add_body(&text);
                rows.push((rows.len(), text));
            }
            groups.push(builder.finish().unwrap());
        }
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let encoded = encode_token_index(&groups).unwrap();
        file.write_all(&encoded).unwrap();
        let digest = format!("{:x}", Sha256::digest(&encoded));
        let hints = vec![CandidateHint::Keyword {
            mode: "token".into(),
            value: "powershell".into(),
        }];
        let expected = rows
            .iter()
            .filter(|(_, text)| text.starts_with("powershell "))
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        let cache = TokenCache::default();
        let selected = |mask: &Mask| {
            rows.iter()
                .filter(|(id, text)| {
                    mask.as_ref().is_none_or(|mask| mask[id / 128])
                        && text.starts_with("powershell ")
                })
                .map(|(id, _)| *id)
                .collect::<Vec<_>>()
        };
        let cold_start = Instant::now();
        let cold = cache.evidence(file.path(), &digest, groups.len(), &hints);
        let cold_us = cold_start.elapsed().as_micros();
        assert_eq!(selected(&cold.0), expected);
        let warm_start = Instant::now();
        for _ in 0..200 {
            let warm = cache.evidence(file.path(), &digest, groups.len(), &hints);
            assert_eq!(warm, cold);
        }
        let warm_us = warm_start.elapsed().as_micros() as f64 / 200.0;
        let counts = cache
            .get(file.path(), &digest)
            .unwrap()
            .iter()
            .map(|group| {
                group
                    .counts
                    .as_ref()
                    .unwrap()
                    .lookup(b"powershell")
                    .unwrap()
                    .unwrap_or_default()
                    .iter()
                    .map(|(_, count)| *count as usize)
                    .sum::<usize>()
            })
            .sum::<usize>();
        assert_eq!(
            counts,
            expected.len(),
            "exact v3 counts agree with unpruned rows"
        );
        let results = super::super::result_cache::ResultCache::default();
        let answer = serde_json::json!({"result": {"rows": expected, "count": counts, "masked_fields": ["enrichments.location"]}});
        results.insert([1; 32], &answer);
        let hit_start = Instant::now();
        for _ in 0..200 {
            let hit = results.get(&[1; 32], "fixture").unwrap();
            assert_eq!(hit["result"]["rows"], answer["result"]["rows"]);
            assert_eq!(hit["result"]["count"], answer["result"]["count"]);
            assert_eq!(
                hit["result"]["masked_fields"],
                answer["result"]["masked_fields"]
            );
        }
        let hit_us = hit_start.elapsed().as_micros() as f64 / 200.0;
        println!("metadata fixture: 64 groups, {} index bytes; cold={cold_us}us, warm uncached-result={warm_us:.1}us, repeated result hit={hit_us:.1}us (JSON clone + parity assertions included)", encoded.len());
    }
}
