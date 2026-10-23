// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-3392: per-file, per-hint row-group evidence of the selection's
//! footer/bloom stage, cached across queries.
//!
//! [`prune::FileMetadataCache::evidence_of_tokens`] answers a file's entity
//! hints by reading one Parquet bloom per (row group, hinted path) on every
//! query. On 7d that is ~830 files × 4–11 ms of synchronous preads per
//! entity query, and for a combined (bareword hash) hint a full token-index
//! read and decode per file. Data files are immutable and content-addressed
//! (the key is the leased file's signed sha256, plus `#ranged` for a sparse
//! copy whose rewritten footer carries no blooms), so the answer for one
//! `(file, hint)` never changes: it is computed once and kept, bounded by
//! bytes.
//!
//! The cache stores one mask per top-level hint and ANDs them. That equals
//! the whole-hint call because every hint's evidence is a per-group
//! conjunct there too: `hints.iter().all(..)` for the entity/combined mask,
//! and the source-family mask is likewise a per-hint conjunct. A hint with no
//! evidence source yields `None` (all kept), which is the identity of
//! [`prune::and`] (`equal_to_the_whole_hint_call_over_every_shape` holds
//! the property). Time masks, row ranges and group times come from the
//! cached footer summary on every call (they depend on per-part membership
//! buckets and are cheap), so a deleted or unreadable file still answers
//! `None` and takes the engine's re-resolution path exactly as before.
//!
//! A bloom that could not be read is kept (unknown, never proof of
//! absence), so a cached entry can be weaker than a later read would be,
//! never wrong. The SQL still filters every row of every kept group.
use super::prune::{self, FileMetadataCache, Mask};
use super::token_cache::TokenCache;
use crate::planner::CandidateHint;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Byte bound of the cache. A 7d entity hint over ~830 files costs ~100 KB,
/// so this holds a few hundred distinct entity pivots.
pub const MAX_EVIDENCE_BYTES: usize = 16 * 1024 * 1024;

/// Most first-time probes in flight per selection (NAN-3392 a-3).
pub const PROBE_CONCURRENCY: usize = 8;

/// NAN-4164: token-index probes in flight per selection (and per token-seed
/// batch). A probe is one positioned read per row group of a local file,
/// almost no CPU, so its wall is the hot volume's latency: on a large hosted tenant a
/// cold 7 d keyword's 2,261 probes averaged 1.6 ms of blocked thread time and
/// took 1.2 s of select_token at [`PROBE_CONCURRENCY`]. The network volume
/// serves a far deeper queue; 32 overlaps that latency.
pub const TOKEN_PROBE_CONCURRENCY: usize = 32;

/// [`TOKEN_PROBE_CONCURRENCY`], or a probe's `token_probe_concurrency` knob.
pub fn token_probe_concurrency() -> usize {
    crate::perf_overrides::probe_count("token_probe_concurrency").map_or(TOKEN_PROBE_CONCURRENCY, |n| n as usize)
}

/// What the footer stage returns per data file: hint mask, membership time
/// mask, row ranges, exact group times (as
/// [`prune::FileMetadataCache::evidence_of_tokens`]).
pub type Footer = (Mask, Mask, Vec<(u64, u64)>, Option<Vec<(i64, i64)>>);

type Key = [u8; 32];

#[derive(Default)]
struct Entries {
    map: HashMap<Key, (usize, Mask)>,
    order: VecDeque<Key>,
    bytes: usize,
}

pub struct EvidenceCache {
    entries: Mutex<Entries>,
    max_bytes: usize,
}

impl Default for EvidenceCache {
    fn default() -> Self {
        Self::with_max_bytes(MAX_EVIDENCE_BYTES)
    }
}

impl EvidenceCache {
    pub fn with_max_bytes(max_bytes: usize) -> Self {
        Self { entries: Mutex::default(), max_bytes }
    }

    pub fn bytes(&self) -> usize {
        self.entries.lock().map(|entries| entries.bytes).unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.entries.lock().map(|entries| entries.map.len()).unwrap_or(0)
    }

    fn key(file_key: &str, hint: &CandidateHint, combined: bool, tokens: Option<&str>) -> Key {
        let mut hash = Sha256::new();
        // Bump the version whenever bloom/token/family evidence semantics change.
        hash.update(b"nano.select-evidence.v1\0");
        hash.update(file_key.as_bytes());
        hash.update([0, u8::from(combined)]);
        // Combined evidence also reads the file's token index: bind it.
        match tokens {
            Some(digest) => {
                hash.update(b"\x01");
                hash.update(digest.as_bytes());
            }
            None => hash.update(b"\x00"),
        }
        hash.update([0]);
        hash.update(format!("{hint:?}").as_bytes());
        hash.finalize().into()
    }

    fn get(&self, key: &Key) -> Option<Mask> {
        self.entries.lock().ok()?.map.get(key).map(|(_, mask)| mask.clone())
    }

    fn insert(&self, key: Key, mask: &Mask) {
        let bytes = 96 + mask.as_ref().map_or(0, Vec::len);
        if bytes > self.max_bytes {
            return;
        }
        let Ok(mut entries) = self.entries.lock() else { return };
        if entries.map.contains_key(&key) {
            return;
        }
        while entries.bytes + bytes > self.max_bytes {
            let Some(oldest) = entries.order.pop_front() else { break };
            if let Some((size, _)) = entries.map.remove(&oldest) {
                entries.bytes -= size;
            }
        }
        entries.bytes += bytes;
        entries.order.push_back(key);
        entries.map.insert(key, (bytes, mask.clone()));
    }
}

/// The leased token index of a data file (combined hints only).
#[derive(Debug, Clone)]
pub struct TokenFile {
    pub path: PathBuf,
    pub sha256: String,
}

/// One data file's footer-stage probe.
#[derive(Debug, Clone)]
pub struct Probe {
    pub path: PathBuf,
    /// Footer-summary / evidence identity (`summary_key`).
    pub file_key: String,
    pub tokens: Option<TokenFile>,
    pub buckets: Option<BTreeSet<i64>>,
    /// NAN-4190: this file's hints when they differ from the selection's
    /// (the window entity index already answered some of them exactly).
    pub hints: Option<Arc<[CandidateHint]>>,
}

/// Per-probe cache outcome.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ProbeStats {
    pub hits: usize,
    pub misses: usize,
    /// Token indexes decoded for a combined miss.
    pub token_decodes: usize,
}

impl ProbeStats {
    pub fn absorb(&mut self, other: ProbeStats) {
        self.hits += other.hits;
        self.misses += other.misses;
        self.token_decodes += other.token_decodes;
    }
}

/// The shared caches a probe reads.
#[derive(Clone)]
pub struct Caches {
    pub metadata: Arc<FileMetadataCache>,
    pub evidence: Arc<EvidenceCache>,
    pub tokens: Arc<TokenCache>,
}

/// [`prune::FileMetadataCache::evidence_of_tokens`] for `hints`, from the
/// evidence cache where every hint is known; only a missing hint reads
/// blooms (and, combined, decodes the token index). `None` exactly when
/// the file's summary cannot be read (or a bloom-reading probe cannot open
/// it), as the uncached call.
pub fn probe(
    caches: &Caches,
    probe: &Probe,
    hints: &[CandidateHint],
    combined: bool,
    cache_footer: bool,
    stats: &mut ProbeStats,
) -> Option<Footer> {
    let (_, time_mask, ranges, group_times) = caches.metadata.evidence_of_tokens(
        &probe.path, &probe.file_key, &[], None, false, cache_footer, probe.buckets.as_ref())?;
    let token_digest = combined.then(|| probe.tokens.as_ref().map(|tokens| tokens.sha256.as_str())).flatten();
    let mut decoded: Option<Option<Arc<Vec<crate::parts::sidecar::TokenGroup>>>> = None;
    let mut mask: Mask = None;
    for hint in hints {
        let key = EvidenceCache::key(&probe.file_key, hint, combined, token_digest);
        let hint_mask = match caches.evidence.get(&key) {
            Some(hit) => {
                stats.hits += 1;
                hit
            }
            None => {
                if !combined && prune::uses_entities(std::slice::from_ref(hint))
                    && caches.metadata.has_blooms(&probe.file_key) {
                    stats.hits += 1;
                } else {
                    stats.misses += 1;
                }
                let tokens = if combined {
                    decoded
                        .get_or_insert_with(|| {
                            probe.tokens.as_ref().and_then(|tokens| {
                                stats.token_decodes += 1;
                                caches.tokens.get(&tokens.path, &tokens.sha256)
                            })
                        })
                        .clone()
                } else {
                    None
                };
                let computed = caches
                    .metadata
                    .evidence_of_tokens(
                        &probe.path,
                        &probe.file_key,
                        std::slice::from_ref(hint),
                        tokens.as_deref().map(Vec::as_slice),
                        combined,
                        cache_footer,
                        None,
                    )?
                    .0;
                // A token index that should exist but did not decode leaves
                // the hint undecided this time; do not pin that answer.
                let token_missing = combined && probe.tokens.is_some() && tokens.is_none();
                if !token_missing {
                    caches.evidence.insert(key, &computed);
                }
                computed
            }
        };
        mask = prune::and(mask, hint_mask);
    }
    Some((mask, time_mask, ranges, group_times))
}

/// [`probe`] for every file, `PROBE_CONCURRENCY` at a time on the blocking
/// pool (never inline on a runtime worker), in input order, with each
/// probe's stats; plus the summed thread CPU (ms). A probe whose task
/// panicked answers `None` (the engine's re-resolution path).
///
/// NAN-4171: each probe also hands back the file's footer summary, read
/// here in parallel, so the engine's scan estimate does not look it up a
/// second time, sequentially, after a sweep that may have evicted it.
pub async fn probe_all(
    caches: &Caches,
    probes: Vec<Option<Probe>>,
    hints: Arc<[CandidateHint]>,
    combined: bool,
    cache_footer: bool,
) -> (Vec<Probed>, f64) {
    let caches = caches.clone();
    let (results, cpu) = blocking_map(probes, move |one| {
        let mut stats = ProbeStats::default();
        let Some(one) = one else { return (None, stats, None) };
        let summary = caches.metadata.summary(&one.path, &one.file_key);
        let hints = one.hints.as_ref().unwrap_or(&hints);
        let footer = summary.as_ref().and_then(|_| probe(&caches, &one, hints, combined, cache_footer, &mut stats));
        (footer, stats, summary)
    })
    .await;
    (results.into_iter().map(|result| result.unwrap_or((None, ProbeStats::default(), None))).collect(), cpu)
}

/// One file's probe: its footer evidence, cache stats and footer summary.
pub type Probed = (Option<Footer>, ProbeStats, Option<Arc<prune::FileSummary>>);

/// Run `work` per item, `PROBE_CONCURRENCY` at a time on the blocking pool,
/// in input order, under the request's phase record. Returns each output
/// and the summed thread CPU (ms).
pub async fn blocking_map<T, R, F>(items: Vec<T>, work: F) -> (Vec<Option<R>>, f64)
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> R + Send + Sync + 'static,
{
    let concurrency = crate::perf_overrides::probe_count("evidence_probe_concurrency").map_or(PROBE_CONCURRENCY, |n| n as usize);
    blocking_map_with(items, concurrency, work).await
}

/// [`blocking_map`] with `concurrency` items in flight (at least one).
pub async fn blocking_map_with<T, R, F>(items: Vec<T>, concurrency: usize, work: F) -> (Vec<Option<R>>, f64)
where
    T: Send + 'static,
    R: Send + 'static,
    F: Fn(T) -> R + Send + Sync + 'static,
{
    use futures::StreamExt;
    let phases = crate::query_timing::current();
    let work = Arc::new(work);
    let results: Vec<Option<(R, f64)>> = futures::stream::iter(items.into_iter().map(|item| {
        let (work, phases) = (work.clone(), phases.clone());
        tokio::task::spawn_blocking(move || {
            crate::query_timing::in_scope(phases, || {
                let mut cpu = 0.0;
                let out = {
                    let _cpu = crate::query_timing::select_cpu(Some(&mut cpu));
                    work(item)
                };
                (out, cpu)
            })
        })
    }))
    .buffered(concurrency.max(1))
    .map(Result::ok)
    .collect()
    .await;
    let cpu = results.iter().flatten().map(|(_, cpu)| cpu).sum();
    (results.into_iter().map(|result| result.map(|(out, _)| out)).collect(), cpu)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;
    use crate::parts::sidecar::{encode_token_index, TokenGroupBuilder};
    use arrow_array::{ArrayRef, RecordBatch, StringArray, StructArray};
    use arrow_schema::{DataType, Field, Schema};
    use parquet::arrow::ArrowWriter;
    use parquet::file::properties::WriterProperties;
    use parquet::schema::types::ColumnPath;
    use std::io::Write;

    const GROUPS: usize = 12;

    fn entity(path: &str, value: &str) -> CandidateHint {
        CandidateHint::Entity { source_path: path.into(), value: value.into() }
    }
    fn keyword(mode: &str, value: &str) -> CandidateHint {
        CandidateHint::Keyword { mode: mode.into(), value: value.into() }
    }
    fn family(value: &str) -> CandidateHint {
        CandidateHint::SourceFamily { value: value.into() }
    }
    fn any(alternatives: Vec<CandidateHint>) -> CandidateHint {
        CandidateHint::Any { alternatives }
    }

    fn user(group: usize) -> String {
        format!("user{}", group % 5)
    }
    fn host(group: usize) -> String {
        format!("ws-exec-{:03}.corp.local", group % 4)
    }
    fn source(group: usize) -> &'static str {
        ["aws_cloudtrail", "conduit_proxy", "windows_sysmon"][group % 3]
    }
    fn hash(group: usize) -> String {
        format!("0faafb1b{:056x}", group % 6)
    }

    /// A part-shaped data file: bloomed `user.name` and
    /// `src_endpoint.hostname`, flat `metadata.log_source` statistics, one
    /// row group per slice, interleaved so only blooms decide.
    fn data_file() -> tempfile::NamedTempFile {
        let user_fields: arrow_schema::Fields = vec![Field::new("name", DataType::Utf8, true)].into();
        let host_fields: arrow_schema::Fields = vec![Field::new("hostname", DataType::Utf8, true)].into();
        let schema = Arc::new(Schema::new(vec![
            Field::new("user", DataType::Struct(user_fields.clone()), true),
            Field::new("src_endpoint", DataType::Struct(host_fields.clone()), true),
            Field::new(prune::SOURCE_FAMILY_PATH, DataType::Utf8, true),
        ]));
        let file = tempfile::NamedTempFile::new().unwrap();
        let props = WriterProperties::builder()
            .set_column_bloom_filter_enabled(ColumnPath::new(vec!["user".into(), "name".into()]), true)
            .set_column_bloom_filter_enabled(ColumnPath::new(vec!["src_endpoint".into(), "hostname".into()]), true)
            .set_max_row_group_row_count(Some(10_000))
            .build();
        let mut writer = ArrowWriter::try_new(file.reopen().unwrap(), schema.clone(), Some(props)).unwrap();
        for group in 0..GROUPS {
            // Two values per group (min/max span the needles); a decoy
            // pair keeps statistics from deciding on their own.
            let users = vec![Some("aaa".to_string()), Some(user(group)), Some("zzz".to_string())];
            let hosts = vec![Some("a.corp.local".to_string()), Some(host(group)), Some("z.corp.local".to_string())];
            let sources = vec![Some(source(group)); 3];
            let users = StructArray::new(user_fields.clone(), vec![Arc::new(StringArray::from(users)) as ArrayRef], None);
            let hosts = StructArray::new(host_fields.clone(), vec![Arc::new(StringArray::from(hosts)) as ArrayRef], None);
            let batch = RecordBatch::try_new(schema.clone(), vec![
                Arc::new(users),
                Arc::new(hosts),
                Arc::new(StringArray::from(sources)) as ArrayRef,
            ]).unwrap();
            writer.write(&batch).unwrap();
            writer.flush().unwrap();
        }
        writer.close().unwrap();
        file
    }

    /// The data file's token index: one group per row group holding its
    /// hash and a few words.
    fn token_file() -> (tempfile::NamedTempFile, String) {
        let groups = (0..GROUPS)
            .map(|group| {
                let mut builder = TokenGroupBuilder::new();
                for _ in 0..3 {
                    builder.add_row();
                }
                builder.add_text(&format!("{} {} event", hash(group), if group % 2 == 0 { "powershell" } else { "curl" }));
                builder.finish().unwrap()
            })
            .collect::<Vec<_>>();
        let encoded = encode_token_index(&groups).unwrap();
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&encoded).unwrap();
        let digest = format!("{:x}", Sha256::digest(&encoded));
        (file, digest)
    }

    fn shapes() -> Vec<Vec<CandidateHint>> {
        vec![
            vec![entity("user.name", "user3")],
            vec![entity("user.name", "USER3")],
            vec![entity("user.name", "nobody")],
            vec![entity("src_endpoint.hostname", "ws-exec-002.corp.local")],
            vec![entity("src_endpoint.hostname", "WS-EXEC-002.corp.local")],
            vec![entity("src_endpoint.hostname", "absent.corp.local")],
            vec![entity("user.name", "user1"), entity("src_endpoint.hostname", "ws-exec-001.corp.local")],
            vec![entity("user.name", "user1"), entity("src_endpoint.hostname", "ws-exec-002.corp.local")],
            vec![entity("user.name", "user2"), family("windows_sysmon")],
            vec![family("aws_cloudtrail")],
            vec![family("AUDIT")],
            vec![CandidateHint::Class { value: 4001 }, entity("user.name", "user4")],
            vec![keyword("token", "powershell")],
            vec![keyword("token", "powershell"), entity("user.name", "user0")],
            vec![keyword("contains", "x"), entity("src_endpoint.hostname", "ws-exec-003.corp.local")],
            vec![any(vec![entity("user.name", "user1"), entity("user.name", "user2")])],
            vec![any(vec![entity("user.name", "user1"), keyword("token", "powershell")])],
            vec![any(vec![])],
            // The bareword-hash shape: entity hash arrays OR the keyword.
            vec![any(vec![entity("file.hashes.value", &hash(3)), keyword("token", &hash(3))])],
            vec![any(vec![entity("file.hashes.value", &hash(3)), keyword("token", &hash(3))]), family("conduit_proxy")],
            vec![any(vec![entity("user.name", "user2"), entity("file.hashes.value", &hash(5))])],
            vec![any(vec![entity("user.name", "user2"), entity("file.hashes.value", &hash(5))]), entity("src_endpoint.hostname", "ws-exec-001.corp.local")],
            vec![entity("message", "bob")],
            vec![entity("user.name", "İ")],
            vec![],
        ]
    }

    fn kept(footer: &Footer) -> Vec<(u64, u64)> {
        let (hint, time, ranges, _) = footer;
        let mask = prune::and(hint.clone(), time.clone());
        ranges
            .iter()
            .enumerate()
            .filter(|(group, _)| mask.as_ref().is_none_or(|mask| mask[*group]))
            .map(|(_, range)| *range)
            .collect()
    }

    #[test]
    fn prewarmed_file_hits_on_first_selection_and_other_digest_misses() {
        let data = data_file();
        let caches = Caches { metadata: Arc::default(), evidence: Arc::default(), tokens: Arc::default() };
        assert!(caches.metadata.prewarm(data.path(), "signed-a"));
        let one = Probe { path: data.path().into(), file_key: "signed-a".into(), tokens: None, buckets: None, hints: None };
        let hints = [CandidateHint::Entity { source_path: "user.name".into(), value: "alice".into() }];
        let mut stats = ProbeStats::default();
        let got = probe(&caches, &one, &hints, false, true, &mut stats).unwrap();
        assert_eq!(stats.hits, 1);
        assert_eq!(stats.misses, 0);
        let reference = FileMetadataCache::default().evidence(data.path(), "signed-a", &hints, None, false, true, None).unwrap();
        assert_eq!(got, reference);
        assert!(!caches.metadata.has_blooms("signed-b"), "different signed content cannot reuse evidence");
        let other_tenant = FileMetadataCache::default();
        assert!(!other_tenant.has_blooms("signed-a"), "tenant engines do not share caches");
    }

    /// Byte-identical evidence: for every hint shape, combined or not, with
    /// and without a token index and membership buckets, cold and warm, the
    /// cached probe returns exactly the uncached whole-hint tuple, hence the
    /// same kept row groups.
    #[test]
    fn equal_to_the_whole_hint_call_over_every_shape() {
        let data = data_file();
        let (tokens, digest) = token_file();
        let caches = Caches { metadata: Arc::default(), evidence: Arc::default(), tokens: Arc::default() };
        let reference = FileMetadataCache::default();
        let reference_tokens = TokenCache::default();
        let mut buckets = BTreeSet::new();
        buckets.insert(0);
        let mut pruned_somewhere = 0;
        for pass in 0..2 {
            for hints in shapes() {
                for combined in [false, true] {
                    for token in [true, false] {
                        for buckets in [None, Some(buckets.clone())] {
                            let token_ref = token.then(|| TokenFile { path: tokens.path().to_path_buf(), sha256: digest.clone() });
                            let decoded = if combined && token { reference_tokens.get(tokens.path(), &digest) } else { None };
                            let expected = reference
                                .evidence_of_tokens(data.path(), "data-digest", &hints, decoded.as_deref().map(Vec::as_slice), combined, true, buckets.as_ref())
                                .unwrap();
                            let one = Probe { path: data.path().to_path_buf(), file_key: "data-digest".into(), tokens: token_ref, buckets: buckets.clone(), hints: None };
                            let mut stats = ProbeStats::default();
                            let got = probe(&caches, &one, &hints, combined, true, &mut stats).unwrap();
                            assert_eq!(got, expected, "pass {pass} combined={combined} token={token} buckets={} {hints:?}", buckets.is_some());
                            assert_eq!(kept(&got), kept(&expected));
                            if pass == 1 {
                                assert_eq!(stats.misses, 0, "warm pass reads no bloom: {hints:?}");
                                assert_eq!(stats.token_decodes, 0, "warm pass decodes no token index: {hints:?}");
                            }
                            pruned_somewhere += usize::from(kept(&got).len() < GROUPS);
                        }
                    }
                }
            }
        }
        assert!(pruned_somewhere > 100, "the fixture must actually prune ({pruned_somewhere})");
    }

    /// Measurable: a warm entry answers without touching the bloom bytes.
    /// Zeroing every bloom on disk after the first query changes what an
    /// uncached read decides (unreadable blooms keep every group), but not
    /// the cached answer.
    #[test]
    fn a_warm_hit_reads_no_bloom() {
        let data = data_file();
        let hints = [entity("src_endpoint.hostname", "ws-exec-002.corp.local")];
        let caches = Caches { metadata: Arc::default(), evidence: Arc::default(), tokens: Arc::default() };
        let one = Probe { path: data.path().to_path_buf(), file_key: "d".into(), tokens: None, buckets: None, hints: None };
        let mut stats = ProbeStats::default();
        let cold = probe(&caches, &one, &hints, false, false, &mut stats).unwrap();
        assert_eq!(stats, ProbeStats { hits: 0, misses: 1, token_decodes: 0 });
        let cold_kept = kept(&cold).len();
        assert!((GROUPS / 4..GROUPS).contains(&cold_kept), "the host lives in a quarter of the groups ({cold_kept})");
        // Corrupt the bloom bitsets (everything between the data pages and
        // the footer is fair game: zero all but the footer and magic).
        let bytes = std::fs::read(data.path()).unwrap();
        let footer_len = u32::from_le_bytes(bytes[bytes.len() - 8..bytes.len() - 4].try_into().unwrap()) as usize;
        let summary = caches.metadata.summary(data.path(), "d").unwrap();
        assert_eq!(summary.ranges.len(), GROUPS);
        let mut corrupted = bytes.clone();
        let end = bytes.len() - 8 - footer_len;
        for byte in &mut corrupted[4..end] {
            *byte = 0;
        }
        std::fs::write(data.path(), &corrupted).unwrap();
        let uncached = FileMetadataCache::default();
        // Fresh caches would now decide differently (unreadable blooms).
        let mut fresh_stats = ProbeStats::default();
        let fresh = Caches { metadata: Arc::new(uncached), evidence: Arc::default(), tokens: Arc::default() };
        let fresh_answer = probe(&fresh, &one, &hints, false, false, &mut fresh_stats);
        assert_ne!(fresh_answer.as_ref().map(kept), Some(kept(&cold)), "corruption is observable to a bloom read");
        let mut stats = ProbeStats::default();
        let warm = probe(&caches, &one, &hints, false, false, &mut stats).unwrap();
        assert_eq!(stats, ProbeStats { hits: 1, misses: 0, token_decodes: 0 });
        assert_eq!(warm, cold);
    }

    /// The combined (hash) path consults evidence first: warm, the token
    /// index is never decoded (it may even be gone).
    #[test]
    fn combined_warm_hit_decodes_no_token_index() {
        let data = data_file();
        let (tokens, digest) = token_file();
        let hints = [any(vec![entity("file.hashes.value", &hash(3)), keyword("token", &hash(3))])];
        let caches = Caches { metadata: Arc::default(), evidence: Arc::default(), tokens: Arc::default() };
        let one = Probe {
            path: data.path().to_path_buf(),
            file_key: "d".into(),
            tokens: Some(TokenFile { path: tokens.path().to_path_buf(), sha256: digest }),
            buckets: None,
            hints: None,
        };
        let mut stats = ProbeStats::default();
        let cold = probe(&caches, &one, &hints, true, true, &mut stats).unwrap();
        assert_eq!(stats.token_decodes, 1);
        let cold_kept = kept(&cold).len();
        assert!((GROUPS / 6..GROUPS).contains(&cold_kept), "the hash lives in a sixth of the groups ({cold_kept})");
        std::fs::write(tokens.path(), b"gone").unwrap();
        let mut stats = ProbeStats::default();
        assert_eq!(probe(&caches, &one, &hints, true, true, &mut stats).unwrap(), cold);
        assert_eq!(stats, ProbeStats { hits: 1, misses: 0, token_decodes: 0 });
    }

    /// An undecodable token index is never pinned as the answer.
    #[test]
    fn an_undecodable_token_index_is_not_cached() {
        let data = data_file();
        let (tokens, digest) = token_file();
        std::fs::write(tokens.path(), b"not an index").unwrap();
        let hints = [any(vec![entity("file.hashes.value", &hash(3)), keyword("token", &hash(3))])];
        let caches = Caches { metadata: Arc::default(), evidence: Arc::default(), tokens: Arc::default() };
        let one = Probe {
            path: data.path().to_path_buf(),
            file_key: "d".into(),
            tokens: Some(TokenFile { path: tokens.path().to_path_buf(), sha256: digest }),
            buckets: None,
            hints: None,
        };
        let mut stats = ProbeStats::default();
        probe(&caches, &one, &hints, true, true, &mut stats).unwrap();
        assert_eq!(caches.evidence.len(), 0);
    }

    #[test]
    fn a_deleted_file_still_takes_the_re_resolution_path() {
        let data = data_file();
        let path = data.path().to_path_buf();
        let hints = [entity("user.name", "user1")];
        let caches = Caches { metadata: Arc::default(), evidence: Arc::default(), tokens: Arc::default() };
        let one = Probe { path: path.clone(), file_key: "d".into(), tokens: None, buckets: None, hints: None };
        assert!(probe(&caches, &one, &hints, false, true, &mut ProbeStats::default()).is_some());
        drop(data);
        assert!(probe(&caches, &one, &hints, false, true, &mut ProbeStats::default()).is_none());
    }

    #[test]
    fn the_cache_is_bounded_by_bytes_and_keyed_by_file_hint_and_mode() {
        let cache = EvidenceCache::with_max_bytes(1_000);
        let hint = entity("user.name", "a");
        for i in 0..100 {
            cache.insert(EvidenceCache::key(&format!("f{i}"), &hint, false, None), &Some(vec![true; 50]));
        }
        assert!(cache.bytes() <= 1_000);
        assert_eq!(cache.len(), 1_000 / 146);
        assert!(cache.get(&EvidenceCache::key("f99", &hint, false, None)).is_some());
        assert!(cache.get(&EvidenceCache::key("f0", &hint, false, None)).is_none());
        let base = EvidenceCache::key("f", &hint, false, None);
        assert_ne!(base, EvidenceCache::key("f#ranged", &hint, false, None));
        assert_ne!(base, EvidenceCache::key("f", &entity("user.name", "b"), false, None));
        assert_ne!(base, EvidenceCache::key("f", &entity("actor.user.name", "a"), false, None));
        assert_ne!(base, EvidenceCache::key("f", &hint, true, None));
        assert_ne!(EvidenceCache::key("f", &hint, true, None), EvidenceCache::key("f", &hint, true, Some("t")));
    }

    /// The fan-out keeps input order, runs off the runtime worker, and is
    /// bounded (`PROBE_CONCURRENCY`).
    #[tokio::test(flavor = "current_thread")]
    async fn fan_out_is_ordered_bounded_and_off_the_runtime() {
        use std::sync::atomic::AtomicUsize;
        let runtime_thread = std::thread::current().id();
        let (live, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let (l, p) = (live.clone(), peak.clone());
        let (out, _) = blocking_map((0..64).collect::<Vec<usize>>(), move |i| {
            assert_ne!(std::thread::current().id(), runtime_thread);
            let now = l.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(now, Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(5));
            l.fetch_sub(1, Ordering::SeqCst);
            i * 2
        })
        .await;
        assert_eq!(out, (0..64).map(|i| Some(i * 2)).collect::<Vec<_>>());
        let peak = peak.load(Ordering::SeqCst);
        assert!(peak <= PROBE_CONCURRENCY, "peak {peak}");
        assert!(peak > 1, "first-time evidence runs in parallel (peak {peak})");
    }

    /// The cold wall of N probes whose I/O blocks for `latency` drops ~8x
    /// with the fan-out, against the inline sequential loop it replaces.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fan_out_cuts_cold_wall_by_the_concurrency() {
        let latency = std::time::Duration::from_millis(10);
        let started = std::time::Instant::now();
        for _ in 0..32 {
            std::thread::sleep(latency);
        }
        let sequential = started.elapsed();
        let started = std::time::Instant::now();
        let _ = blocking_map((0..32).collect::<Vec<_>>(), move |_| std::thread::sleep(latency)).await;
        let parallel = started.elapsed();
        println!("32 cold probes @10ms: sequential {sequential:?}, fan-out {parallel:?}");
        assert!(parallel * 4 < sequential, "sequential {sequential:?} vs fan-out {parallel:?}");
    }

    /// NAN-4164: token probes (I/O-bound) run [`TOKEN_PROBE_CONCURRENCY`]
    /// at a time: 128 probes blocked 10 ms each finish in ~4 rounds, where
    /// the footer fan-out ([`PROBE_CONCURRENCY`]) takes ~16.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_fan_out_overlaps_io_latency_four_times_deeper() {
        let latency = std::time::Duration::from_millis(10);
        let (inflight, peak) = (Arc::new(std::sync::atomic::AtomicUsize::new(0)), Arc::new(std::sync::atomic::AtomicUsize::new(0)));
        let probe = {
            let (inflight, peak) = (inflight.clone(), peak.clone());
            move |_: usize| {
                let now = inflight.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(latency);
                inflight.fetch_sub(1, Ordering::SeqCst);
            }
        };
        let started = std::time::Instant::now();
        let (out, _) = blocking_map_with((0..128).collect::<Vec<_>>(), TOKEN_PROBE_CONCURRENCY, probe.clone()).await;
        let token = started.elapsed();
        assert_eq!(out.len(), 128);
        assert_eq!(peak.load(Ordering::SeqCst), TOKEN_PROBE_CONCURRENCY);
        let started = std::time::Instant::now();
        let _ = blocking_map_with((0..128).collect::<Vec<_>>(), PROBE_CONCURRENCY, probe).await;
        let footer = started.elapsed();
        println!("128 probes @10ms: token fan-out {token:?}, footer fan-out {footer:?}");
        assert!(token * 2 < footer, "token {token:?} vs footer {footer:?}");
    }
}
