// SPDX-License-Identifier: AGPL-3.0-or-later

//! Immutable Tantivy candidate indexes for token, contains, and regex hunts.
//!
//! The indexes never decide whether an event matched. They only select a
//! bounded set of Parquet row groups; the compiler-owned OCSF predicate is
//! always evaluated again over the original event rows.

use crate::planner::{CandidateBlock, SourceManifest};
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;
use tantivy::collector::{Collector, Count, SegmentCollector, TopDocs};
use tantivy::index::SegmentReader;
use tantivy::query::{BooleanQuery, Occur, Query, TermQuery, TermSetQuery};
use tantivy::schema::{Field, IndexRecordOption, Value as TantivyValue};
use tantivy::tokenizer::{LowerCaser, NgramTokenizer, SimpleTokenizer, TextAnalyzer, TokenStream};
use tantivy::{DocAddress, DocId, Index, IndexReader, Order, Score, Term};

const KEYWORD_INDEX_VERSION: &str = "ocsf-keyword-block-v2";
const FRAGMENT_INDEX_VERSION: &str = "ocsf-term-fragment-rust-probe-v1";
pub const KEYWORD_INDEX_VERSION_V3: &str = "ocsf-keyword-block-v3-incremental";
pub const FRAGMENT_INDEX_VERSION_V2: &str = "ocsf-term-fragment-v2-incremental";
const KEYWORD_TOKENIZER: &str = "nano_split_lower_v1";
const FRAGMENT_TOKENIZER: &str = "nano_char_trigram_v1";
/// The fragment builder's serving profile: normalized lowercase hex-only
/// terms of at least eight bytes (file hashes, GUID halves, trace IDs) are
/// excluded from the fragment accelerator. They are unique-per-event
/// substring-search terms that bloat the trigram index (78.75% of all terms
/// on the measured Saturn day) while exact hash hunts are already served by
/// the entity and token lanes. The keyword index keeps its full dictionary.
pub const FRAGMENT_FILTER_PROFILE_SKIP_HEX8: &str = "skip-hex8";
const MAX_CANDIDATE_BLOCKS: usize = 4_096;
const MAX_FRAGMENT_TERMS: usize = 100_000;
const FRAGMENT_CACHE_MAX_ENTRIES: usize = 256;
const FRAGMENT_CACHE_MAX_BYTES: usize = 16 * 1_024 * 1_024;

/// Canonical OCSF text leaves whose terms may safely provide a candidate
/// superset. The complete compiler-owned field predicate is still rechecked
/// against Parquet, so sharing one block-level dictionary cannot create a
/// false positive result. Keeping structured hunt text here avoids falling
/// back to a broad scan merely because an event's raw payload omitted a value
/// that its parser populated canonically.
pub const KEYWORD_BODY_FIELDS: &[&str] = &[
    "message",
    "raw_data",
    "process.cmd_line",
    "actor.process.cmd_line",
    "process.name",
    "actor.process.name",
    "process.file.path",
    "actor.process.file.path",
    "process.file.hashes.value",
    "actor.process.file.hashes.value",
    "file.path",
    "file.name",
    "file.hashes.value",
    "module.file.path",
    "module.file.name",
    "http_request.url.url_string",
    "http_request.url.hostname",
    "http_request.user_agent",
    "query.hostname",
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    "device.hostname",
    "user.name",
    "actor.user.name",
    "finding_info.title",
    "finding_info.analytic.name",
    "enrichments.name",
    "enrichments.value",
    "enrichments.provider",
    "enrichments.short_desc",
];

#[derive(Debug, thiserror::Error)]
pub enum TextSidecarError {
    #[error("text sidecar is invalid: {0}")]
    Invalid(String),
    #[error("failed to read text sidecar: {0}")]
    Read(#[source] std::io::Error),
    #[error("failed to decode text sidecar: {0}")]
    Decode(#[source] serde_json::Error),
    #[error("text sidecar engine failed: {0}")]
    Tantivy(#[from] tantivy::TantivyError),
}

type Result<T> = std::result::Result<T, TextSidecarError>;

#[derive(Debug, Deserialize)]
struct KeywordManifest {
    index_version: String,
    tenant_id: String,
    engine: String,
    tokenizer: String,
    index_granularity: String,
    exactness: String,
    body_fields: Vec<String>,
    source_files: usize,
    source_bytes: u64,
    event_rows: u64,
    blocks: Vec<KeywordBlock>,
    objects: Vec<KeywordObject>,
    block_documents: usize,
    index_bytes: u64,
    segments: usize,
    fragment_dictionary_ready: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct KeywordObject {
    object_id: u32,
    event_object_key: String,
    event_object_version: String,
    event_object_bytes: u64,
    rows: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct KeywordBlock {
    locator: u64,
    object_id: u32,
    row_group: u32,
    row_start: u64,
    row_end: u64,
    rows: u64,
}

#[derive(Debug, Deserialize)]
struct FragmentManifest {
    index_version: String,
    engine: String,
    tantivy_version: String,
    tokenizer: String,
    index_option: String,
    fieldnorms: bool,
    term_payload: String,
    filter_profile: String,
    source_terms: u64,
    indexed_terms: u64,
    index_bytes: u64,
    segments: usize,
}

pub struct KeywordSidecar {
    reader: IndexReader,
    body_field: Field,
    blocks: BTreeMap<u64, CandidateBlock>,
    object_by_locator: BTreeMap<u64, u32>,
    total_blocks: usize,
    fragment: FragmentSidecar,
}

struct FragmentSidecar {
    reader: IndexReader,
    term_field: Field,
    resolver: FragmentTermResolver,
    source_terms: u64,
    filter_profile: String,
    cache: Mutex<FragmentExpansionCache>,
}

#[derive(Clone, Copy)]
enum FragmentTermResolver {
    KeywordOrdinal { field: &'static str },
    StoredExact { field: Field },
}

#[derive(Debug)]
pub enum KeywordPlan {
    Candidates {
        candidates: Vec<CandidateBlock>,
        evidence: KeywordPlannerEvidence,
    },
    Fallback(KeywordPlannerEvidence),
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KeywordPlannerEvidence {
    pub kind: &'static str,
    pub mode: String,
    pub accelerated: bool,
    pub candidate_blocks: usize,
    pub candidate_objects: usize,
    pub total_blocks: usize,
    pub exact_recheck: bool,
    pub tokens: Vec<String>,
    pub fragment_matching_terms: Vec<usize>,
    pub fragment_raw_candidates: Vec<usize>,
    pub fragment_cache_hits: usize,
    pub index_seconds: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_reason: Option<String>,
}

impl KeywordSidecar {
    pub fn load(
        keyword_manifest_path: &Path,
        keyword_index_path: &Path,
        fragment_manifest_path: &Path,
        fragment_index_path: &Path,
        tenant_id: &str,
        source_manifest: &SourceManifest,
    ) -> Result<Self> {
        let keyword_bytes = std::fs::read(keyword_manifest_path).map_err(TextSidecarError::Read)?;
        let manifest: KeywordManifest =
            serde_json::from_slice(&keyword_bytes).map_err(TextSidecarError::Decode)?;
        validate_keyword_manifest(&manifest, tenant_id, source_manifest, keyword_index_path)?;

        let keyword_index = Index::open_in_dir(keyword_index_path)?;
        keyword_index.tokenizers().register(
            KEYWORD_TOKENIZER,
            TextAnalyzer::builder(SimpleTokenizer::default())
                .filter(LowerCaser)
                .build(),
        );
        let schema = keyword_index.schema();
        let body_field = schema
            .get_field("body")
            .map_err(|_| TextSidecarError::Invalid("keyword body field is absent".to_string()))?;
        schema.get_field("locator").map_err(|_| {
            TextSidecarError::Invalid("keyword locator field is absent".to_string())
        })?;
        schema.get_field("max_time").map_err(|_| {
            TextSidecarError::Invalid("keyword max_time field is absent".to_string())
        })?;
        if manifest.index_version == KEYWORD_INDEX_VERSION_V3 {
            schema.get_field("object_id").map_err(|_| {
                TextSidecarError::Invalid(
                    "incremental keyword object ID field is absent".to_string(),
                )
            })?;
        }
        let reader = keyword_index.reader()?;
        let searcher = reader.searcher();
        if searcher.segment_readers().len() != manifest.segments
            || searcher.num_docs() as usize != manifest.block_documents
        {
            return Err(TextSidecarError::Invalid(
                "keyword segment or document count differs from its manifest".to_string(),
            ));
        }

        let source_objects = source_manifest
            .objects
            .iter()
            .map(|object| (object.event_object_key.as_str(), object))
            .collect::<BTreeMap<_, _>>();
        let objects = manifest
            .objects
            .iter()
            .map(|object| (object.object_id, object))
            .collect::<BTreeMap<_, _>>();
        let mut blocks = BTreeMap::new();
        let mut object_by_locator = BTreeMap::new();
        for block in &manifest.blocks {
            let object = objects.get(&block.object_id).ok_or_else(|| {
                TextSidecarError::Invalid("keyword block references an unknown object".to_string())
            })?;
            let source = source_objects
                .get(object.event_object_key.as_str())
                .ok_or_else(|| {
                    TextSidecarError::Invalid(
                        "keyword block references an object outside the source snapshot"
                            .to_string(),
                    )
                })?;
            let expected_locator = ((block.object_id as u64) << 32) | block.row_group as u64;
            if block.locator != expected_locator
                || block.row_start >= block.row_end
                || block.row_end > object.rows
                || block.rows != block.row_end - block.row_start
                || object.event_object_bytes != source.event_object_bytes
            {
                return Err(TextSidecarError::Invalid(
                    "keyword block locator, range, or object size is invalid".to_string(),
                ));
            }
            if blocks
                .insert(
                    block.locator,
                    CandidateBlock {
                        event_object_key: object.event_object_key.clone(),
                        event_object_bytes: object.event_object_bytes,
                        row_start: block.row_start,
                        row_end: block.row_end,
                        max_time_ms: None,
                        time_range_us: None,
                    },
                )
                .is_some()
                || object_by_locator
                    .insert(block.locator, block.object_id)
                    .is_some()
            {
                return Err(TextSidecarError::Invalid(
                    "keyword block locator is duplicated".to_string(),
                ));
            }
        }

        let fragment = FragmentSidecar::load(
            fragment_manifest_path,
            fragment_index_path,
            &keyword_index,
            &manifest,
        )?;
        Ok(Self {
            reader,
            body_field,
            blocks,
            object_by_locator,
            total_blocks: manifest.block_documents,
            fragment,
        })
    }

    pub fn plan(&self, mode: &str, value: &str) -> Result<KeywordPlan> {
        let started = Instant::now();
        let tokens = query_tokens(value);
        if tokens.is_empty() {
            return Ok(KeywordPlan::Fallback(self.fallback_evidence(
                mode,
                tokens,
                Vec::new(),
                Vec::new(),
                0,
                started,
                "query produced no indexable token",
            )));
        }
        let (query, matching_terms, raw_candidates, fragment_cache_hits): (
            Box<dyn Query>,
            Vec<usize>,
            Vec<usize>,
            usize,
        ) = match mode {
            "token" => {
                let clauses = tokens
                    .iter()
                    .map(|token| {
                        Box::new(TermQuery::new(
                            Term::from_field_text(self.body_field, token),
                            IndexRecordOption::Basic,
                        )) as Box<dyn Query>
                    })
                    .collect();
                (and_query(clauses), Vec::new(), Vec::new(), 0)
            }
            "contains" | "regex_guard" => {
                if tokens.iter().any(|token| token.chars().count() < 3) {
                    return Ok(KeywordPlan::Fallback(self.fallback_evidence(
                        mode,
                        tokens,
                        Vec::new(),
                        Vec::new(),
                        0,
                        started,
                        "fragment guard contains a token shorter than three characters",
                    )));
                }
                // Under the skip-hex8 profile the fragment dictionary is
                // deliberately incomplete for hex-only text: a filtered
                // >=8-byte hash term may contain any hex-only token as a
                // substring. Expanding such a token against the filtered
                // index would under-select candidate blocks — a silent wrong
                // answer, because Candidates PRUNE the source recheck. Route
                // the whole hunt to the unpruned exact lane instead.
                if !self.fragment.is_complete()
                    && tokens.iter().any(|token| hex_only_token(token))
                {
                    return Ok(KeywordPlan::Fallback(self.fallback_evidence(
                        mode,
                        tokens,
                        Vec::new(),
                        Vec::new(),
                        0,
                        started,
                        "hex-only token may match terms the skip-hex8 fragment profile filtered; \
                         routing to the unpruned exact lane",
                    )));
                }
                let mut clauses = Vec::new();
                let mut matching_terms = Vec::new();
                let mut raw_candidates = Vec::new();
                let mut fragment_cache_hits = 0_usize;
                for token in &tokens {
                    let (fragment, cache_hit) =
                        self.fragment
                            .matching_terms(&self.reader, self.body_field, token)?;
                    fragment_cache_hits += usize::from(cache_hit);
                    raw_candidates.push(fragment.raw_candidates);
                    matching_terms.push(fragment.terms.len());
                    if fragment.raw_candidates > MAX_FRAGMENT_TERMS {
                        return Ok(KeywordPlan::Fallback(self.fallback_evidence(
                            mode,
                            tokens,
                            matching_terms,
                            raw_candidates,
                            fragment_cache_hits,
                            started,
                            "fragment term candidate bound was exceeded",
                        )));
                    }
                    if fragment.terms.is_empty() {
                        // Definitive: hex-only tokens were already routed to
                        // the fallback lane above, and a non-hex token cannot
                        // be a substring of any term the skip-hex8 profile
                        // filtered. So an empty expansion proves the token
                        // appears in no source term — under every admitted
                        // filter profile — and the empty candidate set is an
                        // exact answer, not a gap in the dictionary.
                        let evidence = KeywordPlannerEvidence {
                            kind: "keyword",
                            mode: mode.to_string(),
                            accelerated: true,
                            candidate_blocks: 0,
                            candidate_objects: 0,
                            total_blocks: self.total_blocks,
                            exact_recheck: true,
                            tokens,
                            fragment_matching_terms: matching_terms,
                            fragment_raw_candidates: raw_candidates,
                            fragment_cache_hits,
                            index_seconds: started.elapsed().as_secs_f64(),
                            fallback_reason: None,
                        };
                        return Ok(KeywordPlan::Candidates {
                            candidates: Vec::new(),
                            evidence,
                        });
                    }
                    clauses.push(Box::new(TermSetQuery::new(
                        fragment
                            .terms
                            .iter()
                            .map(|term| Term::from_field_text(self.body_field, term)),
                    )) as Box<dyn Query>);
                }
                (
                    and_query(clauses),
                    matching_terms,
                    raw_candidates,
                    fragment_cache_hits,
                )
            }
            _ => {
                return Err(TextSidecarError::Invalid(
                    "compiler requested an unsupported keyword mode".to_string(),
                ));
            }
        };

        let searcher = self.reader.searcher();
        let collector = TopDocs::with_limit(MAX_CANDIDATE_BLOCKS + 1)
            .order_by_fast_field::<u64>("max_time", Order::Desc);
        let (hits, count) = searcher.search(query.as_ref(), &(collector, Count))?;
        if count > MAX_CANDIDATE_BLOCKS {
            return Ok(KeywordPlan::Fallback(self.fallback_evidence(
                mode,
                tokens,
                matching_terms,
                raw_candidates,
                fragment_cache_hits,
                started,
                "keyword candidate block bound was exceeded",
            )));
        }
        let mut candidates = Vec::with_capacity(hits.len());
        let mut candidate_objects = BTreeSet::new();
        let mut locators = BTreeSet::new();
        for (max_time, address) in hits {
            let locator = searcher
                .segment_reader(address.segment_ord)
                .fast_fields()
                .u64("locator")?
                .first(address.doc_id)
                .ok_or_else(|| {
                    TextSidecarError::Invalid(
                        "keyword document is missing its block locator".to_string(),
                    )
                })?;
            let candidate = self.blocks.get(&locator).ok_or_else(|| {
                TextSidecarError::Invalid(
                    "keyword index returned a locator outside its manifest".to_string(),
                )
            })?;
            if !locators.insert(locator) {
                return Err(TextSidecarError::Invalid(
                    "keyword index returned a duplicate block locator".to_string(),
                ));
            }
            candidate_objects.insert(self.object_by_locator[&locator]);
            let mut candidate = candidate.clone();
            candidate.max_time_ms = max_time;
            candidates.push(candidate);
        }
        if candidates.len() != count {
            return Err(TextSidecarError::Invalid(
                "keyword collector did not return every bounded candidate".to_string(),
            ));
        }
        let evidence = KeywordPlannerEvidence {
            kind: "keyword",
            mode: mode.to_string(),
            accelerated: true,
            candidate_blocks: candidates.len(),
            candidate_objects: candidate_objects.len(),
            total_blocks: self.total_blocks,
            exact_recheck: true,
            tokens,
            fragment_matching_terms: matching_terms,
            fragment_raw_candidates: raw_candidates,
            fragment_cache_hits,
            index_seconds: started.elapsed().as_secs_f64(),
            fallback_reason: None,
        };
        Ok(KeywordPlan::Candidates {
            candidates,
            evidence,
        })
    }

    fn fallback_evidence(
        &self,
        mode: &str,
        tokens: Vec<String>,
        matching_terms: Vec<usize>,
        raw_candidates: Vec<usize>,
        fragment_cache_hits: usize,
        started: Instant,
        reason: &str,
    ) -> KeywordPlannerEvidence {
        KeywordPlannerEvidence {
            kind: "keyword",
            mode: mode.to_string(),
            accelerated: false,
            candidate_blocks: self.total_blocks,
            candidate_objects: 0,
            total_blocks: self.total_blocks,
            exact_recheck: true,
            tokens,
            fragment_matching_terms: matching_terms,
            fragment_raw_candidates: raw_candidates,
            fragment_cache_hits,
            index_seconds: started.elapsed().as_secs_f64(),
            fallback_reason: Some(reason.to_string()),
        }
    }
}

impl FragmentSidecar {
    fn is_complete(&self) -> bool {
        self.filter_profile == "all"
    }

    fn load(
        manifest_path: &Path,
        index_path: &Path,
        keyword_index: &Index,
        keyword_manifest: &KeywordManifest,
    ) -> Result<Self> {
        let bytes = std::fs::read(manifest_path).map_err(TextSidecarError::Read)?;
        let manifest: FragmentManifest =
            serde_json::from_slice(&bytes).map_err(TextSidecarError::Decode)?;
        let legacy = manifest.index_version == FRAGMENT_INDEX_VERSION
            && manifest.term_payload == "keyword dictionary ordinal fast field";
        let incremental = manifest.index_version == FRAGMENT_INDEX_VERSION_V2
            && manifest.term_payload == "stored exact keyword term";
        if (!legacy && !incremental)
            || manifest.engine != "tantivy"
            || manifest.tantivy_version != "0.26.0"
            || manifest.tokenizer != "character ngram 3..3"
            || manifest.index_option != "basic postings: distinct-term document IDs only"
            || manifest.fieldnorms
            || !matches!(manifest.filter_profile.as_str(), "all" | "skip-hex8")
            || manifest.source_terms == 0
            || manifest.indexed_terms == 0
            || manifest.indexed_terms > manifest.source_terms
            || manifest.segments == 0
            || manifest.index_bytes != directory_bytes(index_path)?
            || !keyword_manifest.fragment_dictionary_ready
            || (legacy && keyword_manifest.segments != 1)
        {
            return Err(TextSidecarError::Invalid(
                "fragment version, schema, source, or byte contract failed".to_string(),
            ));
        }
        let index = Index::open_in_dir(index_path)?;
        index.tokenizers().register(
            FRAGMENT_TOKENIZER,
            NgramTokenizer::new(3, 3, false).map_err(|error| {
                TextSidecarError::Invalid(format!("fragment tokenizer is invalid: {error}"))
            })?,
        );
        let term_field = index
            .schema()
            .get_field("term")
            .map_err(|_| TextSidecarError::Invalid("fragment term field is absent".to_string()))?;
        let resolver = if legacy {
            let keyword_reader = keyword_index.reader()?;
            let keyword_searcher = keyword_reader.searcher();
            if keyword_searcher.segment_readers().len() != 1 {
                return Err(TextSidecarError::Invalid(
                    "keyword dictionary must have one immutable segment".to_string(),
                ));
            }
            let body = keyword_index.schema().get_field("body").map_err(|_| {
                TextSidecarError::Invalid("keyword body field is absent".to_string())
            })?;
            let dictionary = keyword_searcher.segment_reader(0).inverted_index(body)?;
            if dictionary.terms().num_terms() as u64 != manifest.source_terms {
                return Err(TextSidecarError::Invalid(
                    "fragment source term count differs from the keyword dictionary".to_string(),
                ));
            }
            index.schema().get_field("keyword_term_ord").map_err(|_| {
                TextSidecarError::Invalid("fragment ordinal field is absent".to_string())
            })?;
            FragmentTermResolver::KeywordOrdinal {
                field: "keyword_term_ord",
            }
        } else {
            let field = index.schema().get_field("exact_term").map_err(|_| {
                TextSidecarError::Invalid("fragment exact-term field is absent".to_string())
            })?;
            FragmentTermResolver::StoredExact { field }
        };
        let reader = index.reader()?;
        if reader.searcher().segment_readers().len() != manifest.segments
            || (incremental && reader.searcher().num_docs() != manifest.indexed_terms)
        {
            return Err(TextSidecarError::Invalid(
                "fragment segment count differs from its manifest".to_string(),
            ));
        }
        Ok(Self {
            reader,
            term_field,
            resolver,
            source_terms: manifest.source_terms,
            filter_profile: manifest.filter_profile,
            cache: Mutex::new(FragmentExpansionCache::default()),
        })
    }

    fn matching_terms(
        &self,
        keyword_reader: &IndexReader,
        keyword_body: Field,
        token: &str,
    ) -> Result<(FragmentTerms, bool)> {
        if let Some(cached) = self
            .cache
            .lock()
            .map_err(|_| TextSidecarError::Invalid("fragment cache is poisoned".to_string()))?
            .get(token)
        {
            return Ok((cached, true));
        }
        let clauses = trigrams(token)
            .into_iter()
            .map(|gram| {
                Box::new(TermQuery::new(
                    Term::from_field_text(self.term_field, &gram),
                    IndexRecordOption::Basic,
                )) as Box<dyn Query>
            })
            .collect();
        let query = and_query(clauses);
        let searcher = self.reader.searcher();
        let (addresses, count) = searcher.search(
            query.as_ref(),
            &(
                Addresses {
                    per_segment_limit: MAX_FRAGMENT_TERMS + 1,
                },
                Count,
            ),
        )?;
        if count > MAX_FRAGMENT_TERMS {
            let result = FragmentTerms {
                terms: Vec::new(),
                raw_candidates: count,
            };
            self.cache
                .lock()
                .map_err(|_| TextSidecarError::Invalid("fragment cache is poisoned".to_string()))?
                .insert(token.to_string(), result.clone());
            return Ok((result, false));
        }
        let keyword_searcher = keyword_reader.searcher();
        let legacy_dictionary = match self.resolver {
            FragmentTermResolver::KeywordOrdinal { .. } => {
                if keyword_searcher.segment_readers().len() != 1 {
                    return Err(TextSidecarError::Invalid(
                        "keyword dictionary no longer has one segment".to_string(),
                    ));
                }
                Some(
                    keyword_searcher
                        .segment_reader(0)
                        .inverted_index(keyword_body)?,
                )
            }
            FragmentTermResolver::StoredExact { .. } => None,
        };
        let mut term_bytes = Vec::new();
        let mut terms = BTreeSet::new();
        for address in addresses {
            let term = match self.resolver {
                FragmentTermResolver::KeywordOrdinal { field } => {
                    let ordinal = searcher
                        .segment_reader(address.segment_ord)
                        .fast_fields()
                        .u64(field)?
                        .first(address.doc_id)
                        .ok_or_else(|| {
                            TextSidecarError::Invalid(
                                "fragment document is missing its keyword ordinal".to_string(),
                            )
                        })?;
                    if ordinal >= self.source_terms {
                        return Err(TextSidecarError::Invalid(
                            "fragment ordinal is outside the keyword dictionary".to_string(),
                        ));
                    }
                    term_bytes.clear();
                    if !legacy_dictionary
                        .as_ref()
                        .expect("legacy dictionary is present")
                        .terms()
                        .ord_to_term(ordinal, &mut term_bytes)
                        .map_err(TextSidecarError::Read)?
                    {
                        return Err(TextSidecarError::Invalid(
                            "fragment ordinal cannot be resolved".to_string(),
                        ));
                    }
                    std::str::from_utf8(&term_bytes)
                        .map_err(|_| {
                            TextSidecarError::Invalid(
                                "keyword dictionary term is not UTF-8".to_string(),
                            )
                        })?
                        .to_string()
                }
                FragmentTermResolver::StoredExact { field } => {
                    let document: tantivy::TantivyDocument = searcher.doc(address)?;
                    document
                        .get_first(field)
                        .and_then(|value| value.as_str())
                        .ok_or_else(|| {
                            TextSidecarError::Invalid(
                                "fragment document is missing its exact term".to_string(),
                            )
                        })?
                        .to_string()
                }
            };
            if term.contains(token) {
                terms.insert(term);
            }
        }
        let result = FragmentTerms {
            terms: terms.into_iter().collect(),
            raw_candidates: count,
        };
        self.cache
            .lock()
            .map_err(|_| TextSidecarError::Invalid("fragment cache is poisoned".to_string()))?
            .insert(token.to_string(), result.clone());
        Ok((result, false))
    }
}

#[derive(Clone)]
struct FragmentTerms {
    terms: Vec<String>,
    raw_candidates: usize,
}

struct FragmentCacheEntry {
    terms: FragmentTerms,
    bytes: usize,
}

#[derive(Default)]
struct FragmentExpansionCache {
    entries: BTreeMap<String, FragmentCacheEntry>,
    lru: VecDeque<String>,
    bytes: usize,
}

impl FragmentExpansionCache {
    fn get(&mut self, key: &str) -> Option<FragmentTerms> {
        let result = self.entries.get(key)?.terms.clone();
        self.touch(key);
        Some(result)
    }

    fn insert(&mut self, key: String, terms: FragmentTerms) {
        let bytes = key.len()
            + terms.terms.iter().map(|term| term.len()).sum::<usize>()
            + std::mem::size_of::<FragmentTerms>();
        if bytes > FRAGMENT_CACHE_MAX_BYTES {
            return;
        }
        self.remove(&key);
        self.bytes = self.bytes.saturating_add(bytes);
        self.lru.push_back(key.clone());
        self.entries
            .insert(key, FragmentCacheEntry { terms, bytes });
        while self.entries.len() > FRAGMENT_CACHE_MAX_ENTRIES
            || self.bytes > FRAGMENT_CACHE_MAX_BYTES
        {
            let Some(oldest) = self.lru.pop_front() else {
                break;
            };
            if let Some(entry) = self.entries.remove(&oldest) {
                self.bytes = self.bytes.saturating_sub(entry.bytes);
            }
        }
    }

    fn touch(&mut self, key: &str) {
        if let Some(position) = self.lru.iter().position(|candidate| candidate == key) {
            self.lru.remove(position);
        }
        self.lru.push_back(key.to_string());
    }

    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.bytes = self.bytes.saturating_sub(entry.bytes);
        }
        if let Some(position) = self.lru.iter().position(|candidate| candidate == key) {
            self.lru.remove(position);
        }
    }
}

fn validate_keyword_manifest(
    manifest: &KeywordManifest,
    tenant_id: &str,
    source_manifest: &SourceManifest,
    index_path: &Path,
) -> Result<()> {
    if !matches!(
        manifest.index_version.as_str(),
        KEYWORD_INDEX_VERSION | KEYWORD_INDEX_VERSION_V3
    ) || manifest.tenant_id != tenant_id
        || manifest.engine != "tantivy"
        || manifest.tokenizer != "simple split on non-alphanumeric, then lowercase"
        || manifest.index_granularity != "one document per aligned Parquet row group"
        || manifest.exactness != "candidate superset only; source text is always rechecked"
        || !manifest
            .body_fields
            .iter()
            .map(String::as_str)
            .eq(KEYWORD_BODY_FIELDS.iter().copied())
        || manifest.source_files == 0
        || manifest.objects.len() != manifest.source_files
        || manifest.blocks.len() != manifest.block_documents
        || manifest.block_documents == 0
        || manifest.segments == 0
        || (manifest.index_version == KEYWORD_INDEX_VERSION && manifest.segments != 1)
        || !manifest.fragment_dictionary_ready
        || manifest.index_bytes != directory_bytes(index_path)?
    {
        return Err(TextSidecarError::Invalid(
            "keyword version, tenant, schema, or byte contract failed".to_string(),
        ));
    }
    let source_objects = source_manifest
        .objects
        .iter()
        .map(|object| (object.event_object_key.as_str(), object))
        .collect::<BTreeMap<_, _>>();
    let mut object_ids = BTreeSet::new();
    let mut source_bytes = 0_u64;
    let mut event_rows = 0_u64;
    for object in &manifest.objects {
        let source = source_objects
            .get(object.event_object_key.as_str())
            .ok_or_else(|| {
                TextSidecarError::Invalid(
                    "keyword object is outside the source manifest".to_string(),
                )
            })?;
        if !object_ids.insert(object.object_id)
            || object.event_object_version != source.event_object_version
            || object.event_object_bytes != source.event_object_bytes
            || object.rows != source.rows
        {
            return Err(TextSidecarError::Invalid(
                "keyword object identity, version, size, or rows failed".to_string(),
            ));
        }
        source_bytes = source_bytes.saturating_add(object.event_object_bytes);
        event_rows = event_rows.saturating_add(object.rows);
    }
    if object_ids.len() != source_objects.len()
        || source_bytes != manifest.source_bytes
        || event_rows != manifest.event_rows
    {
        return Err(TextSidecarError::Invalid(
            "keyword source totals differ from the immutable event snapshot".to_string(),
        ));
    }
    let mut per_object = BTreeMap::<u32, Vec<&KeywordBlock>>::new();
    for block in &manifest.blocks {
        per_object.entry(block.object_id).or_default().push(block);
    }
    for object in &manifest.objects {
        let blocks = per_object.get_mut(&object.object_id).ok_or_else(|| {
            TextSidecarError::Invalid("keyword object has no block document".to_string())
        })?;
        blocks.sort_by_key(|block| block.row_group);
        let mut row_start = 0_u64;
        for (row_group, block) in blocks.iter().enumerate() {
            if block.row_group as usize != row_group || block.row_start != row_start {
                return Err(TextSidecarError::Invalid(
                    "keyword block ranges are not contiguous".to_string(),
                ));
            }
            row_start = block.row_end;
        }
        if row_start != object.rows {
            return Err(TextSidecarError::Invalid(
                "keyword block ranges do not cover the source object".to_string(),
            ));
        }
    }
    Ok(())
}

/// True when the skip-hex8 fragment profile excludes this normalized term:
/// lowercase hex-only (ASCII digits and a-f) and at least eight bytes. Terms
/// are already lowercased by both the builder and `query_tokens`, so an
/// uppercase byte correctly reads as non-hex here.
pub fn hex8_filtered_term(term: &str) -> bool {
    term.len() >= 8
        && term
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// True when a lowercase query token could be a substring of a term the
/// skip-hex8 profile removed. Every substring of a hex-only string is itself
/// hex-only, so any hex-only token — regardless of its own length — may hide
/// inside a filtered >=8-byte hash term. A token with one non-hex byte can
/// never appear inside a filtered term, so the fragment index stays complete
/// for it.
fn hex_only_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn query_tokens(value: &str) -> Vec<String> {
    let mut analyzer = TextAnalyzer::builder(SimpleTokenizer::default())
        .filter(LowerCaser)
        .build();
    let mut tokens = BTreeSet::new();
    analyzer.token_stream(value.trim()).process(&mut |token| {
        tokens.insert(token.text.clone());
    });
    tokens.into_iter().collect()
}

fn trigrams(value: &str) -> Vec<String> {
    let characters = value.chars().collect::<Vec<_>>();
    let mut grams = BTreeSet::new();
    for window in characters.windows(3) {
        grams.insert(window.iter().collect());
    }
    grams.into_iter().collect()
}

fn and_query(mut clauses: Vec<Box<dyn Query>>) -> Box<dyn Query> {
    if clauses.len() == 1 {
        return clauses.pop().expect("one clause is present");
    }
    Box::new(BooleanQuery::new(
        clauses
            .into_iter()
            .map(|query| (Occur::Must, query))
            .collect(),
    ))
}

/// Total bytes of a text index tree.
///
/// NAN-2754: a generation admitted through the incremental-inventory path
/// (`generation_bundle::hydrate_generation_bundle_inner`) installs every index
/// member as a symlink into the per-root content store
/// `<generations_root>/objects/<sha256>`. `DirEntry::file_type` does not follow
/// symlinks, so refusing every non-regular entry made each such generation
/// fail the reader at boot ("text index contains a non-file entry") even
/// though config.rs already accepts the same layout (NAN-2532). A symlink is
/// admitted only when it resolves to a regular file directly inside an
/// `objects` directory whose parent is an ancestor of the index; anything
/// else (an escaping, dangling or directory link, a socket, a FIFO) is still
/// refused.
fn directory_bytes(path: &Path) -> Result<u64> {
    let mut canonical_root: Option<PathBuf> = None;
    let mut pending = vec![path.to_path_buf()];
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory).map_err(TextSidecarError::Read)? {
            let entry = entry.map_err(TextSidecarError::Read)?;
            let kind = entry.file_type().map_err(TextSidecarError::Read)?;
            if kind.is_dir() {
                pending.push(entry.path());
            } else if kind.is_file() {
                bytes =
                    bytes.saturating_add(entry.metadata().map_err(TextSidecarError::Read)?.len());
            } else if kind.is_symlink() {
                if canonical_root.is_none() {
                    canonical_root =
                        Some(std::fs::canonicalize(path).map_err(TextSidecarError::Read)?);
                }
                let root = canonical_root.as_deref().expect("canonical root is set");
                bytes = bytes.saturating_add(content_store_member_bytes(root, &entry.path())?);
            } else {
                return Err(TextSidecarError::Invalid(
                    "text index contains a non-file entry".to_string(),
                ));
            }
        }
    }
    Ok(bytes)
}

/// Size of one content-store member linked into the index at `link`.
fn content_store_member_bytes(canonical_root: &Path, link: &Path) -> Result<u64> {
    let refuse = || {
        TextSidecarError::Invalid(
            "text index contains a symlink that is not a content-store file".to_string(),
        )
    };
    // Dangling or unreadable: refused, never an I/O error that reads like
    // transient trouble.
    let target = std::fs::canonicalize(link).map_err(|_| refuse())?;
    let metadata = std::fs::metadata(&target).map_err(|_| refuse())?;
    let store = target.parent().ok_or_else(refuse)?;
    let store_owner = store.parent().ok_or_else(refuse)?;
    if !metadata.is_file()
        || store.file_name().and_then(|name| name.to_str()) != Some("objects")
        || !canonical_root.starts_with(store_owner)
    {
        return Err(refuse());
    }
    Ok(metadata.len())
}

struct Addresses {
    per_segment_limit: usize,
}

struct AddressSegmentCollector {
    segment_ord: u32,
    limit: usize,
    addresses: Vec<DocAddress>,
}

impl Collector for Addresses {
    type Fruit = Vec<DocAddress>;
    type Child = AddressSegmentCollector;

    fn for_segment(
        &self,
        segment_local_id: u32,
        _segment_reader: &SegmentReader,
    ) -> tantivy::Result<Self::Child> {
        Ok(AddressSegmentCollector {
            segment_ord: segment_local_id,
            limit: self.per_segment_limit,
            addresses: Vec::new(),
        })
    }

    fn requires_scoring(&self) -> bool {
        false
    }

    fn merge_fruits(&self, fruits: Vec<Self::Fruit>) -> tantivy::Result<Self::Fruit> {
        Ok(fruits.into_iter().flatten().collect())
    }
}

impl SegmentCollector for AddressSegmentCollector {
    type Fruit = Vec<DocAddress>;

    fn collect(&mut self, doc: DocId, _score: Score) {
        if self.addresses.len() < self.limit {
            self.addresses.push(DocAddress::new(self.segment_ord, doc));
        }
    }

    fn harvest(self) -> Self::Fruit {
        self.addresses
    }
}

#[cfg(test)]
mod tests {

    /// The compiler decides which fields get a keyword hint; this file decides
    /// which fields are indexed. If a path is hinted but not indexed, the
    /// planner can return an EMPTY candidate set, and that set fences the query
    /// BEFORE the source recheck — every hunt on that field silently returns
    /// zero rows. So the two lists are one contract, and this pins them.
    ///
    /// Adding a field: add it to `nanosiem_core::search::keyword_sidecar` and
    /// here, and make sure the index actually builds it. Never add it to the
    /// compiler's list alone.
    #[test]
    fn keyword_body_fields_match_the_compiler_contract() {
        use nanosiem_core::search::keyword_sidecar::KEYWORD_SIDECAR_PATHS;

        let indexed: Vec<&str> = KEYWORD_BODY_FIELDS.to_vec();
        let hinted: Vec<&str> = KEYWORD_SIDECAR_PATHS.to_vec();

        let hinted_not_indexed: Vec<&&str> =
            hinted.iter().filter(|p| !indexed.contains(p)).collect();
        assert!(
            hinted_not_indexed.is_empty(),
            "these paths are hinted by the query compiler but NOT indexed here, so a hunt on \
             them can be fenced to zero rows before the source recheck runs: {hinted_not_indexed:?}"
        );

        // The reverse direction is merely a lost optimization, but the two are
        // meant to be one list — flag it so drift is deliberate, not accidental.
        let indexed_not_hinted: Vec<&&str> =
            indexed.iter().filter(|p| !hinted.contains(p)).collect();
        assert!(
            indexed_not_hinted.is_empty(),
            "indexed but never hinted (harmless, but the lists are meant to agree): {indexed_not_hinted:?}"
        );
    }
    use super::*;

    #[test]
    fn query_tokenization_matches_the_published_analyzer() {
        assert_eq!(
            query_tokens(" RUNDLL32.exe + Admin "),
            ["admin", "exe", "rundll32"]
        );
    }

    #[test]
    fn canonical_hash_arrays_are_part_of_the_fragment_dictionary() {
        for path in [
            "file.hashes.value",
            "process.file.hashes.value",
            "actor.process.file.hashes.value",
        ] {
            assert!(KEYWORD_BODY_FIELDS.contains(&path), "missing {path}");
        }
    }

    #[test]
    fn skip_hex8_filters_only_long_lowercase_hex_terms() {
        // At least eight bytes AND every byte in [0-9a-f]: excluded.
        assert!(hex8_filtered_term("deadbeef"));
        assert!(hex8_filtered_term("0123456789abcdef"));
        assert!(hex8_filtered_term("12345678")); // digit-only is hex-only
        assert!(hex8_filtered_term(
            "5f2b1c9e8d7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c"
        ));
        // Seven bytes: kept, whatever the alphabet.
        assert!(!hex8_filtered_term("deadbee"));
        // One non-hex byte anywhere: kept.
        assert!(!hex8_filtered_term("rundll32"));
        assert!(!hex8_filtered_term("deadbeefg"));
        assert!(!hex8_filtered_term("DEADBEEF")); // builder terms are lowercase
        assert!(!hex8_filtered_term(""));
    }

    #[test]
    fn hex_only_tokens_route_away_from_a_filtered_fragment_lane() {
        // Any hex-only token can hide inside a filtered hash term.
        assert!(hex_only_token("bee"));
        assert!(hex_only_token("deadbee"));
        assert!(hex_only_token("deadbeefcafe1234"));
        // A non-hex byte makes fragment expansion complete again.
        assert!(!hex_only_token("rundll32"));
        assert!(!hex_only_token("exe"));
        assert!(!hex_only_token(""));
    }

    #[test]
    fn fragments_are_unicode_safe_and_unique() {
        assert_eq!(trigrams("aaaa"), ["aaa"]);
        assert_eq!(trigrams("éxéc"), ["xéc", "éxé"]);
    }

    #[test]
    fn fragment_expansion_cache_is_bounded_lru() {
        let mut cache = FragmentExpansionCache::default();
        for index in 0..=FRAGMENT_CACHE_MAX_ENTRIES {
            cache.insert(
                format!("term-{index}"),
                FragmentTerms {
                    terms: vec![format!("expanded-{index}")],
                    raw_candidates: 1,
                },
            );
        }
        assert_eq!(cache.entries.len(), FRAGMENT_CACHE_MAX_ENTRIES);
        assert!(cache.get("term-0").is_none());
        assert_eq!(
            cache.get("term-1").map(|terms| terms.terms),
            Some(vec!["expanded-1".to_string()])
        );
    }
}
