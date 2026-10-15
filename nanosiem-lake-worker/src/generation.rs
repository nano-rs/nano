// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native builders for one immutable query-serving generation.
//!
//! These builders consume exact local copies of the files in an Iceberg
//! snapshot. They publish candidate indexes only; every hit is rechecked
//! against canonical OCSF event data by the query worker.

use anyhow::{bail, Context, Result};
use arrow_array::builder::{
    FixedSizeBinaryBuilder, Int64Builder, StringBuilder, TimestampMicrosecondBuilder,
    UInt16Builder, UInt32Builder, UInt64Builder, UInt8Builder,
};
use arrow_array::types::{
    TimestampMicrosecondType, TimestampMillisecondType, TimestampNanosecondType,
    TimestampSecondType,
};
use arrow_array::{
    Array, ArrayRef, BinaryArray, FixedSizeBinaryArray, FixedSizeListArray, Int32Array, Int64Array,
    LargeBinaryArray, LargeListArray, LargeStringArray, ListArray, PrimitiveArray, RecordBatch,
    StringArray, StringViewArray, StructArray, UInt16Array, UInt32Array, UInt64Array, UInt8Array,
};
use arrow_schema::{DataType, Field, Schema};
use futures::{StreamExt, TryStreamExt};
use hmac::{Hmac, Mac};
use iceberg::spec::DataFileFormat;
use iceberg::Catalog;
use iceberg_catalog_rest::RestCatalog;
use opendal::{services::S3, Operator};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::metadata::ParquetMetaData;
use parquet::file::properties::WriterProperties;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::net::IpAddr;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tantivy::schema::OwnedValue;
use tantivy::schema::{
    Field as TantivyField, IndexRecordOption, Schema as TantivySchema, TextFieldIndexing,
    TextOptions, FAST, INDEXED, STORED, STRING,
};
use tantivy::termdict::TermMerger;
use tantivy::tokenizer::{LowerCaser, NgramTokenizer, SimpleTokenizer, TextAnalyzer};
use tantivy::{doc, Index, IndexWriter, TantivyDocument, Term};
use tantivy::{
    index::{SegmentId, SegmentMeta},
    indexer::IndexWriterOptions,
    merge_policy::{MergeCandidate, MergePolicy},
};

use crate::bounds::{HOT_TAIL_OBJECT_FORMAT_CEILING, HOT_TAIL_SERVING_CEILING_BYTES};

const NORMALIZATION_VERSION: &str = "ocsf-entity-v1";
/// Entity-sidecar object identity model: stable u32 ids from a persisted
/// per-lineage allocator (never snapshot ordinals). Manifests without this
/// marker carry pre-stable UInt16 ordinal ids and are migrated on reuse.
const OBJECT_ID_MODEL: &str = "stable-u32-v1";
/// v1 stored the full 32-byte HMAC per posting row; v2 stores the leading
/// `ENTITY_VALUE_HASH_BYTES` bytes. Measured on the deployed sidecar, the
/// full-width hash column was 95.3% of the derivative's bytes and essentially
/// incompressible; truncation is sound because the sidecar is only a
/// candidate SUPERSET selector — a 128-bit HMAC-prefix collision can only ADD
/// a candidate block, and every candidate block is rechecked by the exact
/// compiler-owned event query. Under-selection is impossible: any row whose
/// full hash equals the probe's full hash also matches its 16-byte prefix.
const ENTITY_INDEX_VERSION_V1: &str = "ocsf-entity-block-v1";
const ENTITY_INDEX_VERSION_V2: &str = "ocsf-entity-block-v2";
/// Stored prefix length of the per-value HMAC-SHA256 digest (v2 layout).
const ENTITY_VALUE_HASH_BYTES: usize = 16;
const KEYWORD_TOKENIZER: &str = "nano_simple_lower_v1";
const FRAGMENT_TOKENIZER: &str = "nano_char_trigram_v1";
/// Bound the only owned term material between Tantivy's on-disk keyword
/// dictionary and the fragment writer. The former implementation retained a
/// table-sized `BTreeSet<String>` while Tantivy simultaneously held its writer
/// heap; a 1-TB incremental generation exceeded a 10-GiB cgroup even though
/// both configured writer budgets remained inside their profile.
const FRAGMENT_TERM_BATCH_TERMS: usize = 65_536;
/// Move row-group bodies directly into Tantivy's asynchronous admission queue.
/// `TantivyDocument::add_text` copies its input into CompactDoc storage, which
/// temporarily retained two multi-hundred-MiB bodies per producer. The owned
/// map is itself a supported Tantivy `Document`, preserving one document per
/// row group and every existing locator while avoiding that second full copy.
/// `build_keyword` must still drain that queue at each bounded producer batch:
/// Tantivy bounds it by DOCUMENT COUNT (10,000), not bytes, so admitting a
/// table's worth of large row-group bodies can otherwise exceed the cgroup
/// while its configured writer heap remains inside the deployment envelope.
type KeywordDocument = BTreeMap<TantivyField, OwnedValue>;
/// Arrow decoding is independently bounded from the physical Parquet row-group
/// size. Product writers currently cap row groups, but the derivative builder
/// also consumes older generations and must not trust that as a memory bound.
const DERIVATIVE_PARQUET_BATCH_ROWS: usize = 8_192;
const DERIVATIVE_COMPATIBILITY_CONTRACT_VERSION: &str = "nano-lake-derivative-compatibility-v3";
const ENTITY_MANIFEST_SCHEMA_VERSION: u64 = 1;
const IDENTITY_MANIFEST_SCHEMA_VERSION: u64 = 1;
const IDENTITY_WINDOW_DAYS: u64 = 30;

// NAN-2361: per-promotion maintenance must cost time proportional to NEW data,
// not total table size. The constants below control the verified-stamp trust
// records and the incremental metadata.uid uniqueness ledger that replace the
// former re-hash-everything / re-prove-everything passes. Every skipped full
// verification is compensated by (a) cheap stat corroboration, (b) a random
// re-verification sample each promotion, and (c) a bounded-age full re-proof.
const LOCAL_VERIFICATION_FILE: &str = "local-verification.json";
const LOCAL_VERIFICATION_SCHEMA_VERSION: u64 = 1;
/// One in this many reusable artifacts is fully re-hashed per promotion, so
/// silent bit-rot behind a matching stamp is still detected in an expected
/// ~64 promotions instead of never.
const REVERIFY_SAMPLE_DENOMINATOR: u64 = 64;
/// Bound the entire HEAD-to-streamed-GET pipeline, including transport
/// buffers and open candidate files, independently of the snapshot size.
const HYDRATION_READ_CONCURRENCY: usize = 8;
const UID_LEDGER_DIRECTORY: &str = "uid-ledger";
const UID_LEDGER_SCHEMA_VERSION: u64 = 1;
/// `trunc128` marks that uid digests are the stored 16-byte entity-sidecar
/// prefix; `r24` marks the 24-byte on-disk window record (16-byte digest,
/// no padding, plus u64 time). Bumping this string is the fence that forces
/// ONE full proof when the digest width or record layout changes: a prior
/// ledger in another encoding must never be merged against these records —
/// a real duplicate would compare unequal and be silently missed, or the
/// record stream would desynchronize entirely.
const UID_LEDGER_ALGORITHM: &str = "hmac-sha256-trunc128-r24-uid-window-v1";
// The algorithm string ENCODES the digest width (trunc128) and record size
// (r24); if the stored entity hash width ever changes, the record layout
// changes with it and this string must be bumped in the same commit.
const _: () = assert!(ENTITY_VALUE_HASH_BYTES == 16 && UID_WINDOW_RECORD_BYTES == 24);
/// Event-time horizon inside which a NEW object's metadata.uid values are
/// exactly checked against previously proven uids. Duplicates injected by
/// ingest retries are temporally local; ClickHouse deployments get only
/// per-insert-block dedup, so a 7-day exact window is strictly stronger.
const UID_WINDOW_DAYS: u64 = 7;
const UID_WINDOW_MS: u64 = UID_WINDOW_DAYS * 24 * 60 * 60 * 1_000;
/// A full O(table) uniqueness proof is re-run at least this often even when
/// every promotion in between qualified for the incremental proof, bounding
/// how long an out-of-window duplicate can remain undetected.
const UID_FULL_PROOF_MAX_AGE_MS: u64 = 30 * 24 * 60 * 60 * 1_000;
/// The stored 16-byte HMAC prefix (`ENTITY_VALUE_HASH_BYTES`, exactly as the
/// entity sidecar stores it — no padding) plus little-endian u64 max event
/// time (milliseconds). Uniqueness over the 16-byte prefixes is what the
/// proof establishes either way; the former 32-byte slot carried 16 bytes of
/// zeros once ab7c8a560 truncated the stored hash, which was 40% of the
/// ledger's bytes buying nothing.
const UID_WINDOW_RECORD_BYTES: usize = ENTITY_VALUE_HASH_BYTES + 8;
/// One window/bucket record's digest: the stored entity-sidecar hash prefix.
type UidDigest = [u8; ENTITY_VALUE_HASH_BYTES];
const UID_PROOF_BUCKET_SHIFT: u32 = 2;
const UID_PROOF_BUCKETS: usize = 256 >> UID_PROOF_BUCKET_SHIFT;
/// Measured peak reservation for one 32,768-row exact count-rollup lane.
/// Deployers must couple lane count to the derivative-build memory envelope.
pub const COUNT_ROLLUP_LANE_MEMORY_BYTES: u64 = 768 * 1_048_576;
/// Conservative measured reservation for one decoded Parquet entity lane.
/// The entity builder previously fanned `--threads` directly across objects;
/// eight lanes consumed more than 8 GiB anonymous memory inside a 6-GiB
/// derivative profile and let the 10-GiB manager cgroup OOM before the first
/// phase boundary. Couple lane count to the deployer-owned derivative budget.
pub const ENTITY_LANE_MEMORY_BYTES: u64 = 1_610_612_736;
/// Same reservation used by the scale03 deployer for one decoded keyword body
/// producer. Reserve Tantivy's configured writer heap inside the derivative
/// phase budget before admitting these decoded-object lanes.
pub const KEYWORD_PRODUCER_LANE_MEMORY_BYTES: u64 = 3_221_225_472;
/// A keyword generation is an append-only LSM-like index. Tantivy's default
/// policy merges every same-sized worker segment into ONE candidate, and one
/// candidate is executed by one core even when the writer has many merge
/// threads. Bound the searchable fanout while merging small pairs in parallel
/// only when the generation would otherwise exceed this count.
const KEYWORD_MAX_SEGMENTS: usize = 16;
/// Bounded Parquet producers for the keyword sidecar. Decoded row-group bodies
/// live outside Tantivy's configured heap, so object fanout must stay finite
/// even when a deployment gives other generation stages many more threads.
const KEYWORD_PRODUCER_CEILING: usize = 4;
pub const MAX_KEYWORD_PRODUCER_CEILING: usize = 32;
/// Tantivy refuses a smaller arena per indexing worker. The fragment writer
/// still uses the full generation thread count, so the total heap must cover
/// this floor for every declared thread before a long build starts.
const TANTIVY_MIN_MEMORY_PER_THREAD: usize = 15_000_000;
// The partition count and the digest-prefix shift are one decision: bucket
// index is digest[0] >> UID_PROOF_BUCKET_SHIFT, so BUCKETS must be exactly
// 2^(8 - SHIFT) or records silently land outside the proven partitions.
const _: () = assert!(UID_PROOF_BUCKETS == 1 << (8 - UID_PROOF_BUCKET_SHIFT));

use crate::iceberg::CatalogConfig;
use crate::native::file_sha256;
use crate::planner::{DASHBOARD_BREAKDOWN_COMPONENTS, DASHBOARD_BREAKDOWN_FIELD};
use crate::rollup::{
    CountRollupManifest, CountRollupManifestField, CountRollupObject, COUNT_ROLLUP_BUCKET_US,
    COUNT_ROLLUP_FIELDS, COUNT_ROLLUP_VERSION,
};
use crate::text_sidecar::{
    hex8_filtered_term, FRAGMENT_FILTER_PROFILE_SKIP_HEX8, FRAGMENT_INDEX_VERSION_V2,
    KEYWORD_BODY_FIELDS, KEYWORD_INDEX_VERSION_V3,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStampManifest {
    pub metadata_location: String,
    pub snapshot_id: i64,
    pub table: String,
    pub objects: Vec<ObjectStamp>,
    /// NAN-2361 wave 8: bound ONLY by the zero-snapshot bootstrap generation
    /// (`crate::bootstrap_generation`), whose identity is the table UUID
    /// because an empty table has no snapshot to name. Real generations omit
    /// it, so their serialized bytes and digests are unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub table_uuid: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectStamp {
    pub relative_path: String,
    pub source_uri: String,
    pub version_id: String,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HotTailManifest {
    pub schema_version: u64,
    pub tenant_id: String,
    pub table: String,
    pub base_snapshot_id: i64,
    pub head_snapshot_id: i64,
    /// Content identity of an out-of-catalog staged tail. Schema v1 tails are
    /// Iceberg descendants and therefore use the head snapshot as their
    /// identity. Schema v2 tails keep the base snapshot fixed and bind the
    /// exact staged object set with this digest instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tail_id: Option<String>,
    pub head_metadata_location: String,
    pub iceberg_metadata_file_path: String,
    /// Catalog-owned schema current when this exact tail was published. A
    /// staged object may introduce additive OCSF fields after the indexed base
    /// snapshot was activated. Binding the read contract into the signed
    /// manifest lets both the old base and the new objects materialize one
    /// compatible nullable shape without advancing the derivative generation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub read_schema: Option<String>,
    /// Queryable canonical paths represented by `read_schema`. These are kept
    /// beside the physical projection so the planner can distinguish a field
    /// that is genuinely absent from one introduced by the exact hot tail.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub available_paths: Vec<String>,
    pub objects: Vec<HotTailObject>,
    /// Process-local, digest-verified hard links for schema-v4 objects.
    ///
    /// These paths are never part of the signed wire contract. The query
    /// worker fills them only after every exact S3 version in the manifest has
    /// passed its byte-length and SHA-256 fence. Keeping the paths beside the
    /// verified manifest lets every planner lane use one constant-shape local
    /// `file()` source without weakening the signed object identity.
    #[serde(skip)]
    pub local_paths: Vec<PathBuf>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HotTailObject {
    pub source_uri: String,
    pub version_id: String,
    /// Opaque provider ETag returned by the authoritative object-store write
    /// or HEAD. Enterprise-shared R2 manifests require this field because R2
    /// has no native S3 object-version API. It is omitted for every existing
    /// versioned-S3 manifest so their signed wire representation is unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    pub size_bytes: u64,
    pub rows: u64,
    /// Immutable content identity required by schema v4. Older schemas omit
    /// it and retain their exact-version remote-read compatibility path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_time_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_time_ms: Option<i64>,
    /// NAN-2361 two-tier hot tail. `false` (Tier A): staged, not yet in any
    /// Iceberg snapshot — bounded by the tight signed serving envelope whose
    /// size is governed by pack/commit latency. `true` (Tier B): committed to
    /// an Iceberg snapshot that the pinned serving base does not yet cover —
    /// exempt from the byte envelope (its scan cost is charged and
    /// Reject-enforced per query by the planner budget, exactly like the
    /// base) and bounded by object count only.
    ///
    /// Serialization is OMITTED when false so a manifest without a committed
    /// tier stays BYTE-IDENTICAL to the legacy format: every pre-NAN-2361
    /// reader deserializes tail manifests with `deny_unknown_fields`, so this
    /// key may only ever appear in `schema_version: 3` manifests, which such
    /// readers must never be handed (the publishers gate v3 emission on an
    /// explicit committed-tier bound being configured).
    #[serde(default, skip_serializing_if = "is_false")]
    pub committed: bool,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// One PostgreSQL-ledger candidate for the bounded staged serving tail.
///
/// The object digest is intentionally kept beside, rather than inside, the
/// public serving manifest. It participates in the content identity and must
/// exactly match an object already present in the immutable base before that
/// candidate can be removed from the tail.
#[derive(Clone, Debug)]
pub struct StagedHotTailLedgerObject {
    pub object: HotTailObject,
    pub sha256: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SignedHotTailManifest {
    manifest: HotTailManifest,
    hmac_sha256: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
struct FieldSpec {
    field_id: u8,
    entity_type: &'static str,
    subtype: &'static str,
    role: &'static str,
    source_path: &'static str,
    kind: &'static str,
}

const ENTITY_FIELDS: &[FieldSpec] = &[
    FieldSpec {
        field_id: 0,
        entity_type: "ip",
        subtype: "address",
        role: "source",
        source_path: "src_endpoint.ip",
        kind: "ip",
    },
    FieldSpec {
        field_id: 1,
        entity_type: "ip",
        subtype: "address",
        role: "destination",
        source_path: "dst_endpoint.ip",
        kind: "ip",
    },
    FieldSpec {
        field_id: 2,
        entity_type: "mac",
        subtype: "address",
        role: "source",
        source_path: "src_endpoint.mac",
        kind: "text",
    },
    FieldSpec {
        field_id: 3,
        entity_type: "mac",
        subtype: "address",
        role: "destination",
        source_path: "dst_endpoint.mac",
        kind: "text",
    },
    FieldSpec {
        field_id: 4,
        entity_type: "host",
        subtype: "hostname",
        role: "source",
        source_path: "src_endpoint.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 5,
        entity_type: "host",
        subtype: "hostname",
        role: "destination",
        source_path: "dst_endpoint.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 6,
        entity_type: "host",
        subtype: "hostname",
        role: "device",
        source_path: "device.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 7,
        entity_type: "user",
        subtype: "name",
        role: "subject",
        source_path: "user.name",
        kind: "text",
    },
    FieldSpec {
        field_id: 8,
        entity_type: "user",
        subtype: "uid",
        role: "subject",
        source_path: "user.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 9,
        entity_type: "user",
        subtype: "name",
        role: "actor",
        source_path: "actor.user.name",
        kind: "text",
    },
    FieldSpec {
        field_id: 10,
        entity_type: "process",
        subtype: "uid",
        role: "subject",
        source_path: "process.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 11,
        entity_type: "hash",
        subtype: "sha256",
        role: "file",
        source_path: "file.hashes.value",
        kind: "text",
    },
    FieldSpec {
        field_id: 12,
        entity_type: "hash",
        subtype: "sha256",
        role: "subject_process",
        source_path: "process.file.hashes.value",
        kind: "text",
    },
    FieldSpec {
        field_id: 13,
        entity_type: "domain",
        subtype: "hostname",
        role: "network",
        source_path: "url.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 14,
        entity_type: "domain",
        subtype: "hostname",
        role: "dns_query",
        source_path: "query.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 15,
        entity_type: "url",
        subtype: "full",
        role: "network",
        source_path: "url.url_string",
        kind: "text",
    },
    FieldSpec {
        field_id: 16,
        entity_type: "dns_answer",
        subtype: "rdata",
        role: "answer",
        source_path: "answers.rdata",
        kind: "text",
    },
    FieldSpec {
        field_id: 17,
        entity_type: "user",
        subtype: "email",
        role: "sender",
        source_path: "email.from",
        kind: "text",
    },
    FieldSpec {
        field_id: 18,
        entity_type: "user",
        subtype: "email",
        role: "recipient",
        source_path: "email.to",
        kind: "text",
    },
    FieldSpec {
        field_id: 19,
        entity_type: "cve",
        subtype: "uid",
        role: "vulnerability",
        source_path: "vulnerabilities.cve.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 20,
        entity_type: "user",
        subtype: "uid",
        role: "actor",
        source_path: "actor.user.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 21,
        entity_type: "process",
        subtype: "uid",
        role: "actor",
        source_path: "actor.process.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 22,
        entity_type: "hash",
        subtype: "sha256",
        role: "actor_process",
        source_path: "actor.process.file.hashes.value",
        kind: "text",
    },
    FieldSpec {
        field_id: 23,
        entity_type: "domain",
        subtype: "hostname",
        role: "http",
        source_path: "http_request.url.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 24,
        entity_type: "url",
        subtype: "full",
        role: "http",
        source_path: "http_request.url.url_string",
        kind: "text",
    },
    FieldSpec {
        field_id: 25,
        entity_type: "ip",
        subtype: "address",
        role: "finding_resource",
        source_path: "resources.ip",
        kind: "ip",
    },
    FieldSpec {
        field_id: 26,
        entity_type: "host",
        subtype: "hostname",
        role: "finding_resource",
        source_path: "resources.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 27,
        entity_type: "host",
        subtype: "hostname",
        role: "finding_device",
        source_path: "resources.device.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 28,
        entity_type: "user",
        subtype: "name",
        role: "finding_user",
        source_path: "resources.user.name",
        kind: "text",
    },
    FieldSpec {
        field_id: 29,
        entity_type: "user",
        subtype: "uid",
        role: "finding_user",
        source_path: "resources.user.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 30,
        entity_type: "cloud",
        subtype: "uid",
        role: "finding_resource",
        source_path: "resources.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 31,
        entity_type: "domain",
        subtype: "hostname",
        role: "finding_evidence",
        source_path: "evidences.query.hostname",
        kind: "text",
    },
    FieldSpec {
        field_id: 32,
        entity_type: "url",
        subtype: "full",
        role: "finding_evidence",
        source_path: "evidences.url.url_string",
        kind: "text",
    },
    FieldSpec {
        field_id: 33,
        entity_type: "process",
        subtype: "name",
        role: "subject",
        source_path: "process.name",
        kind: "text",
    },
    FieldSpec {
        field_id: 34,
        entity_type: "process",
        subtype: "name",
        role: "actor",
        source_path: "actor.process.name",
        kind: "text",
    },
    FieldSpec {
        field_id: 35,
        entity_type: "trace",
        subtype: "uid",
        role: "trace",
        source_path: "trace.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 36,
        entity_type: "trace",
        subtype: "span_uid",
        role: "span",
        source_path: "trace.span.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 37,
        entity_type: "trace",
        subtype: "uid",
        role: "trace_fallback",
        source_path: "unmapped.trace_id",
        kind: "text",
    },
    FieldSpec {
        field_id: 38,
        entity_type: "trace",
        subtype: "span_uid",
        role: "span_fallback",
        source_path: "unmapped.span_id",
        kind: "text",
    },
    FieldSpec {
        field_id: 39,
        entity_type: "event",
        subtype: "uid",
        role: "identity",
        source_path: "metadata.uid",
        kind: "text",
    },
    FieldSpec {
        field_id: 40,
        entity_type: "artifact",
        subtype: "enrichment_value",
        role: "enrichment",
        source_path: "enrichments.value",
        kind: "text",
    },
];

/// Content identity for the on-disk derivative formats consumed by a query
/// worker. This deliberately excludes executable bytes: a bug-fix rebuild of
/// the compiler or chDB runtime must not force every tenant to rebuild valid
/// indexes. Any change that makes an existing entity/text/rollup/identity or
/// prevalence derivative unreadable or incomplete must change one of the
/// semantic values below (normally its format version or field list).
pub fn derivative_compatibility_contract_sha256() -> Result<String> {
    derivative_contract_for_bundle(crate::generation_bundle::GENERATION_BUNDLE_CONTRACT_VERSION)
}

fn derivative_contract_for_bundle(bundle_contract: &str) -> Result<String> {
    let contract = json!({
        "contract_version": DERIVATIVE_COMPATIBILITY_CONTRACT_VERSION,
        // The registry keys publication by this digest, so a bundle contract
        // upgrade must miss old pointers and publish a fresh compatible bundle.
        "generation_bundle_contract": bundle_contract,
        "event_contract": "ocsf-1.9",
        "entity": {
            "manifest_schema_version": ENTITY_MANIFEST_SCHEMA_VERSION,
            "normalization_version": NORMALIZATION_VERSION,
            "fields": ENTITY_FIELDS,
        },
        "keyword": {
            "index_version": KEYWORD_INDEX_VERSION_V3,
            "tokenizer": KEYWORD_TOKENIZER,
            "body_fields": KEYWORD_BODY_FIELDS,
        },
        "fragment": {
            "index_version": FRAGMENT_INDEX_VERSION_V2,
            "tokenizer": FRAGMENT_TOKENIZER,
            "ngram_min": 3,
            "ngram_max": 3,
        },
        "count_rollup": {
            "manifest_schema_version": 1,
            "rollup_version": COUNT_ROLLUP_VERSION,
            "bucket_width_us": COUNT_ROLLUP_BUCKET_US,
            "fields": COUNT_ROLLUP_FIELDS,
            "dashboard_breakdown_field": DASHBOARD_BREAKDOWN_FIELD,
            "dashboard_breakdown_components": DASHBOARD_BREAKDOWN_COMPONENTS,
        },
        "identity": {
            "manifest_schema_version": IDENTITY_MANIFEST_SCHEMA_VERSION,
            "window_days": IDENTITY_WINDOW_DAYS,
            "normalization_version": NORMALIZATION_VERSION,
            "fields": [
                "time",
                "metadata.log_source",
                "src_endpoint.ip",
                "src_endpoint.hostname",
                "device.hostname",
                "user.name",
                "actor.user.name",
                "src_endpoint.mac",
            ],
        },
        "prevalence": crate::prevalence_build::derivative_compatibility_contract(),
    });
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&contract)?)))
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBuildResult {
    pub source_files: usize,
    pub event_rows: u64,
    /// Rows covered by the exact cross-object metadata.uid uniqueness proof.
    pub event_uid_rows: u64,
    pub source_bytes: u64,
    pub entity_index_bytes: u64,
    pub keyword_index_bytes: u64,
    pub fragment_index_bytes: u64,
    pub count_rollup_rows: u64,
    pub count_rollup_bytes: u64,
    pub identity_observation_rows: u64,
    pub identity_snapshot_bytes: u64,
    pub entity_reused_objects: usize,
    pub entity_built_objects: usize,
    pub identity_reused_objects: usize,
    pub identity_built_objects: usize,
    pub count_rollup_reused_objects: usize,
    pub count_rollup_built_objects: usize,
    pub keyword_reused_objects: usize,
    pub keyword_built_objects: usize,
    pub keyword_retired_objects: usize,
    pub fragment_reused_terms: u64,
    pub fragment_built_terms: u64,
    pub thread_layout: GenerationBuildThreadLayout,
    pub phase_timings_seconds: GenerationBuildPhaseTimings,
    pub build_seconds: f64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBuildThreadLayout {
    pub configured_threads: usize,
    pub entity_threads: usize,
    pub keyword_producer_ceiling: usize,
    pub count_rollup_threads: usize,
    pub derivative_build_memory_bytes: u64,
    pub entity_lane_memory_bytes: u64,
    pub keyword_producer_lane_memory_bytes: u64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationBuildPhaseTimings {
    pub entity: f64,
    pub uid_proof: f64,
    pub keyword: f64,
    pub fragment: f64,
    pub identity: f64,
    pub count_rollup: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct IdentitySnapshotBuildManifest {
    pub schema_version: u64,
    pub tenant_id: String,
    pub event_snapshot_id: i64,
    pub object_stamp_sha256: String,
    pub snapshot_id: String,
    pub window_days: u64,
    pub source_files: usize,
    pub source_rows: u64,
    #[serde(default)]
    pub source_objects: Vec<IdentitySnapshotSourceObject>,
    #[serde(default)]
    pub source_object_identities_sha256: String,
    #[serde(default)]
    pub reused_source_files: usize,
    #[serde(default)]
    pub built_source_files: usize,
    pub rows: u64,
    pub bytes: u64,
    pub min_observed_at_us: Option<i64>,
    pub max_observed_at_us: Option<i64>,
    pub by_ip_sha256: String,
    pub build_seconds: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct IdentitySnapshotSourceObject {
    pub event_object_key: String,
    pub event_object_version: String,
    pub event_object_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct IdentityObservation {
    ip: String,
    observed_at_us: i64,
    hostname_lc: String,
    user_lc: String,
    mac: String,
    source: String,
}

#[derive(Debug, Serialize)]
pub struct SnapshotHydrateResult {
    #[serde(skip)]
    pub received_files: crate::generation_proof::ReceivedFiles,
    pub table: String,
    pub snapshot_id: i64,
    pub metadata_location: String,
    pub objects: usize,
    pub rows: u64,
    pub bytes: u64,
    pub reused_objects: usize,
    pub reused_bytes: u64,
    pub downloaded_objects: usize,
    pub downloaded_bytes: u64,
    pub output_root: PathBuf,
    pub object_stamp_manifest: PathBuf,
}

#[derive(Clone)]
struct PriorHydrationObject {
    path: PathBuf,
    stamp: ObjectStamp,
}

/// Hydrate one exact, immutable Iceberg snapshot into a local candidate root.
///
/// Each S3 object is HEADed to obtain its provider version ID and then read by
/// that exact version. The catalog is reloaded before the candidate is made
/// visible, so advancing the table during hydration fails closed.
pub async fn hydrate_current_snapshot(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    table_id: &iceberg::TableIdent,
    table_location_prefix: &str,
    output_root: &Path,
) -> Result<SnapshotHydrateResult> {
    hydrate_snapshot_inner(
        catalog,
        catalog_config,
        table_id,
        table_location_prefix,
        None,
        output_root,
        None,
        None,
        None,
        false,
    )
    .await
}

/// Hydrate one explicitly selected snapshot even when newer append-only
/// snapshots already exist. Generation promotion uses this to build the
/// newest compaction-fenced ancestor while live Bronze commits continue at the
/// table head.
pub async fn hydrate_snapshot(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    table_id: &iceberg::TableIdent,
    table_location_prefix: &str,
    snapshot_id: i64,
    output_root: &Path,
) -> Result<SnapshotHydrateResult> {
    hydrate_snapshot_reusing(
        catalog,
        catalog_config,
        table_id,
        table_location_prefix,
        snapshot_id,
        output_root,
        None,
    )
    .await
}

/// Hydrate a selected snapshot while reusing exact immutable objects from a
/// prior local generation. Reuse is deliberately an optimization only: a
/// missing, incompatible, or locally corrupted prior object is fetched again
/// by its provider version ID.
pub async fn hydrate_snapshot_reusing(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    table_id: &iceberg::TableIdent,
    table_location_prefix: &str,
    snapshot_id: i64,
    output_root: &Path,
    prior_snapshot_root: Option<&Path>,
) -> Result<SnapshotHydrateResult> {
    if snapshot_id <= 0 {
        bail!("snapshot hydration requires a positive snapshot identity");
    }
    hydrate_snapshot_inner(
        catalog,
        catalog_config,
        table_id,
        table_location_prefix,
        Some(snapshot_id),
        output_root,
        prior_snapshot_root,
        None,
        None,
        false,
    )
    .await
}

/// Hydrate from the publisher's authenticated metadata file while still proving
/// the requested snapshot belongs to the current catalog table and lineage.
pub async fn hydrate_snapshot_from_metadata(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    table_id: &iceberg::TableIdent,
    table_location_prefix: &str,
    snapshot_id: i64,
    metadata_location: &str,
    output_root: &Path,
    prior_snapshot_root: Option<&Path>,
) -> Result<SnapshotHydrateResult> {
    let current = catalog.load_table(table_id).await?;
    let pinned = pinned_snapshot_table(
        &current,
        table_location_prefix,
        snapshot_id,
        metadata_location,
    )
    .await?;
    hydrate_snapshot_inner(
        catalog,
        catalog_config,
        table_id,
        table_location_prefix,
        Some(snapshot_id),
        output_root,
        prior_snapshot_root,
        Some(pinned),
        None,
        false,
    )
    .await
}

/// Hydration with authenticated reuse from the prior admitted generation.
pub async fn hydrate_snapshot_proven(
    catalog: &RestCatalog, config: &CatalogConfig, table_id: &iceberg::TableIdent,
    location: &str, snapshot_id: i64, metadata: Option<&str>, output: &Path,
    prior: Option<&Path>, proof: Option<&crate::generation_proof::Body>,
) -> Result<SnapshotHydrateResult> {
    let pinned = if let Some(metadata) = metadata {
        let current = catalog.load_table(table_id).await?;
        Some(pinned_snapshot_table(&current, location, snapshot_id, metadata).await?)
    } else { None };
    hydrate_snapshot_inner(catalog, config, table_id, location, Some(snapshot_id), output, prior, pinned, proof, true).await
}

/// The same table with iceberg's manifest `ObjectCache` disabled, for a
/// one-pass file plan (NAN-2611).
///
/// iceberg 0.10.1 caches every manifest a scan parses and bounds that cache
/// by `size_of_val` of the `Manifest` struct, a shallow ~100-byte weight that
/// ignores the entries and their per-column statistics. Its 32 MiB default
/// therefore admits every manifest of the snapshot: planning 3,146 wide OCSF
/// data files held ~700 MiB live in the generation publisher, and the
/// allocator kept those pages through the derivative build and the bundle
/// upload. Hydration and the hot-tail reconciliation read each manifest
/// exactly once, so the cache has no hit to lose; without it the plan holds
/// only the manifests in flight.
pub fn uncached_scan_table(table: &iceberg::table::Table) -> Result<iceberg::table::Table> {
    if table.encryption_manager().is_some() {
        bail!("encrypted Iceberg tables are not supported by the generation scan");
    }
    let mut builder = iceberg::table::Table::builder()
        .identifier(table.identifier().clone())
        .metadata(table.metadata_ref())
        .file_io(table.file_io().clone())
        .readonly(true)
        .runtime(iceberg::Runtime::current())
        .disable_cache();
    if let Some(location) = table.metadata_location() {
        builder = builder.metadata_location(location);
    }
    Ok(builder.build()?)
}

pub(crate) async fn pinned_snapshot_table(
    current: &iceberg::table::Table,
    table_location_prefix: &str,
    snapshot_id: i64,
    metadata_location: &str,
) -> Result<iceberg::table::Table> {
    if !metadata_location.starts_with(&format!(
        "{}/metadata/",
        table_location_prefix.trim_end_matches('/')
    )) || !metadata_location.ends_with(".metadata.json")
    {
        bail!("pinned metadata escaped the assigned table");
    }
    let bytes = current
        .file_io()
        .new_input(metadata_location)?
        .read()
        .await?;
    let metadata = decode_pinned_metadata(&bytes, 64 * 1024 * 1024)?;
    validate_pinned_snapshot(
        current.metadata(),
        &metadata,
        snapshot_id,
        table_location_prefix,
    )?;
    let pinned = iceberg::table::Table::builder()
        .identifier(current.identifier().clone())
        .metadata(metadata)
        .metadata_location(metadata_location.to_string())
        .file_io(current.file_io().clone())
        .runtime(iceberg::Runtime::current())
        .build()?;
    Ok(pinned)
}

fn decode_pinned_metadata(bytes: &[u8], max_bytes: usize) -> Result<iceberg::spec::TableMetadata> {
    if bytes.len() > max_bytes {
        bail!("pinned metadata exceeds its byte bound");
    }
    if bytes.starts_with(&[0x1f, 0x8b]) {
        let mut decoded = Vec::new();
        flate2::read::GzDecoder::new(bytes)
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut decoded)
            .context("decompress pinned Iceberg metadata")?;
        if decoded.len() > max_bytes {
            bail!("pinned metadata exceeds its decoded byte bound");
        }
        Ok(serde_json::from_slice(&decoded)?)
    } else {
        Ok(serde_json::from_slice(bytes)?)
    }
}

fn validate_pinned_snapshot(
    current: &iceberg::spec::TableMetadata,
    pinned: &iceberg::spec::TableMetadata,
    snapshot_id: i64,
    table_location: &str,
) -> Result<()> {
    if snapshot_id <= 0
        || current.uuid() != pinned.uuid()
        || pinned.location().trim_end_matches('/') != table_location.trim_end_matches('/')
    {
        bail!("pinned metadata changed the assigned table identity");
    }
    let snapshot = pinned
        .snapshot_by_id(snapshot_id)
        .context("pinned metadata does not name the requested snapshot")?;
    let live = current
        .snapshot_by_id(snapshot_id)
        .context("pinned snapshot is absent from current metadata")?;
    if snapshot.manifest_list() != live.manifest_list()
        || snapshot.schema(pinned)? != live.schema(current)?
    {
        bail!("pinned metadata changed the requested snapshot identity");
    }
    Ok(())
}

async fn hydrate_snapshot_inner(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    table_id: &iceberg::TableIdent,
    table_location_prefix: &str,
    requested_snapshot_id: Option<i64>,
    output_root: &Path,
    prior_snapshot_root: Option<&Path>,
    pinned_table: Option<iceberg::table::Table>,
    proven_reuse: Option<&crate::generation_proof::Body>,
    require_authenticated_reuse: bool,
) -> Result<SnapshotHydrateResult> {
    if output_root.exists() {
        bail!(
            "snapshot hydration output already exists: {}",
            output_root.display()
        );
    }
    let parent = output_root
        .parent()
        .context("snapshot hydration output has no parent")?;
    std::fs::create_dir_all(parent)?;
    let table = match pinned_table {
        Some(table) => table,
        None => catalog
            .load_table(table_id)
            .await
            .context("load Iceberg table for snapshot hydration")?,
    };
    let metadata_location = table
        .metadata_location_result()
        .context("Iceberg table lacks a metadata location")?
        .to_string();
    let current_snapshot_id = table
        .metadata()
        .current_snapshot_id()
        .context("Iceberg table has no current snapshot")?;
    let snapshot_id = requested_snapshot_id.unwrap_or(current_snapshot_id);
    if table.metadata().snapshot_by_id(snapshot_id).is_none() {
        bail!("requested Iceberg snapshot is not present in table metadata");
    }
    let prefix = table_location_prefix.trim_end_matches('/');
    let metadata_prefix = format!("{prefix}/metadata/");
    let data_prefix = format!("{prefix}/data/");
    if !prefix.starts_with("s3://")
        || !metadata_location.starts_with(&metadata_prefix)
        || !metadata_location.ends_with(".metadata.json")
    {
        bail!("Iceberg table metadata is outside the assigned S3 table prefix");
    }

    // Keep only the bounded in-flight scan tasks, not the entire scan plan,
    // and not every parsed manifest either (NAN-2611).
    let scan_table = uncached_scan_table(&table)?;
    let tasks = scan_table.scan().snapshot_id(snapshot_id).build()?.plan_files().await?;

    let (assigned_bucket, _) = parse_s3_uri(prefix)?;
    let storage = s3_operator(catalog_config, assigned_bucket)?;
    let candidate = tempfile::Builder::new()
        .prefix(".lake-snapshot-")
        .tempdir_in(parent)?;
    let data_root = candidate.path().join("data");
    std::fs::create_dir(&data_root)?;
    let prior_objects =
        load_prior_hydration_objects(prior_snapshot_root, &table_id.to_string(), &data_prefix);
    let mut prior_verification =
        load_prior_local_verification(prior_snapshot_root, &table_id.to_string());
    if let Some(proof) = proven_reuse {
        for prior in prior_objects.values() {
            if proof.file_digest(&prior.path) == Some(prior.stamp.sha256.as_str()) {
                let m = std::fs::metadata(&prior.path)?;
                prior_verification.insert(prior.stamp.relative_path.clone(), LocalVerificationStamp {
                    sha256: prior.stamp.sha256.clone(), size_bytes: m.len(), dev: m.dev(), inode: m.ino(),
                    mtime_seconds: m.mtime(), mtime_nanoseconds: m.mtime_nsec(),
                });
            }
        }
    }

    let mut objects = Vec::new();
    let mut verification_objects = BTreeMap::new();
    let mut rows = 0_u64;
    let mut bytes = 0_u64;
    let mut reused_objects = 0_usize;
    let mut reused_bytes = 0_u64;
    let mut reverified_objects = 0_usize;
    let mut downloaded_objects = 0_usize;
    let mut downloaded_bytes = 0_u64;
    let mut seen = BTreeSet::new();
    let append_only_r2 = crate::shared_mode::active();
    let mut placements = tasks.map(|task| {
            let task = task.map_err(anyhow::Error::from).and_then(|task| {
                if task.data_file_format != DataFileFormat::Parquet
                    || !task.deletes.is_empty()
                    || task.start != 0
                    || task.length != task.file_size_in_bytes
                    || task.record_count.is_none()
                    || !task.data_file_path.starts_with(data_prefix.as_str())
                {
                    bail!("Iceberg scan contains a partial, deleted, non-Parquet, or unbounded task");
                }
                let relative_path = task
                    .data_file_path
                    .strip_prefix(data_prefix.as_str())
                    .context("Iceberg data object is outside the assigned table")?;
                validate_relative_path(relative_path)?;
                if !seen.insert(relative_path.to_string()) { bail!("Iceberg snapshot contains a duplicate data object"); }
                Ok(task)
            });
            let storage = storage.clone();
            let prior_objects = &prior_objects;
            let prior_verification = &prior_verification;
            let data_root = &data_root;
            let data_prefix = &data_prefix;
            async move {
                let task = task?;
                let relative_path = task.data_file_path.strip_prefix(data_prefix.as_str())
                    .context("Iceberg data object is outside the assigned table")?;
                let (bucket, key) = parse_s3_uri(&task.data_file_path)?;
                if bucket != assigned_bucket {
                    bail!("Iceberg snapshot crosses the assigned S3 bucket boundary");
                }
                let destination = data_root.join(relative_path);
                if let Some(parent) = destination.parent() { std::fs::create_dir_all(parent)?; }
                let proven = prior_objects.get(&task.data_file_path).is_some_and(|prior|
                    proven_reuse.and_then(|proof| proof.file_digest(&prior.path)) == Some(prior.stamp.sha256.as_str()));
                let identity = if append_only_r2 && (!require_authenticated_reuse || proven) && reuse_verified_r2_object(
                    prior_objects.get(&task.data_file_path), prior_verification.get(relative_path),
                    task.file_size_in_bytes, relative_path, snapshot_id, &destination,
                ) { None } else {
                    Some(storage.stat(key).await.with_context(|| format!("HEAD exact Iceberg object {}", task.data_file_path))?)
                };
                let source_uri = task.data_file_path;
                let relative_path = source_uri
                    .strip_prefix(data_prefix)
                    .context("Iceberg data object is outside the assigned table")?
                    .to_string();
                let (_, key) = parse_s3_uri(&source_uri)?;
                let key = key.to_string();
                let identity = match identity {
                    Some(identity) => identity,
                    None => {
                        let prior = &prior_objects[&source_uri];
                        let placed = std::fs::metadata(data_root.join(&relative_path))?;
                        let verification = LocalVerificationStamp {
                            sha256: prior.stamp.sha256.clone(), size_bytes: placed.len(),
                            dev: placed.dev(), inode: placed.ino(),
                            mtime_seconds: placed.mtime(), mtime_nanoseconds: placed.mtime_nsec(),
                        };
                        return Ok((prior.stamp.clone(), task.record_count.expect("validated row count"), true, false, verification));
                    }
                };
                let (version_id, object_etag) = if append_only_r2 {
                    let (version_id, etag) =
                        crate::object_identity::metadata_provider_identity(&identity)?;
                    (version_id, Some(etag))
                } else {
                    (
                        identity
                            .version()
                            .filter(|value| !value.is_empty() && *value != "null")
                            .context("versioned S3 object identity is required")?
                            .to_string(),
                        None,
                    )
                };
                if identity.content_length() != task.file_size_in_bytes {
                    bail!("Iceberg manifest size differs from the current object version");
                }
                let destination = data_root.join(&relative_path);
                if let Some(directory) = destination.parent() {
                    std::fs::create_dir_all(directory)?;
                }
                let proof_trusted = prior_objects.get(&source_uri).is_some_and(|prior|
                    proven_reuse.and_then(|proof| proof.file_digest(&prior.path)) == Some(prior.stamp.sha256.as_str()));
                let force_full_verify = if require_authenticated_reuse { !proof_trusted } else { sample_reverify(snapshot_id, &relative_path) };
                let reverified = force_full_verify && prior_objects.contains_key(&source_uri);
                let reused = reuse_matching_prior_object(
                    prior_objects.get(&source_uri),
                    &version_id,
                    task.file_size_in_bytes,
                    &relative_path,
                    &destination,
                    prior_verification.get(&relative_path),
                    force_full_verify,
                );
                let (digest, object_bytes) = if reused {
                    (
                        prior_objects
                            .get(&source_uri)
                            .expect("reused prior object disappeared")
                            .stamp
                            .sha256
                            .clone(),
                        task.file_size_in_bytes,
                    )
                } else {
                    let mut file = std::fs::OpenOptions::new().write(true).create_new(true).open(&destination)?;
                    let digest = if let Some(etag) = object_etag.as_deref() {
                        crate::object_identity::read_exact_stream(
                            &storage, &key, task.file_size_in_bytes, None, Some(etag),
                            |chunk| std::future::ready(file.write_all(&chunk).map_err(anyhow::Error::from)),
                        ).await.with_context(|| format!("stream exact append-only R2 Iceberg object {source_uri}"))?.sha256
                    } else {
                        use opendal::raw::{oio::Read as _, Access, OpRead};
                        let (_, mut reader) = storage.inner().read(
                            &opendal::raw::normalize_path(&key), OpRead::default().with_version(&version_id),
                        ).await.with_context(|| format!("stream exact Iceberg object version {source_uri}"))?;
                        let mut hash = Sha256::new();
                        let mut received = 0_u64;
                        loop {
                            let buffer = reader.read().await?;
                            if buffer.is_empty() { break; }
                            for chunk in buffer {
                                received = received.checked_add(chunk.len() as u64).context("snapshot response length overflow")?;
                                if received > task.file_size_in_bytes { bail!("snapshot response exceeds manifest length"); }
                                hash.update(&chunk);
                                file.write_all(&chunk)?;
                            }
                        }
                        if received != task.file_size_in_bytes { bail!("hydrated Iceberg object size differs from its manifest"); }
                        hex::encode(hash.finalize())
                    };
                    file.sync_all()?;
                    (digest, task.file_size_in_bytes)
                };
                // Record the identity of the exact local bytes just proven so
                // the next generation can corroborate reuse with a stat.
                let placed = std::fs::metadata(&destination)?;
                let verification = LocalVerificationStamp {
                    sha256: digest.clone(),
                    size_bytes: object_bytes,
                    dev: placed.dev(),
                    inode: placed.ino(),
                    mtime_seconds: placed.mtime(),
                    mtime_nanoseconds: placed.mtime_nsec(),
                };
                Ok::<_, anyhow::Error>((
                    ObjectStamp {
                        relative_path,
                        source_uri,
                        version_id,
                        size_bytes: object_bytes,
                        sha256: digest,
                    },
                    task.record_count.expect("validated Iceberg row count"),
                    reused,
                    reverified,
                    verification,
                ))
            }
        })
        .buffered(HYDRATION_READ_CONCURRENCY);
    let mut received_paths = BTreeSet::new();
    while let Some((stamp, object_rows, reused, reverified, verification)) = placements.try_next().await? {
        if !reused || reverified || require_authenticated_reuse { received_paths.insert(stamp.relative_path.clone()); }
        if reused {
            reused_objects += 1;
            reused_bytes = reused_bytes
                .checked_add(stamp.size_bytes)
                .context("reused snapshot byte count overflow")?;
        } else {
            downloaded_objects += 1;
            downloaded_bytes = downloaded_bytes
                .checked_add(stamp.size_bytes)
                .context("downloaded snapshot byte count overflow")?;
        }
        if reverified {
            reverified_objects += 1;
        }
        rows = rows
            .checked_add(object_rows)
            .context("snapshot row count overflow")?;
        bytes = bytes
            .checked_add(stamp.size_bytes)
            .context("snapshot byte count overflow")?;
        verification_objects.insert(stamp.relative_path.clone(), verification);
        objects.push(stamp);
    }

    drop(placements);
    if objects.is_empty() { bail!("Iceberg snapshot has no data files"); }
    objects.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));

    let current = catalog.load_table(table_id).await?;
    if current.metadata().uuid() != table.metadata().uuid()
        || current
            .metadata()
            .snapshot_by_id(snapshot_id)
            .map(|s| s.manifest_list())
            != table
                .metadata()
                .snapshot_by_id(snapshot_id)
                .map(|s| s.manifest_list())
    {
        bail!("hydrated snapshot changed its table or manifest-list identity");
    }
    if requested_snapshot_id.is_none() {
        if current.metadata_location() != Some(metadata_location.as_str())
            || current.metadata().current_snapshot_id() != Some(snapshot_id)
        {
            bail!("Iceberg advanced while its snapshot was being hydrated");
        }
    } else {
        let mut ancestor = current.metadata().current_snapshot_id();
        let mut found = false;
        let mut depth = 0_usize;
        while let Some(candidate) = ancestor {
            if candidate == snapshot_id {
                found = true;
                break;
            }
            if depth >= 100_000 {
                bail!("Iceberg snapshot ancestry exceeds the safety bound");
            }
            ancestor = current
                .metadata()
                .snapshot_by_id(candidate)
                .context("Iceberg snapshot ancestry is incomplete")?
                .parent_snapshot_id();
            depth += 1;
        }
        if !found {
            bail!("requested Iceberg snapshot left the current table lineage");
        }
    }
    let table_name = table_id.to_string();
    let manifest = ObjectStampManifest {
        metadata_location: metadata_location.clone(),
        snapshot_id,
        table: table_name.clone(),
        objects,
        table_uuid: None,
    };
    write_json(&candidate.path().join("object-stamps.json"), &manifest)?;
    write_json(
        &candidate.path().join(LOCAL_VERIFICATION_FILE),
        &LocalVerificationLedger {
            schema_version: LOCAL_VERIFICATION_SCHEMA_VERSION,
            table: table_name.clone(),
            objects: verification_objects,
        },
    )?;
    sync_tree(candidate.path())?;
    let candidate_path = candidate.keep();
    std::fs::rename(&candidate_path, output_root)?;
    File::open(parent)?.sync_all()?;
    if reverified_objects > 0 {
        tracing::info!(
            snapshot_id,
            reverified_objects,
            "sampled full re-verification of reusable snapshot objects completed"
        );
    }
    let mut received_files = crate::generation_proof::ReceivedFiles::default();
    for object in manifest.objects.iter().filter(|object| received_paths.contains(&object.relative_path)) {
        received_files.record(output_root.join("data").join(&object.relative_path), object.sha256.clone())?;
    }
    Ok(SnapshotHydrateResult {
        received_files,
        table: table_name,
        snapshot_id,
        metadata_location,
        objects: manifest.objects.len(),
        rows,
        bytes,
        reused_objects,
        reused_bytes,
        downloaded_objects,
        downloaded_bytes,
        output_root: output_root.to_path_buf(),
        object_stamp_manifest: output_root.join("object-stamps.json"),
    })
}

fn load_prior_hydration_objects(
    prior_snapshot_root: Option<&Path>,
    table: &str,
    data_prefix: &str,
) -> BTreeMap<String, PriorHydrationObject> {
    let Some(root) = prior_snapshot_root else {
        return BTreeMap::new();
    };
    let loaded = (|| -> Result<BTreeMap<String, PriorHydrationObject>> {
        let manifest: ObjectStampManifest =
            serde_json::from_slice(&std::fs::read(root.join("object-stamps.json"))?)?;
        if manifest.table != table || manifest.snapshot_id <= 0 || manifest.objects.is_empty() {
            bail!("prior snapshot identity is incompatible");
        }
        let mut objects = BTreeMap::new();
        for stamp in manifest.objects {
            validate_relative_path(&stamp.relative_path)?;
            if !stamp.source_uri.starts_with(data_prefix)
                || stamp.version_id.is_empty()
                || stamp.size_bytes == 0
                || stamp.sha256.len() != 64
                || !stamp.sha256.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                bail!("prior snapshot contains an invalid immutable object stamp");
            }
            let source_uri = stamp.source_uri.clone();
            let object = PriorHydrationObject {
                path: root.join("data").join(&stamp.relative_path),
                stamp,
            };
            if objects.insert(source_uri, object).is_some() {
                bail!("prior snapshot contains duplicate object identities");
            }
        }
        Ok(objects)
    })();
    match loaded {
        Ok(objects) => objects,
        Err(error) => {
            tracing::warn!(
                prior_snapshot_root = %root.display(),
                error = %error,
                "prior hydrated snapshot is incompatible; exact objects will be downloaded again"
            );
            BTreeMap::new()
        }
    }
}

/// Per-object trust record proving one local file's bytes were hashed once.
///
/// NAN-2361 integrity trade: the sha256 was PROVEN when the file was written
/// (download) or last fully verified; later promotions only corroborate that
/// the same inode is unchanged (device, inode, size, exact mtime). What is
/// still proven each promotion: the S3 object identity (versioned HEAD) and
/// the local size. What is now assumed: a file whose inode, size, and mtime
/// are unchanged still holds the hashed bytes. Violating that assumption
/// requires either silent in-place corruption that preserves mtime (bit-rot
/// through the page cache, or a local actor deliberately resetting
/// timestamps — local disk is inside the trust boundary) — and the sampled
/// full re-hash still detects it in an expected REVERIFY_SAMPLE_DENOMINATOR
/// promotions. Any mismatch falls back to the full hash, then to re-download.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalVerificationStamp {
    pub sha256: String,
    pub size_bytes: u64,
    pub dev: u64,
    pub inode: u64,
    pub mtime_seconds: i64,
    pub mtime_nanoseconds: i64,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LocalVerificationLedger {
    schema_version: u64,
    table: String,
    /// Keyed by the object's snapshot-relative path.
    objects: BTreeMap<String, LocalVerificationStamp>,
}

/// Load the hydration verification ledger for a snapshot root, for readers
/// outside this module.
///
/// NAN-2361: `load_snapshot_cache` (config.rs) re-hashed EVERY object in the
/// table on EVERY generation activation. That is a second, independent
/// O(table) wall which the hydration-side O(delta) work did NOT remove -- it
/// only moved the cost from the hydrator to the config loader, so a promotion
/// still read the whole table once per cycle. This exposes the same
/// stat-corroborated ledger the hydrator already writes so the loader can
/// trust an unchanged inode instead, under the same sampled re-hash backstop.
///
/// Returns an empty map on any absence or incompatibility, which makes the
/// caller fall back to full hashing -- the pre-NAN-2361 behaviour.
pub fn local_verification_ledger(
    snapshot_root: &Path,
    table: &str,
) -> BTreeMap<String, LocalVerificationStamp> {
    load_prior_local_verification(Some(snapshot_root), table)
}

/// Whether a locally cached object may be trusted from its recorded stamp
/// instead of a full re-hash.
///
/// The stamp MUST agree with the authoritative digest (from the object-stamp
/// manifest). The ledger lives on the same disk as the artifacts it vouches
/// for, so it can never be the source of truth: without this equality a forged
/// ledger would grant trust to arbitrary bytes. With it, a forger would have
/// to claim the true digest while the bytes differ -- exactly the case the
/// sampled full re-hash exists to catch.
pub fn local_object_is_stamp_trusted(
    stamp: &LocalVerificationStamp,
    authoritative_sha256: &str,
    metadata: &std::fs::Metadata,
) -> bool {
    use std::os::unix::fs::MetadataExt;
    stamp.sha256 == authoritative_sha256
        && stamp.size_bytes == metadata.len()
        && stamp.dev == metadata.dev()
        && stamp.inode == metadata.ino()
        && stamp.mtime_seconds == metadata.mtime()
        && stamp.mtime_nanoseconds == metadata.mtime_nsec()
}

/// Deterministic per-load sample: the same 1-in-N discipline hydration uses.
pub fn snapshot_cache_sample_reverify(snapshot_id: i64, relative_path: &str) -> bool {
    sample_reverify(snapshot_id, relative_path)
}

fn load_prior_local_verification(
    prior_snapshot_root: Option<&Path>,
    table: &str,
) -> BTreeMap<String, LocalVerificationStamp> {
    let Some(root) = prior_snapshot_root else {
        return BTreeMap::new();
    };
    let loaded = (|| -> Result<BTreeMap<String, LocalVerificationStamp>> {
        let ledger: LocalVerificationLedger =
            serde_json::from_slice(&std::fs::read(root.join(LOCAL_VERIFICATION_FILE))?)?;
        if ledger.schema_version != LOCAL_VERIFICATION_SCHEMA_VERSION || ledger.table != table {
            bail!("prior local verification ledger is incompatible");
        }
        Ok(ledger.objects)
    })();
    match loaded {
        Ok(objects) => objects,
        Err(error) => {
            // Absence is the normal first run after upgrade; reuse then pays
            // one full re-hash per object and records fresh stamps.
            tracing::info!(
                prior_snapshot_root = %root.display(),
                error = %error,
                "prior local verification ledger unavailable; reusable objects will be fully re-hashed once"
            );
            BTreeMap::new()
        }
    }
}

/// Deterministic per-promotion sample: selects ~1/REVERIFY_SAMPLE_DENOMINATOR
/// of names for a full re-hash. Seeded by the promotion's snapshot identity so
/// consecutive promotions sample different objects, giving every object an
/// expected full re-verification within REVERIFY_SAMPLE_DENOMINATOR
/// promotions (NAN-2361 bit-rot bound).
fn sample_reverify(snapshot_id: i64, name: &str) -> bool {
    let digest = Sha256::digest(format!("nan2361-reverify:{snapshot_id}:{name}").as_bytes());
    let mut prefix = [0_u8; 8];
    prefix.copy_from_slice(&digest[..8]);
    u64::from_be_bytes(prefix) % REVERIFY_SAMPLE_DENOMINATOR == 0
}

/// A failed local check/link falls back to normal remote identity admission.
fn reuse_verified_r2_object(
    prior: Option<&PriorHydrationObject>, verification: Option<&LocalVerificationStamp>,
    size: u64, relative: &str, snapshot_id: i64, destination: &Path,
) -> bool {
    let (Some(prior), Some(verification)) = (prior, verification) else { return false; };
    if sample_reverify(snapshot_id, relative)
        || prior.stamp.size_bytes != size || prior.stamp.relative_path != relative
        || !prior.stamp.version_id.strip_prefix("r2-etag-sha256:")
            .is_some_and(|digest| digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
    { return false; }
    let Ok(metadata) = std::fs::symlink_metadata(&prior.path) else { return false; };
    metadata.is_file() && local_object_is_stamp_trusted(verification, &prior.stamp.sha256, &metadata)
        && reuse_exact_local_object(prior, destination, Some(verification), false)
}

/// Link the prior generation's copy of this exact object version into the
/// new snapshot, when the prior holds it (same provider version, size and
/// path) and its bytes still verify.
fn reuse_matching_prior_object(
    prior: Option<&PriorHydrationObject>,
    version_id: &str,
    size_bytes: u64,
    relative_path: &str,
    destination: &Path,
    verification: Option<&LocalVerificationStamp>,
    force_full_verify: bool,
) -> bool {
    prior
        .filter(|prior| {
            prior.stamp.version_id == version_id
                && prior.stamp.size_bytes == size_bytes
                && prior.stamp.relative_path == relative_path
        })
        .is_some_and(|prior| reuse_exact_local_object(prior, destination, verification, force_full_verify))
}

fn reuse_exact_local_object(
    prior: &PriorHydrationObject,
    destination: &Path,
    verification: Option<&LocalVerificationStamp>,
    force_full_verify: bool,
) -> bool {
    let Ok(metadata) = std::fs::metadata(&prior.path) else {
        return false;
    };
    if !metadata.is_file() || metadata.len() != prior.stamp.size_bytes {
        return false;
    }
    // NAN-2361: trust an unchanged, previously hashed inode instead of
    // re-hashing the full table every promotion (see LocalVerificationStamp
    // for the exact integrity trade). The stamp must agree with the immutable
    // ObjectStamp digest itself, so a stale or foreign ledger entry can never
    // widen trust beyond what hydration already proved.
    let trusted = !force_full_verify
        && verification.is_some_and(|stamp| {
            stamp.sha256 == prior.stamp.sha256
                && stamp.size_bytes == prior.stamp.size_bytes
                && stamp.dev == metadata.dev()
                && stamp.inode == metadata.ino()
                && stamp.mtime_seconds == metadata.mtime()
                && stamp.mtime_nanoseconds == metadata.mtime_nsec()
        });
    if !trusted && !file_sha256(&prior.path).is_ok_and(|digest| digest == prior.stamp.sha256) {
        return false;
    }
    std::fs::hard_link(&prior.path, destination).is_ok()
}

/// Describe only the immutable objects committed after a fully indexed base
/// generation. The current snapshot must be an append-only descendant: if a
/// base object disappeared, serving base plus tail would resurrect deleted
/// data and therefore fails closed until a new complete generation activates.
pub async fn build_hot_tail_manifest(
    catalog: &RestCatalog,
    catalog_config: &CatalogConfig,
    table_id: &iceberg::TableIdent,
    table_location_prefix: &str,
    tenant_id: &str,
    base: &ObjectStampManifest,
    max_objects: usize,
    max_bytes: u64,
) -> Result<HotTailManifest> {
    if tenant_id.is_empty()
        || tenant_id.len() > 256
        || tenant_id.chars().any(char::is_control)
        || base.snapshot_id <= 0
        || base.table != table_id.to_string()
        || max_objects == 0
        || max_objects > HOT_TAIL_OBJECT_FORMAT_CEILING as usize
        || max_bytes == 0
        || max_bytes > HOT_TAIL_SERVING_CEILING_BYTES
    {
        bail!("hot-tail assignment or safety bound is invalid");
    }
    let prefix = table_location_prefix.trim_end_matches('/');
    let metadata_prefix = format!("{prefix}/metadata/");
    let data_prefix = format!("{prefix}/data/");
    if !prefix.starts_with("s3://")
        || !base.metadata_location.starts_with(&metadata_prefix)
        || base.objects.is_empty()
    {
        bail!("hot-tail base generation is outside the assigned Iceberg table");
    }

    let table = catalog
        .load_table(table_id)
        .await
        .context("load Iceberg table for hot-tail reconciliation")?;
    let head_snapshot_id = table
        .metadata()
        .current_snapshot_id()
        .context("Iceberg table has no current snapshot")?;
    let head_metadata_location = table
        .metadata_location_result()
        .context("Iceberg table has no metadata location")?
        .to_string();
    if head_snapshot_id <= 0 || !head_metadata_location.starts_with(&metadata_prefix) {
        bail!("hot-tail head is outside the assigned Iceberg table");
    }
    let mut ancestor = Some(head_snapshot_id);
    let mut base_is_ancestor = false;
    while let Some(snapshot_id) = ancestor {
        if snapshot_id == base.snapshot_id {
            base_is_ancestor = true;
            break;
        }
        ancestor = table
            .metadata()
            .snapshot_by_id(snapshot_id)
            .context("Iceberg snapshot ancestry is incomplete")?
            .parent_snapshot_id();
    }
    if !base_is_ancestor {
        bail!("active serving generation is not an ancestor of the Iceberg head");
    }

    let mut tasks = uncached_scan_table(&table)?
        .scan()
        .build()?
        .plan_files()
        .await?
        .try_collect::<Vec<_>>()
        .await?;
    tasks.sort_by(|left, right| left.data_file_path.cmp(&right.data_file_path));
    if tasks.is_empty() || tasks.len() > 100_000 {
        bail!("Iceberg hot-tail scan has an invalid data-file count");
    }
    let base_paths = base
        .objects
        .iter()
        .map(|object| object.source_uri.as_str())
        .collect::<BTreeSet<_>>();
    if base_paths.len() != base.objects.len() {
        bail!("hot-tail base generation contains duplicate objects");
    }
    let current_paths = tasks
        .iter()
        .map(|task| task.data_file_path.as_str())
        .collect::<BTreeSet<_>>();
    if !base_paths.is_subset(&current_paths) {
        bail!("Iceberg head removed a base object; a complete generation is required");
    }
    if tasks.iter().any(|task| !task.deletes.is_empty()) {
        bail!("Iceberg head contains row-level deletes; a complete generation is required");
    }

    let tail_tasks = tasks
        .into_iter()
        .filter(|task| !base_paths.contains(task.data_file_path.as_str()))
        .collect::<Vec<_>>();
    if tail_tasks.len() > max_objects {
        bail!(
            "hot-tail object count exceeds its serving bound: hot-tail objects {} > bound {}",
            tail_tasks.len(),
            max_objects
        );
    }
    let (assigned_bucket, _) = parse_s3_uri(prefix)?;
    let storage = s3_operator(catalog_config, assigned_bucket)?;
    let mut objects = Vec::with_capacity(tail_tasks.len());
    let mut bytes = 0_u64;
    for task in tail_tasks {
        if task.data_file_format != DataFileFormat::Parquet
            || !task.deletes.is_empty()
            || task.start != 0
            || task.length != task.file_size_in_bytes
            || task.record_count.is_none()
            || !task.data_file_path.starts_with(&data_prefix)
        {
            bail!("Iceberg hot tail contains a partial, deleted, or invalid data task");
        }
        bytes = bytes
            .checked_add(task.file_size_in_bytes)
            .context("hot-tail byte count overflow")?;
        if bytes > max_bytes {
            bail!(
                "hot-tail bytes exceed the serving bound: hot-tail bytes {bytes} > bound {max_bytes}"
            );
        }
        let (bucket, key) = parse_s3_uri(&task.data_file_path)?;
        if bucket != assigned_bucket {
            bail!("Iceberg hot tail crosses the assigned bucket boundary");
        }
        let identity = storage
            .stat(key)
            .await
            .with_context(|| format!("HEAD hot-tail object {}", task.data_file_path))?;
        let version_id = identity
            .version()
            .filter(|value| !value.is_empty() && *value != "null")
            .context("versioned hot-tail object identity is required")?
            .to_string();
        if identity.content_length() != task.file_size_in_bytes {
            bail!("hot-tail object size differs from its Iceberg manifest");
        }
        objects.push(HotTailObject {
            source_uri: task.data_file_path,
            version_id,
            etag: None,
            size_bytes: identity.content_length(),
            rows: task.record_count.unwrap(),
            sha256: None,
            min_time_ms: None,
            max_time_ms: None,
            // Schema v1 predates the tier split and keeps the legacy
            // envelope semantics; its objects never carry the marker.
            committed: false,
        });
    }

    let current = catalog.load_table(table_id).await?;
    if current.metadata_location() != Some(head_metadata_location.as_str())
        || current.metadata().current_snapshot_id() != Some(head_snapshot_id)
    {
        bail!("Iceberg advanced while the hot tail was being fenced");
    }
    let iceberg_metadata_file_path = head_metadata_location
        .strip_prefix(&format!("{prefix}/"))
        .context("hot-tail metadata is outside the assigned table")?
        .to_string();
    validate_relative_path(&iceberg_metadata_file_path)?;
    Ok(HotTailManifest {
        schema_version: 1,
        tenant_id: tenant_id.to_string(),
        table: table_id.to_string(),
        base_snapshot_id: base.snapshot_id,
        head_snapshot_id,
        tail_id: None,
        head_metadata_location,
        iceberg_metadata_file_path,
        read_schema: None,
        available_paths: Vec::new(),
        objects,
        local_paths: Vec::new(),
    })
}

/// Bind exact-version Parquet objects that have passed strict admission but
/// have not yet moved behind the active Iceberg generation. Unlike schema v1,
/// these objects are absent from the active indexed base. They may be
/// out-of-catalog ingest files or catalog-committed product-event files from a
/// newer snapshot. Their signed content digest is the advancing serving
/// identity while the indexed Iceberg base remains fixed.
pub fn build_staged_hot_tail_manifest(
    table_location_prefix: &str,
    tenant_id: &str,
    base: &ObjectStampManifest,
    tail_id: &str,
    objects: Vec<HotTailObject>,
    max_objects: usize,
    max_bytes: u64,
    max_committed_objects: usize,
) -> Result<HotTailManifest> {
    // NAN-2361 two-tier hot tail: `max_objects`/`max_bytes` are the STAGED
    // (Tier A) envelope; `max_committed_objects` bounds the committed
    // (Tier B) tier by count only. `max_committed_objects == 0` disables the
    // committed tier entirely — every object must then be staged-tier and the
    // manifest keeps its legacy schema_version 2 shape byte-for-byte.
    let staged_count = objects.iter().filter(|object| !object.committed).count();
    let committed_count = objects.len() - staged_count;
    if tenant_id.is_empty()
        || tenant_id.len() > 256
        || tenant_id.chars().any(char::is_control)
        || !(base.snapshot_id > 0 || crate::bootstrap_generation::is_bootstrap_stamps(base))
        || base.table.is_empty()
        || !valid_sha256(tail_id)
        || objects.is_empty()
    {
        bail!("staged hot-tail assignment is invalid");
    }
    if max_objects == 0
        || max_objects > HOT_TAIL_OBJECT_FORMAT_CEILING as usize
        || max_committed_objects > HOT_TAIL_OBJECT_FORMAT_CEILING as usize
        || max_objects.saturating_add(max_committed_objects)
            > HOT_TAIL_OBJECT_FORMAT_CEILING as usize
        || max_bytes == 0
        || max_bytes > HOT_TAIL_SERVING_CEILING_BYTES
    {
        bail!("staged hot-tail safety bound is invalid");
    }
    if staged_count > max_objects {
        bail!(
            "staged hot-tail objects exceed the serving bound: \
             staged objects {staged_count} > bound {max_objects}"
        );
    }
    if committed_count > max_committed_objects {
        // A committed tier past its count bound must refuse loudly rather
        // than truncate: dropping a committed-but-unindexed object from the
        // manifest would make already-acknowledged events invisible to every
        // query until the next activation. The signer's failure classifier
        // keys on "exceed the serving bound" to report this as
        // alive-but-refusing rather than dead.
        bail!(
            "committed hot-tail objects exceed the serving bound: \
             committed objects {committed_count} > bound {max_committed_objects}"
        );
    }
    let prefix = table_location_prefix.trim_end_matches('/');
    let metadata_prefix = format!("{prefix}/metadata/");
    let data_prefix = format!("{prefix}/data/");
    let tenant_tail_prefix = format!(
        "{prefix}/data/tail/tenant_sha256={}/",
        hex::encode(Sha256::digest(tenant_id.as_bytes()))
    );
    if !prefix.starts_with("s3://") || !base.metadata_location.starts_with(&metadata_prefix) {
        bail!("staged hot-tail base is outside the assigned Iceberg table");
    }
    let mut bytes = 0_u64;
    let mut paths = BTreeSet::new();
    for object in &objects {
        let staged_tail = object
            .source_uri
            .starts_with(&format!("{prefix}/data/tail/"));
        if !object.source_uri.starts_with(&data_prefix)
            || (staged_tail && !object.source_uri.starts_with(&tenant_tail_prefix))
            || !object.source_uri.ends_with(".parquet")
            || object.version_id.is_empty()
            || object.version_id == "unversioned"
            || object.size_bytes == 0
            || object.rows == 0
            || match (object.min_time_ms, object.max_time_ms) {
                (Some(minimum), Some(maximum)) => minimum <= 0 || maximum < minimum,
                // A committed-tier object is exempt from the byte envelope,
                // so its per-object time bounds are the only thing keeping a
                // time-scoped query from paying for it. They are mandatory.
                (None, None) => object.committed,
                _ => true,
            }
            || !paths.insert(object.source_uri.as_str())
        {
            bail!("staged hot-tail object is outside its assigned tenant prefix");
        }
        // Only the staged tier counts against the signed byte envelope. The
        // committed tier is already durable in Iceberg and is charged per
        // query by the planner's Reject-enforced scan budget instead.
        if !object.committed {
            bytes = bytes
                .checked_add(object.size_bytes)
                .context("staged hot-tail byte count overflow")?;
        }
    }
    if bytes > max_bytes {
        bail!(
            "staged hot-tail bytes exceed the serving bound: \
             staged bytes {bytes} > bound {max_bytes}"
        );
    }
    let iceberg_metadata_file_path = base
        .metadata_location
        .strip_prefix(&format!("{prefix}/"))
        .context("staged hot-tail metadata is outside the assigned table")?
        .to_string();
    validate_relative_path(&iceberg_metadata_file_path)?;
    let manifest = HotTailManifest {
        // schema_version 3 exists ONLY to mark the presence of a committed
        // tier; a tiered publisher whose reconcile finds no committed object
        // still emits the byte-identical legacy schema so a not-yet-upgraded
        // (deny_unknown_fields) reader keeps working through a rolling deploy.
        schema_version: if objects.iter().all(|object| object.sha256.is_some()) {
            4
        } else if committed_count > 0 {
            3
        } else {
            2
        },
        tenant_id: tenant_id.to_string(),
        table: base.table.clone(),
        base_snapshot_id: base.snapshot_id,
        head_snapshot_id: base.snapshot_id,
        tail_id: Some(tail_id.to_string()),
        head_metadata_location: base.metadata_location.clone(),
        iceberg_metadata_file_path,
        read_schema: None,
        available_paths: Vec::new(),
        objects,
        local_paths: Vec::new(),
    };
    validate_hot_tail_manifest(&manifest)?;
    Ok(manifest)
}

/// Select and bind the exact staged object set against one immutable base.
///
/// Both the continuously refreshed tail publisher and generation activation
/// call this function. Keeping filtering, identity construction, empty-tail
/// behavior, and safety bounds here prevents those two publication paths from
/// becoming independent storage authorities.
pub fn select_staged_hot_tail_manifest(
    table_location_prefix: &str,
    tenant_id: &str,
    base: &ObjectStampManifest,
    ledger: Vec<StagedHotTailLedgerObject>,
    max_objects: usize,
    max_bytes: u64,
    max_committed_objects: usize,
) -> Result<HotTailManifest> {
    select_staged_hot_tail_manifest_inner(
        table_location_prefix,
        tenant_id,
        base,
        ledger,
        max_objects,
        max_bytes,
        max_committed_objects,
        false,
    )
}

/// Schema-v4 variant for deployments whose query workers have an exact local
/// hot-tail cache. The separate entry point is a deliberate rolling-upgrade
/// fence: pre-v4 publishers keep emitting byte-identical legacy manifests
/// until the deployment explicitly flips both publication coordinators.
pub fn select_cached_staged_hot_tail_manifest(
    table_location_prefix: &str,
    tenant_id: &str,
    base: &ObjectStampManifest,
    ledger: Vec<StagedHotTailLedgerObject>,
    max_objects: usize,
    max_bytes: u64,
    max_committed_objects: usize,
) -> Result<HotTailManifest> {
    select_staged_hot_tail_manifest_inner(
        table_location_prefix,
        tenant_id,
        base,
        ledger,
        max_objects,
        max_bytes,
        max_committed_objects,
        true,
    )
}

/// Schema-v4 publisher contract for the hosted enterprise-shared R2 path.
///
/// The storage writer owns append-only conditional creation and supplies the
/// exact ETag observed from R2. This entry point refuses a version-only ledger
/// so the signed manifest can never make a shared reader depend on S3 bucket
/// versioning. Existing publishers continue to call
/// [`select_cached_staged_hot_tail_manifest`] and retain their wire format.
pub fn select_shared_r2_hot_tail_manifest(
    table_location_prefix: &str,
    tenant_id: &str,
    base: &ObjectStampManifest,
    ledger: Vec<StagedHotTailLedgerObject>,
    max_objects: usize,
    max_bytes: u64,
    max_committed_objects: usize,
) -> Result<HotTailManifest> {
    let manifest = select_staged_hot_tail_manifest_inner(
        table_location_prefix,
        tenant_id,
        base,
        ledger,
        max_objects,
        max_bytes,
        max_committed_objects,
        true,
    )?;
    if manifest.objects.is_empty() {
        // No out-of-catalog object will be read. Keep the established
        // schema-v1 base-only publication rather than inventing an empty v4.
        return Ok(manifest);
    }
    validate_shared_r2_hot_tail_manifest(&manifest)?;
    Ok(manifest)
}

fn select_staged_hot_tail_manifest_inner(
    table_location_prefix: &str,
    tenant_id: &str,
    base: &ObjectStampManifest,
    mut ledger: Vec<StagedHotTailLedgerObject>,
    max_objects: usize,
    max_bytes: u64,
    max_committed_objects: usize,
    include_content_digests: bool,
) -> Result<HotTailManifest> {
    ledger.sort_by(|left, right| {
        left.object
            .source_uri
            .cmp(&right.object.source_uri)
            .then_with(|| left.object.version_id.cmp(&right.object.version_id))
    });
    let indexed = base
        .objects
        .iter()
        .map(|object| (object.source_uri.as_str(), object))
        .collect::<BTreeMap<_, _>>();
    let mut selected = Vec::with_capacity(ledger.len());
    let mut digest = Sha256::new();
    digest.update(b"nano:staged-hot-tail:v1\0");
    for candidate in ledger {
        if !valid_sha256(&candidate.sha256) {
            bail!("staged hot-tail ledger has an invalid content digest");
        }
        if let Some(object) = indexed.get(candidate.object.source_uri.as_str()) {
            if object.version_id != candidate.object.version_id
                || object.size_bytes != candidate.object.size_bytes
                || object.sha256 != candidate.sha256
            {
                bail!("active generation and staged ledger disagree on one object identity");
            }
            continue;
        }
        for value in [
            candidate.object.source_uri.as_bytes(),
            candidate.object.version_id.as_bytes(),
            candidate.sha256.as_bytes(),
        ] {
            digest.update((value.len() as u64).to_be_bytes());
            digest.update(value);
        }
        // Keep the established versioned-S3 tail identity byte-for-byte when
        // no ETag is present. Enterprise-shared appends the provider ETag to
        // the identity before the enclosing HMAC signs the whole manifest.
        if let Some(etag) = candidate.object.etag.as_deref() {
            digest.update(b"nano:provider-etag:v1\0");
            digest.update((etag.len() as u64).to_be_bytes());
            digest.update(etag.as_bytes());
        }
        digest.update(candidate.object.size_bytes.to_be_bytes());
        digest.update(candidate.object.rows.to_be_bytes());
        digest.update(
            candidate
                .object
                .min_time_ms
                .unwrap_or_default()
                .to_be_bytes(),
        );
        digest.update(
            candidate
                .object
                .max_time_ms
                .unwrap_or_default()
                .to_be_bytes(),
        );
        let mut object = candidate.object;
        object.sha256 = include_content_digests.then_some(candidate.sha256);
        selected.push(object);
    }
    if selected.is_empty() {
        let prefix = format!("{}/", table_location_prefix.trim_end_matches('/'));
        let relative = base
            .metadata_location
            .strip_prefix(&prefix)
            .filter(|value| value.starts_with("metadata/") && !value.contains(".."))
            .context("active metadata is outside the staged tail table")?;
        let manifest = HotTailManifest {
            schema_version: 1,
            tenant_id: tenant_id.to_string(),
            table: base.table.clone(),
            base_snapshot_id: base.snapshot_id,
            head_snapshot_id: base.snapshot_id,
            tail_id: None,
            head_metadata_location: base.metadata_location.clone(),
            iceberg_metadata_file_path: relative.to_string(),
            read_schema: None,
            available_paths: Vec::new(),
            objects: Vec::new(),
            local_paths: Vec::new(),
        };
        validate_hot_tail_manifest(&manifest)?;
        return Ok(manifest);
    }
    let tail_id = hex::encode(digest.finalize());
    // The content identity deliberately excludes the `committed` tier marker:
    // identity is the exact object set (URI, version, digest, shape); which
    // envelope an object is charged against is a serving annotation that the
    // enclosing HMAC binds instead. Re-tiering the same set therefore keeps
    // its tail_id, so durable-job admission pins survive a committed-tier
    // rollout.
    build_staged_hot_tail_manifest(
        table_location_prefix,
        tenant_id,
        base,
        &tail_id,
        selected,
        max_objects,
        max_bytes,
        max_committed_objects,
    )
}

/// Attach the catalog-owned additive read contract to one exact staged tail.
/// The enclosing HMAC binds both values before a query worker can consume
/// them. Keeping this operation in the generation module gives every publisher
/// the same validation rather than allowing planner-specific schema hints.
pub fn bind_hot_tail_read_contract(
    manifest: &mut HotTailManifest,
    read_schema: String,
    mut available_paths: Vec<String>,
) -> Result<()> {
    available_paths.sort();
    available_paths.dedup();
    if manifest.objects.is_empty()
        || read_schema.is_empty()
        || read_schema.len() > 1_048_576
        || read_schema.chars().any(char::is_control)
        || available_paths.is_empty()
        || available_paths.len() > 100_000
        || available_paths.iter().any(|path| !valid_event_path(path))
    {
        bail!("hot-tail read contract is empty, malformed, or exceeds its bound");
    }
    manifest.read_schema = Some(read_schema);
    manifest.available_paths = available_paths;
    validate_hot_tail_manifest(manifest)
}

pub fn sign_hot_tail_manifest(manifest: HotTailManifest, key: &[u8]) -> Result<Vec<u8>> {
    if key.len() < 32 {
        bail!("hot-tail HMAC key must contain at least 32 bytes");
    }
    validate_hot_tail_manifest(&manifest)?;
    let payload = serde_json::to_vec(&manifest)?;
    let mut signer = Hmac::<Sha256>::new_from_slice(key)?;
    signer.update(&payload);
    let envelope = SignedHotTailManifest {
        manifest,
        hmac_sha256: hex::encode(signer.finalize().into_bytes()),
    };
    Ok(serde_json::to_vec(&envelope)?)
}

pub fn verify_hot_tail_manifest(bytes: &[u8], key: &[u8]) -> Result<HotTailManifest> {
    if bytes.is_empty() || bytes.len() > 4_194_304 || key.len() < 32 {
        bail!("hot-tail envelope or HMAC key violates its bound");
    }
    let envelope: SignedHotTailManifest = serde_json::from_slice(bytes)?;
    let signature = hex::decode(&envelope.hmac_sha256)?;
    let payload = serde_json::to_vec(&envelope.manifest)?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(key)?;
    verifier.update(&payload);
    verifier
        .verify_slice(&signature)
        .context("hot-tail manifest signature mismatch")?;
    validate_hot_tail_manifest(&envelope.manifest)?;
    Ok(envelope.manifest)
}

/// The bootstrap generation (NAN-2361 wave 8) has no Iceberg snapshot: its
/// staged tail is bound to base 0 and, because a staged tail never advances
/// the head, head 0. Any OTHER zero or negative identity remains invalid, and
/// a schema-1 Iceberg-descendant tail (head advanced past the base) can never
/// be bootstrap because there is no base snapshot to descend from.
pub fn hot_tail_is_bootstrap(manifest: &HotTailManifest) -> bool {
    manifest.base_snapshot_id == crate::bootstrap_generation::BOOTSTRAP_SNAPSHOT_ID
        && manifest.head_snapshot_id == crate::bootstrap_generation::BOOTSTRAP_SNAPSHOT_ID
}

fn validate_hot_tail_manifest(manifest: &HotTailManifest) -> Result<()> {
    let snapshot_identity_valid = hot_tail_is_bootstrap(manifest)
        || (manifest.base_snapshot_id > 0 && manifest.head_snapshot_id > 0);
    if !matches!(manifest.schema_version, 1..=4)
        || manifest.tenant_id.is_empty()
        || manifest.tenant_id.len() > 256
        || manifest.tenant_id.chars().any(char::is_control)
        || manifest.table.is_empty()
        || !snapshot_identity_valid
        || !manifest.head_metadata_location.starts_with("s3://")
        || !manifest
            .head_metadata_location
            .ends_with(&manifest.iceberg_metadata_file_path)
        || manifest.objects.len() > HOT_TAIL_OBJECT_FORMAT_CEILING as usize
    {
        bail!("hot-tail manifest identity is invalid");
    }
    validate_relative_path(&manifest.iceberg_metadata_file_path)?;
    match (&manifest.read_schema, manifest.available_paths.is_empty()) {
        (None, true) => {}
        (Some(schema), false)
            if !schema.is_empty()
                && schema.len() <= 1_048_576
                && !schema.chars().any(char::is_control)
                && manifest.available_paths.len() <= 100_000
                && manifest
                    .available_paths
                    .iter()
                    .all(|path| valid_event_path(path)) => {}
        _ => bail!("hot-tail read contract is incomplete or invalid"),
    }
    let mut paths = BTreeSet::new();
    let mut staged_bytes = 0_u64;
    let mut total_bytes = 0_u64;
    let mut committed_objects = 0_usize;
    for object in &manifest.objects {
        if object.source_uri.is_empty()
            || object.version_id.is_empty()
            || object.version_id == "unversioned"
            || object.size_bytes == 0
            || object.rows == 0
            || match manifest.schema_version {
                4 => {
                    !object.sha256.as_deref().is_some_and(valid_sha256)
                        || !object.etag.as_deref().is_none_or(valid_etag)
                }
                _ => object.sha256.is_some() || object.etag.is_some(),
            }
            // Committed-tier objects escape the byte envelope, so their
            // per-object time bounds are the only per-query cost fence a
            // time-scoped read has against them; absent bounds fail closed.
            || (object.committed
                && (object.min_time_ms.is_none() || object.max_time_ms.is_none()))
            || !paths.insert(object.source_uri.as_str())
        {
            bail!("hot-tail object identity is invalid");
        }
        parse_s3_uri(&object.source_uri)?;
        total_bytes = total_bytes
            .checked_add(object.size_bytes)
            .context("hot-tail manifest byte count overflow")?;
        if object.committed {
            committed_objects += 1;
        } else {
            staged_bytes = staged_bytes
                .checked_add(object.size_bytes)
                .context("hot-tail manifest byte count overflow")?;
        }
    }
    // NAN-2361 two-tier hot tail: the absolute serving bound applies to the
    // STAGED tier. In schema 1/2 every object is staged-tier (committed
    // markers are rejected below), so this is byte-for-byte today's check;
    // in schema 3 the committed tier's bytes are governed by the per-query
    // scan budget the planner Reject-enforces, exactly like the base.
    if staged_bytes > HOT_TAIL_SERVING_CEILING_BYTES {
        bail!("hot-tail manifest exceeds its absolute byte bound");
    }
    match manifest.schema_version {
        1 if manifest.tail_id.is_some()
            || committed_objects != 0
            || (manifest.base_snapshot_id == manifest.head_snapshot_id
                && !manifest.objects.is_empty()) =>
        {
            bail!("Iceberg hot-tail snapshot identity is inconsistent");
        }
        // A committed marker in a legacy schema would smuggle the byte-bound
        // exemption into manifests that pre-tier readers also accept; only
        // schema 3 — which such readers reject wholesale — may carry it.
        2 if manifest.base_snapshot_id != manifest.head_snapshot_id
            || manifest.objects.is_empty()
            || committed_objects != 0
            || !manifest.tail_id.as_deref().is_some_and(valid_sha256) =>
        {
            bail!("staged hot-tail content identity is inconsistent");
        }
        // Schema 3 is canonical only WITH a committed tier: an all-staged set
        // must publish as schema 2 so legacy readers keep working during a
        // rolling deploy.
        3 if manifest.base_snapshot_id != manifest.head_snapshot_id
            || manifest.objects.is_empty()
            || committed_objects == 0
            || !manifest.tail_id.as_deref().is_some_and(valid_sha256) =>
        {
            bail!("staged hot-tail content identity is inconsistent");
        }
        4 if manifest.base_snapshot_id != manifest.head_snapshot_id
            || manifest.objects.is_empty()
            || !manifest.tail_id.as_deref().is_some_and(valid_sha256) =>
        {
            bail!("cached hot-tail content identity is inconsistent");
        }
        _ => {}
    }
    Ok(())
}

/// Additional verification applied only by the enterprise-shared R2
/// publisher and reader. Generic schema-v4 remains version-ID compatible for
/// dedicated/open deployments, while the hosted path requires an opaque ETag
/// on every signed object.
pub fn validate_shared_r2_hot_tail_manifest(manifest: &HotTailManifest) -> Result<()> {
    validate_hot_tail_manifest(manifest)?;
    if uuid::Uuid::parse_str(&manifest.tenant_id).is_err()
        || manifest.schema_version != 4
        || manifest.objects.is_empty()
    {
        bail!("enterprise_shared R2 requires a schema-v4 ETag-bound hot-tail manifest");
    }
    if manifest
        .objects
        .iter()
        .any(|object| !object.etag.as_deref().is_some_and(valid_etag))
    {
        bail!("enterprise_shared R2 hot-tail ledger omitted an authoritative ETag");
    }
    Ok(())
}

fn valid_etag(value: &str) -> bool {
    (3..=1_024).contains(&value.len())
        && value.starts_with('"')
        && value.ends_with('"')
        && !value[1..value.len() - 1].contains('"')
        && !value.chars().any(char::is_control)
}

fn valid_event_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= 2_048
        && !path.chars().any(char::is_control)
        && !path.starts_with('.')
        && !path.ends_with('.')
        && path.split('.').all(|segment| {
            !segment.is_empty()
                && segment != "_path"
                && segment != "_row_number"
                && !segment.contains('`')
        })
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn s3_operator(config: &CatalogConfig, bucket: &str) -> Result<Operator> {
    let mut builder = S3::default().bucket(bucket).region(&config.s3_region);
    if !config.s3_endpoint.is_empty() {
        builder = builder.endpoint(&config.s3_endpoint);
    }
    if config.s3_path_style_access {
        // Path style is OpenDAL's default. Keep this branch explicit so the
        // provider mode below is visibly different from AWS virtual-hosted S3.
    } else {
        builder = builder.enable_virtual_host_style();
    }
    if !config.s3_default_credentials {
        builder = builder
            .access_key_id(&config.s3_access_key)
            .secret_access_key(&config.s3_secret_key)
            .disable_config_load()
            .disable_ec2_metadata();
        if let Some(token) = &config.s3_session_token {
            builder = builder.session_token(token);
        }
    }
    Ok(Operator::new(builder)?.layer(crate::r2_ops::layer()).finish())
}

fn parse_s3_uri(value: &str) -> Result<(&str, &str)> {
    let remainder = value
        .strip_prefix("s3://")
        .context("Iceberg object is not an s3:// URI")?;
    let (bucket, key) = remainder
        .split_once('/')
        .context("Iceberg S3 URI has no object key")?;
    if bucket.is_empty()
        || key.is_empty()
        || bucket.chars().any(char::is_control)
        || key.chars().any(char::is_control)
    {
        bail!("Iceberg S3 URI is invalid");
    }
    Ok((bucket, key))
}

fn validate_relative_path(value: &str) -> Result<()> {
    if value.is_empty()
        || value.starts_with('/')
        || value
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
        || value.chars().any(char::is_control)
    {
        bail!("Iceberg object produced an unsafe relative path");
    }
    Ok(())
}

fn sync_tree(root: &Path) -> Result<()> {
    let mut directories = vec![root.to_path_buf()];
    let mut cursor = 0;
    while cursor < directories.len() {
        let directory = directories[cursor].clone();
        for entry in std::fs::read_dir(&directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                directories.push(entry.path());
            }
        }
        cursor += 1;
    }
    for directory in directories.into_iter().rev() {
        File::open(directory)?.sync_all()?;
    }
    Ok(())
}

#[derive(Clone)]
struct LocalObject {
    /// Stable per-object artifact identity. A function of the object's exact
    /// immutable identity (source URI, version, size) via the persisted
    /// allocator seeded from the prior generation's entity manifest — NEVER a
    /// position in a sorted list, so retiring or inserting a neighbour never
    /// changes any other object's id (and therefore never rewrites any other
    /// object's derivative artifact).
    id: u32,
    /// Snapshot-local ordinal (position in the path-sorted object list). Used
    /// ONLY to name per-object artifact files (`object-{position:04}.parquet`)
    /// so the query engine keeps its single contiguous brace-range glob; a
    /// position shift is repaired by re-linking the immutable artifact under a
    /// new name, never by rewriting its contents.
    position: u32,
    path: PathBuf,
    stamp: ObjectStamp,
}

#[derive(Clone, Deserialize, Serialize)]
struct ObjectBuild {
    object_id: u32,
    rows: u64,
    bytes: u64,
    seconds: f64,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    max_event_time_us: Option<i64>,
}

type EventObjectIdentity = (String, String, u64);

struct PriorEntityObject {
    manifest: Value,
    build: ObjectBuild,
    /// The prior generation's on-disk artifact filename for this object.
    /// Artifacts are named by snapshot POSITION (contiguous, glob-friendly),
    /// which both the current and the pre-stable-id layouts derive from the
    /// manifest's path-sorted object order.
    artifact_name: String,
}

struct PriorEntitySidecar {
    directory: PathBuf,
    objects: BTreeMap<EventObjectIdentity, PriorEntityObject>,
    /// Physical width of the `object_id` column in the prior generation's
    /// entity artifacts. Pre-stable-id generations wrote UInt16 ordinals; they
    /// are accepted and migrated (loudly, once per object) to UInt32.
    object_id_width: u32,
    /// High-water mark of the prior generation's stable-id allocator. New
    /// objects are allocated from here so a retired object's id is never
    /// recycled within a lineage.
    next_object_id: u32,
    /// Stored byte width of the prior generation's `value_hash` column.
    /// v1 manifests carried the full 32-byte HMAC; v2 stores the leading
    /// `ENTITY_VALUE_HASH_BYTES`. Full-width artifacts are accepted and
    /// migrated (truncate + merge, loudly, once per object) on reuse.
    value_hash_bytes: usize,
}

struct PriorCountRollups {
    directory: PathBuf,
    parts: BTreeMap<EventObjectIdentity, CountRollupObject>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeywordManifestObject {
    object_id: u32,
    relative_path: String,
    event_object_key: String,
    event_object_version: String,
    event_object_bytes: u64,
    rows: u64,
    row_groups: usize,
    available_paths: Vec<String>,
    field_types: BTreeMap<String, String>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct KeywordManifestBlock {
    locator: u64,
    object_id: u32,
    row_group: u32,
    row_start: u64,
    row_end: u64,
    rows: u64,
    max_time: u64,
}

#[derive(Deserialize)]
struct PriorKeywordManifest {
    index_version: String,
    tenant_id: String,
    body_fields: Vec<String>,
    objects: Vec<KeywordManifestObject>,
    blocks: Vec<KeywordManifestBlock>,
    block_documents: usize,
}

struct PriorKeywordIndex {
    directory: PathBuf,
    manifest: PriorKeywordManifest,
    objects: BTreeMap<EventObjectIdentity, KeywordManifestObject>,
}

#[derive(Serialize, Deserialize)]
struct KeywordBuildResult {
    manifest: Value,
    reused_objects: usize,
    built_objects: usize,
    retired_objects: usize,
}

#[derive(Serialize, Deserialize)]
struct FragmentBuildResult {
    manifest: Value,
    reused_terms: u64,
    built_terms: u64,
}

fn stamp_identity(stamp: &ObjectStamp) -> EventObjectIdentity {
    (
        stamp.source_uri.clone(),
        stamp.version_id.clone(),
        stamp.size_bytes,
    )
}

pub fn build_generation(
    input_root: &Path,
    output_root: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    key_id: &str,
    hmac_key_path: &Path,
    threads: usize,
    heap_bytes: usize,
) -> Result<GenerationBuildResult> {
    build_generation_reusing(
        input_root,
        output_root,
        stamp_manifest,
        tenant_id,
        key_id,
        hmac_key_path,
        threads,
        heap_bytes,
        None,
    )
}

/// Build a complete immutable generation while reusing per-object artifacts
/// from the active generation when their exact object identities and artifact
/// digests still match. A missing or incompatible prior derivative silently
/// falls back to rebuilding that object; publication remains all-or-nothing.
#[allow(clippy::too_many_arguments)]
pub fn build_generation_reusing(
    input_root: &Path,
    output_root: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    key_id: &str,
    hmac_key_path: &Path,
    threads: usize,
    heap_bytes: usize,
    prior_derivatives: Option<&Path>,
) -> Result<GenerationBuildResult> {
    build_generation_reusing_with_count_rollup_threads(
        input_root,
        output_root,
        stamp_manifest,
        tenant_id,
        key_id,
        hmac_key_path,
        threads,
        heap_bytes,
        1,
        prior_derivatives,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_generation_reusing_with_count_rollup_threads(
    input_root: &Path,
    output_root: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    key_id: &str,
    hmac_key_path: &Path,
    threads: usize,
    heap_bytes: usize,
    count_rollup_threads: usize,
    prior_derivatives: Option<&Path>,
) -> Result<GenerationBuildResult> {
    let derivative_build_memory_bytes = u64::try_from(threads)
        .unwrap_or(u64::MAX)
        .saturating_mul(ENTITY_LANE_MEMORY_BYTES)
        .max(
            u64::try_from(KEYWORD_PRODUCER_CEILING)
                .unwrap_or(u64::MAX)
                .saturating_mul(KEYWORD_PRODUCER_LANE_MEMORY_BYTES),
        )
        .max(
            u64::try_from(count_rollup_threads)
                .unwrap_or(u64::MAX)
                .saturating_mul(COUNT_ROLLUP_LANE_MEMORY_BYTES),
        );
    build_generation_reusing_with_layout(
        input_root,
        output_root,
        stamp_manifest,
        tenant_id,
        key_id,
        hmac_key_path,
        threads,
        heap_bytes,
        count_rollup_threads,
        KEYWORD_PRODUCER_CEILING,
        derivative_build_memory_bytes,
        prior_derivatives,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn build_generation_reusing_with_layout(
    input_root: &Path,
    output_root: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    key_id: &str,
    hmac_key_path: &Path,
    threads: usize,
    heap_bytes: usize,
    count_rollup_threads: usize,
    keyword_producer_ceiling: usize,
    derivative_build_memory_bytes: u64,
    prior_derivatives: Option<&Path>,
) -> Result<GenerationBuildResult> {
    if output_root.exists() {
        bail!(
            "generation output already exists: {}",
            output_root.display()
        );
    }
    let parent = output_root
        .parent()
        .context("generation output has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    // Fixed staging identity survives a killed builder. Bind it to the exact
    // source stamps and semantic configuration before trusting phase receipts.
    let identity = hex::encode(Sha256::digest(serde_json::to_vec(&json!({
        "stamps": file_sha256(stamp_manifest)?,
        "tenant": tenant_id, "key_id": key_id,
        "key": file_sha256(hmac_key_path)?,
        "contract": derivative_compatibility_contract_sha256()?,
        "prior": prior_derivatives,
    }))?));
    let candidate = parent.join(format!(".generation-build-{identity}"));
    std::fs::create_dir_all(&candidate)?;
    let phase_lock = std::fs::OpenOptions::new().create(true).read(true).write(true)
        .open(candidate.join(".builder.lock"))?;
    // One build per lake_sidecar_build process, which spawns no children (NAN-2822).
    fs2::FileExt::try_lock_exclusive(&phase_lock)
        .context("another builder still owns the resumable derivative candidate")?;
    if output_root.exists() { bail!("generation output was published by another builder"); }
    let tree = candidate.join("tree");
    std::fs::create_dir_all(&tree)?;
    let result = build_generation_in(
        input_root, &tree, stamp_manifest, tenant_id, key_id, hmac_key_path,
        threads, heap_bytes, count_rollup_threads, keyword_producer_ceiling,
        derivative_build_memory_bytes, prior_derivatives,
    )?;
    sync_tree(&tree)?;
    // Receipts stay outside the atomic publication tree. A kill immediately
    // before rename therefore preserves every completed phase receipt.
    std::fs::rename(&tree, output_root)?;
    File::open(parent)?.sync_all()?;
    std::fs::remove_dir_all(candidate)?;
    Ok(result)
}

fn resume_derivative_phase<T: Serialize + serde::de::DeserializeOwned>(
    root: &Path, phase: &str, build: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let checkpoint_root = root.parent().context("derivative phase has no checkpoint directory")?;
    let receipt = checkpoint_root.join(format!(".{phase}.receipt.json"));
    if let Ok(metadata) = std::fs::symlink_metadata(&receipt) {
        if !metadata.is_file() || metadata.len() > 64 * 1024 * 1024 || !root.join(phase).is_dir() {
            bail!("derivative phase receipt is not a bounded completed artifact");
        }
        tracing::info!(phase, "resuming completed derivative phase");
        return serde_json::from_slice(&std::fs::read(receipt)?)
            .context("decode completed derivative phase receipt");
    }
    let directory = root.join(phase);
    if directory.exists() { std::fs::remove_dir_all(&directory)?; }
    std::fs::create_dir(&directory)?;
    let result = build()?;
    sync_tree(&directory)?;
    let mut candidate = tempfile::NamedTempFile::new_in(checkpoint_root)?;
    serde_json::to_writer(&mut candidate, &result)?;
    candidate.as_file().sync_all()?;
    candidate.persist(&receipt)?;
    File::open(checkpoint_root)?.sync_all()?;
    #[cfg(test)]
    if std::env::var("NAN2460_KILL_AFTER_PHASE").as_deref() == Ok(phase) {
        // Fault injection only in the test harness; no unwinding/TempDir cleanup.
        unsafe { libc::raise(libc::SIGKILL); }
    }
    Ok(result)
}

fn generation_build_thread_layout(
    threads: usize,
    heap_bytes: usize,
    count_rollup_threads: usize,
    keyword_producer_ceiling: usize,
    derivative_build_memory_bytes: u64,
) -> Result<GenerationBuildThreadLayout> {
    if threads == 0 || count_rollup_threads == 0 || keyword_producer_ceiling == 0 {
        bail!("generation thread layout has a zero lane count");
    }
    let count_rollup_reservation = u64::try_from(count_rollup_threads)?
        .checked_mul(COUNT_ROLLUP_LANE_MEMORY_BYTES)
        .context("count-rollup reservation overflow")?;
    if count_rollup_reservation > derivative_build_memory_bytes {
        bail!("count-rollup lanes exceed the derivative build memory bound");
    }
    let keyword_decoded_memory_bytes = derivative_build_memory_bytes
        .checked_sub(u64::try_from(heap_bytes)?)
        .context("keyword writer heap exhausts the derivative build memory bound")?;
    let bounded_lanes = |lane_bytes: u64| {
        usize::try_from(derivative_build_memory_bytes / lane_bytes)
            .unwrap_or(usize::MAX)
            .max(1)
    };
    Ok(GenerationBuildThreadLayout {
        configured_threads: threads,
        entity_threads: threads.min(bounded_lanes(ENTITY_LANE_MEMORY_BYTES)),
        keyword_producer_ceiling: keyword_producer_ceiling.min(
            usize::try_from(keyword_decoded_memory_bytes / KEYWORD_PRODUCER_LANE_MEMORY_BYTES)
                .unwrap_or(usize::MAX)
                .max(1),
        ),
        count_rollup_threads,
        derivative_build_memory_bytes,
        entity_lane_memory_bytes: ENTITY_LANE_MEMORY_BYTES,
        keyword_producer_lane_memory_bytes: KEYWORD_PRODUCER_LANE_MEMORY_BYTES,
    })
}

fn build_generation_in(
    input_root: &Path,
    output_root: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    key_id: &str,
    hmac_key_path: &Path,
    threads: usize,
    heap_bytes: usize,
    count_rollup_threads: usize,
    keyword_producer_ceiling: usize,
    derivative_build_memory_bytes: u64,
    prior_derivatives: Option<&Path>,
) -> Result<GenerationBuildResult> {
    let thread_layout = generation_build_thread_layout(
        threads,
        heap_bytes,
        count_rollup_threads,
        keyword_producer_ceiling,
        derivative_build_memory_bytes,
    )?;
    let minimum_heap_bytes = threads.saturating_mul(TANTIVY_MIN_MEMORY_PER_THREAD);
    if tenant_id.is_empty()
        || key_id.is_empty()
        || threads == 0
        || count_rollup_threads == 0
        || count_rollup_threads > threads
        || keyword_producer_ceiling == 0
        || keyword_producer_ceiling > MAX_KEYWORD_PRODUCER_CEILING
        || heap_bytes < minimum_heap_bytes
    {
        bail!("generation tenant, key ID, thread count, or heap bound is invalid");
    }
    tracing::info!(
        configured_threads = thread_layout.configured_threads,
        entity_threads = thread_layout.entity_threads,
        keyword_producer_ceiling = thread_layout.keyword_producer_ceiling,
        count_rollup_threads = thread_layout.count_rollup_threads,
        derivative_build_memory_bytes = thread_layout.derivative_build_memory_bytes,
        "generation derivative memory lanes resolved"
    );
    let started = Instant::now();
    let stamps: ObjectStampManifest = serde_json::from_slice(&std::fs::read(stamp_manifest)?)?;
    let mut objects = local_objects(input_root, &stamps)?;
    // The prior entity sidecar is loaded ONCE and shared by the stable-id
    // allocator and the entity reuse path, so the id an object is assigned and
    // the id its reusable prior artifact carries can never diverge.
    let prior_entity = prior_entity_sidecar(
        prior_derivatives
            .map(|root| root.join("entity-sidecar"))
            .as_deref(),
        tenant_id,
        key_id,
    )?;
    let next_object_id = assign_stable_object_ids(&mut objects, prior_entity.as_ref())?;
    let objects = objects;
    let key = trim_ascii(&std::fs::read(hmac_key_path)?).to_vec();
    if key.len() < 32 {
        bail!("entity HMAC key is shorter than 32 bytes");
    }
    std::fs::create_dir_all(output_root)?;
    let entity = output_root.join("entity-sidecar");
    let keyword = output_root.join("keyword-sidecar");
    let fragment = output_root.join("fragment-sidecar");
    let identity = output_root.join("identity-snapshot");
    let count_rollup = output_root.join("count-rollup");

    let entity_started = Instant::now();
    let entity_build = resume_derivative_phase(output_root, "entity-sidecar", || build_entity(
        input_root,
        &entity,
        stamp_manifest,
        tenant_id,
        key_id,
        &key,
        stamps.snapshot_id,
        &objects,
        prior_entity,
        next_object_id,
        thread_layout.entity_threads,
    ))?;
    let entity_seconds = entity_started.elapsed().as_secs_f64();
    tracing::info!(
        phase = "entity",
        phase_seconds = entity_seconds,
        "generation derivative phase completed"
    );
    let EntityBuildOutput {
        manifest: mut entity_manifest,
        event_rows,
        source_bytes,
        index_bytes: entity_bytes,
        max_event_time_us,
        reused_object_ids: entity_reused_ids,
    } = entity_build;
    let prior_uid_ledger = prior_derivatives.map(|root| root.join(UID_LEDGER_DIRECTORY));
    let uid_proof_started = Instant::now();
    let uid_output = output_root.join(UID_LEDGER_DIRECTORY);
    if uid_output.exists() { std::fs::remove_dir_all(&uid_output)?; }
    let uid_proof = verify_unique_event_uids(
        &entity,
        &output_root.join(UID_LEDGER_DIRECTORY),
        prior_uid_ledger.as_deref(),
        tenant_id,
        &objects,
        &entity_reused_ids,
        heap_bytes,
        event_rows,
    )?;
    let uid_proof_seconds = uid_proof_started.elapsed().as_secs_f64();
    tracing::info!(
        phase = "uid-proof",
        phase_seconds = uid_proof_seconds,
        "generation derivative phase completed"
    );
    let event_uid_rows = uid_proof.uid_rows;
    entity_manifest
        .as_object_mut()
        .context("entity manifest is not a JSON object")?
        .insert(
            "event_uid_uniqueness".to_string(),
            json!({
                "algorithm": uid_proof.algorithm,
                "mode": uid_proof.mode,
                "window_days": UID_WINDOW_DAYS,
                "field": "metadata.uid",
                "rows": event_uid_rows,
                "duplicates": 0,
            }),
        );
    write_json(&entity.join("manifest.json"), &entity_manifest)?;
    let keyword_started = Instant::now();
    let keyword_build = resume_derivative_phase(output_root, "keyword-sidecar", || build_keyword(
        input_root,
        &keyword,
        stamp_manifest,
        tenant_id,
        &objects,
        threads,
        heap_bytes,
        thread_layout.keyword_producer_ceiling,
        prior_derivatives.map(|root| root.join("keyword-sidecar")),
    ))?;
    write_json(&keyword.join("manifest.json"), &keyword_build.manifest)?;
    let keyword_seconds = keyword_started.elapsed().as_secs_f64();
    tracing::info!(
        phase = "keyword",
        phase_seconds = keyword_seconds,
        "generation derivative phase completed"
    );
    let fragment_started = Instant::now();
    let fragment_build = resume_derivative_phase(output_root, "fragment-sidecar", || build_fragment(
        &keyword.join("index"),
        &fragment,
        threads,
        heap_bytes,
        prior_derivatives.map(|root| root.join("keyword-sidecar/index")),
        prior_derivatives.map(|root| root.join("fragment-sidecar")),
    ))?;
    write_json(&fragment.join("manifest.json"), &fragment_build.manifest)?;
    let fragment_seconds = fragment_started.elapsed().as_secs_f64();
    tracing::info!(
        phase = "fragment",
        phase_seconds = fragment_seconds,
        "generation derivative phase completed"
    );
    let identity_started = Instant::now();
    let identity_manifest = resume_derivative_phase(output_root, "identity-snapshot", || build_identity_snapshot(
        &identity,
        stamp_manifest,
        tenant_id,
        &stamps,
        &objects,
        event_rows,
        max_event_time_us,
        thread_layout.entity_threads,
        prior_derivatives.map(|root| root.join("identity-snapshot")),
    ))?;
    write_json(&identity.join("manifest.json"), &identity_manifest)?;
    let identity_seconds = identity_started.elapsed().as_secs_f64();
    tracing::info!(
        phase = "identity",
        phase_seconds = identity_seconds,
        "generation derivative phase completed"
    );
    let count_rollup_started = Instant::now();
    let count_rollup_manifest = resume_derivative_phase(output_root, "count-rollup", || build_count_rollup(
        &count_rollup,
        stamp_manifest,
        tenant_id,
        &stamps,
        &objects,
        prior_derivatives.map(|root| root.join("count-rollup")),
        count_rollup_threads,
    ))?;
    write_json(&count_rollup.join("manifest.json"), &count_rollup_manifest)?;
    let count_rollup_seconds = count_rollup_started.elapsed().as_secs_f64();
    tracing::info!(
        phase = "count-rollup",
        phase_seconds = count_rollup_seconds,
        "generation derivative phase completed"
    );
    Ok(GenerationBuildResult {
        source_files: objects.len(),
        event_rows,
        event_uid_rows,
        source_bytes,
        entity_index_bytes: entity_bytes,
        keyword_index_bytes: directory_bytes(&keyword.join("index"))?,
        fragment_index_bytes: directory_bytes(&fragment.join("index"))?,
        count_rollup_rows: count_rollup_manifest.rows,
        count_rollup_bytes: count_rollup_manifest.bytes,
        identity_observation_rows: identity_manifest.rows,
        identity_snapshot_bytes: identity_manifest.bytes,
        entity_reused_objects: entity_manifest
            .get("reused_objects")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(0),
        entity_built_objects: entity_manifest
            .get("built_objects")
            .and_then(Value::as_u64)
            .and_then(|value| usize::try_from(value).ok())
            .unwrap_or(objects.len()),
        identity_reused_objects: identity_manifest.reused_source_files,
        identity_built_objects: identity_manifest.built_source_files,
        count_rollup_reused_objects: count_rollup_manifest.reused_objects,
        count_rollup_built_objects: count_rollup_manifest.built_objects,
        keyword_reused_objects: keyword_build.reused_objects,
        keyword_built_objects: keyword_build.built_objects,
        keyword_retired_objects: keyword_build.retired_objects,
        fragment_reused_terms: fragment_build.reused_terms,
        fragment_built_terms: fragment_build.built_terms,
        thread_layout,
        phase_timings_seconds: GenerationBuildPhaseTimings {
            entity: entity_seconds,
            uid_proof: uid_proof_seconds,
            keyword: keyword_seconds,
            fragment: fragment_seconds,
            identity: identity_seconds,
            count_rollup: count_rollup_seconds,
        },
        build_seconds: started.elapsed().as_secs_f64(),
    })
}

/// Build bounded per-object hourly count parts. Keeping each source object's
/// derivative separate avoids an unbounded in-memory global aggregation and
/// lets the query planner select only parts whose bucket range overlaps the
/// request. Generation activation binds every part to the same Iceberg
/// snapshot and exact object-stamp ledger as the other sidecars.
pub fn build_count_rollup_generation(
    input_root: &Path,
    output_root: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
) -> Result<CountRollupManifest> {
    if output_root.exists() || tenant_id.is_empty() {
        bail!("count rollup output already exists or tenant is empty");
    }
    let stamps: ObjectStampManifest = serde_json::from_slice(&std::fs::read(stamp_manifest)?)?;
    let objects = local_objects(input_root, &stamps)?;
    let parent = output_root
        .parent()
        .context("count rollup output has no parent directory")?;
    std::fs::create_dir_all(parent)?;
    let candidate = tempfile::Builder::new()
        .prefix(".count-rollup-")
        .tempdir_in(parent)?;
    let manifest = build_count_rollup(
        candidate.path(),
        stamp_manifest,
        tenant_id,
        &stamps,
        &objects,
        None,
        1,
    )?;
    write_json(&candidate.path().join("manifest.json"), &manifest)?;
    sync_tree(candidate.path())?;
    let candidate_path = candidate.keep();
    std::fs::rename(candidate_path, output_root)?;
    File::open(parent)?.sync_all()?;
    Ok(manifest)
}

fn build_count_rollup(
    output: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    stamps: &ObjectStampManifest,
    objects: &[LocalObject],
    prior: Option<PathBuf>,
    threads: usize,
) -> Result<CountRollupManifest> {
    if threads == 0 {
        bail!("count rollup thread count is zero");
    }
    let started = Instant::now();
    let prior = prior_count_rollups(prior.as_deref(), tenant_id)?;
    let schema = count_rollup_schema();
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(9)?))
        .set_max_row_group_row_count(Some(262_144))
        .build();
    let mut total_rows = 0_u64;
    let mut total_bytes = 0_u64;
    let mut manifest_objects = Vec::with_capacity(objects.len());
    let mut reused_objects = 0_usize;
    let mut pending = Vec::new();
    for object in objects {
        // Count-rollup parts embed NO object id in their bytes; the manifest
        // object_id is purely the positional file locator that the load and
        // activation fences verify (`object_id == position`). Reuse restamps
        // this metadata; it never rewrites part bytes.
        let relative_path = format!("object-{:04}.parquet", object.position);
        let path = output.join(&relative_path);
        if let Some(reused) = prior
            .as_ref()
            .and_then(|parts| parts.parts.get(&stamp_identity(&object.stamp)))
        {
            let source = prior
                .as_ref()
                .expect("prior rollup exists")
                .directory
                .join(&reused.relative_path);
            if reuse_verified_artifact(
                &source,
                &path,
                reused.bytes,
                &reused.sha256,
                sample_reverify(stamps.snapshot_id, &object.stamp.source_uri),
            )? {
                total_rows = total_rows
                    .checked_add(reused.rows)
                    .context("count rollup row overflow")?;
                total_bytes = total_bytes
                    .checked_add(reused.bytes)
                    .context("count rollup byte overflow")?;
                let mut reused = reused.clone();
                reused.object_id = object.position;
                reused.relative_path = relative_path;
                reused.event_object_key = object.stamp.source_uri.clone();
                reused.event_object_version = object.stamp.version_id.clone();
                reused.event_object_bytes = object.stamp.size_bytes;
                manifest_objects.push(reused);
                reused_objects += 1;
                continue;
            }
        }
        pending.push(object);
    }
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|index| format!("count-rollup-{index}"))
        .build()
        .context("build bounded count-rollup worker pool")?;
    let built = pool.install(|| {
        pending
            .par_iter()
            .map(|object| {
                let relative_path = format!("object-{:04}.parquet", object.position);
                let path = output.join(&relative_path);
                build_count_rollup_object(object, relative_path, &path, &schema, &properties)
            })
            .collect::<Result<Vec<_>>>()
    })?;
    for built in built {
        total_rows = total_rows
            .checked_add(built.rows)
            .context("count rollup row overflow")?;
        total_bytes = total_bytes
            .checked_add(built.bytes)
            .context("count rollup byte overflow")?;
        manifest_objects.push(built);
    }
    manifest_objects.sort_unstable_by_key(|object| object.object_id);
    Ok(CountRollupManifest {
        schema_version: 1,
        rollup_version: COUNT_ROLLUP_VERSION.to_string(),
        tenant_id: tenant_id.to_string(),
        event_snapshot_id: stamps.snapshot_id,
        object_stamp_sha256: file_digest(stamp_manifest)?,
        bucket_width_us: COUNT_ROLLUP_BUCKET_US,
        fields: COUNT_ROLLUP_FIELDS
            .iter()
            .map(|field| CountRollupManifestField {
                field_id: field.field_id,
                source_path: field.source_path.to_string(),
                multi_value: field.multi_value,
            })
            .collect(),
        objects: manifest_objects,
        rows: total_rows,
        bytes: total_bytes,
        build_seconds: started.elapsed().as_secs_f64(),
        reused_objects,
        built_objects: objects.len() - reused_objects,
    })
}

/// Exact per-batch count-rollup aggregation (one batch of event rows).
/// Shared by the generation builder and the lean-lake part writer
/// (NAN-2868), which sums these per part.
pub(crate) fn count_rollup_batch_counts(
    batch: &RecordBatch,
    source_types: &mut HashMap<String, Arc<str>>,
) -> Result<HashMap<CountRollupKey, u64>> {
    let mut counts = HashMap::<CountRollupKey, u64>::new();
    let mut context_rows = HashMap::<CountRollupContextKey, u64>::new();
    let mut present_rows = HashMap::<CountRollupPresentKey, u64>::new();
    let source_path = CompiledStringPath::new(&batch, "metadata.log_source");
    let field_paths = COUNT_ROLLUP_FIELDS
        .iter()
        .map(|field| {
            (field.source_path != DASHBOARD_BREAKDOWN_FIELD)
                .then(|| CompiledStringPath::new(&batch, field.source_path))
                .flatten()
        })
        .collect::<Vec<_>>();
    let dashboard_paths = DASHBOARD_BREAKDOWN_COMPONENTS
        .iter()
        .map(|path| CompiledStringPath::new(&batch, path))
        .collect::<Vec<_>>();
    let time = batch
        .schema()
        .index_of("time")
        .ok()
        .map(|index| batch.column(index));
    let mut row_contexts = Vec::with_capacity(batch.num_rows());
    for row in 0..batch.num_rows() {
        let Some(observed_at_us) =
            time.and_then(|array| event_time_us_from_array(array.as_ref(), row))
        else {
            row_contexts.push(None);
            continue;
        };
        let bucket_start_us =
            observed_at_us.div_euclid(COUNT_ROLLUP_BUCKET_US) * COUNT_ROLLUP_BUCKET_US;
        let source_type = source_path
            .as_ref()
            .and_then(|path| {
                path.strings(row)
                    .into_iter()
                    .find(|value| !value.trim().is_empty())
            })
            .unwrap_or_default();
        let source_type = match source_types.get(source_type.as_str()) {
            Some(source_type) => Arc::clone(source_type),
            None => {
                let interned = Arc::<str>::from(source_type.as_str());
                source_types.insert(source_type, Arc::clone(&interned));
                interned
            }
        };
        let context = (bucket_start_us, source_type);
        let count = context_rows.entry(context.clone()).or_default();
        *count = count
            .checked_add(1)
            .context("count rollup context overflow")?;
        row_contexts.push(Some(context));
    }
    for (field, field_path) in COUNT_ROLLUP_FIELDS.iter().zip(&field_paths) {
        if field.source_path != DASHBOARD_BREAKDOWN_FIELD && field_path.is_none() {
            continue;
        }
        for (row, context) in row_contexts.iter().enumerate() {
            let Some((bucket_start_us, source_type)) = context else {
                continue;
            };
            let mut values = if field.source_path == DASHBOARD_BREAKDOWN_FIELD {
                let components = dashboard_paths
                    .iter()
                    .map(|path| {
                        path.as_ref()
                            .and_then(|path| path.strings(row).into_iter().next())
                    })
                    .collect::<Vec<_>>();
                vec![serde_json::to_string(&components)?]
            } else {
                field_path
                    .as_ref()
                    .expect("non-dashboard count-rollup path is compiled")
                    .strings(row)
            };
            if values.len() > 1 {
                values.sort();
                values.dedup();
            }
            if !values.is_empty() {
                let present = present_rows
                    .entry((*bucket_start_us, field.field_id, Arc::clone(source_type)))
                    .or_default();
                *present = present
                    .checked_add(1)
                    .context("count rollup present-row overflow")?;
            }
            for value in values {
                let count = counts
                    .entry((
                        *bucket_start_us,
                        field.field_id,
                        Arc::clone(source_type),
                        Some(value),
                    ))
                    .or_default();
                *count = count.checked_add(1).context("count rollup overflow")?;
            }
        }
    }
    for ((bucket_start_us, source_type), context_count) in context_rows {
        for field in COUNT_ROLLUP_FIELDS {
            let present_count = present_rows
                .get(&(bucket_start_us, field.field_id, Arc::clone(&source_type)))
                .copied()
                .unwrap_or_default();
            let missing_count =
                context_count.checked_sub(present_count).with_context(|| {
                    format!(
                        "count rollup present rows exceed context rows for field {}",
                        field.field_id
                    )
                })?;
            if missing_count > 0 {
                counts.insert(
                    (
                        bucket_start_us,
                        field.field_id,
                        Arc::clone(&source_type),
                        None,
                    ),
                    missing_count,
                );
            }
        }
    }
    Ok(counts)
}

fn build_count_rollup_object(
    object: &LocalObject,
    relative_path: String,
    path: &Path,
    schema: &Arc<Schema>,
    properties: &WriterProperties,
) -> Result<CountRollupObject> {
    // Aggregate one bounded Arrow batch at a time. Count-rollup queries
    // already SUM duplicate keys, so keeping exact partial counts avoids a
    // whole-object map whose resident size reached ~1 GiB for a 103 MiB
    // source pack. Hash aggregation plus deterministic per-batch sorting
    // keeps CPU and memory bounded without changing count semantics.
    let mut source_types = HashMap::<String, Arc<str>>::new();
    let mut writer = ArrowWriter::try_new(
        File::create(path)?,
        Arc::clone(schema),
        Some(properties.clone()),
    )?;
    let mut rows = 0_u64;
    let mut object_min_bucket_start_us = None::<i64>;
    let mut object_max_bucket_start_us = None::<i64>;
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&object.path)?)?
        .with_batch_size(32_768)
        .build()?;
    for batch in reader {
        let batch = batch?;
        let counts = count_rollup_batch_counts(&batch, &mut source_types)?;
        let Some(batch_min_bucket_start_us) = counts.keys().map(|(bucket, _, _, _)| *bucket).min()
        else {
            continue;
        };
        let batch_max_bucket_start_us = counts
            .keys()
            .map(|(bucket, _, _, _)| *bucket)
            .max()
            .expect("nonempty count-rollup batch has a maximum bucket");
        object_min_bucket_start_us = Some(
            object_min_bucket_start_us.map_or(batch_min_bucket_start_us, |current| {
                current.min(batch_min_bucket_start_us)
            }),
        );
        object_max_bucket_start_us = Some(
            object_max_bucket_start_us.map_or(batch_max_bucket_start_us, |current| {
                current.max(batch_max_bucket_start_us)
            }),
        );
        let ordered_counts = ordered_count_rollups(counts);
        rows = rows
            .checked_add(ordered_counts.len() as u64)
            .context("count rollup row overflow")?;
        writer.write(&count_rollup_batch(&ordered_counts)?)?;
    }
    if rows == 0 {
        bail!("count rollup source object contains no timestamped rows");
    }
    writer.close()?;
    let object_min_bucket_start_us =
        object_min_bucket_start_us.context("count rollup part has no minimum bucket")?;
    let object_max_bucket_start_us =
        object_max_bucket_start_us.context("count rollup part has no maximum bucket")?;
    File::open(path)?.sync_all()?;
    let bytes = std::fs::metadata(path)?.len();
    Ok(CountRollupObject {
        object_id: object.position,
        event_object_key: object.stamp.source_uri.clone(),
        event_object_version: object.stamp.version_id.clone(),
        event_object_bytes: object.stamp.size_bytes,
        relative_path,
        min_bucket_start_us: object_min_bucket_start_us,
        max_bucket_start_us: object_max_bucket_start_us,
        rows,
        bytes,
        sha256: file_digest(path)?,
    })
}

fn count_rollup_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new("bucket_start_us", DataType::Int64, false),
        Field::new("field_id", DataType::UInt16, false),
        Field::new("source_type", DataType::Utf8, false),
        Field::new("value", DataType::Utf8, true),
        Field::new("events", DataType::UInt64, false),
    ]))
}

pub(crate) type CountRollupKey = (i64, u16, Arc<str>, Option<String>);
type CountRollupContextKey = (i64, Arc<str>);
type CountRollupPresentKey = (i64, u16, Arc<str>);

fn ordered_count_rollups(counts: HashMap<CountRollupKey, u64>) -> Vec<(CountRollupKey, u64)> {
    let mut counts = counts.into_iter().collect::<Vec<_>>();
    counts.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
    counts
}

fn count_rollup_batch(counts: &[(CountRollupKey, u64)]) -> Result<RecordBatch> {
    let mut bucket_start_us = Int64Builder::with_capacity(counts.len());
    let mut field_id = UInt16Builder::with_capacity(counts.len());
    let mut source_type = StringBuilder::with_capacity(counts.len(), counts.len() * 16);
    let mut value = StringBuilder::with_capacity(counts.len(), counts.len() * 24);
    let mut events = UInt64Builder::with_capacity(counts.len());
    for ((bucket, field, source, field_value), count) in counts {
        bucket_start_us.append_value(*bucket);
        field_id.append_value(*field);
        source_type.append_value(source.as_ref());
        match field_value {
            Some(field_value) => value.append_value(field_value),
            None => value.append_null(),
        }
        events.append_value(*count);
    }
    Ok(RecordBatch::try_new(
        count_rollup_schema(),
        vec![
            Arc::new(bucket_start_us.finish()),
            Arc::new(field_id.finish()),
            Arc::new(source_type.finish()),
            Arc::new(value.finish()),
            Arc::new(events.finish()),
        ],
    )?)
}

fn local_objects(root: &Path, stamps: &ObjectStampManifest) -> Result<Vec<LocalObject>> {
    if stamps.snapshot_id <= 0
        || stamps.objects.is_empty()
        || stamps.objects.len() > u32::MAX as usize
    {
        bail!("object-stamp manifest has an invalid snapshot or object count");
    }
    let mut seen = BTreeSet::new();
    let mut objects = Vec::with_capacity(stamps.objects.len());
    let mut ordered = stamps.objects.clone();
    ordered.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    for (position, stamp) in ordered.into_iter().enumerate() {
        if stamp.relative_path.is_empty()
            || stamp.relative_path.starts_with('/')
            || stamp.relative_path.contains("..")
            || !stamp.source_uri.starts_with("s3://")
            || stamp.version_id.is_empty()
            || stamp.size_bytes == 0
            || !seen.insert(stamp.relative_path.clone())
        {
            bail!("object-stamp manifest contains an invalid object");
        }
        let path = root.join(&stamp.relative_path);
        if std::fs::metadata(&path)?.len() != stamp.size_bytes {
            bail!("local snapshot object size differs from its immutable stamp");
        }
        let position = u32::try_from(position).context("snapshot object position overflow")?;
        objects.push(LocalObject {
            // Degenerate identity for builds without a prior generation (and
            // for the standalone count-rollup path, which never embeds ids in
            // artifact bytes). `assign_stable_object_ids` replaces this with
            // the persisted allocator's identity whenever a prior entity
            // manifest exists.
            id: position,
            position,
            path,
            stamp,
        });
    }
    Ok(objects)
}

/// Assign each snapshot object its STABLE artifact id from the persisted
/// allocator carried in the prior generation's entity manifest: an object that
/// existed before keeps its id, a new object takes the next never-used id.
/// Because the id is a function of the object's immutable identity and not of
/// its position in the path-sorted snapshot, retiring or inserting a
/// neighbour never changes any surviving object's id — which is what lets
/// every per-object derivative be reused byte-for-byte instead of rewritten.
///
/// Fails closed if the resulting assignment is not injective: a duplicated id
/// would conflate two objects' postings and corrupt candidate sets, so a
/// build must never survive one.
fn assign_stable_object_ids(
    objects: &mut [LocalObject],
    prior: Option<&PriorEntitySidecar>,
) -> Result<u32> {
    let Some(prior) = prior else {
        // Fresh lineage: ids equal positions (already assigned) and the
        // allocator starts after them.
        let mut seen = BTreeSet::new();
        for object in objects.iter() {
            if !seen.insert(object.id) {
                bail!("stable object id assignment produced a duplicate id");
            }
        }
        return u32::try_from(objects.len()).context("stable object id space is exhausted");
    };
    let mut next_object_id = prior.next_object_id;
    for object in objects.iter_mut() {
        if let Some(reused) = prior.objects.get(&stamp_identity(&object.stamp)) {
            object.id = reused.build.object_id;
        } else {
            object.id = next_object_id;
            next_object_id = next_object_id
                .checked_add(1)
                .context("stable object id space is exhausted")?;
        }
    }
    let mut seen = BTreeSet::new();
    for object in objects.iter() {
        if !seen.insert(object.id) {
            bail!(
                "stable object id assignment produced a duplicate id; the prior entity manifest allocator state is corrupt"
            );
        }
    }
    Ok(next_object_id)
}

fn prior_entity_sidecar(
    directory: Option<&Path>,
    tenant_id: &str,
    key_id: &str,
) -> Result<Option<PriorEntitySidecar>> {
    let Some(directory) = directory.filter(|path| path.is_dir()) else {
        return Ok(None);
    };
    let manifest: Value =
        match serde_json::from_slice(&std::fs::read(directory.join("manifest.json"))?) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
    let value_hash_bytes = match (
        manifest.get("index_version").and_then(Value::as_str),
        manifest.get("value_hash_bytes").and_then(Value::as_u64),
    ) {
        // v1 stored the full HMAC and never declared a width.
        (Some(ENTITY_INDEX_VERSION_V1), None) => 32_usize,
        // v2 must declare exactly the width this builder writes; any other
        // declared width is a format this code does not understand.
        (Some(ENTITY_INDEX_VERSION_V2), Some(width))
            if width as usize == ENTITY_VALUE_HASH_BYTES =>
        {
            ENTITY_VALUE_HASH_BYTES
        }
        _ => return Ok(None),
    };
    if manifest.get("tenant_id").and_then(Value::as_str) != Some(tenant_id)
        || manifest.get("key_id").and_then(Value::as_str) != Some(key_id)
        || manifest
            .get("normalization_version")
            .and_then(Value::as_str)
            != Some(NORMALIZATION_VERSION)
        || manifest.get("hash_algorithm").and_then(Value::as_str) != Some("hmac-sha256")
        || manifest.get("plaintext_values").and_then(Value::as_bool) != Some(false)
        || manifest.get("field_specs") != Some(&serde_json::to_value(ENTITY_FIELDS)?)
    {
        return Ok(None);
    }
    let mut objects_by_id = BTreeMap::new();
    for (position, object) in manifest
        .get("objects")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .enumerate()
    {
        let Some(id) = object
            .get("object_id")
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
        else {
            return Ok(None);
        };
        if objects_by_id
            .insert(id, (position, object.clone()))
            .is_some()
        {
            return Ok(None);
        }
    }
    let mut builds_by_id = BTreeMap::new();
    for build in manifest
        .get("object_builds")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let build: ObjectBuild = serde_json::from_value(build.clone())?;
        if build.sha256.len() != 64
            || build
                .sha256
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
            || builds_by_id.insert(build.object_id, build).is_some()
        {
            return Ok(None);
        }
    }
    if objects_by_id.is_empty() || objects_by_id.len() != builds_by_id.len() {
        return Ok(None);
    }
    let mut objects = BTreeMap::new();
    for (object_id, (position, manifest)) in objects_by_id {
        let Some(build) = builds_by_id.remove(&object_id) else {
            return Ok(None);
        };
        let Some(event_object_key) = manifest
            .get("event_object_key")
            .and_then(Value::as_str)
            .filter(|value| value.starts_with("s3://"))
        else {
            return Ok(None);
        };
        let Some(event_object_version) = manifest
            .get("event_object_version")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let Some(event_object_bytes) = manifest
            .get("event_object_bytes")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0)
        else {
            return Ok(None);
        };
        let identity = (
            event_object_key.to_string(),
            event_object_version.to_string(),
            event_object_bytes,
        );
        if objects
            .insert(
                identity,
                PriorEntityObject {
                    manifest,
                    build,
                    artifact_name: format!("object-{position:04}.parquet"),
                },
            )
            .is_some()
        {
            return Ok(None);
        }
    }
    if !builds_by_id.is_empty() {
        return Ok(None);
    }
    // Stable-id generations declare their id model and persist the allocator
    // high-water mark. Pre-stable generations (ordinal UInt16 ids) omit both;
    // their dense 0..n-1 ordinals seed the allocator exactly, so every
    // existing object keeps its last ordinal as its stable id forever.
    let object_id_width = match manifest.get("object_id_model").and_then(Value::as_str) {
        Some(OBJECT_ID_MODEL) => 32_u32,
        Some(_) => return Ok(None),
        None => {
            // Pre-stable ordinal manifests predate v2; a v2 manifest without
            // its id model is corrupt.
            if value_hash_bytes == ENTITY_VALUE_HASH_BYTES {
                return Ok(None);
            }
            16
        }
    };
    let max_object_id = objects
        .values()
        .map(|object| object.build.object_id)
        .max()
        .unwrap_or(0);
    let next_object_id = match manifest.get("next_object_id").and_then(Value::as_u64) {
        Some(value) => {
            let Ok(value) = u32::try_from(value) else {
                return Ok(None);
            };
            // The persisted allocator can never sit at or below an id it has
            // already handed out; such a manifest is corrupt and unusable.
            if value <= max_object_id {
                return Ok(None);
            }
            value
        }
        None => {
            if object_id_width == 32 {
                // A stable-id manifest without its allocator is corrupt.
                return Ok(None);
            }
            // Ordinal manifests are dense, so max + 1 is the exact high water.
            max_object_id
                .checked_add(1)
                .context("stable object id space is exhausted")?
        }
    };
    Ok(Some(PriorEntitySidecar {
        directory: directory.to_path_buf(),
        objects,
        object_id_width,
        next_object_id,
        value_hash_bytes,
    }))
}

fn prior_count_rollups(
    directory: Option<&Path>,
    tenant_id: &str,
) -> Result<Option<PriorCountRollups>> {
    let Some(directory) = directory.filter(|path| path.is_dir()) else {
        return Ok(None);
    };
    let manifest: CountRollupManifest =
        match serde_json::from_slice(&std::fs::read(directory.join("manifest.json"))?) {
            Ok(value) => value,
            Err(_) => return Ok(None),
        };
    if manifest.schema_version != 1
        || manifest.rollup_version != COUNT_ROLLUP_VERSION
        || manifest.tenant_id != tenant_id
        || manifest.bucket_width_us != COUNT_ROLLUP_BUCKET_US
        || manifest.fields
            != COUNT_ROLLUP_FIELDS
                .iter()
                .map(|field| CountRollupManifestField {
                    field_id: field.field_id,
                    source_path: field.source_path.to_string(),
                    multi_value: field.multi_value,
                })
                .collect::<Vec<_>>()
    {
        return Ok(None);
    }
    let mut parts = BTreeMap::new();
    for part in manifest.objects {
        if part.relative_path != format!("object-{:04}.parquet", part.object_id)
            || !part.event_object_key.starts_with("s3://")
            || part.event_object_version.is_empty()
            || part.event_object_bytes == 0
            || part.sha256.len() != 64
            || part
                .sha256
                .bytes()
                .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
        {
            return Ok(None);
        }
        let identity = (
            part.event_object_key.clone(),
            part.event_object_version.clone(),
            part.event_object_bytes,
        );
        if parts.insert(identity, part).is_some() {
            return Ok(None);
        }
    }
    if parts.is_empty() {
        return Ok(None);
    }
    Ok(Some(PriorCountRollups {
        directory: directory.to_path_buf(),
        parts,
    }))
}

/// Reuse an immutable, content-addressed derivative artifact by hard link.
///
/// NAN-2361 integrity trade: the artifact's sha256 was PROVEN when it was
/// built (file_digest immediately after the write) and is recorded in the
/// prior generation's manifest; this path no longer re-reads and re-hashes
/// every reused artifact on every promotion (the former verified_copy did a
/// source hash, a full copy, and a destination hash — three full passes over
/// bytes that never change). What is still proven: the file exists, is a
/// regular file, and has the exact recorded size; the hard link makes the new
/// generation share the very inode whose digest was proven, exactly like the
/// pre-existing Tantivy segment reuse in clone_tantivy_index. What is now
/// assumed: an unchanged inode of the right size still holds the hashed
/// bytes. A same-size in-place corruption defeats the cheap check but is
/// caught by the sampled full re-hash (force_full_verify) within an expected
/// REVERIFY_SAMPLE_DENOMINATOR promotions; any failure here simply rebuilds
/// the artifact from the source snapshot, so detection self-heals.
fn reuse_verified_artifact(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    force_full_verify: bool,
) -> Result<bool> {
    if expected_bytes == 0
        || expected_sha256.len() != 64
        || expected_sha256
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Ok(false);
    }
    let Ok(metadata) = std::fs::metadata(source) else {
        return Ok(false);
    };
    if !metadata.is_file() || metadata.len() != expected_bytes {
        return Ok(false);
    }
    if force_full_verify && file_digest(source)? != expected_sha256 {
        tracing::warn!(
            source = %source.display(),
            "sampled re-verification found a corrupted reusable artifact; rebuilding it"
        );
        return Ok(false);
    }
    if std::fs::hard_link(source, destination).is_err() {
        // Cross-device fallback: one streaming pass that copies and hashes
        // together instead of the former hash + copy + hash triple pass.
        let mut reader = BufReader::new(File::open(source)?);
        let output = File::create(destination)?;
        let mut writer = BufWriter::new(output);
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; 1024 * 1024];
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            writer.write_all(&buffer[..count])?;
        }
        writer.flush()?;
        writer.into_inner()?.sync_all()?;
        if hex::encode(hasher.finalize()) != expected_sha256 {
            std::fs::remove_file(destination).ok();
            return Ok(false);
        }
    }
    Ok(true)
}

fn verified_file(source: &Path, expected_bytes: u64, expected_sha256: &str) -> Result<bool> {
    if expected_bytes == 0
        || expected_sha256.len() != 64
        || expected_sha256
            .bytes()
            .any(|byte| !byte.is_ascii_hexdigit() || byte.is_ascii_uppercase())
    {
        return Ok(false);
    }
    let Ok(metadata) = std::fs::metadata(source) else {
        return Ok(false);
    };
    if metadata.len() != expected_bytes || file_digest(source)? != expected_sha256 {
        return Ok(false);
    }
    Ok(true)
}

/// Rewrite one immutable prior entity artifact into the current layout:
/// verify every row carries exactly `prior_object_id`, restamp it as
/// `object_id` (always emitting the UInt32 stable-id column), truncate a
/// full-width v1 `value_hash` to the stored `ENTITY_VALUE_HASH_BYTES` prefix,
/// merge postings whose truncated hashes collide within one (field, block) —
/// summing `matches` and taking the max `max_time`, exactly the fold a fresh
/// build's per-row-group count map performs — and write in the fresh build's
/// (field, digest, block) order. Returns (bytes, sha256, index rows). This
/// runs only as the one-time migration of a prior-layout artifact; in the
/// steady state a reused artifact is hard-linked untouched.
fn rewrite_entity_artifact(
    source: &Path,
    destination: &Path,
    expected_bytes: u64,
    expected_sha256: &str,
    prior_object_id: u32,
    object_id: u32,
) -> Result<Option<(u64, String, u64)>> {
    if !verified_file(source, expected_bytes, expected_sha256)? {
        return Ok(None);
    }
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(source)?)?;
    let source_schema = builder.schema().clone();
    let Ok(object_id_column) = source_schema.index_of("object_id") else {
        return Ok(None);
    };
    let id_is_u16 = match source_schema.field(object_id_column).data_type() {
        DataType::UInt16 => true,
        DataType::UInt32 => false,
        _ => return Ok(None),
    };
    let Ok(value_hash_column) = source_schema.index_of("value_hash") else {
        return Ok(None);
    };
    let source_hash_bytes = match source_schema.field(value_hash_column).data_type() {
        DataType::FixedSizeBinary(32) => 32_usize,
        DataType::FixedSizeBinary(width) if *width as usize == ENTITY_VALUE_HASH_BYTES => {
            ENTITY_VALUE_HASH_BYTES
        }
        _ => return Ok(None),
    };
    let reader = builder.with_batch_size(8_192).build()?;
    // (field, digest, block) keyed so iteration IS the fresh build's on-disk
    // order; colliding truncations inside one block fold exactly once.
    let mut merged = BTreeMap::<(u8, [u8; ENTITY_VALUE_HASH_BYTES], u32), (u64, u64)>::new();
    for batch in reader {
        let batch = batch?;
        let uniform_prior = if id_is_u16 {
            batch
                .column(object_id_column)
                .as_any()
                .downcast_ref::<UInt16Array>()
                .map(|previous_ids| {
                    previous_ids.null_count() == 0
                        && previous_ids
                            .values()
                            .iter()
                            .all(|value| u32::from(*value) == prior_object_id)
                })
        } else {
            batch
                .column(object_id_column)
                .as_any()
                .downcast_ref::<UInt32Array>()
                .map(|previous_ids| {
                    previous_ids.null_count() == 0
                        && previous_ids
                            .values()
                            .iter()
                            .all(|value| *value == prior_object_id)
                })
        };
        if uniform_prior != Some(true) {
            return Ok(None);
        }
        let (Some(value_hash), Some(field_id), Some(block_id), Some(matches), Some(max_time)) = (
            batch
                .column(value_hash_column)
                .as_any()
                .downcast_ref::<FixedSizeBinaryArray>(),
            batch
                .column_by_name("field_id")
                .and_then(|column| column.as_any().downcast_ref::<UInt8Array>()),
            batch
                .column_by_name("block_id")
                .and_then(|column| column.as_any().downcast_ref::<UInt32Array>()),
            batch
                .column_by_name("matches")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>()),
            batch
                .column_by_name("max_time")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>()),
        ) else {
            return Ok(None);
        };
        for row in 0..batch.num_rows() {
            let digest = value_hash.value(row);
            if digest.len() != source_hash_bytes {
                return Ok(None);
            }
            let mut stored = [0_u8; ENTITY_VALUE_HASH_BYTES];
            stored.copy_from_slice(&digest[..ENTITY_VALUE_HASH_BYTES]);
            let entry = merged
                .entry((field_id.value(row), stored, block_id.value(row)))
                .or_default();
            entry.0 = entry
                .0
                .checked_add(matches.value(row))
                .context("entity migration match count overflowed")?;
            entry.1 = entry.1.max(max_time.value(row));
        }
    }
    let postings = merged
        .into_iter()
        .map(|((field_id, digest, block_id), (matches, max_time))| {
            (digest, field_id, object_id, block_id, matches, max_time)
        })
        .collect::<Vec<EntityPosting>>();
    write_entity_postings(destination, &postings)?;
    let bytes = std::fs::metadata(destination)?.len();
    let sha256 = file_digest(destination)?;
    Ok(Some((bytes, sha256, postings.len() as u64)))
}

#[derive(Serialize, Deserialize)]
struct EntityBuildOutput {
    manifest: Value,
    event_rows: u64,
    source_bytes: u64,
    index_bytes: u64,
    max_event_time_us: Option<i64>,
    /// Stable object ids whose derivative artifacts were carried over
    /// from the prior generation instead of being rebuilt (NAN-2361: these
    /// are exactly the objects the incremental uid proof may trust).
    reused_object_ids: BTreeSet<u32>,
}

#[allow(clippy::too_many_arguments)]
fn build_entity(
    input_root: &Path,
    output: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    key_id: &str,
    key: &[u8],
    snapshot_id: i64,
    objects: &[LocalObject],
    prior: Option<PriorEntitySidecar>,
    next_object_id: u32,
    threads: usize,
) -> Result<EntityBuildOutput> {
    let started = Instant::now();
    let mut manifest_objects = Vec::<(u32, Value)>::new();
    let mut builds = Vec::<(u32, ObjectBuild)>::new();
    let mut event_rows = 0_u64;
    let mut source_bytes = 0_u64;
    let mut index_rows = 0_u64;
    let mut index_bytes = 0_u64;
    let mut max_event_time_us = None::<i64>;
    let mut reused_objects = 0_usize;
    let mut reused_object_ids = BTreeSet::new();
    let mut pending = Vec::new();
    for object in objects {
        let object_started = Instant::now();
        let destination = output.join(format!("object-{:04}.parquet", object.position));
        if let Some((prior_sidecar, reused)) = prior.as_ref().and_then(|sidecar| {
            sidecar
                .objects
                .get(&stamp_identity(&object.stamp))
                .map(|reused| (sidecar, reused))
        }) {
            let identity_matches = reused.manifest.get("relative_path").and_then(Value::as_str)
                == Some(object.stamp.relative_path.as_str())
                && reused
                    .manifest
                    .get("event_object_key")
                    .and_then(Value::as_str)
                    == Some(object.stamp.source_uri.as_str())
                && reused
                    .manifest
                    .get("event_object_version")
                    .and_then(Value::as_str)
                    == Some(object.stamp.version_id.as_str())
                && reused
                    .manifest
                    .get("event_object_bytes")
                    .and_then(Value::as_u64)
                    == Some(object.stamp.size_bytes);
            if identity_matches {
                // The allocator was seeded from this exact prior manifest, so
                // an unchanged object's stable id can never differ from its
                // prior artifact's id. A mismatch means the id assignment and
                // the reuse path read different states — reusing under a
                // different id would conflate postings, so fail closed.
                if reused.build.object_id != object.id {
                    bail!(
                        "stable object id diverged from the prior entity manifest for {}",
                        object.stamp.source_uri
                    );
                }
                let source = prior_sidecar.directory.join(&reused.artifact_name);
                let mut reused_build = reused.build.clone();
                let artifact_reused = if prior_sidecar.object_id_width == 32
                    && prior_sidecar.value_hash_bytes == ENTITY_VALUE_HASH_BYTES
                {
                    // Steady state: the id is stable and already embedded in
                    // the immutable artifact — a position shift only changes
                    // the FILENAME, repaired by the hard link below.
                    reuse_verified_artifact(
                        &source,
                        &destination,
                        reused_build.bytes,
                        &reused_build.sha256,
                        sample_reverify(snapshot_id, &object.stamp.source_uri),
                    )?
                } else if let Some((bytes, sha256, rows)) = rewrite_entity_artifact(
                    &source,
                    &destination,
                    reused_build.bytes,
                    &reused_build.sha256,
                    reused_build.object_id,
                    object.id,
                )? {
                    // One-time, deliberate migration of a prior-layout
                    // artifact: a pre-stable UInt16 ordinal id widens to the
                    // stable UInt32 layout (the id VALUE is preserved), and a
                    // full-width v1 value_hash is truncated to the stored
                    // prefix (postings whose prefixes collide within one
                    // block merge exactly as a fresh build would merge them).
                    tracing::info!(
                        source_uri = %object.stamp.source_uri,
                        object_id = object.id,
                        "migrating entity sidecar artifact to the current stable-id truncated-hash layout"
                    );
                    reused_build.bytes = bytes;
                    reused_build.sha256 = sha256;
                    reused_build.rows = rows;
                    reused_build.seconds = object_started.elapsed().as_secs_f64();
                    true
                } else {
                    false
                };
                if artifact_reused {
                    reused_build.object_id = object.id;
                    event_rows = event_rows
                        .checked_add(
                            reused
                                .manifest
                                .get("rows")
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                        )
                        .context("entity event row overflow")?;
                    source_bytes = source_bytes
                        .checked_add(object.stamp.size_bytes)
                        .context("entity source byte overflow")?;
                    index_rows = index_rows
                        .checked_add(reused_build.rows)
                        .context("entity index row overflow")?;
                    index_bytes = index_bytes
                        .checked_add(reused_build.bytes)
                        .context("entity index byte overflow")?;
                    max_event_time_us = match (max_event_time_us, reused_build.max_event_time_us) {
                        (Some(left), Some(right)) => Some(left.max(right)),
                        (None, value) | (value, None) => value,
                    };
                    let mut reused_manifest = reused.manifest.clone();
                    let reused_manifest = reused_manifest
                        .as_object_mut()
                        .context("prior entity object is not a JSON object")?;
                    reused_manifest.insert("object_id".to_string(), json!(object.id));
                    reused_manifest.insert(
                        "relative_path".to_string(),
                        json!(object.stamp.relative_path),
                    );
                    manifest_objects
                        .push((object.position, Value::Object(reused_manifest.clone())));
                    builds.push((object.position, reused_build));
                    reused_objects += 1;
                    reused_object_ids.insert(object.id);
                    continue;
                }
            }
        }
        pending.push(object);
    }
    // A generation may contain hundreds of independently immutable Parquet
    // objects. Building their entity sidecars serially left every configured
    // worker thread but one idle and made the generation manager fall behind
    // even 1-TB/day ingest. Each task reads one source object and writes one
    // disjoint artifact, so bounded object-level parallelism preserves exact
    // bytes and ordering while using the capacity the operator assigned.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|index| format!("entity-sidecar-{index}"))
        .build()
        .context("build bounded entity-sidecar worker pool")?;
    let built = pool.install(|| {
        pending
            .par_iter()
            .map(|object| build_entity_object(object, output, key))
            .collect::<Result<Vec<_>>>()
    })?;
    for built in built {
        event_rows = event_rows
            .checked_add(built.event_rows)
            .context("entity event row overflow")?;
        source_bytes = source_bytes
            .checked_add(built.source_bytes)
            .context("entity source byte overflow")?;
        index_rows = index_rows
            .checked_add(built.build.rows)
            .context("entity index row overflow")?;
        index_bytes = index_bytes
            .checked_add(built.build.bytes)
            .context("entity index byte overflow")?;
        max_event_time_us = match (max_event_time_us, built.build.max_event_time_us) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (None, value) | (value, None) => value,
        };
        manifest_objects.push((built.position, built.manifest));
        builds.push((built.position, built.build));
    }
    manifest_objects.sort_unstable_by_key(|(position, _)| *position);
    builds.sort_unstable_by_key(|(position, _)| *position);
    let manifest_objects = manifest_objects
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    let builds = builds
        .into_iter()
        .map(|(_, value)| value)
        .collect::<Vec<_>>();
    let manifest = json!({
        "index_version": ENTITY_INDEX_VERSION_V2,
        "tenant_id": tenant_id,
        "key_id": key_id,
        "normalization_version": NORMALIZATION_VERSION,
        "normalization": "trim then lowercase; promoted IP text is canonical at compaction",
        "hash_algorithm": "hmac-sha256",
        // Stored per-row hash width: the leading bytes of the full HMAC. The
        // probe truncates its full hash identically, so stored-prefix
        // equality selects a superset of full-hash equality (recheck-safe).
        "value_hash_bytes": ENTITY_VALUE_HASH_BYTES,
        "plaintext_values": false,
        "object_id_model": OBJECT_ID_MODEL,
        "next_object_id": next_object_id,
        "granularity": "exact count per entity role, immutable object, and aligned block",
        "input_root": input_root,
        "source_uri_prefix": Value::Null,
        "object_stamp_manifest": stamp_manifest,
        "field_specs": ENTITY_FIELDS,
        "objects": manifest_objects,
        "source_files": objects.len(),
        "source_bytes": source_bytes,
        "event_rows": event_rows,
        "index_rows": index_rows,
        "index_bytes": index_bytes,
        "build_seconds": started.elapsed().as_secs_f64(),
        "reused_objects": reused_objects,
        "built_objects": objects.len() - reused_objects,
        "object_builds": builds,
    });
    Ok(EntityBuildOutput {
        manifest,
        event_rows,
        source_bytes,
        index_bytes,
        max_event_time_us,
        reused_object_ids,
    })
}

struct EntityObjectBuild {
    position: u32,
    manifest: Value,
    build: ObjectBuild,
    event_rows: u64,
    source_bytes: u64,
}

fn build_entity_object(
    object: &LocalObject,
    output: &Path,
    key: &[u8],
) -> Result<EntityObjectBuild> {
    let object_started = Instant::now();
    let destination = output.join(format!("object-{:04}.parquet", object.position));
    let source = File::open(&object.path)?;
    let builder = ParquetRecordBatchReaderBuilder::try_new(source)?;
    let schema = builder.schema().clone();
    let metadata = builder.metadata().clone();
    let rows = metadata.file_metadata().num_rows() as u64;
    let mut row_ranges = Vec::new();
    let mut postings = Vec::new();
    let mut object_max_event_time_us = None::<i64>;
    let mut row_start = 0_u64;
    for row_group in 0..metadata.num_row_groups() {
        let row_count = metadata.row_group(row_group).num_rows() as usize;
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&object.path)?)?
            .with_row_groups(vec![row_group])
            .with_batch_size(DERIVATIVE_PARQUET_BATCH_ROWS.min(row_count.max(1)))
            .build()?;
        let mut counts = BTreeMap::<(u8, [u8; ENTITY_VALUE_HASH_BYTES]), (u64, u64)>::new();
        for batch in reader {
            let batch = batch?;
            // Resolve every Arrow path once per batch. The former row-first
            // loop split and walked all 41 schema paths for every row (and
            // cloned intermediate ArrayRefs), accounting for millions of
            // identical schema traversals per immutable object.
            let field_paths = ENTITY_FIELDS
                .iter()
                .map(|field| {
                    (!field.source_path.ends_with(".hashes.value"))
                        .then(|| CompiledStringPath::new(&batch, field.source_path))
                        .flatten()
                })
                .collect::<Vec<_>>();
            let time = batch
                .schema()
                .index_of("time")
                .ok()
                .map(|index| batch.column(index));
            let mut timestamps = Vec::with_capacity(batch.num_rows());
            for row in 0..batch.num_rows() {
                let timestamp_ms = time
                    .map(|array| event_time_ms_from_array(array.as_ref(), row))
                    .unwrap_or(0);
                timestamps.push(timestamp_ms);
                if let Some(timestamp_us) =
                    time.and_then(|array| event_time_us_from_array(array.as_ref(), row))
                {
                    object_max_event_time_us = Some(
                        object_max_event_time_us
                            .map_or(timestamp_us, |value| value.max(timestamp_us)),
                    );
                }
            }
            for (field, field_path) in ENTITY_FIELDS.iter().zip(&field_paths) {
                if !field.source_path.ends_with(".hashes.value") && field_path.is_none() {
                    continue;
                }
                for (row, timestamp) in timestamps.iter().copied().enumerate() {
                    let values = if field_path.is_none() {
                        sha256_values(&batch, row, field.source_path)
                    } else {
                        field_path
                            .as_ref()
                            .expect("non-hash entity path is compiled")
                            .strings(row)
                    };
                    for value in values {
                        let canonical = canonicalize(&value, field.kind);
                        if canonical.is_empty() {
                            continue;
                        }
                        let digest = stored_entity_digest(entity_digest(key, &canonical)?);
                        let entry = counts.entry((field.field_id, digest)).or_default();
                        entry.0 += 1;
                        entry.1 = entry.1.max(timestamp);
                    }
                }
            }
        }
        for ((field_id, digest), (matches, max_time)) in counts {
            postings.push((
                digest,
                field_id,
                object.id,
                row_group as u32,
                matches,
                max_time,
            ));
        }
        let row_end = row_start + row_count as u64;
        row_ranges
            .push(json!({"row_group": row_group, "row_start": row_start, "row_end": row_end}));
        row_start = row_end;
    }
    // (field, digest, block) order clusters every repeat of a digest
    // adjacently (measured 1.57 rows per distinct hash on the deployed
    // sidecar), which zstd then folds, and gives the probe's equality filter
    // monotonic per-row-group value_hash statistics to prune on. The order of
    // rows inside the artifact carries no meaning: the probe SQL sorts its
    // own output and the uid proof buckets by digest.
    postings
        .sort_unstable_by(|left, right| (left.1, left.0, left.3).cmp(&(right.1, right.0, right.3)));
    write_entity_postings(&destination, &postings)?;
    let bytes = std::fs::metadata(&destination)?.len();
    let sha256 = file_digest(&destination)?;
    let field_types = schema_leaf_types(schema.as_ref());
    let column_compressed_bytes = parquet_column_compressed_bytes(metadata.as_ref())?;
    let build = ObjectBuild {
        object_id: object.id,
        rows: postings.len() as u64,
        bytes,
        seconds: object_started.elapsed().as_secs_f64(),
        sha256,
        max_event_time_us: object_max_event_time_us,
    };
    Ok(EntityObjectBuild {
        position: object.position,
        manifest: json!({
            "object_id": object.id,
            "relative_path": object.stamp.relative_path,
            "event_object_key": object.stamp.source_uri,
            "event_object_version": object.stamp.version_id,
            "event_object_bytes": object.stamp.size_bytes,
            "rows": rows,
            "row_groups": metadata.num_row_groups(),
            "row_group_ranges": row_ranges,
            "available_paths": field_types.keys().collect::<Vec<_>>(),
            "field_types": field_types,
            "column_compressed_bytes": column_compressed_bytes,
        }),
        build,
        event_rows: rows,
        source_bytes: object.stamp.size_bytes,
    })
}

fn parquet_column_compressed_bytes(metadata: &ParquetMetaData) -> Result<BTreeMap<String, u64>> {
    let mut output = BTreeMap::<String, u64>::new();
    for row_group in metadata.row_groups() {
        for column in row_group.columns() {
            let path = column
                .column_path()
                .parts()
                .iter()
                .filter(|part| !matches!(part.as_str(), "list" | "element"))
                .cloned()
                .collect::<Vec<_>>()
                .join(".");
            let bytes = u64::try_from(column.compressed_size())
                .context("Parquet column compressed size is negative")?;
            let total = output.entry(path).or_default();
            *total = total
                .checked_add(bytes)
                .context("Parquet column compressed byte total overflowed")?;
        }
    }
    if output.is_empty() {
        bail!("Parquet object has no physical column byte metadata");
    }
    Ok(output)
}

type EntityPosting = ([u8; ENTITY_VALUE_HASH_BYTES], u8, u32, u32, u64, u64);

fn write_entity_postings(path: &Path, rows: &[EntityPosting]) -> Result<()> {
    let mut value_hash = FixedSizeBinaryBuilder::with_capacity(
        rows.len(),
        i32::try_from(ENTITY_VALUE_HASH_BYTES).context("entity hash width overflow")?,
    );
    let mut field_id = UInt8Builder::with_capacity(rows.len());
    let mut object_id = UInt32Builder::with_capacity(rows.len());
    let mut block_id = UInt32Builder::with_capacity(rows.len());
    let mut matches = UInt64Builder::with_capacity(rows.len());
    let mut max_time = UInt64Builder::with_capacity(rows.len());
    for row in rows {
        value_hash.append_value(row.0)?;
        field_id.append_value(row.1);
        object_id.append_value(row.2);
        block_id.append_value(row.3);
        matches.append_value(row.4);
        max_time.append_value(row.5);
    }
    let schema = Arc::new(Schema::new(vec![
        Field::new(
            "value_hash",
            DataType::FixedSizeBinary(
                i32::try_from(ENTITY_VALUE_HASH_BYTES).context("entity hash width overflow")?,
            ),
            false,
        ),
        Field::new("field_id", DataType::UInt8, false),
        Field::new("object_id", DataType::UInt32, false),
        Field::new("block_id", DataType::UInt32, false),
        Field::new("matches", DataType::UInt64, false),
        Field::new("max_time", DataType::UInt64, false),
    ]));
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(value_hash.finish()),
            Arc::new(field_id.finish()),
            Arc::new(object_id.finish()),
            Arc::new(block_id.finish()),
            Arc::new(matches.finish()),
            Arc::new(max_time.finish()),
        ],
    )?;
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(262_144))
        .build();
    let mut writer = ArrowWriter::try_new(File::create(path)?, schema, Some(properties))?;
    writer.write(&batch)?;
    writer.close()?;
    File::open(path)?.sync_all()?;
    Ok(())
}

struct UidProofResult {
    uid_rows: u64,
    mode: &'static str,
    algorithm: &'static str,
}

/// Persisted summary of a completed metadata.uid uniqueness proof.
///
/// NAN-2361: the ledger is what lets promotion N+1 prove uniqueness for NEW
/// objects without re-reading every entity sidecar in the table. It records,
/// per immutable source object identity, how many uid rows that object
/// contributed, plus one sorted on-disk file of every (uid digest, max event
/// time) pair whose event time falls inside UID_WINDOW_DAYS of the newest
/// event. The window file is content-addressed by `window_sha256` and is
/// re-verified byte-for-byte on every incremental use (it is read in full
/// anyway), so a corrupted window can never silently pass or fail the proof —
/// it falls back to the full partitioned proof instead.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UidLedgerManifest {
    schema_version: u64,
    tenant_id: String,
    algorithm: String,
    field: String,
    window_days: u64,
    window_cutoff_ms: u64,
    window_records: u64,
    window_sha256: String,
    /// Wall-clock time of the last FULL O(table) proof this ledger descends
    /// from. Incremental proofs refuse ledgers older than
    /// UID_FULL_PROOF_MAX_AGE_MS so the exact global property is re-proven on
    /// a bounded cadence.
    full_proof_unix_ms: u64,
    objects: Vec<UidLedgerObject>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct UidLedgerObject {
    event_object_key: String,
    event_object_version: String,
    event_object_bytes: u64,
    uid_rows: u64,
    max_event_time_ms: u64,
}

enum UidIncrementalOutcome {
    Proven(u64),
    Incompatible(String),
}

fn unix_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Stream the metadata.uid postings of one entity sidecar object.
fn stream_uid_postings(
    sidecar: &Path,
    mut visit: impl FnMut(UidDigest, u32, u64, u64) -> Result<()>,
) -> Result<()> {
    const EVENT_UID_FIELD_ID: u8 = 39;
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(sidecar)?)?
        .with_batch_size(262_144)
        .build()?;
    for batch in reader {
        let batch = batch?;
        let value_hash = batch
            .column_by_name("value_hash")
            .and_then(|column| column.as_any().downcast_ref::<FixedSizeBinaryArray>())
            .context("entity sidecar value_hash is not fixed-size binary")?;
        let field_id = batch
            .column_by_name("field_id")
            .and_then(|column| column.as_any().downcast_ref::<UInt8Array>())
            .context("entity sidecar field_id is not UInt8")?;
        let object_id = batch
            .column_by_name("object_id")
            .and_then(|column| column.as_any().downcast_ref::<UInt32Array>())
            .context("entity sidecar object_id is not UInt32")?;
        let matches = batch
            .column_by_name("matches")
            .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
            .context("entity sidecar matches is not UInt64")?;
        let max_time = batch
            .column_by_name("max_time")
            .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
            .context("entity sidecar max_time is not UInt64")?;
        for row in 0..batch.num_rows() {
            if field_id.value(row) != EVENT_UID_FIELD_ID {
                continue;
            }
            let digest = value_hash.value(row);
            // The proof runs only over artifacts this builder just wrote, so
            // the stored width is always the truncated prefix; the record
            // carries it verbatim (bucket routing keys on digest[0], which
            // keeps its real entropy).
            if digest.len() != ENTITY_VALUE_HASH_BYTES {
                bail!("event UID digest width does not match the stored entity hash width");
            }
            let mut fixed = [0_u8; ENTITY_VALUE_HASH_BYTES];
            fixed.copy_from_slice(digest);
            visit(
                fixed,
                object_id.value(row),
                matches.value(row),
                max_time.value(row),
            )?;
        }
    }
    Ok(())
}

fn read_uid_window_record(
    reader: &mut impl Read,
    hasher: &mut Sha256,
) -> Result<Option<(UidDigest, u64)>> {
    let mut record = [0_u8; UID_WINDOW_RECORD_BYTES];
    let first = reader.read(&mut record[..1])?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut record[1..])?;
    hasher.update(record);
    let mut digest = [0_u8; ENTITY_VALUE_HASH_BYTES];
    digest.copy_from_slice(&record[..ENTITY_VALUE_HASH_BYTES]);
    let mut time = [0_u8; 8];
    time.copy_from_slice(&record[ENTITY_VALUE_HASH_BYTES..]);
    Ok(Some((digest, u64::from_le_bytes(time))))
}

/// Prove the serving snapshot has exactly one physical row for every OCSF
/// `metadata.uid`, at a cost proportional to NEW objects whenever a prior
/// proof's ledger is reusable (NAN-2361).
///
/// Incremental mode — what is still PROVEN, exactly: new objects contain no
/// duplicate uid among themselves, and no duplicate against any previously
/// proven uid whose event time is within UID_WINDOW_DAYS of the newest event;
/// total uid coverage still equals the physical event row count. What is now
/// ASSUMED instead of re-proven: the reused objects' uids are mutually unique
/// — attested by the prior generation's activated proof over the exact same
/// immutable object identities — and a NEW duplicate of an event OLDER than
/// the window is not detected until the next full proof (forced at least
/// every UID_FULL_PROOF_MAX_AGE_MS). For that assumption to be violated, a
/// previously activated generation would have to have attested a false proof,
/// or an ingest path would have to re-emit an event more than
/// UID_WINDOW_DAYS after the original — a case ClickHouse deployments
/// (per-insert-block dedup only) never detect at all. Any coverage, identity,
/// age, or content-digest mismatch falls back to the full exact proof.
///
/// The prior ledger may cover objects the snapshot no longer serves
/// (retention delete snapshots): such drops stay incremental ONLY when every
/// dropped object's max event time is strictly before the prior window
/// cutoff, i.e. it provably contributed nothing to the window being merged
/// against. Nothing new is assumed by such a drop — its rows are deleted (the
/// physical row-count equality still enforces exactly that) and its window
/// absence is a proven property of the prior ledger. A drop reaching into the
/// window falls back to the full exact proof.
///
/// Full mode retains the original property: a partitioned exact-set proof
/// over every posting in the table, and additionally seeds the ledger.
#[allow(clippy::too_many_arguments)]
fn verify_unique_event_uids(
    entity_root: &Path,
    ledger_output: &Path,
    prior_ledger: Option<&Path>,
    tenant_id: &str,
    objects: &[LocalObject],
    reused_object_ids: &BTreeSet<u32>,
    heap_bytes: usize,
    expected_rows: u64,
) -> Result<UidProofResult> {
    if objects.is_empty() {
        bail!("event UID uniqueness proof has no entity sidecar objects");
    }
    if let Some(prior) = prior_ledger {
        match try_incremental_uid_proof(
            entity_root,
            ledger_output,
            prior,
            tenant_id,
            objects,
            reused_object_ids,
            heap_bytes,
            expected_rows,
        )? {
            UidIncrementalOutcome::Proven(uid_rows) => {
                return Ok(UidProofResult {
                    uid_rows,
                    mode: "incremental",
                    algorithm: UID_LEDGER_ALGORITHM,
                });
            }
            UidIncrementalOutcome::Incompatible(reason) => {
                tracing::info!(
                    reason,
                    "incremental event UID proof unavailable; running the full partitioned proof"
                );
            }
        }
    }
    let outcome = full_uid_proof(
        entity_root,
        ledger_output,
        tenant_id,
        objects,
        heap_bytes,
        expected_rows,
    )?;
    tracing::info!(
        uid_rows = outcome.uid_rows,
        bucket_shift = outcome.bucket_shift,
        buckets = outcome.buckets,
        spilled_sort_runs = outcome.spilled_sort_runs,
        "full event UID uniqueness proof complete"
    );
    Ok(UidProofResult {
        uid_rows: outcome.uid_rows,
        mode: "full",
        algorithm: "hmac-sha256-partitioned-exact-set-v1",
    })
}

/// Diagnostics of one full partitioned uid proof. `spilled_sort_runs` counts
/// sorted spill runs beyond the first per bucket: 0 means every bucket was
/// sorted entirely in memory (the pre-NAN-2361 behavior), >0 means the
/// external merge sort bounded a bucket that no longer fit the heap budget.
#[derive(Debug)]
struct UidFullProofOutcome {
    uid_rows: u64,
    bucket_shift: u32,
    buckets: usize,
    spilled_sort_runs: u64,
}

/// Choose the digest-prefix partition layout for a full uid proof from the
/// heap budget. BUCKETS and the `digest[0] >> shift` bucketing are ONE
/// decision (see the const assert on UID_PROOF_BUCKET_SHIFT): the runtime
/// assert below re-states that coupling for the now-dynamic value, and the
/// bucket index being the digest's leading bits is what keeps bucket order
/// equal to digest order — the globally sorted window write depends on it.
/// More buckets are used only when the expected per-bucket volume exceeds one
/// in-memory sort chunk; a single digest byte caps the fan-out at 256, and
/// anything still larger is bounded by the external merge sort, never by
/// giving up exactness.
fn uid_proof_bucket_layout(expected_rows: u64, chunk_records: usize) -> (u32, usize) {
    let mut shift = UID_PROOF_BUCKET_SHIFT;
    while shift > 0 && expected_rows / (256_u64 >> shift) > chunk_records as u64 {
        shift -= 1;
    }
    let buckets = 256_usize >> shift;
    // Runtime re-assertion of the const coupling for the dynamic layout:
    // records are routed with digest[0] >> shift, so the partition count must
    // be exactly 2^(8-shift) or postings land outside the proven partitions.
    assert_eq!(
        buckets,
        1_usize << (8 - shift),
        "uid proof bucket count diverged from its digest-prefix shift"
    );
    (shift, buckets)
}

/// Visit every `UID_WINDOW_RECORD_BYTES` (digest, time) record of one proof
/// partition in
/// ascending digest order while materializing at most `chunk_records` records
/// at a time. A partition that fits one chunk is sorted in memory; a larger
/// one is external-merge-sorted: consecutive chunks are sorted and spilled as
/// runs, then streamed back through a k-way merge. Equal digests are emitted
/// adjacently in both paths, so the caller's previous-digest duplicate
/// detection is unaffected by which path ran. Returns the number of sorted
/// runs merged (1 = fully in memory, no spill).
fn visit_uid_bucket_sorted(
    path: &Path,
    chunk_records: usize,
    mut visit: impl FnMut(UidDigest, u64) -> Result<()>,
) -> Result<u64> {
    let total_bytes = std::fs::metadata(path)?.len();
    if total_bytes % UID_WINDOW_RECORD_BYTES as u64 != 0 {
        bail!("event UID proof partition is not record-aligned");
    }
    let total_records = total_bytes / UID_WINDOW_RECORD_BYTES as u64;
    if total_records == 0 {
        return Ok(1);
    }
    let chunk_records = chunk_records.max(1);
    let mut reader = BufReader::new(File::open(path)?);
    let mut read_chunk = |limit: usize| -> Result<Vec<(UidDigest, u64)>> {
        let mut chunk = Vec::with_capacity(limit.min(chunk_records));
        let mut record = [0_u8; UID_WINDOW_RECORD_BYTES];
        while chunk.len() < limit {
            match reader.read(&mut record[..1])? {
                0 => break,
                _ => reader.read_exact(&mut record[1..])?,
            }
            let mut digest = [0_u8; ENTITY_VALUE_HASH_BYTES];
            digest.copy_from_slice(&record[..ENTITY_VALUE_HASH_BYTES]);
            let mut time = [0_u8; 8];
            time.copy_from_slice(&record[ENTITY_VALUE_HASH_BYTES..]);
            chunk.push((digest, u64::from_le_bytes(time)));
        }
        chunk.sort_unstable_by(|left, right| left.0.cmp(&right.0));
        Ok(chunk)
    };
    if total_records <= chunk_records as u64 {
        for (digest, time) in read_chunk(total_records as usize)? {
            visit(digest, time)?;
        }
        return Ok(1);
    }
    // Spill path: the heap bound holds regardless of partition size.
    let runs_dir = tempfile::Builder::new()
        .prefix(".uid-sort-runs-")
        .tempdir_in(path.parent().context("uid proof partition has no parent")?)?;
    let mut run_paths = Vec::new();
    loop {
        let chunk = read_chunk(chunk_records)?;
        if chunk.is_empty() {
            break;
        }
        let run_path = runs_dir
            .path()
            .join(format!("run-{:04}.bin", run_paths.len()));
        let mut writer = BufWriter::new(File::create(&run_path)?);
        for (digest, time) in &chunk {
            writer.write_all(digest)?;
            writer.write_all(&time.to_le_bytes())?;
        }
        writer.flush()?;
        run_paths.push(run_path);
    }
    drop(reader);
    let mut runs = run_paths
        .iter()
        .map(|run| File::open(run).map(|file| BufReader::with_capacity(8 * 1024, file)))
        .collect::<std::io::Result<Vec<_>>>()?;
    // K-way merge via a min-heap keyed on (digest, time, run); equal digests
    // across runs pop consecutively.
    let mut heap = std::collections::BinaryHeap::new();
    let mut merge_hashers = runs.iter().map(|_| Sha256::new()).collect::<Vec<_>>();
    for (index, run) in runs.iter_mut().enumerate() {
        if let Some((digest, time)) = read_uid_window_record(run, &mut merge_hashers[index])? {
            heap.push(std::cmp::Reverse((digest, time, index)));
        }
    }
    let mut merged = 0_u64;
    while let Some(std::cmp::Reverse((digest, time, index))) = heap.pop() {
        visit(digest, time)?;
        merged += 1;
        if let Some((next_digest, next_time)) =
            read_uid_window_record(&mut runs[index], &mut merge_hashers[index])?
        {
            heap.push(std::cmp::Reverse((next_digest, next_time, index)));
        }
    }
    if merged != total_records {
        bail!("event UID proof merge lost records against its partition");
    }
    Ok(run_paths.len() as u64)
}

fn full_uid_proof(
    entity_root: &Path,
    ledger_output: &Path,
    tenant_id: &str,
    objects: &[LocalObject],
    heap_bytes: usize,
    expected_rows: u64,
) -> Result<UidFullProofOutcome> {
    if ledger_output.exists() {
        // An abandoned incremental attempt may have left partial output.
        std::fs::remove_dir_all(ledger_output)?;
    }
    // NAN-2361: the proof's memory use is bounded by the heap budget, never
    // by table size. One sort chunk is the unit of materialization; buckets
    // that exceed it are external-merge-sorted instead of read whole (at the
    // shipped 50GB/day x 365d design size a 1/64th bucket is ~14GB — reading
    // it with std::fs::read was a live activation wedge).
    let chunk_records = (heap_bytes / UID_WINDOW_RECORD_BYTES).max(1);
    let (bucket_shift, bucket_count) = uid_proof_bucket_layout(expected_rows, chunk_records);
    let partitions = tempfile::Builder::new()
        .prefix(".event-uid-proof-")
        .tempdir_in(entity_root)?;
    let mut writers = (0..bucket_count)
        .map(|bucket| {
            File::create(partitions.path().join(format!("bucket-{bucket:03}.bin")))
                .map(BufWriter::new)
        })
        .collect::<std::io::Result<Vec<_>>>()?;

    let mut per_object = objects
        .iter()
        .map(|object| (object.id, (0_u64, 0_u64)))
        .collect::<BTreeMap<u32, (u64, u64)>>();
    let mut uid_rows = 0_u64;
    let mut max_time_ms = 0_u64;
    for object in objects {
        let sidecar = entity_root.join(format!("object-{:04}.parquet", object.position));
        stream_uid_postings(&sidecar, |digest, posting_object_id, occurrences, time| {
            if occurrences == 0 {
                bail!("event UID sidecar contains a zero-occurrence posting");
            }
            let bucket = usize::from(digest[0] >> bucket_shift);
            writers[bucket].write_all(&digest)?;
            writers[bucket].write_all(&time.to_le_bytes())?;
            let tallies = per_object
                .get_mut(&posting_object_id)
                .context("event UID posting references an unknown object")?;
            tallies.0 = tallies
                .0
                .checked_add(occurrences)
                .context("event UID proof row count overflowed")?;
            tallies.1 = tallies.1.max(time);
            uid_rows = uid_rows
                .checked_add(occurrences)
                .context("event UID proof row count overflowed")?;
            max_time_ms = max_time_ms.max(time);
            Ok(())
        })?;
    }
    for writer in &mut writers {
        writer.flush()?;
    }
    drop(writers);

    let window_cutoff_ms = max_time_ms.saturating_sub(UID_WINDOW_MS);
    std::fs::create_dir_all(ledger_output)?;
    let window_path = ledger_output.join("window.uids");
    let mut window_writer = BufWriter::new(File::create(&window_path)?);
    let mut window_hasher = Sha256::new();
    let mut window_records = 0_u64;
    let mut unique_uids = 0_u64;
    // Buckets partition on the digest's leading bits, so visiting buckets in
    // index order and sorting inside each bucket yields one globally sorted
    // stream (asserted by the uid_bucket_coupling test). A digest can never
    // span buckets, so previous-digest duplicate collapsing per bucket is
    // exhaustive.
    let mut spilled_sort_runs = 0_u64;
    for bucket in 0..bucket_count {
        let path = partitions.path().join(format!("bucket-{bucket:03}.bin"));
        let mut previous: Option<UidDigest> = None;
        let runs = visit_uid_bucket_sorted(&path, chunk_records, |digest, time| {
            if previous.is_some_and(|last| last == digest) {
                return Ok(());
            }
            previous = Some(digest);
            unique_uids = unique_uids
                .checked_add(1)
                .context("unique event UID count overflowed")?;
            if time >= window_cutoff_ms {
                window_writer.write_all(&digest)?;
                window_writer.write_all(&time.to_le_bytes())?;
                window_hasher.update(digest);
                window_hasher.update(time.to_le_bytes());
                window_records += 1;
            }
            Ok(())
        })?;
        spilled_sort_runs += runs.saturating_sub(1);
    }
    if uid_rows != expected_rows {
        bail!(
            "Iceberg generation metadata.uid coverage {uid_rows} does not match {expected_rows} event rows"
        );
    }
    let duplicate_rows = uid_rows
        .checked_sub(unique_uids)
        .context("unique event UID count exceeds physical event rows")?;
    if duplicate_rows != 0 {
        bail!(
            "Iceberg generation contains {duplicate_rows} duplicate metadata.uid rows across {uid_rows} physical event rows"
        );
    }
    window_writer.flush()?;
    window_writer.into_inner()?.sync_all()?;
    let mut ledger_objects = objects
        .iter()
        .map(|object| {
            let (rows, max_ms) = per_object.get(&object.id).copied().unwrap_or((0, 0));
            UidLedgerObject {
                event_object_key: object.stamp.source_uri.clone(),
                event_object_version: object.stamp.version_id.clone(),
                event_object_bytes: object.stamp.size_bytes,
                uid_rows: rows,
                max_event_time_ms: max_ms,
            }
        })
        .collect::<Vec<_>>();
    ledger_objects.sort_by(|left, right| left.event_object_key.cmp(&right.event_object_key));
    write_json(
        &ledger_output.join("manifest.json"),
        &UidLedgerManifest {
            schema_version: UID_LEDGER_SCHEMA_VERSION,
            tenant_id: tenant_id.to_string(),
            algorithm: UID_LEDGER_ALGORITHM.to_string(),
            field: "metadata.uid".to_string(),
            window_days: UID_WINDOW_DAYS,
            window_cutoff_ms,
            window_records,
            window_sha256: hex::encode(window_hasher.finalize()),
            full_proof_unix_ms: unix_time_ms(),
            objects: ledger_objects,
        },
    )?;
    Ok(UidFullProofOutcome {
        uid_rows,
        bucket_shift,
        buckets: bucket_count,
        spilled_sort_runs,
    })
}

#[allow(clippy::too_many_arguments)]
fn try_incremental_uid_proof(
    entity_root: &Path,
    ledger_output: &Path,
    prior_ledger: &Path,
    tenant_id: &str,
    objects: &[LocalObject],
    reused_object_ids: &BTreeSet<u32>,
    heap_bytes: usize,
    expected_rows: u64,
) -> Result<UidIncrementalOutcome> {
    use UidIncrementalOutcome::Incompatible;
    if reused_object_ids.is_empty() {
        return Ok(Incompatible("no reusable prior objects".to_string()));
    }
    let manifest = match std::fs::read(prior_ledger.join("manifest.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<UidLedgerManifest>(&bytes).ok())
    {
        Some(manifest) => manifest,
        None => {
            return Ok(Incompatible(
                "prior uid ledger is absent or unreadable".to_string(),
            ));
        }
    };
    if manifest.schema_version != UID_LEDGER_SCHEMA_VERSION
        || manifest.tenant_id != tenant_id
        || manifest.algorithm != UID_LEDGER_ALGORITHM
        || manifest.field != "metadata.uid"
        || manifest.window_days != UID_WINDOW_DAYS
        || manifest.window_sha256.len() != 64
    {
        return Ok(Incompatible(
            "prior uid ledger contract mismatch".to_string(),
        ));
    }
    let now_ms = unix_time_ms();
    // A ledger stamped in the future means the clock stepped backwards; treat
    // it as stale rather than trusting an unverifiable age.
    if now_ms.saturating_sub(manifest.full_proof_unix_ms) > UID_FULL_PROOF_MAX_AGE_MS
        || manifest.full_proof_unix_ms > now_ms.saturating_add(UID_FULL_PROOF_MAX_AGE_MS)
    {
        return Ok(Incompatible("scheduled full uid proof is due".to_string()));
    }
    let mut ledger_objects = BTreeMap::new();
    for object in &manifest.objects {
        let identity = (
            object.event_object_key.clone(),
            object.event_object_version.clone(),
            object.event_object_bytes,
        );
        if ledger_objects.insert(identity, object.clone()).is_some() {
            return Ok(Incompatible(
                "prior uid ledger has duplicate object identities".to_string(),
            ));
        }
    }
    let reused_identities = objects
        .iter()
        .filter(|object| reused_object_ids.contains(&object.id))
        .map(|object| stamp_identity(&object.stamp))
        .collect::<BTreeSet<_>>();
    // NAN-2361: the reused set must be covered by the ledger — a reused
    // object missing from the ledger would leave its uids unchecked, and only
    // the exact full proof can answer safely.
    let ledger_identities = ledger_objects.keys().cloned().collect::<BTreeSet<_>>();
    if !reused_identities.is_subset(&ledger_identities) {
        return Ok(Incompatible(
            "a reused object is absent from the prior uid ledger".to_string(),
        ));
    }
    // The ledger may cover MORE than the reused set: retention publishes a
    // delete snapshot that removes whole objects, so requiring equality would
    // force the full O(table) proof on every retention day. Dropping a
    // covered object is sound exactly when it provably contributed NOTHING to
    // the prior window file: every window record has time >= the PRIOR
    // ledger's window_cutoff_ms (the cutoff that window was written under —
    // NOT this proof's newer cutoff, because the merge below duplicate-checks
    // the delta against the entire prior window and its records carry no
    // object attribution), and every uid in an object has time <= that
    // object's max_event_time_ms. So max_event_time_ms strictly below the
    // prior cutoff means zero of the object's uids are in the window, and
    // forgetting it can neither mask a real duplicate nor fabricate a false
    // one — the only changes are subtracting its uid_rows from coverage
    // (enforced against the served snapshot's physical row count below) and
    // no longer attesting its internal uniqueness, which its deletion made
    // moot. Retention (>=30d) versus the 7d window satisfies this by
    // construction; a drop that reaches into the window (or a recent object
    // rebuilt instead of reused) still forces the exact full proof.
    for identity in ledger_identities.difference(&reused_identities) {
        let dropped = &ledger_objects[identity];
        if dropped.max_event_time_ms >= manifest.window_cutoff_ms {
            return Ok(Incompatible(
                "a dropped object's events reach into the prior uid window".to_string(),
            ));
        }
    }
    // Everything downstream — coverage arithmetic, the carried ledger, and
    // the window-cutoff anchor — must see only the KEPT objects; a dropped
    // object's rows are no longer physically served.
    let kept_objects = manifest
        .objects
        .iter()
        .filter(|object| {
            reused_identities.contains(&(
                object.event_object_key.clone(),
                object.event_object_version.clone(),
                object.event_object_bytes,
            ))
        })
        .cloned()
        .collect::<Vec<_>>();
    let window_path = prior_ledger.join("window.uids");
    let Ok(window_meta) = std::fs::metadata(&window_path) else {
        return Ok(Incompatible("prior uid window file is missing".to_string()));
    };
    let expected_window_bytes = manifest
        .window_records
        .checked_mul(UID_WINDOW_RECORD_BYTES as u64);
    if !window_meta.is_file() || Some(window_meta.len()) != expected_window_bytes {
        return Ok(Incompatible(
            "prior uid window file size does not match its manifest".to_string(),
        ));
    }

    // Read the postings of NEW objects only — this is the O(delta) pass.
    let delta_cap = (heap_bytes / UID_WINDOW_RECORD_BYTES).clamp(1_000_000, 134_217_728);
    let mut delta = Vec::new();
    let mut delta_objects = Vec::new();
    let mut delta_rows = 0_u64;
    let mut duplicate_rows = 0_u64;
    let mut over_cap = false;
    for object in objects
        .iter()
        .filter(|object| !reused_object_ids.contains(&object.id))
    {
        let mut object_rows = 0_u64;
        let mut object_max_ms = 0_u64;
        let sidecar = entity_root.join(format!("object-{:04}.parquet", object.position));
        stream_uid_postings(&sidecar, |digest, _posting_object_id, occurrences, time| {
            if occurrences == 0 {
                bail!("event UID sidecar contains a zero-occurrence posting");
            }
            delta_rows = delta_rows
                .checked_add(occurrences)
                .context("event UID proof row count overflowed")?;
            duplicate_rows += occurrences - 1;
            object_rows = object_rows
                .checked_add(occurrences)
                .context("event UID proof row count overflowed")?;
            object_max_ms = object_max_ms.max(time);
            if delta.len() >= delta_cap {
                over_cap = true;
            } else {
                delta.push((digest, time));
            }
            Ok(())
        })?;
        delta_objects.push(UidLedgerObject {
            event_object_key: object.stamp.source_uri.clone(),
            event_object_version: object.stamp.version_id.clone(),
            event_object_bytes: object.stamp.size_bytes,
            uid_rows: object_rows,
            max_event_time_ms: object_max_ms,
        });
    }
    if over_cap {
        return Ok(Incompatible(
            "new-object uid volume exceeds the incremental proof memory bound".to_string(),
        ));
    }
    delta.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    for pair in delta.windows(2) {
        if pair[0].0 == pair[1].0 {
            duplicate_rows += 1;
        }
    }

    let prior_max_ms = kept_objects
        .iter()
        .map(|object| object.max_event_time_ms)
        .max()
        .unwrap_or(0);
    let delta_max_ms = delta_objects
        .iter()
        .map(|object| object.max_event_time_ms)
        .max()
        .unwrap_or(0);
    let window_cutoff_ms = prior_max_ms.max(delta_max_ms).saturating_sub(UID_WINDOW_MS);

    // Merge the prior sorted window with the sorted delta: one sequential
    // O(window + delta) pass that simultaneously (a) detects every
    // delta-vs-window duplicate, (b) re-verifies the prior window's content
    // digest, and (c) writes the pruned, merged window for the next
    // generation. The window is bounded by the ingest of UID_WINDOW_DAYS, so
    // this cost is independent of total table size.
    std::fs::create_dir_all(ledger_output)?;
    let merge = (|| -> Result<Option<(u64, String)>> {
        let mut reader = BufReader::new(File::open(&window_path)?);
        let mut input_hasher = Sha256::new();
        let mut writer = BufWriter::new(File::create(ledger_output.join("window.uids"))?);
        let mut output_hasher = Sha256::new();
        let mut window_records = 0_u64;
        let mut records_read = 0_u64;
        let mut last_prior: Option<UidDigest> = None;
        let mut delta_iter = delta.iter().peekable();
        let mut prior_next = read_uid_window_record(&mut reader, &mut input_hasher)?;
        let mut emit = |digest: &UidDigest, time: u64| -> Result<()> {
            if time >= window_cutoff_ms {
                writer.write_all(digest)?;
                writer.write_all(&time.to_le_bytes())?;
                output_hasher.update(digest);
                output_hasher.update(time.to_le_bytes());
                window_records += 1;
            }
            Ok(())
        };
        while let Some((prior_digest, prior_time)) = prior_next {
            records_read += 1;
            if last_prior.is_some_and(|last| last >= prior_digest) {
                // The prior window must be strictly ascending; anything else
                // is corruption and only the full proof can answer safely.
                return Ok(None);
            }
            last_prior = Some(prior_digest);
            while let Some(&&(delta_digest, delta_time)) =
                delta_iter.peek().filter(|next| next.0 < prior_digest)
            {
                emit(&delta_digest, delta_time)?;
                delta_iter.next();
            }
            while delta_iter.peek().is_some_and(|next| next.0 == prior_digest) {
                duplicate_rows += 1;
                delta_iter.next();
            }
            emit(&prior_digest, prior_time)?;
            prior_next = read_uid_window_record(&mut reader, &mut input_hasher)?;
        }
        for record in delta_iter {
            emit(&record.0, record.1)?;
        }
        if records_read != manifest.window_records
            || hex::encode(input_hasher.finalize()) != manifest.window_sha256
        {
            return Ok(None);
        }
        writer.flush()?;
        writer.into_inner()?.sync_all()?;
        Ok(Some((
            window_records,
            hex::encode(output_hasher.finalize()),
        )))
    })()?;
    let Some((window_records, window_sha256)) = merge else {
        std::fs::remove_dir_all(ledger_output).ok();
        return Ok(Incompatible(
            "prior uid window failed its content verification".to_string(),
        ));
    };

    let mut uid_rows = delta_rows;
    for object in kept_objects.iter() {
        uid_rows = uid_rows
            .checked_add(object.uid_rows)
            .context("event UID proof row count overflowed")?;
    }
    if uid_rows != expected_rows {
        bail!(
            "Iceberg generation metadata.uid coverage {uid_rows} does not match {expected_rows} event rows"
        );
    }
    if duplicate_rows != 0 {
        bail!(
            "Iceberg generation contains {duplicate_rows} duplicate metadata.uid rows within the {UID_WINDOW_DAYS}-day event-time window across {uid_rows} physical event rows"
        );
    }
    let mut carried = kept_objects;
    carried.extend(delta_objects);
    carried.sort_by(|left, right| left.event_object_key.cmp(&right.event_object_key));
    write_json(
        &ledger_output.join("manifest.json"),
        &UidLedgerManifest {
            schema_version: UID_LEDGER_SCHEMA_VERSION,
            tenant_id: tenant_id.to_string(),
            algorithm: UID_LEDGER_ALGORITHM.to_string(),
            field: "metadata.uid".to_string(),
            window_days: UID_WINDOW_DAYS,
            window_cutoff_ms,
            window_records,
            window_sha256,
            full_proof_unix_ms: manifest.full_proof_unix_ms,
            objects: carried,
        },
    )?;
    Ok(UidIncrementalOutcome::Proven(uid_rows))
}

/// Build the immutable point-in-time IP identity lane for one exact event
/// snapshot. The snapshot is anchored to the newest event in the generation,
/// rather than wall-clock time, so rebuilding identical Iceberg inputs is
/// deterministic. Only observations carrying a canonical source identity are
/// published; provenance-free rows cannot become an RBAC-visible identity.
fn build_identity_snapshot(
    output: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    stamps: &ObjectStampManifest,
    objects: &[LocalObject],
    source_rows: u64,
    max_event_time_us: Option<i64>,
    threads: usize,
    prior: Option<PathBuf>,
) -> Result<IdentitySnapshotBuildManifest> {
    const WINDOW_US: i64 = IDENTITY_WINDOW_DAYS as i64 * 24 * 60 * 60 * 1_000_000;
    const MAX_OBSERVATIONS: usize = 100_000_000;

    let started = Instant::now();
    let cutoff = max_event_time_us.map(|value| value.saturating_sub(WINDOW_US));
    let source_objects = objects
        .iter()
        .map(|object| IdentitySnapshotSourceObject {
            event_object_key: object.stamp.source_uri.clone(),
            event_object_version: object.stamp.version_id.clone(),
            event_object_bytes: object.stamp.size_bytes,
        })
        .collect::<Vec<_>>();
    let source_object_identities_sha256 = identity_source_objects_digest(&source_objects)?;
    let prior = prior_identity_snapshot(
        prior.as_deref(),
        tenant_id,
        IDENTITY_WINDOW_DAYS,
        &source_objects,
    )?;
    let mut observations = match prior.as_ref() {
        Some(prior) => read_identity_observations(&prior.by_ip, cutoff)?,
        None => Vec::new(),
    };
    if observations.len() > MAX_OBSERVATIONS {
        bail!("prior identity snapshot exceeds its bounded observation count");
    }
    let prior_objects = prior
        .as_ref()
        .map(|prior| &prior.source_objects)
        .cloned()
        .unwrap_or_default();
    let objects_to_build = objects
        .iter()
        .filter(|object| {
            !prior_objects.contains(&IdentitySnapshotSourceObject {
                event_object_key: object.stamp.source_uri.clone(),
                event_object_version: object.stamp.version_id.clone(),
                event_object_bytes: object.stamp.size_bytes,
            })
        })
        .collect::<Vec<_>>();
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .thread_name(|index| format!("identity-snapshot-{index}"))
        .build()
        .context("build bounded identity-snapshot worker pool")?;
    for object_batch in objects_to_build.chunks(threads) {
        let built = pool.install(|| {
            object_batch
                .par_iter()
                .map(|object| identity_observations_for_object(object, cutoff))
                .collect::<Result<Vec<_>>>()
        })?;
        for mut object_observations in built {
            if observations.len().saturating_add(object_observations.len()) > MAX_OBSERVATIONS {
                bail!("identity snapshot exceeds its bounded observation count");
            }
            observations.append(&mut object_observations);
        }
    }

    observations.sort();
    observations.dedup();
    let min_observed_at_us = observations.iter().map(|row| row.observed_at_us).min();
    let max_observed_at_us = observations.iter().map(|row| row.observed_at_us).max();

    let by_ip = output.join("by-ip.parquet");
    write_identity_observations(&by_ip, &observations)?;
    let bytes = std::fs::metadata(&by_ip)?.len();
    let by_ip_sha256 = file_digest(&by_ip)?;
    let object_stamp_sha256 = file_digest(stamp_manifest)?;
    let identity_digest = hex::encode(Sha256::digest(
        [
            tenant_id.as_bytes(),
            &stamps.snapshot_id.to_be_bytes(),
            object_stamp_sha256.as_bytes(),
            by_ip_sha256.as_bytes(),
        ]
        .concat(),
    ));
    Ok(IdentitySnapshotBuildManifest {
        schema_version: IDENTITY_MANIFEST_SCHEMA_VERSION,
        tenant_id: tenant_id.to_string(),
        event_snapshot_id: stamps.snapshot_id,
        object_stamp_sha256,
        snapshot_id: format!("identity-{}-{}", stamps.snapshot_id, &identity_digest[..20]),
        window_days: IDENTITY_WINDOW_DAYS,
        source_files: objects.len(),
        source_rows,
        source_objects,
        source_object_identities_sha256,
        reused_source_files: prior_objects.len(),
        built_source_files: objects_to_build.len(),
        rows: observations.len() as u64,
        bytes,
        min_observed_at_us,
        max_observed_at_us,
        by_ip_sha256,
        build_seconds: started.elapsed().as_secs_f64(),
    })
}

fn identity_observations_for_object(
    object: &LocalObject,
    cutoff: Option<i64>,
) -> Result<Vec<IdentityObservation>> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&object.path)?)?
        .with_batch_size(8_192)
        .build()?;
    let mut observations = Vec::new();
    for batch in reader {
        let batch = batch?;
        let time = batch
            .schema()
            .index_of("time")
            .ok()
            .map(|index| batch.column(index));
        let compile = |paths: &[&str]| {
            paths
                .iter()
                .filter_map(|path| CompiledStringPath::new(&batch, path))
                .collect::<Vec<_>>()
        };
        let ip_paths = compile(&["src_endpoint.ip"]);
        let hostname_paths = compile(&["src_endpoint.hostname", "device.hostname"]);
        let source_paths = compile(&["metadata.log_source"]);
        let user_paths = compile(&["user.name", "actor.user.name"]);
        let mac_paths = compile(&["src_endpoint.mac"]);
        for row in 0..batch.num_rows() {
            let Some(observed_at_us) =
                time.and_then(|array| event_time_us_from_array(array.as_ref(), row))
            else {
                continue;
            };
            if cutoff.is_some_and(|cutoff| observed_at_us < cutoff) {
                continue;
            }
            let Some(ip) =
                first_nonempty_compiled(&ip_paths, row).and_then(|value| identity_ip(&value))
            else {
                continue;
            };
            let hostname_lc = first_nonempty_compiled(&hostname_paths, row)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| valid_identity_hostname(value))
                .unwrap_or_default();
            let Some(source) = first_nonempty_compiled(&source_paths, row)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| valid_identity_text(value))
            else {
                continue;
            };
            let user_lc = first_nonempty_compiled(&user_paths, row)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| valid_identity_text(value))
                .unwrap_or_default();
            let mac = first_nonempty_compiled(&mac_paths, row)
                .map(|value| value.trim().to_ascii_lowercase())
                .filter(|value| valid_identity_text(value))
                .unwrap_or_default();
            if hostname_lc.is_empty() && user_lc.is_empty() && mac.is_empty() {
                continue;
            }
            observations.push(IdentityObservation {
                ip,
                observed_at_us,
                hostname_lc,
                user_lc,
                mac,
                source,
            });
        }
    }
    Ok(observations)
}

struct PriorIdentitySnapshot {
    by_ip: PathBuf,
    source_objects: BTreeSet<IdentitySnapshotSourceObject>,
}

fn prior_identity_snapshot(
    directory: Option<&Path>,
    tenant_id: &str,
    window_days: u64,
    current_objects: &[IdentitySnapshotSourceObject],
) -> Result<Option<PriorIdentitySnapshot>> {
    let Some(directory) = directory.filter(|path| path.is_dir()) else {
        return Ok(None);
    };
    let manifest: IdentitySnapshotBuildManifest =
        match std::fs::read(directory.join("manifest.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        {
            Some(manifest) => manifest,
            None => return Ok(None),
        };
    if manifest.schema_version != 1
        || manifest.tenant_id != tenant_id
        || manifest.event_snapshot_id <= 0
        || manifest.window_days != window_days
        || manifest.source_objects.is_empty()
        || manifest.source_files != manifest.source_objects.len()
        || manifest.source_object_identities_sha256
            != identity_source_objects_digest(&manifest.source_objects)?
    {
        return Ok(None);
    }
    let source_objects = manifest
        .source_objects
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if source_objects.len() != manifest.source_objects.len()
        || source_objects.iter().any(|object| {
            !object.event_object_key.starts_with("s3://")
                || object.event_object_version.is_empty()
                || object.event_object_bytes == 0
        })
    {
        return Ok(None);
    }
    let current_objects = current_objects.iter().cloned().collect::<BTreeSet<_>>();
    if !source_objects.is_subset(&current_objects) {
        return Ok(None);
    }
    let by_ip = directory.join("by-ip.parquet");
    if !verified_file(&by_ip, manifest.bytes, &manifest.by_ip_sha256)? {
        return Ok(None);
    }
    Ok(Some(PriorIdentitySnapshot {
        by_ip,
        source_objects,
    }))
}

fn identity_source_objects_digest(objects: &[IdentitySnapshotSourceObject]) -> Result<String> {
    let mut ordered = objects.to_vec();
    ordered.sort();
    Ok(hex::encode(Sha256::digest(serde_json::to_vec(&ordered)?)))
}

fn read_identity_observations(
    path: &Path,
    cutoff: Option<i64>,
) -> Result<Vec<IdentityObservation>> {
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(path)?)?;
    if builder.schema().as_ref() != identity_schema().as_ref() {
        bail!("prior identity snapshot schema is incompatible");
    }
    let mut observations = Vec::new();
    for batch in builder.with_batch_size(8_192).build()? {
        let batch = batch?;
        if batch
            .columns()
            .iter()
            .any(|column| column.null_count() != 0)
        {
            bail!("prior identity snapshot contains null values");
        }
        let observed_at = batch
            .column(0)
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMicrosecondType>>()
            .context("prior identity timestamp column has the wrong type")?;
        let ip = batch
            .column(1)
            .as_any()
            .downcast_ref::<StringArray>()
            .context("prior identity IP column has the wrong type")?;
        let hostname = batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .context("prior identity hostname column has the wrong type")?;
        let user = batch
            .column(3)
            .as_any()
            .downcast_ref::<StringArray>()
            .context("prior identity user column has the wrong type")?;
        let mac = batch
            .column(4)
            .as_any()
            .downcast_ref::<StringArray>()
            .context("prior identity MAC column has the wrong type")?;
        let source = batch
            .column(5)
            .as_any()
            .downcast_ref::<StringArray>()
            .context("prior identity source column has the wrong type")?;
        for row in 0..batch.num_rows() {
            let observed_at_us = observed_at.value(row);
            if cutoff.is_some_and(|cutoff| observed_at_us < cutoff) {
                continue;
            }
            observations.push(IdentityObservation {
                ip: ip.value(row).to_string(),
                observed_at_us,
                hostname_lc: hostname.value(row).to_string(),
                user_lc: user.value(row).to_string(),
                mac: mac.value(row).to_string(),
                source: source.value(row).to_string(),
            });
        }
    }
    Ok(observations)
}

fn identity_schema() -> Arc<Schema> {
    Arc::new(Schema::new(vec![
        Field::new(
            "observed_at",
            DataType::Timestamp(
                arrow_schema::TimeUnit::Microsecond,
                Some(Arc::<str>::from("UTC")),
            ),
            false,
        ),
        Field::new("ip", DataType::Utf8, false),
        Field::new("hostname_lc", DataType::Utf8, false),
        Field::new("user_lc", DataType::Utf8, false),
        Field::new("mac", DataType::Utf8, false),
        Field::new("source", DataType::Utf8, false),
    ]))
}

fn write_identity_observations(path: &Path, observations: &[IdentityObservation]) -> Result<()> {
    let schema = identity_schema();
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(9)?))
        .set_max_row_group_row_count(Some(131_072))
        .build();
    let mut writer = ArrowWriter::try_new(File::create(path)?, schema.clone(), Some(properties))?;
    for rows in observations.chunks(131_072) {
        let mut observed_at = TimestampMicrosecondBuilder::with_capacity(rows.len());
        let mut ip = StringBuilder::with_capacity(rows.len(), rows.len() * 16);
        let mut hostname = StringBuilder::with_capacity(rows.len(), rows.len() * 24);
        let mut user = StringBuilder::with_capacity(rows.len(), rows.len() * 16);
        let mut mac = StringBuilder::with_capacity(rows.len(), rows.len() * 12);
        let mut source = StringBuilder::with_capacity(rows.len(), rows.len() * 16);
        for row in rows {
            observed_at.append_value(row.observed_at_us);
            ip.append_value(&row.ip);
            hostname.append_value(&row.hostname_lc);
            user.append_value(&row.user_lc);
            mac.append_value(&row.mac);
            source.append_value(&row.source);
        }
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(observed_at.finish().with_timezone("UTC")),
                Arc::new(ip.finish()),
                Arc::new(hostname.finish()),
                Arc::new(user.finish()),
                Arc::new(mac.finish()),
                Arc::new(source.finish()),
            ],
        )?;
        writer.write(&batch)?;
    }
    writer.close()?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn first_nonempty_compiled(paths: &[CompiledStringPath], row: usize) -> Option<String> {
    paths.iter().find_map(|path| {
        path.strings(row)
            .into_iter()
            .find(|value| !value.trim().is_empty())
    })
}

fn identity_ip(value: &str) -> Option<String> {
    let address = value.trim().parse::<IpAddr>().ok()?;
    let allowed = match address {
        IpAddr::V4(address) => address.is_private(),
        IpAddr::V6(address) => address.is_unique_local(),
    };
    if !allowed || address.is_loopback() || address.is_unspecified() {
        return None;
    }
    Some(address.to_string().to_ascii_lowercase())
}

fn valid_identity_hostname(value: &str) -> bool {
    valid_identity_text(value) && !matches!(value, "localhost" | "unknown")
}

fn valid_identity_text(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && !matches!(value, "-" | "0" | "null")
        && !value.chars().any(char::is_control)
}

fn file_digest(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(std::fs::read(path)?)))
}

fn keyword_schema() -> TantivySchema {
    let mut builder = TantivySchema::builder();
    let indexing = TextFieldIndexing::default()
        .set_tokenizer(KEYWORD_TOKENIZER)
        .set_index_option(IndexRecordOption::Basic)
        .set_fieldnorms(false);
    builder.add_text_field(
        "body",
        TextOptions::default().set_indexing_options(indexing),
    );
    builder.add_u64_field("locator", FAST);
    builder.add_u64_field("max_time", FAST);
    builder.add_u64_field("object_id", INDEXED | FAST);
    builder.build()
}

fn fragment_schema() -> TantivySchema {
    let mut builder = TantivySchema::builder();
    let indexing = TextFieldIndexing::default()
        .set_tokenizer(FRAGMENT_TOKENIZER)
        .set_index_option(IndexRecordOption::Basic)
        .set_fieldnorms(false);
    builder.add_text_field(
        "term",
        TextOptions::default().set_indexing_options(indexing),
    );
    builder.add_text_field("exact_term", STRING | STORED);
    builder.build()
}

fn prior_keyword_index(
    directory: Option<&Path>,
    tenant_id: &str,
) -> Result<Option<PriorKeywordIndex>> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    let manifest_path = directory.join("manifest.json");
    let index_path = directory.join("index");
    if !manifest_path.is_file() || !index_path.is_dir() {
        return Ok(None);
    }
    let manifest: PriorKeywordManifest = match serde_json::from_slice(&std::fs::read(
        &manifest_path,
    )?) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "prior keyword manifest is incompatible; rebuilding exactly");
            return Ok(None);
        }
    };
    if manifest.index_version != KEYWORD_INDEX_VERSION_V3
        || manifest.tenant_id != tenant_id
        || !manifest
            .body_fields
            .iter()
            .map(String::as_str)
            .eq(KEYWORD_BODY_FIELDS.iter().copied())
        || manifest.objects.is_empty()
        || manifest.blocks.is_empty()
        || manifest.blocks.len() != manifest.block_documents
    {
        return Ok(None);
    }
    let mut objects = BTreeMap::new();
    let mut object_ids = BTreeSet::new();
    for object in &manifest.objects {
        if object.event_object_key.is_empty()
            || object.event_object_version.is_empty()
            || object.event_object_bytes == 0
            || !object_ids.insert(object.object_id)
            || objects
                .insert(
                    (
                        object.event_object_key.clone(),
                        object.event_object_version.clone(),
                        object.event_object_bytes,
                    ),
                    object.clone(),
                )
                .is_some()
        {
            return Ok(None);
        }
    }
    let index = match Index::open_in_dir(&index_path) {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(error = %error, "prior keyword index cannot be opened; rebuilding exactly");
            return Ok(None);
        }
    };
    let schema = index.schema();
    if schema.get_field("body").is_err()
        || schema.get_field("locator").is_err()
        || schema.get_field("max_time").is_err()
        || schema.get_field("object_id").is_err()
        || index.reader()?.searcher().num_docs() as usize != manifest.block_documents
    {
        return Ok(None);
    }
    Ok(Some(PriorKeywordIndex {
        directory: directory.to_path_buf(),
        manifest,
        objects,
    }))
}

struct PriorFragmentIndex {
    directory: PathBuf,
    filtered_terms: u64,
}

fn prior_fragment_index(directory: Option<&Path>) -> Result<Option<PriorFragmentIndex>> {
    let Some(directory) = directory else {
        return Ok(None);
    };
    let manifest_path = directory.join("manifest.json");
    let index_path = directory.join("index");
    if !manifest_path.is_file() || !index_path.is_dir() {
        return Ok(None);
    }
    let manifest: Value = match serde_json::from_slice(&std::fs::read(&manifest_path)?) {
        Ok(value) => value,
        Err(_) => return Ok(None),
    };
    // A prior index built under a different filter profile cannot seed this
    // build: an unfiltered ("all") prior would carry every hex hash term
    // forward and the measured ~79% term reduction would never materialize.
    // Rejecting it forces one clean rebuild from the complete keyword
    // dictionary.
    if manifest.get("index_version").and_then(Value::as_str) != Some(FRAGMENT_INDEX_VERSION_V2)
        || manifest.get("term_payload").and_then(Value::as_str) != Some("stored exact keyword term")
        || manifest.get("filter_profile").and_then(Value::as_str)
            != Some(FRAGMENT_FILTER_PROFILE_SKIP_HEX8)
        || Index::open_in_dir(&index_path).is_err()
    {
        return Ok(None);
    }
    Ok(Some(PriorFragmentIndex {
        directory: directory.to_path_buf(),
        filtered_terms: manifest
            .get("filtered_terms")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    }))
}

struct KeywordDictionaryVisit {
    terms: u64,
    selected_segments: usize,
    total_segments: usize,
}

fn keyword_segment_ids(directory: &Path) -> Result<BTreeSet<SegmentId>> {
    let index = Index::open_in_dir(directory)?;
    Ok(index
        .reader()?
        .searcher()
        .segment_readers()
        .iter()
        .map(|reader| reader.segment_id())
        .collect())
}

/// Stream either the complete normalized term dictionary or the exact union
/// of segments absent from a proven prior index, in bounded globally unique
/// batches. Tantivy's `TermMerger` performs the sorted union over immutable
/// segment dictionaries without materializing table-sized Rust strings. The
/// keyword index remains authoritative: its tokenizer (split on
/// non-alphanumeric, lowercase) is also the fragment builder's contract.
fn visit_keyword_dictionary_batches(
    keyword_index_dir: &Path,
    prior_segment_ids: Option<&BTreeSet<SegmentId>>,
    mut visit: impl FnMut(&[String]) -> Result<()>,
) -> Result<KeywordDictionaryVisit> {
    let index = Index::open_in_dir(keyword_index_dir)?;
    let body = index
        .schema()
        .get_field("body")
        .context("keyword body field is absent")?;
    let reader = index.reader()?;
    let searcher = reader.searcher();
    let total_segments = searcher.segment_readers().len();
    let inverted = searcher
        .segment_readers()
        .iter()
        .filter(|segment| {
            prior_segment_ids.is_none_or(|prior| !prior.contains(&segment.segment_id()))
        })
        .map(|segment| segment.inverted_index(body))
        .collect::<tantivy::Result<Vec<_>>>()?;
    let selected_segments = inverted.len();
    let streams = inverted
        .iter()
        .map(|reader| reader.terms().stream())
        .collect::<std::io::Result<Vec<_>>>()?;
    if streams.is_empty() {
        return Ok(KeywordDictionaryVisit {
            terms: 0,
            selected_segments,
            total_segments,
        });
    }
    let mut merger = TermMerger::new(streams);
    let mut batch = Vec::with_capacity(FRAGMENT_TERM_BATCH_TERMS);
    let mut term_count = 0_u64;
    while merger.advance() {
        batch.push(
            std::str::from_utf8(merger.key())
                .context("keyword dictionary term is not UTF-8")?
                .to_string(),
        );
        if batch.len() == FRAGMENT_TERM_BATCH_TERMS {
            term_count = term_count
                .checked_add(batch.len() as u64)
                .context("keyword dictionary term count overflow")?;
            visit(&batch)?;
            batch.clear();
        }
    }
    if !batch.is_empty() {
        term_count = term_count
            .checked_add(batch.len() as u64)
            .context("keyword dictionary term count overflow")?;
        visit(&batch)?;
    }
    Ok(KeywordDictionaryVisit {
        terms: term_count,
        selected_segments,
        total_segments,
    })
}

/// Clone a committed Tantivy directory without mutating the active generation.
/// Segment files are immutable and can be hard-linked on one filesystem;
/// catalog and lock files are copied because the new writer may replace them.
fn clone_tantivy_index(source: &Path, destination: &Path) -> Result<()> {
    if !source.is_dir() || destination.exists() {
        bail!("Tantivy clone source is absent or destination already exists");
    }
    std::fs::create_dir(destination)?;
    for entry in std::fs::read_dir(source)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if !file_type.is_file() {
            bail!("Tantivy index contains an unexpected non-file entry");
        }
        let name = entry.file_name();
        let target = destination.join(&name);
        let name_text = name.to_string_lossy();
        let mutable_metadata = matches!(
            name_text.as_ref(),
            "meta.json" | ".managed.json" | ".tantivy-meta.lock" | ".tantivy-writer.lock"
        );
        if mutable_metadata || std::fs::hard_link(entry.path(), &target).is_err() {
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn index_keyword_object(
    object: &LocalObject,
    object_id: u32,
    writer: &IndexWriter<KeywordDocument>,
    body_field: TantivyField,
    locator_field: TantivyField,
    max_time_field: TantivyField,
    object_id_field: TantivyField,
) -> Result<(KeywordManifestObject, Vec<KeywordManifestBlock>)> {
    if std::fs::metadata(&object.path)?.len() != object.stamp.size_bytes {
        bail!("local keyword object size differs from its immutable stamp");
    }
    let builder = ParquetRecordBatchReaderBuilder::try_new(File::open(&object.path)?)?;
    let schema = builder.schema().clone();
    let metadata = builder.metadata().clone();
    if schema.index_of("time").is_err() {
        bail!("keyword object lacks canonical OCSF time");
    }
    let rows = u64::try_from(metadata.file_metadata().num_rows())
        .context("keyword object row count is negative")?;
    let mut blocks = Vec::with_capacity(metadata.num_row_groups());
    let mut row_start = 0_u64;
    for row_group in 0..metadata.num_row_groups() {
        let row_count = usize::try_from(metadata.row_group(row_group).num_rows())
            .context("keyword row-group row count is negative")?;
        let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&object.path)?)?
            .with_row_groups(vec![row_group])
            .with_batch_size(DERIVATIVE_PARQUET_BATCH_ROWS.min(row_count.max(1)))
            .build()?;
        let mut body = String::new();
        let mut block_max_time = 0_u64;
        let mut observed_rows = 0_u64;
        for batch in reader {
            let batch = batch?;
            // Compile the 30 canonical hunt paths once for this Arrow batch.
            // Resolving schema nodes and allocating traversal vectors for
            // every (row, path) pair dominated high-rate keyword builds.
            let body_paths = KEYWORD_BODY_FIELDS
                .iter()
                .filter_map(|path| CompiledStringPath::new(&batch, path))
                .collect::<Vec<_>>();
            let time = batch
                .schema()
                .index_of("time")
                .ok()
                .map(|index| batch.column(index));
            observed_rows = observed_rows
                .checked_add(batch.num_rows() as u64)
                .context("keyword row-group row total overflow")?;
            for row in 0..batch.num_rows() {
                block_max_time = block_max_time.max(
                    time.map(|array| event_time_ms_from_array(array.as_ref(), row))
                        .unwrap_or(0),
                );
                for path in &body_paths {
                    for value in path.strings(row) {
                        if value.is_empty() {
                            continue;
                        }
                        if !body.is_empty() {
                            body.push('\n');
                        }
                        body.push_str(&value);
                    }
                }
            }
        }
        if observed_rows != row_count as u64 {
            bail!("keyword row-group reader returned a different row count");
        }
        let row_group_id = u32::try_from(row_group).context("keyword row-group ID overflow")?;
        let locator = (u64::from(object_id) << 32) | u64::from(row_group_id);
        let mut document = KeywordDocument::new();
        if !body.is_empty() {
            document.insert(body_field, OwnedValue::Str(body));
        }
        document.insert(locator_field, OwnedValue::U64(locator));
        document.insert(max_time_field, OwnedValue::U64(block_max_time));
        document.insert(object_id_field, OwnedValue::U64(u64::from(object_id)));
        writer.add_document(document)?;
        let row_end = row_start
            .checked_add(observed_rows)
            .context("keyword object row range overflow")?;
        blocks.push(KeywordManifestBlock {
            locator,
            object_id,
            row_group: row_group_id,
            row_start,
            row_end,
            rows: observed_rows,
            max_time: block_max_time,
        });
        row_start = row_end;
    }
    if row_start != rows || blocks.is_empty() {
        bail!("keyword block rows differ from the immutable object");
    }
    let field_types = schema_leaf_types(schema.as_ref());
    let available_paths = field_types.keys().cloned().collect();
    Ok((
        KeywordManifestObject {
            object_id,
            relative_path: object.stamp.relative_path.clone(),
            event_object_key: object.stamp.source_uri.clone(),
            event_object_version: object.stamp.version_id.clone(),
            event_object_bytes: object.stamp.size_bytes,
            rows,
            row_groups: metadata.num_row_groups(),
            available_paths,
            field_types,
        },
        blocks,
    ))
}

/// Keep incremental keyword serving bounded without collapsing every writer
/// segment through one serial merge. Each policy pass pairs the smallest
/// disjoint segments needed to move toward the cap; Tantivy can execute those
/// independent candidates on its configured merge-worker pool.
#[derive(Debug)]
struct BoundedParallelMergePolicy {
    max_segments: usize,
}

impl MergePolicy for BoundedParallelMergePolicy {
    fn compute_merge_candidates(&self, segments: &[SegmentMeta]) -> Vec<MergeCandidate> {
        if segments.len() <= self.max_segments || self.max_segments == 0 {
            return Vec::new();
        }
        let mut ordered = segments.iter().collect::<Vec<_>>();
        ordered.sort_unstable_by_key(|segment| (segment.num_docs(), segment.id()));
        let pair_count = bounded_merge_pair_count(segments.len(), self.max_segments);
        ordered
            .chunks_exact(2)
            .take(pair_count)
            .map(|pair| MergeCandidate(vec![pair[0].id(), pair[1].id()]))
            .collect()
    }
}

fn bounded_merge_pair_count(segment_count: usize, max_segments: usize) -> usize {
    segment_count
        .saturating_sub(max_segments)
        .min(segment_count / 2)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct KeywordThreadLayout {
    producers: usize,
    indexers: usize,
    mergers: usize,
}

/// Treat the configured keyword thread count as one CPU budget across the
/// producer, Tantivy indexer, and Tantivy merge pools. Tantivy requires at
/// least one indexer and one merger; configurations below three therefore
/// retain that unavoidable minimum, while every production-sized layout fits
/// exactly inside the declared bound.
fn keyword_thread_layout(threads: usize, producer_ceiling: usize) -> KeywordThreadLayout {
    if threads < 3 {
        return KeywordThreadLayout {
            producers: 1,
            indexers: 1,
            mergers: 1,
        };
    }
    let producers = (threads.saturating_mul(3) / 8).clamp(1, producer_ceiling);
    let remaining = threads - producers;
    let mergers = (remaining / 2).max(1);
    let indexers = remaining - mergers;
    KeywordThreadLayout {
        producers,
        indexers,
        mergers,
    }
}

fn build_keyword(
    input_root: &Path,
    output: &Path,
    stamp_manifest: &Path,
    tenant_id: &str,
    objects: &[LocalObject],
    threads: usize,
    heap_bytes: usize,
    producer_ceiling: usize,
    prior_directory: Option<PathBuf>,
) -> Result<KeywordBuildResult> {
    let started = Instant::now();
    let index_dir = output.join("index");
    let mut prior = prior_keyword_index(prior_directory.as_deref(), tenant_id)?;
    if let Some(candidate) = prior.as_ref() {
        if let Err(error) = clone_tantivy_index(&candidate.directory.join("index"), &index_dir) {
            tracing::warn!(error = %error, "prior keyword index cannot be cloned; rebuilding exactly");
            if index_dir.exists() {
                std::fs::remove_dir_all(&index_dir)?;
            }
            prior = None;
        }
    }

    let index = if prior.is_some() {
        Index::open_in_dir(&index_dir)?
    } else {
        std::fs::create_dir(&index_dir)?;
        Index::create_in_dir(&index_dir, keyword_schema())?
    };
    index.tokenizers().register(
        KEYWORD_TOKENIZER,
        TextAnalyzer::builder(SimpleTokenizer::default())
            .filter(LowerCaser)
            .build(),
    );
    let schema = index.schema();
    let body = schema.get_field("body")?;
    let locator = schema.get_field("locator")?;
    let max_time = schema.get_field("max_time")?;
    let object_id_field = schema.get_field("object_id")?;
    let thread_layout = keyword_thread_layout(threads, producer_ceiling);
    let writer_options = IndexWriterOptions::builder()
        .num_worker_threads(thread_layout.indexers)
        .num_merge_threads(thread_layout.mergers)
        .memory_budget_per_thread(heap_bytes / thread_layout.indexers)
        .build();
    let mut writer: IndexWriter<KeywordDocument> = index.writer_with_options(writer_options)?;
    writer.set_merge_policy(Box::new(BoundedParallelMergePolicy {
        max_segments: KEYWORD_MAX_SEGMENTS,
    }));
    let current_identities = objects
        .iter()
        .map(|object| stamp_identity(&object.stamp))
        .collect::<BTreeSet<_>>();
    let mut retired_objects = 0_usize;
    if let Some(prior) = prior.as_ref() {
        for (identity, object) in &prior.objects {
            if !current_identities.contains(identity) {
                writer.delete_term(Term::from_field_u64(
                    object_id_field,
                    object.object_id as u64,
                ));
                retired_objects += 1;
            }
        }
    }

    let mut next_id = prior
        .as_ref()
        .and_then(|value| {
            value
                .manifest
                .objects
                .iter()
                .map(|object| object.object_id)
                .max()
        })
        .map(|value| {
            value
                .checked_add(1)
                .context("keyword object ID space is exhausted")
        })
        .transpose()?
        .unwrap_or(0);
    let prior_blocks = prior
        .as_ref()
        .map(|value| {
            value.manifest.blocks.iter().cloned().fold(
                BTreeMap::<u32, Vec<KeywordManifestBlock>>::new(),
                |mut map, block| {
                    map.entry(block.object_id).or_default().push(block);
                    map
                },
            )
        })
        .unwrap_or_default();
    let mut manifest_objects = Vec::with_capacity(objects.len());
    let mut blocks = Vec::new();
    let mut reused_objects = 0_usize;
    let mut pending = Vec::new();
    for object in objects {
        let identity = stamp_identity(&object.stamp);
        if let Some(reused) = prior
            .as_ref()
            .and_then(|value| value.objects.get(&identity))
        {
            let reused_blocks = prior_blocks
                .get(&reused.object_id)
                .context("prior keyword object has no blocks")?;
            manifest_objects.push(reused.clone());
            blocks.extend(reused_blocks.iter().cloned());
            reused_objects += 1;
            continue;
        }
        let assigned_id = next_id;
        next_id = next_id
            .checked_add(1)
            .context("keyword object ID space is exhausted")?;
        pending.push((object, assigned_id));
    }
    let built_objects = pending.len();
    tracing::info!(
        producer_threads = thread_layout.producers,
        index_threads = thread_layout.indexers,
        merge_threads = thread_layout.mergers,
        built_objects,
        "keyword object producer layout resolved"
    );
    let producer_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_layout.producers)
        .thread_name(|index| format!("keyword-producer-{index}"))
        .build()
        .context("build bounded keyword object producer pool")?;
    let mut admission_batches = 0_usize;
    for batch in pending.chunks(thread_layout.producers) {
        let built = producer_pool.install(|| {
            batch
                .par_iter()
                .map(|(object, assigned_id)| {
                    index_keyword_object(
                        object,
                        *assigned_id,
                        &writer,
                        body,
                        locator,
                        max_time,
                        object_id_field,
                    )
                })
                .collect::<Result<Vec<_>>>()
        })?;
        for (manifest_object, object_blocks) in built {
            manifest_objects.push(manifest_object);
            blocks.extend(object_blocks);
        }
        // `add_document` only backpressures after 10,000 queued DOCUMENTS.
        // One document here is an entire OCSF row-group body, so that count is
        // not a meaningful byte bound. Commit is the supported barrier that
        // drains the admission queue and flushes the bounded writer arenas
        // before the next producer batch can materialize more bodies.
        writer.commit()?;
        admission_batches += 1;
    }
    // A delete-only incremental generation has no producer batch in which to
    // commit its retired-object tombstones.
    if pending.is_empty() {
        writer.commit()?;
    }
    writer.wait_merging_threads()?;
    manifest_objects.sort_by_key(|object| object.object_id);
    blocks.sort_by_key(|block| block.locator);
    let segment_count = index.searchable_segment_ids()?.len();
    let searcher = index.reader()?.searcher();
    if segment_count == 0 || searcher.num_docs() as usize != blocks.len() {
        bail!("keyword index document set differs from the current immutable objects");
    }
    let events = manifest_objects.iter().try_fold(0_u64, |total, object| {
        total
            .checked_add(object.rows)
            .context("keyword row total overflow")
    })?;
    let source_bytes = manifest_objects.iter().try_fold(0_u64, |total, object| {
        total
            .checked_add(object.event_object_bytes)
            .context("keyword byte total overflow")
    })?;
    Ok(KeywordBuildResult {
        manifest: json!({
            "index_version": KEYWORD_INDEX_VERSION_V3,
            "tenant_id": tenant_id,
            "engine": "tantivy",
            "tantivy_version": "0.26.0",
            "tokenizer": "simple split on non-alphanumeric, then lowercase",
            "index_granularity": "one document per aligned Parquet row group",
            "exactness": "candidate superset only; source text is always rechecked",
            "block_field": Value::Null,
            "block_locator": "physical-column-or-parquet-row-group",
            "body_fields": KEYWORD_BODY_FIELDS,
            "input_root": input_root,
            "source_uri_prefix": Value::Null,
            "object_stamp_manifest": stamp_manifest,
            "source_files": objects.len(),
            "source_bytes": source_bytes,
            "event_rows": events,
            "blocks": blocks,
            "objects": manifest_objects,
            "block_documents": blocks.len(),
            "index_bytes": directory_bytes(&index_dir)?,
            "build_seconds": started.elapsed().as_secs_f64(),
            "segments": segment_count,
            "fragment_dictionary_ready": true,
            "producer_threads": thread_layout.producers,
            "index_threads": thread_layout.indexers,
            "merge_threads": thread_layout.mergers,
            "admission_batches": admission_batches,
            "incremental": {
                "reused_objects": reused_objects,
                "built_objects": built_objects,
                "retired_objects": retired_objects,
            },
        }),
        reused_objects,
        built_objects,
        retired_objects,
    })
}

fn build_fragment(
    keyword_index_dir: &Path,
    output: &Path,
    threads: usize,
    heap_bytes: usize,
    prior_keyword_directory: Option<PathBuf>,
    prior_directory: Option<PathBuf>,
) -> Result<FragmentBuildResult> {
    let started = Instant::now();
    let index_dir = output.join("index");
    let mut prior_compatible = prior_fragment_index(prior_directory.as_deref())?;
    if let Some(prior) = prior_compatible.as_ref() {
        if let Err(error) = clone_tantivy_index(&prior.directory.join("index"), &index_dir) {
            tracing::warn!(error = %error, "prior fragment index cannot be cloned; rebuilding exactly");
            if index_dir.exists() {
                std::fs::remove_dir_all(&index_dir)?;
            }
            prior_compatible = None;
        }
    }
    let index = if prior_compatible.is_some() {
        Index::open_in_dir(&index_dir)?
    } else {
        std::fs::create_dir(&index_dir)?;
        Index::create_in_dir(&index_dir, fragment_schema())?
    };
    index
        .tokenizers()
        .register(FRAGMENT_TOKENIZER, NgramTokenizer::new(3, 3, false)?);
    let schema = index.schema();
    let term = schema.get_field("term")?;
    let exact_term = schema.get_field("exact_term")?;
    let prior_reader = index.reader()?;
    let prior_searcher = prior_reader.searcher();
    let reused_terms = prior_searcher.num_docs();
    let prior_exact_term_dictionaries = prior_searcher
        .segment_readers()
        .iter()
        .map(|segment| segment.inverted_index(exact_term))
        .collect::<tantivy::Result<Vec<_>>>()?;
    // The keyword builder clones immutable prior Tantivy segments and writes
    // every appended object's blocks into new segments. The fragment index is
    // a conservative candidate superset, so it may retain terms belonging to
    // retired objects; consequently every genuinely NEW keyword term must be
    // present in a segment whose ID was absent from the prior generation.
    // Scan only those delta segments, while falling back to the complete
    // dictionary if either prior artifact cannot prove that lineage.
    let prior_keyword_segments = if prior_compatible.is_some() {
        prior_keyword_directory.as_deref().and_then(|directory| {
            keyword_segment_ids(directory)
                .map_err(|error| {
                    tracing::warn!(
                        error = %error,
                        "prior keyword segments cannot seed fragment delta scan; scanning completely"
                    );
                    error
                })
                .ok()
        })
    } else {
        None
    };
    let delta_scan = prior_keyword_segments.is_some();
    // Fragment admission used to feed Tantivy from one serial loop. At the
    // retained 15-TB/day scale that loop spent 180.79 seconds with its main
    // thread pinned while sixteen index workers received only 3-6% CPU each
    // and the 64-vCPU host remained 96% idle. Share the declared thread budget
    // across bounded producers, indexers, and mergers just like the keyword
    // builder; IndexWriter admission and the immutable prior Searcher are
    // thread-safe, and document order is not part of the candidate-superset
    // serving contract.
    let thread_layout = keyword_thread_layout(threads, MAX_KEYWORD_PRODUCER_CEILING);
    let writer_options = IndexWriterOptions::builder()
        .num_worker_threads(thread_layout.indexers)
        .num_merge_threads(thread_layout.mergers)
        .memory_budget_per_thread(heap_bytes / thread_layout.indexers)
        .build();
    let mut writer: IndexWriter<TantivyDocument> = index.writer_with_options(writer_options)?;
    tracing::info!(
        producer_threads = thread_layout.producers,
        index_threads = thread_layout.indexers,
        merge_threads = thread_layout.mergers,
        term_batch_size = FRAGMENT_TERM_BATCH_TERMS,
        "fragment term producer layout resolved"
    );
    let producer_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_layout.producers)
        .thread_name(|index| format!("fragment-producer-{index}"))
        .build()
        .context("build bounded fragment term producer pool")?;
    let mut built_terms = 0_u64;
    let mut run_filtered_terms = 0_u64;
    let dictionary_started = Instant::now();
    let dictionary = visit_keyword_dictionary_batches(
        keyword_index_dir,
        prior_keyword_segments.as_ref(),
        |batch| {
            let (built, filtered) = producer_pool.install(|| {
                batch
                    .par_iter()
                    .try_fold(
                        || (0_u64, 0_u64),
                        |(built, filtered), text| -> Result<(u64, u64)> {
                            if text.chars().count() < 3 {
                                return Ok((built, filtered));
                            }
                            // skip-hex8: normalized lowercase hex-only terms of
                            // at least eight bytes (file hashes and friends) never
                            // enter the fragment accelerator. The planner routes
                            // hex-only contains/regex tokens to the unpruned exact
                            // lane, so this is a pure size win, never a correctness
                            // gap. The keyword index keeps its full dictionary.
                            if hex8_filtered_term(text) {
                                return Ok((built, filtered + 1));
                            }
                            // `Searcher::doc_freq` resolves postings metadata
                            // for every segment. This phase only needs exact
                            // membership, and millions of delta terms made
                            // those extra postings lookups dominate retained
                            // generation time. Tantivy's immutable FST term
                            // dictionaries provide the same fail-closed
                            // membership result without opening postings.
                            let exists_in_prior = prior_exact_term_dictionaries.iter().try_fold(
                                false,
                                |found, dictionary| {
                                    if found {
                                        Ok::<_, anyhow::Error>(true)
                                    } else {
                                        Ok(dictionary.terms().term_ord(text.as_bytes())?.is_some())
                                    }
                                },
                            )?;
                            if exists_in_prior {
                                return Ok((built, filtered));
                            }
                            writer.add_document(doc!(
                                term => text.as_str(),
                                exact_term => text.as_str()
                            ))?;
                            Ok((built + 1, filtered))
                        },
                    )
                    .try_reduce(
                        || (0_u64, 0_u64),
                        |left, right| Ok((left.0 + right.0, left.1 + right.1)),
                    )
            })?;
            built_terms = built_terms
                .checked_add(built)
                .context("fragment built-term count overflow")?;
            run_filtered_terms = run_filtered_terms
                .checked_add(filtered)
                .context("fragment filtered-term count overflow")?;
            Ok(())
        },
    )?;
    let dictionary_seconds = dictionary_started.elapsed().as_secs_f64();
    let commit_started = Instant::now();
    writer.commit()?;
    let commit_seconds = commit_started.elapsed().as_secs_f64();
    let merge_started = Instant::now();
    writer.wait_merging_threads()?;
    let merge_seconds = merge_started.elapsed().as_secs_f64();
    let reader = index.reader()?;
    let indexed_terms = reader.searcher().num_docs();
    let segments = reader.searcher().segment_readers().len();
    if indexed_terms == 0 || segments == 0 {
        bail!("fragment index is empty");
    }
    // On the initial/full path these are exact current-dictionary counts. On
    // the incremental path they are conservative cumulative upper bounds:
    // terms repeated between old and new keyword segments may be counted
    // twice, which cannot weaken the serving contract (the v2 resolver stores
    // exact terms and only requires indexed_terms <= source_terms).
    let filtered_terms = if delta_scan {
        let prior = prior_compatible
            .as_ref()
            .context("fragment delta scan lost its compatible prior")?;
        prior
            .filtered_terms
            .checked_add(run_filtered_terms)
            .context("fragment cumulative filtered-term count overflow")?
    } else {
        run_filtered_terms
    };
    let source_terms = indexed_terms
        .checked_add(filtered_terms)
        .context("fragment source-term count overflow")?;
    Ok(FragmentBuildResult {
        manifest: json!({
            "index_version": FRAGMENT_INDEX_VERSION_V2,
            "engine": "tantivy",
            "tantivy_version": "0.26.0",
            "tokenizer": "character ngram 3..3",
            "index_option": "basic postings: distinct-term document IDs only",
            "fieldnorms": false,
            "term_payload": "stored exact keyword term",
            "filter_profile": FRAGMENT_FILTER_PROFILE_SKIP_HEX8,
            "source_terms_file": "embedded:incremental-exact-term-dictionary",
            "source_terms": source_terms,
            "filtered_terms": filtered_terms,
            "source_term_accounting": "indexed-plus-cumulative-filtered",
            "dictionary_scan": if delta_scan { "new-keyword-segments" } else { "complete" },
            "dictionary_terms_examined": dictionary.terms,
            "dictionary_segments_examined": dictionary.selected_segments,
            "dictionary_segments_total": dictionary.total_segments,
            "indexed_terms": indexed_terms,
            "build_seconds": started.elapsed().as_secs_f64(),
            "phase_timings_seconds": {
                "dictionary_and_admission": dictionary_seconds,
                "commit": commit_seconds,
                "merge_wait": merge_seconds,
            },
            "index_bytes": directory_bytes(&index_dir)?,
            "segments": segments,
            "producer_threads": thread_layout.producers,
            "index_threads": thread_layout.indexers,
            "merge_threads": thread_layout.mergers,
            "incremental": {
                "reused_terms": reused_terms,
                "built_terms": built_terms,
            },
        }),
        reused_terms,
        built_terms,
    })
}

#[derive(Clone, Copy)]
enum CompiledStringPathStep {
    Struct(usize),
    List,
    LargeList,
    FixedSizeList,
}

pub(crate) struct CompiledStringPath {
    root: ArrayRef,
    steps: Vec<CompiledStringPathStep>,
}

impl CompiledStringPath {
    pub(crate) fn new(batch: &RecordBatch, path: &str) -> Option<Self> {
        let mut parts = path.split('.');
        let root = batch.schema().index_of(parts.next()?).ok()?;
        let root = batch.column(root).clone();
        let mut data_type = root.data_type().clone();
        let mut steps = Vec::new();
        for part in parts {
            loop {
                match &data_type {
                    DataType::Struct(fields) => {
                        let position = fields.iter().position(|field| field.name() == part)?;
                        data_type = fields[position].data_type().clone();
                        steps.push(CompiledStringPathStep::Struct(position));
                        break;
                    }
                    DataType::List(child) => {
                        data_type = child.data_type().clone();
                        steps.push(CompiledStringPathStep::List);
                    }
                    DataType::LargeList(child) => {
                        data_type = child.data_type().clone();
                        steps.push(CompiledStringPathStep::LargeList);
                    }
                    DataType::FixedSizeList(child, _) => {
                        data_type = child.data_type().clone();
                        steps.push(CompiledStringPathStep::FixedSizeList);
                    }
                    _ => return None,
                }
            }
        }
        Some(Self { root, steps })
    }

    pub(crate) fn strings(&self, row: usize) -> Vec<String> {
        let mut output = Vec::new();
        collect_compiled_strings(self.root.as_ref(), row, &self.steps, &mut output);
        output
    }
}

fn collect_compiled_strings(
    array: &dyn Array,
    index: usize,
    steps: &[CompiledStringPathStep],
    output: &mut Vec<String>,
) {
    if index >= array.len() || array.is_null(index) {
        return;
    }
    let Some((step, remaining)) = steps.split_first() else {
        collect_terminal_strings(array, index, output);
        return;
    };
    match step {
        CompiledStringPathStep::Struct(position) => {
            let values = array
                .as_any()
                .downcast_ref::<StructArray>()
                .expect("compiled struct path");
            collect_compiled_strings(values.column(*position).as_ref(), index, remaining, output);
        }
        CompiledStringPathStep::List => {
            let list = array
                .as_any()
                .downcast_ref::<ListArray>()
                .expect("compiled list path");
            let offsets = list.value_offsets();
            for child in offsets[index] as usize..offsets[index + 1] as usize {
                collect_compiled_strings(list.values().as_ref(), child, remaining, output);
            }
        }
        CompiledStringPathStep::LargeList => {
            let list = array
                .as_any()
                .downcast_ref::<LargeListArray>()
                .expect("compiled large-list path");
            let offsets = list.value_offsets();
            for child in offsets[index] as usize..offsets[index + 1] as usize {
                collect_compiled_strings(list.values().as_ref(), child, remaining, output);
            }
        }
        CompiledStringPathStep::FixedSizeList => {
            let list = array
                .as_any()
                .downcast_ref::<FixedSizeListArray>()
                .expect("compiled fixed-list path");
            let start = list.value_offset(index) as usize;
            for child in start..start + list.value_length() as usize {
                collect_compiled_strings(list.values().as_ref(), child, remaining, output);
            }
        }
    }
}

fn collect_terminal_strings(array: &dyn Array, index: usize, output: &mut Vec<String>) {
    match array.data_type() {
        DataType::List(_) => {
            let list = array
                .as_any()
                .downcast_ref::<ListArray>()
                .expect("terminal list path");
            let offsets = list.value_offsets();
            for child in offsets[index] as usize..offsets[index + 1] as usize {
                collect_terminal_strings(list.values().as_ref(), child, output);
            }
        }
        DataType::LargeList(_) => {
            let list = array
                .as_any()
                .downcast_ref::<LargeListArray>()
                .expect("terminal large-list path");
            let offsets = list.value_offsets();
            for child in offsets[index] as usize..offsets[index + 1] as usize {
                collect_terminal_strings(list.values().as_ref(), child, output);
            }
        }
        _ => {
            if let Some(value) = scalar_string(array, index) {
                output.push(value);
            }
        }
    }
}

#[cfg(test)]
fn path_strings(batch: &RecordBatch, row: usize, path: &str) -> Vec<String> {
    let mut parts = path.split('.');
    let Some(root) = parts.next() else {
        return Vec::new();
    };
    let Ok(index) = batch.schema().index_of(root) else {
        return Vec::new();
    };
    let remaining = parts.collect::<Vec<_>>();
    let nodes = resolve_nodes(batch.column(index).clone(), row, &remaining);
    let mut output = Vec::new();
    for (array, index) in nodes {
        for (value_array, value_index) in explode_node(array, index) {
            if let Some(value) = scalar_string(value_array.as_ref(), value_index) {
                output.push(value);
            }
        }
    }
    output
}

fn resolve_nodes(array: ArrayRef, index: usize, parts: &[&str]) -> Vec<(ArrayRef, usize)> {
    if index >= array.len() || array.is_null(index) {
        return Vec::new();
    }
    if parts.is_empty() {
        return vec![(array, index)];
    }
    match array.data_type() {
        DataType::Struct(fields) => {
            let Some(position) = fields.iter().position(|field| field.name() == parts[0]) else {
                return Vec::new();
            };
            let values = array
                .as_any()
                .downcast_ref::<StructArray>()
                .expect("struct type");
            resolve_nodes(values.column(position).clone(), index, &parts[1..])
        }
        DataType::List(_) => {
            let list = array
                .as_any()
                .downcast_ref::<ListArray>()
                .expect("list type");
            let offsets = list.value_offsets();
            (offsets[index] as usize..offsets[index + 1] as usize)
                .flat_map(|child| resolve_nodes(list.values().clone(), child, parts))
                .collect()
        }
        DataType::LargeList(_) => {
            let list = array
                .as_any()
                .downcast_ref::<LargeListArray>()
                .expect("large list type");
            let offsets = list.value_offsets();
            (offsets[index] as usize..offsets[index + 1] as usize)
                .flat_map(|child| resolve_nodes(list.values().clone(), child, parts))
                .collect()
        }
        DataType::FixedSizeList(_, _) => {
            let list = array
                .as_any()
                .downcast_ref::<FixedSizeListArray>()
                .expect("fixed list type");
            let start = list.value_offset(index) as usize;
            (start..start + list.value_length() as usize)
                .flat_map(|child| resolve_nodes(list.values().clone(), child, parts))
                .collect()
        }
        _ => Vec::new(),
    }
}

fn explode_node(array: ArrayRef, index: usize) -> Vec<(ArrayRef, usize)> {
    if index >= array.len() || array.is_null(index) {
        return Vec::new();
    }
    match array.data_type() {
        DataType::List(_) => {
            let list = array
                .as_any()
                .downcast_ref::<ListArray>()
                .expect("list type");
            let offsets = list.value_offsets();
            (offsets[index] as usize..offsets[index + 1] as usize)
                .flat_map(|child| explode_node(list.values().clone(), child))
                .collect()
        }
        DataType::LargeList(_) => {
            let list = array
                .as_any()
                .downcast_ref::<LargeListArray>()
                .expect("large list type");
            let offsets = list.value_offsets();
            (offsets[index] as usize..offsets[index + 1] as usize)
                .flat_map(|child| explode_node(list.values().clone(), child))
                .collect()
        }
        _ => vec![(array, index)],
    }
}

fn sha256_values(batch: &RecordBatch, row: usize, value_path: &str) -> Vec<String> {
    let hashes_path = value_path.strip_suffix(".value").unwrap_or(value_path);
    let mut parts = hashes_path.split('.');
    let Some(root) = parts.next() else {
        return Vec::new();
    };
    let Ok(column) = batch.schema().index_of(root) else {
        return Vec::new();
    };
    let remaining = parts.collect::<Vec<_>>();
    let nodes = resolve_nodes(batch.column(column).clone(), row, &remaining);
    let mut values = Vec::new();
    for (array, index) in nodes {
        for (array, index) in explode_node(array, index) {
            let Some(structure) = array.as_any().downcast_ref::<StructArray>() else {
                continue;
            };
            let fields = match structure.data_type() {
                DataType::Struct(fields) => fields,
                _ => continue,
            };
            let field = |name: &str| fields.iter().position(|value| value.name() == name);
            let algorithm_id = field("algorithm_id")
                .and_then(|position| scalar_i64(structure.column(position).as_ref(), index))
                .unwrap_or(0);
            let algorithm = field("algorithm")
                .and_then(|position| scalar_string(structure.column(position).as_ref(), index))
                .unwrap_or_default()
                .to_ascii_lowercase()
                .replace('-', "");
            if algorithm_id == 3 || algorithm == "sha256" {
                if let Some(value) = field("value")
                    .and_then(|position| scalar_string(structure.column(position).as_ref(), index))
                {
                    values.push(value);
                }
            }
        }
    }
    values
}

fn scalar_string(array: &dyn Array, index: usize) -> Option<String> {
    if array.is_null(index) {
        return None;
    }
    if let Some(values) = array.as_any().downcast_ref::<StringArray>() {
        return Some(values.value(index).to_string());
    }
    if let Some(values) = array.as_any().downcast_ref::<LargeStringArray>() {
        return Some(values.value(index).to_string());
    }
    if let Some(values) = array.as_any().downcast_ref::<StringViewArray>() {
        return Some(values.value(index).to_string());
    }
    if let Some(values) = array.as_any().downcast_ref::<BinaryArray>() {
        return std::str::from_utf8(values.value(index))
            .ok()
            .map(ToOwned::to_owned);
    }
    if let Some(values) = array.as_any().downcast_ref::<LargeBinaryArray>() {
        return std::str::from_utf8(values.value(index))
            .ok()
            .map(ToOwned::to_owned);
    }
    scalar_i64(array, index).map(|value| value.to_string())
}

fn scalar_i64(array: &dyn Array, index: usize) -> Option<i64> {
    if array.is_null(index) {
        return None;
    }
    if let Some(values) = array.as_any().downcast_ref::<Int64Array>() {
        return Some(values.value(index));
    }
    if let Some(values) = array.as_any().downcast_ref::<Int32Array>() {
        return Some(values.value(index) as i64);
    }
    if let Some(values) = array.as_any().downcast_ref::<UInt64Array>() {
        return i64::try_from(values.value(index)).ok();
    }
    if let Some(values) = array.as_any().downcast_ref::<UInt32Array>() {
        return Some(values.value(index) as i64);
    }
    None
}

fn event_time_ms_from_array(array: &dyn Array, row: usize) -> u64 {
    if row >= array.len() {
        return 0;
    }
    if array.is_null(row) {
        return 0;
    }
    let value = match array.data_type() {
        DataType::Timestamp(arrow_schema::TimeUnit::Second, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampSecondType>>()
            .map(|values| values.value(row).saturating_mul(1_000)),
        DataType::Timestamp(arrow_schema::TimeUnit::Millisecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMillisecondType>>()
            .map(|values| values.value(row)),
        DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMicrosecondType>>()
            .map(|values| values.value(row) / 1_000),
        DataType::Timestamp(arrow_schema::TimeUnit::Nanosecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampNanosecondType>>()
            .map(|values| values.value(row) / 1_000_000),
        _ => scalar_i64(array, row),
    };
    value
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(0)
}

pub(crate) fn event_time_us_from_array(array: &dyn Array, row: usize) -> Option<i64> {
    if row >= array.len() {
        return None;
    }
    if array.is_null(row) {
        return None;
    }
    match array.data_type() {
        DataType::Timestamp(arrow_schema::TimeUnit::Second, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampSecondType>>()
            .map(|values| values.value(row).saturating_mul(1_000_000)),
        DataType::Timestamp(arrow_schema::TimeUnit::Millisecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMillisecondType>>()
            .map(|values| values.value(row).saturating_mul(1_000)),
        DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMicrosecondType>>()
            .map(|values| values.value(row)),
        DataType::Timestamp(arrow_schema::TimeUnit::Nanosecond, _) => array
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampNanosecondType>>()
            .map(|values| values.value(row) / 1_000),
        _ => scalar_i64(array, row),
    }
}

fn canonicalize(value: &str, kind: &str) -> String {
    let value = value.trim();
    if kind == "ip" {
        if let Ok(address) = value.parse::<IpAddr>() {
            return match address {
                IpAddr::V6(value) => value
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(value))
                    .to_string()
                    .to_lowercase(),
                other => other.to_string().to_lowercase(),
            };
        }
    }
    value.to_lowercase()
}

fn entity_digest(key: &[u8], value: &str) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).context("invalid HMAC key")?;
    mac.update(NORMALIZATION_VERSION.as_bytes());
    mac.update(&[0]);
    mac.update(value.as_bytes());
    Ok(mac.finalize().into_bytes().into())
}

/// The stored form of an entity digest: the LEADING `ENTITY_VALUE_HASH_BYTES`
/// bytes of the full HMAC. The probe side (sidecar.rs) truncates its full
/// probe hash identically, so equality on the stored prefix is a superset of
/// equality on the full hash — over-selection only, never under-selection.
fn stored_entity_digest(digest: [u8; 32]) -> [u8; ENTITY_VALUE_HASH_BYTES] {
    let mut stored = [0_u8; ENTITY_VALUE_HASH_BYTES];
    stored.copy_from_slice(&digest[..ENTITY_VALUE_HASH_BYTES]);
    stored
}

pub fn schema_leaf_types(schema: &Schema) -> BTreeMap<String, String> {
    let mut output = BTreeMap::new();
    for field in schema.fields() {
        schema_field_types(field, "", false, &mut output);
    }
    output
}

fn schema_field_types(
    field: &Field,
    prefix: &str,
    repeated: bool,
    output: &mut BTreeMap<String, String>,
) {
    let path = if prefix.is_empty() {
        field.name().clone()
    } else {
        format!("{prefix}.{}", field.name())
    };
    match field.data_type() {
        DataType::Struct(fields) => {
            for child in fields {
                schema_field_types(child, &path, repeated, output);
            }
        }
        DataType::List(child) | DataType::LargeList(child) | DataType::FixedSizeList(child, _) => {
            if let DataType::Struct(fields) = child.data_type() {
                for nested in fields {
                    schema_field_types(nested, &path, true, output);
                }
            } else {
                output.insert(path, "array".to_string());
            }
        }
        data_type => {
            let kind = if repeated {
                "array"
            } else {
                match data_type {
                    DataType::Boolean => "boolean",
                    DataType::Int8
                    | DataType::Int16
                    | DataType::Int32
                    | DataType::UInt8
                    | DataType::UInt16
                    | DataType::UInt32 => "integer",
                    DataType::Int64 | DataType::UInt64 => "long",
                    DataType::Float16
                    | DataType::Float32
                    | DataType::Float64
                    | DataType::Decimal32(_, _)
                    | DataType::Decimal64(_, _)
                    | DataType::Decimal128(_, _)
                    | DataType::Decimal256(_, _) => "float",
                    DataType::Timestamp(_, _)
                    | DataType::Date32
                    | DataType::Date64
                    | DataType::Time32(_)
                    | DataType::Time64(_) => "timestamp",
                    _ => "string",
                }
            };
            output.insert(path, kind.to_string());
        }
    }
}

fn directory_bytes(path: &Path) -> Result<u64> {
    let mut pending = vec![path.to_path_buf()];
    let mut bytes = 0_u64;
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                pending.push(entry.path());
            } else if entry.file_type()?.is_file() {
                bytes = bytes.saturating_add(entry.metadata()?.len());
            }
        }
    }
    Ok(bytes)
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let file = File::create(path)?;
    serde_json::to_writer_pretty(&file, value)?;
    File::open(path)?.sync_all()?;
    Ok(())
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_restart_child() {
        let Ok(root) = std::env::var("NAN2460_RESTART_FIXTURE") else { return; };
        let root = Path::new(&root);
        build_generation_reusing(&root.join("input"), &root.join("output"),
            &root.join("stamps.json"), "tenant-a", "key-v1", &root.join("key"),
            1, 20_000_000, None).unwrap();
    }

    #[test]
    fn sigkill_after_each_derivative_receipt_resumes_same_tree() {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::process::ExitStatusExt;
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_incremental_test_event(&input.join("hour=2/object.parquet"), "host-a", 1_786_388_123_456_789);
        std::fs::write(root.path().join("key"), [7_u8; 32]).unwrap();
        write_json(&root.path().join("stamps.json"), &ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".into(), snapshot_id: 73,
            table: "test.events".into(), objects: vec![incremental_test_stamp(&input, "hour=2/object.parquet", "v1")],
            table_uuid: None,
        }).unwrap();
        let mut entity_inode = None;
        for phase in ["entity-sidecar", "keyword-sidecar", "fragment-sidecar", "identity-snapshot", "count-rollup"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "generation::tests::generation_restart_child", "--nocapture"])
                .env("NAN2460_RESTART_FIXTURE", root.path()).env("NAN2460_KILL_AFTER_PHASE", phase)
                .stdout(std::process::Stdio::null()).status().unwrap();
            assert_eq!(status.signal(), Some(libc::SIGKILL), "{phase}");
            let candidate = std::fs::read_dir(root.path()).unwrap().filter_map(Result::ok)
                .find(|entry| entry.file_name().to_string_lossy().starts_with(".generation-build-")).unwrap().path();
            assert!(candidate.join(format!(".{phase}.receipt.json")).is_file());
            let inode = std::fs::metadata(candidate.join("tree/entity-sidecar/object-0000.parquet")).unwrap().ino();
            if let Some(prior) = entity_inode { assert_eq!(inode, prior, "completed entity artifact rebuilt after {phase}"); }
            entity_inode = Some(inode);
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "generation::tests::generation_restart_child"])
            .env("NAN2460_RESTART_FIXTURE", root.path()).stdout(std::process::Stdio::null()).status().unwrap();
        assert!(status.success());
        assert_eq!(std::fs::metadata(root.path().join("output/entity-sidecar/object-0000.parquet")).unwrap().ino(), entity_inode.unwrap());
    }

    #[test]
    fn derivative_phase_receipt_survives_restart_and_rebuilds_only_unfinished_work() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        for phase in ["entity-sidecar", "keyword-sidecar", "fragment-sidecar", "identity-snapshot", "count-rollup"] {
            let directory = tree.join(phase);
            let interrupted: Result<u64> = resume_derivative_phase(&tree, phase, || {
                std::fs::write(directory.join("incomplete"), b"partial")?;
                bail!("fixture interrupted before receipt")
            });
            assert!(interrupted.is_err());
            let completed = resume_derivative_phase(&tree, phase, || {
                assert!(!directory.join("incomplete").exists());
                std::fs::write(directory.join("artifact"), b"complete")?;
                Ok(73_u64)
            }).unwrap();
            let resumed: u64 = resume_derivative_phase(&tree, phase, || {
                panic!("completed phase must not rebuild after restart")
            }).unwrap();
            assert_eq!(resumed, completed);
            assert_eq!(std::fs::read(directory.join("artifact")).unwrap(), b"complete");
        }
    }

    #[test]
    fn pinned_metadata_rejects_corrupt_gzip_and_encoded_or_decoded_overflow() {
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&vec![b' '; 4096]).unwrap();
        let compressed = encoder.finish().unwrap();
        assert!(compressed.len() < 1024);
        assert!(decode_pinned_metadata(&compressed, 1024)
            .unwrap_err()
            .to_string()
            .contains("decoded byte bound"));
        assert!(decode_pinned_metadata(&[b' '; 1025], 1024)
            .unwrap_err()
            .to_string()
            .contains("byte bound"));
        assert!(decode_pinned_metadata(&[0x1f, 0x8b, 0], 1024).is_err());
    }

    #[test]
    fn keyword_merge_policy_reduces_only_the_excess_with_disjoint_pairs() {
        assert_eq!(bounded_merge_pair_count(16, 16), 0);
        assert_eq!(bounded_merge_pair_count(17, 16), 1);
        assert_eq!(bounded_merge_pair_count(24, 16), 8);
        assert_eq!(bounded_merge_pair_count(100, 16), 50);
    }

    #[test]
    fn keyword_thread_layout_bounds_producers_and_one_total_cpu_budget() {
        assert_eq!(
            keyword_thread_layout(1, KEYWORD_PRODUCER_CEILING),
            KeywordThreadLayout {
                producers: 1,
                indexers: 1,
                mergers: 1,
            }
        );
        assert_eq!(
            keyword_thread_layout(4, KEYWORD_PRODUCER_CEILING),
            KeywordThreadLayout {
                producers: 1,
                indexers: 2,
                mergers: 1,
            }
        );
        assert_eq!(
            keyword_thread_layout(8, KEYWORD_PRODUCER_CEILING),
            KeywordThreadLayout {
                producers: 3,
                indexers: 3,
                mergers: 2,
            }
        );
        let wide = keyword_thread_layout(32, KEYWORD_PRODUCER_CEILING);
        assert_eq!(wide.producers, KEYWORD_PRODUCER_CEILING);
        assert_eq!(wide.producers + wide.indexers + wide.mergers, 32);
        let retained_volume = keyword_thread_layout(16, 6);
        assert_eq!(retained_volume.producers, 6);
        assert_eq!(
            retained_volume.producers + retained_volume.indexers + retained_volume.mergers,
            16
        );
    }

    #[test]
    fn derivative_memory_bound_limits_decoded_object_lanes_without_changing_cpu_budget() {
        let layout = generation_build_thread_layout(8, 1_073_741_824, 4, 4, 6_442_450_944).unwrap();
        assert_eq!(layout.configured_threads, 8);
        assert_eq!(layout.entity_threads, 4);
        assert_eq!(layout.keyword_producer_ceiling, 1);
        assert_eq!(layout.count_rollup_threads, 4);
        assert_eq!(layout.derivative_build_memory_bytes, 6_442_450_944);

        let large =
            generation_build_thread_layout(32, 1_073_741_824, 8, 12, 64_424_509_440).unwrap();
        assert_eq!(large.entity_threads, 32);
        assert_eq!(large.keyword_producer_ceiling, 12);
        assert!(generation_build_thread_layout(8, 1_073_741_824, 4, 4, 3_000_000_000).is_err());
    }

    #[test]
    fn count_rollup_hash_aggregation_is_sorted_deterministically_before_encoding() {
        let first = (
            300_000_000,
            5,
            Arc::<str>::from("windows_sysmon"),
            Some("host-b".to_string()),
        );
        let second = (0, 0, Arc::<str>::from("apache_http_server"), None);
        let mut forward = HashMap::new();
        forward.insert(first.clone(), 2);
        forward.insert(second.clone(), 3);
        let mut reverse = HashMap::new();
        reverse.insert(second, 3);
        reverse.insert(first, 2);

        let forward = ordered_count_rollups(forward);
        let reverse = ordered_count_rollups(reverse);
        assert_eq!(forward, reverse);
        assert_eq!(forward[0].0 .0, 0);
        assert_eq!(forward[1].0 .0, 300_000_000);
        assert_eq!(count_rollup_batch(&forward).unwrap().num_rows(), 2);
    }

    #[test]
    fn compiled_string_path_matches_dynamic_nested_lookup() {
        let metadata = StructArray::from(vec![(
            Arc::new(Field::new("log_source", DataType::Utf8, true)),
            Arc::new(StringArray::from(vec![Some("windows_sysmon"), None])) as ArrayRef,
        )]);
        let batch =
            RecordBatch::try_from_iter(vec![("metadata", Arc::new(metadata) as ArrayRef)]).unwrap();
        let compiled = CompiledStringPath::new(&batch, "metadata.log_source").unwrap();

        assert_eq!(
            compiled.strings(0),
            path_strings(&batch, 0, "metadata.log_source")
        );
        assert_eq!(
            compiled.strings(1),
            path_strings(&batch, 1, "metadata.log_source")
        );
        assert!(CompiledStringPath::new(&batch, "metadata.missing").is_none());
    }

    #[test]
    fn batched_parallel_count_rollups_preserve_exact_summed_counts_and_order() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        let hostnames = vec!["host-a"; 40_000];
        write_multi_host_test_events(
            &input.join("hour=1/object-a.parquet"),
            &hostnames,
            1_786_388_123_456_789,
            8_192,
        );
        write_incremental_test_event(
            &input.join("hour=2/object-b.parquet"),
            "host-b",
            1_786_391_723_456_789,
        );
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=2/object-b.parquet", "v2"),
                incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let stamp_path = root.path().join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        let objects = local_objects(&input, &stamps).unwrap();
        let output = root.path().join("count-rollup");
        std::fs::create_dir(&output).unwrap();
        let manifest =
            build_count_rollup(&output, &stamp_path, "tenant-a", &stamps, &objects, None, 2)
                .unwrap();

        assert_eq!(manifest.objects.len(), 2);
        assert_eq!(
            manifest
                .objects
                .iter()
                .map(|object| object.object_id)
                .collect::<Vec<_>>(),
            vec![0, 1]
        );
        let mut source_events = 0_u64;
        let mut missing_process_events = 0_u64;
        let reader = ParquetRecordBatchReaderBuilder::try_new(
            File::open(output.join("object-0000.parquet")).unwrap(),
        )
        .unwrap()
        .build()
        .unwrap();
        for batch in reader {
            let batch = batch.unwrap();
            let fields = batch
                .column_by_name("field_id")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt16Array>()
                .unwrap();
            let values = batch
                .column_by_name("value")
                .unwrap()
                .as_any()
                .downcast_ref::<StringArray>()
                .unwrap();
            let events = batch
                .column_by_name("events")
                .unwrap()
                .as_any()
                .downcast_ref::<UInt64Array>()
                .unwrap();
            for row in 0..batch.num_rows() {
                if fields.value(row) == 0
                    && !values.is_null(row)
                    && values.value(row) == "windows_sysmon"
                {
                    source_events += events.value(row);
                }
                if fields.value(row) == 1 && values.is_null(row) {
                    missing_process_events += events.value(row);
                }
            }
        }
        assert_eq!(source_events, 40_000);
        assert_eq!(missing_process_events, 40_000);
    }

    #[test]
    fn snapshot_hydration_reuses_only_verified_exact_local_objects() {
        let prior = tempfile::tempdir().unwrap();
        let relative_path = "event_hour=1/object.parquet";
        let prior_object = prior.path().join("data").join(relative_path);
        std::fs::create_dir_all(prior_object.parent().unwrap()).unwrap();
        std::fs::write(&prior_object, b"immutable parquet fixture").unwrap();
        let stamp = ObjectStamp {
            relative_path: relative_path.to_string(),
            source_uri: format!("s3://bucket/events/data/{relative_path}"),
            version_id: "version-1".to_string(),
            size_bytes: std::fs::metadata(&prior_object).unwrap().len(),
            sha256: file_sha256(&prior_object).unwrap(),
        };
        write_json(
            &prior.path().join("object-stamps.json"),
            &ObjectStampManifest {
                metadata_location: "s3://bucket/events/metadata/v1.json".to_string(),
                snapshot_id: 1,
                table: "tenant.events".to_string(),
                objects: vec![stamp.clone()],
                table_uuid: None,
            },
        )
        .unwrap();

        let reusable = load_prior_hydration_objects(
            Some(prior.path()),
            "tenant.events",
            "s3://bucket/events/data/",
        );
        let exact = reusable.get(&stamp.source_uri).unwrap();
        let candidate = tempfile::tempdir().unwrap();
        let destination = candidate.path().join("object.parquet");
        assert!(reuse_exact_local_object(exact, &destination, None, false));
        assert_eq!(
            std::fs::read(&destination).unwrap(),
            b"immutable parquet fixture"
        );

        std::fs::write(&prior_object, b"corrupt object").unwrap();
        let corrupt_destination = candidate.path().join("corrupt.parquet");
        assert!(!reuse_exact_local_object(
            exact,
            &corrupt_destination,
            None,
            false
        ));
        assert!(!corrupt_destination.exists());
    }

    /// NAN-2849 acceptance: the publisher keeps its hydrated source through
    /// upload (roomy volume), so the second cycle's hydration links every
    /// unchanged object from it and downloads only the delta; the overlap
    /// costs only the delta on disk; and releasing the prior source after
    /// hydration leaves the new snapshot intact.
    #[tokio::test]
    async fn second_publisher_cycle_hydrates_only_the_delta_from_the_retained_prior() {
        use crate::publisher_disk_budget::{
            release_snapshot_data, run_publisher_build, trees_bytes, ByteMode,
            PublisherBuildLayout, PublisherBuildOutcome, PublisherDiskLimits,
        };
        const OBJECTS: usize = 40;
        const NEW: usize = 3;
        const OBJECT_BYTES: usize = 256 * 1024;
        let data_prefix = "s3://bucket/events/data/";
        let object = |index: usize| {
            let relative_path = format!("event_hour={}/object-{index:04}.parquet", index % 4);
            let mut content = vec![0_u8; OBJECT_BYTES];
            for (offset, byte) in content.iter_mut().enumerate() {
                *byte = (offset.wrapping_mul(31) ^ index.wrapping_mul(7919)) as u8;
            }
            (relative_path, content)
        };
        let stamp_for = |relative_path: &str, content: &[u8]| ObjectStamp {
            relative_path: relative_path.to_string(),
            source_uri: format!("{data_prefix}{relative_path}"),
            version_id: "version-1".to_string(),
            size_bytes: content.len() as u64,
            sha256: hex::encode(Sha256::digest(content)),
        };
        let root = tempfile::tempdir().unwrap();
        let generations = root.path().join("generations");
        // Cycle 1: hydrated (downloaded) snapshot 1, then built under the
        // disk discipline on a roomy volume.
        let first = generations.join("snapshot-1-aaaaaaaaaaaaaaaa");
        let first_snapshot = first.join("snapshot");
        let mut first_stamps = Vec::new();
        for index in 0..OBJECTS {
            let (relative_path, content) = object(index);
            let path = first_snapshot.join("data").join(&relative_path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, &content).unwrap();
            first_stamps.push(stamp_for(&relative_path, &content));
        }
        write_json(
            &first_snapshot.join("object-stamps.json"),
            &ObjectStampManifest {
                metadata_location: "s3://bucket/events/metadata/v1.metadata.json".to_string(),
                snapshot_id: 1,
                table: "tenant.events".to_string(),
                objects: first_stamps,
                table_uuid: None,
            },
        )
        .unwrap();
        let layout = PublisherBuildLayout {
            generations_root: generations.clone(),
            snapshot_root: first_snapshot.clone(),
            derivatives: first.join("derivatives-v1-0123456789abcdef"),
            prior_derivatives: None,
        };
        let limits = PublisherDiskLimits {
            declared_volume_bytes: None,
            reserve_bytes: 0,
            upload_staging_bytes: 0,
        };
        let derivatives = layout.derivatives.clone();
        let outcome = run_publisher_build(
            &layout,
            &limits,
            || Ok((u64::MAX / 4, u64::MAX / 4)),
            |_, _| {},
            |_| async move {
                std::fs::create_dir_all(derivatives.join("entity-sidecar")).unwrap();
                Ok::<_, anyhow::Error>(())
            },
            |_| async {
                std::fs::create_dir_all(layout.derivatives.join(crate::publisher_disk_budget::PREVALENCE_MEMBER)).unwrap();
                Ok::<_, anyhow::Error>(())
            },
        )
        .await
        .unwrap();
        let PublisherBuildOutcome::Built { decision, .. } = outcome else { panic!("cycle 1 must build") };
        assert!(decision.plan().keep_snapshot_data);
        assert!(first_snapshot.join("data").is_dir(), "the source survives upload as the next reuse source");

        // Cycle 2: object 0 expired, NEW objects committed. Hydrate exactly as
        // the publisher does: no admission proof, so every reuse re-verifies.
        let prior_objects = load_prior_hydration_objects(Some(&first_snapshot), "tenant.events", data_prefix);
        assert_eq!(prior_objects.len(), OBJECTS);
        let before = trees_bytes(&[&generations], ByteMode::Logical).unwrap();
        let second_data = generations.join("snapshot-2-bbbbbbbbbbbbbbbb/snapshot/data");
        let (mut reused, mut downloaded, mut peak) = (0_usize, 0_usize, before);
        for index in 1..OBJECTS + NEW {
            let (relative_path, content) = object(index);
            let destination = second_data.join(&relative_path);
            std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
            let source_uri = format!("{data_prefix}{relative_path}");
            if reuse_matching_prior_object(
                prior_objects.get(&source_uri), "version-1", content.len() as u64,
                &relative_path, &destination, None, true,
            ) {
                reused += 1;
            } else {
                std::fs::write(&destination, &content).unwrap();
                downloaded += 1;
            }
            peak = peak.max(trees_bytes(&[&generations], ByteMode::Logical).unwrap());
        }
        assert_eq!(reused, OBJECTS - 1, "every unchanged object is linked from the prior");
        assert_eq!(downloaded, NEW, "only the delta is downloaded");
        // Overlap peak: prior + delta (+ directory entries), never two copies.
        let delta = (NEW * OBJECT_BYTES) as u64;
        assert!(
            peak <= before + delta + 64 * 1024,
            "overlap peak {peak} exceeds prior {before} + delta {delta}"
        );
        // Post-hydration release of the prior source frees only what the new
        // snapshot no longer holds; the new snapshot stays intact.
        release_snapshot_data(&first_snapshot).unwrap();
        assert!(!first_snapshot.join("data").exists());
        assert!(first_snapshot.join("object-stamps.json").is_file());
        for index in 1..OBJECTS + NEW {
            let (relative_path, content) = object(index);
            assert_eq!(std::fs::read(second_data.join(&relative_path)).unwrap(), content);
        }
        let after = trees_bytes(&[&generations], ByteMode::Logical).unwrap();
        assert!(after <= before + delta - OBJECT_BYTES as u64 + 64 * 1024);
    }

    #[test]
    fn hydration_reuse_fixture_measures_verified_inode_path() {
        let content = vec![29_u8; 16 * 1024 * 1024];
        let digest = hex::encode(Sha256::digest(&content));
        let (prior, path, _) = hydration_fixture(&content, &digest);
        let objects = load_prior_hydration_objects(Some(prior.path()), "tenant.events", "s3://bucket/events/data/");
        let object = objects.values().next().unwrap();
        let output = tempfile::tempdir().unwrap();
        let started = Instant::now();
        assert!(reuse_exact_local_object(object, &output.path().join("cold"), None, false));
        let cold_ms = started.elapsed().as_secs_f64() * 1000.0;
        let stamp = verification_stamp_for(&path, &digest);
        let started = Instant::now();
        assert!(reuse_exact_local_object(object, &output.path().join("warm"), Some(&stamp), false));
        let warm_ms = started.elapsed().as_secs_f64() * 1000.0;
        eprintln!("NAN2460 hydration reuse fixture: bytes=16777216 cold_verify_ms={cold_ms:.3} verified_inode_ms={warm_ms:.3}");
    }

    #[test]
    fn incompatible_prior_hydration_manifest_falls_back_to_download() {
        let prior = tempfile::tempdir().unwrap();
        write_json(
            &prior.path().join("object-stamps.json"),
            &ObjectStampManifest {
                metadata_location: "s3://bucket/events/metadata/v1.json".to_string(),
                snapshot_id: 1,
                table: "other.events".to_string(),
                objects: Vec::new(),
                table_uuid: None,
            },
        )
        .unwrap();
        assert!(load_prior_hydration_objects(
            Some(prior.path()),
            "tenant.events",
            "s3://bucket/events/data/",
        )
        .is_empty());
    }

    fn hydration_fixture(
        content: &[u8],
        sha256: &str,
    ) -> (tempfile::TempDir, PathBuf, ObjectStamp) {
        let prior = tempfile::tempdir().unwrap();
        let relative_path = "event_hour=1/object.parquet";
        let prior_object = prior.path().join("data").join(relative_path);
        std::fs::create_dir_all(prior_object.parent().unwrap()).unwrap();
        std::fs::write(&prior_object, content).unwrap();
        let stamp = ObjectStamp {
            relative_path: relative_path.to_string(),
            source_uri: format!("s3://bucket/events/data/{relative_path}"),
            version_id: "version-1".to_string(),
            size_bytes: std::fs::metadata(&prior_object).unwrap().len(),
            sha256: sha256.to_string(),
        };
        write_json(
            &prior.path().join("object-stamps.json"),
            &ObjectStampManifest {
                metadata_location: "s3://bucket/events/metadata/v1.json".to_string(),
                snapshot_id: 1,
                table: "tenant.events".to_string(),
                objects: vec![stamp.clone()],
                table_uuid: None,
            },
        )
        .unwrap();
        (prior, prior_object, stamp)
    }

    fn verification_stamp_for(path: &Path, sha256: &str) -> LocalVerificationStamp {
        let metadata = std::fs::metadata(path).unwrap();
        LocalVerificationStamp {
            sha256: sha256.to_string(),
            size_bytes: metadata.len(),
            dev: metadata.dev(),
            inode: metadata.ino(),
            mtime_seconds: metadata.mtime(),
            mtime_nanoseconds: metadata.mtime_nsec(),
        }
    }

    #[test]
    fn r2_hydration_skips_head_only_for_verified_immutable_local_files() {
        let digest = hex::encode(Sha256::digest(b"cached parquet"));
        let (_root, path, mut stamp) = hydration_fixture(b"cached parquet", &digest);
        stamp.version_id = format!("r2-etag-sha256:{}", "a".repeat(64));
        let prior = PriorHydrationObject { path: path.clone(), stamp };
        let verification = verification_stamp_for(&path, &digest);
        let out = tempfile::tempdir().unwrap();
        let relative = &prior.stamp.relative_path;
        let unsampled = (1..10000).find(|id| !sample_reverify(*id, relative)).unwrap();
        let sampled = (1..10000).find(|id| sample_reverify(*id, relative)).unwrap();
        assert!(reuse_verified_r2_object(Some(&prior), Some(&verification), 14, relative, unsampled, &out.path().join("hit")));
        assert!(!reuse_verified_r2_object(Some(&prior), None, 14, relative, unsampled, &out.path().join("no-ledger")));
        assert!(!reuse_verified_r2_object(Some(&prior), Some(&verification), 14, relative, sampled, &out.path().join("sample")));
        assert!(!reuse_verified_r2_object(Some(&prior), Some(&verification), 15, relative, unsampled, &out.path().join("size")));
        let mut versioned = prior.clone(); versioned.stamp.version_id = "s3-version".into();
        assert!(!reuse_verified_r2_object(Some(&versioned), Some(&verification), 14, relative, unsampled, &out.path().join("s3")));
        std::fs::write(&path, b"changed parquet").unwrap();
        assert!(!reuse_verified_r2_object(Some(&prior), Some(&verification), 14, relative, unsampled, &out.path().join("changed")));
    }

    #[test]
    fn hydration_reuse_trusts_verification_stamp_without_rehash() {
        // The stamp digest is deliberately NOT the file's real digest: reuse
        // succeeding under a matching stat proves no re-hash happened, which
        // is exactly the NAN-2361 O(delta) property.
        let fake_sha = "1".repeat(64);
        let (prior, prior_object, stamp) =
            hydration_fixture(b"immutable parquet fixture", &fake_sha);
        let reusable = load_prior_hydration_objects(
            Some(prior.path()),
            "tenant.events",
            "s3://bucket/events/data/",
        );
        let exact = reusable.get(&stamp.source_uri).unwrap();
        let verification = verification_stamp_for(&prior_object, &fake_sha);
        let candidate = tempfile::tempdir().unwrap();
        assert!(reuse_exact_local_object(
            exact,
            &candidate.path().join("trusted.parquet"),
            Some(&verification),
            false
        ));
        // The sampled promotion must ignore the stamp and re-hash in full:
        // the fake digest then fails, so sampling keeps the fence non-vacuous.
        assert!(!reuse_exact_local_object(
            exact,
            &candidate.path().join("sampled.parquet"),
            Some(&verification),
            true
        ));
        // Any stat drift (here: a bumped mtime) falls back to the full hash.
        let file = File::options().write(true).open(&prior_object).unwrap();
        file.set_times(
            std::fs::FileTimes::new()
                .set_modified(std::time::SystemTime::now() + std::time::Duration::from_secs(30)),
        )
        .unwrap();
        drop(file);
        assert!(!reuse_exact_local_object(
            exact,
            &candidate.path().join("drifted.parquet"),
            Some(&verification),
            false
        ));
    }

    #[test]
    fn the_reverify_sample_actually_selects_and_rotates() {
        // NAN-2361: the tamper tests above force full verification directly,
        // so NOTHING exercised the sampler itself. Stubbing sample_reverify to
        // `false` left the whole suite green while silently converting
        // "detected within an expected 64 promotions" into "never detected" --
        // the trust-an-inode trade has no backstop without this. Assert the
        // two properties the integrity argument actually rests on.
        let names: Vec<String> = (0..10_000).map(|i| format!("obj-{i}.parquet")).collect();
        let selected = |snapshot: i64| -> usize {
            names
                .iter()
                .filter(|n| sample_reverify(snapshot, n))
                .count()
        };

        // 1. It selects a live fraction near 1/REVERIFY_SAMPLE_DENOMINATOR.
        //    A stub returning a constant fails here in either direction.
        let expected = names.len() as f64 / REVERIFY_SAMPLE_DENOMINATOR as f64;
        let hits = selected(1_234_567) as f64;
        assert!(
            hits > expected * 0.5 && hits < expected * 1.5,
            "sampler must select ~1/{} of objects, got {hits} of {} (expected ~{expected})",
            REVERIFY_SAMPLE_DENOMINATOR,
            names.len()
        );

        // 2. Consecutive promotions must sample DIFFERENT objects, or a
        //    tampered object outside the first sample is never re-checked and
        //    the bounded-detection claim is false.
        let a: Vec<&String> = names
            .iter()
            .filter(|n| sample_reverify(1_234_567, n))
            .collect();
        let b: Vec<&String> = names
            .iter()
            .filter(|n| sample_reverify(987_654_321, n))
            .collect();
        assert!(
            !a.is_empty() && !b.is_empty(),
            "both promotions must sample something"
        );
        let overlap = a.iter().filter(|n| b.contains(n)).count();
        assert!(
            overlap * 4 < a.len(),
            "samples must rotate across snapshots; {overlap} of {} repeated",
            a.len()
        );
    }

    #[test]
    fn hydration_reuse_detects_tampered_object() {
        let content = b"immutable parquet fixture";
        let real_sha = hex::encode(Sha256::digest(content));
        let (prior, prior_object, stamp) = hydration_fixture(content, &real_sha);
        let reusable = load_prior_hydration_objects(
            Some(prior.path()),
            "tenant.events",
            "s3://bucket/events/data/",
        );
        let exact = reusable.get(&stamp.source_uri).unwrap();
        let verification = verification_stamp_for(&prior_object, &real_sha);
        let recorded_mtime = std::fs::metadata(&prior_object)
            .unwrap()
            .modified()
            .unwrap();
        // Tamper in place with the SAME length, then restore the recorded
        // mtime so the cheap stat corroboration cannot see the change.
        std::fs::write(&prior_object, b"immutable parquet fixturX").unwrap();
        let file = File::options().write(true).open(&prior_object).unwrap();
        file.set_times(std::fs::FileTimes::new().set_modified(recorded_mtime))
            .unwrap();
        drop(file);
        let candidate = tempfile::tempdir().unwrap();
        // Without a verification stamp the fence is still exact.
        assert!(!reuse_exact_local_object(
            exact,
            &candidate.path().join("unstamped.parquet"),
            None,
            false
        ));
        // The sampled full re-hash detects the tamper even behind a stamp.
        assert!(!reuse_exact_local_object(
            exact,
            &candidate.path().join("sampled.parquet"),
            Some(&verification),
            true
        ));
    }

    #[test]
    fn artifact_reuse_hard_links_and_sampled_verification_detects_tamper() {
        let root = tempfile::tempdir().unwrap();
        let source = root.path().join("artifact.parquet");
        std::fs::write(&source, b"entity sidecar artifact bytes").unwrap();
        let sha = file_digest(&source).unwrap();
        let bytes = std::fs::metadata(&source).unwrap().len();
        let reused = root.path().join("reused.parquet");
        assert!(reuse_verified_artifact(&source, &reused, bytes, &sha, false).unwrap());
        // Hard link: the reused artifact IS the proven inode — no bytes were
        // read, copied, or re-hashed (the O(delta) property under test).
        assert_eq!(
            std::fs::metadata(&reused).unwrap().ino(),
            std::fs::metadata(&source).unwrap().ino()
        );
        // Same-length tamper: the sampled full verification must catch it.
        std::fs::write(&source, b"entity sidecar artifact bytEs").unwrap();
        assert!(!reuse_verified_artifact(
            &source,
            &root.path().join("sampled.parquet"),
            bytes,
            &sha,
            true
        )
        .unwrap());
        // A size change is always rejected, sampled or not.
        std::fs::write(&source, b"short").unwrap();
        assert!(!reuse_verified_artifact(
            &source,
            &root.path().join("sized.parquet"),
            bytes,
            &sha,
            false
        )
        .unwrap());
        // Malformed expected digests never authorize reuse.
        assert!(!reuse_verified_artifact(
            &source,
            &root.path().join("bad.parquet"),
            bytes,
            "ABC",
            false
        )
        .unwrap());
    }

    #[test]
    fn uid_proof_bucket_coupling_is_exact_and_order_preserving() {
        // BUCKETS and the digest-prefix shift are one decision: changing one
        // without the other silently corrupts the uniqueness proof.
        assert_eq!(UID_PROOF_BUCKETS, 1 << (8 - UID_PROOF_BUCKET_SHIFT));
        let mut last = 0_usize;
        for byte in 0_u16..=255 {
            let bucket = usize::from((byte as u8) >> UID_PROOF_BUCKET_SHIFT);
            assert!(bucket < UID_PROOF_BUCKETS);
            // Bucket order must preserve digest order so concatenating sorted
            // buckets yields one globally sorted window file.
            assert!(bucket >= last);
            last = bucket;
        }
        assert_eq!(last, UID_PROOF_BUCKETS - 1);
    }

    fn write_incremental_test_event(path: &Path, hostname: &str, time_us: i64) {
        write_incremental_test_event_with_message(
            path,
            hostname,
            time_us,
            &format!("process start on {hostname}"),
        );
    }

    fn write_incremental_test_event_with_message(
        path: &Path,
        hostname: &str,
        time_us: i64,
        message: &str,
    ) {
        let metadata = StructArray::from(vec![
            (
                Arc::new(Field::new("uid", DataType::Utf8, false)),
                Arc::new(StringArray::from(vec![format!(
                    "event-{hostname}-{time_us}"
                )])) as ArrayRef,
            ),
            (
                Arc::new(Field::new("log_source", DataType::Utf8, false)),
                Arc::new(StringArray::from(vec!["windows_sysmon"])) as ArrayRef,
            ),
        ]);
        let device = StructArray::from(vec![(
            Arc::new(Field::new("hostname", DataType::Utf8, false)),
            Arc::new(StringArray::from(vec![hostname])) as ArrayRef,
        )]);
        let src_endpoint = StructArray::from(vec![(
            Arc::new(Field::new("ip", DataType::Utf8, false)),
            Arc::new(StringArray::from(vec!["10.1.2.3"])) as ArrayRef,
        )]);
        let time = arrow_array::TimestampMicrosecondArray::from(vec![time_us]).with_timezone("UTC");
        let message = StringArray::from(vec![message.to_string()]);
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", time.data_type().clone(), false),
            Field::new("metadata", metadata.data_type().clone(), false),
            Field::new("device", device.data_type().clone(), false),
            Field::new("src_endpoint", src_endpoint.data_type().clone(), false),
            Field::new("message", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(time),
                Arc::new(metadata),
                Arc::new(device),
                Arc::new(src_endpoint),
                Arc::new(message),
            ],
        )
        .unwrap();
        let mut writer = ArrowWriter::try_new(File::create(path).unwrap(), schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    fn incremental_test_stamp(root: &Path, relative_path: &str, version: &str) -> ObjectStamp {
        let path = root.join(relative_path);
        ObjectStamp {
            relative_path: relative_path.to_string(),
            source_uri: format!("s3://test/events/data/{relative_path}"),
            version_id: version.to_string(),
            size_bytes: std::fs::metadata(&path).unwrap().len(),
            sha256: file_digest(&path).unwrap(),
        }
    }

    fn entity_object_ids(path: &Path) -> Vec<u32> {
        ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
            .unwrap()
            .build()
            .unwrap()
            .flat_map(|batch| {
                let batch = batch.unwrap();
                batch
                    .column_by_name("object_id")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<UInt32Array>()
                    .unwrap()
                    .values()
                    .to_vec()
            })
            .collect()
    }

    fn uid_proof_mode(root: &Path) -> String {
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(root.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        manifest["event_uid_uniqueness"]["mode"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn load_keyword_sidecar(root: &Path) -> crate::text_sidecar::KeywordSidecar {
        let keyword_manifest = root.join("keyword-sidecar/manifest.json");
        let source_manifest: crate::planner::SourceManifest =
            serde_json::from_slice(&std::fs::read(&keyword_manifest).unwrap()).unwrap();
        crate::text_sidecar::KeywordSidecar::load(
            &keyword_manifest,
            &root.join("keyword-sidecar/index"),
            &root.join("fragment-sidecar/manifest.json"),
            &root.join("fragment-sidecar/index"),
            "tenant-a",
            &source_manifest,
        )
        .unwrap()
    }

    /// Documents in the serving fragment index whose stored exact term equals
    /// `term_text`: 1 when the dictionary kept the term, 0 when it filtered
    /// or never saw it.
    fn fragment_exact_term_doc_freq(root: &Path, term_text: &str) -> u64 {
        let index = Index::open_in_dir(root.join("fragment-sidecar/index")).unwrap();
        let exact_term = index.schema().get_field("exact_term").unwrap();
        index
            .reader()
            .unwrap()
            .searcher()
            .doc_freq(&Term::from_field_text(exact_term, term_text))
            .unwrap()
    }

    fn keyword_candidate_keys(root: &Path, mode: &str, value: &str) -> BTreeSet<String> {
        let sidecar = load_keyword_sidecar(root);
        match sidecar.plan(mode, value).unwrap() {
            crate::text_sidecar::KeywordPlan::Candidates { candidates, .. } => candidates
                .into_iter()
                .map(|candidate| candidate.event_object_key)
                .collect(),
            crate::text_sidecar::KeywordPlan::Fallback(evidence) => {
                panic!(
                    "unexpected keyword fallback: {:?}",
                    evidence.fallback_reason
                )
            }
        }
    }

    /// NAN-2361 skip-hex8: long hex terms (file hashes) never enter the
    /// fragment accelerator, and the planner routes contains/regex hunts
    /// over hex-only text to the UNPRUNED exact lane — never to an empty or
    /// under-selected candidate set.
    #[test]
    fn fragment_skip_hex8_excludes_long_hex_and_planner_routes_to_exact_lane() {
        use crate::text_sidecar::KeywordPlan;

        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event_with_message(
            &input.join("hour=1/object-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
            "rundll32 dropped deadbeefcafe1234 alongside deadbee",
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![incremental_test_stamp(
                &input,
                "hour=1/object-a.parquet",
                "v1",
            )],
            table_uuid: None,
        };
        let stamp_path = root.path().join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        let output = root.path().join("generation");
        build_generation_reusing(
            &input,
            &output,
            &stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();

        // The serving manifest declares the filter and its exact accounting.
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(output.join("fragment-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["filter_profile"], "skip-hex8");
        assert_eq!(manifest["filtered_terms"], 1); // deadbeefcafe1234
        assert_eq!(
            manifest["source_terms"].as_u64().unwrap(),
            manifest["indexed_terms"].as_u64().unwrap() + 1
        );

        // Index content: >=8-byte hex excluded; 7-byte hex and non-hex kept.
        assert_eq!(fragment_exact_term_doc_freq(&output, "deadbeefcafe1234"), 0);
        assert_eq!(fragment_exact_term_doc_freq(&output, "deadbee"), 1);
        assert_eq!(fragment_exact_term_doc_freq(&output, "rundll32"), 1);

        let sidecar = load_keyword_sidecar(&output);
        // A contains/regex hunt over an excluded hash must fall back to the
        // unpruned exact lane (Fallback contributes NO candidate set, so the
        // source recheck scans everything and still finds the event). An
        // empty Candidates set here would fence the query to zero rows.
        for mode in ["contains", "regex_guard"] {
            match sidecar.plan(mode, "deadbeefcafe1234").unwrap() {
                KeywordPlan::Fallback(evidence) => {
                    assert!(!evidence.accelerated);
                    assert!(
                        evidence.fallback_reason.unwrap().contains("hex-only"),
                        "fallback must be attributed to the hex guard"
                    );
                }
                KeywordPlan::Candidates { .. } => {
                    panic!("hex contains/regex must never use the filtered fragment lane")
                }
            }
        }
        // The token (exact word) lane is untouched by the fragment filter:
        // the hash is still a keyword-index term and selects its block.
        assert_eq!(
            keyword_candidate_keys(&output, "token", "deadbeefcafe1234").len(),
            1
        );
        // Short hex tokens are conservatively routed away too: "deadbee"
        // could be a substring of some other filtered hash term.
        assert!(matches!(
            sidecar.plan("contains", "deadbee").unwrap(),
            KeywordPlan::Fallback(_)
        ));
        // A non-hex token can never hide inside a filtered hex term, so the
        // fragment lane stays complete for it.
        assert_eq!(
            keyword_candidate_keys(&output, "contains", "rundll32").len(),
            1
        );
        // ... and an empty expansion for an absent non-hex token is a
        // definitive, accelerated empty answer — not a fallback scan.
        match sidecar.plan("contains", "zzzqqqvvv").unwrap() {
            KeywordPlan::Candidates {
                candidates,
                evidence,
            } => {
                assert!(candidates.is_empty());
                assert!(evidence.accelerated);
            }
            KeywordPlan::Fallback(_) => {
                panic!("absent non-hex terms have a definitive empty answer")
            }
        }
    }

    /// Rewrite every regular file directly under `index` the way the
    /// generation bundle consumer's incremental-inventory admission installs it
    /// (`hydrate_generation_bundle_inner`): the bytes move to the per-root
    /// content store `<generations_root>/objects/<sha256>` and the index keeps
    /// a symlink per member. Lock files are never published, so drop them.
    fn content_store_link_index(generations_root: &Path, index: &Path) {
        let objects = generations_root.join("objects");
        std::fs::create_dir_all(&objects).unwrap();
        for entry in std::fs::read_dir(index).unwrap() {
            let entry = entry.unwrap();
            assert!(entry.file_type().unwrap().is_file());
            let path = entry.path();
            if entry.file_name().to_str().unwrap().ends_with(".lock") {
                std::fs::remove_file(&path).unwrap();
                continue;
            }
            let object = objects.join(file_digest(&path).unwrap());
            if object.exists() {
                std::fs::remove_file(&path).unwrap();
            } else {
                std::fs::rename(&path, &object).unwrap();
            }
            std::os::unix::fs::symlink(&object, &path).unwrap();
        }
    }

    fn build_single_event_generation(root: &Path, output: &Path) {
        let input = root.join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event_with_message(
            &input.join("hour=1/object-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
            "rundll32 launched from quebecalpha",
        );
        let key = root.join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1")],
            table_uuid: None,
        };
        let stamp_path = root.join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        build_generation_reusing(
            &input, output, &stamp_path, "tenant-a", "key-v1", &key, 1, 20_000_000, None,
        )
        .unwrap();
    }

    /// NAN-2754: an incremental-inventory generation (every index member a
    /// symlink into the content store, exactly as the consumer admits
    /// 09df2462) must load. Before the fix the query container exited at boot
    /// with "text sidecar is invalid: text index contains a non-file entry".
    #[test]
    fn keyword_sidecar_loads_from_content_store_symlinked_indexes() {
        let root = tempfile::tempdir().unwrap();
        let generations = root.path().join("generations");
        let output = generations.join("snapshot-1-abc/derivatives-v1-def");
        build_single_event_generation(root.path(), &output);
        content_store_link_index(&generations, &output.join("keyword-sidecar/index"));
        content_store_link_index(&generations, &output.join("fragment-sidecar/index"));
        assert!(std::fs::symlink_metadata(output.join("keyword-sidecar/index/meta.json"))
            .unwrap()
            .file_type()
            .is_symlink());

        let source_manifest: crate::planner::SourceManifest = serde_json::from_slice(
            &std::fs::read(output.join("keyword-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        let sidecar = crate::text_sidecar::KeywordSidecar::load(
            &output.join("keyword-sidecar/manifest.json"),
            &output.join("keyword-sidecar/index"),
            &output.join("fragment-sidecar/manifest.json"),
            &output.join("fragment-sidecar/index"),
            "tenant-a",
            &source_manifest,
        )
        .unwrap_or_else(|error| panic!("symlinked content-store index must load: {error}"));
        drop(sidecar);
        assert_eq!(keyword_candidate_keys(&output, "token", "host-a").len(), 1);
        assert_eq!(keyword_candidate_keys(&output, "contains", "quebecalpha").len(), 1);
    }

    /// The symlink allowance is for content-store members only: a link that
    /// escapes to any other file, a dangling link, or a link to a directory
    /// is still refused.
    #[test]
    fn keyword_sidecar_refuses_symlinks_outside_the_content_store() {
        let load = |output: &Path| {
            let source_manifest: crate::planner::SourceManifest = serde_json::from_slice(
                &std::fs::read(output.join("keyword-sidecar/manifest.json")).unwrap(),
            )
            .unwrap();
            crate::text_sidecar::KeywordSidecar::load(
                &output.join("keyword-sidecar/manifest.json"),
                &output.join("keyword-sidecar/index"),
                &output.join("fragment-sidecar/manifest.json"),
                &output.join("fragment-sidecar/index"),
                "tenant-a",
                &source_manifest,
            )
            .map(|_| ())
        };
        for case in ["escape", "dangling", "directory"] {
            let root = tempfile::tempdir().unwrap();
            let generations = root.path().join("generations");
            let output = generations.join("snapshot-1-abc/derivatives-v1-def");
            build_single_event_generation(root.path(), &output);
            content_store_link_index(&generations, &output.join("keyword-sidecar/index"));
            let meta = output.join("keyword-sidecar/index/meta.json");
            let target = std::fs::read_link(&meta).unwrap();
            std::fs::remove_file(&meta).unwrap();
            match case {
                "escape" => {
                    let outside = root.path().join("outside-meta.json");
                    std::fs::copy(&target, &outside).unwrap();
                    std::os::unix::fs::symlink(&outside, &meta).unwrap();
                }
                "dangling" => {
                    std::os::unix::fs::symlink(generations.join("objects/absent"), &meta).unwrap();
                }
                _ => {
                    std::os::unix::fs::symlink(generations.join("objects"), &meta).unwrap();
                }
            }
            let error = load(&output).expect_err(case).to_string();
            assert!(error.contains("text index"), "{case}: {error}");
        }
    }

    /// When the prior fragment index was built under a different filter
    /// profile it cannot seed the incremental build, and the rebuild must
    /// stream the COMPLETE dictionary from the keyword index, including every
    /// token owned by reused keyword objects.
    #[test]
    fn incompatible_prior_fragment_profile_rebuilds_from_the_full_dictionary() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event_with_message(
            &input.join("hour=1/object-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
            "quebecalpha marker",
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![incremental_test_stamp(
                &input,
                "hour=1/object-a.parquet",
                "v1",
            )],
            table_uuid: None,
        };
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(&first_stamp_path, &first_stamps).unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();

        // Model a pre-filter deployment: rewrite the committed manifest to
        // the unfiltered profile the old builder stamped.
        let manifest_path = first.join("fragment-sidecar/manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["filter_profile"] = Value::from("all");
        write_json(&manifest_path, &manifest).unwrap();

        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_incremental_test_event_with_message(
            &input.join("hour=2/object-b.parquet"),
            "host-b",
            1_786_391_723_456_789,
            "bravonewer marker",
        );
        let second_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v2.json".to_string(),
            snapshot_id: 2,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
                incremental_test_stamp(&input, "hour=2/object-b.parquet", "v2"),
            ],
            table_uuid: None,
        };
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &second_stamps).unwrap();
        let second = root.path().join("second");
        let second_result = build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();

        // Keyword objects reused, but the "all"-profile prior fragment was
        // rejected: the fragment rebuilt from scratch...
        assert_eq!(second_result.keyword_reused_objects, 1);
        assert_eq!(second_result.fragment_reused_terms, 0);
        // ...and still carries the reused object's terms. Losing them would
        // silently fence contains hunts over older data to zero rows.
        assert_eq!(fragment_exact_term_doc_freq(&second, "quebecalpha"), 1);
        assert_eq!(fragment_exact_term_doc_freq(&second, "bravonewer"), 1);
        assert_eq!(
            keyword_candidate_keys(&second, "contains", "quebecalpha").len(),
            1
        );
    }

    #[test]
    fn parallel_entity_keyword_and_fragment_builds_preserve_exact_semantics() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_incremental_test_event_with_message(
            &input.join("hour=1/object-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
            "first marker",
        );
        write_incremental_test_event_with_message(
            &input.join("hour=2/object-b.parquet"),
            "host-b",
            1_786_391_723_456_789,
            "second marker",
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
                incremental_test_stamp(&input, "hour=2/object-b.parquet", "v2"),
            ],
            table_uuid: None,
        };
        let stamp_path = root.path().join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        let serial = root.path().join("serial");
        let parallel = root.path().join("parallel");
        build_generation_reusing(
            &input,
            &serial,
            &stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        build_generation_reusing(
            &input,
            &parallel,
            &stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            8,
            160_000_000,
            None,
        )
        .unwrap();

        for position in 0..2 {
            let name = format!("entity-sidecar/object-{position:04}.parquet");
            assert_eq!(
                std::fs::read(serial.join(&name)).unwrap(),
                std::fs::read(parallel.join(&name)).unwrap()
            );
        }
        let serial_manifest: Value = serde_json::from_slice(
            &std::fs::read(serial.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        let parallel_manifest: Value = serde_json::from_slice(
            &std::fs::read(parallel.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(serial_manifest["objects"], parallel_manifest["objects"]);
        let stable_builds = |manifest: &Value| {
            manifest["object_builds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|build| {
                    json!({
                        "object_id": build["object_id"],
                        "rows": build["rows"],
                        "bytes": build["bytes"],
                        "sha256": build["sha256"],
                        "max_event_time_us": build["max_event_time_us"],
                    })
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            stable_builds(&serial_manifest),
            stable_builds(&parallel_manifest)
        );
        let serial_keyword: Value = serde_json::from_slice(
            &std::fs::read(serial.join("keyword-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        let parallel_keyword: Value = serde_json::from_slice(
            &std::fs::read(parallel.join("keyword-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(serial_keyword["objects"], parallel_keyword["objects"]);
        assert_eq!(serial_keyword["blocks"], parallel_keyword["blocks"]);
        // Every producer batch is separated by a real Tantivy commit barrier.
        // The queue's built-in 10,000-document cap is not a byte bound for
        // whole-row-group OCSF bodies, so omitting either barrier would allow
        // table-sized owned documents to accumulate again.
        assert_eq!(serial_keyword["admission_batches"], 2);
        assert_eq!(parallel_keyword["admission_batches"], 1);
        let serial_fragment: Value = serde_json::from_slice(
            &std::fs::read(serial.join("fragment-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        let parallel_fragment: Value = serde_json::from_slice(
            &std::fs::read(parallel.join("fragment-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(serial_fragment["producer_threads"], 1);
        assert_eq!(serial_fragment["index_threads"], 1);
        assert_eq!(serial_fragment["merge_threads"], 1);
        assert_eq!(parallel_fragment["producer_threads"], 3);
        assert_eq!(parallel_fragment["index_threads"], 3);
        assert_eq!(parallel_fragment["merge_threads"], 2);
        for term in ["first", "second", "marker", "host"] {
            assert_eq!(
                keyword_candidate_keys(&serial, "contains", term),
                keyword_candidate_keys(&parallel, "contains", term)
            );
        }
    }

    #[test]
    fn append_only_generation_reuses_exact_per_object_derivatives() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_incremental_test_event(
            &input.join("hour=2/object-z.parquet"),
            "host-a",
            1_786_388_123_456_789,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![incremental_test_stamp(
                &input,
                "hour=2/object-z.parquet",
                "v1",
            )],
            table_uuid: None,
        };
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(&first_stamp_path, &first_stamps).unwrap();
        let first = root.path().join("first");
        let first_result = build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        assert_eq!(first_result.entity_built_objects, 1);
        assert_eq!(first_result.identity_built_objects, 1);
        assert_eq!(first_result.count_rollup_built_objects, 1);
        assert_eq!(first_result.keyword_reused_objects, 0);
        assert_eq!(first_result.keyword_built_objects, 1);
        assert_eq!(first_result.keyword_retired_objects, 0);
        assert_eq!(first_result.fragment_reused_terms, 0);
        assert!(first_result.fragment_built_terms > 0);

        // The new object's lexical path sorts before the old object. This
        // models real Iceberg appends where snapshot-local ordinals shift even
        // though the prior S3 object identity remains exact and immutable.
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event_with_message(
            &input.join("hour=1/object-a.parquet"),
            "host-b",
            1_786_391_723_456_789,
            "bravonewer marker",
        );
        let second_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v2.json".to_string(),
            snapshot_id: 2,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=2/object-z.parquet", "v1"),
                incremental_test_stamp(&input, "hour=1/object-a.parquet", "v2"),
            ],
            table_uuid: None,
        };
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &second_stamps).unwrap();
        let second = root.path().join("second");
        let second_result = build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();

        assert_eq!(second_result.entity_reused_objects, 1);
        assert_eq!(second_result.entity_built_objects, 1);
        assert_eq!(second_result.identity_reused_objects, 1);
        assert_eq!(second_result.identity_built_objects, 1);
        assert_eq!(second_result.count_rollup_reused_objects, 1);
        assert_eq!(second_result.count_rollup_built_objects, 1);
        assert_eq!(second_result.keyword_reused_objects, 1);
        assert_eq!(second_result.keyword_built_objects, 1);
        assert_eq!(second_result.keyword_retired_objects, 0);
        assert_eq!(
            second_result.fragment_reused_terms,
            first_result.fragment_built_terms
        );
        let second_fragment: Value = serde_json::from_slice(
            &std::fs::read(second.join("fragment-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(second_fragment["dictionary_scan"], "new-keyword-segments");
        assert!(
            second_fragment["dictionary_segments_examined"]
                .as_u64()
                .unwrap()
                > 0
        );
        assert!(
            second_fragment["dictionary_segments_examined"]
                .as_u64()
                .unwrap()
                <= second_fragment["dictionary_segments_total"]
                    .as_u64()
                    .unwrap()
        );
        assert_eq!(fragment_exact_term_doc_freq(&second, "process"), 1);
        assert_eq!(fragment_exact_term_doc_freq(&second, "bravonewer"), 1);
        assert!(
            entity_object_ids(&first.join("entity-sidecar/object-0000.parquet"))
                .iter()
                .all(|object_id| *object_id == 0)
        );
        // Stable identity: hour=2/object-z moved from position 0 to position 1
        // when hour=1/object-a sorted in front of it, but its OBJECT ID stays
        // 0 — the artifact is byte-identical and never rewritten.
        assert!(
            entity_object_ids(&second.join("entity-sidecar/object-0001.parquet"))
                .iter()
                .all(|object_id| *object_id == 0)
        );
        assert!(
            entity_object_ids(&second.join("entity-sidecar/object-0000.parquet"))
                .iter()
                .all(|object_id| *object_id == 1)
        );
        assert_eq!(
            std::fs::read(first.join("entity-sidecar/object-0000.parquet")).unwrap(),
            std::fs::read(second.join("entity-sidecar/object-0001.parquet")).unwrap()
        );
        assert_eq!(
            std::fs::read(first.join("count-rollup/object-0000.parquet")).unwrap(),
            std::fs::read(second.join("count-rollup/object-0001.parquet")).unwrap()
        );

        let full = root.path().join("second-full");
        let full_result = build_generation_reusing(
            &input,
            &full,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        eprintln!("NAN2460 derivative fixture incremental={} full={}",
            serde_json::to_string(&second_result).unwrap(), serde_json::to_string(&full_result).unwrap());
        assert_eq!(full_result.identity_reused_objects, 0);
        assert_eq!(full_result.identity_built_objects, 2);
        assert_eq!(full_result.keyword_reused_objects, 0);
        assert_eq!(full_result.keyword_built_objects, 2);
        let incremental_manifest: IdentitySnapshotBuildManifest = serde_json::from_slice(
            &std::fs::read(second.join("identity-snapshot/manifest.json")).unwrap(),
        )
        .unwrap();
        let full_manifest: IdentitySnapshotBuildManifest = serde_json::from_slice(
            &std::fs::read(full.join("identity-snapshot/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(incremental_manifest.rows, 2);
        assert_eq!(
            incremental_manifest.by_ip_sha256,
            full_manifest.by_ip_sha256
        );
        assert_eq!(
            keyword_candidate_keys(&second, "token", "host-b"),
            keyword_candidate_keys(&full, "token", "host-b")
        );
        assert_eq!(
            keyword_candidate_keys(&second, "contains", "host"),
            keyword_candidate_keys(&full, "contains", "host")
        );

        let third_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v3.json".to_string(),
            snapshot_id: 3,
            table: "test.events".to_string(),
            objects: vec![incremental_test_stamp(
                &input,
                "hour=1/object-a.parquet",
                "v2",
            )],
            table_uuid: None,
        };
        let third_stamp_path = root.path().join("third-stamps.json");
        write_json(&third_stamp_path, &third_stamps).unwrap();
        let third = root.path().join("third");
        let third_result = build_generation_reusing(
            &input,
            &third,
            &third_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&second),
        )
        .unwrap();
        assert_eq!(third_result.keyword_reused_objects, 1);
        assert_eq!(third_result.keyword_built_objects, 0);
        assert_eq!(third_result.keyword_retired_objects, 1);
        assert!(keyword_candidate_keys(&third, "token", "host-a").is_empty());
        assert_eq!(
            keyword_candidate_keys(&third, "token", "host-b"),
            BTreeSet::from(["s3://test/events/data/hour=1/object-a.parquet".to_string()])
        );

        // NAN-2361: the uid proof runs incrementally exactly when the prior
        // ledger covers the reused set — the pure-append second build — and
        // falls back to the exact full proof both without a prior generation
        // and when an object whose events reach into the uid window was
        // retired (the third build; an out-of-window retirement stays
        // incremental, see retention_shaped_drop_outside_window_stays_incremental).
        assert_eq!(uid_proof_mode(&first), "full");
        assert_eq!(uid_proof_mode(&second), "incremental");
        assert_eq!(uid_proof_mode(&full), "full");
        assert_eq!(uid_proof_mode(&third), "full");
        let ledger: UidLedgerManifest = serde_json::from_slice(
            &std::fs::read(second.join("uid-ledger/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(ledger.objects.len(), 2);
        assert_eq!(ledger.window_records, 2);
        assert_eq!(
            std::fs::metadata(second.join("uid-ledger/window.uids"))
                .unwrap()
                .len(),
            2 * UID_WINDOW_RECORD_BYTES as u64
        );
    }

    /// Downgrade a freshly built entity sidecar to the pre-stable v1 layout:
    /// UInt16 ordinal object_id columns, full-width 32-byte `value_hash`
    /// values (the stored 16-byte prefix extended with arbitrary tail bytes —
    /// v1 tails are exactly the HMAC bytes the truncation later discards, so
    /// ANY tail is a faithful stand-in for migration testing), a v1
    /// index_version, and a manifest without the `object_id_model` /
    /// `next_object_id` allocator keys or the `value_hash_bytes` width. This
    /// is the exact artifact shape deployed v1 generations carry.
    fn downgrade_entity_sidecar_to_ordinal_u16(generation_root: &Path) {
        let directory = generation_root.join("entity-sidecar");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                .unwrap();
        let object_count = manifest["objects"].as_array().unwrap().len();
        let mut index_bytes = 0_u64;
        for position in 0..object_count {
            let path = directory.join(format!("object-{position:04}.parquet"));
            let builder =
                ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap()).unwrap();
            let source_schema = builder.schema().clone();
            let object_id_column = source_schema.index_of("object_id").unwrap();
            let value_hash_column = source_schema.index_of("value_hash").unwrap();
            let schema = Arc::new(Schema::new(
                source_schema
                    .fields()
                    .iter()
                    .enumerate()
                    .map(|(index, field)| {
                        if index == object_id_column {
                            Arc::new(Field::new(field.name(), DataType::UInt16, false))
                        } else if index == value_hash_column {
                            Arc::new(Field::new(
                                field.name(),
                                DataType::FixedSizeBinary(32),
                                false,
                            ))
                        } else {
                            field.clone()
                        }
                    })
                    .collect::<Vec<_>>(),
            ));
            let batches = builder.build().unwrap().collect::<Vec<_>>();
            let replacement = path.with_extension("parquet.downgrade");
            let properties = WriterProperties::builder()
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(6).unwrap()))
                .build();
            let mut writer = ArrowWriter::try_new(
                File::create(&replacement).unwrap(),
                schema.clone(),
                Some(properties),
            )
            .unwrap();
            for batch in batches {
                let batch = batch.unwrap();
                let ids = batch
                    .column(object_id_column)
                    .as_any()
                    .downcast_ref::<UInt32Array>()
                    .unwrap()
                    .values()
                    .iter()
                    .map(|value| u16::try_from(*value).unwrap())
                    .collect::<Vec<_>>();
                let hashes = batch
                    .column(value_hash_column)
                    .as_any()
                    .downcast_ref::<FixedSizeBinaryArray>()
                    .unwrap();
                let mut widener = FixedSizeBinaryBuilder::with_capacity(batch.num_rows(), 32);
                for row in 0..batch.num_rows() {
                    let prefix = hashes.value(row);
                    assert_eq!(prefix.len(), ENTITY_VALUE_HASH_BYTES);
                    let mut full = [0xAB_u8; 32];
                    full[..ENTITY_VALUE_HASH_BYTES].copy_from_slice(prefix);
                    widener.append_value(full).unwrap();
                }
                let mut columns = batch.columns().to_vec();
                columns[object_id_column] = Arc::new(UInt16Array::from(ids));
                columns[value_hash_column] = Arc::new(widener.finish());
                writer
                    .write(&RecordBatch::try_new(schema.clone(), columns).unwrap())
                    .unwrap();
            }
            writer.close().unwrap();
            std::fs::rename(&replacement, &path).unwrap();
            let bytes = std::fs::metadata(&path).unwrap().len();
            index_bytes += bytes;
            manifest["object_builds"][position]["bytes"] = json!(bytes);
            manifest["object_builds"][position]["sha256"] = json!(file_digest(&path).unwrap());
        }
        manifest["index_bytes"] = json!(index_bytes);
        let manifest_map = manifest.as_object_mut().unwrap();
        manifest_map.insert("index_version".to_string(), json!(ENTITY_INDEX_VERSION_V1));
        manifest_map.remove("value_hash_bytes");
        manifest_map.remove("object_id_model");
        manifest_map.remove("next_object_id");
        write_json(&directory.join("manifest.json"), &manifest).unwrap();
    }

    fn entity_manifest_object_ids(root: &Path) -> Vec<u64> {
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(root.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        manifest["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|object| object["object_id"].as_u64().unwrap())
            .collect()
    }

    /// THE decoupling property: retiring one object must not change any other
    /// object's id, and must not rewrite any surviving artifact. Uses the
    /// lexical trap (`hour=10` sorts before `hour=2`) so positions genuinely
    /// shift while identities do not.
    #[test]
    fn retiring_an_object_never_renumbers_or_rewrites_survivors() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        for (hour, host, time_us) in [
            (1_i64, "host-a", 1_786_388_120_000_000_i64),
            (2, "host-b", 1_786_391_720_000_000),
            (10, "host-c", 1_786_395_320_000_000),
        ] {
            std::fs::create_dir_all(input.join(format!("hour={hour}"))).unwrap();
            write_incremental_test_event(
                &input.join(format!("hour={hour}/object.parquet")),
                host,
                time_us,
            );
        }
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps_for = |snapshot_id: i64, hours: &[i64]| ObjectStampManifest {
            metadata_location: format!("s3://test/events/metadata/v{snapshot_id}.json"),
            snapshot_id,
            table: "test.events".to_string(),
            objects: hours
                .iter()
                .map(|hour| {
                    incremental_test_stamp(&input, &format!("hour={hour}/object.parquet"), "v1")
                })
                .collect(),
            table_uuid: None,
        };
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(&first_stamp_path, &stamps_for(1, &[1, 2, 10])).unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        // Path-sorted order: hour=1, hour=10, hour=2 -> ids 0, 1, 2.
        assert_eq!(entity_manifest_object_ids(&first), vec![0, 1, 2]);

        // Retire hour=1: every survivor's POSITION shifts down by one.
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &stamps_for(2, &[2, 10])).unwrap();
        let second = root.path().join("second");
        let second_result = build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();
        // Survivors keep their STABLE ids (1 for hour=10, 2 for hour=2) even
        // though their positions are now 0 and 1.
        assert_eq!(entity_manifest_object_ids(&second), vec![1, 2]);
        assert_eq!(second_result.entity_reused_objects, 2);
        assert_eq!(second_result.entity_built_objects, 0);
        // No survivor artifact was rewritten: bytes are identical and the
        // inode is shared (hard link), which a restamp rewrite cannot produce.
        for (prior_position, position) in [(1_u32, 0_u32), (2, 1)] {
            let prior = first.join(format!("entity-sidecar/object-{prior_position:04}.parquet"));
            let current = second.join(format!("entity-sidecar/object-{position:04}.parquet"));
            // Byte equality is the proof: a restamp rewrite would have
            // changed the embedded object_id column values. (The artifact is
            // usually also hard-linked, but the sampled full re-verify may
            // legitimately copy instead.)
            assert_eq!(
                std::fs::read(&prior).unwrap(),
                std::fs::read(&current).unwrap()
            );
        }
        // Allocator high water survives retirement: a later new object must
        // NOT recycle the retired id 0.
        std::fs::create_dir_all(input.join("hour=3")).unwrap();
        write_incremental_test_event(
            &input.join("hour=3/object.parquet"),
            "host-d",
            1_786_398_920_000_000,
        );
        let third_stamp_path = root.path().join("third-stamps.json");
        write_json(&third_stamp_path, &stamps_for(3, &[2, 3, 10])).unwrap();
        let third = root.path().join("third");
        build_generation_reusing(
            &input,
            &third,
            &third_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&second),
        )
        .unwrap();
        // Path order: hour=10 (id 1), hour=2 (id 2), hour=3 (NEW -> id 3).
        assert_eq!(entity_manifest_object_ids(&third), vec![1, 2, 3]);
    }

    /// A collision in the stable-id assignment would conflate two objects'
    /// postings; the assignment must fail closed, never merge.
    #[test]
    fn a_corrupt_prior_allocator_that_would_collide_fails_closed() {
        let stamp = |name: &str| ObjectStamp {
            relative_path: format!("hour=1/{name}.parquet"),
            source_uri: format!("s3://test/events/data/hour=1/{name}.parquet"),
            version_id: "v1".to_string(),
            size_bytes: 10,
            sha256: "0".repeat(64),
        };
        let local = |position: u32, name: &str| LocalObject {
            id: position,
            position,
            path: PathBuf::from(format!("/tmp/{name}.parquet")),
            stamp: stamp(name),
        };
        let prior_object = |object_id: u32| PriorEntityObject {
            manifest: json!({}),
            build: ObjectBuild {
                object_id,
                rows: 1,
                bytes: 10,
                seconds: 0.0,
                sha256: "0".repeat(64),
                max_event_time_us: None,
            },
            artifact_name: format!("object-{object_id:04}.parquet"),
        };
        // Corrupt allocator state: next_object_id (5) collides with a live
        // object's id (5). prior_entity_sidecar refuses to load such a
        // manifest; this exercises the defense-in-depth fence at the
        // assignment site itself.
        let prior = PriorEntitySidecar {
            directory: PathBuf::from("/tmp"),
            objects: BTreeMap::from([
                (stamp_identity(&stamp("a")), prior_object(0)),
                (stamp_identity(&stamp("b")), prior_object(5)),
            ]),
            object_id_width: 32,
            next_object_id: 5,
            value_hash_bytes: ENTITY_VALUE_HASH_BYTES,
        };
        let mut objects = vec![local(0, "a"), local(1, "b"), local(2, "c")];
        let error = assign_stable_object_ids(&mut objects, Some(&prior))
            .expect_err("a colliding assignment must fail closed");
        assert!(
            error.to_string().contains("duplicate id"),
            "unexpected error: {error}"
        );
    }

    /// End to end: a prior manifest whose persisted allocator sits at or below
    /// an already-issued id is rejected outright, so the build falls back to a
    /// full rebuild with injective ids instead of reusing anything under a
    /// corrupt identity map.
    #[test]
    fn a_tampered_prior_allocator_never_reaches_reuse() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event(
            &input.join("hour=1/object.parquet"),
            "host-a",
            1_786_388_120_000_000,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![incremental_test_stamp(
                &input,
                "hour=1/object.parquet",
                "v1",
            )],
            table_uuid: None,
        };
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(&first_stamp_path, &first_stamps).unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        // Tamper: allocator high water at 0 while id 0 is live.
        let manifest_path = first.join("entity-sidecar/manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["next_object_id"] = json!(0);
        write_json(&manifest_path, &manifest).unwrap();

        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_incremental_test_event(
            &input.join("hour=2/object.parquet"),
            "host-b",
            1_786_391_720_000_000,
        );
        let second_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v2.json".to_string(),
            snapshot_id: 2,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=1/object.parquet", "v1"),
                incremental_test_stamp(&input, "hour=2/object.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &second_stamps).unwrap();
        let second = root.path().join("second");
        let second_result = build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();
        assert_eq!(second_result.entity_reused_objects, 0);
        assert_eq!(second_result.entity_built_objects, 2);
        assert_eq!(entity_manifest_object_ids(&second), vec![0, 1]);
    }

    /// The keyword sidecar packs `(object_id << 32) | row_group` into a u64
    /// locator; the id space must exhaust with an error, never wrap into a
    /// reused id that would conflate two objects' blocks.
    #[test]
    fn keyword_object_id_space_exhaustion_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event(
            &input.join("hour=1/object.parquet"),
            "host-a",
            1_786_388_120_000_000,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![incremental_test_stamp(
                &input,
                "hour=1/object.parquet",
                "v1",
            )],
            table_uuid: None,
        };
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(&first_stamp_path, &first_stamps).unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        // Move the retained object's keyword id to the top of the id space.
        let manifest_path = first.join("keyword-sidecar/manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        manifest["objects"][0]["object_id"] = json!(u32::MAX);
        manifest["blocks"][0]["object_id"] = json!(u32::MAX);
        manifest["blocks"][0]["locator"] = json!((u64::from(u32::MAX)) << 32);
        write_json(&manifest_path, &manifest).unwrap();

        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_incremental_test_event(
            &input.join("hour=2/object.parquet"),
            "host-b",
            1_786_391_720_000_000,
        );
        let second_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v2.json".to_string(),
            snapshot_id: 2,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=1/object.parquet", "v1"),
                incremental_test_stamp(&input, "hour=2/object.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &second_stamps).unwrap();
        let error = build_generation_reusing(
            &input,
            &root.path().join("second"),
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .expect_err("allocating past u32::MAX must fail closed");
        assert!(
            format!("{error:#}").contains("keyword object ID space is exhausted"),
            "unexpected error: {error:#}"
        );
    }

    /// Migration: a generation built by the PRE-stable release (UInt16 ordinal
    /// object_id columns, no allocator keys in the manifest) is accepted as a
    /// prior, its objects keep their old ordinals as their stable ids, and its
    /// artifacts are reused via the one-time widening rewrite instead of being
    /// rebuilt from source.
    #[test]
    fn a_pre_stable_ordinal_generation_is_migrated_and_reused() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        for (hour, host, time_us) in [
            (2_i64, "host-a", 1_786_388_120_000_000_i64),
            (10, "host-b", 1_786_391_720_000_000),
        ] {
            std::fs::create_dir_all(input.join(format!("hour={hour}"))).unwrap();
            write_incremental_test_event(
                &input.join(format!("hour={hour}/object.parquet")),
                host,
                time_us,
            );
        }
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=2/object.parquet", "v1"),
                incremental_test_stamp(&input, "hour=10/object.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(&first_stamp_path, &first_stamps).unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        downgrade_entity_sidecar_to_ordinal_u16(&first);
        // Sanity: the fixture really is the old layout.
        assert!(
            entity_object_ids_u16(&first.join("entity-sidecar/object-0000.parquet"))
                .iter()
                .all(|object_id| *object_id == 0)
        );

        // Append a THIRD object that sorts between the two existing ones so
        // positions shift during the very migration build.
        std::fs::create_dir_all(input.join("hour=11")).unwrap();
        write_incremental_test_event(
            &input.join("hour=11/object.parquet"),
            "host-c",
            1_786_395_320_000_000,
        );
        let second_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v2.json".to_string(),
            snapshot_id: 2,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=2/object.parquet", "v1"),
                incremental_test_stamp(&input, "hour=10/object.parquet", "v1"),
                incremental_test_stamp(&input, "hour=11/object.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &second_stamps).unwrap();
        let second = root.path().join("second");
        let second_result = build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();
        // Both old objects were REUSED (via the widening rewrite), not rebuilt.
        assert_eq!(second_result.entity_reused_objects, 2);
        assert_eq!(second_result.entity_built_objects, 1);
        // Old ordinals became the stable ids: hour=10 keeps 0, hour=2 keeps 1
        // (old sort order was hour=10, hour=2); the new hour=11 object gets 2.
        // New path order: hour=10 (pos 0), hour=11 (pos 1), hour=2 (pos 2).
        assert_eq!(entity_manifest_object_ids(&second), vec![0, 2, 1]);
        // Every artifact in the migrated generation is the UInt32 layout.
        assert_eq!(
            entity_object_ids(&second.join("entity-sidecar/object-0000.parquet")),
            vec![0; entity_object_ids(&second.join("entity-sidecar/object-0000.parquet")).len()]
        );
        assert!(
            entity_object_ids(&second.join("entity-sidecar/object-0002.parquet"))
                .iter()
                .all(|object_id| *object_id == 1)
        );
        // The migrated generation persists its allocator for the next build.
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(second.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(manifest["object_id_model"].as_str(), Some(OBJECT_ID_MODEL));
        assert_eq!(manifest["next_object_id"].as_u64(), Some(3));
    }

    fn entity_object_ids_u16(path: &Path) -> Vec<u16> {
        ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
            .unwrap()
            .build()
            .unwrap()
            .flat_map(|batch| {
                let batch = batch.unwrap();
                batch
                    .column_by_name("object_id")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<UInt16Array>()
                    .unwrap()
                    .values()
                    .to_vec()
            })
            .collect()
    }

    fn load_entity_sidecar(
        root: &Path,
        key: &Path,
    ) -> std::result::Result<crate::sidecar::EntitySidecar, crate::sidecar::SidecarError> {
        let manifest_path = root.join("entity-sidecar/manifest.json");
        let source_manifest: crate::planner::SourceManifest =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let index_files = (0..manifest["objects"].as_array().unwrap().len())
            .map(|position| root.join(format!("entity-sidecar/object-{position:04}.parquet")))
            .collect::<Vec<_>>();
        crate::sidecar::EntitySidecar::load(
            &manifest_path,
            key,
            index_files,
            "tenant-a",
            &source_manifest,
        )
    }

    /// The query loader accepts both id layouts and refuses a manifest whose
    /// build records are bound to the wrong objects — the join between an
    /// artifact's rows and its manifest entry is the stable object id, so a
    /// swapped binding must fail closed.
    #[test]
    fn entity_sidecar_load_joins_builds_to_objects_by_stable_id() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        for (hour, host, time_us) in [
            (2_i64, "host-a", 1_786_388_120_000_000_i64),
            (10, "host-b", 1_786_391_720_000_000),
        ] {
            std::fs::create_dir_all(input.join(format!("hour={hour}"))).unwrap();
            write_incremental_test_event(
                &input.join(format!("hour={hour}/object.parquet")),
                host,
                time_us,
            );
        }
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=2/object.parquet", "v1"),
                incremental_test_stamp(&input, "hour=10/object.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let stamp_path = root.path().join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        let generation = root.path().join("generation");
        build_generation_reusing(
            &input,
            &generation,
            &stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        // A freshly built stable-id generation loads.
        load_entity_sidecar(&generation, &key).expect("stable-id generation loads");

        // A pre-stable (ordinal UInt16, no allocator keys) generation ALSO
        // still loads: upgrading the worker must not strand the active
        // generation.
        let legacy = root.path().join("legacy");
        copy_dir_recursive(&generation, &legacy);
        downgrade_entity_sidecar_to_ordinal_u16(&legacy);
        load_entity_sidecar(&legacy, &key).expect("pre-stable generation loads");

        // Swapping the build records' object ids breaks the id join and must
        // fail closed, never bind rows to the wrong object.
        let manifest_path = generation.join("entity-sidecar/manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        let first_id = manifest["object_builds"][0]["object_id"].clone();
        let second_id = manifest["object_builds"][1]["object_id"].clone();
        manifest["object_builds"][0]["object_id"] = second_id;
        manifest["object_builds"][1]["object_id"] = first_id;
        write_json(&manifest_path, &manifest).unwrap();
        let error = match load_entity_sidecar(&generation, &key) {
            Ok(_) => panic!("a swapped build binding must fail closed"),
            Err(error) => error,
        };
        assert!(
            error.to_string().contains("build object id"),
            "unexpected error: {error}"
        );
    }

    /// Write one source event object with `hostnames.len()` rows and Parquet
    /// row groups capped at `rows_per_group`, so entity blocks (source row
    /// groups) genuinely split mid-object.
    fn write_multi_host_test_events(
        path: &Path,
        hostnames: &[&str],
        base_time_us: i64,
        rows_per_group: usize,
    ) {
        let uids = hostnames
            .iter()
            .enumerate()
            .map(|(row, hostname)| format!("event-{hostname}-{row}-{base_time_us}"))
            .collect::<Vec<_>>();
        let metadata = StructArray::from(vec![
            (
                Arc::new(Field::new("uid", DataType::Utf8, false)),
                Arc::new(StringArray::from(uids)) as ArrayRef,
            ),
            (
                Arc::new(Field::new("log_source", DataType::Utf8, false)),
                Arc::new(StringArray::from(vec!["windows_sysmon"; hostnames.len()])) as ArrayRef,
            ),
        ]);
        let device = StructArray::from(vec![(
            Arc::new(Field::new("hostname", DataType::Utf8, false)),
            Arc::new(StringArray::from(hostnames.to_vec())) as ArrayRef,
        )]);
        let src_endpoint = StructArray::from(vec![(
            Arc::new(Field::new("ip", DataType::Utf8, false)),
            Arc::new(StringArray::from(vec!["10.1.2.3"; hostnames.len()])) as ArrayRef,
        )]);
        let time = arrow_array::TimestampMicrosecondArray::from(
            (0..hostnames.len() as i64)
                .map(|row| base_time_us + row)
                .collect::<Vec<_>>(),
        )
        .with_timezone("UTC");
        let message = StringArray::from(
            hostnames
                .iter()
                .map(|hostname| format!("process start on {hostname}"))
                .collect::<Vec<_>>(),
        );
        let schema = Arc::new(Schema::new(vec![
            Field::new("time", time.data_type().clone(), false),
            Field::new("metadata", metadata.data_type().clone(), false),
            Field::new("device", device.data_type().clone(), false),
            Field::new("src_endpoint", src_endpoint.data_type().clone(), false),
            Field::new("message", DataType::Utf8, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(time),
                Arc::new(metadata),
                Arc::new(device),
                Arc::new(src_endpoint),
                Arc::new(message),
            ],
        )
        .unwrap();
        let properties = WriterProperties::builder()
            .set_max_row_group_row_count(Some(rows_per_group))
            .build();
        let mut writer =
            ArrowWriter::try_new(File::create(path).unwrap(), schema, Some(properties)).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    /// Execute an entity probe against a built generation EXACTLY as the
    /// engine would: load the sidecar through the query loader, take the SQL's
    /// own bind parameters (the truncated probe hash and field id), and apply
    /// the SQL's equality predicate to every artifact row. Returns the
    /// candidate set as (object_id, block_id, matches) triples.
    fn probe_candidate_blocks(
        generation: &Path,
        key: &Path,
        source_path: &str,
        value: &str,
    ) -> BTreeSet<(u32, u32, u64)> {
        let sidecar = load_entity_sidecar(generation, key).expect("generation loads");
        let query = sidecar.query(source_path, value).expect("probe compiles");
        let value_hash_hex = query
            .params
            .iter()
            .find(|(name, _)| name == "value_hash_hex")
            .map(|(_, value)| value.clone())
            .expect("probe binds a value hash");
        let field_id_param = query
            .params
            .iter()
            .find(|(name, _)| name == "field_id")
            .map(|(_, value)| value.parse::<u8>().unwrap())
            .expect("probe binds a field id");
        // The probe must compare the exact stored width: prefix equality is
        // the superset fence, width mismatch would silently select nothing.
        assert!(
            query
                .sql
                .contains(&format!("FixedString({ENTITY_VALUE_HASH_BYTES})")),
            "probe SQL does not compare the stored hash width: {}",
            query.sql
        );
        let probe_hash = hex::decode(&value_hash_hex).unwrap();
        assert_eq!(probe_hash.len(), ENTITY_VALUE_HASH_BYTES);
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(generation.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        let mut candidates = BTreeSet::new();
        for position in 0..manifest["objects"].as_array().unwrap().len() {
            let path = generation.join(format!("entity-sidecar/object-{position:04}.parquet"));
            let reader = ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap())
                .unwrap()
                .build()
                .unwrap();
            for batch in reader {
                let batch = batch.unwrap();
                let value_hash = batch
                    .column_by_name("value_hash")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<FixedSizeBinaryArray>()
                    .unwrap();
                assert_eq!(value_hash.value_length() as usize, ENTITY_VALUE_HASH_BYTES);
                let field_id = batch
                    .column_by_name("field_id")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<UInt8Array>()
                    .unwrap();
                let object_id = batch
                    .column_by_name("object_id")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<UInt32Array>()
                    .unwrap();
                let block_id = batch
                    .column_by_name("block_id")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<UInt32Array>()
                    .unwrap();
                let matches = batch
                    .column_by_name("matches")
                    .unwrap()
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .unwrap();
                for row in 0..batch.num_rows() {
                    if value_hash.value(row) == probe_hash.as_slice()
                        && field_id.value(row) == field_id_param
                    {
                        candidates.insert((
                            object_id.value(row),
                            block_id.value(row),
                            matches.value(row),
                        ));
                    }
                }
            }
        }
        candidates
    }

    /// THE under-selection fence for the truncated-hash layout: every source
    /// block that truly contains an entity value must come back from a probe
    /// over the re-encoded sidecar. Edge cases pinned: the first row of an
    /// object, the last row of an object's final short block, a value
    /// spanning a row-group boundary, and one value present in many objects.
    /// Ground truth is computed BY CONSTRUCTION of the corpus, not by any
    /// builder helper, so a build-side and probe-side bug cannot cancel out.
    #[test]
    fn truncated_hash_probe_returns_every_true_candidate_block() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        // Object 0 (path-sorted first): 5 rows, 2-row blocks -> blocks
        // {0: [edge-first, common-host], 1: [other-x, common-host],
        //  2: [edge-last]}.
        write_multi_host_test_events(
            &input.join("hour=1/object-a.parquet"),
            &[
                "edge-first",
                "common-host",
                "other-x",
                "common-host",
                "edge-last",
            ],
            1_786_388_120_000_000,
            2,
        );
        // Object 1: 3 rows, 2-row blocks -> blocks
        // {0: [common-host, zeta], 1: [common-host]}.
        write_multi_host_test_events(
            &input.join("hour=2/object-b.parquet"),
            &["common-host", "zeta", "common-host"],
            1_786_391_720_000_000,
            2,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
                incremental_test_stamp(&input, "hour=2/object-b.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let stamp_path = root.path().join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        let generation = root.path().join("generation");
        build_generation_reusing(
            &input,
            &generation,
            &stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        let probe =
            |value: &str| probe_candidate_blocks(&generation, &key, "device.hostname", value);
        // A value present in MANY objects and MANY blocks, including across a
        // row-group boundary of object 0 and the final block of object 1.
        assert_eq!(
            probe("common-host"),
            BTreeSet::from([(0, 0, 1), (0, 1, 1), (1, 0, 1), (1, 1, 1)])
        );
        // First row of the first block of an object (plus canonicalization:
        // the probe value is dirty, storage was already canonical).
        assert_eq!(probe("  EDGE-FIRST "), BTreeSet::from([(0, 0, 1)]));
        // Last row of an object's trailing short block.
        assert_eq!(probe("edge-last"), BTreeSet::from([(0, 2, 1)]));
        // Present in exactly one middle block.
        assert_eq!(probe("other-x"), BTreeSet::from([(0, 1, 1)]));
        assert_eq!(probe("zeta"), BTreeSet::from([(1, 0, 1)]));
        // Absent value: empty candidate set (no phantom collisions in a
        // corpus this size).
        assert_eq!(probe("absent-host"), BTreeSet::new());
        // The shared IP appears on every row: every block of every object,
        // with exact per-block match counts.
        assert_eq!(
            probe_candidate_blocks(&generation, &key, "src_endpoint.ip", "10.1.2.3"),
            BTreeSet::from([(0, 0, 2), (0, 1, 2), (0, 2, 1), (1, 0, 2), (1, 1, 1)])
        );
    }

    /// Widen a freshly built entity sidecar into the deployed v1 layout that
    /// kept stable UInt32 ids but stored the FULL 32-byte hash: the stored
    /// 16-byte prefix is extended with arbitrary tail bytes (v1 tails are
    /// exactly the HMAC bytes truncation discards, so any tail is a faithful
    /// stand-in), and the manifest reverts to the v1 version without a
    /// declared width. This is the exact shape the live tenant serves today.
    fn widen_entity_sidecar_hashes_to_v1(generation_root: &Path) {
        let directory = generation_root.join("entity-sidecar");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(directory.join("manifest.json")).unwrap())
                .unwrap();
        let object_count = manifest["objects"].as_array().unwrap().len();
        let mut index_bytes = 0_u64;
        for position in 0..object_count {
            let path = directory.join(format!("object-{position:04}.parquet"));
            let builder =
                ParquetRecordBatchReaderBuilder::try_new(File::open(&path).unwrap()).unwrap();
            let source_schema = builder.schema().clone();
            let value_hash_column = source_schema.index_of("value_hash").unwrap();
            let schema = Arc::new(Schema::new(
                source_schema
                    .fields()
                    .iter()
                    .enumerate()
                    .map(|(index, field)| {
                        if index == value_hash_column {
                            Arc::new(Field::new(
                                field.name(),
                                DataType::FixedSizeBinary(32),
                                false,
                            ))
                        } else {
                            field.clone()
                        }
                    })
                    .collect::<Vec<_>>(),
            ));
            let batches = builder.build().unwrap().collect::<Vec<_>>();
            let replacement = path.with_extension("parquet.widen");
            let properties = WriterProperties::builder()
                .set_compression(Compression::ZSTD(ZstdLevel::try_new(6).unwrap()))
                .build();
            let mut writer = ArrowWriter::try_new(
                File::create(&replacement).unwrap(),
                schema.clone(),
                Some(properties),
            )
            .unwrap();
            for batch in batches {
                let batch = batch.unwrap();
                let hashes = batch
                    .column(value_hash_column)
                    .as_any()
                    .downcast_ref::<FixedSizeBinaryArray>()
                    .unwrap();
                let mut widener = FixedSizeBinaryBuilder::with_capacity(batch.num_rows(), 32);
                for row in 0..batch.num_rows() {
                    let prefix = hashes.value(row);
                    assert_eq!(prefix.len(), ENTITY_VALUE_HASH_BYTES);
                    let mut full = [0xCD_u8; 32];
                    full[..ENTITY_VALUE_HASH_BYTES].copy_from_slice(prefix);
                    widener.append_value(full).unwrap();
                }
                let mut columns = batch.columns().to_vec();
                columns[value_hash_column] = Arc::new(widener.finish());
                writer
                    .write(&RecordBatch::try_new(schema.clone(), columns).unwrap())
                    .unwrap();
            }
            writer.close().unwrap();
            std::fs::rename(&replacement, &path).unwrap();
            let bytes = std::fs::metadata(&path).unwrap().len();
            index_bytes += bytes;
            manifest["object_builds"][position]["bytes"] = json!(bytes);
            manifest["object_builds"][position]["sha256"] = json!(file_digest(&path).unwrap());
        }
        manifest["index_bytes"] = json!(index_bytes);
        let manifest_map = manifest.as_object_mut().unwrap();
        manifest_map.insert("index_version".to_string(), json!(ENTITY_INDEX_VERSION_V1));
        manifest_map.remove("value_hash_bytes");
        write_json(&directory.join("manifest.json"), &manifest).unwrap();
    }

    /// The LIVE migration path: a v1 stable-id generation with full-width
    /// hashes is truncation-migrated on reuse (counted as reused, never
    /// rebuilt from source) and the migrated generation answers every probe
    /// with exactly the candidate set the v1 generation answered.
    #[test]
    fn a_full_width_v1_generation_is_truncation_migrated_with_equal_candidates() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_multi_host_test_events(
            &input.join("hour=1/object-a.parquet"),
            &["host-a", "common-host", "host-a"],
            1_786_388_120_000_000,
            2,
        );
        write_multi_host_test_events(
            &input.join("hour=2/object-b.parquet"),
            &["common-host", "host-b"],
            1_786_391_720_000_000,
            2,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
                incremental_test_stamp(&input, "hour=2/object-b.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let stamp_path = root.path().join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        let expected: Vec<(&str, &str)> = vec![
            ("device.hostname", "host-a"),
            ("device.hostname", "common-host"),
            ("device.hostname", "host-b"),
            ("src_endpoint.ip", "10.1.2.3"),
        ];
        let baseline = expected
            .iter()
            .map(|(field, value)| probe_candidate_blocks(&first, &key, field, value))
            .collect::<Vec<_>>();
        assert!(baseline.iter().all(|set| !set.is_empty()));

        // Rewrite the first generation into the deployed v1 full-width shape.
        widen_entity_sidecar_hashes_to_v1(&first);

        let second_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v2.json".to_string(),
            snapshot_id: 2,
            table: "test.events".to_string(),
            objects: stamps.objects.clone(),
            table_uuid: None,
        };
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &second_stamps).unwrap();
        let second = root.path().join("second");
        let result = build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();
        // Migration IS reuse: no object was rebuilt from source events.
        assert_eq!(result.entity_reused_objects, 2);
        assert_eq!(result.entity_built_objects, 0);
        let manifest: Value = serde_json::from_slice(
            &std::fs::read(second.join("entity-sidecar/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            manifest["index_version"].as_str(),
            Some(ENTITY_INDEX_VERSION_V2)
        );
        assert_eq!(
            manifest["value_hash_bytes"].as_u64(),
            Some(ENTITY_VALUE_HASH_BYTES as u64)
        );
        // Identical candidate sets for every probed field and value —
        // no under-selection through the migration.
        for ((field, value), before) in expected.iter().zip(baseline) {
            assert_eq!(
                probe_candidate_blocks(&second, &key, field, value),
                before,
                "candidate set diverged for {field}={value}"
            );
        }
    }

    fn copy_dir_recursive(source: &Path, destination: &Path) {
        std::fs::create_dir_all(destination).unwrap();
        for entry in std::fs::read_dir(source).unwrap() {
            let entry = entry.unwrap();
            let target = destination.join(entry.file_name());
            if entry.file_type().unwrap().is_dir() {
                copy_dir_recursive(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), &target).unwrap();
            }
        }
    }

    /// The migrating rewrite must verify that every row of a prior artifact
    /// carries exactly the id the manifest claims before restamping it. If two
    /// artifacts are swapped on disk (sizes and digests updated to match),
    /// restamping would publish object B's postings under object A's identity
    /// — conflated candidate sets. The rewrite must refuse and rebuild.
    #[test]
    fn a_swapped_prior_artifact_is_rebuilt_not_restamped() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        for (hour, host, time_us) in [
            (2_i64, "host-a", 1_786_388_120_000_000_i64),
            (10, "host-b", 1_786_391_720_000_000),
        ] {
            std::fs::create_dir_all(input.join(format!("hour={hour}"))).unwrap();
            write_incremental_test_event(
                &input.join(format!("hour={hour}/object.parquet")),
                host,
                time_us,
            );
        }
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=2/object.parquet", "v1"),
                incremental_test_stamp(&input, "hour=10/object.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(&first_stamp_path, &stamps).unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        downgrade_entity_sidecar_to_ordinal_u16(&first);
        // Swap the two artifacts on disk and swap the build records' bytes and
        // digests so the cheap size/digest fences still pass. Only the id
        // VALUES inside the rows now contradict the manifest binding.
        let entity = first.join("entity-sidecar");
        let a = entity.join("object-0000.parquet");
        let b = entity.join("object-0001.parquet");
        let swap = entity.join("object-swap.parquet");
        std::fs::rename(&a, &swap).unwrap();
        std::fs::rename(&b, &a).unwrap();
        std::fs::rename(&swap, &b).unwrap();
        let manifest_path = entity.join("manifest.json");
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
        for (position, path) in [(0, &a), (1, &b)] {
            manifest["object_builds"][position]["bytes"] =
                json!(std::fs::metadata(path).unwrap().len());
            manifest["object_builds"][position]["sha256"] = json!(file_digest(path).unwrap());
        }
        write_json(&manifest_path, &manifest).unwrap();

        let second_stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v2.json".to_string(),
            snapshot_id: 2,
            ..stamps
        };
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(&second_stamp_path, &second_stamps).unwrap();
        let second = root.path().join("second");
        let second_result = build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();
        // Both artifacts contradicted their claimed ids: neither may be
        // restamped; both are rebuilt from the immutable source objects.
        assert_eq!(second_result.entity_reused_objects, 0);
        assert_eq!(second_result.entity_built_objects, 2);
        assert!(
            entity_object_ids(&second.join("entity-sidecar/object-0000.parquet"))
                .iter()
                .all(|object_id| *object_id == 0)
        );
        assert!(
            entity_object_ids(&second.join("entity-sidecar/object-0001.parquet"))
                .iter()
                .all(|object_id| *object_id == 1)
        );
    }

    #[test]
    fn incremental_uid_proof_rejects_duplicate_against_prior_window() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event(
            &input.join("hour=1/object-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(
            &first_stamp_path,
            &ObjectStampManifest {
                metadata_location: "s3://test/events/metadata/v1.json".to_string(),
                snapshot_id: 1,
                table: "test.events".to_string(),
                objects: vec![incremental_test_stamp(
                    &input,
                    "hour=1/object-a.parquet",
                    "v1",
                )],
                table_uuid: None,
            },
        )
        .unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        assert_eq!(uid_proof_mode(&first), "full");

        // An ingest retry replays the SAME event (same metadata.uid) into a
        // later append. The lexically later path keeps the prior object's
        // ordinal stable, so the incremental proof path is what must reject
        // the cross-generation duplicate.
        std::fs::create_dir_all(input.join("hour=3")).unwrap();
        write_incremental_test_event(
            &input.join("hour=3/object-b.parquet"),
            "host-a",
            1_786_388_123_456_789,
        );
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(
            &second_stamp_path,
            &ObjectStampManifest {
                metadata_location: "s3://test/events/metadata/v2.json".to_string(),
                snapshot_id: 2,
                table: "test.events".to_string(),
                objects: vec![
                    incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
                    incremental_test_stamp(&input, "hour=3/object-b.parquet", "v2"),
                ],
                table_uuid: None,
            },
        )
        .unwrap();
        let error = build_generation_reusing(
            &input,
            &root.path().join("second"),
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate metadata.uid rows within the 7-day event-time window"),
            "unexpected error: {error}"
        );
    }

    /// Upgrade fence for the record encoding (r24): a prior ledger written
    /// under ANOTHER algorithm string — here the deployed full-width
    /// `hmac-sha256-uid-window-v1`, whose window records are 40 bytes — must
    /// never be merged as 24-byte records. The contract check has to refuse
    /// it and force one full proof, which then reseeds the ledger in the
    /// current encoding so the NEXT promotion is incremental again.
    #[test]
    fn prior_ledger_in_another_encoding_forces_full_proof() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event(
            &input.join("hour=1/object-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(
            &first_stamp_path,
            &ObjectStampManifest {
                metadata_location: "s3://test/events/metadata/v1.json".to_string(),
                snapshot_id: 1,
                table: "test.events".to_string(),
                objects: vec![incremental_test_stamp(
                    &input,
                    "hour=1/object-a.parquet",
                    "v1",
                )],
                table_uuid: None,
            },
        )
        .unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        assert_eq!(uid_proof_mode(&first), "full");

        // Rewrite the first generation's ledger as the pre-r24 deployment
        // wrote it: the old algorithm string over 40-byte records (32-byte
        // zero-padded digest slot + u64 time), manifest window_sha256 kept
        // consistent so content verification is not what refuses it. Both
        // remaining fences must refuse this encoding: the algorithm string
        // AND the window-size check (records x 24 != the 40-byte file) —
        // mutation-verified that removing either alone still forces the full
        // proof, and removing both fails this test.
        let ledger = first.join("uid-ledger");
        let old_window = std::fs::read(ledger.join("window.uids")).unwrap();
        assert_eq!(old_window.len() % UID_WINDOW_RECORD_BYTES, 0);
        let mut wide = Vec::new();
        for record in old_window.chunks_exact(UID_WINDOW_RECORD_BYTES) {
            wide.extend_from_slice(&record[..ENTITY_VALUE_HASH_BYTES]);
            wide.extend_from_slice(&[0_u8; 32 - ENTITY_VALUE_HASH_BYTES]);
            wide.extend_from_slice(&record[ENTITY_VALUE_HASH_BYTES..]);
        }
        std::fs::write(ledger.join("window.uids"), &wide).unwrap();
        let mut manifest: Value =
            serde_json::from_slice(&std::fs::read(ledger.join("manifest.json")).unwrap()).unwrap();
        manifest["algorithm"] = json!("hmac-sha256-uid-window-v1");
        manifest["window_sha256"] = json!(hex::encode(Sha256::digest(&wide)));
        write_json(&ledger.join("manifest.json"), &manifest).unwrap();

        // Append a NEW object so the second build has a reusable prior AND a
        // delta — the exact shape that would take the incremental path if the
        // fence failed to refuse the foreign encoding.
        std::fs::create_dir_all(input.join("hour=3")).unwrap();
        write_incremental_test_event(
            &input.join("hour=3/object-b.parquet"),
            "host-b",
            1_786_388_223_456_789,
        );
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(
            &second_stamp_path,
            &ObjectStampManifest {
                metadata_location: "s3://test/events/metadata/v2.json".to_string(),
                snapshot_id: 2,
                table: "test.events".to_string(),
                objects: vec![
                    incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
                    incremental_test_stamp(&input, "hour=3/object-b.parquet", "v2"),
                ],
                table_uuid: None,
            },
        )
        .unwrap();
        let second = root.path().join("second");
        build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();
        assert_eq!(uid_proof_mode(&second), "full");
        // The full proof reseeded the ledger in the CURRENT encoding.
        let reseeded: UidLedgerManifest = serde_json::from_slice(
            &std::fs::read(second.join("uid-ledger/manifest.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(reseeded.algorithm, UID_LEDGER_ALGORITHM);
        assert_eq!(
            std::fs::metadata(second.join("uid-ledger/window.uids"))
                .unwrap()
                .len(),
            reseeded.window_records * UID_WINDOW_RECORD_BYTES as u64
        );
    }

    /// One retention day at capacity: the delete snapshot drops whole objects
    /// whose events are all OLDER than the uid window. That drop must stay on
    /// the O(delta) incremental proof (NAN-2361 D1) — before this fix every
    /// retention day fell back to the full O(table) proof — while a genuine
    /// in-window duplicate appended after the drop is still rejected.
    #[test]
    fn retention_shaped_drop_outside_window_stays_incremental() {
        const DAY_US: i64 = 24 * 60 * 60 * 1_000_000;
        let recent_us = 1_786_388_123_456_789_i64;
        let old_us = recent_us - 40 * DAY_US;
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        write_incremental_test_event(&input.join("hour=1/old.parquet"), "host-old", old_us);
        write_incremental_test_event(&input.join("hour=2/live.parquet"), "host-live", recent_us);
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let build =
            |snapshot_id: i64, objects: Vec<ObjectStamp>, output: &Path, prior: Option<&Path>| {
                let stamp_path = root.path().join(format!("stamps-{snapshot_id}.json"));
                write_json(
                    &stamp_path,
                    &ObjectStampManifest {
                        metadata_location: format!("s3://test/events/metadata/v{snapshot_id}.json"),
                        snapshot_id,
                        table: "test.events".to_string(),
                        objects,
                        table_uuid: None,
                    },
                )
                .unwrap();
                build_generation_reusing(
                    &input,
                    output,
                    &stamp_path,
                    "tenant-a",
                    "key-v1",
                    &key,
                    1,
                    20_000_000,
                    prior,
                )
            };
        let first = root.path().join("first");
        build(
            1,
            vec![
                incremental_test_stamp(&input, "hour=1/old.parquet", "v1"),
                incremental_test_stamp(&input, "hour=2/live.parquet", "v1"),
            ],
            &first,
            None,
        )
        .unwrap();
        assert_eq!(uid_proof_mode(&first), "full");

        // Retention: the old object leaves the snapshot; ingest appends one
        // fresh object. The prior ledger now covers MORE than the reused set.
        std::fs::create_dir_all(input.join("hour=3")).unwrap();
        write_incremental_test_event(
            &input.join("hour=3/fresh.parquet"),
            "host-fresh",
            recent_us + 60 * 60 * 1_000_000,
        );
        let second = root.path().join("second");
        build(
            2,
            vec![
                incremental_test_stamp(&input, "hour=2/live.parquet", "v1"),
                incremental_test_stamp(&input, "hour=3/fresh.parquet", "v2"),
            ],
            &second,
            Some(&first),
        )
        .unwrap();
        assert_eq!(uid_proof_mode(&second), "incremental");
        let ledger: UidLedgerManifest = serde_json::from_slice(
            &std::fs::read(second.join("uid-ledger/manifest.json")).unwrap(),
        )
        .unwrap();
        // The dropped object is forgotten: its uid_rows left the coverage
        // accounting and its identity left the carried ledger.
        assert_eq!(ledger.objects.len(), 2);
        assert!(ledger
            .objects
            .iter()
            .all(|object| !object.event_object_key.ends_with("hour=1/old.parquet")));
        assert_eq!(ledger.window_records, 2);

        // Documented assumed gap (identical to the pure-append path): a
        // re-ingest of the DROPPED object's uid is out-of-window and passes
        // the incremental proof — its original physical row was deleted, so
        // this is not a duplicate of anything served.
        std::fs::create_dir_all(input.join("hour=4")).unwrap();
        write_incremental_test_event(&input.join("hour=4/reingest.parquet"), "host-old", old_us);
        let third = root.path().join("third");
        build(
            3,
            vec![
                incremental_test_stamp(&input, "hour=2/live.parquet", "v1"),
                incremental_test_stamp(&input, "hour=3/fresh.parquet", "v2"),
                incremental_test_stamp(&input, "hour=4/reingest.parquet", "v3"),
            ],
            &third,
            Some(&second),
        )
        .unwrap();
        assert_eq!(uid_proof_mode(&third), "incremental");

        // The fence that must survive the drop: a genuine in-window duplicate
        // of a KEPT object's uid is still rejected by the incremental path.
        std::fs::create_dir_all(input.join("hour=5")).unwrap();
        write_incremental_test_event(&input.join("hour=5/dup.parquet"), "host-live", recent_us);
        let error = build(
            4,
            vec![
                incremental_test_stamp(&input, "hour=2/live.parquet", "v1"),
                incremental_test_stamp(&input, "hour=3/fresh.parquet", "v2"),
                incremental_test_stamp(&input, "hour=5/dup.parquet", "v4"),
            ],
            &root.path().join("fourth"),
            Some(&second),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate metadata.uid rows within the 7-day event-time window"),
            "unexpected error: {error}"
        );
    }

    /// A dropped object whose events reach INTO the uid window could leave
    /// orphaned records in the prior window file (they carry no object
    /// attribution), fabricating duplicates against legitimate re-ingests.
    /// Such a drop must force the exact full proof.
    #[test]
    fn drop_inside_uid_window_forces_full_proof() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        std::fs::create_dir_all(input.join("hour=2")).unwrap();
        // Both objects are within 7 days of the newest event.
        write_incremental_test_event(
            &input.join("hour=1/recent-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
        );
        write_incremental_test_event(
            &input.join("hour=2/recent-b.parquet"),
            "host-b",
            1_786_391_723_456_789,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let first_stamp_path = root.path().join("first-stamps.json");
        write_json(
            &first_stamp_path,
            &ObjectStampManifest {
                metadata_location: "s3://test/events/metadata/v1.json".to_string(),
                snapshot_id: 1,
                table: "test.events".to_string(),
                objects: vec![
                    incremental_test_stamp(&input, "hour=1/recent-a.parquet", "v1"),
                    incremental_test_stamp(&input, "hour=2/recent-b.parquet", "v1"),
                ],
                table_uuid: None,
            },
        )
        .unwrap();
        let first = root.path().join("first");
        build_generation_reusing(
            &input,
            &first,
            &first_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap();
        std::fs::create_dir_all(input.join("hour=3")).unwrap();
        write_incremental_test_event(
            &input.join("hour=3/fresh.parquet"),
            "host-c",
            1_786_395_323_456_789,
        );
        let second_stamp_path = root.path().join("second-stamps.json");
        write_json(
            &second_stamp_path,
            &ObjectStampManifest {
                metadata_location: "s3://test/events/metadata/v2.json".to_string(),
                snapshot_id: 2,
                table: "test.events".to_string(),
                objects: vec![
                    incremental_test_stamp(&input, "hour=2/recent-b.parquet", "v1"),
                    incremental_test_stamp(&input, "hour=3/fresh.parquet", "v2"),
                ],
                table_uuid: None,
            },
        )
        .unwrap();
        let second = root.path().join("second");
        build_generation_reusing(
            &input,
            &second,
            &second_stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            Some(&first),
        )
        .unwrap();
        assert_eq!(uid_proof_mode(&second), "full");
    }

    /// Synthesize one entity-sidecar object with `count` uid postings whose
    /// digests are Sha256(index) — uniformly spread over every proof bucket.
    /// `duplicate_of` plants a second posting of that index's digest at the
    /// END of the object, far from the original in file order so the two
    /// copies land in DIFFERENT spill runs of the same bucket.
    fn write_synthetic_uid_sidecar(
        path: &Path,
        count: u64,
        max_time_ms: u64,
        out_of_window_ms: u64,
        duplicate_of: Option<u64>,
    ) {
        let mut value_hash =
            FixedSizeBinaryBuilder::new(i32::try_from(ENTITY_VALUE_HASH_BYTES).unwrap());
        let mut field_id = UInt8Builder::new();
        let mut object_id = UInt32Builder::new();
        let mut matches = UInt64Builder::new();
        let mut max_time = UInt64Builder::new();
        let mut push = |index: u64| {
            let digest = Sha256::digest(index.to_le_bytes());
            value_hash
                .append_value(&digest[..ENTITY_VALUE_HASH_BYTES])
                .unwrap();
            field_id.append_value(39);
            object_id.append_value(0);
            matches.append_value(1);
            max_time.append_value(if index % 2 == 0 {
                max_time_ms
            } else {
                out_of_window_ms
            });
        };
        for index in 0..count {
            push(index);
        }
        if let Some(index) = duplicate_of {
            push(index);
        }
        let schema = Arc::new(Schema::new(vec![
            Field::new(
                "value_hash",
                DataType::FixedSizeBinary(i32::try_from(ENTITY_VALUE_HASH_BYTES).unwrap()),
                false,
            ),
            Field::new("field_id", DataType::UInt8, false),
            Field::new("object_id", DataType::UInt32, false),
            Field::new("matches", DataType::UInt64, false),
            Field::new("max_time", DataType::UInt64, false),
        ]));
        let batch = RecordBatch::try_new(
            schema.clone(),
            vec![
                Arc::new(value_hash.finish()),
                Arc::new(field_id.finish()),
                Arc::new(object_id.finish()),
                Arc::new(matches.finish()),
                Arc::new(max_time.finish()),
            ],
        )
        .unwrap();
        let mut writer = ArrowWriter::try_new(File::create(path).unwrap(), schema, None).unwrap();
        writer.write(&batch).unwrap();
        writer.close().unwrap();
    }

    fn synthetic_uid_local_object(path: &Path) -> LocalObject {
        LocalObject {
            id: 0,
            position: 0,
            path: path.to_path_buf(),
            stamp: ObjectStamp {
                relative_path: "object.parquet".to_string(),
                source_uri: "s3://test/events/data/object.parquet".to_string(),
                version_id: "v1".to_string(),
                size_bytes: std::fs::metadata(path).unwrap().len(),
                sha256: file_digest(path).unwrap(),
            },
        }
    }

    /// NAN-2361 D2: the full proof's memory use is bounded by the heap budget
    /// (external merge sort), not by table size (the old whole-bucket
    /// `std::fs::read` — ~14GB per bucket at the shipped 50GB/day x 365d
    /// design size). A 2KB budget over 30k uids must spill, stay EXACT, and
    /// produce a window byte-identical to the fully in-memory layout.
    #[test]
    fn full_uid_proof_bounds_memory_with_external_bucket_sort() {
        const ROWS: u64 = 30_000;
        const MAX_MS: u64 = 1_000_000_000_000;
        const OLD_MS: u64 = MAX_MS - 8 * 24 * 60 * 60 * 1_000;
        let root = tempfile::tempdir().unwrap();
        let entity = root.path().join("entity");
        std::fs::create_dir_all(&entity).unwrap();
        write_synthetic_uid_sidecar(
            &entity.join("object-0000.parquet"),
            ROWS,
            MAX_MS,
            OLD_MS,
            None,
        );
        let object = synthetic_uid_local_object(&entity.join("object-0000.parquet"));

        // Tiny budget: 2048/24 = 85 records per chunk. 30k rows over the
        // maximum 256 buckets is ~117 records per bucket, so every bucket
        // still overflows the chunk and must spill.
        let spilled = full_uid_proof(
            &entity,
            &root.path().join("ledger-spilled"),
            "tenant-a",
            std::slice::from_ref(&object),
            2_048,
            ROWS,
        )
        .unwrap();
        assert_eq!(spilled.uid_rows, ROWS);
        assert_eq!(spilled.bucket_shift, 0);
        assert_eq!(spilled.buckets, 256);
        assert!(
            spilled.spilled_sort_runs > 0,
            "the memory bound was never exercised: no bucket spilled"
        );

        // Ample budget: default 64-bucket layout, everything in memory.
        let in_memory = full_uid_proof(
            &entity,
            &root.path().join("ledger-memory"),
            "tenant-a",
            std::slice::from_ref(&object),
            64_000_000,
            ROWS,
        )
        .unwrap();
        assert_eq!(in_memory.uid_rows, ROWS);
        assert_eq!(in_memory.bucket_shift, UID_PROOF_BUCKET_SHIFT);
        assert_eq!(in_memory.buckets, UID_PROOF_BUCKETS);
        assert_eq!(in_memory.spilled_sort_runs, 0);

        // Both layouts must publish the SAME globally sorted window — the
        // digest-prefix bucketing preserving digest order is what the window
        // write depends on, independent of bucket count or spilling.
        let manifest = |name: &str| -> UidLedgerManifest {
            serde_json::from_slice(
                &std::fs::read(root.path().join(name).join("manifest.json")).unwrap(),
            )
            .unwrap()
        };
        let spilled_manifest = manifest("ledger-spilled");
        let memory_manifest = manifest("ledger-memory");
        assert_eq!(spilled_manifest.window_records, ROWS / 2);
        assert_eq!(
            spilled_manifest.window_sha256,
            memory_manifest.window_sha256
        );
        let window = std::fs::read(root.path().join("ledger-spilled/window.uids")).unwrap();
        let mut previous: Option<UidDigest> = None;
        for record in window.chunks_exact(UID_WINDOW_RECORD_BYTES) {
            let mut digest = [0_u8; ENTITY_VALUE_HASH_BYTES];
            digest.copy_from_slice(&record[..ENTITY_VALUE_HASH_BYTES]);
            assert!(
                previous.is_none_or(|last| last < digest),
                "window is not strictly ascending"
            );
            previous = Some(digest);
        }

        // Exactness under spilling: a duplicate digest whose two copies sit
        // in different sorted runs of the same bucket is still detected.
        let dup_entity = root.path().join("dup-entity");
        std::fs::create_dir_all(&dup_entity).unwrap();
        write_synthetic_uid_sidecar(
            &dup_entity.join("object-0000.parquet"),
            ROWS,
            MAX_MS,
            OLD_MS,
            Some(0),
        );
        let dup_object = synthetic_uid_local_object(&dup_entity.join("object-0000.parquet"));
        let error = full_uid_proof(
            &dup_entity,
            &root.path().join("ledger-dup"),
            "tenant-a",
            std::slice::from_ref(&dup_object),
            2_048,
            ROWS + 1,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("duplicate metadata.uid rows across"),
            "unexpected error: {error}"
        );
    }

    /// The dynamic layout keeps the BUCKETS <-> digest-prefix-shift coupling
    /// exact and order-preserving for every shift the derivation can choose.
    #[test]
    fn uid_proof_dynamic_bucket_layout_is_coupled_and_order_preserving() {
        // Small tables keep the default layout; the derivation only widens.
        assert_eq!(
            uid_proof_bucket_layout(0, 1),
            (UID_PROOF_BUCKET_SHIFT, UID_PROOF_BUCKETS)
        );
        assert_eq!(
            uid_proof_bucket_layout(1_000, 1_000_000),
            (UID_PROOF_BUCKET_SHIFT, UID_PROOF_BUCKETS)
        );
        // Oversized tables widen to at most 256 buckets (one digest byte).
        assert_eq!(uid_proof_bucket_layout(u64::MAX, 1), (0, 256));
        for chunk in [1_usize, 100, 1_000_000] {
            for rows in [0_u64, 1, 64, 100_000, 23_000_000_000] {
                let (shift, buckets) = uid_proof_bucket_layout(rows, chunk);
                // The coupling (also asserted at runtime inside the layout fn).
                assert_eq!(buckets, 1 << (8 - shift));
                // Routing exactness and digest-order preservation.
                let mut last = 0_usize;
                for byte in 0_u16..=255 {
                    let bucket = usize::from((byte as u8) >> shift);
                    assert!(bucket < buckets);
                    assert!(bucket >= last);
                    last = bucket;
                }
                assert_eq!(last, buckets - 1);
            }
        }
    }

    #[test]
    fn generation_rejects_duplicate_event_uids_across_iceberg_objects() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        std::fs::create_dir_all(input.join("hour=1")).unwrap();
        write_incremental_test_event(
            &input.join("hour=1/object-a.parquet"),
            "host-a",
            1_786_388_123_456_789,
        );
        write_incremental_test_event(
            &input.join("hour=1/object-b.parquet"),
            "host-a",
            1_786_388_123_456_789,
        );
        let key = root.path().join("entity.key");
        std::fs::write(&key, [7_u8; 32]).unwrap();
        let stamps = ObjectStampManifest {
            metadata_location: "s3://test/events/metadata/v1.json".to_string(),
            snapshot_id: 1,
            table: "test.events".to_string(),
            objects: vec![
                incremental_test_stamp(&input, "hour=1/object-a.parquet", "v1"),
                incremental_test_stamp(&input, "hour=1/object-b.parquet", "v1"),
            ],
            table_uuid: None,
        };
        let stamp_path = root.path().join("stamps.json");
        write_json(&stamp_path, &stamps).unwrap();
        let error = build_generation_reusing(
            &input,
            &root.path().join("candidate"),
            &stamp_path,
            "tenant-a",
            "key-v1",
            &key,
            1,
            20_000_000,
            None,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("contains 1 duplicate metadata.uid rows across 2 physical event rows"));
    }

    #[test]
    fn hot_tail_manifest_is_signed_and_tamper_evident() {
        let key = [9_u8; 32];
        let manifest = HotTailManifest {
            schema_version: 1,
            tenant_id: "tenant-a".to_string(),
            table: "nano.events".to_string(),
            base_snapshot_id: 10,
            head_snapshot_id: 11,
            tail_id: None,
            head_metadata_location: "s3://serving/nano/events/metadata/v11.metadata.json"
                .to_string(),
            iceberg_metadata_file_path: "metadata/v11.metadata.json".to_string(),
            read_schema: None,
            available_paths: Vec::new(),
            objects: vec![HotTailObject {
                source_uri: "s3://serving/nano/events/data/day=1/new.parquet".to_string(),
                version_id: "version-1".to_string(),
                etag: None,
                size_bytes: 123,
                rows: 4,
                sha256: None,
                min_time_ms: None,
                max_time_ms: None,
                committed: false,
            }],
            local_paths: Vec::new(),
        };
        let encoded = sign_hot_tail_manifest(manifest.clone(), &key).unwrap();
        let verified = verify_hot_tail_manifest(&encoded, &key).unwrap();
        assert_eq!(verified.base_snapshot_id, manifest.base_snapshot_id);
        assert_eq!(verified.objects.len(), 1);

        let mut tampered: Value = serde_json::from_slice(&encoded).unwrap();
        tampered["manifest"]["objects"][0]["rows"] = json!(5);
        assert!(verify_hot_tail_manifest(&serde_json::to_vec(&tampered).unwrap(), &key).is_err());
    }

    #[test]
    fn staged_hot_tail_can_share_the_base_snapshot_with_a_content_identity() {
        let key = [7_u8; 32];
        let manifest = HotTailManifest {
            schema_version: 2,
            tenant_id: "tenant-a".to_string(),
            table: "nano.events".to_string(),
            base_snapshot_id: 10,
            head_snapshot_id: 10,
            tail_id: Some("a".repeat(64)),
            head_metadata_location: "s3://serving/nano/events/metadata/v10.metadata.json"
                .to_string(),
            iceberg_metadata_file_path: "metadata/v10.metadata.json".to_string(),
            read_schema: None,
            available_paths: Vec::new(),
            objects: vec![HotTailObject {
                source_uri: "s3://serving/nano/events/data/tail/tenant_sha256=abc/new.parquet"
                    .to_string(),
                version_id: "version-1".to_string(),
                etag: None,
                size_bytes: 123,
                rows: 4,
                sha256: None,
                min_time_ms: Some(1_000),
                max_time_ms: Some(2_000),
                committed: false,
            }],
            local_paths: Vec::new(),
        };
        let encoded = sign_hot_tail_manifest(manifest, &key).unwrap();
        assert_eq!(
            verify_hot_tail_manifest(&encoded, &key)
                .unwrap()
                .schema_version,
            2
        );
    }

    #[test]
    fn staged_hot_tail_builder_rejects_cross_tenant_objects() {
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        let base = ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.metadata.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: vec![ObjectStamp {
                relative_path: "old.parquet".to_string(),
                source_uri: "s3://serving/nano/events/data/old.parquet".to_string(),
                version_id: "version-old".to_string(),
                size_bytes: 100,
                sha256: "b".repeat(64),
            }],
            table_uuid: None,
        };
        let object = HotTailObject {
            source_uri: format!(
                "s3://serving/nano/events/data/tail/tenant_sha256={tenant_hash}/new.parquet"
            ),
            version_id: "version-new".to_string(),
            etag: None,
            size_bytes: 100,
            rows: 2,
            sha256: None,
            min_time_ms: None,
            max_time_ms: None,
            committed: false,
        };
        assert!(build_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            &"a".repeat(64),
            vec![object.clone()],
            10,
            1_000,
            0,
        )
        .is_ok());
        assert!(build_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-b",
            &base,
            &"a".repeat(64),
            vec![object],
            10,
            1_000,
            0,
        )
        .is_err());
    }

    #[test]
    fn staged_hot_tail_object_overrun_has_a_serving_bound_error() {
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        let base = ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.metadata.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: Vec::new(),
            table_uuid: None,
        };
        let object = |name: &str| HotTailObject {
            source_uri: format!(
                "s3://serving/nano/events/data/tail/tenant_sha256={tenant_hash}/{name}.parquet"
            ),
            version_id: format!("version-{name}"),
            etag: None,
            size_bytes: 100,
            rows: 2,
            sha256: None,
            min_time_ms: Some(1_000),
            max_time_ms: Some(2_000),
            committed: false,
        };
        let error = build_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            &"a".repeat(64),
            vec![object("a"), object("b")],
            1,
            1_000,
            0,
        )
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "staged hot-tail objects exceed the serving bound: staged objects 2 > bound 1"
        );
    }

    /// NAN-2539: a tail one object over the bound wedged activation for half
    /// an hour and the refusal said only "exceed the serving bound" — an
    /// operator could not tell which of the four bounds tripped, nor by how
    /// much, without lifting the child's argv out of /proc and re-running it.
    /// The refusal must name the bound and both numbers, and it must keep the
    /// exact substring the signer's failure classifier
    /// (`lake_staged_tail_manage::failure_class`) keys on.
    #[test]
    fn staged_hot_tail_refusal_one_object_over_names_the_bound_and_both_numbers() {
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        let base = ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.metadata.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: Vec::new(),
            table_uuid: None,
        };
        let object = |name: &str| HotTailObject {
            source_uri: format!(
                "s3://serving/nano/events/data/tail/tenant_sha256={tenant_hash}/{name}.parquet"
            ),
            version_id: format!("version-{name}"),
            etag: None,
            size_bytes: 100,
            rows: 2,
            sha256: None,
            min_time_ms: Some(1_000),
            max_time_ms: Some(2_000),
            committed: false,
        };
        let bound = 3_usize;
        let staged = (0..bound + 1)
            .map(|index| object(&format!("object-{index}")))
            .collect::<Vec<_>>();
        let error = build_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            &"a".repeat(64),
            staged.clone(),
            bound,
            1_000_000,
            0,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            error,
            "staged hot-tail objects exceed the serving bound: staged objects 4 > bound 3",
            "the refusal names the bound that tripped and both numbers"
        );
        // The signer's failure classifier keys on this exact substring to
        // report "alive but refusing" rather than "dead"; the added detail
        // must not break it.
        assert!(
            error.contains("exceed the serving bound"),
            "classifier substring survives: {error}"
        );

        // The byte bound is a distinct refusal and must be distinguishable
        // from the object-count one in the same log line.
        let bytes_error = build_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            &"a".repeat(64),
            staged,
            64,
            399,
            0,
        )
        .unwrap_err()
        .to_string();
        assert_eq!(
            bytes_error,
            "staged hot-tail bytes exceed the serving bound: staged bytes 400 > bound 399"
        );
        assert!(bytes_error.contains("exceed the serving bound"));
    }

    #[test]
    fn staged_hot_tail_builder_accepts_catalog_committed_product_objects_only_in_table() {
        let base = ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.metadata.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: vec![ObjectStamp {
                relative_path: "old.parquet".to_string(),
                source_uri: "s3://serving/nano/events/data/old.parquet".to_string(),
                version_id: "version-old".to_string(),
                size_bytes: 100,
                sha256: "b".repeat(64),
            }],
            table_uuid: None,
        };
        let product = HotTailObject {
            source_uri: "s3://serving/nano/events/data/event_hour=10/signal.parquet".to_string(),
            version_id: "version-signal".to_string(),
            etag: None,
            size_bytes: 100,
            rows: 2,
            sha256: None,
            min_time_ms: Some(36_000_000),
            max_time_ms: Some(39_599_999),
            committed: false,
        };
        assert!(build_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            &"a".repeat(64),
            vec![product.clone()],
            10,
            1_000,
            0,
        )
        .is_ok());

        let mut cross_table = product;
        cross_table.source_uri =
            "s3://serving/another/events/data/event_hour=10/signal.parquet".to_string();
        assert!(build_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            &"a".repeat(64),
            vec![cross_table],
            10,
            1_000,
            0,
        )
        .is_err());
    }

    #[test]
    fn staged_tail_selection_has_one_exact_version_content_identity() {
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        let base = ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: Vec::new(),
            table_uuid: None,
        };
        let candidate = |version: &str| {
            StagedHotTailLedgerObject {
            object: HotTailObject {
                source_uri: format!(
                    "s3://serving/nano/events/data/tail/tenant_sha256={tenant_hash}/event_hour=1/a.parquet"
                ),
                version_id: version.to_string(),
                etag: None,
                size_bytes: 10,
                rows: 2,
                sha256: None,
                min_time_ms: Some(1_000),
                max_time_ms: Some(2_000),
                committed: false,
            },
            sha256: "a".repeat(64),
        }
        };
        let first = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            vec![candidate("version-a")],
            10,
            1_000,
            0,
        )
        .unwrap();
        let second = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            vec![candidate("version-b")],
            10,
            1_000,
            0,
        )
        .unwrap();
        assert_ne!(first.tail_id, second.tail_id);
    }

    #[test]
    fn staged_tail_selection_rejects_untrusted_ledger_digests() {
        let base = ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: Vec::new(),
            table_uuid: None,
        };
        let candidate = StagedHotTailLedgerObject {
            object: HotTailObject {
                source_uri: "s3://serving/nano/events/data/event_hour=1/a.parquet".to_string(),
                version_id: "version-a".to_string(),
                etag: None,
                size_bytes: 10,
                rows: 2,
                sha256: None,
                min_time_ms: Some(1_000),
                max_time_ms: Some(2_000),
                committed: false,
            },
            sha256: "not-a-digest".to_string(),
        };
        assert!(select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            vec![candidate],
            10,
            1_000,
            0,
        )
        .is_err());
    }

    #[test]
    fn staged_tail_selection_removes_only_an_exact_indexed_identity() {
        let indexed = ObjectStamp {
            relative_path: "data/event_hour=1/a.parquet".to_string(),
            source_uri: "s3://serving/nano/events/data/event_hour=1/a.parquet".to_string(),
            version_id: "version-a".to_string(),
            size_bytes: 10,
            sha256: "a".repeat(64),
        };
        let base = ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: vec![indexed.clone()],
            table_uuid: None,
        };
        let candidate = |version: &str| StagedHotTailLedgerObject {
            object: HotTailObject {
                source_uri: indexed.source_uri.clone(),
                version_id: version.to_string(),
                etag: None,
                size_bytes: indexed.size_bytes,
                rows: 2,
                sha256: None,
                min_time_ms: Some(1_000),
                max_time_ms: Some(2_000),
                committed: false,
            },
            sha256: indexed.sha256.clone(),
        };
        let empty = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            vec![candidate("version-a")],
            10,
            1_000,
            0,
        )
        .unwrap();
        assert!(empty.objects.is_empty());
        assert_eq!(empty.schema_version, 1);
        assert!(select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &base,
            vec![candidate("different-version")],
            10,
            1_000,
            0,
        )
        .is_err());
    }

    // -- NAN-2361 two-tier hot tail ------------------------------------------

    fn tier_base() -> ObjectStampManifest {
        ObjectStampManifest {
            metadata_location: "s3://serving/nano/events/metadata/v10.json".to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: Vec::new(),
            table_uuid: None,
        }
    }

    fn tier_ledger_object(
        name: &str,
        size_bytes: u64,
        committed: bool,
    ) -> StagedHotTailLedgerObject {
        let tenant_hash = hex::encode(Sha256::digest(b"tenant-a"));
        StagedHotTailLedgerObject {
            object: HotTailObject {
                source_uri: format!(
                    "s3://serving/nano/events/data/tail/tenant_sha256={tenant_hash}/event_hour=1/{name}.parquet"
                ),
                version_id: format!("version-{name}"),
                etag: None,
                size_bytes,
                rows: 2,
                sha256: None,
                min_time_ms: Some(1_000),
                max_time_ms: Some(2_000),
                committed,
            },
            sha256: "c".repeat(64),
        }
    }

    /// The headline behavior: an object leaves the tight byte envelope at
    /// COMMIT (committed marker from the ledger) rather than at activation.
    /// Mutations caught: (a) removing the staged byte check entirely — the
    /// second half fails; (b) charging committed bytes against the envelope —
    /// the first half fails; (c) forgetting schema 3 in sign/verify/validate.
    #[test]
    fn committed_tier_is_exempt_from_the_staged_byte_envelope() {
        let five_gib = 5 * 1_073_741_824_u64;
        let ledger = vec![
            tier_ledger_object("staged", 100, false),
            tier_ledger_object("committed-a", five_gib, true),
            tier_ledger_object("committed-b", five_gib, true),
        ];
        let manifest = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            ledger.clone(),
            10,
            1_000, // staged envelope: 1_000 bytes — dwarfed by the committed tier
            10,
        )
        .expect("a 10 GiB committed tier must still publish");
        assert_eq!(manifest.schema_version, 3);
        assert_eq!(manifest.objects.len(), 3);
        let key = [3_u8; 32];
        let encoded = sign_hot_tail_manifest(manifest, &key).expect("signs");
        let verified = verify_hot_tail_manifest(&encoded, &key).expect("verifies");
        assert_eq!(
            verified
                .objects
                .iter()
                .filter(|object| object.committed)
                .count(),
            2
        );

        // The SAME objects without the committed marker (the pre-tier world,
        // and the disabled-tier configuration) still refuse at the envelope.
        let unmarked = ledger
            .into_iter()
            .map(|mut candidate| {
                candidate.object.committed = false;
                candidate
            })
            .collect::<Vec<_>>();
        let error = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            unmarked,
            10,
            1_000,
            10,
        )
        .expect_err("unmarked objects must still gate the signer");
        assert!(
            error
                .to_string()
                .contains("staged hot-tail bytes exceed the serving bound"),
            "unexpected refusal: {error}"
        );
    }

    /// Tier A alone gates the signer even when a committed tier is present.
    /// Mutation caught: computing the envelope over committed-only or
    /// total-minus-committed forms that accidentally exclude staged bytes.
    #[test]
    fn staged_tier_alone_still_gates_the_signer() {
        let error = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![
                tier_ledger_object("staged-big", 2_000, false),
                tier_ledger_object("committed", 100, true),
            ],
            10,
            1_000,
            10,
        )
        .expect_err("staged bytes over the envelope must refuse");
        assert!(error
            .to_string()
            .contains("staged hot-tail bytes exceed the serving bound"));
    }

    /// Mutations caught: dropping the committed count bound, or truncating
    /// instead of refusing (truncation would hide committed events entirely).
    #[test]
    fn committed_object_count_gates_at_its_own_count_bound() {
        let over = vec![
            tier_ledger_object("committed-a", 100, true),
            tier_ledger_object("committed-b", 100, true),
            tier_ledger_object("committed-c", 100, true),
        ];
        let error = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            over.clone(),
            10,
            1_000,
            2,
        )
        .expect_err("committed count over its bound must refuse");
        assert!(
            error
                .to_string()
                .contains("committed hot-tail objects exceed the serving bound"),
            "the refusal must classify as serving_bound_exceeded: {error}"
        );
        // A committed object while the tier is DISABLED (bound 0) is a
        // configuration fault, not a silent envelope exemption.
        assert!(select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![tier_ledger_object("committed-a", 100, true)],
            10,
            1_000,
            0,
        )
        .is_err());
    }

    /// A field-frozen twin of TODAY'S wire format (`deny_unknown_fields`, no
    /// `committed` key), standing in for every not-yet-upgraded reader.
    /// Mutation caught: serializing `committed: false` unconditionally (or any
    /// other new key) — the twin's deserialization fails and so would every
    /// old worker mid-rolling-deploy.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyHotTailManifestTwin {
        schema_version: u64,
        #[allow(dead_code)]
        tenant_id: String,
        #[allow(dead_code)]
        table: String,
        #[allow(dead_code)]
        base_snapshot_id: i64,
        #[allow(dead_code)]
        head_snapshot_id: i64,
        #[serde(default)]
        #[allow(dead_code)]
        tail_id: Option<String>,
        #[allow(dead_code)]
        head_metadata_location: String,
        #[allow(dead_code)]
        iceberg_metadata_file_path: String,
        #[serde(default)]
        #[allow(dead_code)]
        read_schema: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        available_paths: Vec<String>,
        objects: Vec<LegacyHotTailObjectTwin>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct LegacyHotTailObjectTwin {
        #[allow(dead_code)]
        source_uri: String,
        #[allow(dead_code)]
        version_id: String,
        #[allow(dead_code)]
        size_bytes: u64,
        #[allow(dead_code)]
        rows: u64,
        #[serde(default)]
        #[allow(dead_code)]
        min_time_ms: Option<i64>,
        #[serde(default)]
        #[allow(dead_code)]
        max_time_ms: Option<i64>,
    }

    #[test]
    fn a_tiered_publisher_without_committed_objects_emits_the_legacy_format_byte_for_byte() {
        // committed tier ENABLED (bound 10) but the reconcile found only
        // staged rows: the manifest must remain schema 2 with no new keys, so
        // an old reader keeps verifying it during a rolling deploy.
        let manifest = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![tier_ledger_object("staged", 100, false)],
            10,
            1_000,
            10,
        )
        .unwrap();
        assert_eq!(manifest.schema_version, 2);
        let encoded = serde_json::to_vec(&manifest).unwrap();
        assert!(!String::from_utf8(encoded.clone())
            .unwrap()
            .contains("committed"));
        let twin: LegacyHotTailManifestTwin = serde_json::from_slice(&encoded).expect(
            "a legacy (deny_unknown_fields) reader must accept a committed-tier-free manifest",
        );
        assert_eq!(twin.schema_version, 2);
        assert_eq!(twin.objects.len(), 1);

        // And the inverse direction, stated as a fact rather than hoped: a
        // schema-3 manifest is NOT legacy-readable, which is exactly why v3
        // emission is gated on an explicit flag shipped with upgraded images.
        let tiered = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![
                tier_ledger_object("staged", 100, false),
                tier_ledger_object("committed", 100, true),
            ],
            10,
            1_000,
            10,
        )
        .unwrap();
        assert_eq!(tiered.schema_version, 3);
        assert!(serde_json::from_slice::<LegacyHotTailManifestTwin>(
            &serde_json::to_vec(&tiered).unwrap()
        )
        .is_err());
    }

    #[test]
    fn cached_tail_publication_binds_every_object_digest_in_schema_v4() {
        let manifest = select_cached_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![
                tier_ledger_object("staged", 100, false),
                tier_ledger_object("committed", 200, true),
            ],
            10,
            1_000,
            10,
        )
        .unwrap();
        assert_eq!(manifest.schema_version, 4);
        assert!(manifest
            .objects
            .iter()
            .all(|object| object.sha256.as_deref().is_some_and(valid_sha256)));
        assert!(manifest.local_paths.is_empty());
        let wire = serde_json::to_vec(&manifest).unwrap();
        assert!(
            !String::from_utf8(wire.clone())
                .unwrap()
                .contains("\"etag\""),
            "dedicated schema-v4 wire bytes must not gain the enterprise_shared ETag field"
        );
        assert!(serde_json::from_slice::<LegacyHotTailManifestTwin>(&wire).is_err());
        let key = [8_u8; 32];
        let encoded = sign_hot_tail_manifest(manifest, &key).unwrap();
        let verified = verify_hot_tail_manifest(&encoded, &key).unwrap();
        assert_eq!(verified.schema_version, 4);
        assert!(verified.local_paths.is_empty());
    }

    #[test]
    fn shared_r2_manifest_signs_authoritative_etags_and_refuses_omission() {
        let tenant_id = uuid::Uuid::from_u128(1).to_string();
        let tenant_hash = hex::encode(Sha256::digest(tenant_id.as_bytes()));
        let base = ObjectStampManifest {
            metadata_location: "s3://nano-tenant-a/warehouse/nano/events/metadata/v10.json"
                .to_string(),
            snapshot_id: 10,
            table: "nano.events".to_string(),
            objects: Vec::new(),
            table_uuid: None,
        };
        let candidate = |etag: Option<&str>| {
            StagedHotTailLedgerObject {
                object: HotTailObject {
                source_uri: format!(
                    "s3://nano-tenant-a/warehouse/nano/events/data/tail/tenant_sha256={tenant_hash}/event_hour=1/a.parquet"
                ),
                // Compatibility identity returned by the R2 bridge. Shared
                // readers deliberately do not call the version API with it.
                version_id: "r2-version-a".to_string(),
                etag: etag.map(ToOwned::to_owned),
                size_bytes: 10,
                rows: 2,
                sha256: None,
                min_time_ms: Some(1_000),
                max_time_ms: Some(2_000),
                committed: false,
                },
                sha256: "a".repeat(64),
            }
        };
        assert!(select_shared_r2_hot_tail_manifest(
            "s3://nano-tenant-a/warehouse/nano/events",
            &tenant_id,
            &base,
            vec![candidate(None)],
            10,
            1_000,
            0,
        )
        .is_err());

        let manifest = select_shared_r2_hot_tail_manifest(
            "s3://nano-tenant-a/warehouse/nano/events",
            &tenant_id,
            &base,
            vec![candidate(Some("\"r2-etag-a\""))],
            10,
            1_000,
            0,
        )
        .unwrap();
        assert_eq!(manifest.schema_version, 4);
        assert_eq!(manifest.objects[0].etag.as_deref(), Some("\"r2-etag-a\""));
        let key = [9_u8; 32];
        let encoded = sign_hot_tail_manifest(manifest, &key).unwrap();
        let verified = verify_hot_tail_manifest(&encoded, &key).unwrap();
        validate_shared_r2_hot_tail_manifest(&verified).unwrap();

        let mut tampered: Value = serde_json::from_slice(&encoded).unwrap();
        tampered["manifest"]["objects"][0]["etag"] = json!("\"r2-etag-b\"");
        assert!(verify_hot_tail_manifest(&serde_json::to_vec(&tampered).unwrap(), &key).is_err());
    }

    /// An old-format manifest (no `committed` keys) deserializes with the tier
    /// marker defaulted off and re-serializes to the IDENTICAL bytes.
    /// Mutation caught: any wire-shape drift of the legacy formats in either
    /// direction (new field serialized, old field dropped, default changed).
    #[test]
    fn old_format_manifest_round_trips_unchanged() {
        let legacy = serde_json::json!({
            "schema_version": 2,
            "tenant_id": "tenant-a",
            "table": "nano.events",
            "base_snapshot_id": 10,
            "head_snapshot_id": 10,
            "tail_id": "a".repeat(64),
            "head_metadata_location": "s3://serving/nano/events/metadata/v10.json",
            "iceberg_metadata_file_path": "metadata/v10.json",
            "objects": [{
                "source_uri": "s3://serving/nano/events/data/event_hour=1/a.parquet",
                "version_id": "version-a",
                "size_bytes": 10,
                "rows": 2,
                "min_time_ms": 1_000,
                "max_time_ms": 2_000,
            }],
        });
        let bytes = serde_json::to_vec(&legacy).unwrap();
        let manifest: HotTailManifest = serde_json::from_slice(&bytes).unwrap();
        assert!(!manifest.objects[0].committed);
        validate_hot_tail_manifest(&manifest).expect("legacy manifest must stay valid");
        assert_eq!(
            serde_json::to_value(&manifest).unwrap(),
            legacy,
            "legacy manifest must round-trip without gaining or losing keys"
        );
        // And it still signs/verifies through the current code paths.
        let key = [5_u8; 32];
        let encoded = sign_hot_tail_manifest(manifest, &key).unwrap();
        assert_eq!(
            verify_hot_tail_manifest(&encoded, &key)
                .unwrap()
                .schema_version,
            2
        );
    }

    #[test]
    fn staged_tail_accepts_more_than_the_retired_one_gib_literal() {
        let two_gib = 2 * 1_073_741_824;
        let manifest = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![tier_ledger_object("staged", two_gib, false)],
            10,
            two_gib,
            0,
        )
        .expect("a staged tail above the retired 1 GiB literal must be valid");
        validate_hot_tail_manifest(&manifest).expect("every reader must accept the same envelope");

        assert!(
            select_staged_hot_tail_manifest(
                "s3://serving/nano/events",
                "tenant-a",
                &tier_base(),
                vec![tier_ledger_object(
                    "too-large",
                    HOT_TAIL_SERVING_CEILING_BYTES + 1,
                    false,
                )],
                10,
                HOT_TAIL_SERVING_CEILING_BYTES,
                0,
            )
            .is_err(),
            "the centralized absolute ceiling must remain fail-closed"
        );
    }

    /// The legacy schemas must never carry the committed marker: it would
    /// smuggle the byte-envelope exemption into manifests that pre-tier
    /// readers also accept, so its validity is bound to schema 3.
    /// Mutation caught: dropping `committed_objects != 0` from the schema-1/2
    /// arms of `validate_hot_tail_manifest`.
    #[test]
    fn legacy_schemas_reject_a_smuggled_committed_marker() {
        let mut manifest = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![tier_ledger_object("staged", 100, false)],
            10,
            1_000,
            0,
        )
        .unwrap();
        assert_eq!(manifest.schema_version, 2);
        manifest.objects[0].committed = true;
        let key = [5_u8; 32];
        assert!(sign_hot_tail_manifest(manifest.clone(), &key).is_err());
        // Schema 3 without any committed object is equally non-canonical: it
        // must have been emitted as schema 2 for legacy readers.
        manifest.objects[0].committed = false;
        manifest.schema_version = 3;
        assert!(sign_hot_tail_manifest(manifest, &key).is_err());
    }

    /// Committed objects escape the byte envelope, so per-object time bounds
    /// are their only per-query cost fence; they are mandatory at every
    /// validation site. Mutation caught: dropping the committed => Some(min/max)
    /// requirement from `validate_hot_tail_manifest`.
    #[test]
    fn a_committed_object_without_time_bounds_fails_closed() {
        let mut ledger = tier_ledger_object("committed", 100, true);
        ledger.object.min_time_ms = None;
        ledger.object.max_time_ms = None;
        assert!(select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![ledger],
            10,
            1_000,
            10,
        )
        .is_err());
    }

    /// The tier marker rides inside the HMAC trust boundary: re-tiering a
    /// signed manifest in transit must break the signature.
    /// Mutation caught: excluding `committed` from the signed payload.
    #[test]
    fn tampering_the_tier_marker_breaks_the_signature() {
        let key = [7_u8; 32];
        let manifest = select_staged_hot_tail_manifest(
            "s3://serving/nano/events",
            "tenant-a",
            &tier_base(),
            vec![
                tier_ledger_object("staged", 100, false),
                tier_ledger_object("committed", 100, true),
            ],
            10,
            1_000,
            10,
        )
        .unwrap();
        let encoded = sign_hot_tail_manifest(manifest, &key).unwrap();
        assert!(verify_hot_tail_manifest(&encoded, &key).is_ok());
        let mut tampered: Value = serde_json::from_slice(&encoded).unwrap();
        // Both directions: promoting a staged object into the exempt tier,
        // and demoting a committed one under the envelope.
        let objects = tampered["manifest"]["objects"].as_array_mut().unwrap();
        for object in objects.iter_mut() {
            let committed = object
                .get("committed")
                .and_then(Value::as_bool)
                .unwrap_or(false);
            if committed {
                object.as_object_mut().unwrap().remove("committed");
            } else {
                object["committed"] = json!(true);
            }
        }
        assert!(verify_hot_tail_manifest(&serde_json::to_vec(&tampered).unwrap(), &key).is_err());
    }

    /// Re-tiering the same object set keeps its content identity, so durable
    /// job admission pins survive a committed-tier rollout.
    #[test]
    fn tier_markers_do_not_change_the_tail_content_identity() {
        let build = |committed: bool| {
            select_staged_hot_tail_manifest(
                "s3://serving/nano/events",
                "tenant-a",
                &tier_base(),
                vec![tier_ledger_object("pack", 100, committed)],
                10,
                1_000,
                10,
            )
            .unwrap()
        };
        assert_eq!(build(false).tail_id, build(true).tail_id);
    }

    #[test]
    fn canonicalization_matches_entity_contract() {
        assert_eq!(canonicalize("  EXAMPLE.COM ", "text"), "example.com");
        assert_eq!(canonicalize("::ffff:192.0.2.1", "ip"), "192.0.2.1");
        assert_eq!(canonicalize("not-an-ip", "ip"), "not-an-ip");
    }

    #[test]
    fn entity_sidecar_covers_canonical_process_names() {
        let fields = ENTITY_FIELDS
            .iter()
            .map(|field| (field.field_id, field.source_path))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(fields.len(), ENTITY_FIELDS.len());
        assert_eq!(fields.get(&33), Some(&"process.name"));
        assert_eq!(fields.get(&34), Some(&"actor.process.name"));
    }

    #[test]
    fn entity_sidecar_covers_ocsf_trace_correlation_and_generic_fallbacks() {
        let fields = ENTITY_FIELDS
            .iter()
            .map(|field| (field.field_id, field.source_path))
            .collect::<BTreeMap<_, _>>();
        assert_eq!(fields.len(), ENTITY_FIELDS.len());
        assert_eq!(fields.get(&35), Some(&"trace.uid"));
        assert_eq!(fields.get(&36), Some(&"trace.span.uid"));
        assert_eq!(fields.get(&37), Some(&"unmapped.trace_id"));
        assert_eq!(fields.get(&38), Some(&"unmapped.span_id"));
        assert_eq!(fields.get(&39), Some(&"metadata.uid"));
    }

    #[test]
    fn derivative_compatibility_contract_is_stable_and_content_addressed() {
        let first = derivative_compatibility_contract_sha256().unwrap();
        let second = derivative_compatibility_contract_sha256().unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert!(first
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    }

    #[test]
    fn bundle_upgrade_invalidates_published_pointer_compatibility() {
        assert_ne!(
            derivative_contract_for_bundle("nano-lake-generation-bundle-v2").unwrap(),
            derivative_compatibility_contract_sha256().unwrap(),
        );
    }

    #[test]
    fn digest_is_domain_separated_and_stable() {
        let key = [7_u8; 32];
        assert_eq!(
            entity_digest(&key, "host-a").unwrap(),
            entity_digest(&key, "host-a").unwrap()
        );
        assert_ne!(
            entity_digest(&key, "host-a").unwrap(),
            entity_digest(&key, "host-b").unwrap()
        );
    }

    #[test]
    fn identity_snapshot_writer_preserves_utc_microseconds() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("by-ip.parquet");
        let expected_time = 1_786_388_123_456_789_i64;
        write_identity_observations(
            &path,
            &[IdentityObservation {
                ip: "10.1.2.3".to_string(),
                observed_at_us: expected_time,
                hostname_lc: "host-a".to_string(),
                user_lc: "alice".to_string(),
                mac: "00:11:22:33:44:55".to_string(),
                source: "sysmon".to_string(),
            }],
        )
        .unwrap();

        let mut reader = ParquetRecordBatchReaderBuilder::try_new(File::open(path).unwrap())
            .unwrap()
            .build()
            .unwrap();
        let batch = reader.next().unwrap().unwrap();
        assert_eq!(
            batch.schema().field(0).data_type(),
            &DataType::Timestamp(
                arrow_schema::TimeUnit::Microsecond,
                Some(Arc::<str>::from("UTC")),
            )
        );
        let observed_at = batch
            .column(0)
            .as_any()
            .downcast_ref::<PrimitiveArray<TimestampMicrosecondType>>()
            .unwrap();
        assert_eq!(observed_at.value(0), expected_time);
    }

    #[test]
    fn identity_snapshot_accepts_only_private_source_addresses() {
        assert_eq!(identity_ip("10.1.2.3").as_deref(), Some("10.1.2.3"));
        assert_eq!(identity_ip("fd00::1234").as_deref(), Some("fd00::1234"));
        assert!(identity_ip("8.8.8.8").is_none());
        assert!(identity_ip("127.0.0.1").is_none());
        assert!(identity_ip("::").is_none());
    }
}
