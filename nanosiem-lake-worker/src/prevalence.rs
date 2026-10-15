// SPDX-License-Identifier: AGPL-3.0-or-later

//! Point prevalence serving from exact, tenant-assigned SlateDB checkpoints.

use crate::config::{
    LoadedImmutableFile, LoadedPrevalenceDailyHistory, LoadedPrevalenceSnapshotConfig,
};
use crate::executor::NativeExecutor;
use crate::planner::{
    external_processing_limits, trusted_iceberg_source, SourceManifest, TenantQueryConfig,
};
use futures::stream::{self, StreamExt};
use hmac::{Hmac, Mac};
use nanosiem_core::prevalence::PrevalenceExplorerCursor;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use slatedb::bytes::Bytes;
use slatedb::db_cache::foyer::{FoyerCache, FoyerCacheOptions};
use slatedb::db_cache::{DbCache, SplitCache};
use slatedb::object_store::local::LocalFileSystem;
use slatedb::object_store::ObjectStore;
use slatedb::{DbReader, DbReaderBuilder, DbReaderMode, MergeOperator, MergeOperatorError};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

const VALUE_VERSION: u8 = 1;
const VALUE_HEADER_BYTES: usize = 28;
const HOST_CAP: usize = 65;
const MAX_LOOKUPS: usize = 10_000;
const LOOKUP_CONCURRENCY: usize = 32;
const MAX_EXPLORER_PAGE_SIZE: u64 = 200;
const MAX_LEGACY_EXPLORER_OFFSET: u64 = 50_000;
const MAX_EXPORT_ROWS: u64 = 10_000;
// The API client defaults to a 30-second deadline. chDB is blocking once a
// native query starts, so a longer worker deadline would let an abandoned
// detail scan occupy its executor lane after the caller has already failed.
// Leave two seconds for admission/selection and publication inside the
// publisher's 10-second budget; ordinary search budgets remain unchanged.
const PREVALENCE_DETAIL_MAX_EXECUTION_SECONDS: u64 = 8;
// SlateDB otherwise creates a private 512-MiB block cache plus a 128-MiB
// metadata cache for every checkpoint reader. A normal four-window prevalence
// assignment therefore retained 2.5 GiB before a single lookup, and every
// Bronze shard also owns an independent UID ledger cache. Share the same total
// cache budget across all immutable prevalence checkpoints instead. SST IDs are
// content-unique and DbReader scopes externally supplied caches, so entries
// cannot alias between snapshots.
const PREVALENCE_BLOCK_CACHE_BYTES: u64 = 512 * 1024 * 1024;
const PREVALENCE_CACHE_SHARDS: usize = 16;

/// NAN-2710: the decoded-cache budget one prevalence service may hold. The
/// query worker keeps the historical 512 MiB block + 128 MiB metadata split;
/// a hosted Bronze publisher sizes it from `--prevalence-cache-bytes`, which
/// the platform derives in lockstep with the Bronze container memory limit.
/// Metadata is always a quarter of the block budget, as in the default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrevalenceCacheBudget {
    block_bytes: u64,
}

impl PrevalenceCacheBudget {
    pub const MIN_BLOCK_BYTES: u64 = 16 * 1024 * 1024;
    pub const MAX_BLOCK_BYTES: u64 = 8 * 1024 * 1024 * 1024;

    pub fn new(block_bytes: u64) -> std::result::Result<Self, String> {
        if !(Self::MIN_BLOCK_BYTES..=Self::MAX_BLOCK_BYTES).contains(&block_bytes) {
            return Err(format!(
                "prevalence cache budget must be between {} and {} bytes",
                Self::MIN_BLOCK_BYTES,
                Self::MAX_BLOCK_BYTES
            ));
        }
        Ok(Self { block_bytes })
    }

    pub fn block_bytes(self) -> u64 {
        self.block_bytes
    }

    pub fn meta_bytes(self) -> u64 {
        self.block_bytes / 4
    }
}

impl Default for PrevalenceCacheBudget {
    fn default() -> Self {
        Self {
            block_bytes: PREVALENCE_BLOCK_CACHE_BYTES,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PrevalenceError {
    #[error("prevalence request is invalid: {0}")]
    InvalidRequest(String),
    #[error("prevalence snapshot startup failed: {0}")]
    Startup(String),
    #[error("prevalence snapshot read failed")]
    Read,
    /// NAN-3766: a detail statement ran out of its execution budget.
    #[error("prevalence detail scan exceeded its time budget")]
    Timeout,
    #[error("prevalence value is invalid")]
    InvalidValue,
}

type Result<T> = std::result::Result<T, PrevalenceError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum ArtifactKind {
    Hash,
    Domain,
    Ip,
}

impl ArtifactKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Hash => "hash",
            Self::Domain => "domain",
            Self::Ip => "ip",
        }
    }
}

#[derive(Debug, Clone)]
struct ParsedArtifact {
    kind: ArtifactKind,
    entity: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrevalenceValue {
    hosts: BTreeSet<u64>,
    saturated: bool,
    is_private: bool,
    first_seen_us: i64,
    last_seen_us: i64,
    total_occurrences: u64,
}

#[derive(Debug, Serialize)]
pub struct PrevalenceResult {
    pub artifact: String,
    pub artifact_type: String,
    pub host_count: u64,
    pub host_count_saturated: bool,
    pub total_occurrences: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub is_rare: bool,
    pub prevalence_score: u8,
}

#[derive(Debug, Serialize)]
pub struct PrevalenceExplorerArtifact {
    pub artifact: String,
    pub artifact_type: String,
    pub host_count: u64,
    pub host_count_saturated: bool,
    pub total_occurrences: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub is_rare: bool,
    pub prevalence_score: u8,
    pub daily_counts: Vec<u64>,
    pub daily_start: String,
}

#[derive(Debug, Serialize)]
pub struct PrevalenceExplorerResult {
    pub artifacts: Vec<PrevalenceExplorerArtifact>,
    pub total: u64,
    pub limit: u64,
    pub offset: u64,
    pub has_more: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<PrevalenceExplorerCursor>,
    pub rarity_threshold: u64,
    pub rare_count: u64,
    pub new_count: u64,
    pub high_risk_asset_count: u64,
    pub counts_approximate: bool,
}

#[derive(Debug, Serialize)]
pub struct PrevalenceExportResult {
    pub results: Vec<PrevalenceResult>,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct PrevalenceDetailResult {
    pub artifact: String,
    pub artifact_type: String,
    pub top_hosts: Vec<DetailHost>,
    pub top_users: Vec<DetailUser>,
    pub source_types: Vec<DetailSource>,
    pub processes: Vec<DetailProcess>,
    pub top_file_names: Vec<DetailFileName>,
    pub network: Vec<DetailNetwork>,
    pub geo: Vec<serde_json::Value>,
    pub threat_intel: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
pub struct DetailHost {
    pub host: String,
    pub count: u64,
    pub last_seen: String,
}

#[derive(Debug, Serialize)]
pub struct DetailUser {
    pub user: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct DetailSource {
    pub source_type: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct DetailProcess {
    pub process_name: String,
    pub command_line: String,
    pub count: u64,
    pub is_wrapper: bool,
}

#[derive(Debug, Serialize)]
pub struct DetailFileName {
    pub file_name: String,
    pub count: u64,
}

#[derive(Debug, Serialize)]
pub struct DetailNetwork {
    pub dest_port: u16,
    pub protocol: String,
    pub count: u64,
}

#[derive(Debug, Deserialize)]
struct ExplorerPageRow {
    kind: String,
    entity: String,
    host_count: u64,
    saturated: u8,
    private: u8,
    first_seen: String,
    last_seen: String,
    total_occurrences: u64,
}

#[derive(Debug, Deserialize)]
struct ExplorerSummaryRow {
    total: u64,
    rare_count: u64,
    new_count: u64,
    high_risk_asset_count: u64,
}

#[derive(Debug, Deserialize)]
struct DailyCountRow {
    kind: String,
    entity: String,
    day: String,
    daily_count: u64,
}

#[derive(Debug, Deserialize)]
struct ExportRow {
    kind: String,
    entity: String,
    host_count: u64,
    private: u8,
    first_seen: String,
    last_seen: String,
    total_occurrences: u64,
}

#[derive(Debug, Deserialize)]
struct DetailRow {
    facet: String,
    name: String,
    meta: String,
    count: u64,
    last_seen: String,
}

struct PrevalenceSnapshot {
    window: String,
    checkpoint_id: uuid::Uuid,
    source_types: Vec<String>,
    rarity_threshold: u64,
    reader: Arc<DbReader>,
    scan_files: Vec<LoadedImmutableFile>,
    scan_source: String,
    explorer: Option<LoadedImmutableFile>,
    explorer_source: Option<String>,
    daily_history: Option<LoadedPrevalenceDailyHistory>,
    daily_history_source: Option<String>,
}

pub struct PrevalenceService {
    snapshots: BTreeMap<String, PrevalenceSnapshot>,
    secret: Arc<Vec<u8>>,
}

impl PrevalenceService {
    pub async fn load(
        configs: BTreeMap<String, LoadedPrevalenceSnapshotConfig>,
        secret: Vec<u8>,
    ) -> Result<Option<Self>> {
        Self::load_with_cache(configs, secret, PrevalenceCacheBudget::default()).await
    }

    pub async fn load_with_cache(
        configs: BTreeMap<String, LoadedPrevalenceSnapshotConfig>,
        secret: Vec<u8>,
        cache: PrevalenceCacheBudget,
    ) -> Result<Option<Self>> {
        if configs.is_empty() {
            return Ok(None);
        }
        if secret.len() < 32 {
            return Err(PrevalenceError::Startup(
                "HMAC key must contain at least 32 bytes".to_string(),
            ));
        }
        let object_store: Arc<dyn ObjectStore> = Arc::new(
            LocalFileSystem::new_with_prefix("/")
                .map_err(|error| PrevalenceError::Startup(error.to_string()))?,
        );
        let configured_snapshots = configs.len();
        let db_cache = shared_prevalence_db_cache(cache);
        tracing::info!(
            configured_snapshots,
            decoded_block_cache_bytes = cache.block_bytes(),
            decoded_meta_cache_bytes = cache.meta_bytes(),
            cache_shards = PREVALENCE_CACHE_SHARDS,
            "opening prevalence checkpoints with one shared decoded cache"
        );
        let mut readers = BTreeMap::<String, Arc<DbReader>>::new();
        let mut snapshots = BTreeMap::new();
        for (_, config) in configs {
            if config.object_store_url != "file:///" {
                return Err(PrevalenceError::Startup(
                    "this worker build currently requires a local SlateDB object store".to_string(),
                ));
            }
            let reader_key = format!("{}:{}", config.database_path, config.checkpoint_id);
            let reader = if let Some(reader) = readers.get(&reader_key) {
                reader.clone()
            } else {
                let reader = Arc::new(
                    DbReaderBuilder::new(config.database_path.clone(), object_store.clone())
                        .with_reader_mode(DbReaderMode::Checkpoint(config.checkpoint_id))
                        .with_merge_operator(Arc::new(PrevalenceMergeOperator))
                        .with_db_cache(db_cache.clone())
                        .build()
                        .await
                        .map_err(|error| PrevalenceError::Startup(error.to_string()))?,
                );
                readers.insert(reader_key, reader.clone());
                reader
            };
            let daily_history_source = config
                .daily_history
                .as_ref()
                .map(|history| scan_source(std::slice::from_ref(&history.scan_file)))
                .transpose()?;
            let explorer_source = config
                .explorer
                .as_ref()
                .map(|explorer| scan_source(std::slice::from_ref(explorer)))
                .transpose()?;
            snapshots.insert(
                config.snapshot_id.clone(),
                PrevalenceSnapshot {
                    window: config.window,
                    checkpoint_id: config.checkpoint_id,
                    source_types: config.source_types,
                    rarity_threshold: config.rarity_threshold,
                    reader,
                    scan_source: scan_source(&config.scan_files)?,
                    scan_files: config.scan_files,
                    explorer: config.explorer,
                    explorer_source,
                    daily_history: config.daily_history,
                    daily_history_source,
                },
            );
        }
        Ok(Some(Self {
            snapshots,
            secret: Arc::new(secret),
        }))
    }

    pub fn checkpoint_id(&self, snapshot_id: &str) -> Option<uuid::Uuid> {
        self.snapshots
            .get(snapshot_id)
            .map(|snapshot| snapshot.checkpoint_id)
    }

    /// Resolve the immutable tenant-assigned snapshot for a semantic window.
    /// Durable product jobs use this instead of accepting a caller-supplied
    /// checkpoint or object path.
    pub fn snapshot_id_for_window(&self, window: &str) -> Option<&str> {
        self.snapshots
            .iter()
            .find(|(_, snapshot)| snapshot.window == window)
            .map(|(snapshot_id, _)| snapshot_id.as_str())
    }

    pub async fn lookup(
        &self,
        snapshot_id: &str,
        window: &str,
        artifacts: &[String],
        deny_source_types: &[String],
    ) -> Result<Vec<PrevalenceResult>> {
        let snapshot = self.snapshots.get(snapshot_id).ok_or_else(|| {
            PrevalenceError::InvalidRequest(
                "prevalence snapshot is not assigned to this tenant".to_string(),
            )
        })?;
        if window != snapshot.window {
            return Err(PrevalenceError::InvalidRequest(
                "prevalence window does not match the immutable snapshot".to_string(),
            ));
        }
        if artifacts.len() > MAX_LOOKUPS {
            return Err(PrevalenceError::InvalidRequest(
                "prevalence lookup exceeds 10000 artifacts".to_string(),
            ));
        }
        let denied = normalize_sources(deny_source_types)?;
        let scopes = snapshot
            .source_types
            .iter()
            .filter(|source| !denied.contains(source.as_str()))
            .cloned()
            .collect::<Vec<_>>();
        if scopes.is_empty() || artifacts.is_empty() {
            return Ok(Vec::new());
        }
        let mut parsed = Vec::new();
        let mut seen = BTreeSet::new();
        for artifact in artifacts {
            if let Some(item) = parse_artifact(artifact) {
                if seen.insert((item.kind, item.entity.clone())) {
                    parsed.push(item);
                }
            }
        }
        let mut jobs = Vec::with_capacity(parsed.len().saturating_mul(scopes.len()));
        for artifact in &parsed {
            for scope in &scopes {
                jobs.push((
                    artifact.kind,
                    artifact.entity.clone(),
                    prevalence_key(&self.secret, artifact.kind, scope, &artifact.entity)?,
                ));
            }
        }
        let reader = snapshot.reader.clone();
        let reads = stream::iter(jobs)
            .map(|(kind, entity, key)| {
                let reader = reader.clone();
                async move {
                    reader
                        .get(key)
                        .await
                        .map(|value| (kind, entity, value))
                        .map_err(|_| PrevalenceError::Read)
                }
            })
            .buffer_unordered(LOOKUP_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        let mut merged = BTreeMap::<(ArtifactKind, String), PrevalenceValue>::new();
        for read in reads {
            let (kind, entity, value) = read?;
            let Some(value) = value else {
                continue;
            };
            let incoming = decode_value(&value)?;
            let key = (kind, entity);
            let combined = match merged.remove(&key) {
                Some(existing) => merge_decoded(existing, incoming)?,
                None => incoming,
            };
            merged.insert(key, combined);
        }
        let mut results = Vec::new();
        for artifact in parsed {
            let Some(value) = merged.remove(&(artifact.kind, artifact.entity.clone())) else {
                continue;
            };
            let host_count = value.hosts.len() as u64;
            results.push(PrevalenceResult {
                artifact: artifact.entity.clone(),
                artifact_type: artifact_type(artifact.kind, &artifact.entity, value.is_private),
                host_count,
                host_count_saturated: value.saturated,
                total_occurrences: value.total_occurrences,
                first_seen: timestamp(value.first_seen_us)?,
                last_seen: timestamp(value.last_seen_us)?,
                is_rare: !value.saturated && host_count < snapshot.rarity_threshold,
                prevalence_score: prevalence_score_with_saturation(
                    host_count,
                    snapshot.rarity_threshold,
                    value.saturated,
                ),
            });
        }
        Ok(results)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn explore(
        &self,
        executor: &NativeExecutor,
        tenant: &TenantQueryConfig,
        manifest: &SourceManifest,
        snapshot_id: &str,
        window: &str,
        artifact_kind: Option<&str>,
        risk_level: Option<&str>,
        first_seen_since: Option<&str>,
        search: Option<&str>,
        limit: u64,
        offset: u64,
        cursor: Option<&PrevalenceExplorerCursor>,
        deny_source_types: &[String],
        rarity_threshold: Option<u64>,
    ) -> Result<PrevalenceExplorerResult> {
        let snapshot = self.snapshot(snapshot_id, window)?;
        // NAN-3451: the caller's Settings threshold, when it sends one, rules
        // "rare"; the snapshot's configured threshold is the default.
        let threshold = match rarity_threshold {
            None => snapshot.rarity_threshold,
            Some(value) if (1..=10_000).contains(&value) => value,
            Some(_) => {
                return Err(PrevalenceError::InvalidRequest(
                    "prevalence rarity threshold must be between 1 and 10000".to_string(),
                ))
            }
        };
        verify_scan_files(snapshot)?;
        if limit == 0
            || limit > MAX_EXPLORER_PAGE_SIZE
            || (cursor.is_none() && offset.saturating_add(limit) > MAX_LEGACY_EXPLORER_OFFSET)
            || (cursor.is_some() && offset != 0)
        {
            return Err(PrevalenceError::InvalidRequest(
                "prevalence explorer pagination exceeds its bound".to_string(),
            ));
        }
        if !matches!(artifact_kind, None | Some("hash" | "domain" | "ip"))
            || !matches!(risk_level, None | Some("rare" | "new"))
            || search.is_some_and(|value| value.len() > 512 || value.chars().any(char::is_control))
        {
            return Err(PrevalenceError::InvalidRequest(
                "prevalence explorer filter is invalid".to_string(),
            ));
        }
        if let Some(value) = first_seen_since {
            chrono::DateTime::parse_from_rfc3339(value).map_err(|_| {
                PrevalenceError::InvalidRequest(
                    "prevalence first-seen boundary must be RFC3339".to_string(),
                )
            })?;
        }
        // NAN-3802: accept the legacy `YYYY-MM-DD HH:MM:SS.ffffff` cursor too,
        // and seek on its RFC 3339 form.
        let cursor = cursor
            .map(|cursor| {
                cursor.validated().ok_or_else(|| {
                    PrevalenceError::InvalidRequest(
                        "prevalence explorer cursor is invalid".to_string(),
                    )
                })
            })
            .transpose()?;
        let cursor = cursor.as_ref();
        let scopes = self.allowed_scopes(snapshot, deny_source_types)?;
        if scopes.is_empty() {
            return Ok(empty_explorer(limit, offset, threshold));
        }
        let materialized_explorer = if scopes == snapshot.source_types {
            snapshot
                .explorer
                .as_ref()
                .zip(snapshot.explorer_source.as_ref())
        } else {
            None
        };
        let (mut predicates, mut params, source) =
            if let Some((explorer, explorer_source)) = materialized_explorer {
                verify_immutable_file(explorer)?;
                (Vec::new(), Vec::new(), explorer_source.clone())
            } else {
                let (source_filter, params) = source_filter(&scopes);
                (vec![source_filter], params, snapshot.scan_source.clone())
            };
        params.extend([
            ("source".to_string(), source),
            (
                "threshold".to_string(),
                threshold.to_string(),
            ),
            ("limit".to_string(), limit.saturating_add(1).to_string()),
            ("offset".to_string(), offset.to_string()),
        ]);
        if let Some(value) = artifact_kind {
            predicates.push("kind = {artifact_type:String}".to_string());
            params.push(("artifact_type".to_string(), value.to_string()));
        }
        if let Some(value) = search {
            predicates.push("positionCaseInsensitiveUTF8(entity, {search:String}) > 0".to_string());
            params.push(("search".to_string(), value.to_string()));
        }
        let mut filtered = Vec::new();
        if risk_level == Some("rare") {
            filtered.push("host_count < {threshold:UInt64} AND saturated = 0");
        } else if risk_level == Some("new") {
            filtered.push("first_seen >= now64(6) - INTERVAL 24 HOUR");
        }
        if let Some(value) = first_seen_since {
            filtered.push("first_seen >= parseDateTime64BestEffort({first_seen_since:String}, 6)");
            params.push(("first_seen_since".to_string(), value.to_string()));
        }
        let filtered_sql = if filtered.is_empty() {
            String::new()
        } else {
            format!(" AND {}", filtered.join(" AND "))
        };
        let cursor_sql = if let Some(cursor) = cursor {
            params.extend([
                ("cursor_last_seen".to_string(), cursor.last_seen.clone()),
                ("cursor_kind".to_string(), cursor.kind.clone()),
                ("cursor_artifact".to_string(), cursor.artifact.clone()),
            ]);
            " WHERE last_seen < parseDateTime64BestEffort({cursor_last_seen:String}, 6) \
               OR (last_seen = parseDateTime64BestEffort({cursor_last_seen:String}, 6) \
                   AND (kind > {cursor_kind:String} \
                        OR (kind = {cursor_kind:String} AND entity > {cursor_artifact:String})))"
        } else {
            ""
        };
        let (external_threshold, temporary_disk_bytes) =
            external_processing_limits(tenant.max_memory_bytes);
        let source_where = if predicates.is_empty() {
            "1 = 1".to_string()
        } else {
            predicates.join(" AND ")
        };
        let aggregated_sql = explorer_aggregate_sql(materialized_explorer.is_some(), &source_where);
        // Keep the exact whole-snapshot counters separate from ordered page
        // selection. Combining window counters with ORDER BY retained every
        // expanded entity column until the sort completed, which made a
        // compressed 130 MiB explorer exceed the unchanged 1.75 GiB query
        // budget. The summary aggregate streams in constant memory, while the
        // page query can use ClickHouse's bounded top-N sort.
        let summary_sql = format!(
            "WITH aggregated AS (\
               {}\
             ) SELECT count() AS total, \
                    countIf(host_count < {{threshold:UInt64}} AND saturated = 0) AS rare_count, \
                    countIf(first_seen >= now64(6) - INTERVAL 24 HOUR) AS new_count, \
                    countIf(host_count < {{threshold:UInt64}} AND saturated = 0 \
                            AND last_seen >= now64(6) - INTERVAL 24 HOUR) AS high_risk_asset_count \
             FROM aggregated WHERE 1 = 1{} \
             SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
                      max_memory_usage={}, use_query_cache=0",
            aggregated_sql,
            filtered_sql,
            tenant.threads,
            tenant.max_execution_seconds,
            tenant.max_query_bytes,
            tenant.max_memory_bytes,
        );
        let page_sql = format!(
            "WITH aggregated AS (\
               {}\
             ), filtered AS (SELECT * FROM aggregated WHERE 1 = 1{}) \
             SELECT kind, entity, host_count, saturated, private, first_seen, last_seen, \
                    total_occurrences \
             FROM filtered{} ORDER BY last_seen DESC, kind ASC, entity ASC \
             LIMIT {{limit:UInt64}} OFFSET {{offset:UInt64}} \
             SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
                      max_memory_usage={}, max_bytes_before_external_sort={}, \
                      max_bytes_before_external_group_by={}, \
                      max_temporary_data_on_disk_size_for_query={}, use_query_cache=0",
            aggregated_sql,
            filtered_sql,
            cursor_sql,
            tenant.threads,
            tenant.max_execution_seconds,
            tenant.max_query_bytes,
            tenant.max_memory_bytes,
            external_threshold,
            external_threshold,
            temporary_disk_bytes,
        );
        let summary_started = Instant::now();
        let summary_output = executor
            .execute_sql(summary_sql, params.clone())
            .await
            .map_err(|error| {
                tracing::warn!(%error, "prevalence explorer summary query failed");
                PrevalenceError::Read
            })?;
        tracing::info!(
            phase = "summary",
            materialized = materialized_explorer.is_some(),
            wall_ms = summary_started.elapsed().as_secs_f64() * 1_000.0,
            engine_ms = summary_output.elapsed.as_secs_f64() * 1_000.0,
            storage_rows = summary_output.storage_rows_read,
            storage_bytes = summary_output.storage_bytes_read,
            "prevalence explorer phase completed"
        );
        let summary_rows = decode_json_each_row::<ExplorerSummaryRow>(&summary_output.data)?;
        let summary = summary_rows
            .into_iter()
            .next()
            .ok_or(PrevalenceError::InvalidValue)?;

        let page_started = Instant::now();
        let page_output = executor
            .execute_sql(page_sql, params)
            .await
            .map_err(|error| {
                tracing::warn!(%error, "prevalence explorer page query failed");
                PrevalenceError::Read
            })?;
        tracing::info!(
            phase = "page",
            materialized = materialized_explorer.is_some(),
            wall_ms = page_started.elapsed().as_secs_f64() * 1_000.0,
            engine_ms = page_output.elapsed.as_secs_f64() * 1_000.0,
            storage_rows = page_output.storage_rows_read,
            storage_bytes = page_output.storage_bytes_read,
            "prevalence explorer phase completed"
        );
        let mut rows = decode_json_each_row::<ExplorerPageRow>(&page_output.data)?;
        let has_more = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let next_cursor = has_more.then(|| {
            let row = rows
                .last()
                .expect("has_more prevalence page has at least one retained row");
            PrevalenceExplorerCursor {
                last_seen: chdb_timestamp(&row.last_seen),
                kind: row.kind.clone(),
                artifact: row.entity.clone(),
            }
        });
        let mut artifacts = rows
            .into_iter()
            .map(|row| PrevalenceExplorerArtifact {
                artifact_type: artifact_type_from_text(&row.kind, &row.entity, row.private != 0),
                artifact: row.entity,
                host_count: row.host_count,
                host_count_saturated: row.saturated != 0,
                total_occurrences: row.total_occurrences,
                first_seen: chdb_timestamp(&row.first_seen),
                last_seen: chdb_timestamp(&row.last_seen),
                is_rare: row.saturated == 0 && row.host_count < threshold,
                prevalence_score: prevalence_score_with_saturation(
                    row.host_count,
                    threshold,
                    row.saturated != 0,
                ),
                daily_counts: Vec::new(),
                daily_start: String::new(),
            })
            .collect::<Vec<_>>();
        self.attach_daily_history(
            executor,
            tenant,
            manifest,
            snapshot,
            &scopes,
            &mut artifacts,
        )
        .await?;
        Ok(PrevalenceExplorerResult {
            has_more,
            next_cursor,
            artifacts,
            total: summary.total,
            limit,
            offset,
            rarity_threshold: threshold,
            rare_count: summary.rare_count,
            new_count: summary.new_count,
            high_risk_asset_count: summary.high_risk_asset_count,
            counts_approximate: false,
        })
    }

    /// Attach the fixed 30-day heatmap from the exact event generation that
    /// owns the prevalence snapshot. New generations read a small immutable
    /// daily derivative. Older generations retain the exact event-scan fallback
    /// so a rolling upgrade never renders real activity as "no activity".
    async fn attach_daily_history(
        &self,
        executor: &NativeExecutor,
        tenant: &TenantQueryConfig,
        manifest: &SourceManifest,
        snapshot: &PrevalenceSnapshot,
        scopes: &[String],
        artifacts: &mut [PrevalenceExplorerArtifact],
    ) -> Result<()> {
        const DAYS: i64 = 30;
        if artifacts.is_empty() {
            return Ok(());
        }
        let (rows, start) = if let (Some(history), Some(source)) =
            (&snapshot.daily_history, &snapshot.daily_history_source)
        {
            verify_immutable_file(&history.scan_file)?;
            let (source_scope, mut params) = source_filter(scopes);
            params.push(("daily_source".to_string(), source.clone()));
            let mut predicates = Vec::with_capacity(artifacts.len());
            for (index, artifact) in artifacts.iter().enumerate() {
                let parsed =
                    parse_artifact(&artifact.artifact).ok_or(PrevalenceError::InvalidValue)?;
                let kind = format!("daily_kind_{index}");
                let entity = format!("daily_entity_{index}");
                predicates.push(format!(
                    "(kind = {{{kind}:String}} AND entity = {{{entity}:String}})"
                ));
                params.push((kind, parsed.kind.as_str().to_string()));
                params.push((entity, parsed.entity));
            }
            let sql = format!(
                "SELECT kind, entity, toString(day) AS day, sum(daily_count) AS daily_count \
                 FROM file({{daily_source:String}}, Parquet) \
                 WHERE {source_scope} AND ({}) GROUP BY kind, entity, day \
                 ORDER BY kind, entity, day \
                 SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
                          max_memory_usage={}, use_query_cache=0",
                predicates.join(" OR "),
                tenant.threads,
                tenant.max_execution_seconds,
                history.scan_file.bytes,
                tenant.max_memory_bytes,
            );
            let history_started = Instant::now();
            let output = executor.execute_sql(sql, params).await.map_err(|error| {
                tracing::warn!(%error, "materialized prevalence daily-history query failed");
                PrevalenceError::Read
            })?;
            tracing::info!(
                phase = "daily_history",
                wall_ms = history_started.elapsed().as_secs_f64() * 1_000.0,
                engine_ms = output.elapsed.as_secs_f64() * 1_000.0,
                storage_rows = output.storage_rows_read,
                storage_bytes = output.storage_bytes_read,
                "prevalence explorer phase completed"
            );
            (
                decode_json_each_row::<DailyCountRow>(&output.data)?,
                history.daily_start,
            )
        } else {
            let (source, mut params) = trusted_iceberg_source(tenant).map_err(|_| {
                PrevalenceError::InvalidRequest("event snapshot is invalid".to_string())
            })?;
            let (source_scope, source_params) = source_filter(scopes);
            params.extend(source_params);
            let mut counts = Vec::with_capacity(artifacts.len());
            let mut tuples = Vec::with_capacity(artifacts.len());
            for (index, artifact) in artifacts.iter().enumerate() {
                let parsed =
                    parse_artifact(&artifact.artifact).ok_or(PrevalenceError::InvalidValue)?;
                let parameter = format!("daily_artifact_{index}");
                let predicate = artifact_filter(manifest, parsed.kind)?
                    .replace("{artifact:String}", &format!("{{{parameter}:String}}"));
                let alias = format!("daily_count_{index}");
                counts.push(format!("countIf({predicate}) AS {alias}"));
                tuples.push(format!(
                    "tuple('{}', {{{parameter}:String}}, toUInt64({alias}))",
                    parsed.kind.as_str(),
                ));
                params.push((parameter, parsed.entity));
            }
            let allowed_sources = source_scope
                .trim_start_matches("scope IN (")
                .trim_end_matches(')');
            let sql = format!(
                "WITH daily AS (\
                   SELECT toDate(time) AS day, {} FROM {source} \
                   WHERE time >= toStartOfDay(now64(6)) - INTERVAL 29 DAY \
                     AND tupleElement(metadata, 'log_source') IN ({allowed_sources}) \
                   GROUP BY day\
                 ), expanded AS (\
                   SELECT day, arrayJoin([{}]) AS item FROM daily\
                 ) SELECT tupleElement(item, 1) AS kind, tupleElement(item, 2) AS entity, \
                          toString(day) AS day, tupleElement(item, 3) AS daily_count \
                   FROM expanded WHERE daily_count > 0 ORDER BY kind, entity, day \
                   SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
                            max_memory_usage={}, use_query_cache=0",
                counts.join(", "),
                tuples.join(", "),
                tenant.threads,
                tenant.max_execution_seconds,
                tenant.max_query_bytes,
                tenant.max_memory_bytes,
            );
            let output = executor.execute_sql(sql, params).await.map_err(|error| {
                tracing::warn!(%error, "fallback prevalence daily-history query failed");
                PrevalenceError::Read
            })?;
            (
                decode_json_each_row::<DailyCountRow>(&output.data)?,
                chrono::Utc::now().date_naive() - chrono::Duration::days(DAYS - 1),
            )
        };
        let mut sparse = BTreeMap::<(String, String), BTreeMap<String, u64>>::new();
        for row in rows {
            if !matches!(row.kind.as_str(), "hash" | "domain" | "ip") {
                return Err(PrevalenceError::InvalidValue);
            }
            sparse
                .entry((row.kind, row.entity))
                .or_default()
                .insert(row.day, row.daily_count);
        }
        for artifact in artifacts {
            let parsed = parse_artifact(&artifact.artifact).ok_or(PrevalenceError::InvalidValue)?;
            let values = sparse
                .remove(&(parsed.kind.as_str().to_string(), parsed.entity))
                .unwrap_or_default();
            artifact.daily_start = start.format("%Y-%m-%d").to_string();
            artifact.daily_counts = (0..DAYS)
                .map(|offset| {
                    values
                        .get(
                            &(start + chrono::Duration::days(offset))
                                .format("%Y-%m-%d")
                                .to_string(),
                        )
                        .copied()
                        .unwrap_or(0)
                })
                .collect();
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn export(
        &self,
        executor: &NativeExecutor,
        tenant: &TenantQueryConfig,
        snapshot_id: &str,
        window: &str,
        artifact_kind: Option<&str>,
        max_prevalence: u64,
        limit: u64,
        deny_source_types: &[String],
    ) -> Result<PrevalenceExportResult> {
        let snapshot = self.snapshot(snapshot_id, window)?;
        verify_scan_files(snapshot)?;
        if limit == 0
            || limit > MAX_EXPORT_ROWS
            || !matches!(artifact_kind, None | Some("hash" | "domain" | "ip"))
        {
            return Err(PrevalenceError::InvalidRequest(
                "prevalence export bound or artifact type is invalid".to_string(),
            ));
        }
        let scopes = self.allowed_scopes(snapshot, deny_source_types)?;
        if scopes.is_empty() {
            return Ok(PrevalenceExportResult {
                results: Vec::new(),
                truncated: false,
            });
        }
        let (source_filter, mut params) = source_filter(&scopes);
        let mut predicates = vec![source_filter];
        if let Some(value) = artifact_kind {
            predicates.push("kind = {artifact_type:String}".to_string());
            params.push(("artifact_type".to_string(), value.to_string()));
        }
        params.extend([
            ("source".to_string(), snapshot.scan_source.clone()),
            (
                "threshold".to_string(),
                snapshot.rarity_threshold.to_string(),
            ),
            ("max_prevalence".to_string(), max_prevalence.to_string()),
            ("limit".to_string(), (limit + 1).to_string()),
        ]);
        let (external_threshold, temporary_disk_bytes) =
            external_processing_limits(tenant.max_memory_bytes);
        let sql = format!(
            "WITH aggregated AS (\
               SELECT kind, entity, uniqExactArray(host_fingerprints) AS host_count, \
                      max(toUInt8(host_count_saturated)) AS saturated, max(toUInt8(is_private)) AS private, \
                      min(first_seen) AS first_seen, max(last_seen) AS last_seen, \
                      sum(total_occurrences) AS total_occurrences \
               FROM file({{source:String}}, Parquet) WHERE {} GROUP BY kind, entity\
             ) SELECT kind, entity, host_count, private, first_seen, last_seen, total_occurrences \
             FROM aggregated WHERE saturated = 0 AND host_count < {{threshold:UInt64}} \
                  AND host_count <= {{max_prevalence:UInt64}} \
             ORDER BY host_count ASC, last_seen DESC, entity ASC LIMIT {{limit:UInt64}} \
             SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
                      max_memory_usage={}, max_bytes_before_external_sort={}, \
                      max_bytes_before_external_group_by={}, \
                      max_temporary_data_on_disk_size_for_query={}, use_query_cache=0",
            predicates.join(" AND "),
            tenant.threads,
            tenant.max_execution_seconds,
            tenant.max_query_bytes,
            tenant.max_memory_bytes,
            external_threshold,
            external_threshold,
            temporary_disk_bytes,
        );
        let output = executor
            .execute_sql(sql, params)
            .await
            .map_err(|_| PrevalenceError::Read)?;
        let mut rows = decode_json_each_row::<ExportRow>(&output.data)?;
        let truncated = rows.len() > limit as usize;
        rows.truncate(limit as usize);
        let results = rows
            .into_iter()
            .map(|row| PrevalenceResult {
                artifact_type: artifact_type_from_text(&row.kind, &row.entity, row.private != 0),
                artifact: row.entity,
                host_count: row.host_count,
                host_count_saturated: false,
                total_occurrences: row.total_occurrences,
                first_seen: chdb_timestamp(&row.first_seen),
                last_seen: chdb_timestamp(&row.last_seen),
                is_rare: true,
                prevalence_score: prevalence_score(row.host_count, snapshot.rarity_threshold),
            })
            .collect();
        Ok(PrevalenceExportResult { results, truncated })
    }

    /// Write the complete filtered export directly from chDB to a local
    /// Parquet spool. The durable runner subsequently re-chunks that file into
    /// manifest-fenced result pages, so neither chDB's JSON response nor Rust
    /// needs to hold the complete export in memory.
    #[allow(clippy::too_many_arguments)]
    pub async fn export_to_parquet(
        &self,
        executor: &NativeExecutor,
        tenant: &TenantQueryConfig,
        snapshot_id: &str,
        window: &str,
        artifact_kind: Option<&str>,
        max_prevalence: u64,
        deny_source_types: &[String],
        output: &Path,
    ) -> Result<crate::native::NativeQueryOutput> {
        let snapshot = self.snapshot(snapshot_id, window)?;
        verify_scan_files(snapshot)?;
        if !matches!(artifact_kind, None | Some("hash" | "domain" | "ip"))
            || output.as_os_str().is_empty()
            || output.exists()
            || output.parent().is_none_or(|parent| !parent.is_dir())
        {
            return Err(PrevalenceError::InvalidRequest(
                "durable prevalence export target or artifact type is invalid".to_string(),
            ));
        }
        let output = output.to_str().ok_or_else(|| {
            PrevalenceError::InvalidRequest(
                "durable prevalence export target is not UTF-8".to_string(),
            )
        })?;
        let scopes = self.allowed_scopes(snapshot, deny_source_types)?;
        let mut params = vec![
            ("output".to_string(), output.to_string()),
            ("source".to_string(), snapshot.scan_source.clone()),
            (
                "threshold".to_string(),
                snapshot.rarity_threshold.max(1).to_string(),
            ),
            ("max_prevalence".to_string(), max_prevalence.to_string()),
        ];
        let mut predicates = if scopes.is_empty() {
            vec!["0".to_string()]
        } else {
            let (filter, filter_params) = source_filter(&scopes);
            params.extend(filter_params);
            vec![filter]
        };
        if let Some(value) = artifact_kind {
            predicates.push("kind = {artifact_type:String}".to_string());
            params.push(("artifact_type".to_string(), value.to_string()));
        }
        let (external_threshold, temporary_disk_bytes) =
            external_processing_limits(tenant.max_memory_bytes);
        let sql = format!(
            "INSERT INTO FUNCTION file({{output:String}}, Parquet) \
             WITH aggregated AS (\
               SELECT kind, entity, uniqExactArray(host_fingerprints) AS host_count, \
                      max(toUInt8(host_count_saturated)) AS saturated, max(toUInt8(is_private)) AS private, \
                      min(first_seen) AS first_seen, max(last_seen) AS last_seen, \
                      sum(total_occurrences) AS total_occurrences \
               FROM file({{source:String}}, Parquet) WHERE {} GROUP BY kind, entity\
             ), filtered AS (\
               SELECT * FROM aggregated \
               WHERE saturated = 0 AND host_count < {{threshold:UInt64}} \
                 AND host_count <= {{max_prevalence:UInt64}}\
             ) SELECT entity AS artifact, \
                      multiIf(\
                        kind = 'hash' AND length(entity) = 32, 'hash_md5', \
                        kind = 'hash', 'hash_sha256', \
                        kind = 'domain' AND length(splitByChar('.', entity)) > 2, 'subdomain', \
                        kind = 'domain', 'domain', \
                        private != 0, 'ip_address_private', 'ip_address'\
                      ) AS artifact_type, \
                      host_count, total_occurrences, first_seen, last_seen, \
                      CAST(1 AS Bool) AS is_rare, \
                      toUInt8(round(least(20.0, toFloat64(host_count) / \
                          toFloat64({{threshold:UInt64}}) * 20.0))) AS prevalence_score \
               FROM filtered ORDER BY host_count ASC, last_seen DESC, artifact ASC \
             SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
                      max_memory_usage={}, max_bytes_before_external_sort={}, \
                      max_bytes_before_external_group_by={}, \
                      max_temporary_data_on_disk_size_for_query={}, \
                      output_format_parquet_compression_method='zstd', \
                      output_format_compression_level=6, \
                      output_format_parquet_write_bloom_filter=1, \
                      output_format_parquet_write_page_index=1, use_query_cache=0",
            predicates.join(" AND "),
            tenant.threads,
            tenant.max_execution_seconds,
            tenant.max_query_bytes,
            tenant.max_memory_bytes,
            external_threshold,
            external_threshold,
            temporary_disk_bytes,
        );
        let result = executor.execute_sql(sql, params).await.map_err(|error| {
            tracing::warn!(%error, "durable prevalence export query failed");
            PrevalenceError::Read
        })?;
        if !output_file_is_parquet(Path::new(output)) {
            return Err(PrevalenceError::Read);
        }
        Ok(result)
    }

    pub async fn detail(
        &self,
        executor: &NativeExecutor,
        tenant: &TenantQueryConfig,
        manifest: &SourceManifest,
        snapshot_id: &str,
        window: &str,
        artifact: &str,
        deny_source_types: &[String],
    ) -> Result<PrevalenceDetailResult> {
        let snapshot = self.snapshot(snapshot_id, window)?;
        let parsed = parse_artifact(artifact).ok_or_else(|| {
            PrevalenceError::InvalidRequest(
                "artifact is not a supported hash, IP address, or domain".to_string(),
            )
        })?;
        let scopes = self.allowed_scopes(snapshot, deny_source_types)?;
        let result_type = artifact_type(
            parsed.kind,
            &parsed.entity,
            parsed.kind == ArtifactKind::Ip && ip_is_private(&parsed.entity),
        );
        if scopes.is_empty() {
            return Ok(empty_detail(parsed.entity, result_type));
        }
        let (source, mut params) = trusted_iceberg_source(tenant).map_err(|_| {
            PrevalenceError::InvalidRequest("event snapshot is invalid".to_string())
        })?;
        let (source_scope, source_params) = source_filter(&scopes);
        params.extend(source_params);
        params.push(("artifact".to_string(), parsed.entity.clone()));
        params.push((
            "window_seconds".to_string(),
            match window {
                "1h" => 3_600,
                "24h" => 86_400,
                "7d" => 604_800,
                "30d" => 2_592_000,
                _ => {
                    return Err(PrevalenceError::InvalidRequest(
                        "window is invalid".to_string(),
                    ));
                }
            }
            .to_string(),
        ));
        let artifact_filter = artifact_filter(manifest, parsed.kind)?;
        read_detail(executor, tenant, manifest, format!("(SELECT * FROM {source} WHERE time >= now64(6) - toIntervalSecond({{window_seconds:UInt64}}))"), params, artifact_filter,
            format!("tupleElement(metadata, 'log_source') IN ({})", source_scope.trim_start_matches("scope IN (").trim_end_matches(')')),
            parsed, result_type).await
    }

    fn snapshot(&self, snapshot_id: &str, window: &str) -> Result<&PrevalenceSnapshot> {
        let snapshot = self.snapshots.get(snapshot_id).ok_or_else(|| {
            PrevalenceError::InvalidRequest(
                "prevalence snapshot is not assigned to this tenant".to_string(),
            )
        })?;
        if snapshot.window != window {
            return Err(PrevalenceError::InvalidRequest(
                "prevalence window does not match the immutable snapshot".to_string(),
            ));
        }
        Ok(snapshot)
    }

    fn allowed_scopes(
        &self,
        snapshot: &PrevalenceSnapshot,
        deny_source_types: &[String],
    ) -> Result<Vec<String>> {
        let denied = normalize_sources(deny_source_types)?;
        Ok(snapshot
            .source_types
            .iter()
            .filter(|source| !denied.contains(source.as_str()))
            .cloned()
            .collect())
    }
}

fn shared_prevalence_db_cache(cache: PrevalenceCacheBudget) -> Arc<dyn DbCache> {
    let block_cache: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
        max_capacity: cache.block_bytes(),
        shards: PREVALENCE_CACHE_SHARDS,
    }));
    let meta_cache: Arc<dyn DbCache> = Arc::new(FoyerCache::new_with_opts(FoyerCacheOptions {
        max_capacity: cache.meta_bytes(),
        shards: PREVALENCE_CACHE_SHARDS,
    }));
    Arc::new(
        SplitCache::new()
            .with_block_cache(Some(block_cache))
            .with_meta_cache(Some(meta_cache))
            .build(),
    )
}

fn scan_source(files: &[LoadedImmutableFile]) -> Result<String> {
    let first = files.first().ok_or_else(|| {
        PrevalenceError::Startup("prevalence scan has no immutable files".to_string())
    })?;
    let parent = first.path.parent().ok_or_else(|| {
        PrevalenceError::Startup("prevalence scan file has no parent".to_string())
    })?;
    if !parent.is_absolute() || files.iter().any(|file| file.path.parent() != Some(parent)) {
        return Err(PrevalenceError::Startup(
            "prevalence scan files must share one absolute directory".to_string(),
        ));
    }
    let mut names = Vec::with_capacity(files.len());
    for file in files {
        let name = file
            .path
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or_else(|| {
                PrevalenceError::Startup("prevalence scan filename is invalid".to_string())
            })?;
        if name.chars().any(|character| "*?{}[],".contains(character)) {
            return Err(PrevalenceError::Startup(
                "prevalence scan filename contains a glob metacharacter".to_string(),
            ));
        }
        names.push(name.to_string());
    }
    names.sort();
    let parent = parent.to_str().ok_or_else(|| {
        PrevalenceError::Startup("prevalence scan directory is not UTF-8".to_string())
    })?;
    if names.len() == 1 {
        Ok(format!("{parent}/{}", names[0]))
    } else {
        Ok(format!("{parent}/{{{}}}", names.join(",")))
    }
}

fn verify_scan_files(snapshot: &PrevalenceSnapshot) -> Result<()> {
    for file in &snapshot.scan_files {
        verify_immutable_file(file)?;
    }
    Ok(())
}

fn verify_immutable_file(file: &LoadedImmutableFile) -> Result<()> {
    let metadata = std::fs::metadata(&file.path).map_err(|_| PrevalenceError::Read)?;
    if metadata.len() != file.bytes
        || metadata.modified().map_err(|_| PrevalenceError::Read)? != file.modified
    {
        return Err(PrevalenceError::Read);
    }
    Ok(())
}

fn source_filter(scopes: &[String]) -> (String, Vec<(String, String)>) {
    let mut placeholders = Vec::with_capacity(scopes.len());
    let mut params = Vec::with_capacity(scopes.len());
    for (index, scope) in scopes.iter().enumerate() {
        let name = format!("allowed_source_{index}");
        placeholders.push(format!("{{{name}:String}}"));
        params.push((name, scope.clone()));
    }
    (format!("scope IN ({})", placeholders.join(",")), params)
}

fn explorer_aggregate_sql(materialized: bool, source_where: &str) -> String {
    if materialized {
        format!(
            "SELECT kind, entity, host_count, saturated, private, first_seen, last_seen, \
                    total_occurrences FROM file({{source:String}}, Parquet) WHERE {source_where}"
        )
    } else {
        // `host_fingerprints` is already an Array(UInt64). The Array aggregate
        // combinator maintains the exact set directly and avoids the nested
        // groupArray/arrayFlatten copy. This fallback is reserved for exact
        // source-exclusion requests; the default path consumes the immutable
        // cross-source projection above.
        format!(
            "SELECT kind, entity, uniqExactArray(host_fingerprints) AS host_count, \
                    max(toUInt8(host_count_saturated)) AS saturated, \
                    max(toUInt8(is_private)) AS private, \
                    min(first_seen) AS first_seen, max(last_seen) AS last_seen, \
                    sum(total_occurrences) AS total_occurrences \
             FROM file({{source:String}}, Parquet) WHERE {source_where} GROUP BY kind, entity"
        )
    }
}

fn decode_json_each_row<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<Vec<T>> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).map_err(|_| PrevalenceError::InvalidValue))
        .collect()
}

fn empty_explorer(limit: u64, offset: u64, threshold: u64) -> PrevalenceExplorerResult {
    PrevalenceExplorerResult {
        artifacts: Vec::new(),
        total: 0,
        limit,
        offset,
        has_more: false,
        next_cursor: None,
        rarity_threshold: threshold,
        rare_count: 0,
        new_count: 0,
        high_risk_asset_count: 0,
        counts_approximate: false,
    }
}

fn empty_detail(artifact: String, artifact_type: String) -> PrevalenceDetailResult {
    PrevalenceDetailResult {
        artifact,
        artifact_type,
        top_hosts: Vec::new(),
        top_users: Vec::new(),
        source_types: Vec::new(),
        processes: Vec::new(),
        top_file_names: Vec::new(),
        network: Vec::new(),
        geo: Vec::new(),
        threat_intel: Vec::new(),
    }
}

fn is_wrapper_process(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "svchost.exe"
            | "rundll32.exe"
            | "dllhost.exe"
            | "conhost.exe"
            | "regsvr32.exe"
            | "powershell.exe"
            | "cmd.exe"
            | "wscript.exe"
            | "cscript.exe"
            | "mshta.exe"
    )
}

pub(crate) fn ip_is_private(value: &str) -> bool {
    match IpAddr::from_str(value) {
        Ok(IpAddr::V4(value)) => value.is_private() || value.is_loopback() || value.is_link_local(),
        Ok(IpAddr::V6(value)) => {
            value.is_unique_local() || value.is_loopback() || value.is_unicast_link_local()
        }
        Err(_) => false,
    }
}

fn artifact_type_from_text(kind: &str, entity: &str, is_private: bool) -> String {
    let kind = match kind {
        "hash" => ArtifactKind::Hash,
        "domain" => ArtifactKind::Domain,
        "ip" => ArtifactKind::Ip,
        _ => return "unknown".to_string(),
    };
    artifact_type(kind, entity, is_private)
}

fn artifact_filter(manifest: &SourceManifest, kind: ArtifactKind) -> Result<String> {
    present_artifact_filter(manifest, kind).ok_or_else(|| {
        PrevalenceError::InvalidRequest(
            "artifact type is not present in the immutable event schema".to_string(),
        )
    })
}

/// The OR of `kind`'s match predicates over the paths `manifest` carries;
/// `None` when it carries none of them.
fn present_artifact_filter(manifest: &SourceManifest, kind: ArtifactKind) -> Option<String> {
    let candidates: &[(&str, &str)] = match kind {
        ArtifactKind::Hash => &[
            (
                "file.hashes",
                "arrayExists(hash -> hash.algorithm_id = if(length({artifact:String}) = 32, 1, 3) AND lower(coalesce(hash.value, '')) = {artifact:String}, file.hashes)",
            ),
            (
                "process.file.hashes",
                "arrayExists(hash -> hash.algorithm_id = if(length({artifact:String}) = 32, 1, 3) AND lower(coalesce(hash.value, '')) = {artifact:String}, process.file.hashes)",
            ),
            (
                "actor.process.file.hashes",
                "arrayExists(hash -> hash.algorithm_id = if(length({artifact:String}) = 32, 1, 3) AND lower(coalesce(hash.value, '')) = {artifact:String}, actor.process.file.hashes)",
            ),
        ],
        ArtifactKind::Ip => &[
            ("dst_endpoint.ip", "dst_endpoint.ip = {artifact:String}"),
            ("src_endpoint.ip", "src_endpoint.ip = {artifact:String}"),
        ],
        // NAN-3213: the event's own hostnames are its observer identity, not a
        // domain artifact (`ocsf_domains::PREVALENCE_DOMAIN_PATHS`), so a domain's
        // detail never matches the rows where it is merely the observing host.
        ArtifactKind::Domain => &[
            (
                "dst_endpoint.hostname",
                "lower(dst_endpoint.hostname) = {artifact:String}",
            ),
            (
                "query.hostname",
                "lower(query.hostname) = {artifact:String}",
            ),
            ("url.hostname", "lower(url.hostname) = {artifact:String}"),
            (
                "http_request.url.hostname",
                "lower(http_request.url.hostname) = {artifact:String}",
            ),
        ],
    };
    let predicates = candidates
        .iter()
        .filter(|(path, _)| manifest_has_path(manifest, path))
        .map(|(_, predicate)| *predicate)
        .collect::<Vec<_>>();
    (!predicates.is_empty()).then(|| format!("({})", predicates.join(" OR ")))
}

fn manifest_has_path(manifest: &SourceManifest, expected: &str) -> bool {
    manifest.objects.iter().any(|object| {
        object
            .available_paths
            .iter()
            .any(|path| path == expected || path.starts_with(&format!("{expected}.")))
    })
}

fn chdb_timestamp(value: &str) -> String {
    if let Ok(parsed) = chrono::DateTime::parse_from_rfc3339(value) {
        return format_timestamp(parsed.with_timezone(&chrono::Utc));
    }
    for format in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S"] {
        if let Ok(parsed) = chrono::NaiveDateTime::parse_from_str(value, format) {
            return format_timestamp(parsed.and_utc());
        }
    }
    value.to_string()
}

fn format_timestamp(value: chrono::DateTime<chrono::Utc>) -> String {
    let precision = if value.timestamp_subsec_micros() == 0 {
        chrono::SecondsFormat::Secs
    } else {
        chrono::SecondsFormat::Micros
    };
    value.to_rfc3339_opts(precision, true)
}

struct PrevalenceMergeOperator;

impl MergeOperator for PrevalenceMergeOperator {
    fn merge(
        &self,
        _key: &Bytes,
        existing_value: Option<Bytes>,
        value: Bytes,
    ) -> std::result::Result<Bytes, MergeOperatorError> {
        merge_values(existing_value.as_deref(), &value)
            .map(Bytes::from)
            .map_err(|error| MergeOperatorError::Callback {
                message: error.to_string(),
            })
    }
}

fn prevalence_key(secret: &[u8], kind: ArtifactKind, scope: &str, entity: &str) -> Result<Vec<u8>> {
    let mut hmac =
        Hmac::<Sha256>::new_from_slice(secret).map_err(|_| PrevalenceError::InvalidValue)?;
    hmac.update(b"prevalence-v1\0");
    hmac.update(entity.trim().to_ascii_lowercase().as_bytes());
    let digest = hmac.finalize().into_bytes();
    let mut key = Vec::with_capacity(kind.as_str().len() + scope.len() + digest.len() + 2);
    key.extend_from_slice(kind.as_str().as_bytes());
    key.push(0);
    key.extend_from_slice(scope.as_bytes());
    key.push(0);
    key.extend_from_slice(&digest);
    Ok(key)
}

fn decode_value(encoded: &[u8]) -> Result<PrevalenceValue> {
    if encoded.len() < VALUE_HEADER_BYTES || encoded[0] != VALUE_VERSION {
        return Err(PrevalenceError::InvalidValue);
    }
    let count = encoded[1] as usize;
    if count > HOST_CAP || encoded.len() != VALUE_HEADER_BYTES + count * 8 {
        return Err(PrevalenceError::InvalidValue);
    }
    let first_seen_us = i64::from_be_bytes(
        encoded[4..12]
            .try_into()
            .map_err(|_| PrevalenceError::InvalidValue)?,
    );
    let last_seen_us = i64::from_be_bytes(
        encoded[12..20]
            .try_into()
            .map_err(|_| PrevalenceError::InvalidValue)?,
    );
    let total_occurrences = u64::from_be_bytes(
        encoded[20..28]
            .try_into()
            .map_err(|_| PrevalenceError::InvalidValue)?,
    );
    let mut hosts = BTreeSet::new();
    for chunk in encoded[VALUE_HEADER_BYTES..].chunks_exact(8) {
        hosts.insert(u64::from_be_bytes(
            chunk
                .try_into()
                .map_err(|_| PrevalenceError::InvalidValue)?,
        ));
    }
    Ok(PrevalenceValue {
        hosts,
        saturated: encoded[2] != 0,
        is_private: encoded[3] != 0,
        first_seen_us,
        last_seen_us,
        total_occurrences,
    })
}

fn encode_value(value: &PrevalenceValue) -> Result<Vec<u8>> {
    let hosts = value
        .hosts
        .iter()
        .copied()
        .take(HOST_CAP)
        .collect::<Vec<_>>();
    let count = u8::try_from(hosts.len()).map_err(|_| PrevalenceError::InvalidValue)?;
    let mut encoded = Vec::with_capacity(VALUE_HEADER_BYTES + hosts.len() * 8);
    encoded.push(VALUE_VERSION);
    encoded.push(count);
    encoded.push(u8::from(value.saturated || hosts.len() == HOST_CAP));
    encoded.push(u8::from(value.is_private));
    encoded.extend_from_slice(&value.first_seen_us.to_be_bytes());
    encoded.extend_from_slice(&value.last_seen_us.to_be_bytes());
    encoded.extend_from_slice(&value.total_occurrences.to_be_bytes());
    for host in hosts {
        encoded.extend_from_slice(&host.to_be_bytes());
    }
    Ok(encoded)
}

fn merge_values(existing: Option<&[u8]>, incoming: &[u8]) -> Result<Vec<u8>> {
    let incoming = decode_value(incoming)?;
    let combined = match existing {
        Some(existing) => merge_decoded(decode_value(existing)?, incoming)?,
        None => incoming,
    };
    encode_value(&combined)
}

fn merge_decoded(
    mut current: PrevalenceValue,
    incoming: PrevalenceValue,
) -> Result<PrevalenceValue> {
    current.hosts.extend(incoming.hosts);
    current.hosts = current.hosts.into_iter().take(HOST_CAP).collect();
    current.saturated = current.saturated || incoming.saturated || current.hosts.len() == HOST_CAP;
    current.is_private |= incoming.is_private;
    current.first_seen_us = current.first_seen_us.min(incoming.first_seen_us);
    current.last_seen_us = current.last_seen_us.max(incoming.last_seen_us);
    current.total_occurrences = current
        .total_occurrences
        .checked_add(incoming.total_occurrences)
        .ok_or(PrevalenceError::InvalidValue)?;
    Ok(current)
}

/// NAN-2869: the reader's timestamp rendering of a microsecond instant.
pub fn format_micros(micros: i64) -> String {
    timestamp(micros).unwrap_or_default()
}

/// NAN-2869: the reader's artifact parsing, as `(kind, entity)`.
pub fn parse_lookup_artifact(value: &str) -> Option<(String, String)> {
    parse_artifact(value).map(|parsed| (parsed.kind.as_str().to_string(), parsed.entity))
}

/// Rarity threshold (`host_count < N` is rare) of a lean tenant with no
/// stored value, in every mode (hosted and trusted-local): the Settings
/// default (`system_settings.prevalence_rarity_threshold`) and the value
/// API/Search send to the cell.
///
/// NAN-3492: was a literal 5 at ingest and in the cell query fallback, so a
/// hash on 4 hosts was stamped rare at ingest and read common by Search.
pub const DEFAULT_RARITY_THRESHOLD: u64 =
    nanosiem_core::search::lake_cell::LAKE_CELL_PREVALENCE_RARITY_THRESHOLD;

/// The rarity threshold for one tenant's lean paths that receive no
/// per-request value: ingest-time stamps and a cell query request without
/// `rarity_threshold`. A stored tenant value (from the placement, in the
/// assignment) wins; otherwise [`DEFAULT_RARITY_THRESHOLD`]. An out-of-range
/// stored value is ignored (the cell refuses it in the placement already).
pub fn rarity_threshold_for(stored: Option<u64>) -> u64 {
    stored.filter(|value| (1..=10_000).contains(value)).unwrap_or(DEFAULT_RARITY_THRESHOLD)
}

/// [`rarity_threshold_for`] of an assignment's stored value.
pub fn assignment_rarity_threshold(assignment: &nanosiem_lake_cell::contract::Assignment) -> u64 {
    rarity_threshold_for(assignment.prevalence_rarity_threshold)
}

static TENANT_RARITY_THRESHOLD: std::sync::OnceLock<u64> = std::sync::OnceLock::new();

/// Bind this process's tenant threshold. A cell child serves exactly one
/// tenant; the query/detect/product binary calls this once from its
/// assignment. Later calls are ignored.
pub fn bind_tenant_rarity_threshold(threshold: u64) {
    let _ = TENANT_RARITY_THRESHOLD.set(threshold);
}

/// The bound tenant threshold, or [`DEFAULT_RARITY_THRESHOLD`] when nothing
/// was bound (lab binaries, tests).
pub fn tenant_rarity_threshold() -> u64 {
    TENANT_RARITY_THRESHOLD
        .get()
        .copied()
        .unwrap_or(DEFAULT_RARITY_THRESHOLD)
}

/// NAN-2869: one lookup result with the reader's typing, rarity and score.
#[allow(clippy::too_many_arguments)]
pub fn prevalence_result(
    kind: &str,
    entity: &str,
    host_count: u64,
    saturated: bool,
    is_private: bool,
    first_seen_us: i64,
    last_seen_us: i64,
    total_occurrences: u64,
    rarity_threshold: u64,
) -> Result<PrevalenceResult> {
    Ok(PrevalenceResult {
        artifact: entity.to_string(),
        artifact_type: artifact_type_from_text(kind, entity, is_private),
        host_count,
        host_count_saturated: saturated,
        total_occurrences,
        first_seen: timestamp(first_seen_us)?,
        last_seen: timestamp(last_seen_us)?,
        is_rare: !saturated && host_count < rarity_threshold,
        prevalence_score: prevalence_score_with_saturation(host_count, rarity_threshold, saturated),
    })
}

fn parse_artifact(value: &str) -> Option<ParsedArtifact> {
    let entity = value.trim().to_ascii_lowercase();
    if matches!(entity.len(), 32 | 64) && entity.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Some(ParsedArtifact {
            kind: ArtifactKind::Hash,
            entity,
        });
    }
    if IpAddr::from_str(&entity).is_ok() {
        return Some(ParsedArtifact {
            kind: ArtifactKind::Ip,
            entity,
        });
    }
    if entity.len() <= 253
        && entity.contains('.')
        && entity.split('.').all(|label| {
            !label.is_empty()
                && label.chars().count() <= 63
                && label.chars().next().is_some_and(char::is_alphanumeric)
                && label.chars().last().is_some_and(char::is_alphanumeric)
                && label
                    .chars()
                    .all(|character| character.is_alphanumeric() || character == '-')
        })
    {
        return Some(ParsedArtifact {
            kind: ArtifactKind::Domain,
            entity,
        });
    }
    None
}

fn normalize_sources(sources: &[String]) -> Result<BTreeSet<String>> {
    if sources.len() > 1_024
        || sources.iter().any(|source| {
            source.is_empty() || source.len() > 512 || source.chars().any(char::is_control)
        })
    {
        return Err(PrevalenceError::InvalidRequest(
            "prevalence source scope exceeds its bound".to_string(),
        ));
    }
    Ok(sources
        .iter()
        .map(|source| source.trim().to_ascii_lowercase())
        .collect())
}

fn output_file_is_parquet(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if metadata.len() < 8 {
        return false;
    }
    let mut prefix = [0_u8; 4];
    let mut suffix = [0_u8; 4];
    file.read_exact(&mut prefix).is_ok()
        && file.seek(SeekFrom::End(-4)).is_ok()
        && file.read_exact(&mut suffix).is_ok()
        && prefix == *b"PAR1"
        && suffix == *b"PAR1"
}

fn artifact_type(kind: ArtifactKind, entity: &str, is_private: bool) -> String {
    match kind {
        ArtifactKind::Hash if entity.len() == 32 => "hash_md5",
        ArtifactKind::Hash => "hash_sha256",
        ArtifactKind::Domain if entity.split('.').count() > 2 => "subdomain",
        ArtifactKind::Domain => "domain",
        ArtifactKind::Ip if is_private => "ip_address_private",
        ArtifactKind::Ip => "ip_address",
    }
    .to_string()
}

fn timestamp(micros: i64) -> Result<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_micros(micros)
        .map(format_timestamp)
        .ok_or(PrevalenceError::InvalidValue)
}

fn prevalence_score(host_count: u64, rarity_threshold: u64) -> u8 {
    if host_count == 0 {
        return 0;
    }
    let count = host_count as f64;
    let threshold = rarity_threshold.max(1) as f64;
    let score = if count < threshold {
        (count / threshold * 20.0).min(20.0)
    } else if count < threshold * 2.0 {
        20.0 + (count - threshold) / threshold * 30.0
    } else if count < threshold * 10.0 {
        50.0 + (count - threshold * 2.0) / (threshold * 8.0) * 30.0
    } else {
        80.0 + ((count - threshold * 10.0) / (threshold * 90.0) * 20.0).min(20.0)
    };
    score.round().clamp(0.0, 100.0) as u8
}

fn prevalence_score_with_saturation(host_count: u64, rarity_threshold: u64, saturated: bool) -> u8 {
    if saturated {
        100
    } else {
        prevalence_score(host_count, rarity_threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value(hosts: &[u64], first: i64, last: i64, total: u64) -> PrevalenceValue {
        PrevalenceValue {
            hosts: hosts.iter().copied().collect(),
            saturated: false,
            is_private: false,
            first_seen_us: first,
            last_seen_us: last,
            total_occurrences: total,
        }
    }

    #[test]
    fn value_encoding_and_merge_match_the_publication_contract() {
        let left = encode_value(&value(&[1, 3], 20, 40, 2)).expect("left");
        let right = encode_value(&value(&[2, 3], 10, 50, 4)).expect("right");
        let merged =
            decode_value(&merge_values(Some(&left), &right).expect("merge")).expect("decode");
        assert_eq!(merged.hosts, BTreeSet::from([1, 2, 3]));
        assert_eq!(merged.first_seen_us, 10);
        assert_eq!(merged.last_seen_us, 50);
        assert_eq!(merged.total_occurrences, 6);
    }

    #[test]
    fn saturated_host_sets_remain_explicit_and_score_as_common() {
        let mut saturated = value(&[1, 2], 10, 50, 4);
        saturated.saturated = true;
        let decoded = decode_value(&encode_value(&saturated).expect("encode")).expect("decode");

        assert!(decoded.saturated);
        assert_eq!(prevalence_score_with_saturation(65, 3, true), 100);
        assert!(65 >= 3);
    }

    #[test]
    fn artifact_parsing_is_strict_and_normalized() {
        assert_eq!(
            parse_artifact(" EXAMPLE.COM ").map(|item| item.kind),
            Some(ArtifactKind::Domain)
        );
        assert_eq!(
            parse_artifact("192.0.2.1").map(|item| item.kind),
            Some(ArtifactKind::Ip)
        );
        assert!(parse_artifact("not an artifact").is_none());
    }

    #[test]
    fn detail_hints_keep_all_matching_or_legs_and_omit_only_absent_schema_fields() {
        use crate::planner::CandidateHint;
        let fields = ["src_endpoint.ip", "dst_endpoint.ip", "actor.process.file.hashes.value", "dst_endpoint.hostname"]
            .into_iter().map(|path| (path.to_string(), "String".into())).collect();
        for (artifact, expected) in [(" 192.0.2.1 ", vec!["src_endpoint.ip", "dst_endpoint.ip"]),
            ("EXAMPLE.TEST", vec!["dst_endpoint.hostname"]), ("a".repeat(64).as_str(), vec!["actor.process.file.hashes.value"])] {
            let hints = detail_candidate_hints(artifact, &fields);
            let CandidateHint::Any { alternatives } = &hints[0] else { panic!("must preserve OR"); };
            let actual: Vec<_> = alternatives.iter().map(|hint| {
                let CandidateHint::Entity { source_path, value } = hint else { panic!("entity hint"); };
                assert_eq!(value, &artifact.trim().to_ascii_lowercase());
                source_path.as_str()
            }).collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn materialized_explorer_skips_the_request_time_cross_source_group_by() {
        let materialized = explorer_aggregate_sql(true, "kind = {kind:String}");
        assert!(materialized.contains("host_count"));
        assert!(!materialized.contains("uniqExactArray"));
        assert!(!materialized.contains("GROUP BY"));

        let scoped_fallback = explorer_aggregate_sql(false, "scope IN ({scope:String})");
        assert!(scoped_fallback.contains("uniqExactArray(host_fingerprints)"));
        assert!(scoped_fallback.contains("GROUP BY kind, entity"));
    }

    #[test]
    fn prevalence_keys_are_scope_and_entity_bound() {
        let secret = vec![7_u8; 32];
        let first =
            prevalence_key(&secret, ArtifactKind::Ip, "source-a", "192.0.2.1").expect("first key");
        let second =
            prevalence_key(&secret, ArtifactKind::Ip, "source-b", "192.0.2.1").expect("second key");
        assert_ne!(first, second);
        assert!(!first
            .windows("192.0.2.1".len())
            .any(|window| window == b"192.0.2.1"));
    }

    #[test]
    fn interactive_aggregation_spills_before_its_hard_memory_limit() {
        let six_gib = 6 * 1_073_741_824;
        let (external_threshold, temporary_disk_bytes) = external_processing_limits(six_gib);

        assert_eq!(external_threshold, 3_221_225_472);
        assert_eq!(temporary_disk_bytes, 25_769_803_776);
        assert!(external_threshold < six_gib);
    }
}

/// NAN-3760: safe OR hints for exactly the fields tested by the detail
/// predicate. Missing/old locator or bloom evidence remains unknown (keep).
/// In particular domain absence in prevalence partials is NOT a negative:
/// configured internal domains can be omitted from those summaries.
pub(crate) fn detail_candidate_hints(artifact: &str, fields: &std::collections::BTreeMap<String, String>) -> Vec<crate::planner::CandidateHint> {
    use crate::planner::CandidateHint;
    let (paths, value): (&[&str], String) = match parse_artifact(artifact) {
        Some(parsed) => (match parsed.kind {
            ArtifactKind::Hash => &["file.hashes.value", "process.file.hashes.value", "actor.process.file.hashes.value"],
            ArtifactKind::Ip => &["src_endpoint.ip", "dst_endpoint.ip"],
            ArtifactKind::Domain => &["dst_endpoint.hostname", "query.hostname", "url.hostname", "http_request.url.hostname"],
        }, parsed.entity),
        None => (&["user.name", "actor.user.name", "src_endpoint.hostname", "dst_endpoint.hostname", "device.hostname"], artifact.trim().to_ascii_lowercase()),
    };
    vec![CandidateHint::Any { alternatives: paths.iter().filter(|path| fields.contains_key(**path)).map(|path| CandidateHint::Entity {
        source_path: (*path).into(), value: value.clone(),
    }).collect() }]
}

/// The artifact a part detail scan matches: its parsed identity, the
/// response type, and the row predicate over the leaves `manifest` holds.
fn part_detail_target(manifest: &SourceManifest, artifact: &str) -> Result<(ParsedArtifact, String, String)> {
    if let Some(parsed) = parse_artifact(artifact) {
        let result_type = artifact_type(parsed.kind, &parsed.entity,
            parsed.kind == ArtifactKind::Ip && ip_is_private(&parsed.entity));
        // NAN-3805: objects without any of the kind's columns (a tenant with
        // no such source, or a detail slice that holds only other sources)
        // match no row: an empty answer, never a failed build that leaves
        // the detail warming forever.
        let filter = present_artifact_filter(manifest, parsed.kind).unwrap_or_else(|| "0".into());
        return Ok((parsed, result_type, filter));
    }
    // Bare user/host names cannot be distinguished from their spelling.
    // Search both identities and label the response honestly as identity.
    let parsed = ParsedArtifact {kind: ArtifactKind::Hash, entity: artifact.trim().to_ascii_lowercase()};
    let predicates = ["user.name", "actor.user.name", "src_endpoint.hostname", "dst_endpoint.hostname", "device.hostname"]
        .into_iter().filter(|path| manifest_has_path(manifest, path))
        .map(|path| format!("lower({path}) = {{artifact:String}}"))
        .collect::<Vec<_>>();
    let filter = if predicates.is_empty() { "0".into() } else { format!("({})", predicates.join(" OR ")) };
    Ok((parsed, "identity".into(), filter))
}

/// The response identity of `artifact` that does not depend on a manifest.
fn part_detail_identity(artifact: &str) -> (ParsedArtifact, String) {
    match parse_artifact(artifact) {
        Some(parsed) => {
            let result_type = artifact_type(parsed.kind, &parsed.entity,
                parsed.kind == ArtifactKind::Ip && ip_is_private(&parsed.entity));
            (parsed, result_type)
        }
        None => (ParsedArtifact {kind: ArtifactKind::Hash, entity: artifact.trim().to_ascii_lowercase()}, "identity".into()),
    }
}

/// Shared bounded context scan for gen1 snapshots and verified lean parts.
pub(crate) async fn read_part_detail(
    executor: &NativeExecutor, tenant: &TenantQueryConfig, manifest: &SourceManifest,
    source: String, mut params: Vec<(String, String)>, source_scope: String,
    artifact: &str, from_us: i64, to_us: i64,
) -> Result<PrevalenceDetailResult> {
    let (parsed, result_type, filter) = part_detail_target(manifest, artifact)?;
    params.push(("artifact".into(), parsed.entity.clone()));
    params.push(("detail_from_us".into(), from_us.to_string()));
    params.push(("detail_to_us".into(), to_us.to_string()));
    // Use exact caller window bounds, not a second moving clock.
    let source = format!("(SELECT * FROM {source} WHERE time >= fromUnixTimestamp64Micro({{detail_from_us:Int64}}) AND time <= fromUnixTimestamp64Micro({{detail_to_us:Int64}}))");
    read_detail(executor, tenant, manifest, source, params, filter, source_scope, parsed, result_type).await
}

/// NAN-3766: most facet groups one time slice contributes per facet. A
/// slice whose facet has more distinct values keeps its top groups by count
/// and marks the merge approximate (a dropped group's count is missing).
pub(crate) const DETAIL_SLICE_GROUP_CAP: u64 = 1_000;

/// NAN-3766: the facet groups of one time slice of a detail scan.
#[derive(Debug, Default)]
pub(crate) struct DetailSlice {
    rows: Vec<DetailRow>,
    truncated: bool,
}

/// NAN-3766: facet groups (not the ranked top N) of the artifact's events
/// with `from_us <= time <= to_us` (`< to_us` unless `to_inclusive`), so
/// disjoint slices merge exactly. `limit` bounds the statement's execution;
/// running out answers [`PrevalenceError::Timeout`].
pub(crate) async fn read_part_detail_slice(
    executor: &NativeExecutor, tenant: &TenantQueryConfig, manifest: &SourceManifest,
    source: String, mut params: Vec<(String, String)>, source_scope: String,
    artifact: &str, from_us: i64, to_us: i64, to_inclusive: bool, limit: std::time::Duration,
) -> Result<DetailSlice> {
    let (parsed, _, filter) = part_detail_target(manifest, artifact)?;
    params.push(("artifact".into(), parsed.entity.clone()));
    params.push(("detail_from_us".into(), from_us.to_string()));
    params.push(("detail_to_us".into(), to_us.to_string()));
    let upper = if to_inclusive { "<=" } else { "<" };
    let source = format!("(SELECT * FROM {source} WHERE time >= fromUnixTimestamp64Micro({{detail_from_us:Int64}}) AND time {upper} fromUnixTimestamp64Micro({{detail_to_us:Int64}}))");
    let mut rows = detail_rows(executor, tenant, manifest, source, params, filter, source_scope, parsed.kind,
        DetailShape::Groups { cap: DETAIL_SLICE_GROUP_CAP }, ExecutionLimit::Fractional(limit)).await?;
    // The statement returns up to cap + 1 groups per facet; the extra one
    // only proves the facet had more.
    let mut per_facet: BTreeMap<String, u64> = BTreeMap::new();
    let mut truncated = false;
    rows.retain(|row| {
        let seen = per_facet.entry(row.facet.clone()).or_default();
        *seen += 1;
        let keep = *seen <= DETAIL_SLICE_GROUP_CAP;
        truncated |= !keep;
        keep
    });
    Ok(DetailSlice { rows, truncated })
}

/// NAN-3766: merges the facet groups of disjoint time slices into the same
/// ranked response a single whole-range statement answers.
#[derive(Debug)]
pub(crate) struct DetailMerge {
    entity: String,
    result_type: String,
    groups: std::collections::HashMap<(String, String, String), (u64, String)>,
    approximate: bool,
}

impl DetailMerge {
    pub(crate) fn new(artifact: &str) -> Self {
        let (parsed, result_type) = part_detail_identity(artifact);
        Self { entity: parsed.entity, result_type, groups: Default::default(), approximate: false }
    }

    pub(crate) fn add(&mut self, slice: DetailSlice) {
        self.approximate |= slice.truncated;
        for row in slice.rows {
            let entry = self.groups.entry((row.facet, row.name, row.meta)).or_insert((0, String::new()));
            entry.0 += row.count;
            if row.last_seen > entry.1 {
                entry.1 = row.last_seen;
            }
        }
    }

    /// Whether a slice dropped groups beyond [`DETAIL_SLICE_GROUP_CAP`], so
    /// merged counts can be lower bounds.
    pub(crate) fn approximate(&self) -> bool {
        self.approximate
    }

    /// The ranked facets: per facet by count DESC, name ASC (then meta), the
    /// top ten (five file names), exactly as [`read_part_detail`] ranks.
    pub(crate) fn result(&self) -> Result<PrevalenceDetailResult> {
        let mut by_facet: BTreeMap<&str, Vec<(&(String, String, String), &(u64, String))>> = BTreeMap::new();
        for (key, value) in &self.groups {
            by_facet.entry(key.0.as_str()).or_default().push((key, value));
        }
        let mut rows = Vec::new();
        for (facet, mut groups) in by_facet {
            groups.sort_by(|a, b| b.1.0.cmp(&a.1.0).then_with(|| a.0.1.cmp(&b.0.1)).then_with(|| a.0.2.cmp(&b.0.2)));
            let limit = if facet == "file" { 5 } else { 10 };
            rows.extend(groups.into_iter().take(limit).map(|((facet, name, meta), (count, last_seen))| DetailRow {
                facet: facet.clone(), name: name.clone(), meta: meta.clone(), count: *count, last_seen: last_seen.clone(),
            }));
        }
        detail_from_rows(self.entity.clone(), self.result_type.clone(), rows)
    }
}

/// What a detail statement returns: the ranked response facets, or every
/// facet group up to a cap (+1 to detect truncation) for a slice merge.
#[derive(Debug, Clone, Copy)]
enum DetailShape {
    Ranked,
    Groups { cap: u64 },
}

#[derive(Debug, Clone, Copy)]
enum ExecutionLimit {
    /// The tenant's limit, capped at [`PREVALENCE_DETAIL_MAX_EXECUTION_SECONDS`].
    Default,
    /// A slice's remaining budget, also capped at that bound.
    Fractional(std::time::Duration),
}

async fn read_detail(
    executor: &NativeExecutor, tenant: &TenantQueryConfig, manifest: &SourceManifest, source: String,
    params: Vec<(String, String)>, artifact_filter: String, source_scope: String,
    parsed: ParsedArtifact, result_type: String,
) -> Result<PrevalenceDetailResult> {
    let rows = detail_rows(executor, tenant, manifest, source, params, artifact_filter, source_scope, parsed.kind,
        DetailShape::Ranked, ExecutionLimit::Default).await?;
    detail_from_rows(parsed.entity, result_type, rows)
}

#[allow(clippy::too_many_arguments)]
async fn detail_rows(
    executor: &NativeExecutor, tenant: &TenantQueryConfig, manifest: &SourceManifest, source: String,
    params: Vec<(String, String)>, artifact_filter: String, source_scope: String,
    kind: ArtifactKind, shape: DetailShape, limit: ExecutionLimit,
) -> Result<Vec<DetailRow>> {
    let execution_seconds = tenant
        .max_execution_seconds
        .min(PREVALENCE_DETAIL_MAX_EXECUTION_SECONDS);
    let execution_time = match limit {
        ExecutionLimit::Default => execution_seconds.to_string(),
        // ClickHouse accepts fractional seconds: at least 50 ms, never more
        // than the detail bound.
        ExecutionLimit::Fractional(limit) => format!("{:.3}",
            limit.as_secs_f64().min(execution_seconds as f64).max(0.05)),
    };
    // Lean parts preserve their admitted schema; optional OCSF roots can be
    // absent. Only reference leaves present in the verified source manifest.
    let text = |paths: &[&str], fallback: &str| {
        let mut values = paths.iter().filter(|path| manifest_has_path(manifest, path))
            .map(|path| format!("nullIf({path}, '')")).collect::<Vec<_>>();
        values.push(format!("'{fallback}'"));
        format!("coalesce({})", values.join(", "))
    };
    // NAN-3213: the same observer identity the partials count hosts by.
    let host = text(crate::ocsf_domains::PREVALENCE_OBSERVER_PATHS, "unknown");
    let user = text(&["user.name", "actor.user.name"], "");
    let mut facets = vec![
        format!("tuple('host', {host}, '')"),
        format!("tuple('user', {user}, '')"),
        "tuple('source', tupleElement(metadata, 'log_source'), '')".into(),
    ];
    match kind {
        ArtifactKind::Hash => {
            let process = text(&["process.name", "actor.process.name"], "");
            let command = text(&["process.cmd_line", "actor.process.cmd_line"], "");
            let file = text(&["file.name", "module.file.name", "process.file.name", "actor.process.file.name"], "");
            facets.push(format!("tuple('process', {process}, {command})"));
            facets.push(format!("tuple('file', {file}, '')"));
        }
        ArtifactKind::Ip | ArtifactKind::Domain => {
            let port = if manifest_has_path(manifest, "dst_endpoint.port") {
                "if(dst_endpoint.port > 0, toString(dst_endpoint.port), '')"
            } else { "''" };
            let protocol = if manifest_has_path(manifest, "connection_info.protocol_num") {
                "coalesce(toString(connection_info.protocol_num), '')"
            } else { "''" };
            facets.push(format!("tuple('network', {port}, {protocol})"));
        }
    }
    let facets = format!("[{}]", facets.join(", "));
    let (order, rank_limit) = match shape {
        DetailShape::Ranked => ("count DESC, name ASC", "if(facet = 'file', 5, 10)".to_string()),
        DetailShape::Groups { cap } => ("count DESC, name ASC, meta ASC", cap.saturating_add(1).to_string()),
    };
    let sql = format!(
        "WITH expanded AS (\
            SELECT time AS event_time, arrayJoin({facets}) AS item \
            FROM {source} \
            WHERE {source_scope} AND {artifact_filter}\
         ), grouped AS (\
            SELECT tupleElement(item, 1) AS facet, tupleElement(item, 2) AS name, \
                   tupleElement(item, 3) AS meta, count() AS count, max(event_time) AS last_seen \
            FROM expanded WHERE name != '' GROUP BY facet, name, meta\
         ), ranked AS (\
            SELECT *, row_number() OVER (PARTITION BY facet ORDER BY {order}) AS facet_rank \
            FROM grouped\
         ) SELECT facet, name, meta, count, last_seen FROM ranked \
           WHERE facet_rank <= {rank_limit} ORDER BY facet ASC, facet_rank ASC \
           SETTINGS max_threads={}, max_parsing_threads={}, max_execution_time={execution_time}, max_bytes_to_read={}, \
                    max_memory_usage={}, use_query_cache=0",
        tenant.threads,
        tenant.threads,
        tenant.max_query_bytes,
        tenant.max_memory_bytes,
    );
    let output = executor
        .execute_sql(sql, params)
        .await
        .map_err(|error| {
            let message = error.to_string();
            if message.contains("TIMEOUT_EXCEEDED") || message.contains("max_execution_time") {
                return PrevalenceError::Timeout;
            }
            tracing::warn!(error = %message, "prevalence detail scan failed");
            PrevalenceError::Read
        })?;
    decode_json_each_row::<DetailRow>(&output.data)
}

fn detail_from_rows(entity: String, result_type: String, rows: Vec<DetailRow>) -> Result<PrevalenceDetailResult> {
    let mut result = empty_detail(entity, result_type);
    for row in rows {
        match row.facet.as_str() {
            "host" => result.top_hosts.push(DetailHost {
                host: row.name,
                count: row.count,
                last_seen: chdb_timestamp(&row.last_seen),
            }),
            "user" => result.top_users.push(DetailUser {
                user: row.name,
                count: row.count,
            }),
            "source" => result.source_types.push(DetailSource {
                source_type: row.name,
                count: row.count,
            }),
            "process" => result.processes.push(DetailProcess {
                is_wrapper: is_wrapper_process(&row.name),
                process_name: row.name,
                command_line: row.meta,
                count: row.count,
            }),
            "file" => result.top_file_names.push(DetailFileName {
                file_name: row.name,
                count: row.count,
            }),
            "network" => {
                if let Ok(port) = row.name.parse::<u16>() {
                    result.network.push(DetailNetwork {
                        dest_port: port,
                        protocol: row.meta,
                        count: row.count,
                    });
                }
            }
            _ => return Err(PrevalenceError::InvalidValue),
        }
    }
    Ok(result)
}

#[cfg(test)]
mod detail_merge_tests {
    use super::*;

    fn row(facet: &str, name: &str, meta: &str, count: u64, last_seen: &str) -> DetailRow {
        DetailRow { facet: facet.into(), name: name.into(), meta: meta.into(), count, last_seen: last_seen.into() }
    }

    #[test]
    fn slices_merge_by_summing_counts_and_keep_the_newest_last_seen() {
        let mut merge = DetailMerge::new("10.0.0.1");
        merge.add(DetailSlice { rows: vec![row("host", "a", "", 3, "2026-10-13 10:00:00.000000"),
            row("host", "b", "", 5, "2026-10-13 10:00:00.000000"), row("network", "443", "6", 2, "2026-10-13 10:00:00.000000")], truncated: false });
        merge.add(DetailSlice { rows: vec![row("host", "a", "", 4, "2026-10-12 09:00:00.000000"),
            row("network", "443", "6", 1, "2026-10-12 09:00:00.000000")], truncated: false });
        let result = merge.result().unwrap();
        assert!(!merge.approximate());
        assert_eq!(result.artifact_type, "ip_address_private");
        assert_eq!(result.top_hosts.iter().map(|host| (host.host.as_str(), host.count)).collect::<Vec<_>>(), vec![("a", 7), ("b", 5)]);
        assert_eq!(result.top_hosts[0].last_seen, chdb_timestamp("2026-10-13 10:00:00.000000"));
        assert_eq!(result.network[0].count, 3);
    }

    #[test]
    fn merged_ranking_breaks_ties_by_name_and_bounds_each_facet() {
        let mut merge = DetailMerge::new(&"a".repeat(64));
        let rows = (0..12).map(|i| row("file", &format!("f{i:02}"), "", 1, "2026-10-13 10:00:00")).collect();
        merge.add(DetailSlice { rows, truncated: true });
        let result = merge.result().unwrap();
        assert!(merge.approximate(), "a truncated slice makes the merge approximate");
        assert_eq!(result.top_file_names.iter().map(|file| file.file_name.as_str()).collect::<Vec<_>>(),
            vec!["f00", "f01", "f02", "f03", "f04"]);
    }
}
