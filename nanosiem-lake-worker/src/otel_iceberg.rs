// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native OpenTelemetry datasets in Nano's Iceberg catalog.
//!
//! OCSF remains the security-event contract. Spans and metric data points keep
//! their native OTLP shape in separate Iceberg tables so trace topology,
//! nanosecond durations, metric temporality, histogram buckets, and arbitrary
//! semantic-convention attributes are not forced through OCSF Base Event.

use crate::iceberg::{snapshot_for_batch, CatalogConfig, OUTBOX_BATCH_PROPERTY};
use crate::planner::{trusted_iceberg_source, TenantQueryConfig};
use anyhow::{bail, Context, Result};
use arrow_array::RecordBatch;
use arrow_json::ReaderBuilder;
use arrow_schema::{DataType, Field, Schema as ArrowSchema, TimeUnit};
use chrono::{DateTime, SecondsFormat, Utc};
use iceberg::spec::{
    DataFile, DataFileFormat, Literal, PartitionKey, Struct, Transform, UnboundPartitionField,
    UnboundPartitionSpec,
};
use iceberg::table::Table;
use iceberg::transaction::{ApplyTransactionAction, Transaction};
use iceberg::writer::base_writer::data_file_writer::DataFileWriterBuilder;
use iceberg::writer::file_writer::location_generator::{
    DefaultFileNameGenerator, DefaultLocationGenerator,
};
use iceberg::writer::file_writer::rolling_writer::RollingFileWriterBuilder;
use iceberg::writer::file_writer::ParquetWriterBuilder;
use iceberg::writer::{IcebergWriter, IcebergWriterBuilder};
use iceberg::{Catalog, TableCreation, TableIdent};
use iceberg_catalog_rest::RestCatalog;
use nanosiem_core::query::{
    parse_query, ClickHouseSqlGenerator, Command, Dataset, Query, QueryOptions, SearchExpr,
    TimeRange,
};
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Cursor;
use std::sync::Arc;

pub const OTEL_ICEBERG_SCHEMA_VERSION: &str = "nano-otlp-iceberg-v1";
const MAX_OTEL_BATCH_ROWS: usize = 250_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtelDataset {
    Spans,
    Metrics,
}

impl OtelDataset {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Spans => "spans",
            Self::Metrics => "metrics",
        }
    }

    pub fn time_field(self) -> &'static str {
        match self {
            Self::Spans => "start_time",
            Self::Metrics => "timestamp",
        }
    }

    pub fn source_type(self) -> &'static str {
        match self {
            Self::Spans => "otlp_trace",
            Self::Metrics => "otlp_metric",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtelLakeRow {
    pub row_uid: String,
    pub dataset: OtelDataset,
    pub event_hour: i32,
    pub row: Value,
}

#[derive(Debug, Clone, Serialize)]
pub struct OtelPublishResult {
    pub status: &'static str,
    pub dataset: OtelDataset,
    pub batch_sha256: String,
    pub snapshot_id: i64,
    pub rows: usize,
    pub metadata_location: String,
}

#[derive(Debug, Clone)]
pub struct OtelNativeQueryPlan {
    pub sql: String,
    pub params: Vec<(String, String)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetricAggregate {
    Avg,
    Sum,
    Min,
    Max,
    Count,
    Rate,
    P50,
    P95,
    P99,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtelSliKind {
    Availability,
    Latency,
}

#[derive(Debug, Clone)]
pub struct OtelMetricTagFilter {
    pub key: String,
    pub value: String,
}

/// One dataset's query sources (NAN-2361 wave 7). On a dedicated lake this
/// is just the tenant-pinned Iceberg table. On the hosted-shared lake the
/// primary is the committed table read at the metadata location the tail
/// compactor pinned (`lake_hot_tail_ledger_revisions.committed_metadata_location`)
/// — or, before the first registration, the local mirror alone — and
/// `staged_tail` is the local mirror of the objects still staged (drained but
/// not yet packed/committed), unioned positionally: both carry the exact
/// native OTLP v1 column order (`otel_arrow_schema`; the compactor refuses a
/// table whose column order differs, see `verify_native_column_order`).
#[derive(Debug, Clone)]
pub struct OtelQuerySource {
    pub primary: TenantQueryConfig,
    pub staged_tail: Option<TenantQueryConfig>,
}

impl From<TenantQueryConfig> for OtelQuerySource {
    fn from(primary: TenantQueryConfig) -> Self {
        Self { primary, staged_tail: None }
    }
}

impl std::ops::Deref for OtelQuerySource {
    type Target = TenantQueryConfig;
    fn deref(&self) -> &TenantQueryConfig {
        &self.primary
    }
}

/// The trusted `FROM` source for one dataset: the primary alone, or the
/// primary `UNION ALL` the staged tail. Parameter names never collide (the
/// Iceberg source binds `source` / `iceberg_*`, a snapshot cache binds
/// `snapshot_cache_*`); the tail's cache parameters are renamed so a primary
/// that is itself a mirror (pre-registration) can coexist with it.
pub fn trusted_otel_source(source: &OtelQuerySource) -> Result<(String, Vec<(String, String)>)> {
    let (primary, mut params) = trusted_iceberg_source(&source.primary)?;
    let Some(tail) = source.staged_tail.as_ref() else {
        return Ok((primary, params));
    };
    if tail.snapshot_cache.is_none() {
        bail!("OTLP staged tail source must be a local snapshot cache");
    }
    if tail.tenant_id != source.primary.tenant_id {
        bail!("OTLP staged tail source belongs to another tenant");
    }
    let (tail_source, tail_params) = trusted_iceberg_source(tail)?;
    let mut tail_source = tail_source;
    for (name, value) in tail_params {
        let renamed = format!("staged_tail_{name}");
        tail_source = tail_source.replace(&format!("{{{name}:String}}"), &format!("{{{renamed}:String}}"));
        params.push((renamed, value));
    }
    Ok((
        format!("(SELECT * FROM {primary} UNION ALL SELECT * FROM {tail_source})"),
        params,
    ))
}

/// Compile one ordinary nPL pipeline over the tenant-pinned native spans or
/// metrics Iceberg table. Product/external-data commands stay in their owning
/// services; this path supports the query-language transforms needed by Search
/// and scheduled telemetry detections without accepting SQL or storage
/// coordinates from the request.
#[allow(clippy::too_many_arguments)]
pub fn plan_otel_npl_query(
    table: &OtelQuerySource,
    tenant_id: &str,
    dataset: OtelDataset,
    npl: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    offset: usize,
    limit: usize,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if start >= end || npl.is_empty() || npl.len() > 256 * 1024 {
        bail!("native OTLP nPL query or time window is invalid");
    }
    if limit == 0 || limit > 1_000_000 || offset > 1_000_000 {
        bail!("native OTLP nPL page is outside its bounded execution contract");
    }
    let query = parse_query(npl).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    validate_native_otel_query(&query)?;

    let (iceberg_source, mut params) = trusted_otel_source(table)?;
    params.push(("otel_tenant_id".to_string(), tenant_id.to_string()));
    let source = match dataset {
        OtelDataset::Spans => format!(
            "(SELECT *, JSONExtract(attributes_json, 'Map(String, String)') AS attributes, \
             JSONExtract(resource_attributes_json, 'Map(String, String)') AS resource_attributes, \
             events_json AS events FROM {iceberg_source} \
             WHERE tenant_uid = {{otel_tenant_id:String}})"
        ),
        OtelDataset::Metrics => format!(
            "(SELECT *, JSONExtract(attributes_json, 'Map(String, String)') AS attributes, \
             JSONExtract(resource_attributes_json, 'Map(String, String)') AS resource_attributes \
             FROM {iceberg_source} WHERE tenant_uid = {{otel_tenant_id:String}})"
        ),
    };
    let core_dataset = match dataset {
        OtelDataset::Spans => Dataset::Spans,
        OtelDataset::Metrics => Dataset::Metrics,
    };
    let generated = ClickHouseSqlGenerator::new()
        .with_dataset(core_dataset)
        .with_trusted_physical_source(source)
        .generate_with_options(
            &query,
            &TimeRange::new(start, end),
            &QueryOptions {
                use_cache: false,
                table_view: false,
                limit: None,
                unordered: false,
            },
        )
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;

    let fetch = limit
        .checked_add(1)
        .context("native OTLP nPL result sentinel overflow")?;
    params.extend([
        ("otel_npl_offset".to_string(), offset.to_string()),
        ("otel_npl_fetch".to_string(), fetch.to_string()),
    ]);
    let spill_threshold = table.max_memory_bytes.saturating_div(2).max(1);
    let sql = format!(
        "SELECT * FROM ({generated}) LIMIT {{otel_npl_fetch:UInt64}} \
         OFFSET {{otel_npl_offset:UInt64}} SETTINGS max_threads={}, \
         max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_bytes_before_external_group_by={}, max_bytes_before_external_sort={}, \
         max_result_rows={}, result_overflow_mode='throw'",
        table.threads,
        table.max_execution_seconds,
        table.max_query_bytes,
        table.max_memory_bytes,
        spill_threshold,
        spill_threshold,
        fetch,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

fn validate_native_otel_query(query: &Query) -> Result<()> {
    match query {
        Query::Search(expression) => validate_native_otel_expression(expression),
        Query::Piped { source, command } => {
            validate_native_otel_query(source)?;
            match command {
                Command::Join {
                    subsearch,
                    subsearch_dataset,
                    ..
                } => {
                    if subsearch_dataset.is_some() {
                        bail!("cross-dataset subsearches are not available in native OTLP nPL");
                    }
                    validate_native_otel_query(subsearch)
                }
                Command::Append { subsearch, .. } => validate_native_otel_query(subsearch),
                Command::Where { condition } => validate_native_otel_expression(condition),
                Command::Transaction {
                    startswith,
                    endswith,
                    ..
                } => {
                    if let Some(condition) = startswith {
                        validate_native_otel_expression(condition)?;
                    }
                    if let Some(condition) = endswith {
                        validate_native_otel_expression(condition)?;
                    }
                    Ok(())
                }
                Command::Sequence { conditions, .. } => {
                    for condition in conditions {
                        validate_native_otel_expression(condition)?;
                    }
                    Ok(())
                }
                Command::Funnel { steps, .. } => {
                    for (_, condition) in steps {
                        validate_native_otel_expression(condition)?;
                    }
                    Ok(())
                }
                Command::Lookup { .. }
                | Command::Prevalence { .. }
                | Command::InputLookup { .. }
                | Command::Tree { .. }
                | Command::ResolveIdentity { .. }
                | Command::Asset { .. }
                | Command::Cloud { .. }
                | Command::Lateral { .. }
                | Command::Ai { .. }
                | Command::Output { .. }
                | Command::Services
                | Command::Service { .. }
                | Command::Trace { .. }
                | Command::Metric { .. }
                | Command::Retro { .. }
                | Command::Baseline { .. } => {
                    bail!("this product command is not available in native OTLP nPL")
                }
                Command::Stats { .. }
                | Command::Chart { .. }
                | Command::StreamStats { .. }
                | Command::Sort { .. }
                | Command::Head { .. }
                | Command::Tail { .. }
                | Command::Timechart { .. }
                | Command::Table { .. }
                | Command::Rename { .. }
                | Command::Eval { .. }
                | Command::Dedup { .. }
                | Command::Bin { .. }
                | Command::Rex { .. }
                | Command::Fields { .. }
                | Command::Top { .. }
                | Command::Rare { .. }
                | Command::Fillnull { .. }
                | Command::Mvexpand { .. }
                | Command::Spath { .. }
                | Command::Format { .. }
                | Command::Return { .. }
                | Command::Risk { .. }
                | Command::Sample { .. }
                | Command::Reverse
                | Command::EventStats { .. }
                | Command::Anomaly { .. } => Ok(()),
            }
        }
    }
}

fn validate_native_otel_expression(expression: &SearchExpr) -> Result<()> {
    match expression {
        SearchExpr::InSubsearch {
            subsearch,
            subsearch_dataset,
            ..
        } => {
            if subsearch_dataset.is_some() {
                bail!("cross-dataset subsearches are not available in native OTLP nPL");
            }
            validate_native_otel_query(subsearch)
        }
        SearchExpr::And(left, right) | SearchExpr::Or(left, right) => {
            validate_native_otel_expression(left)?;
            validate_native_otel_expression(right)
        }
        SearchExpr::Not(inner) | SearchExpr::Group(inner) => validate_native_otel_expression(inner),
        SearchExpr::IocMatch { .. } => {
            bail!("IOC observable expansion is only defined for OCSF events")
        }
        SearchExpr::Keyword(_)
        | SearchExpr::FieldFilter { .. }
        | SearchExpr::FunctionFilter { .. }
        | SearchExpr::FieldFunctionFilter { .. }
        | SearchExpr::InList { .. }
        | SearchExpr::BooleanFunction(_)
        | SearchExpr::EvalPredicate(_)
        | SearchExpr::LiteralComparison { .. } => Ok(()),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtelServicesSort {
    Rate,
    P95,
    Name,
    ErrorRate,
}

impl OtelServicesSort {
    pub fn parse(value: Option<&str>) -> Result<Self> {
        match value.unwrap_or("rate").trim().to_ascii_lowercase().as_str() {
            "rate" | "request_count" | "requests" => Ok(Self::Rate),
            "p95" | "latency" => Ok(Self::P95),
            "name" | "service" => Ok(Self::Name),
            "error_rate" | "errors" => Ok(Self::ErrorRate),
            _ => bail!("services sort is invalid"),
        }
    }

    fn sql_order(self) -> &'static str {
        match self {
            Self::Rate | Self::ErrorRate => "request_count DESC, service ASC",
            Self::P95 => "p95_ms DESC, service ASC",
            Self::Name => "service ASC",
        }
    }
}

impl MetricAggregate {
    fn sql(self) -> String {
        const CUMULATIVE_DELTA: &str = "arraySum(arrayMap(d -> if(d > 0, d, 0), \
            arrayDifference(arrayMap(p -> p.2, arraySort(p -> p.1, \
            groupArray((timestamp, value)))))))";
        match self {
            Self::Avg => "avg(value)".to_string(),
            Self::Sum => {
                format!("if(max(aggregation_temporality) = 2, {CUMULATIVE_DELTA}, sum(value))")
            }
            Self::Min => "min(value)".to_string(),
            Self::Max => "max(value)".to_string(),
            Self::Count => "toFloat64(count())".to_string(),
            Self::Rate => format!(
                "if(max(aggregation_temporality) = 2, {CUMULATIVE_DELTA}, sum(value)) / \
                 greatest(dateDiff('second', min(timestamp), max(timestamp)), 1)"
            ),
            Self::P50 => "quantileTDigest(0.50)(value)".to_string(),
            Self::P95 => "quantileTDigest(0.95)(value)".to_string(),
            Self::P99 => "quantileTDigest(0.99)(value)".to_string(),
        }
    }
}

/// Normalize one Vector OTLP lane row into the fixed native Iceberg contract.
/// Accepts either the `{event: "<OTLP JSON>", ...}` envelope emitted by the
/// existing transforms or the flattened OTLP object itself.
pub fn normalize_otel_row(
    dataset: OtelDataset,
    tenant_id: &str,
    input: &Value,
) -> Result<OtelLakeRow> {
    validate_tenant_id(tenant_id)?;
    let input_object = input
        .as_object()
        .context("OTLP lake input must be one JSON object")?;
    if let Some(source_type) = input_object.get("source_type").and_then(Value::as_str) {
        if source_type != dataset.source_type() {
            bail!("OTLP source_type does not match the selected native dataset");
        }
    }
    let ingest_time = input_object
        .get("ingest_time_unix_nano")
        .map(|value| {
            let nanos =
                value_u64(value).context("OTLP envelope ingest time must be nanoseconds")?;
            if nanos == 0 {
                bail!("OTLP envelope ingest time must be positive");
            }
            nanos_to_datetime(nanos)
        })
        .transpose()?;
    let event = envelope_event(input_object)?;
    match dataset {
        OtelDataset::Spans => normalize_span(tenant_id, &event, ingest_time.as_ref()),
        OtelDataset::Metrics => normalize_metric(tenant_id, &event, ingest_time.as_ref()),
    }
}

/// Decode one `nano-otlp-lake-v1` batch (JSON array or NDJSON) into its
/// untrusted envelope rows. Shared by the dedicated HTTP ingest boundary and
/// the hosted-shared handoff drain so both admit exactly the same wire
/// contract: versioned rows, one dataset per batch, and never a
/// producer-selected tenant.
pub fn decode_otel_batch(body: &[u8], dataset: OtelDataset, max_rows: usize) -> Result<Vec<Value>> {
    if body.is_empty() {
        bail!("native OTLP batch is empty");
    }
    let trimmed = body
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .map(|offset| &body[offset..])
        .unwrap_or_default();
    let rows = if trimmed.first() == Some(&b'[') {
        serde_json::from_slice::<Vec<Value>>(trimmed).context("decode OTLP JSON batch")?
    } else {
        trimmed
            .split(|byte| *byte == b'\n')
            .filter(|line| line.iter().any(|byte| !byte.is_ascii_whitespace()))
            .map(|line| serde_json::from_slice(line).context("decode OTLP NDJSON row"))
            .collect::<Result<Vec<_>>>()?
    };
    if rows.is_empty() || rows.len() > max_rows {
        bail!("native OTLP batch must contain one to {max_rows} rows");
    }
    for row in &rows {
        let object = row
            .as_object()
            .context("OTLP batch row must be an object")?;
        let version = object
            .get("schema_version")
            .and_then(Value::as_str)
            .context("OTLP lake envelope schema_version is required")?;
        if version != "nano-otlp-lake-v1" {
            bail!("OTLP lake envelope schema_version is unsupported");
        }
        let named_dataset = object
            .get("dataset")
            .and_then(Value::as_str)
            .context("OTLP lake envelope dataset is required")?;
        if named_dataset != dataset.as_str() {
            bail!("OTLP lake envelope dataset conflicts with the endpoint");
        }
        if object.contains_key("tenant_id") || object.contains_key("tenant_uid") {
            bail!("OTLP lake rows cannot select their tenant");
        }
    }
    Ok(rows)
}

/// Collapse rows that share a `row_uid` within one batch.
///
/// `row_uid` IS the idempotency identity (for metrics: sha256 over tenant,
/// timestamp and the whole event), so two rows carrying the same uid are the same
/// data point arriving twice -- a duplicate scrape, a collector retransmit, or a
/// generator emitting an identical point. Committing both would put a duplicate
/// identity in the table.
///
/// This used to be a hard `bail!`, which turned an ordinary duplicate into a
/// POISON PILL: the sender retries the identical bytes forever, and the ingest
/// service died on that batch on every restart (observed: 12 restarts in minutes,
/// zero rows landing, and a silent outage because the retry loop never surfaces).
pub fn dedupe_otel_batch(rows: &[OtelLakeRow]) -> (Vec<OtelLakeRow>, usize) {
    let mut seen = BTreeSet::new();
    let mut kept = Vec::with_capacity(rows.len());
    for row in rows {
        if seen.insert(row.row_uid.clone()) {
            kept.push(row.clone());
        }
    }
    let collapsed = rows.len() - kept.len();
    (kept, collapsed)
}

pub fn otel_batch_digest(rows: &[OtelLakeRow]) -> Result<String> {
    if rows.is_empty() || rows.len() > MAX_OTEL_BATCH_ROWS {
        bail!("OTLP batch must contain one to {MAX_OTEL_BATCH_ROWS} rows");
    }
    let dataset = rows[0].dataset;
    let mut seen = BTreeSet::new();
    let mut sorted = rows.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.row_uid.cmp(&right.row_uid));
    let mut digest = Sha256::new();
    digest.update(b"nano:otel-iceberg-batch:v1\0");
    digest.update(dataset.as_str().as_bytes());
    for row in sorted {
        if row.dataset != dataset {
            bail!("one OTLP publication batch cannot mix spans and metrics");
        }
        if !seen.insert(row.row_uid.as_str()) {
            bail!("OTLP publication batch contains a duplicate row identity");
        }
        let encoded = serde_json::to_vec(row)?;
        digest.update((encoded.len() as u64).to_be_bytes());
        digest.update(encoded);
    }
    Ok(hex::encode(digest.finalize()))
}

/// Idempotently append one native OTLP batch to its tenant-owned Iceberg table.
pub async fn publish_otel_rows(
    catalog: &RestCatalog,
    table_id: &TableIdent,
    table_location: &str,
    tenant_id: &str,
    rows: &[OtelLakeRow],
) -> Result<OtelPublishResult> {
    crate::shared_mode::require_serialized_primary_iceberg_authority(
        "native OTLP publication",
    )?;
    validate_tenant_id(tenant_id)?;
    let (deduped, collapsed) = dedupe_otel_batch(rows);
    if collapsed > 0 {
        tracing::warn!(
            collapsed,
            received = rows.len(),
            committed = deduped.len(),
            "collapsed duplicate OTLP row identities within one publication batch"
        );
    }
    let rows: &[OtelLakeRow] = &deduped;
    if rows.is_empty() {
        bail!("OTLP publication batch is empty after collapsing duplicate identities");
    }
    // The digest guard below is now a post-condition: after collapsing, a repeated
    // identity would mean the dedupe itself is broken.
    let digest = otel_batch_digest(rows)?;
    let dataset = rows[0].dataset;
    let table = ensure_otel_table(catalog, table_id, table_location, tenant_id, dataset).await?;
    if let Some(snapshot_id) = snapshot_for_batch(&table, &digest) {
        return Ok(OtelPublishResult {
            status: "already_committed",
            dataset,
            batch_sha256: digest,
            snapshot_id,
            rows: rows.len(),
            metadata_location: required_metadata_location(&table)?.to_string(),
        });
    }

    let data_files = write_otel_data_files(&table, rows, &digest).await?;
    let properties = HashMap::from([
        (
            "nano.writer".to_string(),
            "rust-native-otlp-publisher".to_string(),
        ),
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
        (
            "nano.otel-dataset".to_string(),
            dataset.as_str().to_string(),
        ),
        (
            "nano.otel-schema-version".to_string(),
            OTEL_ICEBERG_SCHEMA_VERSION.to_string(),
        ),
        (OUTBOX_BATCH_PROPERTY.to_string(), digest.clone()),
    ]);
    let commit_uuid = uuid::Uuid::from_slice(&hex::decode(&digest)?[..16])?;
    let transaction = Transaction::new(&table);
    let action = transaction
        .fast_append()
        .set_commit_uuid(commit_uuid)
        .set_snapshot_properties(properties)
        .add_data_files(data_files);
    let committed = action
        .apply(transaction)?
        .commit(catalog)
        .await
        .context("commit native OTLP Iceberg batch")?;
    let snapshot = committed
        .metadata()
        .current_snapshot()
        .context("native OTLP commit exposed no snapshot")?;
    Ok(OtelPublishResult {
        status: "committed",
        dataset,
        batch_sha256: digest,
        snapshot_id: snapshot.snapshot_id(),
        rows: rows.len(),
        metadata_location: required_metadata_location(&committed)?.to_string(),
    })
}

/// Exact trace assembly query over the native span table.
pub fn plan_trace_by_id(
    table: &OtelQuerySource,
    tenant_id: &str,
    trace_id: &str,
    limit: usize,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    validate_hex_id(trace_id, 32, "trace_id")?;
    if limit == 0 || limit > 100_001 {
        bail!("trace query limit must be between 1 and 100001");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_trace_id".to_string(), trace_id.to_ascii_lowercase()),
        ("otel_trace_limit".to_string(), limit.to_string()),
    ]);
    let sql = format!(
        "SELECT trace_id, span_id, parent_span_id, start_time, end_time, duration_ns, \
         service_name, span_name, span_kind, status_code, status_message, \
         attributes_json AS attributes, resource_attributes_json AS resource_attributes, \
         events_json AS events, links_json AS links, src_ip, dest_ip, user, host \
         FROM {source} WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND trace_id = {{otel_trace_id:String}} ORDER BY start_time ASC, span_id ASC \
         LIMIT {{otel_trace_limit:UInt32}} SETTINGS max_threads={}, max_execution_time={}, \
         max_bytes_to_read={}, max_memory_usage={}, max_result_rows=100001, \
         result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

/// Bounded, tenant-pinned recent-trace inventory for the Traces explorer.
///
/// The native table keeps one row per span, so this assembles the same one-row-
/// per-trace contract as the legacy OTLP table without exposing arbitrary SQL.
#[allow(clippy::too_many_arguments)]
pub fn plan_recent_traces(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    service_name: Option<&str>,
    errors_only: bool,
    min_duration_ns: Option<u64>,
    before: Option<DateTime<Utc>>,
    limit: u32,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if start >= end || !(1..=1_000).contains(&limit) {
        bail!("recent-trace window or limit is invalid");
    }
    if service_name.is_some_and(invalid_query_text) {
        bail!("recent-trace service_name is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
        ("otel_trace_limit".to_string(), limit.to_string()),
    ]);
    let mut having = Vec::new();
    if let Some(service_name) = service_name.filter(|value| !value.is_empty()) {
        params.push(("otel_service_name".to_string(), service_name.to_string()));
        having.push("root_service = {otel_service_name:String}".to_string());
    }
    if errors_only {
        having.push("error_count > 0".to_string());
    }
    if let Some(min_duration_ns) = min_duration_ns {
        params.push((
            "otel_min_duration_ns".to_string(),
            min_duration_ns.to_string(),
        ));
        having.push("duration_ns >= {otel_min_duration_ns:UInt64}".to_string());
    }
    if let Some(before) = before {
        params.push(("otel_before".to_string(), before.to_rfc3339()));
        having.push(
            "min(spans.start_time) < parseDateTime64BestEffort({otel_before:String}, 6, 'UTC')"
                .to_string(),
        );
    }
    let having = if having.is_empty() {
        String::new()
    } else {
        format!(" HAVING {}", having.join(" AND "))
    };
    let sql = format!(
        "SELECT trace_id, argMin(service_name, length(parent_span_id)) AS root_service, \
         argMin(span_name, length(parent_span_id)) AS root_name, count() AS span_count, \
         countIf(status_code = 'ERROR') AS error_count, \
         argMin(duration_ns, length(parent_span_id)) AS duration_ns, \
         min(start_time) AS start_time FROM {source} AS spans \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         GROUP BY trace_id{having} ORDER BY start_time DESC \
         LIMIT {{otel_trace_limit:UInt32}} SETTINGS max_threads={}, max_execution_time={}, \
         max_bytes_to_read={}, max_memory_usage={}, max_result_rows=1000, \
         result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

/// Distinct metric names for the Metrics explorer. Search caches this bounded
/// inventory; a future Iceberg maintenance rollup can replace the raw distinct
/// scan without changing this typed contract.
pub fn plan_metric_names(
    table: &OtelQuerySource,
    tenant_id: &str,
    service_name: Option<&str>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if service_name.is_some_and(invalid_query_text) {
        bail!("metric inventory service_name is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.push(("otel_tenant_id".to_string(), tenant_id.to_string()));
    let service_filter = if let Some(service_name) = service_name.filter(|value| !value.is_empty())
    {
        params.push(("otel_service_name".to_string(), service_name.to_string()));
        " AND service_name = {otel_service_name:String}"
    } else {
        ""
    };
    let sql = format!(
        "SELECT DISTINCT metric_name FROM {source} \
         WHERE tenant_uid = {{otel_tenant_id:String}}{service_filter} \
         ORDER BY metric_name ASC LIMIT 10000 SETTINGS max_threads={}, \
         max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_result_rows=10000, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

pub fn plan_metric_tag_keys(
    table: &OtelQuerySource,
    tenant_id: &str,
    metric_name: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if metric_name.is_empty() || invalid_query_text(metric_name) || start >= end {
        bail!("metric tag-key query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_metric_name".to_string(), metric_name.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let sql = format!(
        "SELECT DISTINCT arrayJoin(arrayConcat(JSONExtractKeys(attributes_json), \
         JSONExtractKeys(resource_attributes_json))) AS tag_key FROM {source} AS metrics \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metric_name = {{otel_metric_name:String}} \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND tag_key != '' ORDER BY tag_key ASC LIMIT 1001 SETTINGS max_threads={}, \
         max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_result_rows=1001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

pub fn plan_metric_tag_values(
    table: &OtelQuerySource,
    tenant_id: &str,
    metric_name: &str,
    key: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if metric_name.is_empty()
        || invalid_query_text(metric_name)
        || !valid_otel_tag_key(key)
        || start >= end
    {
        bail!("metric tag-value query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_metric_name".to_string(), metric_name.to_string()),
        ("otel_tag_key".to_string(), key.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let value = "if(JSONHas(attributes_json, {otel_tag_key:String}), \
                 JSONExtractString(attributes_json, {otel_tag_key:String}), \
                 JSONExtractString(resource_attributes_json, {otel_tag_key:String}))";
    let sql = format!(
        "SELECT DISTINCT {value} AS tag_value FROM {source} AS metrics \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metric_name = {{otel_metric_name:String}} \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND tag_value != '' ORDER BY tag_value ASC LIMIT 10001 SETTINGS max_threads={}, \
         max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_result_rows=10001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_infra_hosts(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: Option<&str>,
    group: Option<&str>,
    environment: Option<&str>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if start >= end
        || [query, group, environment]
            .into_iter()
            .flatten()
            .any(invalid_query_text)
    {
        bail!("infrastructure query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let host = "JSONExtractString(resource_attributes_json, 'host.name')";
    let host_group = "if(JSONExtractString(resource_attributes_json, 'host.group') != '', \
                      JSONExtractString(resource_attributes_json, 'host.group'), service_name)";
    let mut filters = String::new();
    if let Some(query) = query.filter(|value| !value.is_empty()) {
        params.push(("otel_host_query".to_string(), query.to_string()));
        filters.push_str(&format!(
            " AND positionCaseInsensitive({host}, {{otel_host_query:String}}) > 0"
        ));
    }
    if let Some(group) = group.filter(|value| !value.is_empty()) {
        params.push(("otel_host_group".to_string(), group.to_string()));
        filters.push_str(&format!(" AND {host_group} = {{otel_host_group:String}}"));
    }
    if let Some(environment) = environment.filter(|value| !value.is_empty()) {
        params.push(("otel_environment".to_string(), environment.to_string()));
        filters.push_str(
            " AND JSONExtractString(resource_attributes_json, 'deployment.environment') = \
             {otel_environment:String}",
        );
    }
    let sql = format!(
        "SELECT {host} AS host, any({host_group}) AS host_group, \
         argMaxIf(value, timestamp, metric_name = 'system.cpu.utilization') AS cpu_util, \
         argMaxIf(value, timestamp, metric_name = 'system.memory.utilization') AS mem_util, \
         argMaxIf(value, timestamp, metric_name = 'system.cpu.load_average.1m') AS load_1m, \
         argMaxIf(value, timestamp, metric_name = 'system.network.io') AS net_io, \
         countIf(metric_name = 'system.cpu.utilization') AS cpu_n, \
         countIf(metric_name = 'system.memory.utilization') AS mem_n, \
         countIf(metric_name = 'system.cpu.load_average.1m') AS load_n, \
         countIf(metric_name = 'system.network.io') AS net_n \
         FROM {source} AS metrics WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND {host} != ''{filters} GROUP BY host ORDER BY host ASC LIMIT 10001 \
         SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=10001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_services_overview(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: Option<&str>,
    sort: OtelServicesSort,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if start >= end || query.is_some_and(invalid_query_text) {
        bail!("services overview window or query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let query_filter = if let Some(query) = query.filter(|value| !value.is_empty()) {
        params.push(("otel_service_query".to_string(), query.to_string()));
        " AND positionCaseInsensitive(service_name, {otel_service_query:String}) > 0"
    } else {
        ""
    };
    let sql = format!(
        "SELECT service_name AS service, count() AS request_count, \
         countIf(status_code = 'ERROR') AS error_count, \
         quantileTDigest(0.50)(duration_ns) / 1000000.0 AS p50_ms, \
         quantileTDigest(0.95)(duration_ns) / 1000000.0 AS p95_ms, \
         quantileTDigest(0.99)(duration_ns) / 1000000.0 AS p99_ms \
         FROM {source} AS spans WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND service_name != ''{query_filter} GROUP BY service_name \
         ORDER BY {} LIMIT 1001 SETTINGS max_threads={}, max_execution_time={}, \
         max_bytes_to_read={}, max_memory_usage={}, max_result_rows=1001, \
         result_overflow_mode='throw'",
        sort.sql_order(),
        table.threads,
        table.max_execution_seconds,
        table.max_query_bytes,
        table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

pub fn plan_services_sparkline(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    step_seconds: u32,
    query: Option<&str>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if start >= end
        || step_seconds == 0
        || step_seconds > 86_400
        || query.is_some_and(invalid_query_text)
    {
        bail!("services sparkline window or step is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
        ("otel_step".to_string(), step_seconds.to_string()),
    ]);
    let query_filter = if let Some(query) = query.filter(|value| !value.is_empty()) {
        params.push(("otel_service_query".to_string(), query.to_string()));
        " AND positionCaseInsensitive(service_name, {otel_service_query:String}) > 0"
    } else {
        ""
    };
    let sql = format!(
        "SELECT service_name AS service, \
         toStartOfInterval(start_time, toIntervalSecond({{otel_step:UInt32}})) AS bucket, \
         count() AS v FROM {source} AS spans \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND service_name != ''{query_filter} GROUP BY service, bucket \
         ORDER BY service ASC, bucket ASC \
         LIMIT 200001 SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=200001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

pub fn plan_service_red(
    table: &OtelQuerySource,
    tenant_id: &str,
    service: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    step_seconds: u32,
) -> Result<OtelNativeQueryPlan> {
    let (source, params) =
        service_query_base(table, tenant_id, service, start, end, Some(step_seconds))?;
    let sql = format!(
        "SELECT toStartOfInterval(start_time, toIntervalSecond({{otel_step:UInt32}})) AS bucket, \
         count() AS rate_count, countIf(status_code = 'ERROR') AS error_count, \
         quantileTDigest(0.50)(duration_ns) / 1000000.0 AS p50_ms, \
         quantileTDigest(0.95)(duration_ns) / 1000000.0 AS p95_ms, \
         quantileTDigest(0.99)(duration_ns) / 1000000.0 AS p99_ms \
         FROM {source} AS spans WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND service_name = {{otel_service_name:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         GROUP BY bucket ORDER BY bucket ASC LIMIT 100001 SETTINGS max_threads={}, \
         max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_result_rows=100001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

pub fn plan_service_endpoints(
    table: &OtelQuerySource,
    tenant_id: &str,
    service: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<OtelNativeQueryPlan> {
    let (source, params) = service_query_base(table, tenant_id, service, start, end, None)?;
    let sql = format!(
        "SELECT span_name, count() AS request_count, \
         countIf(status_code = 'ERROR') AS error_count, \
         quantileTDigest(0.95)(duration_ns) / 1000000.0 AS p95_ms \
         FROM {source} AS spans WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND service_name = {{otel_service_name:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND span_name != '' GROUP BY span_name ORDER BY request_count DESC, span_name ASC \
         LIMIT 1001 SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=1001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

pub fn plan_service_exemplars(
    table: &OtelQuerySource,
    tenant_id: &str,
    service: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: u32,
) -> Result<OtelNativeQueryPlan> {
    if !(1..=200).contains(&limit) {
        bail!("service exemplar limit is invalid");
    }
    let (source, mut params) = service_query_base(table, tenant_id, service, start, end, None)?;
    params.push(("otel_exemplar_limit".to_string(), limit.to_string()));
    let sql = format!(
        "SELECT trace_id, duration_ns / 1000000.0 AS duration_ms, \
         status_code = 'ERROR' AS error, start_time, span_name \
         FROM {source} AS spans WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND service_name = {{otel_service_name:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         ORDER BY error DESC, start_time DESC LIMIT {{otel_exemplar_limit:UInt32}} \
         SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=200, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

fn service_query_base(
    table: &OtelQuerySource,
    tenant_id: &str,
    service: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    step_seconds: Option<u32>,
) -> Result<(String, Vec<(String, String)>)> {
    validate_tenant_id(tenant_id)?;
    if service.is_empty()
        || invalid_query_text(service)
        || start >= end
        || step_seconds.is_some_and(|step| step == 0 || step > 86_400)
    {
        bail!("service detail query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_service_name".to_string(), service.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    if let Some(step_seconds) = step_seconds {
        params.push(("otel_step".to_string(), step_seconds.to_string()));
    }
    Ok((source, params))
}

pub fn plan_rum_vitals(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    environment: Option<&str>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if start >= end || environment.is_some_and(invalid_query_text) {
        bail!("RUM vitals query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let environment_filter =
        if let Some(environment) = environment.filter(|value| !value.is_empty()) {
            params.push(("otel_environment".to_string(), environment.to_string()));
            " AND JSONExtractString(resource_attributes_json, 'deployment.environment') = \
         {otel_environment:String}"
        } else {
            ""
        };
    let sql = format!(
        "SELECT quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.lcp') AS lcp_ms, \
         quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.inp') AS inp_ms, \
         quantileTDigestIf(0.75)(value, metric_name = 'web.vitals.cls') AS cls, \
         countIf(metric_name = 'web.vitals.lcp') AS lcp_n, \
         countIf(metric_name = 'web.vitals.inp') AS inp_n, \
         countIf(metric_name = 'web.vitals.cls') AS cls_n FROM {source} AS metrics \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND metric_name IN ('web.vitals.lcp', 'web.vitals.inp', 'web.vitals.cls') \
         {environment_filter} LIMIT 1 SETTINGS max_threads={}, max_execution_time={}, \
         max_bytes_to_read={}, max_memory_usage={}, max_result_rows=1, \
         result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_rum_series(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    step_seconds: u32,
    page: Option<&str>,
    browser: Option<&str>,
    environment: Option<&str>,
) -> Result<OtelNativeQueryPlan> {
    let (source, params, filters) = rum_span_query_base(
        table,
        tenant_id,
        start,
        end,
        page,
        browser,
        environment,
        Some(step_seconds),
    )?;
    let page_url = "JSONExtractString(attributes_json, 'page.url')";
    let exception_type = "JSONExtractString(attributes_json, 'exception.type')";
    let sql = format!(
        "SELECT toStartOfInterval(start_time, toIntervalSecond({{otel_step:UInt32}})) AS bucket, \
         countIf({page_url} != '' OR startsWith(span_name, 'pageview')) AS views, \
         countIf(status_code = 'ERROR' AND {exception_type} != '') AS js_errors \
         FROM {source} AS spans WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         {filters} GROUP BY bucket ORDER BY bucket ASC LIMIT 100001 SETTINGS max_threads={}, \
         max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_result_rows=100001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_rum_top_pages(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    page: Option<&str>,
    browser: Option<&str>,
    environment: Option<&str>,
) -> Result<OtelNativeQueryPlan> {
    let (source, params, filters) = rum_span_query_base(
        table,
        tenant_id,
        start,
        end,
        page,
        browser,
        environment,
        None,
    )?;
    let page_url = "JSONExtractString(attributes_json, 'page.url')";
    let lcp = "toFloat64OrNull(JSONExtractString(attributes_json, 'web.vitals.lcp'))";
    let sql = format!(
        "SELECT {page_url} AS page, count() AS views, \
         quantileTDigestIf(0.75)({lcp}, {lcp} IS NOT NULL) AS lcp_ms \
         FROM {source} AS spans WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND {page_url} != '' {filters} GROUP BY page ORDER BY views DESC, page ASC \
         LIMIT 10 SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=10, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_rum_recent_errors(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    page: Option<&str>,
    browser: Option<&str>,
    environment: Option<&str>,
) -> Result<OtelNativeQueryPlan> {
    let (source, params, filters) = rum_span_query_base(
        table,
        tenant_id,
        start,
        end,
        page,
        browser,
        environment,
        None,
    )?;
    let exception_type = "JSONExtractString(attributes_json, 'exception.type')";
    let exception_message = "JSONExtractString(attributes_json, 'exception.message')";
    let page_url = "JSONExtractString(attributes_json, 'page.url')";
    let session = "JSONExtractString(attributes_json, 'session.id')";
    let sql = format!(
        "SELECT if({exception_message} != '', {exception_message}, status_message) AS message, \
         {page_url} AS page, formatDateTime(start_time, '%Y-%m-%dT%H:%i:%S.%fZ') AS ts, \
         src_ip, user, {session} AS session FROM {source} AS spans \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND status_code = 'ERROR' AND {exception_type} != '' {filters} \
         ORDER BY start_time DESC LIMIT 20 SETTINGS max_threads={}, max_execution_time={}, \
         max_bytes_to_read={}, max_memory_usage={}, max_result_rows=20, \
         result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

#[allow(clippy::too_many_arguments)]
fn rum_span_query_base(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    page: Option<&str>,
    browser: Option<&str>,
    environment: Option<&str>,
    step_seconds: Option<u32>,
) -> Result<(String, Vec<(String, String)>, String)> {
    validate_tenant_id(tenant_id)?;
    if start >= end
        || [page, browser, environment]
            .into_iter()
            .flatten()
            .any(invalid_query_text)
        || step_seconds.is_some_and(|step| step == 0 || step > 86_400)
    {
        bail!("RUM span query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    if let Some(step_seconds) = step_seconds {
        params.push(("otel_step".to_string(), step_seconds.to_string()));
    }
    let mut filters = String::new();
    if let Some(page) = page.filter(|value| !value.is_empty()) {
        params.push(("otel_page".to_string(), page.to_string()));
        filters.push_str(
            " AND positionCaseInsensitive(JSONExtractString(attributes_json, 'page.url'), \
             {otel_page:String}) > 0",
        );
    }
    if let Some(browser) = browser.filter(|value| !value.is_empty()) {
        params.push(("otel_browser".to_string(), browser.to_string()));
        filters.push_str(
            " AND JSONExtractString(attributes_json, 'browser.name') = {otel_browser:String}",
        );
    }
    if let Some(environment) = environment.filter(|value| !value.is_empty()) {
        params.push(("otel_environment".to_string(), environment.to_string()));
        filters.push_str(
            " AND JSONExtractString(resource_attributes_json, 'deployment.environment') = \
             {otel_environment:String}",
        );
    }
    Ok((source, params, filters))
}

#[allow(clippy::too_many_arguments)]
pub fn plan_metric_timeseries(
    table: &OtelQuerySource,
    tenant_id: &str,
    metric_name: &str,
    service_name: Option<&str>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    step_seconds: u32,
    aggregate: MetricAggregate,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if metric_name.is_empty()
        || metric_name.len() > 1_024
        || metric_name.chars().any(char::is_control)
        || start >= end
        || step_seconds == 0
        || step_seconds > 86_400
    {
        bail!("metric query identity, window, or step is invalid");
    }
    if service_name.is_some_and(|value| value.len() > 1_024 || value.chars().any(char::is_control))
    {
        bail!("metric service_name is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_metric_name".to_string(), metric_name.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
        ("otel_step".to_string(), step_seconds.to_string()),
    ]);
    let service_filter = if let Some(service_name) = service_name.filter(|value| !value.is_empty())
    {
        params.push(("otel_service_name".to_string(), service_name.to_string()));
        " AND service_name = {otel_service_name:String}"
    } else {
        ""
    };
    let sql = format!(
        "SELECT toStartOfInterval(timestamp, toIntervalSecond({{otel_step:UInt32}})) AS t, \
         {} AS v FROM {source} WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metric_name = {{otel_metric_name:String}}{service_filter} \
         AND timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         GROUP BY t ORDER BY t ASC SETTINGS max_threads={}, max_execution_time={}, \
         max_bytes_to_read={}, max_memory_usage={}, max_result_rows=100000, \
         result_overflow_mode='throw'",
        aggregate.sql(),
        table.threads,
        table.max_execution_seconds,
        table.max_query_bytes,
        table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

#[allow(clippy::too_many_arguments)]
pub fn plan_metric_timeseries_v2(
    table: &OtelQuerySource,
    tenant_id: &str,
    metric_name: &str,
    service_name: Option<&str>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    step_seconds: u32,
    aggregate: MetricAggregate,
    group_by: Option<&str>,
    filters: &[OtelMetricTagFilter],
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if metric_name.is_empty()
        || invalid_query_text(metric_name)
        || service_name.is_some_and(invalid_query_text)
        || start >= end
        || step_seconds == 0
        || step_seconds > 86_400
        || group_by.is_some_and(|key| !valid_otel_tag_key(key))
        || filters.len() > 32
        || filters
            .iter()
            .any(|filter| !valid_otel_tag_key(&filter.key) || invalid_query_text(&filter.value))
    {
        bail!("metric v2 query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_metric_name".to_string(), metric_name.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
        ("otel_step".to_string(), step_seconds.to_string()),
    ]);
    let mut predicates = String::new();
    if let Some(service_name) = service_name.filter(|value| !value.is_empty()) {
        params.push(("otel_service_name".to_string(), service_name.to_string()));
        predicates.push_str(" AND service_name = {otel_service_name:String}");
    }
    for (index, filter) in filters.iter().enumerate() {
        let key_name = format!("otel_filter_key_{index}");
        let value_name = format!("otel_filter_value_{index}");
        params.push((key_name.clone(), filter.key.clone()));
        params.push((value_name.clone(), filter.value.clone()));
        predicates.push_str(&format!(
            " AND {} = {{{value_name}:String}}",
            json_tag_lookup(&key_name)
        ));
    }
    let (series_select, group_clause) = if let Some(group_by) = group_by {
        params.push(("otel_group_key".to_string(), group_by.to_string()));
        (json_tag_lookup("otel_group_key"), "series_key, bucket")
    } else {
        ("''".to_string(), "bucket")
    };
    let sql = format!(
        "SELECT {series_select} AS series_key, \
         toStartOfInterval(timestamp, toIntervalSecond({{otel_step:UInt32}})) AS bucket, \
         {} AS v FROM {source} AS metrics WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metric_name = {{otel_metric_name:String}} \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         {predicates} GROUP BY {group_clause} ORDER BY series_key ASC, bucket ASC \
         LIMIT 200001 SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=200001, result_overflow_mode='throw'",
        aggregate.sql(),
        table.threads,
        table.max_execution_seconds,
        table.max_query_bytes,
        table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

/// Compute one metric scalar per optional tag group over the exact requested
/// window. This is the unattended monitor lane: it deliberately has no time
/// bucket, preserves no-data as NULL/absence, and returns cap+1 so the caller
/// can reject excessive cardinality instead of silently dropping series.
#[allow(clippy::too_many_arguments)]
pub fn plan_metric_scalar_v2(
    table: &OtelQuerySource,
    tenant_id: &str,
    metric_name: &str,
    service_name: Option<&str>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    aggregate: MetricAggregate,
    group_by: Option<&str>,
    filters: &[OtelMetricTagFilter],
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if metric_name.is_empty()
        || invalid_query_text(metric_name)
        || service_name.is_some_and(invalid_query_text)
        || start >= end
        || group_by.is_some_and(|key| !valid_otel_tag_key(key))
        || filters.len() > 32
        || filters
            .iter()
            .any(|filter| !valid_otel_tag_key(&filter.key) || invalid_query_text(&filter.value))
    {
        bail!("metric scalar query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_metric_name".to_string(), metric_name.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let mut predicates = String::new();
    if let Some(service_name) = service_name.filter(|value| !value.is_empty()) {
        params.push(("otel_service_name".to_string(), service_name.to_string()));
        predicates.push_str(" AND service_name = {otel_service_name:String}");
    }
    for (index, filter) in filters.iter().enumerate() {
        let key_name = format!("otel_filter_key_{index}");
        let value_name = format!("otel_filter_value_{index}");
        params.push((key_name.clone(), filter.key.clone()));
        params.push((value_name.clone(), filter.value.clone()));
        predicates.push_str(&format!(
            " AND {} = {{{value_name}:String}}",
            json_tag_lookup(&key_name)
        ));
    }
    let (series_select, group_clause) = if let Some(group_by) = group_by {
        params.push(("otel_group_key".to_string(), group_by.to_string()));
        (json_tag_lookup("otel_group_key"), " GROUP BY series_key")
    } else {
        ("''".to_string(), "")
    };
    let sql = format!(
        "SELECT {series_select} AS series_key, {} AS v, count() AS row_count \
         FROM {source} AS metrics WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metric_name = {{otel_metric_name:String}} \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         {predicates}{group_clause} ORDER BY series_key ASC LIMIT 10001 \
         SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=10001, result_overflow_mode='throw'",
        aggregate.sql(),
        table.threads,
        table.max_execution_seconds,
        table.max_query_bytes,
        table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

/// Per-check synthetic probe summaries stored as native OTLP metrics. The
/// probe result itself rides the normal Vector OTLP batching/durable-buffer
/// path under the `nano.synthetic.probe` metric name; these plans only read
/// the committed Iceberg metric rows.
pub fn plan_synthetic_summary(
    table: &OtelQuerySource,
    tenant_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if start >= end {
        bail!("synthetic summary window is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let check_id = "JSONExtractString(attributes_json, 'synthetic.check_id')";
    let success = "JSONExtractString(attributes_json, 'synthetic.success') IN ('true', '1')";
    let sql = format!(
        "SELECT {check_id} AS check_id, count() AS total, countIf({success}) AS good, \
         quantileTDigest(0.50)(value) AS p50_latency_ms FROM {source} AS metrics \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metric_name = 'nano.synthetic.probe' \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         AND {check_id} != '' GROUP BY check_id ORDER BY check_id ASC LIMIT 100001 \
         SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=100001, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

pub fn plan_synthetic_history(
    table: &OtelQuerySource,
    tenant_id: &str,
    check_id: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    limit: u32,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if check_id.is_empty()
        || check_id.len() > 128
        || invalid_query_text(check_id)
        || start >= end
        || !(1..=365).contains(&limit)
    {
        bail!("synthetic history query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_check_id".to_string(), check_id.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
        ("otel_limit".to_string(), limit.to_string()),
    ]);
    let sql = format!(
        "SELECT JSONExtractString(attributes_json, 'synthetic.success') IN ('true', '1') AS success, \
         value AS latency_ms, formatDateTime(timestamp, '%Y-%m-%dT%H:%i:%S.%fZ') AS ts, \
         toUInt16OrZero(JSONExtractString(attributes_json, 'http.status_code')) AS status_code, \
         JSONExtractString(attributes_json, 'error.message') AS error \
         FROM {source} AS metrics WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND metric_name = 'nano.synthetic.probe' \
         AND JSONExtractString(attributes_json, 'synthetic.check_id') = {{otel_check_id:String}} \
         AND metrics.timestamp >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND metrics.timestamp < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         ORDER BY timestamp DESC LIMIT {{otel_limit:UInt32}} SETTINGS max_threads={}, \
         max_execution_time={}, max_bytes_to_read={}, max_memory_usage={}, \
         max_result_rows=365, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

/// Compute the numerator and denominator for one service SLO directly from
/// the native span table. Mutable SLO definitions and alert state remain in
/// PostgreSQL; this plan reads only tenant-pinned immutable telemetry.
pub fn plan_slo_compute(
    table: &OtelQuerySource,
    tenant_id: &str,
    service_name: &str,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    kind: OtelSliKind,
    latency_threshold_ms: Option<f64>,
) -> Result<OtelNativeQueryPlan> {
    validate_tenant_id(tenant_id)?;
    if service_name.is_empty()
        || invalid_query_text(service_name)
        || start >= end
        || (kind == OtelSliKind::Latency
            && !latency_threshold_ms.is_some_and(|value| value.is_finite() && value >= 0.0))
    {
        bail!("SLO query is invalid");
    }
    let (source, mut params) = trusted_otel_source(table)?;
    params.extend([
        ("otel_tenant_id".to_string(), tenant_id.to_string()),
        ("otel_service_name".to_string(), service_name.to_string()),
        ("otel_start".to_string(), start.to_rfc3339()),
        ("otel_end".to_string(), end.to_rfc3339()),
    ]);
    let good = match kind {
        OtelSliKind::Availability => "countIf(status_code != 'ERROR')".to_string(),
        OtelSliKind::Latency => {
            let threshold_ns = (latency_threshold_ms.unwrap_or_default() * 1_000_000.0)
                .round()
                .clamp(0.0, u64::MAX as f64) as u64;
            params.push(("otel_latency_ns".to_string(), threshold_ns.to_string()));
            "countIf(duration_ns <= {otel_latency_ns:UInt64})".to_string()
        }
    };
    let sql = format!(
        "SELECT count() AS total, {good} AS good FROM {source} AS spans \
         WHERE tenant_uid = {{otel_tenant_id:String}} \
         AND service_name = {{otel_service_name:String}} \
         AND spans.start_time >= parseDateTime64BestEffort({{otel_start:String}}, 6, 'UTC') \
         AND spans.start_time < parseDateTime64BestEffort({{otel_end:String}}, 6, 'UTC') \
         LIMIT 1 SETTINGS max_threads={}, max_execution_time={}, max_bytes_to_read={}, \
         max_memory_usage={}, max_result_rows=1, result_overflow_mode='throw'",
        table.threads, table.max_execution_seconds, table.max_query_bytes, table.max_memory_bytes,
    );
    Ok(OtelNativeQueryPlan { sql, params })
}

fn json_tag_lookup(key_parameter: &str) -> String {
    format!(
        "if(JSONHas(attributes_json, {{{key_parameter}:String}}), \
         JSONExtractString(attributes_json, {{{key_parameter}:String}}), \
         JSONExtractString(resource_attributes_json, {{{key_parameter}:String}}))"
    )
}

fn validate_tenant_id(tenant_id: &str) -> Result<()> {
    if tenant_id.is_empty() || tenant_id.len() > 256 || tenant_id.chars().any(char::is_control) {
        bail!("OTLP tenant identity is invalid");
    }
    Ok(())
}

fn invalid_query_text(value: &str) -> bool {
    value.len() > 1_024 || value.chars().any(char::is_control)
}

fn valid_otel_tag_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 256
        && key.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/' | ':')
        })
}

fn envelope_event(input: &Map<String, Value>) -> Result<Map<String, Value>> {
    match input.get("event") {
        Some(Value::String(encoded)) => serde_json::from_str::<Value>(encoded)
            .context("decode flattened OTLP event JSON")?
            .as_object()
            .cloned()
            .context("flattened OTLP event must decode to an object"),
        Some(Value::Object(event)) => Ok(event.clone()),
        Some(_) => bail!("flattened OTLP event must be a JSON object or encoded object"),
        None => Ok(input.clone()),
    }
}

fn normalize_span(
    tenant_id: &str,
    event: &Map<String, Value>,
    ingest_time: Option<&DateTime<Utc>>,
) -> Result<OtelLakeRow> {
    let trace_id = required_string(event, "traceId")?.to_ascii_lowercase();
    let span_id = required_string(event, "spanId")?.to_ascii_lowercase();
    validate_hex_id(&trace_id, 32, "trace_id")?;
    validate_hex_id(&span_id, 16, "span_id")?;
    let parent_span_id = optional_string(event, "parentSpanId").to_ascii_lowercase();
    if !parent_span_id.is_empty() {
        validate_hex_id(&parent_span_id, 16, "parent_span_id")?;
    }
    let start_nanos = required_u64(event, "startTimeUnixNano")?;
    let end_nanos = required_u64(event, "endTimeUnixNano")?;
    if start_nanos == 0 || end_nanos < start_nanos {
        bail!("OTLP span time range is invalid");
    }
    let start_time = nanos_to_datetime(start_nanos)?;
    let end_time = nanos_to_datetime(end_nanos)?;
    let attributes = flatten_attributes(event.get("attributes"))?;
    let resource = event
        .get("resource")
        .and_then(Value::as_object)
        .and_then(|value| value.get("attributes"));
    let resource_attributes = flatten_attributes(resource)?;
    let service_name = resource_attributes
        .get("service.name")
        .cloned()
        .unwrap_or_default();
    let src_ip = attributes
        .get("client.address")
        .or_else(|| attributes.get("network.peer.address"))
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let dest_ip = attributes
        .get("server.address")
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let user = attributes
        .get("enduser.id")
        .or_else(|| attributes.get("user.name"))
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let host = resource_attributes
        .get("host.name")
        .or_else(|| attributes.get("host.name"))
        .cloned()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let status = event.get("status").and_then(Value::as_object);
    let status_number = status
        .and_then(|value| value.get("code"))
        .and_then(value_i64)
        .unwrap_or(0);
    let status_code = match status_number {
        1 => "OK",
        2 => "ERROR",
        _ => "UNSET",
    };
    let kind = event.get("kind").and_then(value_i64).unwrap_or(0);
    let span_kind = match kind {
        2 => "SERVER",
        3 => "CLIENT",
        4 => "PRODUCER",
        5 => "CONSUMER",
        _ => "INTERNAL",
    };
    let row_uid = format!("{trace_id}:{span_id}:{start_nanos}");
    let canonical = json!({
        "tenant_uid": tenant_id,
        "trace_id": trace_id,
        "span_id": span_id,
        "parent_span_id": parent_span_id,
        "start_time": start_time.to_rfc3339_opts(SecondsFormat::Micros, true),
        "end_time": end_time.to_rfc3339_opts(SecondsFormat::Micros, true),
        "duration_ns": i64::try_from(end_nanos - start_nanos).context("span duration exceeds signed storage")?,
        "service_name": service_name,
        "span_name": optional_string(event, "name"),
        "span_kind": span_kind,
        "status_code": status_code,
        "status_message": status.and_then(|value| value.get("message")).and_then(Value::as_str).unwrap_or(""),
        "attributes_json": serde_json::to_string(&attributes)?,
        "resource_attributes_json": serde_json::to_string(&resource_attributes)?,
        "events_json": serde_json::to_string(event.get("events").unwrap_or(&Value::Array(Vec::new())))?,
        "links_json": serde_json::to_string(event.get("links").unwrap_or(&Value::Array(Vec::new())))?,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "user": user,
        "host": host,
        // Vector stamps this before its durable buffer, so an exact delivery
        // retry preserves both the actual receive time and the batch digest.
        // Direct callers without an envelope fall back to event time.
        "ingest_time": ingest_time.unwrap_or(&start_time).to_rfc3339_opts(SecondsFormat::Micros, true),
        "raw_otlp_json": serde_json::to_string(event)?,
    });
    Ok(OtelLakeRow {
        row_uid,
        dataset: OtelDataset::Spans,
        event_hour: event_hour(start_time)?,
        row: canonical,
    })
}

fn normalize_metric(
    tenant_id: &str,
    event: &Map<String, Value>,
    ingest_time: Option<&DateTime<Utc>>,
) -> Result<OtelLakeRow> {
    let metric_name = required_string(event, "name")?;
    if metric_name.len() > 1_024 || metric_name.chars().any(char::is_control) {
        bail!("OTLP metric name is invalid");
    }
    let time_nanos = required_u64(event, "timeUnixNano")?;
    if time_nanos == 0 {
        bail!("OTLP metric time must be positive");
    }
    let timestamp = nanos_to_datetime(time_nanos)?;
    let attributes = flatten_attributes(event.get("attributes"))?;
    let resource = event
        .get("resource")
        .and_then(Value::as_object)
        .and_then(|value| value.get("attributes"));
    let resource_attributes = flatten_attributes(resource)?;
    let service_name = resource_attributes
        .get("service.name")
        .cloned()
        .unwrap_or_default();
    let metric_type = optional_string(event, "type");
    let metric_type = if metric_type.is_empty() {
        if event.get("bucketCounts").is_some_and(Value::is_array) {
            "histogram".to_string()
        } else {
            "gauge".to_string()
        }
    } else {
        metric_type.to_ascii_lowercase()
    };
    if !matches!(metric_type.as_str(), "gauge" | "sum" | "histogram") {
        bail!("OTLP metric type is unsupported");
    }
    let value = event
        .get("asInt")
        .or_else(|| event.get("asDouble"))
        .and_then(value_f64)
        .unwrap_or(0.0);
    if !value.is_finite() {
        bail!("OTLP metric scalar must be finite");
    }
    let count = event.get("count").and_then(value_u64).unwrap_or(0);
    let count = i64::try_from(count).context("OTLP histogram count exceeds signed storage")?;
    let sum = event.get("sum").and_then(value_f64).unwrap_or(0.0);
    if !sum.is_finite() {
        bail!("OTLP histogram sum must be finite");
    }
    let bucket_counts = integer_array(event.get("bucketCounts"))?;
    let explicit_bounds = float_array(event.get("explicitBounds"))?;
    if !bucket_counts.is_empty() && bucket_counts.len() != explicit_bounds.len() + 1 {
        bail!("OTLP histogram bucketCounts must have one more item than explicitBounds");
    }
    let canonical = json!({
        "tenant_uid": tenant_id,
        "metric_uid": "",
        "metric_name": metric_name,
        "metric_type": metric_type,
        "unit": optional_string(event, "unit"),
        "timestamp": timestamp.to_rfc3339_opts(SecondsFormat::Micros, true),
        "value": value,
        "count": count,
        "sum": sum,
        "bucket_counts": bucket_counts,
        "explicit_bounds": explicit_bounds,
        "aggregation_temporality": event.get("aggregationTemporality").and_then(value_i64).unwrap_or(0),
        "attributes_json": serde_json::to_string(&attributes)?,
        "resource_attributes_json": serde_json::to_string(&resource_attributes)?,
        "service_name": service_name,
        "ingest_time": ingest_time.unwrap_or(&timestamp).to_rfc3339_opts(SecondsFormat::Micros, true),
        "raw_otlp_json": serde_json::to_string(event)?,
    });
    let mut uid_hash = Sha256::new();
    uid_hash.update(b"nano:otlp-metric-row:v1\0");
    uid_hash.update(tenant_id.as_bytes());
    uid_hash.update(time_nanos.to_be_bytes());
    uid_hash.update(serde_json::to_vec(event)?);
    let row_uid = hex::encode(uid_hash.finalize());
    let mut canonical = canonical;
    canonical["metric_uid"] = Value::String(row_uid.clone());
    Ok(OtelLakeRow {
        row_uid,
        dataset: OtelDataset::Metrics,
        event_hour: event_hour(timestamp)?,
        row: canonical,
    })
}

fn envelope_string(value: &Value) -> Option<String> {
    match value {
        Value::String(value) => Some(value.clone()),
        Value::Bool(value) => Some(value.to_string()),
        Value::Number(value) => Some(value.to_string()),
        Value::Null => None,
        other => serde_json::to_string(other).ok(),
    }
}

fn flatten_attributes(value: Option<&Value>) -> Result<BTreeMap<String, String>> {
    let Some(values) = value else {
        return Ok(BTreeMap::new());
    };
    let values = values
        .as_array()
        .context("OTLP attributes must be a KeyValue array")?;
    let mut output = BTreeMap::new();
    for entry in values {
        let entry = entry
            .as_object()
            .context("OTLP attribute must be an object")?;
        let key = required_string(entry, "key")?;
        if key.len() > 1_024 || key.chars().any(char::is_control) {
            bail!("OTLP attribute key is invalid");
        }
        let any_value = entry
            .get("value")
            .and_then(Value::as_object)
            .context("OTLP attribute has no AnyValue object")?;
        let value = [
            "stringValue",
            "intValue",
            "doubleValue",
            "boolValue",
            "bytesValue",
            "arrayValue",
            "kvlistValue",
        ]
        .iter()
        .find_map(|name| any_value.get(*name).and_then(envelope_string))
        .unwrap_or_default();
        if output.insert(key.to_string(), value).is_some() {
            bail!("OTLP attribute array contains duplicate key {key}");
        }
    }
    Ok(output)
}

fn required_string<'a>(object: &'a Map<String, Value>, name: &str) -> Result<&'a str> {
    object
        .get(name)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .with_context(|| format!("OTLP field {name} must be a non-empty string"))
}

fn optional_string(object: &Map<String, Value>, name: &str) -> String {
    object
        .get(name)
        .and_then(envelope_string)
        .unwrap_or_default()
}

fn required_u64(object: &Map<String, Value>, name: &str) -> Result<u64> {
    object
        .get(name)
        .and_then(value_u64)
        .with_context(|| format!("OTLP field {name} must be an unsigned integer"))
}

fn value_u64(value: &Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str()?.parse::<u64>().ok())
}

fn value_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str()?.parse::<i64>().ok())
}

fn value_f64(value: &Value) -> Option<f64> {
    value
        .as_f64()
        .or_else(|| value.as_str()?.parse::<f64>().ok())
}

fn integer_array(value: Option<&Value>) -> Result<Vec<i64>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .context("OTLP integer array is not an array")?
        .iter()
        .map(|value| {
            let value = value_u64(value).context("OTLP integer array contains a non-integer")?;
            i64::try_from(value).context("OTLP integer array value exceeds signed storage")
        })
        .collect()
}

fn float_array(value: Option<&Value>) -> Result<Vec<f64>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };
    value
        .as_array()
        .context("OTLP float array is not an array")?
        .iter()
        .map(|value| {
            let value = value_f64(value).context("OTLP float array contains a non-number")?;
            if !value.is_finite() {
                bail!("OTLP float array contains a non-finite value");
            }
            Ok(value)
        })
        .collect()
}

fn validate_hex_id(value: &str, length: usize, name: &str) -> Result<()> {
    if value.len() != length || !value.bytes().all(|value| value.is_ascii_hexdigit()) {
        bail!("OTLP {name} must be exactly {length} hexadecimal characters");
    }
    Ok(())
}

fn nanos_to_datetime(value: u64) -> Result<DateTime<Utc>> {
    let seconds = i64::try_from(value / 1_000_000_000).context("OTLP timestamp is out of range")?;
    let nanos = u32::try_from(value % 1_000_000_000)?;
    DateTime::from_timestamp(seconds, nanos).context("OTLP timestamp is out of range")
}

fn event_hour(value: DateTime<Utc>) -> Result<i32> {
    i32::try_from(value.timestamp().div_euclid(3_600)).context("OTLP event hour is out of range")
}

async fn ensure_otel_table(
    catalog: &RestCatalog,
    table_id: &TableIdent,
    location: &str,
    tenant_id: &str,
    dataset: OtelDataset,
) -> Result<Table> {
    if catalog.table_exists(table_id).await? {
        let table = catalog.load_table(table_id).await?;
        let properties = table.metadata().properties();
        if !same_table_location(table.metadata().location(), location)
            || properties.get("nano.tenant-id").map(String::as_str) != Some(tenant_id)
            || properties.get("nano.otel-dataset").map(String::as_str) != Some(dataset.as_str())
            || properties
                .get("nano.otel-schema-version")
                .map(String::as_str)
                != Some(OTEL_ICEBERG_SCHEMA_VERSION)
        {
            bail!("existing native OTLP table does not match its tenant, dataset, or schema fence");
        }
        return Ok(table);
    }
    if !catalog.namespace_exists(&table_id.namespace).await? {
        catalog
            .create_namespace(&table_id.namespace, HashMap::new())
            .await?;
    }
    let arrow_schema = otel_arrow_schema(dataset);
    let iceberg_schema = iceberg::arrow::arrow_schema_to_schema_auto_assign_ids(&arrow_schema)
        .context("convert native OTLP Arrow schema to Iceberg")?;
    let time_field_id = iceberg_schema
        .field_by_name(dataset.time_field())
        .context("native OTLP schema has no event-time field")?
        .id;
    let properties = HashMap::from([
        ("format-version".to_string(), "2".to_string()),
        (
            "write.parquet.compression-codec".to_string(),
            "zstd".to_string(),
        ),
        (
            "write.metadata.delete-after-commit.enabled".to_string(),
            "false".to_string(),
        ),
        (
            "write.metadata.previous-versions-max".to_string(),
            "10".to_string(),
        ),
        ("nano.tenant-id".to_string(), tenant_id.to_string()),
        (
            "nano.otel-dataset".to_string(),
            dataset.as_str().to_string(),
        ),
        (
            "nano.otel-schema-version".to_string(),
            OTEL_ICEBERG_SCHEMA_VERSION.to_string(),
        ),
    ]);
    let creation = TableCreation::builder()
        .name(table_id.name.clone())
        .location(location.to_string())
        .schema(iceberg_schema)
        .partition_spec(hour_partition_spec(time_field_id, dataset.time_field())?)
        .properties(properties)
        .build();
    catalog
        .create_table(&table_id.namespace, creation)
        .await
        .context("create native OTLP Iceberg table")
}

fn same_table_location(actual: &str, assigned: &str) -> bool {
    actual.trim_end_matches('/') == assigned.trim_end_matches('/')
}

fn hour_partition_spec(time_field_id: i32, time_field: &str) -> Result<UnboundPartitionSpec> {
    let partition_field = UnboundPartitionField::builder()
        .source_id(time_field_id)
        .field_id(1_000)
        .name(format!("{time_field}_hour"))
        .transform(Transform::Hour)
        .build();
    Ok(UnboundPartitionSpec::builder()
        .with_spec_id(0)
        .add_partition_fields([partition_field])?
        .build())
}

async fn write_otel_data_files(
    table: &Table,
    rows: &[OtelLakeRow],
    digest: &str,
) -> Result<Vec<DataFile>> {
    let arrow_schema: Arc<ArrowSchema> = Arc::new(
        table
            .metadata()
            .current_schema()
            .as_ref()
            .try_into()
            .context("convert native OTLP Iceberg schema to Arrow")?,
    );
    let partition_spec = table.metadata().default_partition_spec().as_ref().clone();
    let expected_partition = format!("{}_hour", rows[0].dataset.time_field());
    if partition_spec.fields().len() != 1
        || partition_spec.fields()[0].name != expected_partition
        || partition_spec.fields()[0].transform != Transform::Hour
    {
        bail!("native OTLP table must use its event-time hour partition");
    }
    let mut by_hour = BTreeMap::<i32, Vec<Value>>::new();
    for row in rows {
        by_hour
            .entry(row.event_hour)
            .or_default()
            .push(row.row.clone());
    }
    let properties = WriterProperties::builder()
        .set_compression(Compression::ZSTD(ZstdLevel::try_new(6)?))
        .set_max_row_group_row_count(Some(16_384))
        .build();
    let location = DefaultLocationGenerator::new(table.metadata())?;
    let mut output = Vec::new();
    for (hour, values) in by_hour {
        let batches = json_batches(arrow_schema.clone(), &values)?;
        let file_names = DefaultFileNameGenerator::new(
            format!("nano-otel-{}-{}", rows[0].dataset.as_str(), &digest[..12]),
            None,
            DataFileFormat::Parquet,
        );
        let parquet = ParquetWriterBuilder::new(
            properties.clone(),
            table.metadata().current_schema().clone(),
        );
        let rolling = RollingFileWriterBuilder::new(
            parquet,
            256 * 1_024 * 1_024,
            table.file_io().clone(),
            location.clone(),
            file_names,
        );
        let partition = PartitionKey::new(
            partition_spec.clone(),
            table.metadata().current_schema().clone(),
            Struct::from_iter([Some(Literal::int(hour))]),
        );
        let mut writer = DataFileWriterBuilder::new(rolling)
            .build(Some(partition))
            .await?;
        for batch in batches {
            writer.write(batch).await?;
        }
        output.extend(writer.close().await?);
    }
    if output.is_empty() {
        bail!("native OTLP publication produced no Iceberg data files");
    }
    Ok(output)
}

pub(crate) fn json_batches(schema: Arc<ArrowSchema>, rows: &[Value]) -> Result<Vec<RecordBatch>> {
    let mut bytes = Vec::new();
    for row in rows {
        serde_json::to_writer(&mut bytes, row)?;
        bytes.push(b'\n');
    }
    ReaderBuilder::new(schema)
        .with_batch_size(rows.len().max(1))
        .build(Cursor::new(bytes))?
        .collect::<std::result::Result<Vec<_>, _>>()
        .context("decode native OTLP JSON into the Iceberg Arrow schema")
}

pub(crate) fn otel_arrow_schema(dataset: OtelDataset) -> ArrowSchema {
    let string = |name: &str, nullable: bool| Field::new(name, DataType::Utf8, nullable);
    let timestamp = |name: &str| {
        Field::new(
            name,
            DataType::Timestamp(TimeUnit::Microsecond, Some("+00:00".into())),
            false,
        )
    };
    let fields = match dataset {
        OtelDataset::Spans => vec![
            string("tenant_uid", false),
            string("trace_id", false),
            string("span_id", false),
            string("parent_span_id", false),
            timestamp("start_time"),
            timestamp("end_time"),
            Field::new("duration_ns", DataType::Int64, false),
            string("service_name", false),
            string("span_name", false),
            string("span_kind", false),
            string("status_code", false),
            string("status_message", false),
            string("attributes_json", false),
            string("resource_attributes_json", false),
            string("events_json", false),
            string("links_json", false),
            string("src_ip", false),
            string("dest_ip", false),
            string("user", false),
            string("host", false),
            timestamp("ingest_time"),
            string("raw_otlp_json", false),
        ],
        OtelDataset::Metrics => vec![
            string("tenant_uid", false),
            string("metric_uid", false),
            string("metric_name", false),
            string("metric_type", false),
            string("unit", false),
            timestamp("timestamp"),
            Field::new("value", DataType::Float64, false),
            Field::new("count", DataType::Int64, false),
            Field::new("sum", DataType::Float64, false),
            Field::new(
                "bucket_counts",
                DataType::List(Arc::new(Field::new("item", DataType::Int64, false))),
                false,
            ),
            Field::new(
                "explicit_bounds",
                DataType::List(Arc::new(Field::new("item", DataType::Float64, false))),
                false,
            ),
            Field::new("aggregation_temporality", DataType::Int64, false),
            string("attributes_json", false),
            string("resource_attributes_json", false),
            string("service_name", false),
            timestamp("ingest_time"),
            string("raw_otlp_json", false),
        ],
    };
    ArrowSchema::new(fields)
}

fn required_metadata_location(table: &Table) -> Result<&str> {
    table
        .metadata_location()
        .context("native OTLP Iceberg table has no metadata location")
}

/// Load the catalog using the same credential boundary as OCSF publication.
pub async fn load_otel_catalog(config: &CatalogConfig) -> Result<RestCatalog> {
    config.load().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::planner::ObjectStoreCredentials;

    fn span() -> Value {
        json!({
            "event": serde_json::to_string(&json!({
                "traceId": "0123456789abcdef0123456789abcdef",
                "spanId": "0123456789abcdef",
                "parentSpanId": "fedcba9876543210",
                "name": "GET /checkout",
                "kind": 2,
                "startTimeUnixNano": "1786500000000000000",
                "endTimeUnixNano": "1786500000123000000",
                "status": {"code": 2, "message": "boom"},
                "attributes": [
                    {"key":"client.address","value":{"stringValue":"10.1.2.3"}}
                ],
                "resource": {"attributes": [
                    {"key":"service.name","value":{"stringValue":"checkout"}}
                ]},
                "events": [], "links": []
            })).unwrap(),
            "source_type": "otlp_trace",
            "ingest_time_unix_nano": "1786500000999000000"
        })
    }

    fn metric() -> Value {
        json!({
            "name": "http.server.duration",
            "type": "histogram",
            "unit": "ms",
            "timeUnixNano": "1786500000000000000",
            "count": 3,
            "sum": 42.0,
            "bucketCounts": [1, 1, 1],
            "explicitBounds": [10.0, 50.0],
            "aggregationTemporality": 2,
            "attributes": [],
            "resource": {"attributes": [
                {"key":"service.name","value":{"stringValue":"checkout"}}
            ]}
        })
    }

    fn table() -> OtelQuerySource {
        OtelQuerySource::from(table_config())
    }

    fn table_config() -> TenantQueryConfig {
        TenantQueryConfig {
            tenant_id: "tenant-a".to_string(),
            source: "s3://lake/tenant-a/spans".to_string(),
            iceberg_metadata_file_path: "metadata/00001.json".to_string(),
            max_query_bytes: 1_000_000,
            max_memory_bytes: crate::planner::DEFAULT_QUERY_MEMORY_BYTES,
            max_execution_seconds: 30,
            threads: 4,
            credentials: ObjectStoreCredentials::Static {
                access_key: "access".to_string(),
                secret_key: "secret".to_string(),
                session_token: None,
            },
            snapshot_cache: None,
        }
    }

    /// NAN-2361 wave 7: on the hosted lake the committed table and the
    /// still-staged mirror are unioned positionally with disjoint parameter
    /// names; a foreign-tenant or non-cache tail is refused.
    #[test]
    fn hosted_source_unions_committed_table_and_staged_mirror() {
        let temp = tempfile::tempdir().unwrap();
        let object = temp.path().join("event_hour=1/a.parquet");
        std::fs::create_dir_all(object.parent().unwrap()).unwrap();
        std::fs::write(&object, b"x").unwrap();
        let mut tail = table_config();
        tail.snapshot_cache = Some(crate::planner::SnapshotCache {
            source_spec: object.to_string_lossy().into_owned(),
            objects: std::collections::BTreeMap::from([(
                object.to_string_lossy().into_owned(),
                crate::planner::SnapshotCacheObject { version_id: "mirror".into(), bytes: 1, path: object.clone() },
            )]),
            bytes: 1,
            read_schema: None,
            bootstrap: false,
        });
        tail.credentials = ObjectStoreCredentials::DefaultChain;
        let source = OtelQuerySource { primary: table_config(), staged_tail: Some(tail.clone()) };
        let (sql, params) = trusted_otel_source(&source).unwrap();
        assert!(sql.contains("icebergS3("), "committed table first");
        assert!(sql.contains("UNION ALL"));
        assert!(sql.contains("file({staged_tail_snapshot_cache_source:String}, Parquet)"), "{sql}");
        assert!(params.iter().any(|(k, _)| k == "source"));
        assert!(params.iter().any(|(k, _)| k == "iceberg_access_key"));
        assert!(params.iter().any(|(k, v)| k == "staged_tail_snapshot_cache_source" && v == &object.to_string_lossy()));
        assert!(!params.iter().any(|(k, _)| k == "snapshot_cache_source"), "tail parameters are renamed");
        // Every planner accepts the union source through the same entry.
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z").unwrap().with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z").unwrap().with_timezone(&Utc);
        let plan = plan_recent_traces(&source, "tenant-a", start, end, None, false, None, None, 10).unwrap();
        assert!(plan.sql.contains("UNION ALL"));
        // A tail that is not a local cache, or another tenant's, is refused.
        let mut remote_tail = table_config();
        remote_tail.snapshot_cache = None;
        assert!(trusted_otel_source(&OtelQuerySource { primary: table_config(), staged_tail: Some(remote_tail) }).is_err());
        let mut foreign = tail;
        foreign.tenant_id = "tenant-b".into();
        assert!(trusted_otel_source(&OtelQuerySource { primary: table_config(), staged_tail: Some(foreign) }).is_err());
        // Without a tail the source is byte-identical to the dedicated one.
        let (single, _) = trusted_otel_source(&table()).unwrap();
        assert!(!single.contains("UNION ALL"));
    }

    #[test]
    fn native_npl_uses_tenant_fenced_iceberg_and_json_attribute_maps() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let plan = plan_otel_npl_query(
            &table(),
            "tenant-a",
            OtelDataset::Spans,
            "http.method=\"GET\" | stats count() by service_name",
            start,
            end,
            0,
            100,
        )
        .unwrap();
        assert!(plan.sql.contains("tenant_uid = {otel_tenant_id:String}"));
        assert!(plan
            .sql
            .contains("JSONExtract(attributes_json, 'Map(String, String)')"));
        assert!(plan.sql.contains("attributes['http.method']"));
        assert!(plan.sql.contains("OFFSET {otel_npl_offset:UInt64}"));
        assert!(!plan.sql.contains("otel_spans"));
        assert!(plan
            .params
            .iter()
            .any(|(name, value)| { name == "otel_tenant_id" && value == "tenant-a" }));
    }

    #[test]
    fn native_npl_rejects_cross_dataset_and_product_side_effects() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert!(plan_otel_npl_query(
            &table(),
            "tenant-a",
            OtelDataset::Spans,
            "* | resolve_identity field=src_ip",
            start,
            end,
            0,
            100,
        )
        .is_err());
        assert!(plan_otel_npl_query(
            &table(),
            "tenant-a",
            OtelDataset::Metrics,
            "metric_name in [dataset=spans search span_name=*]",
            start,
            end,
            0,
            100,
        )
        .is_err());
    }

    #[test]
    fn native_npl_compiles_advanced_metric_and_span_detection_shapes() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let metrics = plan_otel_npl_query(
            &table(),
            "tenant-a",
            OtelDataset::Metrics,
            "metric_name=\"http.server.duration\" | stats avg(value) as avg_value, max(value) as peak by service_name | where avg_value > 0 | sort -peak",
            start,
            end,
            0,
            100,
        )
        .unwrap();
        assert!(metrics.sql.contains("avg(value) AS avg_value"));
        assert!(metrics.sql.contains("max(value) AS peak"));

        let spans = plan_otel_npl_query(
            &table(),
            "tenant-a",
            OtelDataset::Spans,
            "* | sequence by trace_id maxspan=5m [status_code=\"ERROR\"] [status_code=\"OK\"]",
            start,
            end,
            0,
            100,
        )
        .unwrap();
        assert!(spans.sql.contains("trace_id"));
        assert!(spans.sql.contains("start_time"));
    }

    #[test]
    fn span_normalization_preserves_trace_and_native_tail() {
        let row = normalize_otel_row(OtelDataset::Spans, "tenant-a", &span()).unwrap();
        assert_eq!(row.row["trace_id"], "0123456789abcdef0123456789abcdef");
        assert_eq!(row.row["service_name"], "checkout");
        assert_eq!(row.row["src_ip"], "10.1.2.3");
        assert_eq!(row.row["duration_ns"], 123_000_000_i64);
        assert_eq!(row.row["ingest_time"], "2026-08-12T02:00:00.999000Z");
        assert!(row.row["raw_otlp_json"]
            .as_str()
            .unwrap()
            .contains("GET /checkout"));
    }

    #[test]
    fn metric_normalization_preserves_histogram_and_temporality() {
        let row = normalize_otel_row(OtelDataset::Metrics, "tenant-a", &metric()).unwrap();
        assert_eq!(row.row["metric_name"], "http.server.duration");
        assert_eq!(row.row["bucket_counts"], json!([1, 1, 1]));
        assert_eq!(row.row["explicit_bounds"], json!([10.0, 50.0]));
        assert_eq!(row.row["aggregation_temporality"], 2);
        assert_eq!(row.row["service_name"], "checkout");
    }

    /// A duplicate data point inside one batch must COLLAPSE, not fail the batch.
    /// Failing it made the sender retry identical bytes forever and crash-looped
    /// the ingest service (12 restarts, zero rows landing, silent outage).
    #[test]
    fn a_duplicate_row_identity_collapses_instead_of_poisoning_the_batch() {
        let row = normalize_otel_row(OtelDataset::Metrics, "tenant-a", &metric()).unwrap();
        let duplicated = vec![row.clone(), row.clone(), row.clone()];
        let (kept, collapsed) = dedupe_otel_batch(&duplicated);
        assert_eq!(kept.len(), 1, "identical points must collapse to one");
        assert_eq!(collapsed, 2);
        // And the digest guard, now a post-condition, accepts the collapsed batch.
        otel_batch_digest(&kept).expect("a deduped batch must digest cleanly");
    }

    #[test]
    fn normalization_and_batch_digest_are_stable_across_retries() {
        let first_span = normalize_otel_row(OtelDataset::Spans, "tenant-a", &span()).unwrap();
        let second_span = normalize_otel_row(OtelDataset::Spans, "tenant-a", &span()).unwrap();
        assert_eq!(first_span.row, second_span.row);
        assert_eq!(
            otel_batch_digest(&[first_span]).unwrap(),
            otel_batch_digest(&[second_span]).unwrap()
        );

        let first_metric = normalize_otel_row(OtelDataset::Metrics, "tenant-a", &metric()).unwrap();
        let second_metric =
            normalize_otel_row(OtelDataset::Metrics, "tenant-a", &metric()).unwrap();
        assert_eq!(first_metric.row, second_metric.row);
        assert_eq!(
            otel_batch_digest(&[first_metric]).unwrap(),
            otel_batch_digest(&[second_metric]).unwrap()
        );
    }

    #[test]
    fn histogram_shape_fails_closed() {
        let mut value = metric();
        value["bucketCounts"] = json!([1]);
        assert!(normalize_otel_row(OtelDataset::Metrics, "tenant-a", &value).is_err());
    }

    #[test]
    fn trace_query_parameterizes_tenant_identity_and_trace_id() {
        let plan = plan_trace_by_id(
            &table(),
            "tenant-a",
            "0123456789abcdef0123456789abcdef",
            100_001,
        )
        .unwrap();
        assert!(plan.sql.contains("tenant_uid = {otel_tenant_id:String}"));
        assert!(plan.sql.contains("trace_id = {otel_trace_id:String}"));
        assert!(!plan.sql.contains("0123456789abcdef0123456789abcdef"));
        assert!(plan
            .params
            .iter()
            .any(|(name, _)| name == "iceberg_access_key"));
    }

    #[test]
    fn metric_query_uses_bounded_time_and_step_parameters() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let plan = plan_metric_timeseries(
            &table(),
            "tenant-a",
            "http.server.duration",
            Some("checkout"),
            start,
            end,
            60,
            MetricAggregate::Avg,
        )
        .unwrap();
        assert!(plan.sql.contains("toIntervalSecond({otel_step:UInt32})"));
        assert!(plan
            .sql
            .contains("service_name = {otel_service_name:String}"));
        assert!(!plan.sql.contains("checkout"));
    }

    #[test]
    fn metric_v2_supports_temporality_grouping_and_filters_without_sql_interpolation() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let plan = plan_metric_timeseries_v2(
            &table(),
            "tenant-a",
            "http.requests",
            Some("checkout"),
            start,
            end,
            60,
            MetricAggregate::Rate,
            Some("http.route"),
            &[OtelMetricTagFilter {
                key: "deployment.environment".to_string(),
                value: "production' OR 1=1".to_string(),
            }],
        )
        .unwrap();
        assert!(plan.sql.contains("max(aggregation_temporality) = 2"));
        assert!(plan.sql.contains("{otel_group_key:String}"));
        assert!(plan.sql.contains("{otel_filter_value_0:String}"));
        assert!(!plan.sql.contains("OR 1=1"));
        assert!(plan.sql.contains("LIMIT 200001"));
    }

    #[test]
    fn metric_scalar_preserves_no_data_and_bounds_series_cardinality() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let plan = plan_metric_scalar_v2(
            &table(),
            "tenant-a",
            "http.requests",
            Some("checkout"),
            start,
            end,
            MetricAggregate::P95,
            Some("http.route"),
            &[OtelMetricTagFilter {
                key: "deployment.environment".to_string(),
                value: "prod' OR 1=1".to_string(),
            }],
        )
        .unwrap();
        assert!(plan.sql.contains("count() AS row_count"));
        assert!(plan.sql.contains("GROUP BY series_key"));
        assert!(plan.sql.contains("LIMIT 10001"));
        assert!(plan.sql.contains("{otel_filter_value_0:String}"));
        assert!(!plan.sql.contains("OR 1=1"));
    }

    #[test]
    fn slo_compute_uses_tenant_service_window_and_parameterized_threshold() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let availability = plan_slo_compute(
            &table(),
            "tenant-a",
            "checkout",
            start,
            end,
            OtelSliKind::Availability,
            None,
        )
        .unwrap();
        assert!(availability.sql.contains("countIf(status_code != 'ERROR')"));
        assert!(!availability.sql.contains("checkout"));

        let latency = plan_slo_compute(
            &table(),
            "tenant-a",
            "checkout",
            start,
            end,
            OtelSliKind::Latency,
            Some(250.0),
        )
        .unwrap();
        assert!(latency.sql.contains("{otel_latency_ns:UInt64}"));
        assert!(latency
            .params
            .iter()
            .any(|(name, value)| { name == "otel_latency_ns" && value == "250000000" }));
        assert!(plan_slo_compute(
            &table(),
            "tenant-a",
            "checkout",
            start,
            end,
            OtelSliKind::Latency,
            None,
        )
        .is_err());
    }

    #[test]
    fn recent_trace_inventory_is_parameterized_and_bounded() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let before = DateTime::parse_from_rfc3339("2026-08-12T00:30:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let plan = plan_recent_traces(
            &table(),
            "tenant-a",
            start,
            end,
            Some("checkout"),
            true,
            Some(1_000_000),
            Some(before),
            200,
        )
        .unwrap();
        assert!(plan.sql.contains("GROUP BY trace_id"));
        assert!(plan.sql.contains("error_count > 0"));
        assert!(plan.sql.contains("{otel_trace_limit:UInt32}"));
        assert!(!plan.sql.contains("checkout"));
        assert!(plan.params.iter().any(|(name, _)| name == "otel_before"));
    }

    #[test]
    fn metric_inventory_keeps_service_out_of_sql() {
        let plan = plan_metric_names(&table(), "tenant-a", Some("checkout")).unwrap();
        assert!(plan.sql.contains("SELECT DISTINCT metric_name"));
        assert!(plan
            .sql
            .contains("service_name = {otel_service_name:String}"));
        assert!(!plan.sql.contains("checkout"));
    }

    #[test]
    fn metric_tag_inventory_parameterizes_dynamic_keys() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let keys =
            plan_metric_tag_keys(&table(), "tenant-a", "http.server.duration", start, end).unwrap();
        assert!(keys.sql.contains("JSONExtractKeys(attributes_json)"));
        assert!(keys.sql.contains("LIMIT 1001"));

        let values = plan_metric_tag_values(
            &table(),
            "tenant-a",
            "http.server.duration",
            "deployment.environment",
            start,
            end,
        )
        .unwrap();
        assert!(values.sql.contains("{otel_tag_key:String}"));
        assert!(!values.sql.contains("deployment.environment"));
        assert!(values
            .params
            .iter()
            .any(|(name, value)| { name == "otel_tag_key" && value == "deployment.environment" }));
        assert!(plan_metric_tag_values(
            &table(),
            "tenant-a",
            "http.server.duration",
            "bad key",
            start,
            end,
        )
        .is_err());
    }

    #[test]
    fn services_plans_are_parameterized_and_bounded() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let overview = plan_services_overview(
            &table(),
            "tenant-a",
            start,
            end,
            Some("check"),
            OtelServicesSort::P95,
        )
        .unwrap();
        assert!(overview.sql.contains("ORDER BY p95_ms DESC"));
        assert!(overview
            .sql
            .contains("positionCaseInsensitive(service_name, {otel_service_query:String})"));
        assert!(!overview.sql.contains("check"));
        let sparkline =
            plan_services_sparkline(&table(), "tenant-a", start, end, 60, Some("check")).unwrap();
        assert!(sparkline
            .sql
            .contains("toIntervalSecond({otel_step:UInt32})"));
        assert!(sparkline.sql.contains("LIMIT 200001"));
    }

    #[test]
    fn service_detail_plans_share_the_tenant_and_service_fence() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let red = plan_service_red(&table(), "tenant-a", "checkout/api", start, end, 60).unwrap();
        assert!(red.sql.contains("{otel_service_name:String}"));
        assert!(red.sql.contains("{otel_step:UInt32}"));
        assert!(!red.sql.contains("checkout/api"));
        let endpoints =
            plan_service_endpoints(&table(), "tenant-a", "checkout/api", start, end).unwrap();
        assert!(endpoints.sql.contains("LIMIT 1001"));
        let exemplars =
            plan_service_exemplars(&table(), "tenant-a", "checkout/api", start, end, 20).unwrap();
        assert!(exemplars.sql.contains("{otel_exemplar_limit:UInt32}"));
        assert!(
            plan_service_exemplars(&table(), "tenant-a", "checkout/api", start, end, 201,).is_err()
        );
    }

    #[test]
    fn infra_plan_parameterizes_filters_and_preserves_absence_counts() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let plan = plan_infra_hosts(
            &table(),
            "tenant-a",
            start,
            end,
            Some("web"),
            Some("prod"),
            Some("production"),
        )
        .unwrap();
        assert!(plan.sql.contains("{otel_host_query:String}"));
        assert!(plan
            .sql
            .contains("countIf(metric_name = 'system.cpu.utilization') AS cpu_n"));
        assert!(plan.sql.contains("LIMIT 10001"));
        assert!(!plan.sql.contains("production"));
    }

    #[test]
    fn rum_plans_keep_filters_parameterized_across_both_datasets() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let vitals = plan_rum_vitals(&table(), "tenant-a", start, end, Some("production")).unwrap();
        assert!(vitals.sql.contains("{otel_environment:String}"));
        assert!(!vitals.sql.contains("production"));
        let series = plan_rum_series(
            &table(),
            "tenant-a",
            start,
            end,
            60,
            Some("checkout"),
            Some("Chrome"),
            Some("production"),
        )
        .unwrap();
        assert!(series.sql.contains("{otel_page:String}"));
        assert!(series.sql.contains("{otel_browser:String}"));
        assert!(series.sql.contains("{otel_step:UInt32}"));
        assert!(!series.sql.contains("checkout"));
        let top = plan_rum_top_pages(&table(), "tenant-a", start, end, None, None, None).unwrap();
        assert!(top.sql.contains("LIMIT 10"));
        let errors =
            plan_rum_recent_errors(&table(), "tenant-a", start, end, None, None, None).unwrap();
        assert!(errors.sql.contains("exception.type"));
    }

    #[test]
    fn synthetic_plans_use_the_native_metric_contract_and_bounded_windows() {
        let start = DateTime::parse_from_rfc3339("2026-08-12T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let end = DateTime::parse_from_rfc3339("2026-08-12T01:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let summary = plan_synthetic_summary(&table(), "tenant-a", start, end).unwrap();
        assert!(summary.sql.contains("metric_name = 'nano.synthetic.probe'"));
        assert!(summary.sql.contains("GROUP BY check_id"));
        assert!(summary.sql.contains("{otel_start:String}"));

        let check_id = "e4081f94-003c-435f-b6c9-65181dd022bf";
        let history =
            plan_synthetic_history(&table(), "tenant-a", check_id, start, end, 90).unwrap();
        assert!(history.sql.contains("{otel_check_id:String}"));
        assert!(!history.sql.contains(check_id));
        assert!(history.sql.contains("LIMIT {otel_limit:UInt32}"));

        assert!(plan_synthetic_history(&table(), "tenant-a", check_id, start, end, 366).is_err());
    }

    #[test]
    fn arrow_contract_accepts_normalized_rows() {
        for (dataset, input) in [
            (OtelDataset::Spans, span()),
            (OtelDataset::Metrics, metric()),
        ] {
            let row = normalize_otel_row(dataset, "tenant-a", &input).unwrap();
            let batches = json_batches(Arc::new(otel_arrow_schema(dataset)), &[row.row]).unwrap();
            assert_eq!(batches.iter().map(RecordBatch::num_rows).sum::<usize>(), 1);
        }
    }

    #[test]
    fn catalog_location_normalization_keeps_the_tenant_fence_strict() {
        assert!(same_table_location(
            "s3://nano-lake/warehouse/tenant-a/otel_spans",
            "s3://nano-lake/warehouse/tenant-a/otel_spans/",
        ));
        assert!(!same_table_location(
            "s3://nano-lake/warehouse/tenant-b/otel_spans",
            "s3://nano-lake/warehouse/tenant-a/otel_spans/",
        ));
    }
}
