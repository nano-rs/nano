// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-pinned HTTP ingest boundary for native OTLP spans and metrics.
//!
//! Vector keeps the durable disk buffer and only receives success after the
//! corresponding Iceberg snapshot is committed. A retry of the same NDJSON
//! batch resolves to the existing digest-fenced snapshot.

use anyhow::{Context, Result, bail};
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::routing::{get, post};
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use iceberg::Catalog;
use iceberg_catalog_rest::RestCatalog;
use nanosiem_lake_worker::error_log::error_chain;
use nanosiem_lake_worker::shared_mode;
use nanosiem_lake_worker::executor::NativeExecutor;
use nanosiem_lake_worker::otel_handoff::{
    mirror_snapshot_cache, DrainPacer, MirrorPolicy, OtelDrainBinding, OtelHandoffDrain,
    DEFAULT_DRAIN_FETCH_CONCURRENCY, DEFAULT_DRAIN_LOOKBACK_HOURS,
    DEFAULT_DRAIN_MAX_OBJECTS, DEFAULT_DRAIN_MAX_ROWS, MAX_DRAIN_FETCH_CONCURRENCY,
};
use nanosiem_lake_worker::otel_lean::{
    compact_mirror, expire_handoff_objects, lean_dataset_location, lean_tenant_bucket,
    load_lean_scan_state, prune_drained_markers, recover_compaction, recover_drain_journal, LeanOtelHandoffLedger, LeanOtelR2Source,
    HandoffExpiryPacer, PostgresOtelDrainPresence,
};
use nanosiem_lake_worker::iceberg::{CatalogConfig, catalog_session_expired, table_ident};
use nanosiem_lake_worker::native::NativeChdb;
use nanosiem_lake_worker::otel_iceberg::{
    MetricAggregate, OtelDataset, OtelLakeRow, OtelMetricTagFilter, OtelQuerySource, OtelServicesSort, OtelSliKind,
    normalize_otel_row, plan_infra_hosts, plan_metric_names, plan_metric_scalar_v2,
    plan_metric_tag_keys, plan_metric_tag_values, plan_metric_timeseries_v2, plan_recent_traces,
    plan_otel_npl_query,
    plan_rum_recent_errors, plan_rum_series, plan_rum_top_pages, plan_rum_vitals,
    plan_service_endpoints, plan_service_exemplars, plan_service_red, plan_services_overview,
    plan_services_sparkline, plan_slo_compute, plan_synthetic_history, plan_synthetic_summary,
    plan_trace_by_id, publish_otel_rows,
};
use nanosiem_lake_worker::otel_metric_catalog::{
    COLD_LOOKBACK, MAX_CATALOG_KEYS, MAX_CATALOG_NAMES, MetricNameCatalog, ScanWindow,
    validate_direct_window,
};
use nanosiem_lake_worker::planner::{ObjectStoreCredentials, TenantQueryConfig};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;

const USAGE: &str = "usage: lake_otel_ingest (configured by environment)
  dedicated:        NANO_ICEBERG_* catalog + NANO_OTEL_{SPANS,METRICS}_{TABLE,LOCATION}; HTTP ingest on /v1/otlp/*
  lean-lake:        NANO_OTEL_LAKE_MODE=lean; drains otel-handoff-v1/ into a local mirror:
                    NANO_OTEL_LAKE_TENANT_ID, NANO_OTEL_LAKE_QUERY_TOKEN_FILE, NANO_OTEL_LEAN_R2_CREDENTIAL_FILE,
                    NANO_OTEL_HANDOFF_MIRROR_DIR, NANO_OTEL_LAKE_DATABASE_URL (otel_publish),
                    NANO_CHDB_LIBRARY_PATH, NANO_CHDB_LIBRARY_SHA256[_FILE]
  drain tuning:     NANO_OTEL_HANDOFF_DRAIN_{INTERVAL_SECS,MAX_ROWS,MAX_OBJECTS,FETCH_CONCURRENCY,LOOKBACK_HOURS}
  every mode serves /health and the /v1/otel/* query routes on NANO_OTEL_LAKE_LISTEN (default 127.0.0.1:3014)";

const DEFAULT_MAX_BODY_BYTES: usize = 64 * 1024 * 1024;
const DEFAULT_MAX_BATCH_ROWS: usize = 50_000;

struct Arguments {
    listen: SocketAddr,
    ingest_token: Vec<u8>,
    query_token: Vec<u8>,
    tenant_id: String,
    spans_table: iceberg::TableIdent,
    spans_location: String,
    metrics_table: iceberg::TableIdent,
    metrics_location: String,
    max_body_bytes: usize,
    max_batch_rows: usize,
    max_query_bytes: u64,
    max_query_memory_bytes: u64,
    max_query_seconds: u64,
    query_threads: u64,
    query_connections: usize,
    native_library: PathBuf,
    native_library_sha256: String,
    catalog: CatalogConfig,
    /// NAN-3243: `NANO_OTEL_LAKE_MODE=lean`. The lean-lake drain: handoff ->
    /// local mirror only (no Iceberg, no owner writer, no hot tail).
    lean: Option<LeanArguments>,
    trusted_local: bool,
}

/// Lean-lake render contract (`nanosiem_lake_worker::otel_lean`).
struct LeanArguments {
    /// `S3Location` JSON scoped to `otel-handoff-v1/tenant_uuid=<T>/` in
    /// `nano-shared-r2-<T>`; re-read every `credential_reload`.
    credential_file: PathBuf,
    credential_reload: std::time::Duration,
    mirror_dir: PathBuf,
    mirror_policy: MirrorPolicy,
    drain_interval: std::time::Duration,
    maintenance_interval: std::time::Duration,
    drain_identity: String,
    /// The tenant's `otel_publish` data-path principal (heartbeat + purge policy).
    database_url: String,
    drain_max_rows: usize,
    drain_max_objects: usize,
    /// NAN-3290: handoff objects fetched concurrently per drain cycle.
    drain_fetch_concurrency: usize,
    drain_lookback_hours: u32,
    expiry_batch: usize,
}

#[derive(Clone)]
struct AppState {
    ingest_token: Arc<[u8]>,
    query_token: Arc<[u8]>,
    tenant_id: Arc<str>,
    spans_table: iceberg::TableIdent,
    spans_location: Arc<str>,
    metrics_table: iceberg::TableIdent,
    metrics_location: Arc<str>,
    max_batch_rows: usize,
    max_query_bytes: u64,
    max_query_memory_bytes: u64,
    max_query_seconds: u64,
    query_threads: u64,
    query_credentials: ObjectStoreCredentials,
    executor: NativeExecutor,
    // One writer per tenant serializes table commits. This avoids manufacturing
    // optimistic-commit conflicts under a burst while Vector's own disk buffer
    // remains the durable queue. Reads deliberately use a separate catalog
    // session: a busy Services/Metrics/Traces UI must never starve the writer
    // that makes newly accepted telemetry visible.
    ingest_catalog: Option<Arc<Mutex<RestCatalog>>>,
    query_catalog: Option<Arc<Mutex<RestCatalog>>>,
    catalog_config: Arc<CatalogConfig>,
    /// Hosted-shared: the query mirror of drained staged objects. `Some`
    /// switches every query to the mirror (+ the committed table the
    /// compactor pinned, wave 7) and closes the HTTP ingest routes.
    hosted_mirror: Option<Arc<PathBuf>>,
    local_store: Option<Arc<nanosiem_lake_worker::otel_local::LocalOtelStore>>,
    /// Hosted-shared: the drain, for the committed-table pins it refreshes.
    hosted_drain: Option<Arc<OtelHandoffDrain>>,
    metric_catalogs: MetricCatalogs,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    r2_ops: serde_json::Value,
    status: &'static str,
    tenant_pinned: bool,
    /// NAN-2361 wave 6: true when this process drains the hosted-shared
    /// handoff instead of accepting HTTP ingest.
    hosted_handoff_drain: bool,
    /// NAN-3243: true for the lean-lake (mirror-only) drain.
    lean_drain: bool,
    datasets: [&'static str; 2],
    query_connections: usize,
    max_query_bytes: u64,
    max_query_memory_bytes: u64,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    message: String,
}

#[derive(Debug, Serialize)]
struct TraceQueryResponse {
    trace_id: String,
    spans: Vec<Value>,
    span_count: usize,
    truncated: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricQueryRequest {
    metric_name: String,
    #[serde(default)]
    service_name: Option<String>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default = "default_metric_step")]
    step_seconds: u32,
    #[serde(default = "default_metric_aggregate")]
    aggregate: String,
    #[serde(default)]
    group_by: Option<String>,
    #[serde(default)]
    filters: Vec<MetricFilterInput>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricFilterInput {
    key: String,
    value: String,
}

#[derive(Debug, Serialize)]
struct MetricQueryResponse {
    metric_name: String,
    aggregate: String,
    step_seconds: u32,
    group_by: Option<String>,
    series: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricScalarRequest {
    metric_name: String,
    #[serde(default)]
    service_name: Option<String>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    aggregate: String,
    #[serde(default)]
    group_by: Option<String>,
    #[serde(default)]
    filters: Vec<MetricFilterInput>,
}

#[derive(Debug, Serialize)]
struct MetricScalarResponse {
    series: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SloComputeRequest {
    service_name: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    sli_kind: String,
    #[serde(default)]
    latency_threshold_ms: Option<f64>,
}

#[derive(Debug, Serialize)]
struct SloComputeResponse {
    total: i64,
    good: i64,
    /// NAN-3894: the reader attests it holds EVERY span of the window (lean
    /// mirror coverage, `otel_lean::lean_window_complete`). False whenever it
    /// cannot prove it — trusted_local and gen1 readers never attest.
    complete_window: bool,
}

/// NAN-3894: `GET /v1/otel/coverage`. Empty when this reader does not
/// attest coverage (not a lean drain).
#[derive(Debug, Serialize)]
struct CoverageResponse {
    coverage: Vec<nanosiem_lake_worker::otel_lean::LeanCoverage>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RecentTracesQuery {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    errors_only: bool,
    #[serde(default)]
    min_duration_ns: Option<u64>,
    #[serde(default)]
    before: Option<DateTime<Utc>>,
    #[serde(default = "default_recent_trace_limit")]
    limit: u32,
}

#[derive(Debug, Serialize)]
struct RecentTracesResponse {
    traces: Vec<Value>,
    count: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricNamesQuery {
    #[serde(default)]
    service_name: Option<String>,
    /// Explicit window (both or neither). Omitted: the cached catalog.
    #[serde(default)]
    start: Option<DateTime<Utc>>,
    #[serde(default)]
    end: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct MetricNamesResponse {
    names: Vec<Value>,
    count: usize,
    /// NAN-4098: start of the window the names cover (end is "now").
    #[serde(skip_serializing_if = "Option::is_none")]
    window_start: Option<DateTime<Utc>>,
    /// NAN-4098: true while the catalog covers less than its full 24 h
    /// (cold start, backfill pending) or the inventory hit its row cap.
    partial: bool,
}

/// NAN-4098: per-service-filter metric-name catalogs ("" = all services).
/// Each entry has its own lock so one slow scan never blocks another filter;
/// concurrent requests for the same filter wait on the one in-flight scan.
type MetricCatalogs = Arc<Mutex<HashMap<String, Arc<Mutex<MetricNameCatalog>>>>>;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricTagsQuery {
    metric_name: String,
    #[serde(default)]
    key: Option<String>,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[derive(Debug, Serialize)]
struct MetricTagsResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    tag_keys: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tag_values: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServicesQuery {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default = "default_service_step")]
    step_seconds: u32,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    sort: Option<String>,
    #[serde(default)]
    health: Option<String>,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct ServicesResponse {
    services: Vec<Value>,
    total: usize,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceDetailQuery {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default = "default_service_step")]
    step_seconds: u32,
    #[serde(default = "default_exemplar_limit")]
    exemplar_limit: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InfraHostsQuery {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default)]
    q: Option<String>,
    #[serde(default)]
    group: Option<String>,
    #[serde(default)]
    env: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    offset: u32,
    #[serde(default)]
    limit: Option<u32>,
}

#[derive(Debug, Serialize)]
struct InfraHostsResponse {
    hosts: Vec<Value>,
    total: usize,
    has_more: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RumQuery {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default = "default_service_step")]
    step_seconds: u32,
    #[serde(default)]
    page: Option<String>,
    #[serde(default)]
    browser: Option<String>,
    #[serde(default)]
    env: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticWindowQuery {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SyntheticHistoryQuery {
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default = "default_synthetic_history_limit")]
    limit: u32,
}

#[derive(Debug, Serialize)]
struct SyntheticSummaryResponse {
    summaries: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct SyntheticHistoryResponse {
    history: Vec<Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OtelNplQueryRequest {
    dataset: String,
    query: String,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    #[serde(default)]
    offset: usize,
    limit: usize,
}

#[derive(Debug, Serialize)]
struct OtelNplQueryResponse {
    dataset: &'static str,
    results: Vec<Value>,
    has_more: bool,
    storage_rows_read: u64,
    storage_bytes_read: u64,
    execution_time_ms: u64,
}

fn default_metric_step() -> u32 {
    60
}

fn default_metric_aggregate() -> String {
    "avg".to_string()
}

fn default_recent_trace_limit() -> u32 {
    200
}

fn default_service_step() -> u32 {
    60
}

fn default_exemplar_limit() -> u32 {
    20
}

fn default_synthetic_history_limit() -> u32 {
    90
}

type ApiResult<T> = std::result::Result<T, (StatusCode, Json<ErrorResponse>)>;

#[tokio::main]
async fn main() -> Result<()> {
    if std::env::args().nth(1).is_some_and(|arg| arg == "--help" || arg == "-h") {
        println!("{USAGE}");
        return Ok(());
    }
    nanosiem_lake_worker::process_limits::initialize()?;
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "lake_otel_ingest=info".into()),
        )
        .json()
        .init();
    let args = Arguments::from_env()?;
    let (ingest_catalog, query_catalog) = if args.lean.is_some() {
        // The lean lake never commits OTLP rows to Iceberg from this
        // process; the catalog is not opened at all.
        (None, None)
    } else {
        (
            Some(Arc::new(Mutex::new(args.catalog.load().await?))),
            Some(Arc::new(Mutex::new(args.catalog.load().await?))),
        )
    };
    let runtime = NativeChdb::load_verified(&args.native_library, &args.native_library_sha256)
        .context("load verified native chDB runtime for OTLP queries")?;
    let executor = NativeExecutor::start(runtime, args.query_connections)
        .context("start native OTLP query executors")?;
    let query_credentials = if args.catalog.s3_default_credentials {
        ObjectStoreCredentials::DefaultChain
    } else {
        ObjectStoreCredentials::Static {
            access_key: args.catalog.s3_access_key.clone(),
            secret_key: args.catalog.s3_secret_key.clone(),
            session_token: args.catalog.s3_session_token.clone(),
        }
    };
    let hosted_drain = match args.lean.as_ref() {
        Some(lean) if !args.trusted_local => Some(spawn_lean_drain(&args, lean).await?),
        Some(_) | None => None,
    };
    let local_store = if args.trusted_local {
        let lean = args.lean.as_ref().context("local telemetry configuration missing")?;
        let store = Arc::new(nanosiem_lake_worker::otel_local::LocalOtelStore::open(
            uuid::Uuid::parse_str(&args.tenant_id)?, lean.mirror_dir.clone(), lean.mirror_policy.max_bytes)?);
        let pool = nanosiem_lake_worker::postgres::connect_spot_safe_pool(&lean.database_url, "local_otel", 1).await?;
        let background = store.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                tick.tick().await;
                match sqlx::query_as::<_, (bool, i32)>("SELECT retention_enabled, retention_days FROM system_settings WHERE id = 'default'")
                    .fetch_one(&pool).await {
                    Ok((enabled, days)) if (1..=3650).contains(&days) => {
                        let store = background.clone();
                        match tokio::task::spawn_blocking(move || store.maintain(enabled.then_some(days as u32), chrono::Utc::now())).await {
                            Ok(Ok(())) => {},
                            _ => tracing::warn!("local OTLP maintenance failed; retrying next minute"),
                        }
                    },
                    _ => tracing::warn!("local OTLP retention settings unreadable; keeping telemetry"),
                }
            }
        });
        Some(store)
    } else { None };
    let state = AppState {
        ingest_token: args.ingest_token.into(),
        query_token: args.query_token.into(),
        tenant_id: args.tenant_id.into(),
        spans_table: args.spans_table,
        spans_location: args.spans_location.into(),
        metrics_table: args.metrics_table,
        metrics_location: args.metrics_location.into(),
        max_batch_rows: args.max_batch_rows,
        max_query_bytes: args.max_query_bytes,
        max_query_memory_bytes: args.max_query_memory_bytes,
        max_query_seconds: args.max_query_seconds,
        query_threads: args.query_threads,
        query_credentials,
        executor,
        ingest_catalog,
        query_catalog,
        catalog_config: Arc::new(args.catalog.clone()),
        hosted_mirror: args
            .lean
            .as_ref()
            .map(|lean| Arc::new(lean.mirror_dir.clone())),
        hosted_drain,
        local_store,
        metric_catalogs: MetricCatalogs::default(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/v1/otlp/spans", post(ingest_spans))
        .route("/v1/otlp/metrics", post(ingest_metrics))
        .route("/v1/otel/traces", get(query_recent_traces))
        .route("/v1/otel/traces/{trace_id}", get(query_trace))
        .route("/v1/otel/services", get(query_services))
        .route("/v1/otel/services/{service}", get(query_service_detail))
        .route("/v1/otel/infra/hosts", get(query_infra_hosts))
        .route("/v1/otel/rum", get(query_rum))
        .route("/v1/otel/metrics/names", get(query_metric_names))
        .route("/v1/otel/metrics/tags", get(query_metric_tags))
        .route("/v1/otel/metrics/timeseries", post(query_metrics))
        .route("/v1/otel/metrics/scalar", post(query_metric_scalar))
        .route("/v1/otel/query", post(query_otel_npl))
        .route("/v1/otel/slos/compute", post(query_slo_compute))
        .route("/v1/otel/coverage", get(query_coverage))
        .route("/v1/otel/synthetics/summary", get(query_synthetic_summary))
        .route(
            "/v1/otel/synthetics/{check_id}/history",
            get(query_synthetic_history),
        )
        .layer(DefaultBodyLimit::max(args.max_body_bytes))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .context("bind native OTLP lake ingest listener")?;
    tracing::info!(listen = %args.listen, "native OTLP Iceberg ingest ready");
    axum::serve(listener, app)
        .await
        .context("serve native OTLP lake ingest")
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        r2_ops: nanosiem_lake_worker::r2_ops::snapshot(),
        status: "ok",
        tenant_pinned: true,
        hosted_handoff_drain: state.hosted_mirror.is_some() && state.local_store.is_none(),
        lean_drain: state.local_store.is_some() || state.hosted_drain.as_ref().is_some_and(|drain| drain.is_lean()),
        datasets: ["spans", "metrics"],
        query_connections: state.executor.connection_count(),
        max_query_bytes: state.max_query_bytes,
        max_query_memory_bytes: state.max_query_memory_bytes,
    })
}

async fn query_otel_npl(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<OtelNplQueryRequest>,
) -> ApiResult<Json<OtelNplQueryResponse>> {
    authorize(&headers, &state.query_token)?;
    let dataset = match request.dataset.trim().to_ascii_lowercase().as_str() {
        "spans" => OtelDataset::Spans,
        "metrics" => OtelDataset::Metrics,
        _ => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_OTEL_DATASET",
                anyhow::anyhow!("native OTLP nPL dataset must be spans or metrics"),
            ));
        }
    };
    let Some(table) = current_query_table(&state, dataset)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(OtelNplQueryResponse {
            dataset: dataset.as_str(),
            results: Vec::new(),
            has_more: false,
            storage_rows_read: 0,
            storage_bytes_read: 0,
            execution_time_ms: 0,
        }));
    };
    let plan = plan_otel_npl_query(
        &table,
        &state.tenant_id,
        dataset,
        &request.query,
        request.start,
        request.end,
        request.offset,
        request.limit,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_OTEL_NPL_QUERY", error))?;
    let output = state.executor.execute_sql(plan.sql, plan.params).await.map_err(|error| {
        let message = error.to_string();
        if is_native_resource_exhaustion(&message) {
            api_error(
                StatusCode::UNPROCESSABLE_ENTITY,
                "OTEL_QUERY_EXHAUSTED",
                anyhow::anyhow!(message),
            )
        } else {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_QUERY_FAILED",
                anyhow::anyhow!(message),
            )
        }
    })?;
    let mut results = decode_json_each_row(&output.data).map_err(|error| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INVALID_OTEL_QUERY_RESULT",
            error,
        )
    })?;
    let has_more = results.len() > request.limit;
    results.truncate(request.limit);
    Ok(Json(OtelNplQueryResponse {
        dataset: dataset.as_str(),
        results,
        has_more,
        storage_rows_read: output.storage_rows_read,
        storage_bytes_read: output.storage_bytes_read,
        execution_time_ms: output.elapsed.as_millis() as u64,
    }))
}

fn is_native_resource_exhaustion(message: &str) -> bool {
    [
        "MEMORY_LIMIT_EXCEEDED",
        "QUERY_MEMORY_LIMIT_EXCEEDED",
        "TOO_MANY_ROWS",
        "TOO_MANY_BYTES",
        "TIMEOUT_EXCEEDED",
        "max_bytes_to_read",
        "memory limit exceeded",
    ]
    .iter()
    .any(|needle| message.to_ascii_lowercase().contains(&needle.to_ascii_lowercase()))
}

async fn ingest_spans(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<nanosiem_lake_worker::otel_iceberg::OtelPublishResult>> {
    ingest(state, headers, body, OtelDataset::Spans).await
}

async fn ingest_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Json<nanosiem_lake_worker::otel_iceberg::OtelPublishResult>> {
    ingest(state, headers, body, OtelDataset::Metrics).await
}

async fn ingest(
    state: AppState,
    headers: HeaderMap,
    body: Bytes,
    dataset: OtelDataset,
) -> ApiResult<Json<nanosiem_lake_worker::otel_iceberg::OtelPublishResult>> {
    authorize(&headers, &state.ingest_token)?;
    if state.hosted_mirror.is_some() && state.local_store.is_none() {
        // Hosted-shared: telemetry arrives through the Worker's
        // `otel.internal` handoff and this process's drain, never over HTTP.
        return Err(api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "OTLP_HOSTED_HANDOFF_ONLY",
            anyhow::anyhow!(
                "hosted-shared OTLP ingest is drained from the tenant's R2 handoff; the HTTP ingest boundary is closed"
            ),
        ));
    }
    let input = decode_batch(&body, dataset, state.max_batch_rows)
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_OTLP_BATCH", error))?;
    let rows = input
        .iter()
        .map(|value| normalize_otel_row(dataset, &state.tenant_id, value))
        .collect::<Result<Vec<OtelLakeRow>>>()
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_OTLP_ROW", error))?;
    if let Some(store) = &state.local_store {
        let store = store.clone();
        let result = tokio::task::spawn_blocking(move || store.publish(dataset, &rows)).await
            .map_err(|error| api_error(StatusCode::SERVICE_UNAVAILABLE, "OTLP_LOCAL_COMMIT_FAILED", error.into()))?
            .map_err(|error| api_error(StatusCode::SERVICE_UNAVAILABLE, "OTLP_LOCAL_COMMIT_FAILED", error))?;
        return Ok(Json(result));
    }
    let (table, location) = match dataset {
        OtelDataset::Spans => (&state.spans_table, state.spans_location.as_ref()),
        OtelDataset::Metrics => (&state.metrics_table, state.metrics_location.as_ref()),
    };
    let result = publish_with_catalog_refresh(
        &state,
        table,
        location,
        &rows,
    )
    .await
    .map_err(|error| {
            tracing::error!(dataset = dataset.as_str(), error = %error_chain(&error), "native OTLP Iceberg commit failed");
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTLP_LAKE_COMMIT_FAILED",
                anyhow::anyhow!("native OTLP batch was not committed"),
            )
        })?;
    Ok(Json(result))
}

async fn publish_with_catalog_refresh(
    state: &AppState,
    table: &iceberg::TableIdent,
    location: &str,
    rows: &[OtelLakeRow],
) -> Result<nanosiem_lake_worker::otel_iceberg::OtelPublishResult> {
    let ingest_catalog = state
        .ingest_catalog
        .as_ref()
        .context("native OTLP ingest catalog is closed on the hosted-shared lake")?;
    let mut catalog = ingest_catalog.lock().await;
    match publish_otel_rows(&catalog, table, location, &state.tenant_id, rows).await {
        Ok(result) => Ok(result),
        Err(error) if catalog_session_expired(&error) => {
            tracing::warn!(
                "native OTLP catalog session expired; refreshing before exact batch retry"
            );
            *catalog = state
                .catalog_config
                .load()
                .await
                .context("refresh native OTLP catalog session")?;
            publish_otel_rows(&catalog, table, location, &state.tenant_id, rows)
                .await
                .context("retry native OTLP Iceberg batch after catalog refresh")
        }
        Err(error) => Err(error),
    }
}

async fn query_trace(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(trace_id): Path<String>,
) -> ApiResult<Json<TraceQueryResponse>> {
    authorize(&headers, &state.query_token)?;
    let Some(table) = current_query_table(&state, OtelDataset::Spans)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(TraceQueryResponse {
            trace_id,
            spans: Vec::new(),
            span_count: 0,
            truncated: false,
        }));
    };
    let plan = plan_trace_by_id(&table, &state.tenant_id, &trace_id, 100_001)
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_TRACE_QUERY", error))?;
    let output = state
        .executor
        .execute_sql(plan.sql, plan.params)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_QUERY_FAILED",
                error.into(),
            )
        })?;
    let mut spans = decode_json_each_row(&output.data).map_err(|error| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INVALID_OTEL_QUERY_RESULT",
            error,
        )
    })?;
    let truncated = spans.len() > 100_000;
    spans.truncate(100_000);
    for span in &mut spans {
        decode_json_fields(
            span,
            &["attributes", "resource_attributes", "events", "links"],
        );
    }
    Ok(Json(TraceQueryResponse {
        trace_id: trace_id.to_ascii_lowercase(),
        span_count: spans.len(),
        truncated,
        spans,
    }))
}

async fn query_recent_traces(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<RecentTracesQuery>,
) -> ApiResult<Json<RecentTracesResponse>> {
    authorize(&headers, &state.query_token)?;
    let Some(table) = current_query_table(&state, OtelDataset::Spans)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(RecentTracesResponse {
            traces: Vec::new(),
            count: 0,
        }));
    };
    let plan = plan_recent_traces(
        &table,
        &state.tenant_id,
        request.start,
        request.end,
        request.service_name.as_deref(),
        request.errors_only,
        request.min_duration_ns,
        request.before,
        request.limit,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_TRACE_QUERY", error))?;
    let traces = execute_json_plan(&state, plan).await?;
    Ok(Json(RecentTracesResponse {
        count: traces.len(),
        traces,
    }))
}

async fn query_metric_names(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<MetricNamesQuery>,
) -> ApiResult<Json<MetricNamesResponse>> {
    authorize(&headers, &state.query_token)?;
    let service = request
        .service_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let explicit = match (request.start, request.end) {
        (Some(start), Some(end)) => Some(ScanWindow { start, end }),
        (None, None) => None,
        _ => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_METRIC_QUERY",
                anyhow::anyhow!("metric inventory start and end go together"),
            ));
        }
    };
    if let Some(window) = explicit {
        validate_direct_window(window.start, window.end).map_err(|error| {
            api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_METRIC_QUERY",
                anyhow::anyhow!(error),
            )
        })?;
    }
    let Some(table) = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(MetricNamesResponse {
            names: Vec::new(),
            count: 0,
            window_start: None,
            partial: false,
        }));
    };

    // An explicit window is a direct, uncached, bounded inventory.
    if let Some(window) = explicit {
        let rows = scan_metric_names(&state, &table, service.as_deref(), window).await?;
        let capped = rows.len() > MAX_CATALOG_NAMES;
        let mut names: Vec<String> = rows.into_iter().map(|(name, _)| name).collect();
        names.truncate(MAX_CATALOG_NAMES);
        return Ok(Json(metric_names_response(names, Some(window.start), capped)));
    }

    let key = service.clone().unwrap_or_default();
    let entry = {
        let mut catalogs = state.metric_catalogs.lock().await;
        match catalogs.get(&key) {
            Some(entry) => Some(entry.clone()),
            None if catalogs.len() < MAX_CATALOG_KEYS => {
                let entry = Arc::new(Mutex::new(MetricNameCatalog::default()));
                catalogs.insert(key.clone(), entry.clone());
                Some(entry)
            }
            None => None,
        }
    };
    let Some(entry) = entry else {
        // Too many distinct service filters cached: answer this one from a
        // bounded cold-lookback scan without caching it.
        let now = Utc::now();
        let window = ScanWindow {
            start: now - COLD_LOOKBACK,
            end: now,
        };
        let rows = scan_metric_names(&state, &table, service.as_deref(), window).await?;
        let mut names: Vec<String> = rows.into_iter().map(|(name, _)| name).collect();
        names.truncate(MAX_CATALOG_NAMES);
        return Ok(Json(metric_names_response(names, Some(window.start), true)));
    };

    let mut catalog = entry.lock().await;
    let now = Utc::now();
    if let Some(window) = catalog.refresh_window(now) {
        match scan_metric_names(&state, &table, service.as_deref(), window).await {
            Ok(rows) => catalog.apply_scan(window, rows, now),
            // Stale-but-serving: a warm catalog answers through a failed
            // incremental scan; only a cold one surfaces the error.
            Err(error) if catalog.names(now).is_empty() => return Err(error),
            Err(_) => tracing::warn!(
                service = %key,
                "metric catalog refresh failed; serving the previous catalog"
            ),
        }
    }
    if let Some(window) = catalog.claim_backfill(now) {
        let state = state.clone();
        let entry = entry.clone();
        let table = table.clone();
        tokio::spawn(async move {
            let result = scan_metric_names(&state, &table, service.as_deref(), window).await;
            let mut catalog = entry.lock().await;
            let now = Utc::now();
            match result {
                Ok(rows) => {
                    catalog.apply_scan(window, rows, now);
                    catalog.finish_backfill(true, now);
                }
                Err(_) => {
                    tracing::warn!("metric catalog 24 h backfill failed; retrying later");
                    catalog.finish_backfill(false, now);
                }
            }
        });
    }
    let names = catalog.names(now);
    let partial = catalog.is_partial() || names.len() >= MAX_CATALOG_NAMES;
    let window_start = catalog.window_start(now);
    Ok(Json(metric_names_response(names, Some(window_start), partial)))
}

fn metric_names_response(
    names: Vec<String>,
    window_start: Option<DateTime<Utc>>,
    partial: bool,
) -> MetricNamesResponse {
    let names: Vec<Value> = names
        .into_iter()
        .map(|name| serde_json::json!({ "metric_name": name }))
        .collect();
    MetricNamesResponse {
        count: names.len(),
        names,
        window_start,
        partial,
    }
}

/// One bounded inventory scan: `(metric_name, last_seen)` rows.
async fn scan_metric_names(
    state: &AppState,
    table: &OtelQuerySource,
    service: Option<&str>,
    window: ScanWindow,
) -> ApiResult<Vec<(String, DateTime<Utc>)>> {
    let plan = plan_metric_names(table, &state.tenant_id, service, window.start, window.end)
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_METRIC_QUERY", error))?;
    let rows = execute_json_plan(state, plan).await?;
    Ok(rows
        .iter()
        .filter_map(|row| {
            let name = json_string(row, "metric_name");
            if name.is_empty() {
                return None;
            }
            let seen = json_optional_number(row, "last_seen_unix")
                .and_then(|secs| DateTime::from_timestamp(secs as i64, 0))
                .unwrap_or(window.end);
            Some((name, seen))
        })
        .collect())
}

async fn query_metric_tags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<MetricTagsQuery>,
) -> ApiResult<Json<MetricTagsResponse>> {
    authorize(&headers, &state.query_token)?;
    let Some(table) = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(empty_metric_tags(request.key.as_deref())));
    };
    let (plan, field, maximum) = match request.key.as_deref().filter(|value| !value.is_empty()) {
        Some(key) => (
            plan_metric_tag_values(
                &table,
                &state.tenant_id,
                &request.metric_name,
                key,
                request.start,
                request.end,
            ),
            "tag_value",
            10_000,
        ),
        None => (
            plan_metric_tag_keys(
                &table,
                &state.tenant_id,
                &request.metric_name,
                request.start,
                request.end,
            ),
            "tag_key",
            1_000,
        ),
    };
    let plan = plan
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_METRIC_TAG_QUERY", error))?;
    let rows = execute_json_plan(&state, plan).await?;
    if rows.len() > maximum {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "METRIC_TAG_CARDINALITY_EXHAUSTED",
            anyhow::anyhow!("metric tag inventory exceeds its interactive bound"),
        ));
    }
    let values = rows
        .iter()
        .map(|row| json_string(row, field))
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    Ok(Json(if field == "tag_key" {
        MetricTagsResponse {
            tag_keys: Some(values),
            tag_values: None,
        }
    } else {
        MetricTagsResponse {
            tag_keys: None,
            tag_values: Some(values),
        }
    }))
}

async fn query_services(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<ServicesQuery>,
) -> ApiResult<Json<ServicesResponse>> {
    authorize(&headers, &state.query_token)?;
    let sort = OtelServicesSort::parse(request.sort.as_deref())
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SERVICES_QUERY", error))?;
    if request.offset > 1_000
        || request
            .limit
            .is_some_and(|limit| !(1..=1_000).contains(&limit))
        || request
            .health
            .as_deref()
            .is_some_and(|health| !matches!(health, "good" | "warn" | "bad"))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_SERVICES_QUERY",
            anyhow::anyhow!("services filter or page is invalid"),
        ));
    }
    let Some(table) = current_query_table(&state, OtelDataset::Spans)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(ServicesResponse {
            services: Vec::new(),
            total: 0,
            has_more: false,
        }));
    };
    let overview = plan_services_overview(
        &table,
        &state.tenant_id,
        request.start,
        request.end,
        request.q.as_deref(),
        sort,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SERVICES_QUERY", error))?;
    let overview = execute_json_plan(&state, overview).await?;
    if overview.len() > 1_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SERVICES_CARDINALITY_EXHAUSTED",
            anyhow::anyhow!("services overview exceeds the 1000-service interactive bound"),
        ));
    }
    let sparkline = plan_services_sparkline(
        &table,
        &state.tenant_id,
        request.start,
        request.end,
        request.step_seconds,
        request.q.as_deref(),
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SERVICES_QUERY", error))?;
    let sparkline = execute_json_plan(&state, sparkline).await?;
    if sparkline.len() > 200_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SERVICES_SERIES_EXHAUSTED",
            anyhow::anyhow!("services sparkline exceeds the interactive result bound"),
        ));
    }
    let mut sparklines: HashMap<String, Vec<Value>> = HashMap::new();
    for row in sparkline {
        let service = json_string(&row, "service");
        if !service.is_empty() {
            sparklines
                .entry(service)
                .or_default()
                .push(serde_json::json!({
                    "t": json_string(&row, "bucket"),
                    "v": json_number(&row, "v"),
                }));
        }
    }
    let window_seconds = (request.end - request.start).num_seconds().max(1) as f64;
    let mut services = overview
        .into_iter()
        .map(|row| {
            let service = json_string(&row, "service");
            let request_count = json_number(&row, "request_count");
            let error_count = json_number(&row, "error_count");
            let p95_ms = json_number(&row, "p95_ms");
            let error_rate = if request_count > 0.0 {
                error_count / request_count
            } else {
                0.0
            };
            let health = service_health(error_rate, p95_ms);
            let sparkline = sparklines.remove(&service).unwrap_or_default();
            let value = serde_json::json!({
                "service": service,
                "request_count": request_count as i64,
                "rate_per_sec": request_count / window_seconds,
                "error_rate": error_rate,
                "p50_ms": json_number(&row, "p50_ms"),
                "p95_ms": p95_ms,
                "p99_ms": json_number(&row, "p99_ms"),
                "health": health,
                "sparkline": sparkline,
            });
            (error_rate, health, value)
        })
        .filter(|(_, health, _)| {
            request
                .health
                .as_deref()
                .is_none_or(|wanted| wanted == *health)
        })
        .collect::<Vec<_>>();
    if sort == OtelServicesSort::ErrorRate {
        services.sort_by(|left, right| right.0.partial_cmp(&left.0).unwrap_or(Ordering::Equal));
    }
    let total = services.len();
    let limit = request
        .limit
        .map(|value| value as usize)
        .unwrap_or(usize::MAX);
    let services = services
        .into_iter()
        .map(|(_, _, value)| value)
        .skip(request.offset as usize)
        .take(limit)
        .collect::<Vec<_>>();
    Ok(Json(ServicesResponse {
        has_more: request.offset as usize + services.len() < total,
        total,
        services,
    }))
}

async fn query_service_detail(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(service): Path<String>,
    Query(request): Query<ServiceDetailQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&headers, &state.query_token)?;
    let Some(table) = current_query_table(&state, OtelDataset::Spans)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(serde_json::json!({
            "service": service,
            "red": { "rate": [], "errors": [], "latency": [] },
            "endpoints": [],
            "exemplars": [],
        })));
    };
    let red = plan_service_red(
        &table,
        &state.tenant_id,
        &service,
        request.start,
        request.end,
        request.step_seconds,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SERVICE_QUERY", error))?;
    let endpoints = plan_service_endpoints(
        &table,
        &state.tenant_id,
        &service,
        request.start,
        request.end,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SERVICE_QUERY", error))?;
    let exemplars = plan_service_exemplars(
        &table,
        &state.tenant_id,
        &service,
        request.start,
        request.end,
        request.exemplar_limit,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SERVICE_QUERY", error))?;
    let red_rows = execute_json_plan(&state, red).await?;
    let endpoint_rows = execute_json_plan(&state, endpoints).await?;
    let exemplar_rows = execute_json_plan(&state, exemplars).await?;
    if red_rows.len() > 100_000 || endpoint_rows.len() > 1_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SERVICE_DETAIL_EXHAUSTED",
            anyhow::anyhow!("service detail exceeds its interactive result bound"),
        ));
    }
    let mut rate = Vec::with_capacity(red_rows.len());
    let mut errors = Vec::with_capacity(red_rows.len());
    let mut latency = Vec::with_capacity(red_rows.len());
    for row in &red_rows {
        let bucket = json_string(row, "bucket");
        rate.push(serde_json::json!({ "t": bucket, "v": json_number(row, "rate_count") }));
        errors.push(serde_json::json!({ "t": bucket, "v": json_number(row, "error_count") }));
        latency.push(serde_json::json!({
            "t": bucket,
            "p50": json_number(row, "p50_ms"),
            "p95": json_number(row, "p95_ms"),
            "p99": json_number(row, "p99_ms"),
        }));
    }
    let endpoints = endpoint_rows
        .iter()
        .map(|row| {
            let request_count = json_number(row, "request_count");
            let error_rate = if request_count > 0.0 {
                json_number(row, "error_count") / request_count
            } else {
                0.0
            };
            serde_json::json!({
                "span_name": json_string(row, "span_name"),
                "request_count": request_count as i64,
                "error_rate": error_rate,
                "p95_ms": json_number(row, "p95_ms"),
            })
        })
        .collect::<Vec<_>>();
    let exemplars = exemplar_rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "trace_id": json_string(row, "trace_id"),
                "duration_ms": json_number(row, "duration_ms"),
                "error": json_bool(row, "error"),
                "start_time": json_string(row, "start_time"),
                "span_name": json_string(row, "span_name"),
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(serde_json::json!({
        "service": service,
        "red": { "rate": rate, "errors": errors, "latency": latency },
        "endpoints": endpoints,
        "exemplars": exemplars,
    })))
}

async fn query_infra_hosts(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<InfraHostsQuery>,
) -> ApiResult<Json<InfraHostsResponse>> {
    authorize(&headers, &state.query_token)?;
    if request.offset > 10_000
        || request
            .limit
            .is_some_and(|limit| !(1..=10_000).contains(&limit))
        || request
            .status
            .as_deref()
            .is_some_and(|status| !matches!(status, "good" | "warn" | "bad"))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_INFRA_QUERY",
            anyhow::anyhow!("infrastructure filter or page is invalid"),
        ));
    }
    let Some(table) = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(InfraHostsResponse {
            hosts: Vec::new(),
            total: 0,
            has_more: false,
        }));
    };
    let plan = plan_infra_hosts(
        &table,
        &state.tenant_id,
        request.start,
        request.end,
        request.q.as_deref(),
        request.group.as_deref(),
        request.env.as_deref(),
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_INFRA_QUERY", error))?;
    let rows = execute_json_plan(&state, plan).await?;
    if rows.len() > 10_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "INFRA_CARDINALITY_EXHAUSTED",
            anyhow::anyhow!("infrastructure inventory exceeds its interactive bound"),
        ));
    }
    let mut hosts = rows
        .iter()
        .map(|row| {
            let host = json_string(row, "host");
            let group = json_string(row, "host_group");
            let kind = json_string(row, "kind");
            let cpu_reported = json_number(row, "cpu_n") > 0.0
                || (json_number(row, "cpu_count") > 0.0 && json_number(row, "cpu_cores_n") > 0.0);
            let cpu_pct = if json_number(row, "cpu_n") > 0.0 {
                json_number(row, "cpu_util") * 100.0
            } else if json_number(row, "cpu_count") > 0.0 && json_number(row, "cpu_cores_n") > 0.0 {
                json_number(row, "cpu_cores") / json_number(row, "cpu_count") * 100.0
            } else {
                0.0
            };
            let mem_pct = json_number(row, "mem_util") * 100.0;
            let utilization_status = host_status(cpu_pct, mem_pct);
            let status = if json_number(row, "health_n") > 0.0 {
                let health = json_number(row, "health");
                if health >= 2.0 || utilization_status == "bad" {
                    "bad"
                } else if health >= 1.0 || utilization_status == "warn" {
                    "warn"
                } else {
                    "good"
                }
            } else if cpu_reported || json_number(row, "mem_n") > 0.0 {
                utilization_status
            } else {
                "unknown"
            };
            let value = serde_json::json!({
                "host": host,
                "group": if group.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(group) },
                "cpu_pct": if cpu_reported { serde_json::json!(cpu_pct) } else { serde_json::Value::Null },
                "mem_pct": gauge_value(row, "mem_n", mem_pct),
                "load": gauge_value(row, "load_n", json_number(row, "load_1m")),
                "net_bytes_per_sec": row.get("net_rate").filter(|value| !value.is_null()).cloned()
                    .unwrap_or_else(|| gauge_value(row, "net_n", json_number(row, "net_io"))),
                "kind": kind,
                "node_name": json_string(row, "node_name"),
                "pod_name": json_string(row, "pod_name"),
                "namespace": json_string(row, "namespace"),
                "workload": json_string(row, "workload"),
                "phase": json_string(row, "phase"),
                "cluster": json_string(row, "cluster"),
                "region": json_string(row, "region"),
                "instance_type": json_string(row, "instance_type"),
                "cpu_cores": gauge_value(row, "cpu_cores_n", json_number(row, "cpu_cores")),
                "mem_bytes": gauge_value(row, "mem_bytes_n", json_number(row, "mem_bytes")),
                "restarts": gauge_value(row, "restarts_n", json_number(row, "restarts")),
                "status": status,
            });
            (status, value)
        })
        .filter(|(status, _)| {
            request
                .status
                .as_deref()
                .is_none_or(|wanted| wanted == *status)
        })
        .collect::<Vec<_>>();
    let total = hosts.len();
    let limit = request
        .limit
        .map(|value| value as usize)
        .unwrap_or(usize::MAX);
    let hosts = hosts
        .drain(..)
        .map(|(_, value)| value)
        .skip(request.offset as usize)
        .take(limit)
        .collect::<Vec<_>>();
    Ok(Json(InfraHostsResponse {
        has_more: request.offset as usize + hosts.len() < total,
        total,
        hosts,
    }))
}

async fn query_rum(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<RumQuery>,
) -> ApiResult<Json<Value>> {
    authorize(&headers, &state.query_token)?;
    // Each signal is optional: browser metrics can arrive before the first
    // pageview span, and pageviews can arrive without web-vitals metrics.
    let metrics = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?;
    let spans = current_query_table(&state, OtelDataset::Spans)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?;
    let map_plan_error = |error| api_error(StatusCode::BAD_REQUEST, "INVALID_RUM_QUERY", error);
    let vital_rows = if let Some(metrics) = metrics.as_ref() {
        execute_json_plan(
            &state,
            plan_rum_vitals(
                metrics,
                &state.tenant_id,
                request.start,
                request.end,
                request.env.as_deref(),
            )
            .map_err(map_plan_error)?,
        )
        .await?
    } else {
        Vec::new()
    };
    let (series_rows, top_rows, error_rows) = if let Some(spans) = spans.as_ref() {
        let series = plan_rum_series(
            spans,
            &state.tenant_id,
            request.start,
            request.end,
            request.step_seconds,
            request.page.as_deref(),
            request.browser.as_deref(),
            request.env.as_deref(),
        );
        let top = plan_rum_top_pages(
            spans,
            &state.tenant_id,
            request.start,
            request.end,
            request.page.as_deref(),
            request.browser.as_deref(),
            request.env.as_deref(),
        );
        let errors = plan_rum_recent_errors(
            spans,
            &state.tenant_id,
            request.start,
            request.end,
            request.page.as_deref(),
            request.browser.as_deref(),
            request.env.as_deref(),
        );
        (
            execute_json_plan(&state, series.map_err(map_plan_error)?).await?,
            execute_json_plan(&state, top.map_err(map_plan_error)?).await?,
            execute_json_plan(&state, errors.map_err(map_plan_error)?).await?,
        )
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    if series_rows.len() > 100_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "RUM_SERIES_EXHAUSTED",
            anyhow::anyhow!("RUM series exceeds its interactive result bound"),
        ));
    }
    Ok(Json(rum_response(
        &vital_rows,
        &series_rows,
        &top_rows,
        &error_rows,
    )))
}

fn rum_response(
    vital_rows: &[Value],
    series_rows: &[Value],
    top_rows: &[Value],
    error_rows: &[Value],
) -> Value {
    let web_vitals = if let Some(row) = vital_rows.first() {
        serde_json::json!({
            "lcp_ms": counted_number(row, "lcp_n", "lcp_ms"),
            "inp_ms": counted_number(row, "inp_n", "inp_ms"),
            "cls": counted_number(row, "cls_n", "cls"),
        })
    } else {
        serde_json::json!({ "lcp_ms": null, "inp_ms": null, "cls": null })
    };
    let mut page_views = 0_i64;
    let mut js_errors = 0_i64;
    let mut page_views_series = Vec::with_capacity(series_rows.len());
    for row in series_rows {
        let views = json_number(row, "views");
        page_views += views as i64;
        js_errors += json_number(row, "js_errors") as i64;
        page_views_series.push(serde_json::json!({
            "t": json_string(row, "bucket"),
            "v": views,
        }));
    }
    let top_pages = top_rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "page": json_string(row, "page"),
                "views": json_number(row, "views") as i64,
                "lcp_ms": json_optional_number(row, "lcp_ms"),
            })
        })
        .collect::<Vec<_>>();
    let recent_errors = error_rows
        .iter()
        .map(|row| {
            serde_json::json!({
                "message": json_string(row, "message"),
                "page": json_string(row, "page"),
                "ts": json_string(row, "ts"),
                "user": json_string(row, "user"),
                "src_ip": json_string(row, "src_ip"),
                "session": json_string(row, "session"),
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "web_vitals": web_vitals,
        "page_views": page_views,
        "page_views_series": page_views_series,
        "js_errors": js_errors,
        "top_pages": top_pages,
        "recent_errors": recent_errors,
    })
}

async fn query_metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MetricQueryRequest>,
) -> ApiResult<Json<MetricQueryResponse>> {
    authorize(&headers, &state.query_token)?;
    let aggregate = parse_metric_aggregate(&request.aggregate)?;
    let Some(table) = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(MetricQueryResponse {
            metric_name: request.metric_name,
            aggregate: request.aggregate.to_ascii_lowercase(),
            step_seconds: request.step_seconds,
            group_by: request.group_by,
            series: Vec::new(),
        }));
    };
    let filters = request
        .filters
        .iter()
        .map(|filter| OtelMetricTagFilter {
            key: filter.key.clone(),
            value: filter.value.clone(),
        })
        .collect::<Vec<_>>();
    let plan = plan_metric_timeseries_v2(
        &table,
        &state.tenant_id,
        &request.metric_name,
        request.service_name.as_deref(),
        request.start,
        request.end,
        request.step_seconds,
        aggregate,
        request.group_by.as_deref(),
        &filters,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_METRIC_QUERY", error))?;
    let rows = execute_json_plan(&state, plan).await?;
    if rows.len() > 200_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "METRIC_SERIES_EXHAUSTED",
            anyhow::anyhow!("metric series exceeds its interactive result bound"),
        ));
    }
    let mut grouped: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for row in rows {
        grouped
            .entry(json_string(&row, "series_key"))
            .or_default()
            .push(serde_json::json!({
                "t": json_string(&row, "bucket"),
                "v": json_number(&row, "v"),
            }));
    }
    let series = grouped
        .into_iter()
        .map(|(key, points)| serde_json::json!({ "key": key, "points": points }))
        .collect();
    Ok(Json(MetricQueryResponse {
        metric_name: request.metric_name,
        aggregate: request.aggregate.to_ascii_lowercase(),
        step_seconds: request.step_seconds,
        group_by: request.group_by,
        series,
    }))
}

async fn query_metric_scalar(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<MetricScalarRequest>,
) -> ApiResult<Json<MetricScalarResponse>> {
    authorize(&headers, &state.query_token)?;
    let aggregate = parse_metric_aggregate(&request.aggregate)?;
    let Some(table) = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(MetricScalarResponse { series: Vec::new() }));
    };
    let filters = request
        .filters
        .iter()
        .map(|filter| OtelMetricTagFilter {
            key: filter.key.clone(),
            value: filter.value.clone(),
        })
        .collect::<Vec<_>>();
    let plan = plan_metric_scalar_v2(
        &table,
        &state.tenant_id,
        &request.metric_name,
        request.service_name.as_deref(),
        request.start,
        request.end,
        aggregate,
        request.group_by.as_deref(),
        &filters,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_METRIC_QUERY", error))?;
    let rows = execute_json_plan(&state, plan).await?;
    if rows.len() > 10_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "METRIC_SERIES_EXHAUSTED",
            anyhow::anyhow!("metric monitor exceeds the 10000-series evaluation bound"),
        ));
    }
    let series = rows
        .iter()
        .map(|row| {
            let row_count = json_number(row, "row_count") as u64;
            serde_json::json!({
                "key": json_string(row, "series_key"),
                "value": if row_count == 0 {
                    Value::Null
                } else {
                    json_optional_number(row, "v").map_or(Value::Null, |value| serde_json::json!(value))
                },
                "row_count": row_count,
            })
        })
        .collect();
    Ok(Json(MetricScalarResponse { series }))
}

async fn query_slo_compute(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SloComputeRequest>,
) -> ApiResult<Json<SloComputeResponse>> {
    authorize(&headers, &state.query_token)?;
    // Attested BEFORE the query reads the mirror: a drain that lands after
    // the read must not vouch for rows the read did not see.
    let complete_window = state
        .hosted_drain
        .as_ref()
        .is_some_and(|drain| drain.lean_window_complete(OtelDataset::Spans, request.start, request.end));
    let kind = match request.sli_kind.trim().to_ascii_lowercase().as_str() {
        "availability" => OtelSliKind::Availability,
        "latency" => OtelSliKind::Latency,
        _ => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "INVALID_SLO_QUERY",
                anyhow::anyhow!("SLO kind must be availability or latency"),
            ));
        }
    };
    let Some(table) = current_query_table(&state, OtelDataset::Spans)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(SloComputeResponse { total: 0, good: 0, complete_window }));
    };
    let plan = plan_slo_compute(
        &table,
        &state.tenant_id,
        &request.service_name,
        request.start,
        request.end,
        kind,
        request.latency_threshold_ms,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SLO_QUERY", error))?;
    let rows = execute_json_plan(&state, plan).await?;
    let row = rows.first();
    Ok(Json(SloComputeResponse {
        total: row
            .map(|value| json_number(value, "total") as i64)
            .unwrap_or(0),
        good: row
            .map(|value| json_number(value, "good") as i64)
            .unwrap_or(0),
        complete_window,
    }))
}

async fn query_coverage(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<CoverageResponse>> {
    authorize(&headers, &state.query_token)?;
    let mut coverage = Vec::new();
    if let Some(drain) = &state.hosted_drain {
        for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
            if let Some(report) = drain
                .lean_coverage(dataset)
                .map_err(|error| api_error(StatusCode::SERVICE_UNAVAILABLE, "OTEL_COVERAGE_UNAVAILABLE", error))?
            {
                coverage.push(report);
            }
        }
    }
    Ok(Json(CoverageResponse { coverage }))
}

async fn query_synthetic_summary(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<SyntheticWindowQuery>,
) -> ApiResult<Json<SyntheticSummaryResponse>> {
    authorize(&headers, &state.query_token)?;
    let Some(table) = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(SyntheticSummaryResponse { summaries: Vec::new() }));
    };
    let plan = plan_synthetic_summary(&table, &state.tenant_id, request.start, request.end)
        .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SYNTHETIC_QUERY", error))?;
    let summaries = execute_json_plan(&state, plan).await?;
    if summaries.len() > 100_000 {
        return Err(api_error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "SYNTHETIC_CARDINALITY_EXHAUSTED",
            anyhow::anyhow!("synthetic summary exceeds its result bound"),
        ));
    }
    Ok(Json(SyntheticSummaryResponse { summaries }))
}

async fn query_synthetic_history(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(check_id): Path<String>,
    Query(request): Query<SyntheticHistoryQuery>,
) -> ApiResult<Json<SyntheticHistoryResponse>> {
    authorize(&headers, &state.query_token)?;
    let Some(table) = current_query_table(&state, OtelDataset::Metrics)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_TABLE_UNAVAILABLE",
                error,
            )
        })?
    else {
        // No table yet == no telemetry yet. Answer empty, not 503.
        return Ok(Json(SyntheticHistoryResponse { history: Vec::new() }));
    };
    let plan = plan_synthetic_history(
        &table,
        &state.tenant_id,
        &check_id,
        request.start,
        request.end,
        request.limit,
    )
    .map_err(|error| api_error(StatusCode::BAD_REQUEST, "INVALID_SYNTHETIC_QUERY", error))?;
    let history = execute_json_plan(&state, plan).await?;
    Ok(Json(SyntheticHistoryResponse { history }))
}

fn parse_metric_aggregate(value: &str) -> ApiResult<MetricAggregate> {
    match value.trim().to_ascii_lowercase().as_str() {
        "avg" => Ok(MetricAggregate::Avg),
        "sum" => Ok(MetricAggregate::Sum),
        "min" => Ok(MetricAggregate::Min),
        "max" => Ok(MetricAggregate::Max),
        "count" => Ok(MetricAggregate::Count),
        "rate" => Ok(MetricAggregate::Rate),
        "p50" => Ok(MetricAggregate::P50),
        "p95" => Ok(MetricAggregate::P95),
        "p99" => Ok(MetricAggregate::P99),
        _ => Err(api_error(
            StatusCode::BAD_REQUEST,
            "INVALID_METRIC_QUERY",
            anyhow::anyhow!(
                "metric aggregate must be avg, sum, min, max, count, rate, p50, p95, or p99"
            ),
        )),
    }
}

async fn execute_json_plan(
    state: &AppState,
    plan: nanosiem_lake_worker::otel_iceberg::OtelNativeQueryPlan,
) -> ApiResult<Vec<Value>> {
    let output = state
        .executor
        .execute_sql(plan.sql, plan.params)
        .await
        .map_err(|error| {
            api_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "OTEL_QUERY_FAILED",
                error.into(),
            )
        })?;
    decode_json_each_row(&output.data).map_err(|error| {
        api_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "INVALID_OTEL_QUERY_RESULT",
            error,
        )
    })
}

fn json_string(row: &Value, field: &str) -> String {
    row.get(field)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string()
}

fn json_number(row: &Value, field: &str) -> f64 {
    json_optional_number(row, field).unwrap_or_default()
}

fn json_optional_number(row: &Value, field: &str) -> Option<f64> {
    row.get(field).and_then(|value| {
        value
            .as_f64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
    })
}

fn json_bool(row: &Value, field: &str) -> bool {
    row.get(field)
        .and_then(|value| {
            value.as_bool().or_else(|| {
                value
                    .as_u64()
                    .map(|number| number != 0)
                    .or_else(|| value.as_str().map(|text| matches!(text, "1" | "true")))
            })
        })
        .unwrap_or(false)
}

fn service_health(error_rate: f64, p95_ms: f64) -> &'static str {
    if error_rate >= 0.05 || p95_ms >= 1_000.0 {
        "bad"
    } else if error_rate >= 0.01 || p95_ms >= 600.0 {
        "warn"
    } else {
        "good"
    }
}

fn host_status(cpu_pct: f64, mem_pct: f64) -> &'static str {
    if cpu_pct >= 90.0 || mem_pct >= 90.0 {
        "bad"
    } else if cpu_pct >= 75.0 || mem_pct >= 75.0 {
        "warn"
    } else {
        "good"
    }
}

fn gauge_value(row: &Value, count_field: &str, value: f64) -> Value {
    if json_number(row, count_field) > 0.0 {
        serde_json::json!(value)
    } else {
        Value::Null
    }
}

fn counted_number(row: &Value, count_field: &str, value_field: &str) -> Value {
    if json_number(row, count_field) > 0.0 {
        json_optional_number(row, value_field).map_or(Value::Null, |value| serde_json::json!(value))
    } else {
        Value::Null
    }
}

/// The empty `MetricTagsResponse` for a request, matching the SHAPE the
/// populated answer would have had.
///
/// `query_metric_tags` answers two different questions through one response
/// type: with a `key` it lists that key's tag VALUES, without one it lists the
/// tag KEYS, and the unused field is `None` rather than an empty list. An empty
/// answer has to make the same distinction — returning both as `None`, or both
/// as empty, would hand callers a shape they never see when data exists.
fn empty_metric_tags(key: Option<&str>) -> MetricTagsResponse {
    if key.is_some_and(|value| !value.is_empty()) {
        MetricTagsResponse {
            tag_keys: None,
            tag_values: Some(Vec::new()),
        }
    } else {
        MetricTagsResponse {
            tag_keys: Some(Vec::new()),
            tag_values: None,
        }
    }
}

/// The query-side view of an OTLP dataset, or `None` when its Iceberg table
/// does not exist yet.
///
/// The OTLP tables are created on FIRST WRITE (`ensure_otel_table`, reached only
/// through `publish_otel_rows`), so a deployment that has never received a span
/// or a metric has no table at all. That is an EMPTY DATASET, not a broken
/// dependency — but `load_table` fails identically for both, and every caller
/// used to map that single failure to 503 SERVICE_UNAVAILABLE. The result: every
/// Observability surface reported "a required search service is temporarily
/// unavailable" on a fresh deployment, forever, until something happened to send
/// telemetry. Retrying — which that message invites — could never help.
///
/// `Ok(None)` therefore means "no rows yet, answer with your empty payload";
/// an unreachable catalog, an expired session that will not refresh, or a
/// malformed table still propagate as errors and still surface as 503.
async fn current_query_table(
    state: &AppState,
    dataset: OtelDataset,
) -> Result<Option<OtelQuerySource>> {
    let (table_id, location) = match dataset {
        OtelDataset::Spans => (&state.spans_table, state.spans_location.as_ref()),
        OtelDataset::Metrics => (&state.metrics_table, state.metrics_location.as_ref()),
    };
    if let Some(mirror) = state.hosted_mirror.as_ref() {
        // Hosted-shared (wave 7): the committed OTLP table at the metadata
        // location the tail compactor pinned, unioned with the local mirror
        // of the objects still staged. Before the first registration the
        // mirror alone serves; an empty mirror without a pin is an empty
        // dataset, not a failed dependency.
        let staged = mirror_snapshot_cache(mirror, dataset)?.map(|cache| TenantQueryConfig {
            tenant_id: state.tenant_id.to_string(),
            source: format!("{location}/data/tail/"),
            iceberg_metadata_file_path: "hosted-staged-hot-tail".to_string(),
            max_query_bytes: state.max_query_bytes,
            max_memory_bytes: state.max_query_memory_bytes,
            max_execution_seconds: state.max_query_seconds,
            threads: state.query_threads,
            credentials: ObjectStoreCredentials::DefaultChain,
            snapshot_cache: Some(cache),
        });
        let pin = state
            .hosted_drain
            .as_ref()
            .and_then(|drain| drain.committed_pin(dataset));
        return Ok(match (pin, staged) {
            (None, None) => None,
            (None, Some(staged)) => Some(OtelQuerySource::from(staged)),
            (Some(pin), staged) => {
                let metadata_path = pin
                    .metadata_location
                    .strip_prefix(location.trim_end_matches('/'))
                    .and_then(|value| value.strip_prefix('/'))
                    .context("committed OTLP metadata pin is outside its assigned table location")?;
                Some(OtelQuerySource {
                    primary: TenantQueryConfig {
                        tenant_id: state.tenant_id.to_string(),
                        source: iceberg_query_source(location, &state.catalog_config.s3_endpoint)?,
                        iceberg_metadata_file_path: metadata_path.to_string(),
                        max_query_bytes: state.max_query_bytes,
                        max_memory_bytes: state.max_query_memory_bytes,
                        max_execution_seconds: state.max_query_seconds,
                        threads: state.query_threads,
                        credentials: state.query_credentials.clone(),
                        snapshot_cache: None,
                    },
                    staged_tail: staged,
                })
            }
        });
    }
    let query_catalog = state
        .query_catalog
        .as_ref()
        .context("native OTLP query catalog is closed")?;
    let mut catalog = query_catalog.lock().await;

    // Ask the catalog whether the table exists before loading it, so absence is
    // a distinct answer rather than an error we would have to classify by
    // matching on message text. Session expiry is refreshed here too, otherwise
    // an expired token would read as "table absent" and silently empty every
    // dashboard — a far worse failure than the 503 this replaces.
    let exists = match catalog
        .table_exists(table_id)
        .await
        .context("probe native OTLP Iceberg table for query")
    {
        Ok(exists) => exists,
        Err(error) if catalog_session_expired(&error) => {
            tracing::warn!("native OTLP catalog session expired; refreshing before existence probe");
            *catalog = state
                .catalog_config
                .load()
                .await
                .context("refresh native OTLP catalog session for query")?;
            catalog
                .table_exists(table_id)
                .await
                .context("probe native OTLP Iceberg table after catalog refresh")?
        }
        Err(error) => return Err(error),
    };
    if !exists {
        tracing::debug!(
            dataset = dataset.as_str(),
            table = %table_id,
            "native OTLP table not created yet; answering as an empty dataset"
        );
        return Ok(None);
    }

    let table = match catalog
        .load_table(table_id)
        .await
        .context("load native OTLP Iceberg table for query")
    {
        Ok(table) => table,
        Err(error) if catalog_session_expired(&error) => {
            tracing::warn!("native OTLP catalog session expired; refreshing before query");
            *catalog = state
                .catalog_config
                .load()
                .await
                .context("refresh native OTLP catalog session for query")?;
            catalog
                .load_table(table_id)
                .await
                .context("load native OTLP Iceberg table after catalog refresh")?
        }
        Err(error) => return Err(error),
    };
    let metadata_location = table
        .metadata_location()
        .context("native OTLP table has no metadata location")?;
    let metadata_path = metadata_location
        .strip_prefix(location.trim_end_matches('/'))
        .and_then(|value| value.strip_prefix('/'))
        .context("native OTLP metadata is outside its assigned table location")?;
    Ok(Some(OtelQuerySource::from(TenantQueryConfig {
        tenant_id: state.tenant_id.to_string(),
        source: iceberg_query_source(location, &state.catalog_config.s3_endpoint)?,
        iceberg_metadata_file_path: metadata_path.to_string(),
        max_query_bytes: state.max_query_bytes,
        max_memory_bytes: state.max_query_memory_bytes,
        max_execution_seconds: state.max_query_seconds,
        threads: state.query_threads,
        credentials: state.query_credentials.clone(),
        snapshot_cache: None,
    })))
}

/// chDB's Iceberg table function must read through the deployment's assigned
/// S3-compatible endpoint when one is configured. The REST catalog correctly
/// retains the portable `s3://` table location, but passing that URI directly
/// would make chDB contact AWS and bypass RustFS, a VPC proxy, or another
/// tenant-fenced gateway.
fn iceberg_query_source(location: &str, endpoint: &str) -> Result<String> {
    if endpoint.is_empty() {
        if !location.starts_with("s3://") {
            bail!("native OTLP table location must be an s3:// URI");
        }
        return Ok(location.to_string());
    }
    let object_path = location
        .strip_prefix("s3://")
        .filter(|path| !path.is_empty() && !path.contains(['?', '#']))
        .context("native OTLP table location must be one bounded s3:// URI")?;
    let endpoint = endpoint.trim_end_matches('/');
    if !matches!(endpoint.split_once("://"), Some(("http" | "https", host)) if !host.is_empty())
        || endpoint.contains(['?', '#'])
    {
        bail!("native OTLP S3 endpoint must be an http(s) origin or path prefix");
    }
    Ok(format!("{endpoint}/{object_path}"))
}

fn decode_json_each_row(bytes: &[u8]) -> Result<Vec<Value>> {
    bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice(line).context("decode chDB JSONEachRow output"))
        .collect()
}

fn decode_json_fields(row: &mut Value, names: &[&str]) {
    let Some(object) = row.as_object_mut() else {
        return;
    };
    for name in names {
        let Some(encoded) = object.get(*name).and_then(Value::as_str) else {
            continue;
        };
        if let Ok(decoded) = serde_json::from_str(encoded) {
            object.insert((*name).to_string(), decoded);
        }
    }
}

fn authorize(headers: &HeaderMap, expected: &[u8]) -> ApiResult<()> {
    let presented = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::as_bytes)
        .unwrap_or_default();
    if presented.len() != expected.len() || !bool::from(presented.ct_eq(expected)) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                code: "UNAUTHORIZED",
                message: "valid bearer authentication is required".to_string(),
            }),
        ));
    }
    Ok(())
}

fn decode_batch(body: &[u8], dataset: OtelDataset, max_rows: usize) -> Result<Vec<Value>> {
    nanosiem_lake_worker::otel_iceberg::decode_otel_batch(body, dataset, max_rows)
}

fn api_error(
    status: StatusCode,
    code: &'static str,
    error: anyhow::Error,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(ErrorResponse {
            code,
            message: error.to_string(),
        }),
    )
}

impl Arguments {
    fn from_env() -> Result<Self> {
        let mode = match std::env::var("NANO_OTEL_LAKE_MODE") {
            Ok(mode) => mode,
            Err(std::env::VarError::NotPresent) => String::new(),
            Err(error) => return Err(error).context("NANO_OTEL_LAKE_MODE"),
        };
        match mode.as_str() {
            "lean" => return Self::lean_from_env(),
            "trusted_local" => return Self::lean_from_env_with_local(true),
            "" => {}
            other => bail!("NANO_OTEL_LAKE_MODE must be unset, \"lean\" or \"trusted_local\", not {other:?}"),
        }
        let ingest_token = token_file("NANO_OTEL_LAKE_INGEST_TOKEN_FILE")?;
        let query_token = token_file("NANO_OTEL_LAKE_QUERY_TOKEN_FILE")?;
        let listen = optional("NANO_OTEL_LAKE_LISTEN", "127.0.0.1:3014")
            .parse()
            .context("NANO_OTEL_LAKE_LISTEN must be a socket address")?;
        let max_body_bytes = optional_usize(
            "NANO_OTEL_LAKE_MAX_BODY_BYTES",
            DEFAULT_MAX_BODY_BYTES,
            1_024,
            512 * 1024 * 1024,
        )?;
        let max_batch_rows = optional_usize(
            "NANO_OTEL_LAKE_MAX_BATCH_ROWS",
            DEFAULT_MAX_BATCH_ROWS,
            1,
            250_000,
        )?;
        if shared_mode::active() {
            // NAN-3861: the gen1 hosted-shared drain (otel-handoff-v1/ into the
            // staged hot tail) is retired; hosted tenants run the lean drain.
            bail!("DEPLOYMENT_MODE=enterprise_shared selected the retired gen1 OTLP drain; set NANO_OTEL_LAKE_MODE=lean");
        }
        Ok(Self {
            listen,
            ingest_token,
            query_token,
            lean: None,
            trusted_local: false,
            tenant_id: required("NANO_OTEL_LAKE_TENANT_ID")?,
            spans_table: table_ident(&required("NANO_OTEL_SPANS_TABLE")?)?,
            spans_location: required("NANO_OTEL_SPANS_LOCATION")?,
            metrics_table: table_ident(&required("NANO_OTEL_METRICS_TABLE")?)?,
            metrics_location: required("NANO_OTEL_METRICS_LOCATION")?,
            max_body_bytes,
            max_batch_rows,
            max_query_bytes: optional_u64(
                "NANO_OTEL_LAKE_MAX_QUERY_BYTES",
                4 * 1024 * 1024 * 1024,
                1_024,
                1024 * 1024 * 1024 * 1024,
            )?,
            max_query_memory_bytes: optional_u64(
                "NANO_OTEL_LAKE_MAX_QUERY_MEMORY_BYTES",
                nanosiem_lake_worker::planner::DEFAULT_QUERY_MEMORY_BYTES,
                64 * 1024 * 1024,
                64 * 1024 * 1024 * 1024,
            )?,
            max_query_seconds: optional_u64("NANO_OTEL_LAKE_MAX_QUERY_SECONDS", 120, 1, 3_600)?,
            query_threads: optional_u64("NANO_OTEL_LAKE_QUERY_THREADS", 4, 1, 256)?,
            query_connections: optional_usize("NANO_OTEL_LAKE_QUERY_CONNECTIONS", 2, 1, 64)?,
            native_library: PathBuf::from(required("NANO_CHDB_LIBRARY_PATH")?),
            native_library_sha256: required_value_or_file(
                "NANO_CHDB_LIBRARY_SHA256",
                "NANO_CHDB_LIBRARY_SHA256_FILE",
            )?,
            catalog: CatalogConfig {
                uri: required("NANO_ICEBERG_CATALOG_URI")?,
                warehouse: required("NANO_ICEBERG_WAREHOUSE")?,
                credential: std::env::var("NANO_ICEBERG_CREDENTIAL").ok(),
                token_file: std::env::var("NANO_ICEBERG_TOKEN_FILE")
                    .ok()
                    .map(PathBuf::from),
                oauth_scope: std::env::var("NANO_ICEBERG_OAUTH_SCOPE").ok(),
                oauth_audience: std::env::var("NANO_ICEBERG_OAUTH_AUDIENCE").ok(),
                oauth_server_uri: std::env::var("NANO_ICEBERG_OAUTH_SERVER_URI").ok(),
                realm: std::env::var("NANO_ICEBERG_REALM").ok(),
                allow_anonymous: optional_bool("NANO_ICEBERG_ALLOW_ANONYMOUS", false)?,
                s3_endpoint: std::env::var("NANO_ICEBERG_S3_ENDPOINT").unwrap_or_default(),
                s3_region: required("NANO_ICEBERG_S3_REGION")?,
                s3_access_key: std::env::var("NANO_ICEBERG_S3_ACCESS_KEY").unwrap_or_default(),
                s3_secret_key: std::env::var("NANO_ICEBERG_S3_SECRET_KEY").unwrap_or_default(),
                s3_session_token: std::env::var("NANO_ICEBERG_S3_SESSION_TOKEN").ok(),
                s3_path_style_access: optional_bool("NANO_ICEBERG_S3_PATH_STYLE", false)?,
                s3_default_credentials: optional_bool(
                    "NANO_ICEBERG_S3_DEFAULT_CREDENTIALS",
                    false,
                )?,
                vended_credentials: optional_bool("NANO_ICEBERG_VENDED_CREDENTIALS", false)?,
            },
        })
    }
}

impl Arguments {
    /// NAN-3243: the lean-lake contract. No Iceberg catalog, no table
    /// identities, no owner writer, no HTTP ingest token: the drain reads the
    /// tenant's handoff prefix with a prefix-scoped credential file and the
    /// query side reads only the local mirror.
    fn lean_from_env() -> Result<Self> { Self::lean_from_env_with_local(false) }

    fn lean_from_env_with_local(trusted_local: bool) -> Result<Self> {
        if shared_mode::active() {
            // the hosted shared deployment mode was the retired gen1 hosted
            // drain; refuse the combination so a mis-render fails at boot.
            bail!("NANO_OTEL_LAKE_MODE=lean must not be combined with DEPLOYMENT_MODE=enterprise_shared");
        }
        let tenant = uuid::Uuid::parse_str(&required("NANO_OTEL_LAKE_TENANT_ID")?)
            .context("lean NANO_OTEL_LAKE_TENANT_ID must be the tenant UUID")?;
        if tenant.is_nil() || tenant.as_hyphenated().to_string() != required("NANO_OTEL_LAKE_TENANT_ID")? {
            bail!("lean NANO_OTEL_LAKE_TENANT_ID must be a lowercase hyphenated tenant UUID");
        }
        let query_token = token_file("NANO_OTEL_LAKE_QUERY_TOKEN_FILE")?;
        // The HTTP ingest boundary is closed on lean (the mirror gate answers
        // 503 before any work); its token is an unguessable per-boot value.
        let ingest_token = if trusted_local { token_file("NANO_OTEL_LAKE_INGEST_TOKEN_FILE")? } else {
            use sha2::Digest;
            let mut digest = sha2::Sha256::new();
            digest.update(b"nano:otel-lean-closed-ingest:v1\0");
            digest.update(&query_token);
            digest.update(uuid::Uuid::now_v7().as_bytes());
            digest.update(uuid::Uuid::now_v7().as_bytes());
            hex::encode(digest.finalize()).into_bytes()
        };
        let mirror_dir = PathBuf::from(required("NANO_OTEL_HANDOFF_MIRROR_DIR")?);
        if !mirror_dir.is_absolute() {
            bail!("NANO_OTEL_HANDOFF_MIRROR_DIR must be absolute");
        }
        let credential_file = if trusted_local { PathBuf::new() } else { PathBuf::from(required("NANO_OTEL_LEAN_R2_CREDENTIAL_FILE")?) };
        if !trusted_local && !credential_file.is_absolute() {
            bail!("NANO_OTEL_LEAN_R2_CREDENTIAL_FILE must be absolute");
        }
        let lean = LeanArguments {
            credential_file,
            credential_reload: std::time::Duration::from_secs(optional_u64(
                "NANO_OTEL_LEAN_CREDENTIAL_RELOAD_SECONDS",
                60,
                5,
                3_600,
            )?),
            mirror_dir,
            mirror_policy: MirrorPolicy {
                max_bytes: optional_u64(
                    "NANO_OTEL_HANDOFF_MIRROR_MAX_BYTES",
                    MirrorPolicy::DEFAULT_MAX_BYTES,
                    64 * 1024 * 1024,
                    4 * 1024 * 1024 * 1024 * 1024,
                )?,
                max_age_hours: u32::try_from(optional_u64(
                    "NANO_OTEL_HANDOFF_MIRROR_MAX_AGE_HOURS",
                    u64::from(MirrorPolicy::DEFAULT_MAX_AGE_HOURS),
                    1,
                    24 * 400,
                )?)?,
            },
            drain_interval: std::time::Duration::from_secs(optional_u64(
                "NANO_OTEL_HANDOFF_DRAIN_INTERVAL_SECS",
                10,
                1,
                300,
            )?),
            maintenance_interval: std::time::Duration::from_secs(optional_u64(
                "NANO_OTEL_LEAN_MAINTENANCE_INTERVAL_SECS",
                60,
                10,
                3_600,
            )?),
            drain_identity: optional("NANO_OTEL_HANDOFF_DRAIN_IDENTITY", "lake-otel-ingest-lean"),
            database_url: required("NANO_OTEL_LAKE_DATABASE_URL")?,
            drain_max_rows: optional_usize(
                "NANO_OTEL_HANDOFF_DRAIN_MAX_ROWS",
                DEFAULT_DRAIN_MAX_ROWS,
                1,
                250_000,
            )?,
            drain_max_objects: optional_usize(
                "NANO_OTEL_HANDOFF_DRAIN_MAX_OBJECTS",
                DEFAULT_DRAIN_MAX_OBJECTS,
                1,
                4_096,
            )?,
            drain_fetch_concurrency: optional_usize(
                "NANO_OTEL_HANDOFF_DRAIN_FETCH_CONCURRENCY",
                DEFAULT_DRAIN_FETCH_CONCURRENCY,
                1,
                MAX_DRAIN_FETCH_CONCURRENCY,
            )?,
            drain_lookback_hours: u32::try_from(optional_u64(
                "NANO_OTEL_HANDOFF_DRAIN_LOOKBACK_HOURS",
                u64::from(DEFAULT_DRAIN_LOOKBACK_HOURS),
                1,
                24 * 90,
            )?)?,
            expiry_batch: optional_usize("NANO_OTEL_LEAN_EXPIRY_BATCH", 256, 1, 4_096)?,
        };
        Ok(Self {
            listen: optional("NANO_OTEL_LAKE_LISTEN", "127.0.0.1:3014")
                .parse()
                .context("NANO_OTEL_LAKE_LISTEN must be a socket address")?,
            ingest_token,
            query_token,
            tenant_id: tenant.to_string(),
            // Never opened on lean (no catalog); kept for the shared state shape.
            spans_table: table_ident("lean_otel.spans")?,
            spans_location: lean_dataset_location(tenant, OtelDataset::Spans),
            metrics_table: table_ident("lean_otel.metrics")?,
            metrics_location: lean_dataset_location(tenant, OtelDataset::Metrics),
            max_body_bytes: if trusted_local { optional_usize("NANO_OTEL_LAKE_MAX_BODY_BYTES", DEFAULT_MAX_BODY_BYTES, 1_024, 512 * 1024 * 1024)? } else { 1_024 },
            max_batch_rows: if trusted_local { optional_usize("NANO_OTEL_LAKE_MAX_BATCH_ROWS", DEFAULT_MAX_BATCH_ROWS, 1, 250_000)? } else { 1 },
            max_query_bytes: optional_u64(
                "NANO_OTEL_LAKE_MAX_QUERY_BYTES",
                4 * 1024 * 1024 * 1024,
                1_024,
                1024 * 1024 * 1024 * 1024,
            )?,
            max_query_memory_bytes: optional_u64(
                "NANO_OTEL_LAKE_MAX_QUERY_MEMORY_BYTES",
                nanosiem_lake_worker::planner::DEFAULT_QUERY_MEMORY_BYTES,
                64 * 1024 * 1024,
                64 * 1024 * 1024 * 1024,
            )?,
            max_query_seconds: optional_u64("NANO_OTEL_LAKE_MAX_QUERY_SECONDS", 120, 1, 3_600)?,
            query_threads: optional_u64("NANO_OTEL_LAKE_QUERY_THREADS", 2, 1, 256)?,
            query_connections: optional_usize("NANO_OTEL_LAKE_QUERY_CONNECTIONS", 2, 1, 64)?,
            native_library: PathBuf::from(required("NANO_CHDB_LIBRARY_PATH")?),
            native_library_sha256: required_value_or_file(
                "NANO_CHDB_LIBRARY_SHA256",
                "NANO_CHDB_LIBRARY_SHA256_FILE",
            )?,
            // Never loaded on lean: the mirror is local files and the drain
            // reads R2 through its own prefix-scoped credential.
            catalog: CatalogConfig {
                uri: String::new(),
                warehouse: String::new(),
                credential: None,
                token_file: None,
                oauth_scope: None,
                oauth_audience: None,
                oauth_server_uri: None,
                realm: None,
                allow_anonymous: false,
                s3_endpoint: String::new(),
                s3_region: String::new(),
                s3_access_key: String::new(),
                s3_secret_key: String::new(),
                s3_session_token: None,
                s3_path_style_access: false,
                s3_default_credentials: true,
                vended_credentials: false,
            },
            lean: Some(lean),
            trusted_local,
        })
    }
}

/// NAN-3243: start the lean-lake drain (handoff -> local mirror) and its
/// maintenance: mirror compaction, dead drain markers, retention expiry of
/// the handoff objects, credential reload. Before the first cycle the mirror
/// is settled (an interrupted compaction recovered, hours outside the window
/// pruned); an empty mirror then re-drains everything inside the window.
async fn spawn_lean_drain(args: &Arguments, lean: &LeanArguments) -> Result<Arc<OtelHandoffDrain>> {
    let tenant = uuid::Uuid::parse_str(&args.tenant_id).context("lean tenant UUID")?;
    let source = Arc::new(LeanOtelR2Source::open(&lean.credential_file, tenant)?);
    let pool = nanosiem_lake_worker::postgres::connect_spot_safe_pool(&lean.database_url, "lake_otel_ingest", 2).await?;
    let presence = Arc::new(PostgresOtelDrainPresence::new(pool, tenant, lean.drain_identity.clone()));
    let ledger = Arc::new(LeanOtelHandoffLedger::new(tenant, lean.mirror_dir.clone(), presence));
    let binding = OtelDrainBinding {
        tenant_uuid: tenant,
        logical_tenant_key: tenant.to_string(),
        bucket: lean_tenant_bucket(tenant),
        spans_location: args.spans_location.clone(),
        metrics_location: args.metrics_location.clone(),
        drain_identity: lean.drain_identity.clone(),
        max_rows: lean.drain_max_rows,
        max_objects: lean.drain_max_objects,
        lookback_hours: lean.drain_lookback_hours,
    };
    let drain = Arc::new(OtelHandoffDrain::lean(
        binding,
        source.clone(),
        ledger.clone(),
        lean.mirror_dir.clone(),
        lean.mirror_policy,
    )?
    .with_fetch_concurrency(lean.drain_fetch_concurrency)?);
    for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
        recover_compaction(&lean.mirror_dir, dataset)
            .with_context(|| format!("recover lean OTLP {} mirror", dataset.as_str()))?;
        // NAN-3886: a drain cycle cut off mid-write (the mirror volume
        // survives a roll) is rolled back before anything reads the mirror.
        let rolled_back = recover_drain_journal(&lean.mirror_dir, dataset, tenant)
            .with_context(|| format!("roll back the interrupted lean OTLP {} drain cycle", dataset.as_str()))?;
        let (resident, pruned) = drain.reconcile_mirror(dataset).await?;
        let scan = load_lean_scan_state(&lean.mirror_dir, dataset);
        tracing::info!(
            dataset = dataset.as_str(),
            resident = resident.len(),
            pruned,
            rolled_back,
            watermark_hour = ?scan.watermark_hour,
            sweep = ?scan.sweep,
            "lean OTLP query mirror settled"
        );
    }
    let (mirror, policy, drain_interval, maintenance_interval, credential_reload, expiry_batch) = (
        lean.mirror_dir.clone(),
        lean.mirror_policy,
        lean.drain_interval,
        lean.maintenance_interval,
        lean.credential_reload,
        lean.expiry_batch,
    );
    let handle = Arc::clone(&drain);
    tokio::spawn(async move {
        let drain = handle;
        let mut unavailable = false;
        let mut last_maintenance = std::time::Instant::now() - maintenance_interval;
        let mut last_reload = std::time::Instant::now();
        let mut warned_no_policy = false;
        // NAN-4084: the handoff retention pass lists R2; it runs every
        // HANDOFF_EXPIRY_INTERVAL (sooner while behind), not every maintenance pass.
        let mut expiry_pacer = HandoffExpiryPacer::default();
        // NAN-3290: a backlogged dataset is drained again on the next loop
        // iteration instead of after `drain_interval` (catch-up after an
        // empty-mirror restart); reload and maintenance timers are still
        // checked every iteration and both datasets are visited each time.
        let mut pacer = DrainPacer::new(drain_interval, std::time::Instant::now());
        loop {
            if last_reload.elapsed() >= credential_reload {
                last_reload = std::time::Instant::now();
                match source.reload() {
                    Ok(true) => tracing::info!("lean OTLP R2 credential rotated"),
                    Ok(false) => {}
                    Err(error) => tracing::error!(error = %error_chain(&error), "lean OTLP R2 credential reload refused; keeping the previous key"),
                }
            }
            for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
                if !pacer.due(dataset, std::time::Instant::now()) {
                    continue;
                }
                // NAN-4084: (backlogged, found anything new). A cycle that
                // found nothing, or failed, backs this dataset off.
                let (backlogged, found) = match drain.drain_once(dataset).await {
                    Ok(report) => {
                        if unavailable {
                            tracing::info!("lean OTLP handoff drain recovered");
                            unavailable = false;
                        }
                        if report.objects_drained > 0 || report.objects_rejected > 0 {
                            tracing::info!(dataset = dataset.as_str(), ?report, "drained lean OTLP handoff objects");
                        }
                        let found = report.objects_pending > 0 || report.objects_drained > 0 || report.objects_rejected > 0;
                        (report.backlogged, found)
                    }
                    Err(error) if !unavailable => {
                        tracing::error!(dataset = dataset.as_str(), error = %error_chain(&error), "lean OTLP handoff drain failed; retrying");
                        unavailable = true;
                        (false, false)
                    }
                    Err(error) => {
                        tracing::debug!(dataset = dataset.as_str(), error = %error, "lean OTLP handoff drain still failing");
                        (false, false)
                    }
                };
                pacer.record(dataset, std::time::Instant::now(), backlogged, found);
            }
            if last_maintenance.elapsed() >= maintenance_interval {
                last_maintenance = std::time::Instant::now();
                let now = Utc::now();
                let current_hour = i32::try_from(now.timestamp().div_euclid(3_600)).unwrap_or(i32::MAX);
                // Fresh, never cached: a hold placed since the last pass must stop this one.
                let purge = match ledger.fresh_purge_policy().await {
                    Ok(purge) => purge,
                    Err(error) => {
                        tracing::warn!(error = %error_chain(&error), "lean OTLP purge policy unreadable; skipping expiry this pass");
                        None
                    }
                };
                let mut max_age_hours = i64::from(policy.max_age_hours);
                if let Some(purge) = purge.as_ref() {
                    max_age_hours = max_age_hours.min(i64::from(purge.retention_days) * 24);
                }
                let floor_hour = i64::from(current_hour) - max_age_hours;
                let expiry_due = expiry_pacer.due(std::time::Instant::now());
                let mut expiry_behind = false;
                for dataset in [OtelDataset::Spans, OtelDataset::Metrics] {
                    let compacted = tokio::task::block_in_place(|| compact_mirror(&mirror, dataset, current_hour));
                    match compacted {
                        Ok(report) if report.hours_compacted > 0 => {
                            tracing::info!(dataset = dataset.as_str(), ?report, "compacted lean OTLP mirror hours");
                        }
                        Ok(_) => {}
                        Err(error) => tracing::warn!(dataset = dataset.as_str(), error = %error_chain(&error), "lean OTLP mirror compaction failed; retrying next pass"),
                    }
                    if let Ok(floor) = i32::try_from(floor_hour - 1) {
                        if let Err(error) = prune_drained_markers(&mirror, dataset, floor) {
                            tracing::warn!(dataset = dataset.as_str(), error = %error_chain(&error), "lean OTLP drain marker prune failed");
                        }
                    }
                    if !expiry_due {
                        continue;
                    }
                    match purge.as_ref() {
                        Some(purge) => match expire_handoff_objects(source.as_ref(), tenant, dataset, purge, now, expiry_batch).await {
                            Ok(report) if report.deleted > 0 || report.held => {
                                expiry_behind |= report.deleted >= expiry_batch;
                                tracing::info!(dataset = dataset.as_str(), ?report, "lean OTLP handoff retention pass");
                            }
                            Ok(_) => {}
                            Err(error) => tracing::warn!(dataset = dataset.as_str(), error = %error_chain(&error), "lean OTLP handoff retention pass failed; retrying next pass"),
                        },
                        None if !warned_no_policy => {
                            warned_no_policy = true;
                            tracing::warn!("lean OTLP drain has no readable purge policy; handoff objects are retained until it does");
                        }
                        None => {}
                    }
                }
                if expiry_due {
                    expiry_pacer.record(std::time::Instant::now(), expiry_behind);
                }
            }
            pause_drain_loop(&pacer).await;
        }
    });
    Ok(drain)
}

/// Sleep until the next dataset is due, or only yield while one is catching up.
async fn pause_drain_loop(pacer: &DrainPacer) {
    let pause = pacer.pause(std::time::Instant::now());
    if pause.is_zero() {
        tokio::task::yield_now().await;
    } else {
        tokio::time::sleep(pause).await;
    }
}

fn token_file(name: &str) -> Result<Vec<u8>> {
    let path = PathBuf::from(required(name)?);
    let mut token = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    while matches!(token.last(), Some(b'\n' | b'\r')) {
        token.pop();
    }
    if token.len() < 32 || token.len() > 4_096 || token.iter().any(|byte| byte.is_ascii_control()) {
        bail!("{name} must contain 32-4096 non-control bytes");
    }
    Ok(token)
}

fn required(name: &str) -> Result<String> {
    std::env::var(name)
        .with_context(|| format!("{name} is required"))
        .and_then(|value| {
            if value.is_empty() || value.chars().any(char::is_control) {
                bail!("{name} is empty or contains control characters");
            }
            Ok(value)
        })
}

fn required_value_or_file(value_name: &str, file_name: &str) -> Result<String> {
    if let Ok(value) = std::env::var(value_name) {
        let value = value.trim();
        if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Ok(value.to_ascii_lowercase());
        }
        bail!("{value_name} must be a 64-character hexadecimal digest");
    }
    let path = PathBuf::from(required(file_name)?);
    let value =
        std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{file_name} must contain a 64-character hexadecimal digest");
    }
    Ok(value.to_ascii_lowercase())
}

fn optional(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn optional_bool(name: &str, default: bool) -> Result<bool> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<bool>()
            .with_context(|| format!("{name} must be true or false")),
        Err(_) => Ok(default),
    }
}

fn optional_usize(name: &str, default: usize, minimum: usize, maximum: usize) -> Result<usize> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .with_context(|| format!("{name} must be an unsigned integer"))?,
        Err(_) => default,
    };
    if !(minimum..=maximum).contains(&value) {
        bail!("{name} must be between {minimum} and {maximum}");
    }
    Ok(value)
}

fn optional_u64(name: &str, default: u64, minimum: u64, maximum: u64) -> Result<u64> {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .with_context(|| format!("{name} must be an unsigned integer"))?,
        Err(_) => default,
    };
    if !(minimum..=maximum).contains(&value) {
        bail!("{name} must be between {minimum} and {maximum}");
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// NAN-2361: an OTLP dataset whose Iceberg table does not exist yet is an
    /// EMPTY dataset, not a failed dependency.
    ///
    /// The tables are created on first write, so before any span or metric is
    /// ingested there is no table — and every query handler used to map that to
    /// 503 SERVICE_UNAVAILABLE. A fresh deployment reported "a required search
    /// service is temporarily unavailable; retry shortly" across the whole
    /// Observability surface, permanently, and retrying could never fix it.
    ///
    /// These assert the empty payloads keep the SHAPE of a populated response,
    /// which is the part a caller actually parses.
    #[test]
    fn empty_metric_tags_mirrors_the_populated_shape() {
        // With a key, the answer is a list of tag VALUES...
        let values = empty_metric_tags(Some("host"));
        assert_eq!(values.tag_values, Some(Vec::new()));
        assert_eq!(values.tag_keys, None);

        // ...without one, a list of tag KEYS. The unused field stays `None`,
        // exactly as it is when rows exist.
        let keys = empty_metric_tags(None);
        assert_eq!(keys.tag_keys, Some(Vec::new()));
        assert_eq!(keys.tag_values, None);

        // An explicitly empty key is "no key", matching the planner's own
        // `filter(|value| !value.is_empty())` selection.
        assert_eq!(empty_metric_tags(Some("")).tag_keys, Some(Vec::new()));
    }

    #[test]
    fn empty_services_response_is_an_empty_page_not_a_null() {
        let body = serde_json::to_value(ServicesResponse {
            services: Vec::new(),
            total: 0,
            has_more: false,
        })
        .unwrap();

        // The Observability services list parses these three fields; `null` for
        // `services` would fault the UI just as the 503 did.
        assert_eq!(body["services"], json!([]));
        assert_eq!(body["total"], json!(0));
        assert_eq!(body["has_more"], json!(false));
    }

    #[test]
    fn rum_preserves_partial_signals_and_empty_contract() {
        let empty = rum_response(&[], &[], &[], &[]);
        assert_eq!(empty["page_views"], json!(0));
        assert_eq!(empty["js_errors"], json!(0));
        assert_eq!(
            empty["web_vitals"],
            json!({"lcp_ms": null, "inp_ms": null, "cls": null})
        );
        let metrics_only = rum_response(&[json!({"lcp_n": 1, "lcp_ms": 1200})], &[], &[], &[]);
        assert_eq!(metrics_only["web_vitals"]["lcp_ms"], json!(1200.0));
        let spans_only = rum_response(
            &[],
            &[json!({"bucket": "2026-10-16 12:00:00", "views": 3, "js_errors": 1})],
            &[],
            &[],
        );
        assert_eq!(spans_only["page_views"], json!(3));
        assert_eq!(spans_only["js_errors"], json!(1));
        assert!(spans_only["web_vitals"]["lcp_ms"].is_null());
    }

    #[test]
    fn decoder_accepts_ndjson_and_enforces_dataset() {
        let body =
            b"{\"schema_version\":\"nano-otlp-lake-v1\",\"dataset\":\"spans\",\"event\":{}}\n";
        let rows = decode_batch(body, OtelDataset::Spans, 10).unwrap();
        assert_eq!(rows.len(), 1);
        assert!(decode_batch(body, OtelDataset::Metrics, 10).is_err());
    }

    #[test]
    fn decoder_rejects_tenant_selection_in_payload() {
        let body = serde_json::to_vec(&vec![json!({
            "schema_version": "nano-otlp-lake-v1",
            "dataset": "metrics",
            "tenant_id": "other",
            "event": {}
        })])
        .unwrap();
        assert!(decode_batch(&body, OtelDataset::Metrics, 10).is_err());
    }

    #[test]
    fn decoder_rejects_unversioned_rows() {
        assert!(decode_batch(b"{\"event\":{}}", OtelDataset::Spans, 10).is_err());
    }

    #[test]
    fn query_source_honors_the_assigned_s3_endpoint() {
        assert_eq!(
            iceberg_query_source(
                "s3://tenant-bucket/tenant-a/otel/spans",
                "http://rustfs-gateway:9000/"
            )
            .unwrap(),
            "http://rustfs-gateway:9000/tenant-bucket/tenant-a/otel/spans"
        );
        assert_eq!(
            iceberg_query_source("s3://tenant-bucket/tenant-a/otel/spans", "").unwrap(),
            "s3://tenant-bucket/tenant-a/otel/spans"
        );
        assert!(iceberg_query_source("file:///tmp/spans", "http://rustfs:9000").is_err());
    }

    #[test]
    fn service_health_and_json_numbers_match_the_product_contract() {
        assert_eq!(service_health(0.0, 599.9), "good");
        assert_eq!(service_health(0.01, 100.0), "warn");
        assert_eq!(service_health(0.0, 600.0), "warn");
        assert_eq!(service_health(0.05, 100.0), "bad");
        assert_eq!(service_health(0.0, 1_000.0), "bad");
        assert_eq!(json_number(&json!({"value": "42.5"}), "value"), 42.5);
        assert_eq!(json_number(&json!({"value": 7}), "value"), 7.0);
        assert!(json_bool(&json!({"value": "1"}), "value"));
        assert!(!json_bool(&json!({"value": 0}), "value"));
        assert_eq!(host_status(74.9, 74.9), "good");
        assert_eq!(host_status(75.0, 10.0), "warn");
        assert_eq!(host_status(10.0, 90.0), "bad");
        assert_eq!(gauge_value(&json!({"count": 0}), "count", 0.0), Value::Null);
        assert_eq!(gauge_value(&json!({"count": 1}), "count", 0.0), json!(0.0));
    }

    #[test]
    fn unattended_metric_aggregate_parser_matches_interactive_metrics() {
        assert_eq!(parse_metric_aggregate("avg").unwrap(), MetricAggregate::Avg);
        assert_eq!(parse_metric_aggregate("P95").unwrap(), MetricAggregate::P95);
        assert_eq!(
            parse_metric_aggregate("rate").unwrap(),
            MetricAggregate::Rate
        );
        assert!(parse_metric_aggregate("median").is_err());
    }
}
