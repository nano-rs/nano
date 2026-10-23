// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authenticated client for the tenant-pinned native OTLP Iceberg service.

use nanosiem_core::query::{MetricAgg, MetricTagFilter, TimeRange};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum OtelLakeClientError {
    #[error("native OTLP lake client configuration is invalid: {0}")]
    Configuration(String),
    #[error("native OTLP lake request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("native OTLP lake returned HTTP {0}")]
    Status(reqwest::StatusCode),
}

impl OtelLakeClientError {
    /// Cross into the shared search error type without discarding retryability.
    ///
    /// A connect failure, a timeout, or a 502/503/504 from the native OTLP lake
    /// is a transient dependency outage, not a malformed request. Folding those
    /// into a validation error renders an outage as HTTP 400 on Services,
    /// Traces, Metrics, Infrastructure and RUM -- which reads as "your query is
    /// wrong" and is retried by no client policy.
    pub fn into_search_error(self) -> nanosiem_core::search::SearchError {
        // Only a genuine 4xx REQUEST fault belongs to the caller. Everything else --
        // transport failure, any 5xx, an auth skew during hourly token rotation, or
        // a local misconfiguration -- is ours, and must not surface as "your query
        // is malformed".
        match &self {
            Self::Request(error)
                if error.is_timeout() || error.is_connect() || error.is_request() =>
            {
                nanosiem_core::search::SearchError::ServiceUnavailable(
                    "native OTLP lake is temporarily unavailable; retry shortly".to_string(),
                )
            }
            // Admission control has its own contract (HTTP 429) that client backoff
            // keys on; collapsing it into a 400 breaks that retry behaviour.
            Self::Status(status) if status.as_u16() == 429 => {
                nanosiem_core::search::SearchError::AdmissionDenied(
                    "native OTLP lake is rate limiting; retry shortly".to_string(),
                )
            }
            // 401/403 here is a token-rotation skew between this process and the
            // OTLP service, not an authorization decision about the analyst.
            Self::Status(status) if status.as_u16() == 401 || status.as_u16() == 403 => {
                nanosiem_core::search::SearchError::ServiceUnavailable(
                    "native OTLP lake rejected this service's credential; retry shortly"
                        .to_string(),
                )
            }
            Self::Status(status) if status.is_server_error() => {
                nanosiem_core::search::SearchError::ServiceUnavailable(format!(
                    "native OTLP lake returned HTTP {status}; retry shortly"
                ))
            }
            // A local misconfiguration is an operator fault, not a query fault. The
            // core error type has no internal-fault variant, so 503 is the honest
            // choice: it is server-side and the analyst can do nothing about it.
            Self::Configuration(_) => nanosiem_core::search::SearchError::ServiceUnavailable(
                "native OTLP lake is not correctly configured; this is a server-side fault"
                    .to_string(),
            ),
            other => nanosiem_core::search::SearchError::SqlValidationError(other.to_string()),
        }
    }
}

/// A resolved OTLP client: the process-global / gen1 registry client
/// (borrowed for the process lifetime) or a lean-lake route's client (shared,
/// rebuilt when the routes file changes). Handlers use it through `Deref`.
pub enum OtelLakeRef<'a> {
    Borrowed(&'a OtelLakeClient),
    Shared(std::sync::Arc<OtelLakeClient>),
}

impl std::ops::Deref for OtelLakeRef<'_> {
    type Target = OtelLakeClient;
    fn deref(&self) -> &OtelLakeClient {
        match self {
            Self::Borrowed(client) => client,
            Self::Shared(client) => client,
        }
    }
}

/// NAN-3243: tenant-pinned clients for lean-lake tenants' `lake_otel_ingest`
/// (lean mode), resolved from the live-reloaded
/// [`nanosiem_core::search::LeanOtelRouteSource`]. A client is built lazily
/// per tenant from that tenant's admitted route and discarded whenever the
/// source publishes a new map -- the routes file changed, or (NAN-3531) a
/// credential file appeared, rotated, or vanished -- so a rotated token is
/// read within one reload. A route whose client cannot be built answers as
/// absent (the typed 503), never another tenant's client.
pub struct LeanOtelClients {
    source: std::sync::Arc<nanosiem_core::search::LeanOtelRouteSource>,
    cache: std::sync::Mutex<(
        Option<std::sync::Arc<nanosiem_core::search::LeanOtelRoutes>>,
        std::collections::HashMap<uuid::Uuid, std::sync::Arc<OtelLakeClient>>,
    )>,
}

impl LeanOtelClients {
    pub fn new(source: std::sync::Arc<nanosiem_core::search::LeanOtelRouteSource>) -> Self {
        Self { source, cache: std::sync::Mutex::new((None, std::collections::HashMap::new())) }
    }

    /// `None` when [`nanosiem_core::search::lean_otel_routes::LEAN_OTEL_ROUTES_FILE_ENV`] is unset.
    pub fn from_env() -> Option<Self> {
        nanosiem_core::search::LeanOtelRouteSource::from_env().map(Self::new)
    }

    pub(crate) fn routes(&self) -> std::sync::Arc<nanosiem_core::search::LeanOtelRoutes> {
        self.source.current()
    }

    /// The client of exactly this authenticated tenant, or `None`.
    pub fn client(&self, tenant_id: uuid::Uuid) -> Option<std::sync::Arc<OtelLakeClient>> {
        let routes = self.source.current();
        let mut cache = self.cache.lock().ok()?;
        if !cache.0.as_ref().is_some_and(|cached| std::sync::Arc::ptr_eq(cached, &routes)) {
            cache.0 = Some(std::sync::Arc::clone(&routes));
            cache.1.clear();
        }
        if let Some(client) = cache.1.get(&tenant_id) {
            return Some(std::sync::Arc::clone(client));
        }
        let assignment = routes.route(tenant_id)?;
        match OtelLakeClient::from_shared_assignment(assignment) {
            Ok(client) => {
                let client = std::sync::Arc::new(client);
                cache.1.insert(tenant_id, std::sync::Arc::clone(&client));
                Some(client)
            }
            Err(error) => {
                tracing::error!(%tenant_id, %error, "lean OTLP route has no usable client");
                None
            }
        }
    }
}

#[derive(Clone)]
pub struct OtelLakeClient {
    base_url: Url,
    token: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
pub struct LakeTraceResponse {
    pub spans: Vec<Value>,
}

#[derive(Debug, Deserialize)]
struct RecentTracesResponse {
    traces: Vec<Value>,
}

/// The lake's metric-name catalog answer (NAN-4098: time-bounded, cached
/// per tenant in the lake process).
#[derive(Debug, Deserialize)]
pub struct LakeMetricNames {
    pub names: Vec<Value>,
    /// Start of the window the names cover; absent from older lake images.
    #[serde(default)]
    pub window_start: Option<chrono::DateTime<chrono::Utc>>,
    /// True while the catalog covers less than its full window.
    #[serde(default)]
    pub partial: bool,
}

#[derive(Debug, Deserialize)]
pub struct LakeMetricTagsResponse {
    pub tag_keys: Option<Vec<String>>,
    pub tag_values: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub struct LakeServicesResponse {
    pub services: Vec<Value>,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Debug, Deserialize)]
pub struct LakeInfraHostsResponse {
    pub hosts: Vec<Value>,
    pub total: usize,
    pub has_more: bool,
}

#[derive(Debug, Serialize)]
struct MetricRequest<'a> {
    metric_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<&'a str>,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    step_seconds: u32,
    aggregate: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    group_by: Option<&'a str>,
    filters: Vec<MetricFilterRequest<'a>>,
}

#[derive(Debug, Serialize)]
struct MetricFilterRequest<'a> {
    key: &'a str,
    value: &'a str,
}

#[derive(Debug, Deserialize)]
struct MetricResponse {
    series: Vec<Value>,
}

#[derive(Debug, Serialize)]
struct SpansNplQueryRequest<'a> {
    dataset: &'a str,
    query: &'a str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    offset: usize,
    limit: usize,
}

#[derive(Debug, Deserialize)]
struct SpansNplQueryResponse {
    results: Vec<Value>,
}

impl OtelLakeClient {
    /// Configure the native OTLP route only when its URL is explicitly set.
    /// A partial configuration fails boot instead of silently falling back to
    /// ClickHouse and hiding a broken lake deployment.
    pub fn from_env() -> Result<Option<Self>, OtelLakeClientError> {

        // OTLP does not have a shadow comparator yet. In shadow mode Vector
        // intentionally continues writing the legacy tables, so selecting the
        // lake reader here would query an unpopulated dataset.
        if !nanosiem_core::schema::log_query_backend_is_lake() {
            return Ok(None);
        }
        let raw_url = std::env::var("NANO_OTEL_LAKE_QUERY_URL").ok();
        let raw_token_path = std::env::var("NANO_OTEL_LAKE_QUERY_TOKEN_FILE").ok();
        let (raw_url, raw_token_path) = match (raw_url, raw_token_path) {
            (None, None) => return Ok(None),
            (Some(url), Some(path)) => (url, path),
            _ => {
                return Err(OtelLakeClientError::Configuration(
                    "NANO_OTEL_LAKE_QUERY_URL and NANO_OTEL_LAKE_QUERY_TOKEN_FILE must be configured together".to_string(),
                ));
            }
        };
        let base_url = Url::parse(&raw_url)
            .map_err(|error| OtelLakeClientError::Configuration(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.cannot_be_a_base()
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
        {
            return Err(OtelLakeClientError::Configuration(
                "NANO_OTEL_LAKE_QUERY_URL must be an http(s) origin without credentials, path, query, or fragment".to_string(),
            ));
        }
        let token_path = PathBuf::from(raw_token_path);
        let token = std::fs::read_to_string(&token_path)
            .map_err(|error| OtelLakeClientError::Configuration(error.to_string()))?;
        let token = token.trim_end_matches(['\r', '\n']).to_string();
        if token.len() < 32 || token.len() > 4_096 || token.chars().any(char::is_control) {
            return Err(OtelLakeClientError::Configuration(
                "native OTLP lake token must be 32-4096 non-control characters".to_string(),
            ));
        }
        let timeout = std::env::var("NANO_OTEL_LAKE_QUERY_TIMEOUT_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| {
                OtelLakeClientError::Configuration(
                    "NANO_OTEL_LAKE_QUERY_TIMEOUT_SECS must be an integer".to_string(),
                )
            })?
            .unwrap_or(130);
        if !(1..=3_600).contains(&timeout) {
            return Err(OtelLakeClientError::Configuration(
                "NANO_OTEL_LAKE_QUERY_TIMEOUT_SECS must be between 1 and 3600".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .map_err(OtelLakeClientError::Request)?;
        Ok(Some(Self {
            base_url,
            token,
            http,
        }))
    }

    /// The drain origin this client queries (isolation tests only).
    #[cfg(test)]
    pub(crate) fn base_url(&self) -> &str {
        self.base_url.as_str()
    }

    /// NAN-2361 wave 6: one tenant-pinned client per `otel_ingest` entry of
    /// the enterprise-shared worker registry. The credential file is the
    /// service's QUERY token; it was admitted (absolute, private, unique)
    /// by `SharedLakeWorkerRegistry`.
    pub fn from_shared_assignment(
        assignment: &nanosiem_core::search::SharedLakeOtelIngestAssignment,
    ) -> Result<Self, OtelLakeClientError> {
        let base_url = Url::parse(&assignment.internal_endpoint)
            .map_err(|error| OtelLakeClientError::Configuration(error.to_string()))?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.cannot_be_a_base()
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
        {
            return Err(OtelLakeClientError::Configuration(
                "shared OTLP ingest endpoint must be an http(s) origin without credentials, path, query, or fragment".to_string(),
            ));
        }
        let token = std::fs::read_to_string(&assignment.credential_file)
            .map_err(|error| OtelLakeClientError::Configuration(error.to_string()))?;
        let token = token.trim_end_matches(['\r', '\n']).to_string();
        if token.len() < 32 || token.len() > 4_096 || token.chars().any(char::is_control) {
            return Err(OtelLakeClientError::Configuration(
                "shared OTLP ingest token must be 32-4096 non-control characters".to_string(),
            ));
        }
        if !(1..=3_600).contains(&assignment.timeout_secs) {
            return Err(OtelLakeClientError::Configuration(
                "shared OTLP ingest timeout must be between 1 and 3600".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(assignment.timeout_secs))
            .build()
            .map_err(OtelLakeClientError::Request)?;
        Ok(Self {
            base_url,
            token,
            http,
        })
    }

    pub async fn trace(&self, trace_id: &str) -> Result<Vec<Value>, OtelLakeClientError> {
        let mut url = self.base_url.clone();
        url.set_path(&format!("v1/otel/traces/{trace_id}"));
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<LakeTraceResponse>().await?.spans)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn recent_traces(
        &self,
        time_range: &TimeRange,
        service_name: Option<&str>,
        errors_only: bool,
        min_duration_ns: Option<u64>,
        before: Option<chrono::DateTime<chrono::Utc>>,
        limit: u32,
    ) -> Result<Vec<Value>, OtelLakeClientError> {
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/traces");
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("start", &time_range.start.to_rfc3339())
                .append_pair("end", &time_range.end.to_rfc3339())
                .append_pair("errors_only", if errors_only { "true" } else { "false" })
                .append_pair("limit", &limit.clamp(1, 1_000).to_string());
            if let Some(service_name) = service_name.filter(|value| !value.is_empty()) {
                query.append_pair("service_name", service_name);
            }
            if let Some(min_duration_ns) = min_duration_ns {
                query.append_pair("min_duration_ns", &min_duration_ns.to_string());
            }
            if let Some(before) = before {
                query.append_pair("before", &before.to_rfc3339());
            }
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<RecentTracesResponse>().await?.traces)
    }

    pub async fn metric_names(
        &self,
        service_name: Option<&str>,
    ) -> Result<LakeMetricNames, OtelLakeClientError> {
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/metrics/names");
        if let Some(service_name) = service_name.filter(|value| !value.is_empty()) {
            url.query_pairs_mut()
                .append_pair("service_name", service_name);
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<LakeMetricNames>().await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn services(
        &self,
        time_range: &TimeRange,
        step_seconds: u64,
        query: Option<&str>,
        sort: Option<&str>,
        health: Option<&str>,
        offset: u32,
        limit: Option<u32>,
    ) -> Result<LakeServicesResponse, OtelLakeClientError> {
        let step_seconds = u32::try_from(step_seconds.max(1)).map_err(|_| {
            OtelLakeClientError::Configuration("services step is out of range".to_string())
        })?;
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/services");
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("start", &time_range.start.to_rfc3339())
                .append_pair("end", &time_range.end.to_rfc3339())
                .append_pair("step_seconds", &step_seconds.to_string())
                .append_pair("offset", &offset.to_string());
            if let Some(query) = query.filter(|value| !value.is_empty()) {
                pairs.append_pair("q", query);
            }
            if let Some(sort) = sort.filter(|value| !value.is_empty()) {
                pairs.append_pair("sort", sort);
            }
            if let Some(health) = health.filter(|value| !value.is_empty()) {
                pairs.append_pair("health", health);
            }
            if let Some(limit) = limit {
                pairs.append_pair("limit", &limit.to_string());
            }
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<LakeServicesResponse>().await?)
    }

    pub async fn service_detail(
        &self,
        service: &str,
        time_range: &TimeRange,
        step_seconds: u64,
        exemplar_limit: u32,
    ) -> Result<Value, OtelLakeClientError> {
        let step_seconds = u32::try_from(step_seconds.max(1)).map_err(|_| {
            OtelLakeClientError::Configuration("service step is out of range".to_string())
        })?;
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| {
                OtelLakeClientError::Configuration(
                    "native OTLP lake URL cannot carry path segments".to_string(),
                )
            })?
            .clear()
            .extend(["v1", "otel", "services", service]);
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("start", &time_range.start.to_rfc3339())
                .append_pair("end", &time_range.end.to_rfc3339())
                .append_pair("step_seconds", &step_seconds.to_string())
                .append_pair("exemplar_limit", &exemplar_limit.to_string());
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<Value>().await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn infra_hosts(
        &self,
        time_range: &TimeRange,
        query: Option<&str>,
        group: Option<&str>,
        environment: Option<&str>,
        status: Option<&str>,
        offset: u32,
        limit: Option<u32>,
    ) -> Result<LakeInfraHostsResponse, OtelLakeClientError> {
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/infra/hosts");
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("start", &time_range.start.to_rfc3339())
                .append_pair("end", &time_range.end.to_rfc3339())
                .append_pair("offset", &offset.to_string());
            for (name, value) in [
                ("q", query),
                ("group", group),
                ("env", environment),
                ("status", status),
            ] {
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    pairs.append_pair(name, value);
                }
            }
            if let Some(limit) = limit {
                pairs.append_pair("limit", &limit.to_string());
            }
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<LakeInfraHostsResponse>().await?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn rum(
        &self,
        time_range: &TimeRange,
        step_seconds: u64,
        page: Option<&str>,
        browser: Option<&str>,
        environment: Option<&str>,
    ) -> Result<Value, OtelLakeClientError> {
        let step_seconds = u32::try_from(step_seconds.max(1)).map_err(|_| {
            OtelLakeClientError::Configuration("RUM step is out of range".to_string())
        })?;
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/rum");
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("start", &time_range.start.to_rfc3339())
                .append_pair("end", &time_range.end.to_rfc3339())
                .append_pair("step_seconds", &step_seconds.to_string());
            for (name, value) in [("page", page), ("browser", browser), ("env", environment)] {
                if let Some(value) = value.filter(|value| !value.is_empty()) {
                    pairs.append_pair(name, value);
                }
            }
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<Value>().await?)
    }

    /// Resolve the distinct hosts a service's spans ran on over the window
    /// (NAN-2361 — Observability ↔ Security convergence, Step 1).
    ///
    /// Runs an nPL aggregation against the SPANS dataset of the lake's
    /// `/v1/otel/query` endpoint: `service_name="<svc>" | stats count by
    /// host.name`. `host.name` is the OTLP semantic-convention resource
    /// attribute and resolves by its literal dotted name into the
    /// `attributes`/`resource_attributes` maps — do NOT use the spans table's
    /// legacy UDM-named columns (`src_ip`/`host`/`user`); they are retired
    /// vocabulary and `src_ip` is empty in practice.
    ///
    /// Returns the non-empty `host.name` values (dedup is the caller's
    /// concern). `limit` bounds the number of grouped rows.
    pub async fn service_span_hosts(
        &self,
        service: &str,
        time_range: &TimeRange,
        limit: usize,
    ) -> Result<Vec<String>, OtelLakeClientError> {
        // The nPL double-quoted grammar has no escape sequences: the only safe
        // embedding is the shared strip-based sanitizer (NAN-1157/NAN-1740).
        let service = nanosiem_core::query::sanitize_npl_quoted_value(service);
        let query = format!("service_name=\"{service}\" | stats count by host.name");
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/query");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .json(&SpansNplQueryRequest {
                dataset: "spans",
                query: &query,
                start: time_range.start,
                end: time_range.end,
                offset: 0,
                limit,
            })
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        let rows = response.json::<SpansNplQueryResponse>().await?.results;
        Ok(rows
            .into_iter()
            .filter_map(|row| {
                row.get("host.name")
                    .and_then(Value::as_str)
                    .map(str::trim)
                    .filter(|value| !value.is_empty())
                    .map(ToString::to_string)
            })
            .collect())
    }

    pub async fn metric_tags(
        &self,
        metric_name: &str,
        key: Option<&str>,
        time_range: &TimeRange,
    ) -> Result<LakeMetricTagsResponse, OtelLakeClientError> {
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/metrics/tags");
        {
            let mut pairs = url.query_pairs_mut();
            pairs
                .append_pair("metric_name", metric_name)
                .append_pair("start", &time_range.start.to_rfc3339())
                .append_pair("end", &time_range.end.to_rfc3339());
            if let Some(key) = key.filter(|value| !value.is_empty()) {
                pairs.append_pair("key", key);
            }
        }
        let response = self.http.get(url).bearer_auth(&self.token).send().await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<LakeMetricTagsResponse>().await?)
    }

    pub async fn metric_timeseries(
        &self,
        metric_name: &str,
        service_name: Option<&str>,
        time_range: &TimeRange,
        step_seconds: u64,
        aggregate: MetricAgg,
        group_by: Option<&str>,
        filters: &[MetricTagFilter],
    ) -> Result<Vec<Value>, OtelLakeClientError> {
        let aggregate = match aggregate {
            MetricAgg::Avg => "avg",
            MetricAgg::Sum => "sum",
            MetricAgg::Min => "min",
            MetricAgg::Max => "max",
            MetricAgg::Count => "count",
            MetricAgg::Rate => "rate",
            MetricAgg::P50 => "p50",
            MetricAgg::P95 => "p95",
            MetricAgg::P99 => "p99",
        };
        let step_seconds = u32::try_from(step_seconds.max(1)).map_err(|_| {
            OtelLakeClientError::Configuration("metric step is out of range".to_string())
        })?;
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/metrics/timeseries");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .json(&MetricRequest {
                metric_name,
                service_name,
                start: time_range.start,
                end: time_range.end,
                step_seconds,
                aggregate,
                group_by,
                filters: filters
                    .iter()
                    .map(|filter| MetricFilterRequest {
                        key: &filter.key,
                        value: &filter.value,
                    })
                    .collect(),
            })
            .send()
            .await?;
        if !response.status().is_success() {
            return Err(OtelLakeClientError::Status(response.status()));
        }
        Ok(response.json::<MetricResponse>().await?.series)
    }
}

#[cfg(test)]
mod tests {
    use super::OtelLakeClientError;
    use reqwest::StatusCode;

    /// A down native OTLP lake must reach the analyst as a retryable 503, not as
    /// a 400 that reads like a malformed query. Only the transport/gateway
    /// classes are retryable -- a misconfiguration is the operator's to fix and
    /// must stay a validation error so it is not retried forever.
    #[test]
    fn an_unavailable_otlp_lake_is_retryable_but_a_misconfiguration_is_not() {
        for status in [502_u16, 503, 504] {
            let error = OtelLakeClientError::Status(StatusCode::from_u16(status).unwrap());
            assert!(
                matches!(
                    error.into_search_error(),
                    nanosiem_core::search::SearchError::ServiceUnavailable(_)
                ),
                "HTTP {status} from the OTLP lake must be retryable"
            );
        }
        // A server fault, an auth skew during token rotation, and admission control
        // each keep their own contract instead of collapsing into "malformed query".
        for status in [500_u16, 502, 503, 504, 401, 403] {
            let error = OtelLakeClientError::Status(StatusCode::from_u16(status).unwrap());
            assert!(
                matches!(
                    error.into_search_error(),
                    nanosiem_core::search::SearchError::ServiceUnavailable(_)
                ),
                "HTTP {status} is a server-side fault and must be retryable"
            );
        }
        assert!(matches!(
            OtelLakeClientError::Status(StatusCode::TOO_MANY_REQUESTS).into_search_error(),
            nanosiem_core::search::SearchError::AdmissionDenied(_)
        ));
        // Only a genuine client-side 4xx stays a validation error.
        for status in [400_u16, 404, 422] {
            let error = OtelLakeClientError::Status(StatusCode::from_u16(status).unwrap());
            assert!(
                matches!(
                    error.into_search_error(),
                    nanosiem_core::search::SearchError::SqlValidationError(_)
                ),
                "HTTP {status} is a request fault"
            );
        }
        // A misconfiguration is the operator's fault, never the analyst's.
        assert!(matches!(
            OtelLakeClientError::Configuration("missing token".to_string()).into_search_error(),
            nanosiem_core::search::SearchError::ServiceUnavailable(_)
        ));
    }

    use super::*;

    #[test]
    fn lake_url_must_be_an_origin() {
        let url = Url::parse("http://127.0.0.1:3014/path").unwrap();
        assert_ne!(url.path(), "/");
    }

    /// NAN-3531: a token rotated at the same path reaches the tenant's client
    /// within one route reload, with routes.json unchanged.
    #[cfg(unix)]
    #[test]
    fn a_rotated_lean_token_rebuilds_the_tenant_client() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let write_token = |content: &str| {
            let staging = dir.path().join(".token.tmp");
            std::fs::write(&staging, content).unwrap();
            std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(0o400)).unwrap();
            std::fs::rename(&staging, dir.path().join("token")).unwrap();
        };
        write_token(&"a".repeat(48));
        let tenant = uuid::Uuid::now_v7();
        let routes = dir.path().join("routes.json");
        std::fs::write(
            &routes,
            serde_json::to_vec(&serde_json::json!({ tenant.to_string(): {
                "internal_endpoint": "http://otel.nano-lean.svc:3014",
                "credential_file": dir.path().join("token"),
            }}))
            .unwrap(),
        )
        .unwrap();
        let source = std::sync::Arc::new(nanosiem_core::search::LeanOtelRouteSource::from_file(&routes));
        let clients = super::LeanOtelClients::new(std::sync::Arc::clone(&source));
        assert_eq!(clients.client(tenant).unwrap().token, "a".repeat(48));
        write_token(&"b".repeat(48));
        source.reload();
        assert_eq!(clients.client(tenant).unwrap().token, "b".repeat(48));
        assert!(clients.client(uuid::Uuid::now_v7()).is_none());
    }

    /// NAN-4098: the lake's catalog answer carries its coverage; an older lake
    /// image's `{names, count}` still decodes (full, unbounded semantics).
    #[test]
    fn lake_metric_names_decodes_new_and_old_shapes() {
        let new: LakeMetricNames = serde_json::from_value(serde_json::json!({
            "names": [{"metric_name": "a"}],
            "count": 1,
            "window_start": "2026-10-17T23:00:00Z",
            "partial": true
        }))
        .unwrap();
        assert_eq!(new.names.len(), 1);
        assert!(new.partial);
        assert!(new.window_start.is_some());

        let old: LakeMetricNames = serde_json::from_value(serde_json::json!({
            "names": [{"metric_name": "a"}],
            "count": 1
        }))
        .unwrap();
        assert!(!old.partial);
        assert!(old.window_start.is_none());
    }
}
