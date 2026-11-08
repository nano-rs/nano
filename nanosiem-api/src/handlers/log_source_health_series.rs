// SPDX-License-Identifier: AGPL-3.0-or-later

//! Log Sources "how do I send data" and per-source health (NAN-4922, open core).
//!
//! The ClickHouse product's replacements for main's hosted-only
//! (`enterprise_shared_sources.rs`) endpoints the unified Add source flow and
//! the Log Source detail read:
//!
//! * `GET /api/log-sources/ingest-endpoint`: the URLs a sender posts to: HTTP
//!   JSON and OTLP through the authenticated web edge, HEC on Vector's listener.
//! * `GET /api/log-sources/health-series` and `GET /api/log-sources/{id}/health-series`:
//!   hourly volume against a seasonal expected band, from the per-source
//!   rollup, under the caller's source scope (NAN-2059).

use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Extension, Json,
};
use nanosiem_core::auth::permissions;
use nanosiem_core::ingest_tokens::TokenDelivery;
use nanosiem_core::log_sources::health_series::{
    BucketAssessment, HealthSeriesPoint, HealthSeriesReader, LogSourceHealthSeries, SegmentDimension,
    SegmentHealthSeries, SourceHealthState, DEFAULT_SERIES_HOURS,
};
use nanosiem_core::typeid::TypeIdParam;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use crate::middleware::{ensure_permission, AuthContext};
use crate::{error::ApiError, state::AppState};

// ---------------------------------------------------------------------------
// Ingest endpoint
// ---------------------------------------------------------------------------

/// The public origin users and senders reach (`https://siem.example[:port]`).
pub const ENV_PUBLIC_BASE_URL: &str = "NANO_INGEST_PUBLIC_BASE_URL";
/// install.sh / compose's public URL; used when the NANO_ variable is unset.
pub const ENV_BASE_URL: &str = "BASE_URL";
/// Vector's HEC listener port (install.sh advertises `http://<host>:8088`).
pub const ENV_HEC_PORT: &str = "NANO_INGEST_HEC_PORT";
/// `http` (default) or `https` when TLS is terminated in front of the HEC listener.
pub const ENV_HEC_SCHEME: &str = "NANO_INGEST_HEC_SCHEME";

/// `GET /api/log-sources/ingest-endpoint`.
///
/// HTTP JSON and OTLP go through the deployment's web edge (nginx), which
/// terminates TLS like the UI: `<base>/ingest` is proxied to Vector's HTTP
/// source (which checks the token), and `<base>/otlp/v1/*` is authenticated by
/// nginx `auth_request` against the token before it reaches Vector. Vector's
/// raw HTTP (8080) and OTLP (4318) listeners are never returned: 4318 does not
/// authenticate and is loopback-only, and neither terminates TLS.
///
/// HEC has no edge path: senders reach Vector's HEC listener directly
/// (install.sh's `http://<host>:8088/services/collector/event`), and Vector
/// authenticates the token itself. Those URLs are the `hec_*` fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, ToSchema)]
pub struct IngestEndpoint {
    /// The public web origin the edge URLs are built on (scheme, host, port).
    pub base_url: String,
    /// The host part of `base_url`.
    pub hostname: String,
    /// `http` or `https`: the scheme of `base_url`.
    pub scheme: String,
    /// HTTP JSON through the edge: `{base_url}/ingest` (`Authorization: Bearer <token>`).
    pub nano_https_url: String,
    /// OTLP/HTTP through the edge's `auth_request`: `{base_url}/otlp/v1/logs`.
    pub otlp_logs_url: String,
    pub otlp_traces_url: String,
    pub otlp_metrics_url: String,
    /// Vector's HEC listener (direct, not through the edge): `{hec_scheme}://{hostname}:{hec_port}`.
    /// What a HEC client's endpoint setting takes.
    pub hec_url: String,
    /// `{hec_url}/services/collector/event`.
    pub hec_event_url: String,
    /// `{hec_url}/services/collector/health`.
    pub hec_health_url: String,
    /// True when the origin came from configuration (`NANO_INGEST_PUBLIC_BASE_URL`
    /// or `BASE_URL`); false when it was inferred from the request.
    pub configured: bool,
    /// How ingest tokens reach Vector; `none` = tokens cannot be issued here.
    pub token_delivery: TokenDelivery,
}

/// The ingest settings, as read from the environment.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IngestEndpointConfig {
    pub public_base_url: Option<String>,
    pub base_url: Option<String>,
    pub hec_port: Option<String>,
    pub hec_scheme: Option<String>,
}

impl IngestEndpointConfig {
    pub fn from_env() -> Self {
        let var = |k: &str| std::env::var(k).ok();
        Self {
            public_base_url: var(ENV_PUBLIC_BASE_URL),
            base_url: var(ENV_BASE_URL),
            hec_port: var(ENV_HEC_PORT),
            hec_scheme: var(ENV_HEC_SCHEME),
        }
    }
}

/// What the request says about the origin the browser used.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RequestOrigin<'a> {
    pub host: Option<&'a str>,
    pub forwarded_host: Option<&'a str>,
    pub forwarded_proto: Option<&'a str>,
}

/// A bare hostname, IPv4 or bracketed IPv6 address: no scheme, path, port,
/// credentials or whitespace. Anything else is refused (never echoed into a URL).
pub fn valid_host(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return inner.parse::<std::net::Ipv6Addr>().is_ok();
    }
    host.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !host.starts_with(['-', '.'])
        && !host.ends_with('-')
}

/// `host[:port]` / `[v6][:port]`, validated and lowercased: `(host, port)`.
pub fn parse_authority(value: &str) -> Option<(String, Option<u16>)> {
    let value = value.trim();
    let (host, port) = if value.starts_with('[') {
        let end = value.find(']')?;
        let rest = &value[end + 1..];
        let port = match rest.strip_prefix(':') {
            Some(p) => Some(p.parse::<u16>().ok().filter(|p| *p > 0)?),
            None if rest.is_empty() => None,
            None => return None,
        };
        (&value[..=end], port)
    } else {
        match value.rsplit_once(':') {
            Some((h, p)) => (h, Some(p.parse::<u16>().ok().filter(|p| *p > 0)?)),
            None => (value, None),
        }
    };
    let host = host.to_ascii_lowercase();
    valid_host(&host).then_some((host, port))
}

/// The hostname of a Host header value (`host[:port]`, `[v6][:port]`), validated.
pub fn host_from_header(value: &str) -> Option<String> {
    parse_authority(value).map(|(h, _)| h)
}

/// An origin `scheme://authority` (a trailing `/` is allowed; any other path,
/// query or credentials is refused): `(scheme, host, port)`.
pub fn parse_origin(value: &str) -> Option<(String, String, Option<u16>)> {
    let value = value.trim().trim_end_matches('/');
    let (scheme, rest) = value.split_once("://")?;
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        return None;
    }
    if rest.contains(['/', '?', '#', '@']) {
        return None;
    }
    let (host, port) = parse_authority(rest)?;
    Some((scheme, host, port))
}

fn origin(scheme: &str, host: &str, port: Option<u16>) -> String {
    let default = if scheme == "https" { 443 } else { 80 };
    match port {
        Some(p) if p != default => format!("{scheme}://{host}:{p}"),
        _ => format!("{scheme}://{host}"),
    }
}

fn port(value: Option<&str>, default: u16) -> u16 {
    value
        .and_then(|v| v.trim().parse::<u16>().ok())
        .filter(|p| *p > 0)
        .unwrap_or(default)
}

/// Pure: the endpoint for this config and request.
pub fn derive_ingest_endpoint(
    config: &IngestEndpointConfig,
    request: &RequestOrigin<'_>,
    token_delivery: TokenDelivery,
) -> IngestEndpoint {
    let configured_origin = [config.public_base_url.as_deref(), config.base_url.as_deref()]
        .into_iter()
        .flatten()
        .find_map(parse_origin);
    let configured = configured_origin.is_some();
    let (scheme, hostname, base_port) = configured_origin.unwrap_or_else(|| {
        // nginx sets X-Forwarded-Proto; Host carries the port the browser used.
        let scheme = match request.forwarded_proto.map(|p| p.trim().to_ascii_lowercase()) {
            Some(p) if p == "https" => "https",
            _ => "http",
        };
        let authority = request
            .forwarded_host
            .and_then(parse_authority)
            .or_else(|| request.host.and_then(parse_authority))
            .unwrap_or_else(|| ("localhost".to_string(), None));
        (scheme.to_string(), authority.0, authority.1)
    });
    let base_url = origin(&scheme, &hostname, base_port);
    let hec_scheme = match config.hec_scheme.as_deref().map(|s| s.trim().to_ascii_lowercase()) {
        Some(s) if s == "https" => "https",
        _ => "http",
    };
    let hec_url = format!("{hec_scheme}://{hostname}:{}", port(config.hec_port.as_deref(), 8088));
    IngestEndpoint {
        nano_https_url: format!("{base_url}/ingest"),
        otlp_logs_url: format!("{base_url}/otlp/v1/logs"),
        otlp_traces_url: format!("{base_url}/otlp/v1/traces"),
        otlp_metrics_url: format!("{base_url}/otlp/v1/metrics"),
        hec_event_url: format!("{hec_url}/services/collector/event"),
        hec_health_url: format!("{hec_url}/services/collector/health"),
        hec_url,
        base_url,
        hostname,
        scheme,
        configured,
        token_delivery,
    }
}

/// Where senders post events on this deployment.
#[utoipa::path(
    get,
    path = "/api/log-sources/ingest-endpoint",
    tag = "log_sources",
    responses(
        (status = 200, description = "Edge URLs for HTTP JSON and OTLP/HTTP, and the HEC listener", body = IngestEndpoint),
        (status = 403, description = "Forbidden"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_ingest_endpoint(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    headers: HeaderMap,
) -> Result<Json<IngestEndpoint>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok());
    let request = RequestOrigin {
        host: header("host"),
        forwarded_host: header("x-forwarded-host"),
        forwarded_proto: header("x-forwarded-proto"),
    };
    Ok(Json(derive_ingest_endpoint(
        &IngestEndpointConfig::from_env(),
        &request,
        state.ingest_token_service.delivery(),
    )))
}

// ---------------------------------------------------------------------------
// Health series
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct HealthSeriesQuery {
    /// Window in hours (1..=168, default 24).
    pub hours: Option<i64>,
}

fn reader(state: &AppState) -> HealthSeriesReader {
    let pool = state.dual_pool();
    HealthSeriesReader::new(pool.clickhouse().clone(), pool.table_names())
}

fn series_unavailable(error: String) -> ApiError {
    tracing::warn!(%error, "log source health series read failed");
    ApiError::ServiceUnavailable("Source health is unavailable (ClickHouse)".into())
}

/// Health series for every log source.
#[utoipa::path(
    get,
    path = "/api/log-sources/health-series",
    tag = "log_sources",
    params(HealthSeriesQuery),
    responses(
        (status = 200, description = "Hourly volume against the seasonal expected band, per log source", body = Vec<LogSourceHealthSeries>),
        (status = 403, description = "Forbidden"),
        (status = 503, description = "ClickHouse unavailable"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn list_health_series(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Query(query): Query<HealthSeriesQuery>,
) -> Result<Json<Vec<LogSourceHealthSeries>>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    let sources = state.log_source_service.list(None).await?;
    let series = reader(&state)
        .series(&sources, query.hours.unwrap_or(DEFAULT_SERIES_HOURS), &auth.effective_viewer_scope())
        .await
        .map_err(series_unavailable)?;
    Ok(Json(series))
}

/// Health series for one log source (a one-element array).
#[utoipa::path(
    get,
    path = "/api/log-sources/{id}/health-series",
    tag = "log_sources",
    params(("id" = String, Path, description = "Log source ID"), HealthSeriesQuery),
    responses(
        (status = 200, description = "A one-element array", body = Vec<LogSourceHealthSeries>),
        (status = 403, description = "Forbidden"),
        (status = 404, description = "Not found (or an enrichment source)"),
        (status = 503, description = "ClickHouse unavailable"),
    ),
    security(("bearer_auth" = []), ("api_key" = []))
)]
pub async fn get_health_series(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthContext>,
    Path(id): Path<TypeIdParam>,
    Query(query): Query<HealthSeriesQuery>,
) -> Result<Json<Vec<LogSourceHealthSeries>>, ApiError> {
    ensure_permission(&auth, permissions::LOG_SOURCES_VIEW)?;
    let source = state.log_source_service.get(*id).await?;
    let series = reader(&state)
        .series(std::slice::from_ref(&source), query.hours.unwrap_or(DEFAULT_SERIES_HOURS), &auth.effective_viewer_scope())
        .await
        .map_err(series_unavailable)?;
    if series.is_empty() {
        return Err(ApiError::NotFound("Enrichment sources have no health series".into()));
    }
    Ok(Json(series))
}

#[derive(utoipa::OpenApi)]
#[openapi(
    paths(get_ingest_endpoint, list_health_series, get_health_series),
    components(schemas(
        IngestEndpoint,
        TokenDelivery,
        LogSourceHealthSeries,
        SegmentHealthSeries,
        HealthSeriesPoint,
        SourceHealthState,
        BucketAssessment,
        SegmentDimension
    )),
    tags((name = "log_sources", description = "Log source management"))
)]
pub struct LogSourceHealthSeriesApiDoc;

#[cfg(test)]
#[path = "log_source_health_series_tests.rs"]
mod tests;
