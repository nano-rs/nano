// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native OTLP Iceberg reads used by in-process product evaluators.
//!
//! The Search HTTP service owns interactive observability routes. Metric
//! monitor and SLO schedulers run inside the API process, so they use this
//! narrow client against the same tenant-pinned OTLP service instead of
//! retaining an otherwise hidden ClickHouse dependency.

use crate::lake_http::LakeRequestBuilderExt;
use crate::query::{MetricAgg, MetricQuery, SliKind, TimeRange};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Clone)]
pub(crate) struct OtelLakeEvaluator {
    base_url: Url,
    token: String,
    http: reqwest::Client,
}

#[derive(Debug, Serialize)]
struct MetricScalarRequest<'a> {
    metric_name: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    service_name: Option<&'a str>,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    aggregate: &'static str,
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
struct MetricScalarResponse {
    series: Vec<MetricScalarSeries>,
}

#[derive(Debug, Deserialize)]
struct MetricScalarSeries {
    key: String,
    value: Option<f64>,
    row_count: u64,
}

#[derive(Debug, Serialize)]
struct SloComputeRequest<'a> {
    service_name: &'a str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    sli_kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_threshold_ms: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct SloComputeResponse {
    total: i64,
    good: i64,
    /// Missing on hot-tail-only readers: absence must never prove coverage.
    #[serde(default)]
    complete_window: bool,
}

#[derive(Debug, Deserialize)]
struct SyntheticSummaryResponse {
    summaries: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct SyntheticHistoryResponse {
    history: Vec<serde_json::Value>,
}

#[derive(Debug, Serialize)]
struct OtelNplQueryRequest<'a> {
    dataset: &'a str,
    query: &'a str,
    start: chrono::DateTime<chrono::Utc>,
    end: chrono::DateTime<chrono::Utc>,
    offset: usize,
    limit: usize,
}

#[derive(Debug, Deserialize)]
struct OtelNplQueryResponse {
    dataset: String,
    results: Vec<serde_json::Value>,
    has_more: bool,
    storage_rows_read: u64,
    storage_bytes_read: u64,
    execution_time_ms: u64,
}

pub(crate) struct OtelNplQueryResult {
    pub results: Vec<serde_json::Value>,
    pub has_more: bool,
    pub storage_rows_read: u64,
    pub storage_bytes_read: u64,
    pub execution_time_ms: u64,
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum OtelNplQueryError {
    #[error("{0}")]
    Invalid(String),
    #[error("{0}")]
    ResourceExhausted(String),
    #[error("{0}")]
    Unavailable(String),
}

impl OtelLakeEvaluator {
    pub(crate) fn from_shared_assignment(
        assignment: &crate::search::SharedLakeOtelIngestAssignment,
    ) -> Result<Self, String> {
        let base_url = Url::parse(&assignment.internal_endpoint)
            .map_err(|error| error.to_string())?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.cannot_be_a_base()
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
        {
            return Err(String::from(
                "shared OTLP ingest endpoint must be an http(s) origin without credentials, path, query, or fragment".to_string(),
            ));
        }
        let token = std::fs::read_to_string(&assignment.credential_file)
            .map_err(|error| error.to_string())?;
        let token = token.trim_end_matches(['\r', '\n']).to_string();
        if token.len() < 32 || token.len() > 4_096 || token.chars().any(char::is_control) {
            return Err(String::from(
                "shared OTLP ingest token must be 32-4096 non-control characters".to_string(),
            ));
        }
        if !(1..=3_600).contains(&assignment.timeout_secs) {
            return Err(String::from(
                "shared OTLP ingest timeout must be between 1 and 3600".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(assignment.timeout_secs))
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Self {
            base_url,
            token,
            http,
        })
    }

    pub(crate) fn from_env() -> Result<Option<Self>, String> {

        // Native telemetry shadowing is not implemented: Vector keeps spans
        // and metrics on the legacy sink in shadow mode. Only make the lake a
        // serving dependency once the product is actually in lake mode.
        if !crate::schema::log_query_backend_is_lake() {
            return Ok(None);
        }
        let raw_url = std::env::var("NANO_OTEL_LAKE_QUERY_URL").ok();
        let raw_token_path = std::env::var("NANO_OTEL_LAKE_QUERY_TOKEN_FILE").ok();
        let (raw_url, raw_token_path) = match (raw_url, raw_token_path) {
            (None, None) => return Ok(None),
            (Some(url), Some(path)) => (url, path),
            _ => {
                return Err(
                    "NANO_OTEL_LAKE_QUERY_URL and NANO_OTEL_LAKE_QUERY_TOKEN_FILE must be configured together"
                        .to_string(),
                );
            }
        };
        let base_url = Url::parse(&raw_url).map_err(|error| error.to_string())?;
        if !matches!(base_url.scheme(), "http" | "https")
            || base_url.cannot_be_a_base()
            || base_url.username() != ""
            || base_url.password().is_some()
            || base_url.query().is_some()
            || base_url.fragment().is_some()
            || base_url.path() != "/"
        {
            return Err(
                "NANO_OTEL_LAKE_QUERY_URL must be an http(s) origin without credentials, path, query, or fragment"
                    .to_string(),
            );
        }
        let token_path = PathBuf::from(raw_token_path);
        let token = std::fs::read_to_string(&token_path)
            .map_err(|error| format!("read {}: {error}", token_path.display()))?;
        let token = token.trim_end_matches(['\r', '\n']).to_string();
        if token.len() < 32 || token.len() > 4_096 || token.chars().any(char::is_control) {
            return Err("native OTLP lake token must be 32-4096 non-control characters".into());
        }
        let timeout = std::env::var("NANO_OTEL_LAKE_QUERY_TIMEOUT_SECS")
            .ok()
            .map(|value| value.parse::<u64>())
            .transpose()
            .map_err(|_| "NANO_OTEL_LAKE_QUERY_TIMEOUT_SECS must be an integer".to_string())?
            .unwrap_or(130);
        if !(1..=3_600).contains(&timeout) {
            return Err("NANO_OTEL_LAKE_QUERY_TIMEOUT_SECS must be between 1 and 3600".to_string());
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout))
            .build()
            .map_err(|error| error.to_string())?;
        Ok(Some(Self {
            base_url,
            token,
            http,
        }))
    }

    #[tracing::instrument(name = "db.lake.metric_scalar", skip_all, fields(db.response.rows = tracing::field::Empty, db.response.bytes = tracing::field::Empty))]
    pub(crate) async fn metric_scalar(
        &self,
        query: &MetricQuery<'_>,
        time_range: &TimeRange,
    ) -> Result<Vec<(String, Option<f64>)>, String> {
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/metrics/scalar");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .json(&MetricScalarRequest {
                metric_name: query.metric_name,
                service_name: query.service_name,
                start: time_range.start,
                end: time_range.end,
                aggregate: metric_aggregate_name(query.agg),
                group_by: query.group_by,
                filters: query
                    .filters
                    .iter()
                    .map(|filter| MetricFilterRequest {
                        key: &filter.key,
                        value: &filter.value,
                    })
                    .collect(),
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "native OTLP lake returned HTTP {}",
                response.status()
            ));
        }
        let bytes = response.bytes().await.map_err(|error| error.to_string())?;
        tracing::Span::current().record("db.response.bytes", bytes.len() as u64);
        let scalar: MetricScalarResponse = serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
        tracing::Span::current().record("db.response.rows", scalar.series.len() as u64);
        Ok(scalar.series
            .into_iter()
            .map(|series| {
                let value = if series.row_count == 0 {
                    None
                } else {
                    series.value
                };
                (series.key, value)
            })
            .collect())
    }

    pub(crate) async fn npl_query(
        &self,
        dataset: &str,
        query: &str,
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
    ) -> Result<OtelNplQueryResult, OtelNplQueryError> {
        if !matches!(dataset, "spans" | "metrics") {
            return Err(OtelNplQueryError::Invalid(
                "native OTLP nPL dataset must be spans or metrics".to_string(),
            ));
        }
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/query");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .json(&OtelNplQueryRequest {
                dataset,
                query,
                start: time_range.start,
                end: time_range.end,
                offset,
                limit,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| OtelNplQueryError::Unavailable(error.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            let message = response
                .text()
                .await
                .unwrap_or_else(|_| format!("native OTLP lake returned HTTP {status}"));
            return Err(if status == reqwest::StatusCode::BAD_REQUEST {
                OtelNplQueryError::Invalid(message)
            } else if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
                OtelNplQueryError::ResourceExhausted(message)
            } else {
                OtelNplQueryError::Unavailable(message)
            });
        }
        let response = response
            .json::<OtelNplQueryResponse>()
            .await
            .map_err(|error| OtelNplQueryError::Unavailable(error.to_string()))?;
        if response.dataset != dataset || response.results.len() > limit {
            return Err(OtelNplQueryError::Unavailable(
                "native OTLP lake response violated its assigned dataset or page bound".to_string(),
            ));
        }
        Ok(OtelNplQueryResult {
            results: response.results,
            has_more: response.has_more,
            storage_rows_read: response.storage_rows_read,
            storage_bytes_read: response.storage_bytes_read,
            execution_time_ms: response.execution_time_ms,
        })
    }

    pub(crate) async fn slo_compute(
        &self,
        service: &str,
        kind: SliKind,
        latency_threshold_ms: Option<f64>,
        time_range: &TimeRange,
    ) -> Result<(f64, i64, bool), String> {
        let (current, total, no_data, _) = self.slo_compute_with_coverage(service, kind, latency_threshold_ms, time_range).await?;
        Ok((current, total, no_data))
    }

    pub(crate) async fn slo_compute_with_coverage(
        &self,
        service: &str,
        kind: SliKind,
        latency_threshold_ms: Option<f64>,
        time_range: &TimeRange,
    ) -> Result<(f64, i64, bool, bool), String> {
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/slos/compute");
        let response = self
            .http
            .post(url)
            .bearer_auth(&self.token)
            .json(&SloComputeRequest {
                service_name: service,
                start: time_range.start,
                end: time_range.end,
                sli_kind: match kind {
                    SliKind::Availability => "availability",
                    SliKind::Latency => "latency",
                },
                latency_threshold_ms,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "native OTLP lake returned HTTP {}",
                response.status()
            ));
        }
        let result = response
            .json::<SloComputeResponse>()
            .await
            .map_err(|error| error.to_string())?;
        let no_data = result.total <= 0;
        let current = if no_data {
            1.0
        } else {
            result.good as f64 / result.total as f64
        };
        if result.total < 0 || result.good < 0 || result.good > result.total {
            return Err("invalid SLO count response".into());
        }
        Ok((current, result.total, no_data, result.complete_window))
    }

    pub(crate) async fn synthetic_summary(
        &self,
        time_range: &TimeRange,
    ) -> Result<std::collections::HashMap<String, serde_json::Value>, String> {
        let mut url = self.base_url.clone();
        url.set_path("v1/otel/synthetics/summary");
        url.query_pairs_mut()
            .append_pair("start", &time_range.start.to_rfc3339())
            .append_pair("end", &time_range.end.to_rfc3339());
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "native OTLP lake returned HTTP {}",
                response.status()
            ));
        }
        let rows = response
            .json::<SyntheticSummaryResponse>()
            .await
            .map_err(|error| error.to_string())?
            .summaries;
        let mut summaries = std::collections::HashMap::new();
        for row in rows {
            let Some(check_id) = row.get("check_id").and_then(serde_json::Value::as_str) else {
                continue;
            };
            let total = json_f64(&row, "total");
            let good = json_f64(&row, "good");
            summaries.insert(
                check_id.to_string(),
                serde_json::json!({
                    "uptime_pct": if total > 0.0 { good / total * 100.0 } else { 0.0 },
                    "p50_latency_ms": json_f64_opt(&row, "p50_latency_ms"),
                }),
            );
        }
        Ok(summaries)
    }

    pub(crate) async fn synthetic_history(
        &self,
        check_id: &str,
        time_range: &TimeRange,
        limit: u32,
    ) -> Result<Vec<serde_json::Value>, String> {
        let mut url = self.base_url.clone();
        url.path_segments_mut()
            .map_err(|_| "native OTLP lake URL cannot hold path segments".to_string())?
            .clear()
            .extend(["v1", "otel", "synthetics", check_id, "history"]);
        url.query_pairs_mut()
            .append_pair("start", &time_range.start.to_rfc3339())
            .append_pair("end", &time_range.end.to_rfc3339())
            .append_pair("limit", &limit.to_string());
        let response = self
            .http
            .get(url)
            .bearer_auth(&self.token)
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| error.to_string())?;
        if !response.status().is_success() {
            return Err(format!(
                "native OTLP lake returned HTTP {}",
                response.status()
            ));
        }
        let mut history = response
            .json::<SyntheticHistoryResponse>()
            .await
            .map_err(|error| error.to_string())?
            .history;
        history.reverse();
        Ok(history)
    }
}

fn json_f64(value: &serde_json::Value, field: &str) -> f64 {
    json_f64_opt(value, field).unwrap_or_default()
}

fn json_f64_opt(value: &serde_json::Value, field: &str) -> Option<f64> {
    value.get(field).and_then(|value| {
        value
            .as_f64()
            .or_else(|| value.as_str().and_then(|text| text.parse().ok()))
    })
}

fn metric_aggregate_name(aggregate: MetricAgg) -> &'static str {
    match aggregate {
        MetricAgg::Avg => "avg",
        MetricAgg::Sum => "sum",
        MetricAgg::Min => "min",
        MetricAgg::Max => "max",
        MetricAgg::Count => "count",
        MetricAgg::Rate => "rate",
        MetricAgg::P50 => "p50",
        MetricAgg::P95 => "p95",
        MetricAgg::P99 => "p99",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metric_aggregate_wire_names_cover_the_product_contract() {
        assert_eq!(metric_aggregate_name(MetricAgg::Avg), "avg");
        assert_eq!(metric_aggregate_name(MetricAgg::Rate), "rate");
        assert_eq!(metric_aggregate_name(MetricAgg::P99), "p99");
    }
}

#[cfg(test)]
mod shared_evaluator_tests {
    use super::*;
    use crate::search::SharedLakeOtelIngestAssignment;
    use wiremock::{Mock, MockServer, ResponseTemplate, matchers::{method, path, header}};

    #[tokio::test]
    async fn shared_metric_no_data_stays_absent_and_rotation_requires_fresh_client() {
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("query-token");
        std::fs::write(&token, "a".repeat(48)).unwrap();
        let assignment = SharedLakeOtelIngestAssignment { internal_endpoint:server.uri(), credential_file:token.clone(), timeout_secs:5 };
        let old = OtelLakeEvaluator::from_shared_assignment(&assignment).unwrap();
        Mock::given(method("POST")).and(path("/v1/otel/metrics/scalar"))
            .and(header("authorization", format!("Bearer {}", "a".repeat(48))))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"series":[{"key":"host-a","value":null,"row_count":0}]})))
            .mount(&server).await;
        let now = chrono::Utc::now();
        let range = TimeRange::new(now-chrono::Duration::minutes(1),now);
        let query = MetricQuery { metric_name:"test.gauge",service_name:None,agg:MetricAgg::Avg,group_by:None,filters:&[],step_secs:60 };
        assert_eq!(old.metric_scalar(&query,&range).await.unwrap(),vec![("host-a".into(),None)]);
        server.reset().await;
        Mock::given(method("POST")).and(path("/v1/otel/metrics/scalar"))
            .and(header("authorization", format!("Bearer {}", "a".repeat(48))))
            .respond_with(ResponseTemplate::new(401)).mount(&server).await;
        Mock::given(method("POST")).and(path("/v1/otel/metrics/scalar"))
            .and(header("authorization", format!("Bearer {}", "b".repeat(48))))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"series":[]})))
            .mount(&server).await;
        std::fs::write(&token,"b".repeat(48)).unwrap();
        assert!(old.metric_scalar(&query,&range).await.is_err());
        let fresh = OtelLakeEvaluator::from_shared_assignment(&assignment).unwrap();
        assert!(fresh.metric_scalar(&query,&range).await.unwrap().is_empty());
    }
    #[test]
    fn slo_coverage_must_be_explicit_and_never_defaults_true() {
        let legacy: SloComputeResponse = serde_json::from_value(serde_json::json!({"total":100,"good":99})).unwrap();
        assert!(!legacy.complete_window);
        let attested: SloComputeResponse = serde_json::from_value(serde_json::json!({"total":100,"good":99,"complete_window":true})).unwrap();
        assert!(attested.complete_window);
    }

}
