// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC lookup against the canonical ClickHouse store.
//!
//! Post-NAN-1112 this module is a single read-side helper —
//! [`lookup_ioc_all_sources`] queries `nanosiem.custom_enrichment_results`
//! (the same table the `custom_ioc_enrichment_dict` ingest-time
//! enrichment is built from) and returns one [`IocLookupResult`] per
//! `(source, key)` pair. The only caller is the prevalence/discovery
//! artifact-detail "threat_intel" panel.
//!
//! The legacy PG-backed `IocRepository` + `sync_threatfox` /
//! `sync_tor_exit_nodes` engine + `ioc_enrichments` table were deleted
//! in NAN-1112. See `project_iocs_canonical_storage_is_clickhouse` for
//! the architectural rationale ("just go direct to CH").

mod types;

pub use types::IocLookupResult;

use crate::db::dual_pool::{on_cluster_clause, TableNames};
use crate::lake_http::LakeRequestBuilderExt;
use clickhouse::Row;
use serde::{Deserialize as SerdeDeserialize, Serialize};
use std::path::PathBuf;
use std::time::Duration;
use thiserror::Error;
use tracing::instrument;

/// Row shape for the CH `custom_enrichment_results` aggregation. The
/// `clickhouse` crate requires a `Row`-deriving named struct for column
/// mapping — tuples don't implement `Row`.
#[derive(Debug, Row, SerdeDeserialize)]
struct CustomEnrichmentIocRow {
    enrichment_name: String,
    key_type: String,
    threat_type: String,
    malware: String,
    confidence: u8,
    first_seen: i64,
    last_seen: i64,
    tags: Vec<String>,
}

/// Errors that can occur during a CH-backed IOC lookup.
#[derive(Debug, Error)]
pub enum IocLookupError {
    #[error("ClickHouse error: {0}")]
    Clickhouse(#[from] clickhouse::error::Error),
    #[error("Lake IOC lookup error: {0}")]
    Lake(String),
}

/// Typed client for the tenant-pinned immutable IOC snapshot assigned to a
/// lake worker. Storage coordinates and credentials never appear in product
/// requests; the caller supplies only an indicator and the expected snapshot
/// identity from process configuration.
#[derive(Clone)]
pub struct LakeIocClient {
    http: reqwest::Client,
    base_url: String,
    tenant_id: String,
    bearer_token: String,
    snapshot_id: String,
}

impl LakeIocClient {
    /// The cell route is resolved from the authenticated tenant.
    pub fn from_lake_cell_route(route: &crate::search::lake_cell::LakeCellRoute) -> Result<Self, IocLookupError> {
        route.validate_query_base().map_err(IocLookupError::Lake)?;
        let bearer_token = route.read_router_token().map_err(IocLookupError::Lake)?;
        let tenant_id = route.tenant_id.to_string();
        let http = crate::search::lake_cell::lake_cell_http_client_builder(Duration::from_secs(130))
            .build()
            .map_err(|error| IocLookupError::Lake(format!("build cell IOC client: {error}")))?;
        Ok(Self { http, base_url: route.query_base_url.clone(), tenant_id: tenant_id.clone(),
            bearer_token, snapshot_id: default_ioc_snapshot_id(&tenant_id) })
    }
    pub fn from_env() -> Result<Option<Self>, IocLookupError> {
        // NAN-3492: a trusted-local install reads IOC through its dedicated
        // lean cell's query[T] (the tenant-bound current pointer).
        if let Some(route) = crate::search::lake_cell::dedicated_route_from_env()
            .map_err(IocLookupError::Lake)?
        {
            return Self::from_lake_cell_route(&route).map(Some);
        }
        let base_url = required_env("NANO_LAKE_QUERY_URL")?;
        let tenant_id = required_env("NANO_LAKE_TENANT_ID")?;
        validate_identity("NANO_LAKE_TENANT_ID", &tenant_id)?;
        // The enrichment coordinator intentionally keeps one stable logical
        // pointer per tenant while the immutable snapshot version changes
        // inside the atomically activated worker generation. Derive that
        // pointer from the already-required tenant assignment so a lake
        // install cannot accidentally enable writes while leaving every IOC
        // read path disabled. Historical/fault tests may still override it.
        let snapshot_id = optional_env("NANO_LAKE_IOC_SNAPSHOT_ID")
            .unwrap_or_else(|| default_ioc_snapshot_id(&tenant_id));
        validate_identity("NANO_LAKE_IOC_SNAPSHOT_ID", &snapshot_id)?;
        let token_file = PathBuf::from(required_env("NANO_LAKE_QUERY_TOKEN_FILE")?);
        let bearer_token = std::fs::read_to_string(&token_file)
            .map_err(|error| {
                IocLookupError::Lake(format!(
                    "failed to read NANO_LAKE_QUERY_TOKEN_FILE {}: {error}",
                    token_file.display()
                ))
            })?
            .trim()
            .to_string();
        if bearer_token.is_empty() {
            return Err(IocLookupError::Lake(
                "NANO_LAKE_QUERY_TOKEN_FILE contains no bearer token".to_string(),
            ));
        }
        let timeout_secs = optional_env("NANO_LAKE_IOC_TIMEOUT_SECS")
            .map(|value| {
                value.parse::<u64>().map_err(|_| {
                    IocLookupError::Lake(
                        "NANO_LAKE_IOC_TIMEOUT_SECS must be an integer".to_string(),
                    )
                })
            })
            .transpose()?
            .unwrap_or(10);
        if !(1..=300).contains(&timeout_secs) {
            return Err(IocLookupError::Lake(
                "NANO_LAKE_IOC_TIMEOUT_SECS must be between 1 and 300".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .build()
            .map_err(|error| IocLookupError::Lake(format!("build IOC client: {error}")))?;
        Ok(Some(Self {
            http,
            base_url: base_url.trim_end_matches('/').to_string(),
            tenant_id,
            bearer_token,
            snapshot_id,
        }))
    }

    /// NAN-2361 wave 6: build the IOC reader for ONE hosted-shared tenant
    /// from its verified worker assignment — the
    /// `RiskLakeClient::from_shared_assignment` shape. The tenant id is the
    /// security tenant UUID the assignment was admitted for (never
    /// `NANO_LAKE_TENANT_ID`), the endpoint and bearer credential are the
    /// tenant query worker's, and the snapshot identity is the stable
    /// per-tenant pointer the tenant `lake_enrichment_coordinator` publishes
    /// under (`ioc-<tenant uuid>-current`, enforced by that binary at start).
    pub fn from_shared_assignment(
        assignment: &crate::search::SharedLakeWorkerAssignment,
    ) -> Result<Self, IocLookupError> {
        if assignment.tenant_id.is_nil() {
            return Err(IocLookupError::Lake(
                "shared lake IOC assignment has a nil tenant".to_string(),
            ));
        }
        let tenant_id = assignment.tenant_id.to_string();
        let bearer_token = std::fs::read_to_string(&assignment.credential_file)
            .map_err(|error| {
                IocLookupError::Lake(format!(
                    "failed to read shared lake worker credential reference {}: {error}",
                    assignment.credential_file.display()
                ))
            })?
            .trim()
            .to_string();
        if bearer_token.len() < 32 {
            return Err(IocLookupError::Lake(
                "shared lake worker credential must contain at least 32 characters".to_string(),
            ));
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(assignment.timeout_secs.clamp(1, 300)))
            .build()
            .map_err(|error| IocLookupError::Lake(format!("build IOC client: {error}")))?;
        Ok(Self {
            http,
            base_url: assignment.internal_endpoint.trim_end_matches('/').to_string(),
            snapshot_id: default_ioc_snapshot_id(&tenant_id),
            tenant_id,
            bearer_token,
        })
    }

    /// The tenant this reader is pinned to.
    pub fn tenant_id(&self) -> &str {
        &self.tenant_id
    }

    pub async fn lookup(&self, value: &str) -> Result<Vec<IocLookupResult>, IocLookupError> {
        self.post_lookup(OWN_SNAPSHOT_LOOKUP_PATH, value)
            .await?
            .map(|lookup| lookup.results)
            .ok_or_else(|| IocLookupError::Lake("worker returned HTTP 404".to_string()))
    }

    /// NAN-3881: point lookup over every IOC source the tenant has enabled —
    /// its own published IOC lists/feeds plus the platform baseline feeds its
    /// policy grants (ThreatFox, Tor exit nodes...) — reporting every source
    /// searched. The worker reads the same snapshot and bundle/policy pair
    /// ingest matching uses. A worker that predates `/v1/ioc/indicator-sets`
    /// (404) falls back to the own-snapshot lookup, where a tenant with no
    /// published snapshot has zero sources (an answer, not a failure).
    pub async fn lookup_indicator_sets(&self, value: &str) -> Result<IocSetLookup, IocLookupError> {
        if let Some(lookup) = self.post_lookup(INDICATOR_SETS_LOOKUP_PATH, value).await? {
            return Ok(lookup);
        }
        match self.post_lookup(OWN_SNAPSHOT_LOOKUP_PATH, value).await {
            Ok(Some(lookup)) => Ok(lookup),
            Ok(None) => Err(IocLookupError::Lake("worker returned HTTP 404".to_string())),
            Err(IocLookupError::Lake(message)) if message.contains(IOC_POINTER_ABSENT) => {
                Ok(IocSetLookup { sources: Some(Vec::new()), ..IocSetLookup::default() })
            }
            Err(error) => Err(error),
        }
    }

    /// `Ok(None)` only for a 404 (a worker without the route).
    async fn post_lookup(&self, path: &str, value: &str) -> Result<Option<IocSetLookup>, IocLookupError> {
        let indicator_sets = path == INDICATOR_SETS_LOOKUP_PATH;
        let value = value.trim();
        if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(IocLookupError::Lake(
                "IOC lookup value is empty or exceeds its text contract".to_string(),
            ));
        }
        let request_id = uuid::Uuid::now_v7().to_string();
        let response = self
            .http
            .post(format!("{}{path}", self.base_url))
            .bearer_auth(&self.bearer_token)
            .json(&LakeIocRequest {
                request_id: &request_id,
                tenant_id: &self.tenant_id,
                snapshot_id: &self.snapshot_id,
                value,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| IocLookupError::Lake(format!("request failed: {error}")))?;
        let status = response.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let body = response
            .bytes()
            .await
            .map_err(|error| IocLookupError::Lake(format!("response read failed: {error}")))?;
        let envelope: LakeIocResponse = serde_json::from_slice(&body).map_err(|error| {
            IocLookupError::Lake(format!("worker returned invalid JSON ({status}): {error}"))
        })?;
        if !status.is_success() || !envelope.ok {
            return Err(IocLookupError::Lake(
                envelope
                    .error
                    .unwrap_or_else(|| format!("worker returned HTTP {status}")),
            ));
        }
        if envelope.request_id.as_deref() != Some(request_id.as_str())
            || envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str())
            || envelope.snapshot_id.as_deref() != Some(self.snapshot_id.as_str())
            // The indicator-set answer carries no snapshot version when the
            // tenant has not published one (its baseline feeds still count).
            || (!indicator_sets && envelope.snapshot_version.is_none())
            || envelope.snapshot_version.as_deref().is_some_and(valid_digest_not)
            || (indicator_sets
                && (envelope.sources.is_none()
                    || !matches!(envelope.platform_status.as_deref(), Some("ok" | "not_configured" | "unavailable"))))
            || envelope
                .value
                .as_deref()
                .is_none_or(|returned| !returned.eq_ignore_ascii_case(value))
            || envelope.results.len() > 10_000
            || envelope.sources.as_ref().is_some_and(|sources| sources.len() > 10_000)
        {
            return Err(IocLookupError::Lake(
                "worker response did not match the pinned IOC request".to_string(),
            ));
        }
        Ok(Some(IocSetLookup {
            results: envelope.results,
            sources: envelope.sources,
            platform_unavailable: envelope.platform_status.as_deref() == Some("unavailable"),
        }))
    }

    /// Enumerate a bounded current feed selection from the same immutable
    /// snapshot used for ingest decoration and point lookup. This replaces the
    /// legacy product reads of `custom_enrichment_results` in primary lake
    /// mode without exposing SQL or object-store coordinates.
    pub async fn source_records(
        &self,
        feeds: &[String],
        feed_name_contains: &[String],
        tags: &[String],
        artifact_types: &[String],
        cursor: Option<(i64, &str)>,
        limit: usize,
        count_only: bool,
    ) -> Result<(Vec<LakeIocSourceRecord>, usize), IocLookupError> {
        if limit == 0 || limit > 100_000 {
            return Err(IocLookupError::Lake(
                "IOC source record limit must be between 1 and 100000".to_string(),
            ));
        }
        let request_id = uuid::Uuid::now_v7().to_string();
        let response = self
            .http
            .post(format!("{}/v1/ioc/source-records", self.base_url))
            .bearer_auth(&self.bearer_token)
            .json(&LakeIocSourceRequest {
                request_id: &request_id,
                tenant_id: &self.tenant_id,
                snapshot_id: &self.snapshot_id,
                feeds,
                feed_name_contains,
                tags,
                artifact_types,
                cursor_published_at_ms: cursor.map(|(timestamp, _)| timestamp),
                cursor_value: cursor.map(|(_, value)| value),
                limit,
                count_only,
            })
            .send_idempotent_with_recovery()
            .await
            .map_err(|error| IocLookupError::Lake(format!("request failed: {error}")))?;
        let status = response.status();
        let body = response
            .bytes()
            .await
            .map_err(|error| IocLookupError::Lake(format!("response read failed: {error}")))?;
        let envelope: LakeIocSourceResponse = serde_json::from_slice(&body).map_err(|error| {
            IocLookupError::Lake(format!("worker returned invalid JSON ({status}): {error}"))
        })?;
        if !status.is_success() || !envelope.ok {
            return Err(IocLookupError::Lake(
                envelope
                    .error
                    .unwrap_or_else(|| format!("worker returned HTTP {status}")),
            ));
        }
        if envelope.request_id.as_deref() != Some(request_id.as_str())
            || envelope.tenant_id.as_deref() != Some(self.tenant_id.as_str())
            || envelope.snapshot_id.as_deref() != Some(self.snapshot_id.as_str())
            || envelope
                .snapshot_version
                .as_deref()
                .is_none_or(valid_digest_not)
            || envelope.count > 5_000_000
            || envelope.records.len() > limit
            || envelope.records.iter().any(|record| {
                record.value.is_empty()
                    || record.value.len() > 4_096
                    || record.key_type.is_empty()
                    || record.source_id.is_empty()
                    || record.enrichment_name.is_empty()
                    || !(0..=100).contains(&record.confidence)
                    || record.published_at_ms < 0
            })
        {
            return Err(IocLookupError::Lake(
                "worker response did not match the pinned IOC source request".to_string(),
            ));
        }
        Ok((envelope.records, envelope.count))
    }
}

fn valid_digest_not(version: &str) -> bool {
    version.len() != 64
        || !version
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// The worker's error text when the tenant has no published IOC snapshot
/// (`lean_ioc_query::lookup`).
const IOC_POINTER_ABSENT: &str = "tenant IOC pointer is absent";
/// Own-snapshot point lookup (search, retro, prevalence discovery).
const OWN_SNAPSHOT_LOOKUP_PATH: &str = "/v1/ioc/lookup";
/// Every enabled source: own snapshot plus granted platform feeds (NAN-3881).
const INDICATOR_SETS_LOOKUP_PATH: &str = "/v1/ioc/indicator-sets";

/// One point lookup over the tenant's indicator sets (NAN-3881).
#[derive(Debug, Clone, Default)]
pub struct IocSetLookup {
    /// One verdict per matching (source, type, threat, malware, confidence).
    pub results: Vec<IocLookupResult>,
    /// Display names of every indicator source searched (the tenant's own
    /// lists/feeds and its enabled platform baseline feeds); `None` when the
    /// worker does not report them.
    pub sources: Option<Vec<String>>,
    /// The tenant has platform feed mounts but its policy or bundle could
    /// not be read for this lookup: the baseline feeds were not searched.
    pub platform_unavailable: bool,
}

#[derive(Serialize)]
struct LakeIocRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    snapshot_id: &'a str,
    value: &'a str,
}

#[derive(Serialize)]
struct LakeIocSourceRequest<'a> {
    request_id: &'a str,
    tenant_id: &'a str,
    snapshot_id: &'a str,
    feeds: &'a [String],
    feed_name_contains: &'a [String],
    tags: &'a [String],
    artifact_types: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor_published_at_ms: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cursor_value: Option<&'a str>,
    limit: usize,
    count_only: bool,
}

#[derive(Debug, Clone, SerdeDeserialize, Serialize)]
pub struct LakeIocSourceRecord {
    pub value: String,
    pub key_type: String,
    pub source_id: String,
    pub enrichment_name: String,
    pub confidence: i32,
    pub tags: Vec<String>,
    pub published_at_ms: i64,
}

#[derive(SerdeDeserialize)]
struct LakeIocResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    snapshot_version: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    results: Vec<IocLookupResult>,
    #[serde(default)]
    sources: Option<Vec<String>>,
    #[serde(default)]
    platform_status: Option<String>,
}

#[derive(SerdeDeserialize)]
struct LakeIocSourceResponse {
    #[serde(default)]
    ok: bool,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    request_id: Option<String>,
    #[serde(default)]
    tenant_id: Option<String>,
    #[serde(default)]
    snapshot_id: Option<String>,
    #[serde(default)]
    snapshot_version: Option<String>,
    #[serde(default)]
    count: usize,
    #[serde(default)]
    records: Vec<LakeIocSourceRecord>,
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn required_env(name: &str) -> Result<String, IocLookupError> {
    optional_env(name)
        .ok_or_else(|| IocLookupError::Lake(format!("{name} is required for lake IOC lookup")))
}

fn validate_identity(name: &str, value: &str) -> Result<(), IocLookupError> {
    if value.len() > 256
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:-".contains(&byte))
    {
        return Err(IocLookupError::Lake(format!("{name} is invalid")));
    }
    Ok(())
}

fn default_ioc_snapshot_id(tenant_id: &str) -> String {
    format!("ioc-{tenant_id}-current")
}

#[cfg(test)]
mod lake_client_tests {
    use super::default_ioc_snapshot_id;

    #[test]
    fn cell_route_pins_ioc_client_to_router_tenant() {
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("router-token");
        std::fs::write(&token, "0123456789abcdef0123456789abcdef\n").unwrap();
        let tenant = uuid::Uuid::from_u128(7);
        let mut route = crate::search::lake_cell::LakeCellRoute::for_test(tenant, "http://127.0.0.1:8790", token);
        let client = super::LakeIocClient::from_lake_cell_route(&route).unwrap();
        assert_eq!(client.tenant_id(), tenant.to_string());
        assert!(client.base_url.ends_with(&format!("/{tenant}/query")));
        route.query_base_url = format!("http://127.0.0.1:8790/v1/tenants/{}/query", uuid::Uuid::from_u128(8));
        assert!(super::LakeIocClient::from_lake_cell_route(&route).is_err());
    }

    #[test]
    fn shared_assignment_pins_the_tenant_uuid_and_its_current_snapshot() {
        let dir = tempfile::tempdir().unwrap();
        let credential = dir.path().join("worker-token");
        std::fs::write(&credential, "0123456789abcdef0123456789abcdef\n").unwrap();
        let tenant = uuid::Uuid::from_u128(7);
        let assignment = crate::search::SharedLakeWorkerAssignment {
            tenant_id: tenant,
            internal_endpoint: "http://lake-worker.tenant.svc:8090/".into(),
            credential_file: credential.clone(),
            expected_worker_identity: "nano-query-x".into(),
            expected_worker_revision: 1,
            timeout_secs: 30,
            prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots {
                one_hour: "p1h".into(),
                twenty_four_hours: "p24h".into(),
                seven_days: "p7d".into(),
                thirty_days: "p30d".into(),
            },
            prevalence_rarity_threshold: 3,
            prevalence_timeout_secs: 30,
            enrichment_coordinator: None,
            otel_ingest: None,
            erasure_executor: None,
        };
        let client = super::LakeIocClient::from_shared_assignment(&assignment).unwrap();
        assert_eq!(client.tenant_id(), tenant.to_string());
        assert_eq!(client.snapshot_id, default_ioc_snapshot_id(&tenant.to_string()));
        assert_eq!(client.base_url, "http://lake-worker.tenant.svc:8090");
        std::fs::write(&credential, "short").unwrap();
        assert!(super::LakeIocClient::from_shared_assignment(&assignment).is_err());
        let mut nil = assignment;
        nil.tenant_id = uuid::Uuid::nil();
        assert!(super::LakeIocClient::from_shared_assignment(&nil).is_err());
    }

    fn assignment_client(tenant: uuid::Uuid, endpoint: &str, dir: &std::path::Path) -> super::LakeIocClient {
        let credential = dir.join("worker-token");
        std::fs::write(&credential, "0123456789abcdef0123456789abcdef\n").unwrap();
        let assignment = crate::search::SharedLakeWorkerAssignment {
            tenant_id: tenant,
            internal_endpoint: endpoint.into(),
            credential_file: credential,
            expected_worker_identity: "nano-query-x".into(),
            expected_worker_revision: 1,
            timeout_secs: 5,
            prevalence_snapshots: crate::prevalence::LakePrevalenceSnapshots {
                one_hour: "p1h".into(),
                twenty_four_hours: "p24h".into(),
                seven_days: "p7d".into(),
                thirty_days: "p30d".into(),
            },
            prevalence_rarity_threshold: 3,
            prevalence_timeout_secs: 5,
            enrichment_coordinator: None,
            otel_ingest: None,
            erasure_executor: None,
        };
        super::LakeIocClient::from_shared_assignment(&assignment).unwrap()
    }

    /// The worker echoes the pinned identity; the body's own request id is
    /// copied back so the envelope check passes.
    struct Echo {
        tenant: String,
        sources: serde_json::Value,
        results: serde_json::Value,
    }

    impl wiremock::Respond for Echo {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            let mut out = serde_json::json!({
                "ok": true, "request_id": body["request_id"], "tenant_id": self.tenant,
                "snapshot_id": format!("ioc-{}-current", self.tenant), "snapshot_version": "a".repeat(64),
                "value": body["value"], "results": self.results,
            });
            if !self.sources.is_null() {
                out["sources"] = self.sources.clone();
            }
            wiremock::ResponseTemplate::new(200).set_body_json(out)
        }
    }

    /// NAN-3881: the flyout's indicator-set search reports the tenant's own
    /// sources beside the matches, and tolerates a worker without the field.
    #[tokio::test]
    async fn indicator_set_lookup_reports_sources_and_matches() {
        use wiremock::{matchers, Mock, MockServer};
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0xa);
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/lookup"))
            .and(matchers::body_partial_json(serde_json::json!({ "value": "198.51.100.7" })))
            .respond_with(Echo {
                tenant: tenant.to_string(),
                sources: serde_json::json!(["Custom IOC list", "ThreatFox", "Tor exit nodes"]),
                results: serde_json::json!([{ "found": true, "source_id": "ThreatFox", "ioc_type": "ip",
                    "confidence_level": 75, "tags": ["botnet_cc"] }]),
            })
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/lookup"))
            .and(matchers::body_partial_json(serde_json::json!({ "value": "old-worker.example" })))
            .respond_with(Echo { tenant: tenant.to_string(), sources: serde_json::Value::Null, results: serde_json::json!([]) })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let client = assignment_client(tenant, &server.uri(), dir.path());
        let hit = client.lookup_indicator_sets("198.51.100.7").await.unwrap();
        assert_eq!(hit.sources.as_deref().map(<[String]>::len), Some(3));
        assert_eq!(hit.results.len(), 1);
        assert_eq!(hit.results[0].source_id.as_deref(), Some("ThreatFox"));
        let old = client.lookup_indicator_sets("old-worker.example").await.unwrap();
        assert!(old.results.is_empty() && old.sources.is_none());
    }

    /// NAN-3881 zero cross-tenant sharing: a worker answering with another
    /// tenant's identity (tenant B's snapshot) is refused, never shown to
    /// tenant A as matches or sources.
    #[tokio::test]
    async fn indicator_set_lookup_refuses_another_tenants_answer() {
        use wiremock::{matchers, Mock, MockServer};
        let server = MockServer::start().await;
        let tenant_a = uuid::Uuid::from_u128(0xa);
        let tenant_b = uuid::Uuid::from_u128(0xb);
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/lookup"))
            .respond_with(Echo {
                tenant: tenant_b.to_string(),
                sources: serde_json::json!(["B private feed"]),
                results: serde_json::json!([{ "found": true, "source_id": "B private feed", "ioc_type": "ip", "tags": [] }]),
            })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let client = assignment_client(tenant_a, &server.uri(), dir.path());
        let error = client.lookup_indicator_sets("198.51.100.7").await.unwrap_err();
        assert!(error.to_string().contains("did not match the pinned IOC request"), "{error}");
    }

    /// The `/v1/ioc/indicator-sets` answer: tenant + pinned identity echoed,
    /// no `snapshot_version` when the tenant has no own snapshot.
    struct SetsEcho {
        tenant: String,
        sources: serde_json::Value,
        results: serde_json::Value,
        platform_status: &'static str,
    }

    impl wiremock::Respond for SetsEcho {
        fn respond(&self, request: &wiremock::Request) -> wiremock::ResponseTemplate {
            let body: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
            wiremock::ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "request_id": body["request_id"], "tenant_id": self.tenant,
                "snapshot_id": format!("ioc-{}-current", self.tenant), "snapshot_version": null,
                "value": body["value"], "results": self.results, "sources": self.sources,
                "platform_status": self.platform_status, "platform_feeds": ["threatfox", "tor_exit_nodes"],
            }))
        }
    }

    /// The flyout searches the tenant's enabled
    /// platform baseline feeds too. A tenant with ThreatFox + Tor granted and
    /// no own snapshot gets both as searched sources and the ThreatFox match;
    /// `/v1/ioc/lookup` is never consulted when the new route answers.
    #[tokio::test]
    async fn indicator_set_lookup_includes_enabled_baseline_feeds() {
        use wiremock::{matchers, Mock, MockServer};
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0xa);
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/indicator-sets"))
            .respond_with(SetsEcho {
                tenant: tenant.to_string(),
                sources: serde_json::json!(["ThreatFox", "Tor exit nodes", "easy_intel"]),
                results: serde_json::json!([{ "found": true, "source_id": "ThreatFox", "ioc_type": "ip",
                    "threat_type": "botnet_cc", "confidence_level": 75, "tags": [] }]),
                platform_status: "ok",
            })
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/lookup"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .expect(0)
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let client = assignment_client(tenant, &server.uri(), dir.path());
        let hit = client.lookup_indicator_sets("198.51.100.7").await.unwrap();
        assert_eq!(
            hit.sources.as_deref(),
            Some(&["ThreatFox".to_string(), "Tor exit nodes".to_string(), "easy_intel".to_string()][..])
        );
        assert_eq!(hit.results.len(), 1);
        assert!(!hit.platform_unavailable);
    }

    /// An unreadable policy is reported, not hidden as "no baseline feeds".
    #[tokio::test]
    async fn indicator_set_lookup_reports_unavailable_baseline_feeds() {
        use wiremock::{matchers, Mock, MockServer};
        let server = MockServer::start().await;
        let tenant = uuid::Uuid::from_u128(0xa);
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/indicator-sets"))
            .respond_with(SetsEcho { tenant: tenant.to_string(), sources: serde_json::json!(["easy_intel"]),
                results: serde_json::json!([]), platform_status: "unavailable" })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let client = assignment_client(tenant, &server.uri(), dir.path());
        let answer = client.lookup_indicator_sets("198.51.100.7").await.unwrap();
        assert!(answer.platform_unavailable);
        assert_eq!(answer.sources.as_deref().map(<[String]>::len), Some(1));
    }

    /// NAN-3881 zero cross-tenant sharing on the new route: tenant B's
    /// answer (B's feeds and list) is refused for tenant A's reader.
    #[tokio::test]
    async fn indicator_sets_route_refuses_another_tenants_answer() {
        use wiremock::{matchers, Mock, MockServer};
        let server = MockServer::start().await;
        let tenant_a = uuid::Uuid::from_u128(0xa);
        let tenant_b = uuid::Uuid::from_u128(0xb);
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/indicator-sets"))
            .respond_with(SetsEcho { tenant: tenant_b.to_string(),
                sources: serde_json::json!(["B private feed", "ThreatFox"]),
                results: serde_json::json!([{ "found": true, "source_id": "B private feed", "ioc_type": "ip", "tags": [] }]),
                platform_status: "ok" })
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let client = assignment_client(tenant_a, &server.uri(), dir.path());
        let error = client.lookup_indicator_sets("198.51.100.7").await.unwrap_err();
        assert!(error.to_string().contains("did not match the pinned IOC request"), "{error}");
    }

    /// A tenant with no published IOC snapshot has zero indicator sources.
    #[tokio::test]
    async fn indicator_set_lookup_without_a_snapshot_is_zero_sources() {
        use wiremock::{matchers, Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(matchers::method("POST"))
            .and(matchers::path("/v1/ioc/lookup"))
            .respond_with(ResponseTemplate::new(500).set_body_json(serde_json::json!({
                "ok": false, "error": "tenant IOC pointer is absent", "reason": "internal" })))
            .mount(&server)
            .await;
        let dir = tempfile::tempdir().unwrap();
        let client = assignment_client(uuid::Uuid::from_u128(0xa), &server.uri(), dir.path());
        let none = client.lookup_indicator_sets("198.51.100.7").await.unwrap();
        assert!(none.results.is_empty());
        assert_eq!(none.sources, Some(Vec::new()));
        // The plain lookup keeps its error semantics.
        assert!(client.lookup("198.51.100.7").await.is_err());
    }

    #[test]
    fn derives_the_coordinator_snapshot_pointer_from_the_tenant() {
        assert_eq!(default_ioc_snapshot_id("tenant-a"), "ioc-tenant-a-current");
    }
}

/// Look an artifact up across every Deno IOC enrichment whose rows are
/// currently in `nanosiem.custom_enrichment_results` with `is_ioc=1`
/// and not yet expired. Returns one row per `(enrichment, key_type,
/// threat_type, malware, confidence)` combination, ordered by
/// confidence descending so the prevalence/discovery panel shows the
/// strongest verdicts first.
///
/// Post-NAN-1112 replacement for the PG-backed
/// `IocRepository::lookup_ioc_all_sources` — same return shape and
/// ordering semantics so the caller doesn't change. See the NAN-1112
/// ticket for the field-mapping analysis.
#[instrument(skip(ch))]
pub async fn lookup_ioc_all_sources(
    ch: &clickhouse::Client,
    value: &str,
) -> Result<Vec<IocLookupResult>, IocLookupError> {
    if value.is_empty() {
        return Ok(Vec::new());
    }

    // Mirrors the `is_ioc = 1 AND expires_at > now()` filter the
    // `custom_ioc_enrichment_dict` definition uses (init.sql:265-298).
    // Reading the underlying table (not the dict) so we can group per
    // enrichment_name and recover first_seen/last_seen via min/max of
    // fetched_at, which the dict aggregates away.
    //
    // No `enabled` filter on the source. The legacy PG path joined
    // `enrichment_sources` and excluded disabled sources, but the
    // marketplace path doesn't carry that signal into
    // `custom_enrichment_results` — once data is written it stays
    // until TTL expiry (30 days) regardless of whether the
    // corresponding enrichment is currently enabled. That matches the
    // panel's "what do we know about this artifact" intent: a
    // recently-disabled feed's historical verdicts should still be
    // visible. If a future product decision wants the disable to
    // suppress immediately, join against `marketplace_catalog` /
    // `custom_enrichments` on `enrichment_id` and filter on
    // `enabled = true`.
    // Reads via the `_distributed` wrapper on clusters (custom_enrichment_results
    // is in DISTRIBUTED_TABLES — a per-shard table with an additive wrapper); on
    // single-node `.read()` returns the local name, so the emitted table
    // reference is byte-identical. Routing through the wrapper is required so the
    // read covers ALL shards, not the one this connection landed on.
    //
    // No `argMax(…, version)` collapse here — unlike a single-row lookup, this
    // query DELIBERATELY reads every version of a row to recover first_seen /
    // last_seen from `min/max(fetched_at)` (see the note above). Cross-shard
    // duplicates of the same content merge into the same GROUP BY bucket (min/max
    // are idempotent, tags are arrayDistinct'd), so completeness — not
    // version-collapse — is the correct multi-shard fix; this matches the
    // existing single-shard pre-merge semantics.
    let table = TableNames::new(!on_cluster_clause().is_empty()).read("custom_enrichment_results");
    let rows: Vec<CustomEnrichmentIocRow> = ch
        .query(&format!(
            "SELECT
                 enrichment_name,
                 key_type,
                 threat_type,
                 malware,
                 confidence,
                 toUnixTimestamp(min(fetched_at)) AS first_seen,
                 toUnixTimestamp(max(fetched_at)) AS last_seen,
                 arrayDistinct(arrayFlatten(groupArray(tags))) AS tags
             FROM {table}
             WHERE key_value = ?
               AND is_ioc = 1
               AND expires_at > now()
             GROUP BY enrichment_name, key_type, threat_type, malware, confidence
             ORDER BY confidence DESC, enrichment_name",
        ))
        .bind(value)
        .fetch_all()
        .await?;

    let empty_to_none = |s: String| if s.is_empty() { None } else { Some(s) };
    let unix_to_rfc3339 = |ts: i64| -> Option<String> {
        if ts <= 0 {
            return None;
        }
        chrono::DateTime::<chrono::Utc>::from_timestamp(ts, 0).map(|d| d.to_rfc3339())
    };

    Ok(rows
        .into_iter()
        .map(|row| IocLookupResult {
            found: true,
            source_id: empty_to_none(row.enrichment_name),
            ioc_type: empty_to_none(row.key_type),
            threat_type: empty_to_none(row.threat_type),
            malware: empty_to_none(row.malware),
            confidence_level: Some(row.confidence as i32),
            first_seen_at: unix_to_rfc3339(row.first_seen),
            last_seen_at: unix_to_rfc3339(row.last_seen),
            tags: row.tags,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn empty_value_returns_no_rows() {
        // Smoke: empty value short-circuits before touching CH so the
        // call is safe to invoke without a configured client. The
        // CH-backed path itself is exercised by integration tests
        // against a live cluster (out of scope for unit tests).
        let ch = clickhouse::Client::default();
        let result = lookup_ioc_all_sources(&ch, "").await.unwrap();
        assert!(result.is_empty());
    }
}
