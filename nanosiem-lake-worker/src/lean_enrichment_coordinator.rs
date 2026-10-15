// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-pinned source publisher for lean ingest snapshots.

use std::{path::PathBuf, sync::Arc};

use arc_swap::ArcSwap;

use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{delete as delete_route, get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::{
    enrichment::IocSnapshotInput,
    ip_context::{IpContextInput, LeanSnapshotCapExceeded},
    lean_ip_context::{
        InvalidIpContextMutation, IpContextRevisionConflict, LeanIpContextPublisher,
    },
    lean_collector_errors::CollectorErrorLog,
    lean_enrichment_snapshot::{LeanEnrichmentSnapshots, SourceUpdate},
    parts::part_log::ObjectStore,
};

#[path = "lean_enrichment_coordinator_identity.rs"]
mod identity;

const MAX_REQUEST_BYTES: usize = crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_BYTES;

#[derive(Debug)]
struct CoordinatorError(StatusCode, &'static str);

impl IntoResponse for CoordinatorError {
    fn into_response(self) -> Response {
        (self.0, Json(serde_json::json!({ "error": self.1 }))).into_response()
    }
}

/// Minimum bearer length the coordinator binary accepts for either token.
pub const MIN_TOKEN_CHARS: usize = 32;

/// The bearer digests one tenant coordinator accepts (NAN-3503).
///
/// - `full`: every route (the API's tenant coordinator token).
/// - `identity_writer`: optional, accepted ONLY on the identity-directory
///   write routes a connector runner needs (deltas, staged run rows, run
///   commit, run abort, and feed delete of a connector sub-feed
///   `<feed uuid>:users|groups`). Every other route refuses it with 403.
///
/// Scope limit (known, accepted for now): the identity-writer token is
/// bound to the tenant, not to a feed. `commit` REPLACES the whole named
/// feed with the staged rows, and `deltas` can add, update or tombstone rows
/// of any feed, so a holder of this token can overwrite or empty any identity
/// feed of its own tenant (never another tenant's, never IOC / IP-context /
/// internal-domains data; it cannot compact, and it can delete only feeds
/// named `<uuid>:users` or `<uuid>:groups`). A later
/// change can bind the token to the runner's feed ids (e.g. a per-token feed
/// allowlist checked against `{feed}` and every row's `feed_id`).
///
/// The two digests always differ.
#[derive(Clone, PartialEq, Eq)]
pub struct CoordinatorAuth {
    full: [u8; 32],
    identity_writer: Option<[u8; 32]>,
}

impl std::fmt::Debug for CoordinatorAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoordinatorAuth")
            .field("identity_writer", &self.identity_writer.is_some())
            .finish_non_exhaustive()
    }
}

impl CoordinatorAuth {
    /// Full token only: today's behavior.
    pub fn full_only(full_digest: [u8; 32]) -> Self {
        Self {
            full: full_digest,
            identity_writer: None,
        }
    }

    /// Validate raw tokens (already trimmed): each at least
    /// [`MIN_TOKEN_CHARS`], and the identity-writer token must differ from the
    /// full token. Error messages never contain token material.
    pub fn from_tokens(full: &str, identity_writer: Option<&str>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            full.len() >= MIN_TOKEN_CHARS,
            "coordinator token is too short"
        );
        let identity_writer = match identity_writer {
            None => None,
            Some(token) => {
                anyhow::ensure!(
                    token.len() >= MIN_TOKEN_CHARS,
                    "coordinator identity-writer token is too short"
                );
                Some(auth_digest(token))
            }
        };
        Self::from_digests(auth_digest(full), identity_writer)
    }

    /// Build from digests; refuses an identity-writer digest equal to the full one.
    pub fn from_digests(
        full_digest: [u8; 32],
        identity_writer_digest: Option<[u8; 32]>,
    ) -> anyhow::Result<Self> {
        if let Some(identity) = identity_writer_digest {
            anyhow::ensure!(
                !bool::from(identity.ct_eq(&full_digest)),
                "coordinator identity-writer token must differ from the full token"
            );
        }
        Ok(Self {
            full: full_digest,
            identity_writer: identity_writer_digest,
        })
    }

    pub fn has_identity_writer(&self) -> bool {
        self.identity_writer.is_some()
    }
}

/// What a route requires of the bearer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// Only the full token.
    Full,
    /// The full token or the identity-writer token.
    IdentityWrite,
}

#[derive(Clone)]
pub struct LeanCoordinatorState {
    pub tenant_id: Uuid,
    /// Accepted bearer digests; swapped in place when the token files rotate.
    pub auth: Arc<ArcSwap<CoordinatorAuth>>,
    pub objects: Arc<dyn ObjectStore>,
    pub scratch: PathBuf,
    /// One writer per tenant process. Deployment must assign only one process.
    pub writer: Arc<Mutex<()>>,
    /// Custom IP-context publisher; its working copy lives under `scratch`.
    pub ip_context: Arc<LeanIpContextPublisher>,
    /// NAN-3765: bounded Vector collector diagnostics under `scratch`.
    pub collector_errors: Arc<CollectorErrorLog>,
}

impl LeanCoordinatorState {
    pub fn new(
        tenant_id: Uuid,
        auth_digest: [u8; 32],
        objects: Arc<dyn ObjectStore>,
        scratch: PathBuf,
    ) -> anyhow::Result<Self> {
        Self::with_auth(
            tenant_id,
            CoordinatorAuth::full_only(auth_digest),
            objects,
            scratch,
        )
    }

    /// Like [`Self::new`], with an explicit token set (NAN-3503).
    pub fn with_auth(
        tenant_id: Uuid,
        auth: CoordinatorAuth,
        objects: Arc<dyn ObjectStore>,
        scratch: PathBuf,
    ) -> anyhow::Result<Self> {
        let ip_context = Arc::new(LeanIpContextPublisher::new(tenant_id, &scratch)?);
        let collector_errors = Arc::new(CollectorErrorLog::open(&scratch)?);
        Ok(Self {
            tenant_id,
            auth: Arc::new(ArcSwap::from_pointee(auth)),
            objects,
            scratch,
            writer: Arc::new(Mutex::new(())),
            ip_context,
            collector_errors,
        })
    }

    /// Swap in rotated tokens. Whether an identity-writer token is configured
    /// is fixed at boot: a rotation may change it, never add or drop it.
    /// Returns `Ok(true)` when the accepted set changed.
    pub fn rotate_auth(&self, next: CoordinatorAuth) -> anyhow::Result<bool> {
        let current = self.auth.load();
        anyhow::ensure!(
            current.has_identity_writer() == next.has_identity_writer(),
            "rotated coordinator tokens add or drop the identity-writer token"
        );
        if **current == next {
            return Ok(false);
        }
        self.auth.store(Arc::new(next));
        Ok(true)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReplaceRequest {
    tenant_id: Uuid,
    records: Vec<IocSnapshotInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeleteRequest {
    tenant_id: Uuid,
}

#[derive(Debug, Serialize)]
struct Publication {
    status: &'static str,
    tenant_id: Uuid,
    snapshot_id: String,
    snapshot_sha256: String,
    rows: usize,
    bytes: usize,
    generation_id: String,
    source_operation: &'static str,
}

pub fn router(state: LeanCoordinatorState) -> Router {
    Router::new()
        .route(
            "/v1/enrichment/sources/{source_id}",
            put(replace).delete(delete),
        )
        // Same wire contract as the gen1 coordinator (Vector NDJSON sink and
        // `LakeIpContextClient`), published as tenant R2 snapshots instead.
        .route("/v1/ip-context/batch", post(ip_context_batch))
        .route(
            "/v1/ip-context/sources/{source_id}",
            delete_route(ip_context_delete_source),
        )
        .route("/v1/ip-context/stats", get(ip_context_stats))
        // NAN-3765: Vector's `lake_collector_errors` sink (92-metrics.toml)
        // and the API's log-source health read (`LakeCollectorDiagnosticsClient`).
        .route("/v1/collector-errors/batch", post(collector_errors_ingest))
        .route("/v1/collector-errors", get(collector_errors_list))
        // NAN-3226: the tenant's internal DNS suffixes for lean ingest.
        .route("/v1/internal-domains", put(internal_domains_publish))
        // NAN-3500: the tenant identity directory (R2 snapshot + deltas).
        .route("/v1/identity/directory/deltas", post(identity::deltas))
        // NAN-3767: the Vector `lake_identity_directory` sink (NDJSON
        // stage/delta lines; the JSON routes stay for direct callers).
        .route("/v1/identity/directory/ingest", post(identity::ingest))
        .route("/v1/identity/directory/compact", post(identity::compact))
        .route(
            "/v1/identity/directory/feeds/{feed_id}",
            delete_route(identity::delete_feed),
        )
        .route(
            "/v1/identity/directory/feeds/{feed_id}/runs/{run_id}",
            delete_route(identity::abort_run),
        )
        .route(
            "/v1/identity/directory/feeds/{feed_id}/runs/{run_id}/rows",
            post(identity::stage_rows),
        )
        .route(
            "/v1/identity/directory/feeds/{feed_id}/runs/{run_id}/commit",
            post(identity::commit_run),
        )
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(state)
}

/// Full-token routes.
fn authenticate(state: &LeanCoordinatorState, headers: &HeaderMap) -> Result<(), CoordinatorError> {
    authorize(state, headers, Scope::Full)
}

/// Unknown or missing bearer: 401. A valid identity-writer bearer on a
/// full-token route: 403. Both compares run in constant time and always run.
fn authorize(
    state: &LeanCoordinatorState,
    headers: &HeaderMap,
    scope: Scope,
) -> Result<(), CoordinatorError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or(CoordinatorError(StatusCode::UNAUTHORIZED, "unauthorized"))?;
    let digest = auth_digest(token);
    let auth = state.auth.load();
    let full = digest.ct_eq(&auth.full);
    // Compare against a value no SHA-256 output equals in practice when no
    // identity-writer token is configured, so the work is the same.
    let (configured, identity_digest) = match auth.identity_writer {
        Some(identity) => (true, identity),
        None => (false, [0u8; 32]),
    };
    let identity = digest.ct_eq(&identity_digest) & subtle::Choice::from(u8::from(configured));
    if bool::from(full) {
        Ok(())
    } else if bool::from(identity) {
        match scope {
            Scope::IdentityWrite => Ok(()),
            Scope::Full => Err(CoordinatorError(StatusCode::FORBIDDEN, "forbidden")),
        }
    } else {
        Err(CoordinatorError(StatusCode::UNAUTHORIZED, "unauthorized"))
    }
}

async fn replace(
    State(state): State<LeanCoordinatorState>,
    Path(source): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Publication>, CoordinatorError> {
    authenticate(&state, &headers)?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(CoordinatorError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tenant IOC upload exceeds 64 MiB",
        ));
    }
    let request: ReplaceRequest = serde_json::from_slice(&body)
        .map_err(|_| CoordinatorError(StatusCode::BAD_REQUEST, "invalid source replacement"))?;
    // NAN-3882: the coordinator runs in 256 MiB; never hold the raw body
    // alongside the parsed rows and the tenant snapshot being rewritten.
    drop(body);
    if request.records.len() > crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_ROWS {
        return Err(CoordinatorError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tenant IOC upload exceeds the snapshot row cap",
        ));
    }
    if request.tenant_id != state.tenant_id
        || request.records.is_empty()
        || request
            .records
            .iter()
            .any(|row| row.source_id != source.to_string())
    {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "tenant or source identity differs from assignment",
        ));
    }
    mutate(
        state,
        SourceUpdate::Replace {
            source_id: source.to_string(),
            rows: request.records,
        },
        "replace_source",
    )
    .await
}

async fn delete(
    State(state): State<LeanCoordinatorState>,
    Path(source): Path<Uuid>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Publication>, CoordinatorError> {
    authenticate(&state, &headers)?;
    let request: DeleteRequest = serde_json::from_slice(&body)
        .map_err(|_| CoordinatorError(StatusCode::BAD_REQUEST, "invalid source deletion"))?;
    if request.tenant_id != state.tenant_id {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "tenant identity differs from assignment",
        ));
    }
    mutate(
        state,
        SourceUpdate::Delete {
            source_id: source.to_string(),
        },
        "delete_source",
    )
    .await
}

async fn mutate(
    state: LeanCoordinatorState,
    update: SourceUpdate,
    operation: &'static str,
) -> Result<Json<Publication>, CoordinatorError> {
    let _guard = state.writer.lock().await;
    let snapshots = LeanEnrichmentSnapshots::new(state.tenant_id, &*state.objects, &state.scratch)
        .map_err(|_| {
            CoordinatorError(
                StatusCode::SERVICE_UNAVAILABLE,
                "tenant snapshot store unavailable",
            )
        })?;
    let expected = snapshots.current().await.map_err(|_| {
        CoordinatorError(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant snapshot pointer unavailable",
        )
    })?;
    // NAN-3882: the row count comes from the write; re-loading the whole
    // published snapshot just to count it doubled the peak memory.
    let (pointer, rows) = snapshots
        .update_source_counted(expected.as_ref(), update)
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "lean enrichment publication refused");
            if error.to_string().contains("snapshot cap") {
                CoordinatorError(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "tenant IOC upload exceeds its snapshot size or row cap",
                )
            } else {
                CoordinatorError(
                    StatusCode::BAD_REQUEST,
                    "tenant IOC source publication refused",
                )
            }
        })?;
    Ok(Json(Publication {
        status: "published",
        tenant_id: state.tenant_id,
        snapshot_id: pointer.revision.to_string(),
        snapshot_sha256: pointer.sha256,
        rows,
        bytes: pointer.bytes,
        generation_id: pointer.revision.to_string(),
        source_operation: operation,
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InternalDomainsRequest {
    tenant_id: Uuid,
    suffixes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct InternalDomainsPublication {
    status: &'static str,
    tenant_id: Uuid,
    suffixes: Vec<String>,
    sha256: String,
}

/// Publish the tenant's internal DNS suffixes (NAN-3226) as
/// `internal_domains/current.json` under the tenant enrichment prefix. The
/// body is bound to the assignment tenant and validated like the API does.
async fn internal_domains_publish(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<InternalDomainsPublication>, CoordinatorError> {
    authenticate(&state, &headers)?;
    if body.len() > 128 * 1024 {
        return Err(CoordinatorError(StatusCode::PAYLOAD_TOO_LARGE, "internal domains list is too large"));
    }
    let request: InternalDomainsRequest = serde_json::from_slice(&body)
        .map_err(|_| CoordinatorError(StatusCode::BAD_REQUEST, "invalid internal domains request"))?;
    if request.tenant_id != state.tenant_id {
        return Err(CoordinatorError(StatusCode::BAD_REQUEST, "tenant identity differs from assignment"));
    }
    if crate::internal_domains_snapshot::InternalDomainsDocument::new(state.tenant_id, &request.suffixes).is_err() {
        return Err(CoordinatorError(StatusCode::BAD_REQUEST, "invalid internal domain suffix"));
    }
    let _guard = state.writer.lock().await;
    let document = crate::internal_domains_snapshot::publish(&*state.objects, state.tenant_id, &request.suffixes)
        .await
        .map_err(|error| {
            tracing::warn!(error = %format!("{error:#}"), "internal domains publication failed");
            CoordinatorError(StatusCode::SERVICE_UNAVAILABLE, "tenant enrichment store unavailable")
        })?;
    Ok(Json(InternalDomainsPublication {
        status: "published",
        tenant_id: document.tenant_id,
        suffixes: document.suffixes,
        sha256: document.sha256,
    }))
}

#[derive(Debug, Serialize)]
struct TenantResponse<T> {
    tenant_id: String,
    result: T,
}

#[derive(Deserialize)]
struct TenantQuery {
    tenant_id: Uuid,
}

fn tenant_header(state: &LeanCoordinatorState, headers: &HeaderMap) -> Result<(), CoordinatorError> {
    let tenant = headers
        .get("x-nano-tenant-id")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<Uuid>().ok())
        .ok_or(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "X-Nano-Tenant-ID is required",
        ))?;
    if tenant == state.tenant_id {
        Ok(())
    } else {
        Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "tenant identity differs from assignment",
        ))
    }
}

fn ip_context_error(error: anyhow::Error) -> CoordinatorError {
    if error.downcast_ref::<LeanSnapshotCapExceeded>().is_some() {
        tracing::info!(error = %format!("{error:#}"), "lean IP context upload over cap");
        CoordinatorError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tenant IP context exceeds its snapshot size or row cap",
        )
    } else if error.downcast_ref::<InvalidIpContextMutation>().is_some() {
        tracing::info!(error = %format!("{error:#}"), "lean IP context mutation refused");
        CoordinatorError(StatusCode::BAD_REQUEST, "tenant IP context mutation refused")
    } else if error.downcast_ref::<IpContextRevisionConflict>().is_some() {
        CoordinatorError(
            StatusCode::CONFLICT,
            "tenant IP context snapshot revision changed",
        )
    } else {
        tracing::warn!(error = %format!("{error:#}"), "lean IP context publication failed");
        CoordinatorError(
            StatusCode::SERVICE_UNAVAILABLE,
            "tenant IP context snapshot store unavailable",
        )
    }
}

async fn ip_context_batch(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TenantResponse<crate::lean_ip_context::LeanIpContextPublication>>, CoordinatorError>
{
    authenticate(&state, &headers)?;
    tenant_header(&state, &headers)?;
    if body.len() > MAX_REQUEST_BYTES {
        return Err(CoordinatorError(
            StatusCode::PAYLOAD_TOO_LARGE,
            "tenant IP context upload exceeds 64 MiB",
        ));
    }
    let mut records = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        if records.len() >= crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_ROWS {
            return Err(CoordinatorError(
                StatusCode::PAYLOAD_TOO_LARGE,
                "tenant IP context upload exceeds the snapshot row cap",
            ));
        }
        records.push(serde_json::from_slice::<IpContextInput>(line).map_err(|_| {
            CoordinatorError(StatusCode::BAD_REQUEST, "invalid IP context NDJSON row")
        })?);
    }
    if records.is_empty() {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "IP context batch is empty",
        ));
    }
    let _guard = state.writer.lock().await;
    let result = state
        .ip_context
        .upsert(&*state.objects, records)
        .await
        .map_err(ip_context_error)?;
    Ok(Json(TenantResponse {
        tenant_id: state.tenant_id.to_string(),
        result,
    }))
}

async fn ip_context_delete_source(
    State(state): State<LeanCoordinatorState>,
    Path(source): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TenantResponse<crate::lean_ip_context::LeanIpContextPublication>>, CoordinatorError>
{
    authenticate(&state, &headers)?;
    let request: DeleteRequest = serde_json::from_slice(&body)
        .map_err(|_| CoordinatorError(StatusCode::BAD_REQUEST, "invalid source deletion"))?;
    if request.tenant_id != state.tenant_id {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "tenant identity differs from assignment",
        ));
    }
    let _guard = state.writer.lock().await;
    let result = state
        .ip_context
        .delete_source(&*state.objects, &source)
        .await
        .map_err(ip_context_error)?;
    Ok(Json(TenantResponse {
        tenant_id: state.tenant_id.to_string(),
        result,
    }))
}

async fn ip_context_stats(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<TenantQuery>,
) -> Result<Json<TenantResponse<crate::ip_context::IpContextCounts>>, CoordinatorError> {
    authenticate(&state, &headers)?;
    if query.tenant_id != state.tenant_id {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "tenant identity differs from assignment",
        ));
    }
    let _guard = state.writer.lock().await;
    let result = state
        .ip_context
        .counts(&*state.objects)
        .await
        .map_err(ip_context_error)?;
    Ok(Json(TenantResponse {
        tenant_id: state.tenant_id.to_string(),
        result,
    }))
}

#[derive(Deserialize)]
struct CollectorErrorsQuery {
    tenant_id: Uuid,
    component_id: String,
    limit: Option<usize>,
}

#[derive(Debug, Serialize)]
struct CollectorErrorsResponse {
    errors: Vec<nanosiem_core::log_sources::CollectorError>,
    total_24h: i64,
}

/// NAN-3765: accept one Vector NDJSON batch of WARN/ERROR internal logs.
async fn collector_errors_ingest(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<TenantResponse<usize>>, CoordinatorError> {
    authenticate(&state, &headers)?;
    tenant_header(&state, &headers)?;
    let now = chrono::Utc::now();
    let records = crate::lean_collector_errors::parse_batch(&body, now)
        .map_err(|reason| CoordinatorError(StatusCode::BAD_REQUEST, reason))?;
    let result = state
        .collector_errors
        .append(records, now)
        .await
        .map_err(|error| {
            tracing::warn!(error = %format!("{error:#}"), "collector diagnostics write failed");
            CoordinatorError(
                StatusCode::SERVICE_UNAVAILABLE,
                "collector diagnostics store unavailable",
            )
        })?;
    Ok(Json(TenantResponse {
        tenant_id: state.tenant_id.to_string(),
        result,
    }))
}

/// NAN-3765: recent collector errors of one Vector component.
async fn collector_errors_list(
    State(state): State<LeanCoordinatorState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<CollectorErrorsQuery>,
) -> Result<Json<TenantResponse<CollectorErrorsResponse>>, CoordinatorError> {
    authenticate(&state, &headers)?;
    if query.tenant_id != state.tenant_id {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "tenant identity differs from assignment",
        ));
    }
    if query.component_id.is_empty()
        || query.component_id.len() > 512
        || query.component_id.chars().any(char::is_control)
    {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "collector component identity is invalid",
        ));
    }
    let limit = query.limit.unwrap_or(20);
    if !(1..=100).contains(&limit) {
        return Err(CoordinatorError(
            StatusCode::BAD_REQUEST,
            "collector error limit must be 1..=100",
        ));
    }
    let (errors, total_24h) = state
        .collector_errors
        .list(&query.component_id, limit, chrono::Utc::now())
        .await;
    Ok(Json(TenantResponse {
        tenant_id: state.tenant_id.to_string(),
        result: CollectorErrorsResponse { errors, total_24h },
    }))
}

pub fn auth_digest(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parts::part_log::LocalObjectStore;

    /// NAN-3226: the coordinator publishes only its own tenant's normalized
    /// list; lean ingest reads it back bound to that tenant.
    #[tokio::test]
    async fn internal_domains_publish_is_tenant_bound() {
        let directory = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let token = "internal-domains-test-bearer-token-0123456789";
        let objects: Arc<dyn ObjectStore> = Arc::new(LocalObjectStore::new(directory.path().join("r2")).unwrap());
        let state = LeanCoordinatorState::new(tenant, auth_digest(token), objects.clone(), directory.path().join("scratch")).unwrap();
        let headers = HeaderMap::from_iter([(axum::http::header::AUTHORIZATION, format!("Bearer {token}").parse().unwrap())]);
        let body = |tenant: Uuid, suffixes: &[&str]| {
            Bytes::from(serde_json::to_vec(&serde_json::json!({"tenant_id": tenant, "suffixes": suffixes})).unwrap())
        };
        let other = internal_domains_publish(State(state.clone()), headers.clone(), body(Uuid::new_v4(), &["prod"])).await.unwrap_err();
        assert_eq!(other.0, StatusCode::BAD_REQUEST);
        let bad = internal_domains_publish(State(state.clone()), headers.clone(), body(tenant, &["a..b"])).await.unwrap_err();
        assert_eq!(bad.0, StatusCode::BAD_REQUEST);
        let unauthenticated = internal_domains_publish(State(state.clone()), HeaderMap::new(), body(tenant, &["prod"])).await.unwrap_err();
        assert_eq!(unauthenticated.0, StatusCode::UNAUTHORIZED);
        assert!(crate::internal_domains_snapshot::read(&*objects, tenant).await.unwrap().is_none());

        let published = internal_domains_publish(State(state), headers, body(tenant, &["PROD.", "nano.cloud"])).await.unwrap().0;
        assert_eq!(published.suffixes, vec!["nano.cloud".to_string(), "prod".to_string()]);
        let read = crate::internal_domains_snapshot::read(&*objects, tenant).await.unwrap().unwrap();
        assert!(read.internal_domains().is_internal("db1.prod"));
        assert!(crate::internal_domains_snapshot::read(&*objects, Uuid::new_v4()).await.is_err(), "another tenant's process refuses it");
    }

    #[tokio::test]
    async fn upload_cap_rejects_before_publication() {
        let directory = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let token = "tenant-upload-cap-test-token";
        let objects: Arc<dyn ObjectStore> =
            Arc::new(LocalObjectStore::new(directory.path().join("r2")).unwrap());
        let state = LeanCoordinatorState::new(
            tenant,
            auth_digest(token),
            objects.clone(),
            directory.path().join("scratch"),
        )
        .unwrap();
        let headers = HeaderMap::from_iter([(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        )]);
        let oversized = Bytes::from(vec![b' '; MAX_REQUEST_BYTES + 1]);
        let error = replace(State(state), Path(Uuid::new_v4()), headers, oversized)
            .await
            .unwrap_err();
        assert_eq!(error.0, StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(error.1, "tenant IOC upload exceeds 64 MiB");
        let store =
            LeanEnrichmentSnapshots::new(tenant, &*objects, &directory.path().join("check"))
                .unwrap();
        assert!(store.current().await.unwrap().is_none());
    }

    #[tokio::test]
    async fn publishes_only_authenticated_tenant_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let other = Uuid::new_v4();
        let token = "this-is-a-private-tenant-test-bearer-token";
        let objects: Arc<dyn ObjectStore> =
            Arc::new(LocalObjectStore::new(directory.path().join("r2")).unwrap());
        let state = LeanCoordinatorState::new(
            tenant,
            auth_digest(token),
            objects.clone(),
            directory.path().join("scratch"),
        )
        .unwrap();
        let headers = HeaderMap::from_iter([(
            axum::http::header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        )]);
        let row = IocSnapshotInput {
            ioc_value: "8.8.8.8".into(),
            ioc_type: "ip".into(),
            source_id: Uuid::nil().to_string(),
            ..Default::default()
        };
        let body = |tenant_id| {
            Bytes::from(
                serde_json::to_vec(&serde_json::json!({
                    "tenant_id": tenant_id, "records": [row.clone()]
                }))
                .unwrap(),
            )
        };
        assert_eq!(
            replace(
                State(state.clone()),
                Path(Uuid::nil()),
                HeaderMap::new(),
                body(tenant)
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            replace(
                State(state.clone()),
                Path(Uuid::nil()),
                headers.clone(),
                body(other)
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::BAD_REQUEST
        );
        let published = replace(
            State(state.clone()),
            Path(Uuid::nil()),
            headers.clone(),
            body(tenant),
        )
        .await
        .unwrap();
        assert_eq!(published.0.tenant_id, tenant);
        let response = serde_json::to_value(&published.0).unwrap();
        assert_eq!(response["status"], "published");
        assert_eq!(response["source_operation"], "replace_source");
        assert_eq!(response["generation_id"], response["snapshot_id"]);
        let restarted =
            LeanEnrichmentSnapshots::new(tenant, &*objects, &directory.path().join("restarted"))
                .unwrap();
        let pointer = restarted.current().await.unwrap().unwrap();
        assert_eq!(pointer.revision.to_string(), published.0.snapshot_id);
        let restored = restarted.load(&pointer).await.unwrap().publication_rows();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].ioc_value, row.ioc_value);
        let wrong = LeanEnrichmentSnapshots::new(other, &*objects, &directory.path().join("wrong"))
            .unwrap();
        assert!(wrong.current().await.is_err());
    }

    /// NAN-3765: open core's Vector `lake_collector_errors` sink posted to a
    /// route the lean coordinator did not have (404), so every collector error
    /// was dropped. The batch route must exist, store tenant-bound rows, and the
    /// API's diagnostics read must get them back across a restart.
    #[tokio::test]
    async fn collector_errors_are_routed_stored_and_listed() {
        let directory = tempfile::tempdir().unwrap();
        let tenant = Uuid::new_v4();
        let token = "collector-errors-test-bearer-token-0123456789";
        let objects: Arc<dyn ObjectStore> =
            Arc::new(LocalObjectStore::new(directory.path().join("r2")).unwrap());
        let scratch = directory.path().join("scratch");
        let state =
            LeanCoordinatorState::new(tenant, auth_digest(token), objects.clone(), scratch.clone())
                .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            axum::serve(listener, router(state)).await.unwrap();
        });
        let client = reqwest::Client::new();
        let line = serde_json::json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "message": "Failed to fetch events.",
            "metadata": {"kind": "event", "level": "ERROR"},
            "vector": {"component_id": "okta_source", "component_kind": "source", "component_type": "http_client"},
            "host": "vector-0",
            "error_code": "failed_fetching_events",
            "error_type": "request_failed",
            "stage": "receiving"
        })
        .to_string();
        let post = |bearer: Option<&str>, tenant_header: String| {
            let mut request = client
                .post(format!("{base}/v1/collector-errors/batch"))
                .header("content-type", "application/x-ndjson")
                .header("x-nano-tenant-id", tenant_header)
                .body(format!("{line}\n"));
            if let Some(bearer) = bearer {
                request = request.bearer_auth(bearer);
            }
            request.send()
        };

        assert_eq!(post(None, tenant.to_string()).await.unwrap().status(), 401);
        let wrong_tenant = post(Some(token), Uuid::new_v4().to_string()).await;
        assert_eq!(wrong_tenant.unwrap().status(), 400);
        let accepted = post(Some(token), tenant.to_string()).await.unwrap();
        assert_eq!(accepted.status(), 200);
        let accepted: serde_json::Value = accepted.json().await.unwrap();
        assert_eq!(accepted["tenant_id"], tenant.to_string());
        assert_eq!(accepted["result"], 1);

        let list = |tenant_id: Uuid| {
            client
                .get(format!("{base}/v1/collector-errors"))
                .bearer_auth(token)
                .query(&[
                    ("tenant_id", tenant_id.to_string()),
                    ("component_id", "okta_source".to_string()),
                    ("limit", "20".to_string()),
                ])
                .send()
        };
        assert_eq!(list(Uuid::new_v4()).await.unwrap().status(), 400);
        let listed: serde_json::Value = list(tenant).await.unwrap().json().await.unwrap();
        assert_eq!(listed["tenant_id"], tenant.to_string());
        assert_eq!(listed["result"]["total_24h"], 1);
        // The shape `LakeCollectorDiagnosticsClient` deserializes.
        let errors: Vec<nanosiem_core::log_sources::CollectorError> =
            serde_json::from_value(listed["result"]["errors"].clone()).unwrap();
        assert_eq!(errors[0].error_code, "failed_fetching_events");
        assert_eq!(errors[0].component_type, "http_client");
        server.abort();

        let restarted =
            LeanCoordinatorState::new(tenant, auth_digest(token), objects, scratch).unwrap();
        let (errors, total) = restarted
            .collector_errors
            .list("okta_source", 20, chrono::Utc::now())
            .await;
        assert_eq!((errors.len(), total), (1, 1), "rows survive a restart");
    }
}
