// SPDX-License-Identifier: AGPL-3.0-or-later

//! The `query[T]` process surface: a cell child (NAN-2871 contract) that
//! serves routed HTTP/1.1 requests handed to it over its control socket.
//! It never listens (the cell's seccomp filter denies `listen`).
//!
//! Routes (paths as the cell router forwards them, the router token already
//! stripped):
//!
//! | Method | Path | Body |
//! |---|---|---|
//! | POST | `/v1/query` | `{"route":"broad_npl"|"fetch_log"|"field_names", …}` (reader wire shapes) |
//! | POST | `/v1/aggregate/count` | the reader's count request |
//! | POST | `/v1/prevalence/lookup` | [`partials::PrevalenceLookupRequest`] |
//! | POST | `/v1/prevalence/explorer` | [`partials::PrevalenceExplorerRequest`] |
//! | POST | `/v1/prevalence/detail` | [`partials::PrevalenceDetailRequest`] |
//! | POST | `/v1/entity/ranges` | [`partials::EntityRangesRequest`] |
//! | POST | `/v1/risk` | the reader's `RiskRequest` |
//! | POST | `/v1/detections/plan` | [`detections::PlanRequest`] |
//! | POST | `/v1/detections/commit` | [`detections::CommitRequest`] (bounded by the observed head and the clock, NAN-3289) |
//! | POST | `/v1/detections/reset` | [`detections::ResetRequest`] (operator reset; detect scope at the router, NAN-3289) |
//! | POST | `/v1/jobs/search` | a `LakeQueryJobSpec` (search tasks); only as the router admitted it (`x-nano-cell-job-auth`, NAN-3289) |
//! | POST | `/v1/jobs/search/status` | `{tenant_id, job_id, attempt_id}` |
//! | POST | `/v1/jobs/search/cancel` | `{tenant_id, job_id, attempt_id}` |
//! | POST | `/v1/jobs/result-page` | `{job_id, reference, page}` |
//! | POST | `/v1/jobs/reuse-check` | `{tenant_id, job_id, manifest_sha256}`: may an identical settled search re-serve this finished job (NAN-3809) |
//! | POST | `/v1/identity/resolve*` | the reader's identity lookup shapes |
//! | GET | `/v1/status` | — |
//! | GET | `/v1/query/progress?request_id=` | — (NAN-3644 cold-read progress of in-flight requests) |
//! | GET | `/v1/schema/manifest` | — (the tenant's stored field inventory, NAN-2997) |
//! | POST | `/v1/ingest/refusals` | `{start_ms, end_ms}`: rows refused at admission per source lane (NAN-3662) |
//! | GET | `/v1/debug/slow-queries?min_ms=&limit=` | — operator only, like the probe: this process's slow real searches, no row data (NAN-3715) |
//! | POST | `/v1/debug/sql-probe` | [`super::sql_probe::ProbeRequest`]: operator only, as the router admitted it (`x-nano-cell-operator-debug`, NAN-3715) |
//!
//! Bootstrap secret (the sealed memfd the supervisor hands over): either the
//! credentials document [`QueryBootstrap`] itself (development / tests via
//! the cell's `DirKeySource`), or the opaque bootstrap token the process
//! exchanges once at the cell credential exchange ([`resolve_bootstrap`]).
//! Either way the process ends up with read-only storage credentials and the
//! owner's **public** signer keys only.

use anyhow::{bail, Context, Result};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use nanosiem_lake_cell::contract::Role;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::path::{Path, PathBuf};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sha2::{Digest, Sha256};

use super::credentials::{is_credential_stale, CredentialStale, QueryCredentialSwap, R2ReadAuthority};
use super::job_results::{JobResultStorageUnavailable, JobResultStore};
use super::detections::{CommitRequest, DetectionGate, GateRefused, PlanRequest, ResetRequest};
use super::engine::{BroadNplRequest, EngineSettings, FetchLogRequest, PartQueryEngine, PartQueryError};
use super::fetch::{parts_key_prefix, PartFetcher, R2ReadStore};
use super::log_view::PartLogView;
use super::{jobs, partials, risk};
use crate::identity::{
    plan_identity_batch, plan_identity_entity_batch, plan_identity_resolve, IdentityBatchItem,
    IdentityBatchRequest, IdentityEntityBatchItem, IdentityEntityBatchRequest, IdentityError,
    IdentityResolveRequest,
};
use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::TenantKeySet;
use crate::reader_object_cache::{ReaderObjectCache, ReaderObjectCacheSettings, ReaderObjectSource};

pub const BOOTSTRAP_FORMAT: &str = "nano.lake-query-bootstrap.v1";

/// Read-only object-store credentials for the tenant bucket.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct R2Credentials {
    pub endpoint: String,
    pub region: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    #[serde(default)]
    pub session_token: Option<String>,
    #[serde(default)]
    pub virtual_host_style: bool,
}

/// Engine placement values the control plane pins per assignment.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineBoot {
    pub chdb_library: PathBuf,
    pub chdb_sha256: String,
    pub compiler: PathBuf,
    #[serde(default = "default_query_bytes")]
    pub max_query_bytes: u64,
    #[serde(default = "default_execution_seconds")]
    pub max_execution_seconds: u64,
    /// Reader cache budget (bytes); default 8 GiB (design 4.1 at 300 eps).
    #[serde(default)]
    pub cache_bytes: Option<u64>,
    /// Per-query heavy cold-read threshold (bytes); default 2 GiB. NAN-3644:
    /// a read over it queues for a heavy slot; it is no longer refused.
    #[serde(default)]
    pub cache_query_bytes: Option<u64>,
    /// NAN-3644: heavy cold reads run at once (default 1; the
    /// `NANO_LAKE_READER_COLD_HEAVY_CONCURRENCY` env knob wins).
    #[serde(default)]
    pub cache_heavy_concurrency: Option<usize>,
    /// Recent window for startup prewarm. Optional residency is newest-first
    /// and byte-bounded; each query verifies any files skipped by prewarm.
    #[serde(default = "default_prewarm_hours")]
    pub prewarm_hours: u64,
    /// Hold readiness (503 `not_ready`) until the startup prewarm has proven
    /// the discovery and required local proofs, with optional residency within
    /// budget. Default false (NAN-2989): the process is ready once
    /// the engine is open and prewarms in the background, so the first
    /// search after a (re)start does only its own work instead of waiting
    /// out a prewarm of the whole 24 h backlog.
    #[serde(default)]
    pub prewarm_gates_readiness: bool,
}

fn default_prewarm_hours() -> u64 { 24 }

fn default_query_bytes() -> u64 {
    64 * 1024 * 1024 * 1024
}

fn default_execution_seconds() -> u64 {
    120
}

/// The credentials document.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryBootstrap {
    pub format: String,
    pub tenant_id: String,
    pub bucket: String,
    /// `None`: serve only from the cell-local parts directory (tests, labs).
    #[serde(default)]
    pub r2: Option<R2Credentials>,
    /// Exact tenant-prefix, read-only IOC snapshot credential.
    #[serde(default)]
    pub enrichment_r2: Option<R2Credentials>,
    /// `detect` only: the `lake_part` write credential (the tenant's
    /// `parts/` and `finding-outbox/receipts/` leaves; NAN-2916).
    #[serde(default)]
    pub part_write_r2: Option<R2Credentials>,
    /// Always `None` since NAN-2916: detect never writes `log/entries/`; the
    /// tenant's ingest process appends finding parts to the log.
    #[serde(default)]
    pub part_log_r2: Option<R2Credentials>,
    /// `query` only: the `job_results` grant (NAN-3042), read-write on
    /// exactly `nano-shared-r2-<T>` / `<T>/durable-query-result/v1/`.
    /// `None`: durable search jobs fail typed (no `file://` fallback).
    #[serde(default)]
    pub job_results_r2: Option<R2Credentials>,
    /// Explicit lab-only RustFS result storage, never exchanged by hosted control.
    #[serde(default)]
    pub trusted_local_job_results: Option<crate::part_ingest::s3_store::S3Location>,
    /// The owner release signer keys trusted for this tenant's part
    /// records (contract r2 4.3): current plus retired-but-retained.
    pub trusted_signer_keys: Vec<TrustedKey>,
    pub engine: EngineBoot,
    /// Optional, local, verified identity snapshot mounted inside this
    /// tenant's private state directory.
    #[serde(default)]
    pub identity_snapshot: Option<QueryIdentitySnapshotBoot>,
    /// The earliest expiry of the exchanged credentials (NAN-3017): the
    /// process re-exchanges before it. `None` for lab documents.
    #[serde(default)]
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryIdentitySnapshotBoot {
    pub snapshot_id: String,
    pub by_ip: crate::config::VerifiedArtifact,
}

/// One trusted owner signer key.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub key_id: String,
    /// Hex of the 32-byte ed25519 public key.
    pub public_key_hex: String,
}

/// One R2 credential from the cell credential exchange (the platform
/// `LakeCellCredential`; the same shape `ingest[T]` consumes).
#[derive(Clone, Deserialize)]
pub struct ExchangedCredential {
    pub credential_class: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub permission: String,
    pub prefixes: Vec<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// The exchange response for `role = "query"` or `role = "detect"`.
#[derive(Deserialize)]
pub struct QueryExchangeResponse {
    pub schema_version: u8,
    pub tenant_id: String,
    pub role: String,
    pub credentials: Vec<ExchangedCredential>,
    /// Owner release signer public keys (current + retained).
    pub trusted_keys: Vec<TrustedKey>,
    /// Image-pinned engine artifacts and limits for this assignment.
    pub query_engine: EngineBoot,
    #[serde(default)]
    pub identity_snapshot: Option<QueryIdentitySnapshotBoot>,
}

/// A detect exchange carries tenant read authority and only the write
/// authority needed to stage owner-signed finding parts and receipts.
#[derive(Deserialize)]
pub struct DetectExchangeResponse {
    pub schema_version: u8,
    pub tenant_id: String,
    pub role: String,
    pub credentials: Vec<ExchangedCredential>,
    pub trusted_keys: Vec<TrustedKey>,
    pub query_engine: EngineBoot,
    #[serde(default)]
    pub identity_snapshot: Option<QueryIdentitySnapshotBoot>,
    pub owner_sign: crate::part_ingest::cell::OwnerSignBearer,
    pub finding_drain: FindingDrainCredential,
    pub assignment_generation: u64,
    pub writer_epoch: u64,
}

#[derive(Deserialize)]
pub struct FindingDrainCredential {
    pub tenant_id: String,
    pub capability: String,
    pub database_url: String,
    pub expires_at: String,
}

pub struct DetectBootstrap {
    pub query: QueryBootstrap,
    pub part: ExchangedCredential,
    pub log: ExchangedCredential,
    pub owner_sign: crate::part_ingest::cell::OwnerSignBearer,
    pub finding_drain: FindingDrainCredential,
    pub assignment_generation: u64,
    pub writer_epoch: u64,
}

pub async fn resolve_detect_bootstrap(secret: &[u8], tenant_id: &str, cell_id: &str, control_url: Option<&str>) -> Result<DetectBootstrap> {
    let control_url = control_url.context("detect assignment has no credential exchange")?;
    if !control_url.starts_with("https://") && !cfg!(test) { bail!("detect credential exchange must use https"); }
    let token = std::str::from_utf8(secret).context("detect bootstrap token is not text")?.trim();
    let url = format!("{}/v1/lake/cells/{cell_id}/credential-exchange", control_url.trim_end_matches('/'));
    let response = reqwest::Client::builder().timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none()).build()?
        .post(url).bearer_auth(token)
        .json(&exchange_request_body(tenant_id, Role::Detect)?).send().await?;
    if !response.status().is_success() {
        return Err(anyhow::Error::new(crate::part_ingest::cell::ExchangeRefused::new(response.status().as_u16()))
            .context("detect credential exchange refused"));
    }
    let exchange: DetectExchangeResponse = serde_json::from_slice(&response.bytes().await?)?;
    detect_bootstrap_from_exchange(exchange, tenant_id)
}

/// Validate a detect exchange: the strict storage-class set of
/// [`bootstrap_from_exchange`] for [`Role::Detect`] (exactly lake_part_read +
/// lake_part, optional enrichment_reader, each once, each exactly scoped),
/// plus the detect-only owner signer and finding-drain DB credential.
pub fn detect_bootstrap_from_exchange(exchange: DetectExchangeResponse, tenant_id: &str) -> Result<DetectBootstrap> {
    if exchange.assignment_generation == 0 || exchange.writer_epoch == 0 {
        bail!("detect exchange lacks an assignment generation or writer epoch");
    }
    if exchange.owner_sign.audience != "owner" || exchange.owner_sign.scope != "lake-parts:sign" {
        bail!("detect signer scope differs");
    }
    if exchange.finding_drain.tenant_id != tenant_id || exchange.finding_drain.capability != "finding_drain" {
        bail!("detect database credential binding differs");
    }
    if !exchange.finding_drain.database_url.starts_with("postgres://") && !exchange.finding_drain.database_url.starts_with("postgresql://") {
        bail!("detect database credential is not a PostgreSQL URL");
    }
    let now = chrono::Utc::now();
    if crate::cell_refresh::owner_bearer_expiry(&exchange.owner_sign.expires_at, now) <= now
        || chrono::DateTime::parse_from_rfc3339(&exchange.finding_drain.expires_at)?.with_timezone(&chrono::Utc) <= now {
        bail!("detect credential has expired");
    }
    let class = |name: &str| exchange.credentials.iter().find(|c| c.credential_class == name).cloned();
    let (read, part) = (class("lake_part_read"), class("lake_part"));
    let query = bootstrap_from_exchange(QueryExchangeResponse {
        schema_version: exchange.schema_version, tenant_id: exchange.tenant_id, role: exchange.role,
        credentials: exchange.credentials, trusted_keys: exchange.trusted_keys,
        query_engine: exchange.query_engine, identity_snapshot: exchange.identity_snapshot,
    }, tenant_id, Role::Detect)?;
    let (Some(read), Some(part)) = (read, part) else { bail!("detect exchange omitted a part credential") };
    // Log reads use the broad tenant read-only key.
    Ok(DetectBootstrap { query, part, log: read, owner_sign: exchange.owner_sign,
        finding_drain: exchange.finding_drain, assignment_generation: exchange.assignment_generation,
        writer_epoch: exchange.writer_epoch })
}

/// Resolve the bootstrap secret into the credentials document.
///
/// - Lab / dev cells (`DirKeySource`): the secret is the
///   [`QueryBootstrap`] JSON itself.
/// - Production: the secret is the opaque, single-use bootstrap token the
///   supervisor minted for THIS process's role. It is POSTed (bearer) once to
///   `{control_url}/v1/lake/cells/{cell_id}/credential-exchange` with
///   `{"tenant_id", "role"}`, where `role` is the assignment's role (`query`
///   or `detect`; this binary serves both). The platform binds the token to that
///   role, so exchanging as any other role is refused. The response must
///   carry exactly that role's credential set ([`role_credential_set`]). A
///   refusal is final for this token; the supervisor restarts with a fresh one.
pub async fn resolve_bootstrap(secret: &[u8], tenant_id: &str, cell_id: &str, control_url: Option<&str>, role: Role) -> Result<QueryBootstrap> {
    if control_url.is_none() {
        if let Ok(value) = serde_json::from_slice::<Value>(secret) {
            if value.get("format").and_then(Value::as_str) == Some(BOOTSTRAP_FORMAT) {
                let document = serde_json::from_value::<QueryBootstrap>(value)?;
                if document.tenant_id != tenant_id {
                    bail!("bootstrap document is for another tenant");
                }
                if document.trusted_local_job_results.is_some() && (role != Role::Query || document.job_results_r2.is_some() || document.expires_at.is_some()) {
                    bail!("trusted-local job results require a local query bootstrap without hosted grants");
                }
                return Ok(document);
            }
        }
    }
    let control_url = control_url.context("assignment has no control_url for the credential exchange")?;
    if !control_url.starts_with("https://") && !cfg!(test) {
        bail!("credential exchange must use https");
    }
    let mut body = exchange_request_body(tenant_id, role)?;
    let token = std::str::from_utf8(secret).context("bootstrap token is not text")?.trim();
    let url = format!("{}/v1/lake/cells/{cell_id}/credential-exchange", control_url.trim_end_matches('/'));
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let mut response = client.post(&url).bearer_auth(token).json(&body).send().await?;
    // NAN-3042 rollout: a control plane that predates `job_results` refuses
    // the unknown `accepts` class as a malformed body (400 `bad_request`)
    // WITHOUT consuming the token, so the same token is re-sent once without
    // it. Jobs then fail typed (no grant) while search keeps working.
    if response.status() == reqwest::StatusCode::BAD_REQUEST && role == Role::Query {
        let refused: Value = response.json().await.unwrap_or(Value::Null);
        if refused.get("error").and_then(Value::as_str) == Some("bad_request") {
            if let Some(accepts) = body.get_mut("accepts").and_then(Value::as_array_mut) {
                accepts.retain(|class| class != super::job_results::JOB_RESULTS_CLASS);
            }
            tracing::warn!("credential exchange refused the job_results declaration; exchanging without it (durable jobs unavailable)");
            response = client.post(&url).bearer_auth(token).json(&body).send().await?;
        } else {
            return Err(anyhow::Error::new(crate::part_ingest::cell::ExchangeRefused::new(400))
                .context(format!("{} credential exchange refused (400); the bootstrap token is spent", role.as_str())));
        }
    }
    let status = response.status();
    if !status.is_success() {
        // Typed, so a refresh tells a final 401/403 from a retryable 503.
        return Err(anyhow::Error::new(crate::part_ingest::cell::ExchangeRefused::new(status.as_u16()))
            .context(format!("{} credential exchange refused ({status}); the bootstrap token is spent", role.as_str())));
    }
    let exchange: QueryExchangeResponse = serde_json::from_slice(&response.bytes().await?).context("credential exchange response")?;
    bootstrap_from_exchange(exchange, tenant_id, role)
}

/// The roles this binary runs as. `ingest` has its own binary and exchange.
fn exchange_role(role: Role) -> Result<&'static str> {
    match role {
        Role::Query | Role::Detect => Ok(role.as_str()),
        // NAN-3148: product[T] holds exactly query's read-only authority and
        // exchanges for it (the supervisor mints its token as `query`).
        Role::Product => Ok(Role::Query.as_str()),
        Role::Ingest => bail!("lake_part_query does not exchange as ingest"),
        Role::Maintenance => bail!("lake_part_query does not exchange as maintenance"),
    }
}

/// The exchange request: the role is the assignment's, never a constant, and
/// `accepts` declares every credential class this binary can consume for that
/// role (required + optional). The platform mints nothing outside it; a
/// response carrying an undeclared class is refused.
pub fn exchange_request_body(tenant_id: &str, role: Role) -> Result<Value> {
    let (required, optional) = role_credential_set(role)?;
    let accepts: Vec<&str> = required.iter().chain(optional).copied().collect();
    Ok(json!({"tenant_id": tenant_id, "role": exchange_role(role)?, "accepts": accepts}))
}

/// Exactly the credential classes each role receives (the platform
/// `LEAN_LAKE_CELL_ROLE_CLASSES`): `(required, optional)`. `enrichment_reader`
/// is present only when the cell image reports `lean_enrichment_reader_v1`.
pub fn role_credential_set(role: Role) -> Result<(&'static [&'static str], &'static [&'static str])> {
    match role {
        // `job_results` (NAN-3042): minted only for images reporting the
        // `lean_job_results_v1` cell feature; absent, jobs fail typed.
        Role::Query => Ok((&["lake_part_read"], &["enrichment_reader", super::job_results::JOB_RESULTS_CLASS])),
        // NAN-2916: detect stages owner-signed finding parts and receipts
        // (lake_part) and reads the tenant (lake_part_read). It never holds
        // lake_part_log: the tenant's single ingest appender commits the Add.
        // owner-sign and the finding-drain DB credential ride in the detect
        // exchange body ([`DetectExchangeResponse`]), not as storage classes.
        Role::Detect => Ok((&["lake_part_read", "lake_part"], &["enrichment_reader"])),
        // NAN-3148: query's read classes, never durable job results.
        Role::Product => Ok((&["lake_part_read"], &["enrichment_reader"])),
        Role::Ingest => bail!("lake_part_query does not exchange as ingest"),
        Role::Maintenance => bail!("lake_part_query does not exchange as maintenance"),
    }
}

/// Validate an exchange response against the role this process runs as and
/// turn it into the bootstrap document. Strict: the response must be bound to
/// this tenant AND role, and carry exactly the role's required classes plus at
/// most its optional ones, each once, each scoped exactly.
pub fn bootstrap_from_exchange(exchange: QueryExchangeResponse, tenant_id: &str, role: Role) -> Result<QueryBootstrap> {
    let role_name = exchange_role(role)?;
    if exchange.schema_version != 1 || exchange.tenant_id != tenant_id || exchange.role != role_name {
        bail!("credential exchange response binding differs");
    }
    let (required, optional) = role_credential_set(role)?;
    let mut seen = BTreeSet::new();
    for credential in &exchange.credentials {
        let class = credential.credential_class.as_str();
        if !required.contains(&class) && !optional.contains(&class) {
            bail!("{role_name} credential exchange returned undeclared class {class:?}");
        }
        if !seen.insert(class) {
            bail!("{role_name} credential exchange returned {class:?} twice");
        }
    }
    if let Some(missing) = required.iter().find(|class| !seen.contains(**class)) {
        bail!("{role_name} credential exchange omitted {missing}");
    }
    let class = |name: &str| exchange.credentials.iter().find(|c| c.credential_class == name);
    let credential = class("lake_part_read").context("credential exchange omitted lake_part_read")?;
    validate_query_credential(credential, tenant_id)?;
    let enrichment = class("enrichment_reader");
    if let Some(enrichment) = enrichment {
        validate_enrichment_credential(enrichment, tenant_id)?;
        if enrichment.bucket != credential.bucket {
            bail!("query enrichment credential names another bucket");
        }
    }
    let job_results = class(super::job_results::JOB_RESULTS_CLASS);
    if let Some(job_results) = job_results {
        super::job_results::validate_job_results_credential(job_results, tenant_id)?;
        if job_results.bucket != credential.bucket || job_results.endpoint != credential.endpoint {
            bail!("query job_results credential names another store");
        }
    }
    let (part_write, part_log) = match role {
        Role::Detect => {
            let write = class("lake_part").context("detect credential exchange omitted lake_part")?;
            validate_detect_write_credential(write, tenant_id)?;
            if write.bucket != credential.bucket || write.endpoint != credential.endpoint {
                bail!("detect write credential names another store");
            }
            (Some(write), None)
        }
        _ => (None, None),
    };
    let to_r2 = |c: &ExchangedCredential| R2Credentials {
        endpoint: c.endpoint.clone(), region: c.region.clone(),
        access_key_id: c.access_key_id.clone(), secret_access_key: c.secret_access_key.clone(),
        session_token: Some(c.session_token.clone()).filter(|token| !token.is_empty()),
        virtual_host_style: false,
    };
    let mut expires_at: Option<chrono::DateTime<chrono::Utc>> = None;
    for used in [Some(credential), enrichment, part_write, job_results].into_iter().flatten() {
        if let Some(at) = &used.expires_at {
            let at = chrono::DateTime::parse_from_rfc3339(at)
                .with_context(|| format!("{} credential expiry is not RFC 3339", used.credential_class))?
                .with_timezone(&chrono::Utc);
            expires_at = Some(expires_at.map_or(at, |current| current.min(at)));
        }
    }
    Ok(QueryBootstrap {
        format: BOOTSTRAP_FORMAT.to_string(),
        tenant_id: tenant_id.to_string(),
        bucket: credential.bucket.clone(),
        r2: Some(to_r2(credential)),
        enrichment_r2: enrichment.map(to_r2),
        part_write_r2: part_write.map(to_r2),
        part_log_r2: part_log.map(to_r2),
        job_results_r2: job_results.map(to_r2),
        trusted_local_job_results: None,
        trusted_signer_keys: exchange.trusted_keys,
        engine: exchange.query_engine,
        identity_snapshot: exchange.identity_snapshot,
        expires_at,
    })
}

/// Identity inputs are local and immutable for the life of a query process.
/// The cell must mount them below this tenant's state directory; a token can
/// never name a sibling tenant's file.
pub fn load_identity_snapshot(boot: &QueryBootstrap, state_dir: &std::path::Path) -> Result<Option<crate::identity::IdentitySnapshot>> {
    let Some(config) = &boot.identity_snapshot else { return Ok(None) };
    if config.snapshot_id.is_empty() || config.snapshot_id.len() > 256 || config.snapshot_id.chars().any(char::is_control) {
        bail!("identity snapshot ID is invalid");
    }
    let root = std::fs::canonicalize(state_dir).context("canonicalize tenant state directory")?;
    let path = std::fs::canonicalize(&config.by_ip.path).context("canonicalize identity snapshot")?;
    if !path.starts_with(root.join("identity")) {
        bail!("identity snapshot is outside the tenant state directory");
    }
    let metadata = std::fs::metadata(&path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > boot.engine.max_query_bytes {
        bail!("identity snapshot exceeds the query budget or is empty");
    }
    if crate::native::file_sha256(&path)? != config.by_ip.sha256 {
        bail!("identity snapshot SHA-256 differs from its assignment");
    }
    Ok(Some(crate::identity::IdentitySnapshot::from(crate::config::LoadedIdentitySnapshotConfig {
        snapshot_id: config.snapshot_id.clone(),
        by_ip: path,
        by_ip_sha256: config.by_ip.sha256.clone(),
        by_ip_bytes: metadata.len(),
        by_ip_modified: metadata.modified()?,
    })))
}

fn validate_query_credential(credential: &ExchangedCredential, tenant_id: &str) -> Result<()> {
    if credential.credential_class != "lake_part_read" {
        bail!("query credential is not lake_part_read");
    }
    let tenant_prefix = format!("{}/tenant={tenant_id}/", crate::parts::format::PARTS_ROOT);
    if credential.permission != "object-read-only" {
        bail!("lake_part_read credential is not object-read-only");
    }
    if credential.prefixes != [tenant_prefix.clone()] {
        bail!("lake_part_read credential is not scoped to exactly {tenant_prefix}");
    }
    Ok(())
}

fn validate_enrichment_credential(credential: &ExchangedCredential, tenant_id: &str) -> Result<()> {
    let expected = format!("lake/enrichment/v1/tenant_id={tenant_id}/");
    if credential.credential_class != "enrichment_reader"
        || credential.permission != "object-read-only"
        || credential.prefixes != [expected]
    {
        bail!("query enrichment credential is not read-only for exactly this tenant");
    }
    Ok(())
}

/// `detect`'s only write credential (NAN-2916): `lake_part` read-write on
/// exactly the tenant's `parts/` and `finding-outbox/receipts/` (any order).
fn validate_detect_write_credential(part: &ExchangedCredential, tenant_id: &str) -> Result<()> {
    let root = format!("{}/tenant={tenant_id}/", crate::parts::format::PARTS_ROOT);
    let mut want = vec![format!("{root}parts/"), format!("{root}finding-outbox/receipts/")];
    want.sort();
    let mut got = part.prefixes.clone();
    got.sort();
    if part.credential_class != "lake_part" || part.permission != "object-read-write" || got != want {
        bail!("detect lake_part credential is not scoped to exactly this tenant's parts and finding receipts");
    }
    Ok(())
}

/// The tenant IOC store; swappable (`S3ObjectStore::replace`) on refresh.
pub fn open_ioc_store(boot: &QueryBootstrap) -> Result<Option<Arc<crate::part_ingest::s3_store::S3ObjectStore>>> {
    let Some(credentials) = &boot.enrichment_r2 else { return Ok(None) };
    Ok(Some(Arc::new(crate::part_ingest::s3_store::S3ObjectStore::new(&ioc_location(boot, credentials))?)))
}

pub(crate) fn ioc_location(boot: &QueryBootstrap, credentials: &R2Credentials) -> crate::part_ingest::s3_store::S3Location {
    crate::part_ingest::s3_store::S3Location {
        endpoint: credentials.endpoint.clone(), region: credentials.region.clone(),
        bucket: boot.bucket.clone(),
        prefix: format!("lake/enrichment/v1/tenant_id={}/", boot.tenant_id),
        access_key_id: credentials.access_key_id.clone(),
        secret_access_key: credentials.secret_access_key.clone(),
        session_token: credentials.session_token.clone(),
    }
}

fn trusted_keys(trusted: &[TrustedKey]) -> Result<TenantKeySet> {
    let mut keys = Vec::new();
    for key in trusted {
        if !crate::parts::provenance::valid_key_id(&key.key_id) {
            bail!("trusted signer key id is malformed");
        }
        let bytes: [u8; 32] = hex::decode(&key.public_key_hex)?.try_into().map_err(|_| anyhow::anyhow!("public key is not 32 bytes"))?;
        keys.push((key.key_id.clone(), ed25519_dalek::VerifyingKey::from_bytes(&bytes)?));
    }
    if keys.is_empty() {
        bail!("no trusted ingest key");
    }
    Ok(TenantKeySet::new(keys))
}

/// Tenant-bucket reads: the cell-local parts dir first (ingest writes there
/// before R2, so a new part is local when query is notified), then R2.
/// Read-only: writes and LIST are refused.
pub struct LayeredStore {
    local: Option<LocalObjectStore>,
    remote: Option<R2ReadStore>,
    /// `lake/parts/v1/tenant=<uuid>/`: every read must stay under it.
    tenant_prefix: String,
}

#[async_trait::async_trait]
impl ObjectStore for LayeredStore {
    async fn get_range(&self, key: &str, range: std::ops::Range<u64>) -> Result<Option<Vec<u8>>> {
        if !key.starts_with(&self.tenant_prefix) { bail!("read outside the tenant's parts prefix refused") }
        if let Some(local) = &self.local {
            if let Some(bytes) = local.get_range(key, range.clone()).await? { return Ok(Some(bytes)) }
        }
        match &self.remote {
            Some(remote) => remote.get_range(key, range).await,
            None => Ok(None),
        }
    }

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>> {
        if !key.starts_with(&self.tenant_prefix) {
            bail!("read outside the tenant's parts prefix refused");
        }
        if let Some(local) = &self.local {
            if let Some(bytes) = local.get(key).await? {
                return Ok(Some(bytes));
            }
        }
        match &self.remote {
            Some(remote) => remote.get(key).await,
            None => Ok(None),
        }
    }
    async fn put_if_absent(&self, _key: &str, _bytes: &[u8]) -> Result<bool> {
        bail!("the query process is read-only")
    }
    async fn put(&self, _key: &str, _bytes: &[u8]) -> Result<()> {
        bail!("the query process is read-only")
    }
    async fn delete(&self, _key: &str) -> Result<()> {
        bail!("the query process is read-only")
    }
    async fn list(&self, _prefix: &str) -> Result<Vec<String>> {
        bail!("the query process never lists")
    }
}

/// Part-file bytes for the verified cache, streamed (never a whole object
/// in memory; data files reach 1 GiB): the cell-local parts dir first, then
/// a ranged R2 GET. The cache fences length and SHA-256 either way.
pub struct LocalFirstSource {
    bucket: String,
    tenant_prefix: String,
    local_root: Option<PathBuf>,
    /// Swappable read authority (NAN-3017): each stream takes the current
    /// operator and a refused open is retried once after a refresh.
    remote: Option<Arc<R2ReadAuthority>>,
}

#[async_trait::async_trait]
impl ReaderObjectSource for LocalFirstSource {
    async fn stream_object(
        &self,
        object: &crate::reader_object_cache::ReaderObjectRef,
        sink: &mut (dyn for<'b> FnMut(&'b [u8]) -> anyhow::Result<()> + Send),
    ) -> anyhow::Result<()> {
        let (bucket, key) = crate::hot_tail_cache::parse_s3_uri(&object.source_uri)?;
        if bucket != self.bucket {
            bail!("part object is outside the tenant bucket");
        }
        if !key.starts_with(&self.tenant_prefix) {
            bail!("part object is outside the tenant's parts prefix");
        }
        if let Some(root) = &self.local_root {
            let path = LocalObjectStore::new(root)?.path(key)?;
            if path.is_file() {
                return super::fetch::stream_local_range(&path, object.range.clone(), sink).await;
            }
        }
        let Some(remote) = &self.remote else {
            bail!("part object vanished: not in the local parts dir and no R2 credential is held");
        };
        let installed = remote.current();
        let mut delivered = 0_u64;
        let first = {
            let mut counting = |chunk: &[u8]| { delivered += chunk.len() as u64; sink(chunk) };
            crate::reader_object_cache::R2ReaderObjectSource::new(installed.operator.clone(), self.bucket.clone())
                .stream_object(object, &mut counting).await
        };
        match first {
            // Retry only a refusal before any byte reached the sink.
            Err(error) if delivered == 0 && is_credential_stale(&error) => match remote.recover(installed.generation).await {
                Some(next) => crate::reader_object_cache::R2ReaderObjectSource::new(next.operator.clone(), self.bucket.clone())
                    .stream_object(object, sink).await
                    .map_err(|error| if is_credential_stale(&error) { CredentialStale(format!("{error:#}")).into() } else { error }),
                None => Err(CredentialStale(format!("{error:#}")).into()),
            },
            other => other,
        }
    }
}

pub fn r2_operator(bucket: &str, credentials: &R2Credentials) -> Result<opendal::Operator> {
    // Tests reach an in-process S3 stand-in on loopback.
    let loopback_test = cfg!(test) && credentials.endpoint.starts_with("http://127.0.0.1:");
    if !(credentials.endpoint.starts_with("https://") || loopback_test) || credentials.endpoint.contains('@') {
        bail!("R2 endpoint must be an HTTPS service endpoint");
    }
    let mut builder = opendal::services::S3::default()
        .bucket(bucket)
        .region(&credentials.region)
        .endpoint(&credentials.endpoint)
        .access_key_id(&credentials.access_key_id)
        .secret_access_key(credentials.secret_access_key.as_str())
        .disable_config_load()
        .disable_ec2_metadata();
    if credentials.virtual_host_style {
        builder = builder.enable_virtual_host_style();
    }
    if let Some(token) = &credentials.session_token {
        builder = builder.session_token(token.as_str());
    }
    Ok(opendal::Operator::new(builder)?.layer(crate::r2_ops::layer()).finish())
}

/// Everything needed to open an engine, independent of the cell.
pub struct OpenOptions {
    pub bootstrap: QueryBootstrap,
    /// The swappable read authority over `bootstrap.r2` (NAN-3017). `None`:
    /// built here without refresh (labs, tests).
    pub r2: Option<Arc<R2ReadAuthority>>,
    pub parts_dir: Option<PathBuf>,
    pub state_dir: PathBuf,
    pub memory_cap_bytes: u64,
    /// NAN-3077: small lanes plus one large lane (the query role); detect[T]
    /// keeps its equal lanes.
    pub size_classes: bool,
    pub cpu_millis: u32,
}

/// Open the per-tenant engine: verified log view, verified cache, chDB lanes.
/// Wall time of each query[T] startup phase (NAN-3008), logged once at
/// INFO as `query startup phases` so every cold start attributes itself
/// (a live cold start spent ~19 s between spawn and first work unexplained).
#[derive(Debug)]
pub struct StartupPhases {
    started: Instant,
    last: Instant,
    phases: Vec<(&'static str, u64)>,
}

impl Default for StartupPhases {
    fn default() -> Self {
        let now = Instant::now();
        Self { started: now, last: now, phases: Vec::new() }
    }
}

impl StartupPhases {
    /// Close the phase that ran since the previous lap.
    pub fn lap(&mut self, phase: &'static str) {
        let now = Instant::now();
        self.phases.push((phase, now.duration_since(self.last).as_millis() as u64));
        self.last = now;
    }

    pub fn total_ms(&self) -> u64 {
        self.last.duration_since(self.started).as_millis() as u64
    }

    pub fn as_json(&self) -> Value {
        let mut phases = serde_json::Map::new();
        for (name, ms) in &self.phases {
            phases.insert(format!("{name}_ms"), json!(ms));
        }
        json!({"total_ms": self.total_ms(), "phases": phases})
    }

    pub fn log(&self, tenant_id: &str) {
        tracing::info!(tenant_id, total_ms = self.total_ms(), phases = %self.as_json()["phases"], "query startup phases");
    }
}

/// Where memoized artifact digests live (the process's private state).
fn artifact_memo_dir(state_dir: &Path) -> Option<PathBuf> {
    let dir = state_dir.join("artifact-digests");
    std::fs::create_dir_all(&dir).ok().map(|_| dir)
}

/// The query compiler's digest (identity pin), memoized like libchdb's.
pub fn compiler_sha256(compiler: &Path, state_dir: &Path) -> Result<String> {
    Ok(crate::native::artifact_sha256_memoized(compiler, artifact_memo_dir(state_dir).as_deref(), true)?)
}

/// Remove leftover chDB embedded-server directories (and their spill files)
/// from `dir`. Best effort; only entries named `clickhouse-embedded-*`.
pub fn remove_stale_embedded_dirs(dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(dir) else { return 0 };
    let mut removed = 0;
    for entry in entries.flatten() {
        let stale = entry.file_name().to_str().is_some_and(|name| name.starts_with("clickhouse-embedded-"))
            && entry.file_type().is_ok_and(|kind| kind.is_dir());
        if stale && std::fs::remove_dir_all(entry.path()).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        tracing::info!(removed, "removed stale chDB embedded directories");
    }
    removed
}

pub async fn open_engine(options: &OpenOptions) -> Result<(PartQueryEngine, DetectionGate)> {
    open_engine_timed(options, &mut StartupPhases::default()).await
}

pub async fn open_engine_timed(options: &OpenOptions, phases: &mut StartupPhases) -> Result<(PartQueryEngine, DetectionGate)> {
    let boot = &options.bootstrap;
    let tenant_id = boot.tenant_id.clone();
    let keys = trusted_keys(&boot.trusted_signer_keys)?;
    let authority = match (&options.r2, &boot.r2) {
        (Some(authority), _) => Some(authority.clone()),
        (None, Some(credentials)) => Some(R2ReadAuthority::new(boot.bucket.clone(), r2_operator(&boot.bucket, credentials)?, None)),
        (None, None) => None,
    };
    let remote = authority.clone().map(R2ReadStore::new);
    let local = match &options.parts_dir {
        Some(dir) if dir.is_dir() => Some(LocalObjectStore::new(dir)?),
        _ => None,
    };
    if local.is_none() && remote.is_none() {
        bail!("query[T] has neither a local parts dir nor R2 credentials");
    }
    let store: Arc<dyn ObjectStore> = Arc::new(LayeredStore { local, remote, tenant_prefix: format!("{}/tenant={tenant_id}/", crate::parts::format::PARTS_ROOT) });
    // chDB's embedded server lives in `clickhouse-embedded-<uuid>` under the
    // working directory (the state dir), and so does its spill `tmp/`. A
    // killed predecessor leaves its copy behind; drop those before starting.
    remove_stale_embedded_dirs(&options.state_dir);
    // libchdb (~550 MB) is verified and loaded on a blocking thread while
    // the part log is read over the network (NAN-3008).
    let chdb = {
        let (library, sha256) = (boot.engine.chdb_library.clone(), boot.engine.chdb_sha256.clone());
        let memo = artifact_memo_dir(&options.state_dir);
        tokio::task::spawn_blocking(move || NativeChdb::load_verified_memoized(&library, &sha256, memo.as_deref()))
    };
    phases.lap("stores");
    let view = PartLogView::open(store.as_ref(), &tenant_id, keys.clone()).await?;
    phases.lap("part_log_open");
    let source: Arc<dyn ReaderObjectSource> = Arc::new(LocalFirstSource {
        bucket: boot.bucket.clone(),
        tenant_prefix: format!("{}/tenant={tenant_id}/", crate::parts::format::PARTS_ROOT),
        local_root: options.parts_dir.clone().filter(|dir| dir.is_dir()),
        remote: authority,
    });
    let hot_settings = crate::local_hot_window::Settings::from_env(&options.state_dir.join("cache"), &tenant_id, options.cpu_millis)?;
    if let Some(settings) = &hot_settings { crate::local_hot_window::create_root(settings)?; }
    // NAN-3647: a persistent (A/B) hot-window volume never blocks query[T]:
    // an unusable cache on it is discarded and rebuilt cold.
    let open_cache = if hot_settings.as_ref().is_some_and(|s| s.persistent) { ReaderObjectCache::open_or_reset } else { ReaderObjectCache::open };
    let cache = open_cache(
        ReaderObjectCacheSettings {
            root: hot_settings.as_ref().map_or_else(|| options.state_dir.join("cache"), |s| s.root.clone()),
            max_bytes: hot_settings.as_ref().map(|s| s.max_bytes).unwrap_or_else(|| boot.engine.cache_bytes.unwrap_or(8 * 1024 * 1024 * 1024)).max(1),
            query_max_bytes: boot.engine.cache_query_bytes.unwrap_or(2 * 1024 * 1024 * 1024),
            // NAN-3647: room for the warm gate's warm-up fan-out (gate off: 8, as before).
            fetch_concurrency: hot_settings.as_ref().filter(|s| s.schedule.warm_gate).map_or(8, |s| s.schedule.pass_concurrency(false).max(8)),
            fetch_deadline: Duration::from_secs(60),
        },
        &tenant_id,
        &boot.bucket,
        &parts_key_prefix(&tenant_id)?,
        source,
    )?;
    if let Some(settings) = &hot_settings { cache.set_hot_capacity(settings.clone()); }
    // NAN-3644: the env knob wins over the boot document.
    if std::env::var_os(crate::reader_object_cache::READER_COLD_HEAVY_CONCURRENCY_ENV).is_none() {
        if let Some(slots) = boot.engine.cache_heavy_concurrency {
            cache.set_cold_heavy_concurrency(slots);
        }
    }
    tracing::info!(
        heavy_concurrency = cache.cold_heavy_concurrency(),
        heavy_threshold_bytes = cache.query_max_bytes(),
        interactive_ceiling_bytes = cache.interactive_cold_ceiling(),
        durable_ceiling_bytes = cache.durable_cold_ceiling(),
        cache_bytes = cache.max_bytes(),
        "reader cold-read admission"
    );
    let fetcher = PartFetcher::new(&tenant_id, &boot.bucket, store.clone(), keys, cache)?
        .with_hot_window(hot_settings)
        .with_edge_logs(view.edge_logs())
        .with_local_root(options.parts_dir.clone().filter(|dir| dir.is_dir()))
        .with_state_dir(&options.state_dir);
    phases.lap("cache_open");
    let runtime = chdb.await.context("chDB load task")??;
    phases.lap("chdb_load_wait");
    // Every limit below is carved out of the role's memory.max (see
    // `memory_budget`): chDB's total and per-statement caps, the number of
    // requests admitted to native work (one per read lane) and the largest
    // result decoded in Rust.
    let budget = super::memory_budget::QueryMemoryBudget::for_process(options.memory_cap_bytes);
    let (budget, classes) = if options.size_classes { budget.with_classes() } else { (budget, None) };
    // NAN-3393 kill switch: `NANO_LAKE_LANE_ROUTING_V2=0` is NAN-3077's lanes.
    let routing_v2 = super::lanes::lane_routing_v2_enabled();
    if let Some(classes) = &classes {
        tracing::info!(small_lanes = classes.small_lanes, small_bytes = classes.small_bytes, large_bytes = classes.large_bytes,
            large_lanes = super::lanes::large_lane_connections(classes.large_bytes, routing_v2), routing_v2, "query lanes by size");
    }
    let threads = u64::from(nanosiem_lake_cell::budget::query_threads(options.cpu_millis));
    let read_lanes = classes.map_or(budget.concurrency, |classes| classes.small_lanes);
    let executor = NativeExecutor::start_with_server_memory_limit(runtime.clone(), read_lanes, "parts", ExecutorMode::ReadOnly, Some(budget.server_bytes))?
        .with_result_limit(budget.result_bytes);
    let large = match &classes {
        Some(classes) => Some((
            // NAN-3393: two statements at half the large memory each when
            // half is still a large lane (the 4 GiB role: 2 x 768 MiB); a
            // statement that outgrows half takes both (see `lanes::LargeLane`).
            NativeExecutor::start_with_server_memory_limit(runtime.clone(), super::lanes::large_lane_connections(classes.large_bytes, routing_v2),
                "parts-large", ExecutorMode::ReadOnly, Some(budget.server_bytes))?
                .with_result_limit(budget.result_bytes),
            classes.large_bytes,
        )),
        None => None,
    };
    // NAN-3077: event detail (one row by uid) gets its own lane, so it never
    // waits behind a scan; its statements read one row group.
    let point = NativeExecutor::start_with_server_memory_limit(runtime.clone(), 1, "parts-point", ExecutorMode::ReadOnly, Some(budget.server_bytes))?
        .with_result_limit(budget.result_bytes);
    let writer = NativeExecutor::start_with_server_memory_limit(runtime, 1, "parts-rw", ExecutorMode::ReadWrite, Some(budget.server_bytes))?;
    phases.lap("executors_start");
    let settings = EngineSettings {
        tenant_id: tenant_id.clone(),
        bucket: boot.bucket.clone(),
        compiler: boot.engine.compiler.clone(),
        max_query_bytes: boot.engine.max_query_bytes,
        max_memory_bytes: budget.per_query_bytes.min(crate::planner::DEFAULT_QUERY_MEMORY_BYTES),
        max_execution_seconds: boot.engine.max_execution_seconds,
        threads,
    };
    let head = view.head().map_or(0, |(seq, _)| seq);
    let live_ranges = view.live().parts().map(|part| (part.min_time_us, part.max_time_us)).collect::<Vec<_>>();
    let mut engine = PartQueryEngine::new(settings, store, view, fetcher, executor)?
        .with_writer(writer)
        .with_point(point);
    if let Some((large, large_bytes)) = large {
        engine = engine.with_large_lane(super::lanes::LargeLane::with_routing(large, large_bytes, routing_v2));
    }
    let engine = engine
        .with_state_dir(&options.state_dir);
    let gate = DetectionGate::new(Some(options.state_dir.clone()), head)?;
    gate.seed(live_ranges);
    phases.lap("engine_and_gate");
    Ok((engine, gate))
}

/// Query readiness vs. prewarm requests (NAN-2984). Only a gated request
/// (the startup prewarm) withdraws readiness; any prewarm that completes
/// while it is still the newest request makes the process ready, since each
/// one covers every live part. A newer request supersedes older ones.
#[derive(Debug, Default)]
pub struct PrewarmReadiness {
    ready: AtomicBool,
    requested: AtomicU64,
}

impl PrewarmReadiness {
    /// Register a prewarm; returns its ticket.
    pub fn request(&self, gate_readiness: bool) -> u64 {
        let ticket = self.requested.fetch_add(1, Ordering::SeqCst) + 1;
        if gate_readiness {
            self.ready.store(false, Ordering::SeqCst);
        }
        ticket
    }

    /// Still the newest request (an older prewarm stops early).
    pub fn is_current(&self, ticket: u64) -> bool {
        self.requested.load(Ordering::SeqCst) == ticket
    }

    /// The prewarm for `ticket` finished.
    pub fn complete(&self, ticket: u64) {
        if self.is_current(ticket) {
            self.ready.store(true, Ordering::SeqCst);
        }
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::SeqCst)
    }

    /// Ready without a gating prewarm (lazy startup).
    pub fn mark_ready(&self) {
        self.ready.store(true, Ordering::SeqCst);
    }
}

/// The cell child service.
pub struct QueryService {
    engine: Arc<PartQueryEngine>,
    gate: Arc<DetectionGate>,
    identity_snapshot: Option<crate::identity::IdentitySnapshot>,
    state_dir: PathBuf,
    ioc_store: Option<Arc<dyn ObjectStore>>,
    compiler_sha256: String,
    native_artifact_sha256: String,
    prewarm_hours: u64,
    product_state_maintenance: AtomicBool,
    product_state_started: AtomicBool,
    prewarm_lock: tokio::sync::Mutex<()>,
    readiness: PrewarmReadiness,
    /// NAN-3403: paces arrival prewarm passes (`None`: the kill switch
    /// `NANO_LAKE_PREWARM_THROTTLE=0`, one pass per advance as before).
    incremental_pacer: Option<super::prewarm_pacing::PrewarmPacer>,
    /// NAN-2997: the field inventory of the read schema, keyed by the
    /// schema fingerprint the part-log head binds (a new schema entry, i.e.
    /// new parts that added leaves, changes the key).
    schema_inventory: Mutex<Option<(String, Arc<SchemaInventory>)>>,
    prewarm_wall_ms: AtomicU64,
    /// Exact `broad_npl` answers keyed on their overlapping part set.
    results: super::result_cache::ResultCache,
    jobs: Mutex<BTreeMap<(String, String), JobRecord>>,
    job_state_error: Option<String>,
    inflight: AtomicU64,
    answered: AtomicU64,
    last_progress_ms: AtomicU64,
    /// How long a request waits for a native slot (query: 20 s; detect[T]
    /// running rules: [`super::engine::DETECT_ADMISSION_DEADLINE`]).
    admission_deadline_ms: AtomicU64,
    router: Router<AppState>,
    /// Refreshable exchange credentials (production cells only; NAN-3017).
    credentials: std::sync::OnceLock<Arc<QueryCredentialSwap>>,
    /// The exchanged `job_results` grant (NAN-3042); unset or empty means
    /// durable jobs answer 503 `result_storage_unavailable`.
    job_results: std::sync::OnceLock<Arc<JobResultStore>>,
    /// NAN-3715: an operator SQL probe is running (at most one at a time).
    probe_busy: AtomicBool,
    /// NAN-3715: this process's slow real searches, for probe replay.
    slow_queries: super::slow_queries::SlowQueries,
}

#[derive(Clone)]
struct AppState {
    service: Arc<QueryService>,
}

#[derive(Debug)]
/// NAN-3644: the fourth field is a cold-ceiling refusal's (needed, ceiling,
/// background) bytes.
struct ApiError(StatusCode, String, &'static str, Option<(u64, u64, u64)>);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Every handler error funnels through here: a 5xx is never silent
        // (NAN-2982: a keyword search 500'd with no log line at all).
        if self.0.is_server_error() {
            tracing::error!(status = self.0.as_u16(), reason = self.2, error = %self.1, "query server returned a server error");
        }
        let mut body = json!({"ok": false, "ready": self.2 != "not_ready", "error": self.1, "reason": self.2});
        if self.2 == "warming" {
            body["availability"] = json!({"available": false, "reason": "warming",
                "detail": "Product state is being prepared; retry shortly"});
        }
        if let Some((needed_bytes, ceiling_bytes, background_bytes)) = self.3 {
            body["needed_bytes"] = json!(needed_bytes);
            body["ceiling_bytes"] = json!(ceiling_bytes);
            body["background_ceiling_bytes"] = json!(background_bytes);
            body["retryable"] = json!(false);
        }
        // NAN-3270: the reason rides on a header too, so a transport retry
        // policy can tell a budget refusal from an outage without the body.
        let reason = axum::http::HeaderValue::from_static(self.2);
        (self.0, [(nanosiem_core::lake_http::LAKE_REASON_HEADER, reason)], Json(body)).into_response()
    }
}

impl From<PartQueryError> for ApiError {
    fn from(error: PartQueryError) -> Self {
        if matches!(&error, PartQueryError::Unavailable(text) if text == super::product_state::WARMING) {
            return Self(StatusCode::CONFLICT, super::product_state::WARMING.into(), "warming", None);
        }
        let status = StatusCode::from_u16(error.status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let bytes = match &error {
            PartQueryError::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_bytes } => Some((*needed_bytes, *ceiling_bytes, *background_bytes)),
            _ => None,
        };
        Self(status, error.to_string(), error.reason(), bytes)
    }
}

/// NAN-3272: a native lane-wait timeout anywhere in `error`'s chain. The
/// part paths flatten executor errors into text, so the typed error's own
/// display (not a copy of it) is matched as well.
fn is_lane_wait_timeout(error: &anyhow::Error) -> bool {
    let marker = crate::executor::ExecutorError::LaneWaitTimeout.to_string();
    error.chain().any(|cause| {
        matches!(cause.downcast_ref::<crate::executor::ExecutorError>(), Some(crate::executor::ExecutorError::LaneWaitTimeout))
            || cause.to_string().contains(&marker)
    })
}

/// NAN-3883: a cold object fetch outlived its deadline anywhere in `error`'s
/// chain. Nothing was committed and every object that did arrive stays in
/// the reader cache, so re-sending the same attempt resumes warm. The part
/// paths flatten reader errors into text, so the typed error's display is
/// matched as well.
pub(crate) fn is_cold_fetch_timeout(error: &anyhow::Error) -> bool {
    let marker = crate::reader_object_cache::ReaderCacheError::FetchTimeout.to_string();
    error.chain().any(|cause| {
        matches!(
            cause.downcast_ref::<crate::reader_object_cache::ReaderCacheError>(),
            Some(crate::reader_object_cache::ReaderCacheError::FetchTimeout)
        ) || cause.to_string().contains(&marker)
    })
}

impl From<anyhow::Error> for ApiError {
    fn from(error: anyhow::Error) -> Self {
        if error.to_string() == super::product_state::WARMING {
            return Self(StatusCode::CONFLICT, super::product_state::WARMING.into(), "warming", None);
        }
        if let Some(PartQueryError::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_bytes }) = error.downcast_ref::<PartQueryError>() {
            return PartQueryError::ColdScanTooLarge { needed_bytes: *needed_bytes, ceiling_bytes: *ceiling_bytes, background_bytes: *background_bytes }.into();
        }
        if let Some(crate::reader_object_cache::ReaderCacheError::ScanTooLarge { required_bytes, ceiling_bytes, background_bytes }) = error.downcast_ref::<crate::reader_object_cache::ReaderCacheError>() {
            return PartQueryError::ColdScanTooLarge { needed_bytes: *required_bytes, ceiling_bytes: *ceiling_bytes, background_bytes: *background_bytes }.into();
        }
        // NAN-3272: the read-write lane stayed busy (a product-state build
        // or risk materialization holds it). Typed and retryable, so the
        // durable runner backs off and re-sends the attempt.
        if is_lane_wait_timeout(&error) {
            return Self(StatusCode::SERVICE_UNAVAILABLE, format!("{error:#}"), "lane_wait_timeout", None);
        }
        // NAN-3883: a cold fetch timed out; typed and retryable, so the
        // durable runner backs off and re-sends the attempt (warm by then).
        if is_cold_fetch_timeout(&error) {
            return Self(StatusCode::SERVICE_UNAVAILABLE, format!("{error:#}"), "cold_fetch_timeout", None);
        }
        // A refused storage credential is being refreshed: retryable.
        if is_credential_stale(&error) {
            return Self(StatusCode::SERVICE_UNAVAILABLE, format!("{error:#}"), "credential_refresh", None);
        }
        if error.chain().any(|cause| cause.downcast_ref::<JobResultStorageUnavailable>().is_some()) {
            return Self(StatusCode::SERVICE_UNAVAILABLE, format!("{error:#}"), "result_storage_unavailable", None);
        }
        if super::memory_budget::is_budget_refusal(&format!("{error:#}")) {
            return PartQueryError::MemoryBudget(format!("{error:#}")).into();
        }
        Self(StatusCode::INTERNAL_SERVER_ERROR, format!("{error:#}"), "internal", None)
    }
}

type ApiResult = std::result::Result<Json<Value>, ApiError>;

#[derive(Deserialize)]
struct ProgressParams {
    request_id: String,
}

/// NAN-3644: `GET /v1/query/progress?request_id=` — the cold-read progress of
/// every in-flight request whose id is `request_id` or `{request_id}-…`
/// (Search's chunk and companion requests): uncached bytes read so far, the
/// total the admitted leases will read, and whether one is queued for a heavy
/// cold-read slot. 404 `not_in_flight` when none is. Bytes only: no query
/// text, rows or object names.
async fn query_progress(axum::extract::Query(params): axum::extract::Query<ProgressParams>) -> ApiResult {
    let request_id = params.request_id;
    if request_id.is_empty() || request_id.len() > 128 || request_id.chars().any(char::is_control) {
        return Err(PartQueryError::Invalid("request_id must be 1..=128 printable characters".into()).into());
    }
    match crate::query_timing::cold_progress(&request_id) {
        Some(progress) => Ok(Json(json!({
            "ok": true,
            "request_id": request_id,
            "requests": progress.requests,
            "cold_bytes_read": progress.cold_bytes_read,
            "cold_bytes_total": progress.cold_bytes_total,
            "queued": progress.queued,
        }))),
        None => Err(ApiError(StatusCode::NOT_FOUND, "no request with this id is in flight".into(), "not_in_flight", None)),
    }
}

#[derive(Deserialize)]
#[serde(tag = "route")]
enum QueryRequest {
    #[serde(rename = "broad_npl")]
    BroadNpl(BroadNplRequest),
    #[serde(rename = "explain_npl")]
    ExplainNpl(BroadNplRequest),
    #[serde(rename = "fetch_log")]
    FetchLog(FetchLogRequest),
    #[serde(rename = "field_names")]
    FieldNames { request_id: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResultPageRequest {
    job_id: String,
    tenant_id: String,
    reference: crate::job::ResultArtifactRef,
    page: usize,
}

/// NAN-3809: `/v1/jobs/reuse-check` body.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReuseCheckRequest {
    tenant_id: String,
    job_id: String,
    manifest_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobControlRequest {
    tenant_id: String,
    job_id: String,
    attempt_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityResolveHttpRequest {
    request_id: String,
    tenant_id: String,
    #[serde(default)]
    snapshot_id: Option<String>,
    ip: String,
    reference_time: String,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    deny_source_types: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityBatchHttpItem {
    ip: String,
    reference_time: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityBatchHttpRequest {
    request_id: String,
    tenant_id: String,
    #[serde(default)]
    snapshot_id: Option<String>,
    items: Vec<IdentityBatchHttpItem>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    deny_source_types: BTreeSet<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityEntityBatchHttpItem {
    value: String,
    reference_time: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct IdentityEntityBatchHttpRequest {
    request_id: String,
    tenant_id: String,
    #[serde(default)]
    snapshot_id: Option<String>,
    entity_type: String,
    items: Vec<IdentityEntityBatchHttpItem>,
    #[serde(default, deserialize_with = "nanosiem_core::auth::source_visibility::deserialize_lake_deny_set")]
    deny_source_types: BTreeSet<String>,
}

struct JobRecord {
    status: &'static str,
    cancelled: Arc<AtomicBool>,
    result: Option<crate::job::ResultArtifactRef>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PersistedJobRecord {
    tenant_id: String,
    job_id: String,
    attempt_id: String,
    status: String,
    result: Option<crate::job::ResultArtifactRef>,
}

fn job_records_path(state_dir: &std::path::Path) -> PathBuf {
    state_dir.join("search-jobs.json")
}

fn load_job_records(state_dir: &std::path::Path, tenant_id: &str) -> Result<BTreeMap<(String, String), JobRecord>> {
    let path = job_records_path(state_dir);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(error).with_context(|| format!("read {}", path.display())),
    };
    let persisted: Vec<PersistedJobRecord> = serde_json::from_slice(&bytes).context("decode search job records")?;
    let mut records = BTreeMap::new();
    for record in persisted {
        if record.tenant_id != tenant_id {
            bail!("search job record belongs to another tenant");
        }
        let key = job_key(&JobControlRequest {
            tenant_id: record.tenant_id,
            job_id: record.job_id,
            attempt_id: record.attempt_id,
        }, tenant_id).map_err(|_| anyhow::anyhow!("invalid persisted job binding"))?;
        // A process restart cannot resume an in-flight native statement. Its
        // result is never advertised; the coordinator may start a new attempt.
        let status = match record.status.as_str() {
            "completed" if record.result.is_some() => "completed",
            "cancelled" | "cancel_requested" => "cancelled",
            "running" | "failed" | "completed" => "failed",
            _ => bail!("invalid persisted job status"),
        };
        if records.insert(key, JobRecord {
            status,
            cancelled: Arc::new(AtomicBool::new(status == "cancelled")),
            result: if status == "completed" { record.result } else { None },
        }).is_some() {
            bail!("duplicate persisted job attempt");
        }
    }
    Ok(records)
}

fn persist_job_records(state_dir: &std::path::Path, tenant_id: &str, records: &BTreeMap<(String, String), JobRecord>) -> Result<()> {
    let persisted = records.iter().map(|((job_id, attempt_id), record)| PersistedJobRecord {
        tenant_id: tenant_id.to_string(),
        job_id: job_id.clone(),
        attempt_id: attempt_id.clone(),
        status: record.status.to_string(),
        result: record.result.clone(),
    }).collect::<Vec<_>>();
    let bytes = serde_json::to_vec(&persisted).context("encode search job records")?;
    std::fs::create_dir_all(state_dir).context("create search job state directory")?;
    let mut temp = tempfile::NamedTempFile::new_in(state_dir).context("create search job state temp file")?;
    use std::io::Write;
    temp.write_all(&bytes).context("write search job state")?;
    temp.as_file().sync_all().context("sync search job state")?;
    temp.persist(job_records_path(state_dir)).map_err(|error| error.error).context("commit search job state")?;
    std::fs::File::open(state_dir)?.sync_all().context("sync search job state directory")?;
    Ok(())
}

fn job_key(request: &JobControlRequest, tenant_id: &str) -> std::result::Result<(String, String), ApiError> {
    if request.tenant_id != tenant_id
        || [request.job_id.as_str(), request.attempt_id.as_str()].iter().any(|value| {
            value.is_empty() || value.len() > 128 || value.bytes().all(|byte| byte == b'.')
                || !value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "job control binding is invalid".into(), "invalid_request", None));
    }
    Ok((request.job_id.clone(), request.attempt_id.clone()))
}

fn now_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |elapsed| elapsed.as_millis() as u64)
}

impl QueryService {
    pub fn new(engine: PartQueryEngine, gate: DetectionGate, state_dir: PathBuf, compiler_sha256: String, native_artifact_sha256: String, identity_snapshot: Option<crate::identity::IdentitySnapshot>, prewarm_hours: u64, ioc_store: Option<Arc<dyn ObjectStore>>) -> Arc<Self> {
        let tenant_id = engine.settings().tenant_id.clone();
        let (jobs, job_state_error) = match load_job_records(&state_dir, &tenant_id) {
            Ok(jobs) => (jobs, None),
            Err(error) => {
                tracing::error!(tenant_id = %tenant_id, error = %error, "search job state unavailable; refusing job requests");
                (BTreeMap::new(), Some(error.to_string()))
            }
        };
        let router = Router::new()
            .route("/v1/query", post(query))
            .route("/v1/query/pages", post(query_pages))
            .route("/v1/query/progress", get(query_progress))
            .route("/v1/aggregate/count", post(count))
            .route("/v1/prevalence/lookup", post(prevalence_lookup))
            .route("/v1/prevalence/explorer", post(prevalence_explorer))
            .route("/v1/prevalence/detail", post(prevalence_detail))
            .route("/v1/entity/ranges", post(entity_ranges))
            .route("/v1/risk", post(risk_route))
            .route("/v1/ioc/lookup", post(ioc_lookup))
            .route("/v1/ioc/indicator-sets", post(ioc_indicator_sets))
            .route("/v1/ioc/source-records", post(ioc_source_records))
            .route("/v1/identity/directory/users", post(identity_directory_list))
            .route("/v1/identity/directory/lookup", post(identity_directory_lookup))
            .route("/v1/identity/directory/stats", post(identity_directory_stats))
            .route("/v1/detections/plan", post(detection_plan))
            .route("/v1/detections/commit", post(detection_commit))
            .route("/v1/detections/reset", post(detection_reset))
            .route("/v1/jobs/search", post(job_search))
            .route("/v1/jobs/search/status", post(job_status))
            .route("/v1/jobs/search/cancel", post(job_cancel))
            .route("/v1/jobs/result-page", post(job_page))
            .route("/v1/jobs/reuse-check", post(job_reuse_check))
            .route("/v1/identity/resolve", post(identity_resolve))
            .route("/v1/identity/resolve-batch", post(identity_resolve_batch))
            .route("/v1/identity/resolve-entity-batch", post(identity_resolve_entity_batch))
            .route("/v1/status", get(status))
            .route("/v1/schema/manifest", get(schema_manifest))
            .route("/v1/ingest/refusals", post(ingest_refusals))
            // NAN-3715: operator-only, never through the search service.
            .route("/v1/debug/sql-probe", post(sql_probe))
            .route("/v1/debug/slow-queries", get(slow_queries))
            // NAN-3406: a debug request's per-request switch overrides.
            .layer(axum::middleware::from_fn(crate::perf_overrides::middleware))
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024));
        Arc::new(Self {
            engine: Arc::new(engine),
            gate: Arc::new(gate),
            identity_snapshot,
            state_dir,
            ioc_store,
            compiler_sha256,
            native_artifact_sha256,
            prewarm_hours,
            product_state_maintenance: AtomicBool::new(false),
            product_state_started: AtomicBool::new(false),
            prewarm_lock: tokio::sync::Mutex::new(()),
            readiness: PrewarmReadiness::default(),
            incremental_pacer: super::prewarm_pacing::throttle_enabled()
                .then(|| super::prewarm_pacing::PrewarmPacer::new(super::prewarm_pacing::min_interval())),
            schema_inventory: Mutex::new(None),
            prewarm_wall_ms: AtomicU64::new(0),
            results: Default::default(),
            jobs: Mutex::new(jobs),
            job_state_error,
            inflight: AtomicU64::new(0),
            answered: AtomicU64::new(0),
            last_progress_ms: AtomicU64::new(0),
            admission_deadline_ms: AtomicU64::new(super::engine::ADMISSION_DEADLINE.as_millis() as u64),
            router,
            credentials: std::sync::OnceLock::new(),
            job_results: std::sync::OnceLock::new(),
            probe_busy: AtomicBool::new(false),
            slow_queries: Default::default(),
        })
    }

    /// Install the job-result store (once), shared with the refresh swap.
    pub fn attach_job_results(&self, store: Arc<JobResultStore>) -> Result<()> {
        if store.tenant_id() != self.engine.settings().tenant_id {
            bail!("job-result store belongs to another tenant");
        }
        self.job_results.set(store).map_err(|_| anyhow::anyhow!("job-result store is already attached"))
    }

    /// The granted job-result store, or the typed 503.
    fn job_results(&self) -> std::result::Result<Arc<JobResultStore>, ApiError> {
        self.job_results.get().filter(|store| store.is_granted()).cloned()
            .ok_or_else(|| ApiError::from(anyhow::Error::new(JobResultStorageUnavailable)))
    }

    /// Install the refresh target for `TenantService::secrets` (once).
    pub fn attach_credentials(&self, credentials: Arc<QueryCredentialSwap>) -> Result<()> {
        self.credentials.set(credentials).map_err(|_| anyhow::anyhow!("query credentials are already attached"))
    }

    pub fn engine(&self) -> &PartQueryEngine {
        &self.engine
    }

    /// NAN-3715: this process's slow real searches (`GET /v1/debug/slow-queries`).
    pub fn slow_queries(&self) -> &super::slow_queries::SlowQueries {
        &self.slow_queries
    }

    /// Catch up with the log (request path) and feed the detection gate.
    /// NAN-3392: while [`Self::spawn_log_refresher`] runs, a view younger
    /// than the 1 s coalesce window is used as is (no GET on the request
    /// path); see `engine::request_may_skip_catch_up` for the bound.
    pub async fn refresh(self: &Arc<Self>) -> std::result::Result<(), PartQueryError> {
        self.engine.refresh_for_request().await?;
        self.observe_advances();
        Ok(())
    }

    /// Catch up with the log now (notify, background refresher).
    pub async fn refresh_now(self: &Arc<Self>) -> std::result::Result<(), PartQueryError> {
        self.engine.refresh().await?;
        self.observe_advances();
        Ok(())
    }

    /// Keep the part-log view caught up at the active refresh cadence,
    /// backing off empty passes. Arrival notifications still refresh at
    /// once; requests independently enforce the one-second freshness bound.
    pub fn spawn_log_refresher(self: Arc<Self>) {
        self.engine.enable_background_log_refresh();
        let service = Arc::downgrade(&self);
        let last_head = Arc::new(AtomicU64::new(0));
        tokio::spawn(super::engine::run_periodic(service, super::engine::BACKGROUND_REFRESH_PERIOD, move |service: Arc<Self>| {
            let last_head = last_head.clone();
            async move {
                service.refresh_now().await?;
                let head = service.engine.latest_head().await.map_or(0, |(seq, _)| seq);
                // Include advances from arrival notifications or requests
                // between background passes when restoring the active cadence.
                Ok(last_head.swap(head, Ordering::Relaxed) != head)
            }
        }));
    }

    fn observe_advances(self: &Arc<Self>) {
        let advances = self.engine.take_advances();
        let has_new_parts = !advances.is_empty();
        for (head, advance) in advances {
            self.gate.observe(head, &advance);
        }
        if has_new_parts {
            self.clone().spawn_incremental_prewarm();
        }
    }

    fn require_ready(&self) -> std::result::Result<(), ApiError> {
        if self.readiness.is_ready() { Ok(()) }
        else { Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "query prewarm is incomplete".into(), "not_ready", None)) }
    }

    fn require_job_state(&self) -> std::result::Result<(), ApiError> {
        if self.job_state_error.is_some() {
            Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "search job state is unavailable".into(), "job_state_unavailable", None))
        } else {
            Ok(())
        }
    }

    /// Enable only in query[T], never the independently budgeted detect role.
    /// NAN-3148: product state is published into this process's state dir
    /// by its own low-priority publisher; requests never build it.
    pub fn enable_product_state_maintenance(&self) {
        match self.engine.set_product_state(super::product_publish::Published::in_process(self.state_dir.clone())) {
            Ok(()) => self.product_state_maintenance.store(true, Ordering::Relaxed),
            Err(error) => tracing::warn!(%error, "product state mode already set; in-process publisher not enabled"),
        }
    }

    /// NAN-3148: query[T] beside a product[T]: read product state published
    /// in `product_dir`, never build it here (no worker, no queue). Product
    /// routes answer 409 `product_state_warming` until every moving window
    /// has been published once; after that the newest snapshot is served.
    pub fn enable_product_state_consumer(&self, product_dir: PathBuf) -> Result<()> {
        // NAN-3791: fail loud (not closed) when the inbox is unwritable:
        // published snapshots still serve; demands cannot be filed.
        let _ = super::product_publish::probe_demand_inbox(&product_dir);
        self.engine.set_product_state(super::product_publish::Published::consumer(product_dir))
    }

    /// NAN-3148: product[T]: this engine builds into `product_dir` and
    /// publishes there (see [`super::product_publish::Publisher`]). NAN-3799:
    /// the supervisor's published dir, which may outlive the pod.
    pub fn enable_product_state_publisher(&self, product_dir: PathBuf) -> Result<()> {
        self.engine.set_product_state(super::product_publish::Published::publisher(product_dir))
    }

    /// The shared engine (product[T]'s publisher drives it directly).
    pub fn engine_arc(&self) -> Arc<PartQueryEngine> {
        self.engine.clone()
    }

    /// Startup prewarm: prove every already-live cell-local data file
    /// (owner-denial proofs, in-place SHA-256) before the process reports
    /// ready. Optional remote residency stays within the cache budget.
    pub fn spawn_prewarm(self: Arc<Self>) {
        if self.engine.fetcher().hot_settings.is_some() {
            self.start_ready_with_background_prewarm();
        } else {
            self.spawn_prewarm_with(true);
        }
    }

    /// product[T] (NAN-3148): serves no search, so no owner-proof prewarm.
    pub fn mark_ready_without_prewarm(&self) {
        self.readiness.mark_ready();
    }

    /// Lazy startup (NAN-2989, the default): ready as soon as the engine is
    /// open; the prewarm of already-live parts runs in the background and a
    /// query over a part it has not reached proves that part's own files.
    pub fn start_ready_with_background_prewarm(self: Arc<Self>) {
        self.readiness.mark_ready();
        if let Some(settings) = &self.engine.fetcher().hot_settings {
            let service = self.clone();
            // NAN-3164: was a fixed 60 s. With the cell's warm gate no user
            // traffic reaches this pod before the recent window is resident,
            // so waiting only delays the roll; a short pause lets the engine
            // settle.
            let delay = settings.schedule.start_delay;
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                loop {
                    if let Err(error) = service.engine.hydrate_hot_window(&service.inflight).await {
                        tracing::warn!(%error, "local hot-window hydration deferred");
                    }
                    // NAN-3690: the pre-latch rediscovery runs at once.
                    if service.engine.fetcher().take_hot_rerun() {
                        continue;
                    }
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
            });
        }
        self.spawn_incremental_prewarm();
    }

    /// Prove files of parts that arrived since, in the background. Readiness
    /// is NOT withdrawn (NAN-2984): a query over a part the prewarm has not
    /// reached yet proves its own few files (`scalar_plan` →
    /// `owner_proofs_for`, and anything unproven keeps every mask), so
    /// results are unchanged. Withdrawing readiness on every new part turned
    /// each L0 flush (and merge) into a 503 window that search retried
    /// through, adding latency right when fresh data arrived.
    ///
    /// NAN-3403: paced. Since the NAN-3392 background refresher every flush
    /// and merge commit was its own advance and its own full pass (~5/min);
    /// now at most one pass per `NANO_LAKE_PREWARM_MIN_INTERVAL_SECONDS`
    /// (default 60 s) runs, and arrivals inside the interval join one
    /// trailing pass.
    pub fn spawn_incremental_prewarm(self: Arc<Self>) {
        let Some(pacer) = &self.incremental_pacer else {
            self.spawn_prewarm_with(false);
            return;
        };
        let Some(delay) = pacer.request(Instant::now()) else { return };
        tokio::spawn(async move {
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }
            if let Some(pacer) = &self.incremental_pacer {
                pacer.start(Instant::now());
            }
            self.spawn_prewarm_with(false);
        });
    }

    /// `gate_readiness`: report not-ready until this (or a newer) prewarm
    /// completes. Single-flight in the engine; a newer request supersedes.
    fn spawn_prewarm_with(self: Arc<Self>, gate_readiness: bool) {
        let ticket = self.readiness.request(gate_readiness);
        tokio::spawn(async move {
            let _guard = self.prewarm_lock.lock().await;
            let started = Instant::now();
            let tenant = self.engine.settings().tenant_id.clone();
            let engine = &self.engine;
            let mut retry = Duration::from_secs(1);
            loop {
                if !self.readiness.is_current(ticket) {
                    break;
                }
                match crate::enrichment_read::execute(
                    || crate::enrichment_read::resolve(&tenant),
                    async {
                        // NAN-3720: a pass no readiness waits on is
                        // background work and yields to searches.
                        let warmed = if gate_readiness {
                            engine.prewarm_owner_proofs(self.prewarm_hours).await?
                        } else {
                            engine.prewarm_owner_proofs_in_background(self.prewarm_hours).await?
                        };
                        Ok::<_, PartQueryError>(warmed)
                    },
                ).await {
                    Ok(Ok(_)) => {
                        self.prewarm_wall_ms.store(started.elapsed().as_millis() as u64, Ordering::Relaxed);
                        self.readiness.complete(ticket);
                        self.clone().spawn_product_state();
                        // Even explicitly gated owner-proof startup leaves
                        // optional evidence warming until searches are ready.
                        if gate_readiness {
                            if engine.prewarm_selection_evidence().await.is_err() {
                                tracing::warn!("optional selection evidence prewarm failed; queries resolve misses");
                            }
                        }
                        if engine.evidence_prewarm_yielded() {
                            tokio::time::sleep(super::prewarm_pacing::min_interval().max(Duration::from_secs(1))).await;
                            continue;
                        }
                        break;
                    }
                    Ok(Err(error)) => tracing::warn!(error = %error, "query prewarm failed; retrying before readiness"),
                    Err(_) => tracing::warn!("query prewarm lacks enrichment read authority; retrying before readiness"),
                }
                tokio::time::sleep(retry).await;
                retry = (retry * 2).min(Duration::from_secs(30));
            }
        });
    }

    /// Product failures never withdraw query readiness. NAN-3148: without a
    /// product role, ONE in-process publisher (the role's code, same cadence
    /// and skip rules) builds on a dedicated nice-19 thread; requests only
    /// read what it published and file demands for it.
    fn spawn_product_state(self: Arc<Self>) {
        if !self.product_state_maintenance.load(Ordering::Relaxed) { return; }
        if self.product_state_started.swap(true, Ordering::Relaxed) { return; }
        let status = Arc::new(super::product_publish::PublisherStatus::default());
        let started = super::product_publish::Publisher::new(self.engine.clone(), status)
            .and_then(|publisher| Ok(super::product_publish::spawn_low_priority(publisher)?));
        if let Err(error) = started {
            self.product_state_started.store(false, Ordering::Relaxed);
            tracing::warn!(error = %format!("{error:#}"), "product state publisher did not start; retrying with the next prewarm");
        }
    }

    /// NAN-3271: gate on the requested moving window only. A published 24h
    /// window answers while a longer one is still warming (or failing).
    fn require_product_state(&self, window: &str) -> std::result::Result<(), ApiError> {
        // An unknown window is a bad request, never "warming".
        partials::window_us(window)?;
        if !super::product_publish::ready_for(&self.engine, window) {
            return Err(ApiError(StatusCode::CONFLICT, super::product_state::WARMING.into(), "warming", None));
        }
        Ok(())
    }

    /// Serve one HTTP/1.1 connection (one routed request).
    pub async fn serve_stream(self: Arc<Self>, stream: tokio::net::UnixStream) {
        let router = self.router.clone().with_state(AppState { service: self.clone() });
        let service = hyper_util::service::TowerToHyperService::new(router);
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
            .await;
    }

    /// A native-work slot for one request (see [`PartQueryEngine::admit`]).
    /// NAN-3058: keep the identity observation index of the lookback window
    /// complete by deriving the parts that predate the flag (or overflowed
    /// ingest's cap) into this role's state, a few parts per interval
    /// ([`super::identity::backfill_once`]; bounded and resumable). Runs only
    /// when the cell turned `identity_observations` on.
    ///
    /// NAN-3077: lowest priority. A pass starts only when every query slot is
    /// free (never queued, so it never delays a search or a detect claim),
    /// holds the slot only for the coverage read, derives one part on a
    /// nice-19 thread, and polls again soon while parts remain. Parts it
    /// cannot index are marked and never retried; derived files in the
    /// state dir are skipped, so a restart resumes where it stopped.
    ///
    /// NAN-3399: each pass then rebuilds the merged identity index when due
    /// ([`super::identity_merged::merge_once`]).
    pub fn spawn_identity_backfill(self: Arc<Self>) {
        tokio::spawn(async move {
            let mut wait = super::identity::BACKFILL_BUSY_POLL;
            loop {
                tokio::time::sleep(wait).await;
                let Some(slot) = self.engine.try_admit_idle() else {
                    wait = super::identity::BACKFILL_BUSY_POLL;
                    continue;
                };
                let pass = async {
                    self.engine.refresh().await?;
                    super::identity::backfill_once(&self.engine, &self.state_dir, chrono::Utc::now().timestamp_micros(),
                        super::identity::BACKFILL_PARTS_PER_TICK, Some(slot)).await
                };
                wait = match pass.await {
                    Ok(report) => {
                        if report.derived > 0 || report.removed > 0 || report.unindexable > 0 {
                            tracing::info!(derived = report.derived, remaining = report.remaining, removed = report.removed,
                                unindexable = report.unindexable, "identity observation backfill pass");
                        }
                        // NAN-3399: fold the window's sources into the merged
                        // index once enough are outside it (idle slot only).
                        if let Err(error) = super::identity_merged::merge_once(&self.engine, &self.state_dir,
                            chrono::Utc::now().timestamp_micros()).await {
                            tracing::warn!(error = %error, "identity observation index merge failed; lookups read the sources directly");
                        }
                        if report.remaining > 0 { super::identity::BACKFILL_BUSY_POLL } else { super::identity::BACKFILL_INTERVAL }
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "identity observation backfill pass failed; retrying next interval");
                        super::identity::BACKFILL_INTERVAL
                    }
                };
            }
        });
    }

    async fn admit(&self) -> std::result::Result<super::engine::AdmissionSlot, ApiError> {
        Ok(self.engine.admit(self.admission_deadline()).await?)
    }

    /// A durable job's own admission (NAN-3077; see `PartQueryEngine::admit_job`).
    async fn admit_job(&self) -> std::result::Result<super::engine::AdmissionSlot, ApiError> {
        Ok(self.engine.admit_job(self.admission_deadline()).await?)
    }

    /// [`Self::admit`] for a request of `class` (NAN-3077).
    async fn admit_class(&self, class: super::engine::RequestClass) -> std::result::Result<super::engine::AdmissionSlot, ApiError> {
        Ok(self.engine.admit_class(class, self.admission_deadline()).await?)
    }

    /// See [`super::engine::DETECT_ADMISSION_DEADLINE`].
    pub fn set_admission_deadline(&self, deadline: Duration) {
        self.admission_deadline_ms.store(deadline.as_millis() as u64, Ordering::Relaxed);
    }

    pub fn admission_deadline(&self) -> Duration {
        Duration::from_millis(self.admission_deadline_ms.load(Ordering::Relaxed))
    }

    fn begin(&self) -> Inflight<'_> {
        self.inflight.fetch_add(1, Ordering::SeqCst);
        Inflight(self)
    }
}

struct Inflight<'a>(&'a QueryService);

/// [`Inflight`] for work that outlives its handler (a streamed response).
struct OwnedInflight(Arc<QueryService>);

impl OwnedInflight {
    fn begin(service: &Arc<QueryService>) -> Self {
        service.inflight.fetch_add(1, Ordering::SeqCst);
        Self(service.clone())
    }
}

impl Drop for OwnedInflight {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
        self.0.answered.fetch_add(1, Ordering::Relaxed);
        self.0.last_progress_ms.store(now_ms(), Ordering::Relaxed);
    }
}

impl Drop for Inflight<'_> {
    fn drop(&mut self) {
        self.0.inflight.fetch_sub(1, Ordering::SeqCst);
        self.0.answered.fetch_add(1, Ordering::Relaxed);
        self.0.last_progress_ms.store(now_ms(), Ordering::Relaxed);
    }
}

async fn query(State(state): State<AppState>, headers: axum::http::HeaderMap, Json(request): Json<QueryRequest>) -> ApiResult {
    let service = &state.service;
    service.require_ready()?;
    let _inflight = service.begin();
    // NAN-3077: event detail takes the point lane, histogram companions the
    // companion gate; every interactive statement runs under the
    // interactive execution deadline (`query_timing::measure`, 55 s), so a
    // request the gateway already gave up on cannot hold a lane for 300 s.
    let (request_id, fetch_log) = match &request {
        QueryRequest::BroadNpl(request) | QueryRequest::ExplainNpl(request) => (request.request_id.clone(), false),
        QueryRequest::FetchLog(request) => (request.request_id.clone(), true),
        QueryRequest::FieldNames { request_id } => (request_id.clone(), false),
    };
    let class = super::engine::RequestClass::of(&request_id, fetch_log);
    // NAN-3715: a slow real search is kept for probe replay (never rows).
    let captured = match &request {
        QueryRequest::BroadNpl(request) => Some(request.clone()),
        _ => None,
    };
    let started = Instant::now();
    let phases = Arc::new(Mutex::new(Value::Null));
    let _slot = service.admit_class(class).await?;
    let engine = service.engine();
    // NAN-3141: every route's future is boxed, and so is the measured work
    // (awaited directly or through `debug::collect`): inline, they made this
    // handler's future ~1 MiB and its poll frame overflow the worker stack.
    let (phases_out, captured_wanted) = (phases.clone(), captured.is_some());
    let work = Box::pin(crate::query_timing::measure(&request_id, async move {
        let answer = Box::pin(answer_query(service, engine, request)).await;
        if captured_wanted && started.elapsed().as_secs_f64() * 1000.0 >= super::slow_queries::SLOW_QUERY_MS {
            *phases_out.lock().unwrap_or_else(|e| e.into_inner()) = super::sql_probe::phases_json();
        }
        answer
    }));
    let outcome = if headers.get("x-nano-search-debug").is_some_and(|value| value == "1") {
        super::debug::collect(work).await
    } else { work.await };
    if let Some(request) = &captured {
        let phases = std::mem::take(&mut *phases.lock().unwrap_or_else(|e| e.into_inner()));
        service.slow_queries.observe(super::slow_queries::Observed::broad("query", request,
            started.elapsed().as_secs_f64() * 1000.0, outcome.as_ref().err().map(|error| error.2), outcome.as_ref().ok(), phases));
    }
    let mut answer = outcome?;
    crate::perf_overrides::annotate(&mut answer);
    Ok(Json(answer))
}

/// `/v1/query`'s measured work, by route.
async fn answer_query(service: &Arc<QueryService>, engine: &PartQueryEngine, request: QueryRequest) -> std::result::Result<Value, ApiError> {
    service.refresh().await?;
    service.require_ready()?;
    Ok(match request {
        QueryRequest::BroadNpl(request) if request.dataset == "risk" =>
            Box::pin(risk::broad_npl(engine, &service.state_dir, &request)).await?,
        QueryRequest::BroadNpl(request) => Box::pin(cached_broad_npl(service, &request)).await?,
        QueryRequest::ExplainNpl(request) => Box::pin(engine.explain_npl(&request)).await?,
        QueryRequest::FetchLog(request) => Box::pin(engine.fetch_log(&request)).await?,
        QueryRequest::FieldNames { request_id } => Box::pin(engine.field_names(&request_id)).await?,
    })
}

/// NAN-3715: releases [`QueryService::probe_busy`].
struct ProbeSlot<'a>(&'a AtomicBool);

impl Drop for ProbeSlot<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// NAN-3715: `POST /v1/debug/sql-probe` (see [`super::sql_probe`]). Only a
/// request the cell router stamped as operator-admitted reaches the engine;
/// at most one runs at a time (409 when busy), under the engine's admission,
/// caps and deadline; every call is audit-logged by hash.
async fn sql_probe(State(state): State<AppState>, headers: axum::http::HeaderMap, Json(request): Json<super::sql_probe::ProbeRequest>) -> ApiResult {
    use super::sql_probe as probe;
    let started = Instant::now();
    let service = &state.service;
    if headers.get(probe::OPERATOR_HEADER).is_none_or(|value| value != nanosiem_lake_cell::router::OPERATOR_DEBUG_ADMITTED) {
        probe::audit(&request, None, Err(&PartQueryError::Invalid("not operator-admitted".into())), 0.0);
        return Err(ApiError(StatusCode::FORBIDDEN, "the SQL probe is operator-only (cell router, full or cluster query token)".into(), "forbidden", None));
    }
    let prepared = match probe::prepare(&request, &service.engine().settings().tenant_id, &probe::Caps::of(service.engine())) {
        Ok(prepared) => prepared,
        Err(error) => {
            probe::audit(&request, None, Err(&error), 0.0);
            return Err(error.into());
        }
    };
    if let Err(error) = service.require_ready() {
        probe::audit(&request, Some(&prepared), Err(&PartQueryError::Unavailable("not ready".into())), 0.0);
        return Err(error);
    }
    if service.probe_busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        probe::audit(&request, Some(&prepared), Err(&PartQueryError::ConcurrencyBudget("probe_busy".into())), 0.0);
        return Err(ApiError(StatusCode::CONFLICT, "another SQL probe is running on this process".into(), "probe_busy", None));
    }
    let _probe_slot = ProbeSlot(&service.probe_busy);
    let _inflight = service.begin();
    let _slot = service.admit_class(super::engine::RequestClass::Primary).await?;
    let scope = Some(Arc::new(prepared.scope.clone()));
    let work = Box::pin(crate::perf_overrides::scoped(scope, crate::query_timing::measure(&prepared.request_id, async {
        service.refresh().await?;
        probe::run(service.engine(), &request, &prepared).await
    })));
    let outcome = match tokio::time::timeout(probe::PROBE_WALL_LIMIT, work).await {
        Ok(outcome) => outcome,
        Err(_) => Err(PartQueryError::Unavailable(format!("the probe exceeded its {} s wall limit", probe::PROBE_WALL_LIMIT.as_secs()))),
    };
    probe::audit(&request, Some(&prepared), outcome.as_ref(), started.elapsed().as_secs_f64() * 1000.0);
    Ok(Json(outcome?))
}

#[derive(Deserialize)]
struct SlowQueriesParams {
    #[serde(default)]
    min_ms: Option<f64>,
    #[serde(default)]
    limit: Option<usize>,
}

/// NAN-3715: `GET /v1/debug/slow-queries` — this process's slow real
/// searches (newest first, no row data), operator-admitted like the probe.
async fn slow_queries(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Query(params): axum::extract::Query<SlowQueriesParams>,
) -> ApiResult {
    if headers.get(super::sql_probe::OPERATOR_HEADER).is_none_or(|value| value != nanosiem_lake_cell::router::OPERATOR_DEBUG_ADMITTED) {
        tracing::info!(target: "nano_audit", event = "lake_slow_queries", status = "forbidden", "lake slow-query read refused");
        return Err(ApiError(StatusCode::FORBIDDEN, "slow-query capture is operator-only (cell router, full or cluster query token)".into(), "forbidden", None));
    }
    let limit = params.limit.unwrap_or(super::slow_queries::RING_ENTRIES).min(super::slow_queries::RING_ENTRIES);
    let answer = state.service.slow_queries.snapshot(params.min_ms.unwrap_or(0.0), limit);
    tracing::info!(target: "nano_audit", event = "lake_slow_queries", status = "ok",
        entries = answer["entries"].as_array().map_or(0, Vec::len), "lake slow-query read");
    Ok(Json(answer))
}

/// Largest page a streamed read may ask for.
const MAX_STREAM_PAGE_ROWS: usize = 50_000;
/// How long a streamed read waits for its reader to take the next page
/// before it gives the lane back (a stalled or vanished client).
const STREAM_READER_IDLE: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
struct PagesParams {
    page_rows: usize,
}

enum StreamMessage {
    Line(bytes::Bytes),
    Failed(PartQueryError),
}

fn ndjson_line(value: &Value) -> bytes::Bytes {
    let mut line = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
    line.push(b'\n');
    bytes::Bytes::from(line)
}

/// NAN-3060: `POST /v1/query/pages?page_rows=N` — a raw-event `broad_npl`
/// read executed ONCE and answered as NDJSON pages (see
/// [`PartQueryEngine::broad_npl_pages`]):
///
/// 1. the `broad_npl` envelope, carrying the first page's rows (plus
///    `"stream": {"page_rows": N}`);
/// 2. `{"rows": [...]}` per further page;
/// 3. `{"done": true, "delivered", "has_more", "pages", "result_statements", …}`,
///    or `{"ok": false, "error", "reason", "status"}` if the read failed after
///    its first page.
///
/// The request holds one admission slot (and one lane) for its whole
/// duration, like any query. Anything that fails before the first page is
/// an ordinary error status (429/503 `query_budget_exhausted`, 413, 422…),
/// so the caller's budget escalation is unchanged. A reader that stops
/// reading for [`STREAM_READER_IDLE`] or disconnects cancels the statement
/// and frees the slot.
async fn query_pages(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<PagesParams>,
    Json(mut body): Json<Value>,
) -> std::result::Result<Response, ApiError> {
    let service = state.service.clone();
    service.require_ready()?;
    // The same body as `/v1/query`'s `broad_npl` (its `route` tag included).
    if let Some(object) = body.as_object_mut() {
        if object.get("route").is_some_and(|route| route != "broad_npl") {
            return Err(PartQueryError::Invalid("a streamed read serves route broad_npl".into()).into());
        }
        object.remove("route");
    }
    let request: BroadNplRequest = serde_json::from_value(body)
        .map_err(|error| PartQueryError::Invalid(format!("streamed read request is invalid: {error}")))?;
    if params.page_rows == 0 || params.page_rows > MAX_STREAM_PAGE_ROWS {
        return Err(PartQueryError::Invalid(format!("page_rows must be between 1 and {MAX_STREAM_PAGE_ROWS}")).into());
    }
    if !service.engine().executor().supports_streaming() {
        return Err(ApiError(StatusCode::NOT_IMPLEMENTED, "this chDB artifact cannot stream results".into(), "stream_unsupported", None));
    }
    let inflight = OwnedInflight::begin(&service);
    let started = Instant::now();
    let slot = service.admit().await?;
    service.refresh().await?;
    service.require_ready()?;
    let (sender, mut receiver) = tokio::sync::mpsc::channel::<StreamMessage>(1);
    // NAN-3406: the read runs on its own task; it keeps the request's
    // per-request switch overrides.
    let perf = crate::perf_overrides::capture();
    tokio::spawn(crate::perf_overrides::scoped(perf, async move {
        let (_slot, _inflight) = (slot, inflight);
        let lines = sender.clone();
        let outcome = service
            .engine()
            .broad_npl_pages(&request, params.page_rows, move |line| {
                let lines = lines.clone();
                async move {
                    let value = match line {
                        super::engine::PagedLine::Envelope(mut envelope) => {
                            crate::perf_overrides::annotate(&mut envelope);
                            envelope
                        }
                        super::engine::PagedLine::Page(rows) => json!({"rows": rows}),
                    };
                    matches!(
                        tokio::time::timeout(STREAM_READER_IDLE, lines.send(StreamMessage::Line(ndjson_line(&value)))).await,
                        Ok(Ok(()))
                    )
                }
            })
            .await;
        // NAN-3715: a slow streamed read is kept for probe replay too.
        let summary = outcome.as_ref().ok().map(|outcome| json!({"result": {
            "result_rows": outcome.delivered, "storage_rows": outcome.storage_rows, "storage_bytes": outcome.storage_bytes}}));
        service.slow_queries.observe(super::slow_queries::Observed::broad("query_pages", &request,
            started.elapsed().as_secs_f64() * 1000.0, outcome.as_ref().err().map(PartQueryError::reason),
            summary.as_ref(), Value::Null));
        let last = match outcome {
            Ok(outcome) if outcome.stopped => return,
            Ok(outcome) => StreamMessage::Line(ndjson_line(&json!({
                "done": true,
                "delivered": outcome.delivered,
                "pages": outcome.pages,
                "has_more": outcome.has_more,
                "result_statements": outcome.result_statements,
                "newest_first_event_rows": outcome.newest_first_event_rows,
                "engine_seconds": outcome.engine_seconds,
                "storage_rows": outcome.storage_rows,
                "storage_bytes": outcome.storage_bytes,
            }))),
            Err(error) => StreamMessage::Failed(error),
        };
        let _ = tokio::time::timeout(STREAM_READER_IDLE, sender.send(last)).await;
    }));
    // The first message decides the status: a read that fails before its
    // first page is an ordinary error response.
    let first = match receiver.recv().await {
        Some(StreamMessage::Line(line)) => line,
        Some(StreamMessage::Failed(error)) => return Err(error.into()),
        None => return Err(PartQueryError::Internal("streamed read ended without a first page".into()).into()),
    };
    let rest = futures::stream::unfold(receiver, |mut receiver| async move {
        let line = match receiver.recv().await? {
            StreamMessage::Line(line) => line,
            StreamMessage::Failed(error) => {
                tracing::warn!(status = error.status(), reason = error.reason(), error = %error, "streamed read failed after its first page");
                let status = error.status();
                let api = ApiError::from(error);
                let mut body = json!({"ok": false, "error": api.1, "reason": api.2, "status": status});
                if let Some((needed_bytes, ceiling_bytes, background_bytes)) = api.3 {
                    body["needed_bytes"] = json!(needed_bytes);
                    body["ceiling_bytes"] = json!(ceiling_bytes);
                    body["background_ceiling_bytes"] = json!(background_bytes);
                    body["retryable"] = json!(false);
                }
                ndjson_line(&body)
            }
        };
        Some((Ok::<_, std::convert::Infallible>(line), receiver))
    });
    let body = futures::StreamExt::chain(futures::stream::once(async move { Ok::<_, std::convert::Infallible>(first) }), rest);
    Ok((
        [(axum::http::header::CONTENT_TYPE, "application/x-ndjson")],
        axum::body::Body::from_stream(body),
    )
        .into_response())
}

/// `broad_npl` through the exact result cache (see [`super::result_cache`]).
async fn cached_broad_npl(service: &QueryService, request: &BroadNplRequest) -> Result<Value, PartQueryError> {
    super::engine::validate_broad_npl(request, &service.engine().settings().tenant_id)?;
    service.engine().pinned(cached_broad_npl_pinned(service, request)).await?
}

async fn cached_broad_npl_pinned(service: &QueryService, request: &BroadNplRequest) -> Result<Value, PartQueryError> {
    let engine = service.engine();
    let window = super::engine::rfc3339_us(&request.start).and_then(|from| Ok((from, super::engine::rfc3339_us(&request.end)?)));
    let Ok((from_us, to_us)) = window else { return engine.broad_npl(request).await };
    if super::debug::enabled() || !super::result_cache::cacheable(request) {
        return engine.broad_npl(request).await;
    }
    let (parts, _, _, _) = engine.snapshot(from_us, to_us).await?;
    let (_, schema) = engine.head_and_schema_fingerprint().await;
    let authority = crate::enrichment_read::resolve(&request.tenant_id).await.cache_identity();
    let config = format!("{}\0{}\0{:?}", service.compiler_sha256, service.native_artifact_sha256, engine.settings());
    let head = engine.head().await;
    let key = super::result_cache::key(request, &parts, schema.as_deref(), &authority, &config);
    if let Some(hit) = service.results.get(&key, &request.request_id) {
        return Ok(hit);
    }
    let answer = engine.broad_npl(request).await?;
    // A vanished-part retry can use a newer scope. Never store that answer
    // under the original part set, or across an enrichment-authority change.
    if head == engine.latest_head().await && authority == crate::enrichment_read::resolve(&request.tenant_id).await.cache_identity() {
        // NAN-3809: a settled, complete answer outlives the 60 s tier, so a
        // pasted absolute-range URL is answered without a second scan.
        if super::result_cache::settled_answer(request, to_us, &answer, chrono::Utc::now()) {
            service.results.insert_settled(key, &answer);
        } else {
            service.results.insert(key, &answer);
        }
    }
    Ok(answer)
}

async fn count(State(state): State<AppState>, Json(request): Json<crate::count_aggregate::CountAggregateRequest>) -> ApiResult {
    state.service.require_ready()?;
    let _inflight = state.service.begin();
    let class = super::engine::RequestClass::of(&request.request_id, false);
    let _slot = state.service.admit_class(class).await?;
    let answer = crate::query_timing::measure(&request.request_id, async {
        state.service.refresh().await?;
        state.service.require_ready()?;
        Ok::<_, ApiError>(partials::count_aggregate(state.service.engine(), &request).await?)
    })
    .await?;
    let mut answer = answer;
    crate::perf_overrides::annotate(&mut answer);
    Ok(Json(answer))
}

async fn prevalence_lookup(State(state): State<AppState>, Json(request): Json<partials::PrevalenceLookupRequest>) -> ApiResult {
    if request.tenant_id != state.service.engine().settings().tenant_id {
        return Err(PartQueryError::Invalid("request tenant is not this process's tenant".into()).into());
    }
    state.service.require_product_state(&request.window)?;
    let _inflight = state.service.begin();
    let _slot = state.service.admit().await?;
    state.service.refresh().await?;
    // Prewarm proves data-file enrichment ownership for broad search. This
    // route reads signed prevalence partials and exact boundary rows through
    // the verified fetcher, so a fresh L0 must remain queryable while broad
    // search's background prewarm catches up.
    let answer = crate::query_timing::measure("prevalence_lookup", async { Ok::<_, ApiError>(partials::prevalence_lookup(state.service.engine(), &request).await?) }).await?;
    Ok(Json(answer))
}

async fn prevalence_detail(State(state): State<AppState>, Json(request): Json<partials::PrevalenceDetailRequest>) -> ApiResult {
    if request.tenant_id != state.service.engine().settings().tenant_id {
        return Err(PartQueryError::Invalid("request tenant is not this process's tenant".into()).into());
    }
    // NAN-3760: detail is demand-built independently of explorer windows.
    // Gate only on a valid window, so an explorer build cannot prevent demand.
    partials::window_us(&request.window)?;
    let _inflight = state.service.begin();
    // A consumer reads a small published JSON file and enqueues on a miss;
    // it needs no native admission slot behind interactive searches.
    let _slot = if super::product_publish::is_consumer(state.service.engine()) { None } else { Some(state.service.admit().await?) };
    state.service.refresh().await?;
    Ok(Json(partials::prevalence_detail(state.service.engine(), &request).await?))
}

async fn prevalence_explorer(State(state): State<AppState>, Json(request): Json<partials::PrevalenceExplorerRequest>) -> ApiResult {
    if request.tenant_id != state.service.engine().settings().tenant_id {
        return Err(PartQueryError::Invalid("request tenant is not this process's tenant".into()).into());
    }
    state.service.require_product_state(&request.window)?;
    let _inflight = state.service.begin();
    let _slot = state.service.admit().await?;
    state.service.refresh().await?;
    let answer = crate::query_timing::measure("prevalence_explorer", async { Ok::<_, ApiError>(partials::prevalence_explorer(state.service.engine(), &request).await?) }).await?;
    Ok(Json(answer))
}

async fn entity_ranges(State(state): State<AppState>, Json(request): Json<partials::EntityRangesRequest>) -> ApiResult {
    state.service.require_ready()?;
    let _inflight = state.service.begin();
    let _slot = state.service.admit().await?;
    state.service.refresh().await?;
    state.service.require_ready()?;
    let mut answer = crate::query_timing::measure("entity_ranges", async { Ok::<_, ApiError>(partials::entity_ranges(state.service.engine(), &request).await?) }).await?;
    crate::perf_overrides::annotate(&mut answer);
    Ok(Json(answer))
}

async fn risk_route(State(state): State<AppState>, Json(request): Json<crate::risk::RiskRequest>) -> ApiResult {
    if request.tenant_id != state.service.engine().settings().tenant_id {
        return Err(PartQueryError::Invalid("request tenant is not this process's tenant".into()).into());
    }
    // NAN-3271: no moving-window gate. The ledger is published before any
    // window, and `risk::risk` answers `product_state_warming` itself while
    // no ledger is published.
    state.service.require_ready()?;
    let _inflight = state.service.begin();
    let _slot = state.service.admit().await?;
    state.service.refresh().await?;
    state.service.require_ready()?;
    Ok(Json(risk::risk(state.service.engine(), &state.service.state_dir, &request).await?))
}

async fn ioc_lookup(State(state): State<AppState>, Json(request): Json<crate::lean_ioc_query::LookupRequest>) -> ApiResult {
    state.service.require_ready()?;
    let _inflight = state.service.begin();
    let store = state.service.ioc_store.as_deref().ok_or_else(||
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "tenant IOC reader is not provisioned".into(), "not_ready", None))?;
    let tenant = state.service.engine().settings().tenant_id.parse().map_err(|_|
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "process tenant is invalid".into(), "not_ready", None))?;
    let result = crate::lean_ioc_query::lookup(store, &state.service.state_dir.join("enrichment"), tenant, request).await?;
    Ok(Json(result))
}

/// NAN-3881: the Enrich flyout's point lookup over every IOC source the
/// tenant has enabled — its own snapshot plus the platform baseline feeds its
/// policy grants — through the same reads ingest matching uses. Unlike
/// `/v1/ioc/lookup` (own snapshot only, used by search and retro), a tenant
/// with no published snapshot or no IOC reader still searches its feeds.
async fn ioc_indicator_sets(State(state): State<AppState>, Json(request): Json<crate::lean_ioc_query::LookupRequest>) -> ApiResult {
    use crate::lean_ioc_query::PlatformIocs;
    state.service.require_ready()?;
    let _inflight = state.service.begin();
    let tenant = state.service.engine().settings().tenant_id.parse().map_err(|_|
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "process tenant is invalid".into(), "not_ready", None))?;
    let view = crate::enrichment_read::platform_ioc_view(tenant).map_err(|error| {
        tracing::warn!(%error, tenant_id = %tenant, "platform IOC feeds unavailable for indicator lookup");
    });
    let platform = match &view {
        Ok(Some((bundle, policy))) => PlatformIocs::Granted { bundle: bundle.as_ref(), policy },
        Ok(None) => PlatformIocs::NotConfigured,
        Err(()) => PlatformIocs::Unavailable,
    };
    let result = crate::lean_ioc_query::indicator_sets(state.service.ioc_store.as_deref(),
        &state.service.state_dir.join("enrichment"), tenant, platform, request).await?;
    Ok(Json(result))
}

async fn ioc_source_records(State(state): State<AppState>, Json(request): Json<crate::lean_ioc_query::SourceRequest>) -> ApiResult {
    state.service.require_ready()?;
    let _inflight = state.service.begin();
    let store = state.service.ioc_store.as_deref().ok_or_else(||
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "tenant IOC reader is not provisioned".into(), "not_ready", None))?;
    let tenant = state.service.engine().settings().tenant_id.parse().map_err(|_|
        ApiError(StatusCode::SERVICE_UNAVAILABLE, "process tenant is invalid".into(), "not_ready", None))?;
    let result = crate::lean_ioc_query::source_records(store, &state.service.state_dir.join("enrichment"), tenant, request).await?;
    Ok(Json(result))
}

/// NAN-3500: identity directory reads from the tenant's R2 snapshot + deltas.
/// The enrichment reader store is the same read-only tenant prefix as IOC.
macro_rules! identity_directory_handler {
    ($name:ident, $request:ty, $call:path) => {
        async fn $name(State(state): State<AppState>, Json(request): Json<$request>) -> ApiResult {
            state.service.require_ready()?;
            let _inflight = state.service.begin();
            let store = state.service.ioc_store.as_deref().ok_or_else(||
                ApiError(StatusCode::SERVICE_UNAVAILABLE, "tenant enrichment reader is not provisioned".into(), "not_ready", None))?;
            let tenant = state.service.engine().settings().tenant_id.parse().map_err(|_|
                ApiError(StatusCode::SERVICE_UNAVAILABLE, "process tenant is invalid".into(), "not_ready", None))?;
            let result = $call(store, &state.service.state_dir.join("enrichment"), tenant, request).await?;
            Ok(Json(result))
        }
    };
}
identity_directory_handler!(identity_directory_list, crate::lean_identity_query::ListRequest, crate::lean_identity_query::list);
identity_directory_handler!(identity_directory_lookup, crate::lean_identity_query::LookupRequest, crate::lean_identity_query::lookup);
identity_directory_handler!(identity_directory_stats, crate::lean_identity_query::StatsRequest, crate::lean_identity_query::stats);

async fn detection_plan(State(state): State<AppState>, Json(request): Json<PlanRequest>) -> ApiResult {
    state.service.refresh().await?;
    Ok(Json(serde_json::to_value(state.service.gate.plan(&request)).map_err(anyhow::Error::from)?))
}

async fn detection_commit(State(state): State<AppState>, Json(request): Json<CommitRequest>) -> ApiResult {
    state.service.gate.commit(&request).map_err(gate_error)?;
    Ok(Json(json!({"ok": true})))
}

/// NAN-3289 P2-1: the operator reset of rule watermarks.
async fn detection_reset(State(state): State<AppState>, Json(request): Json<ResetRequest>) -> ApiResult {
    let dropped = state.service.gate.reset(&request).map_err(gate_error)?;
    tracing::warn!(tenant_id = %state.service.engine().settings().tenant_id, dropped, all = request.all,
        "detection watermarks reset by operator");
    Ok(Json(json!({"ok": true, "dropped": dropped})))
}

/// A refused gate write is the caller's error (400); storage failures stay 5xx.
fn gate_error(error: anyhow::Error) -> ApiError {
    match error.downcast_ref::<GateRefused>() {
        Some(refused) => ApiError(StatusCode::BAD_REQUEST, refused.to_string(), "detection_gate_refused", None),
        None => ApiError::from(error),
    }
}

/// NAN-3289 P2-2: how the cell router admitted a durable-job spec. A signed
/// spec (its tenant's dispatcher signed exactly these bytes) must carry its
/// retention proof: query[T] holds no tenant policy and takes the retention
/// cutoff and the per-source deny scope only from the signed spec. An
/// unsigned spec is admitted only as the router's explicit legacy mode
/// (`router_accept_cluster_query_token` on); anything else (no router
/// verdict at all) is refused.
fn job_spec_admission(auth: Option<&str>, spec: &crate::job::LakeQueryJobSpec) -> std::result::Result<(), ApiError> {
    use nanosiem_lake_cell::tenant_token::{JOB_AUTH_LEGACY, JOB_AUTH_SIGNED};
    match auth {
        Some(JOB_AUTH_SIGNED) if spec.retention_proof.is_some() => Ok(()),
        Some(JOB_AUTH_SIGNED) => Err(ApiError(StatusCode::BAD_REQUEST,
            "signed job spec carries no retention proof".into(), "job_retention_proof_missing", None)),
        Some(JOB_AUTH_LEGACY) => {
            tracing::warn!(job_id = %spec.job_id, "durable job spec admitted unsigned (legacy router mode)");
            Ok(())
        }
        _ => Err(ApiError(StatusCode::FORBIDDEN, "job spec was not admitted by the cell router".into(), "job_spec_unsigned", None)),
    }
}

/// The result root is fixed by tenant identity (never supplied by a job)
/// and written only through the exchanged `job_results` grant (NAN-3042).
fn job_storage_ready(service: &QueryService) -> bool {
    service.job_results().is_ok()
}

fn result_attempt_id(root: &str, manifest_uri: &str, tenant_id: &str, job_id: &str) -> std::result::Result<String, ApiError> {
    let tenant_hash = hex::encode(Sha256::digest(tenant_id.as_bytes()));
    let prefix = format!("{root}/tenant-{tenant_hash}/job-{job_id}/attempt-");
    let attempt = manifest_uri.strip_prefix(&prefix)
        .and_then(|suffix| suffix.strip_suffix("/manifest.json"))
        .filter(|attempt| !attempt.is_empty() && !attempt.contains('/'))
        .ok_or_else(|| ApiError(StatusCode::BAD_REQUEST, "result reference is outside this tenant job".into(), "invalid_request", None))?;
    if let (Some(root_path), Some(path)) = (root.strip_prefix("file://"), manifest_uri.strip_prefix("file://")) {
        let canonical_root = std::fs::canonicalize(root_path).map_err(anyhow::Error::from)?;
        let canonical = std::fs::canonicalize(path).map_err(anyhow::Error::from)?;
        let expected = canonical_root.join(format!("tenant-{tenant_hash}"))
            .join(format!("job-{job_id}"))
            .join(format!("attempt-{attempt}"))
            .join("manifest.json");
        if canonical != expected {
            return Err(ApiError(StatusCode::BAD_REQUEST, "result reference path is not canonical".into(), "invalid_request", None));
        }
    }
    Ok(attempt.to_string())
}

async fn job_search(State(state): State<AppState>, headers: axum::http::HeaderMap, Json(spec): Json<crate::job::LakeQueryJobSpec>) -> ApiResult {
    job_spec_admission(
        headers.get(nanosiem_lake_cell::tenant_token::JOB_AUTH_HEADER).and_then(|v| v.to_str().ok()), &spec)?;
    state.service.require_job_state()?;
    state.service.require_ready()?;
    spec.validate().map_err(|error| ApiError(StatusCode::BAD_REQUEST, error.to_string(), "invalid_request", None))?;
    // Held until the job finishes (the handler awaits it).
    let _slot = state.service.admit_job().await?;
    state.service.refresh().await?;
    state.service.require_ready()?;
    let key = job_key(&JobControlRequest {
        tenant_id: spec.tenant_id.clone(), job_id: spec.job_id.clone(), attempt_id: spec.attempt_id.clone(),
    }, &state.service.engine().settings().tenant_id)?;
    let results = state.service.job_results()?;
    // The refreshed current head executes the job; the admitted head is its floor.
    let (head, schema_fingerprint) = state.service.engine().head_and_schema_fingerprint().await;
    let pin = jobs::PartJobPin::at_head(
        head, schema_fingerprint.as_deref(), &state.service.compiler_sha256, &state.service.native_artifact_sha256,
    )?;
    pin.admits(&spec).map_err(|error| ApiError(StatusCode::CONFLICT, error.to_string(), "stale_job_pin", None))?;
    let cancelled = Arc::new(AtomicBool::new(false));
    {
        let mut records = state.service.jobs.lock().expect("search job records");
        if records.contains_key(&key) {
            return Err(ApiError(StatusCode::CONFLICT, "search job attempt already exists".into(), "duplicate_job", None));
        }
        if records.values().any(|record| matches!(record.status, "running" | "cancel_requested")) {
            return Err(ApiError(StatusCode::TOO_MANY_REQUESTS, "query process already has a running search job".into(), "job_busy", None));
        }
        if records.len() >= 1_024 {
            records.retain(|_, record| matches!(record.status, "running" | "cancel_requested"));
        }
        records.insert(key.clone(), JobRecord { status: "running", cancelled: cancelled.clone(), result: None });
        if let Err(error) = persist_job_records(&state.service.state_dir, &spec.tenant_id, &records) {
            records.remove(&key);
            return Err(ApiError::from(error));
        }
    }
    // The result commit's futures are not provably `Send` across the
    // handler boundary; run the job on a blocking thread with its own
    // `block_on` (the reader runs jobs in a separate child for the same shape).
    let service = state.service.clone();
    let handle = tokio::runtime::Handle::current();
    let response_key = key.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _inflight = service.begin();
        // NAN-3272: a durable job reads under its own resource-class scan
        // budget, not the interactive cold-fetch budget whose refusal says
        // "run it as a background job".
        let outcome = handle.block_on(crate::reader_object_cache::with_durable_job_cold_budget(
            spec.scan_budget_bytes,
            jobs::run_job(service.engine(), &spec, &results, &pin, &cancelled),
        ));
        // NAN-3272: a lane-wait timeout committed nothing; drop the attempt's
        // record so the runner may re-send this same fenced attempt after a
        // backoff instead of being refused as a duplicate.
        // NAN-3883: so did a cold-fetch timeout; the runner re-sends it.
        let lane_wait = matches!(&outcome, Err(error) if is_lane_wait_timeout(error) || is_cold_fetch_timeout(error))
            && !cancelled.load(Ordering::Acquire);
        let mut records = service.jobs.lock().expect("search job records");
        // A cancelled attempt's R2 objects are deliberately orphaned: only
        // the owner-authorized retention path deletes shared-tenant objects;
        // the record below removes reachability.
        if lane_wait {
            records.remove(&key);
        } else if let Some(record) = records.get_mut(&key) {
            record.status = if cancelled.load(Ordering::Acquire) { "cancelled" } else if outcome.is_ok() { "completed" } else { "failed" };
            record.result = if record.status == "completed" { outcome.as_ref().ok().cloned() } else { None };
        }
        if let Err(error) = persist_job_records(&service.state_dir, &spec.tenant_id, &records) {
            tracing::error!(job_id = %spec.job_id, error = %error, "search job terminal state was not persisted");
            if let Some(record) = records.get_mut(&key) {
                record.status = "failed";
                record.result = None;
            }
            return Err(error);
        }
        if cancelled.load(Ordering::Acquire) {
            Err(anyhow::anyhow!("search job was cancelled"))
        } else {
            outcome
        }
    })
        .await
        .map_err(anyhow::Error::from)?;
    let reference = result.map_err(|error| {
        let cancelled = state.service.jobs.lock().expect("search job records")
            .get(&response_key).is_some_and(|record| record.status == "cancelled");
        if cancelled {
            ApiError(StatusCode::CONFLICT, "search job was cancelled".into(), "job_cancelled", None)
        } else {
            ApiError::from(error)
        }
    })?;
    Ok(Json(json!({"ok": true, "result": reference})))
}

async fn job_status(State(state): State<AppState>, Json(request): Json<JobControlRequest>) -> ApiResult {
    state.service.require_job_state()?;
    let key = job_key(&request, &state.service.engine().settings().tenant_id)?;
    let records = state.service.jobs.lock().expect("search job records");
    let record = records.get(&key).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "search job attempt was not found".into(), "job_not_found", None))?;
    Ok(Json(json!({"ok": true, "tenant_id": request.tenant_id, "job_id": request.job_id,
        "attempt_id": request.attempt_id, "status": record.status, "result": record.result})))
}

async fn job_cancel(State(state): State<AppState>, Json(request): Json<JobControlRequest>) -> ApiResult {
    state.service.require_job_state()?;
    let key = job_key(&request, &state.service.engine().settings().tenant_id)?;
    let mut records = state.service.jobs.lock().expect("search job records");
    let record = records.get_mut(&key).ok_or_else(|| ApiError(StatusCode::NOT_FOUND, "search job attempt was not found".into(), "job_not_found", None))?;
    if request_cell_job_cancel(record) {
        // The native chDB ABI has no interrupt handle. The running statement
        // finishes under its SQL deadline, then its result commit is skipped.
        persist_job_records(&state.service.state_dir, &request.tenant_id, &records)?;
    }
    let status = records.get(&key).expect("validated search job attempt").status;
    Ok(Json(json!({"ok": true, "tenant_id": request.tenant_id, "job_id": request.job_id,
        "attempt_id": request.attempt_id, "status": status})))
}

fn request_cell_job_cancel(record: &mut JobRecord) -> bool {
    if record.status != "running" {
        return false;
    }
    record.cancelled.store(true, Ordering::Release);
    record.status = "cancel_requested";
    true
}

fn identity_error(error: IdentityError) -> ApiError {
    match error {
        IdentityError::InvalidRequest(message) => ApiError(StatusCode::BAD_REQUEST, message, "invalid_request", None),
        other => ApiError(StatusCode::SERVICE_UNAVAILABLE, other.to_string(), "identity_snapshot_unavailable", None),
    }
}

fn identity_binding(service: &QueryService, request_id: &str, tenant_id: &str) -> std::result::Result<(), ApiError> {
    if tenant_id != service.engine().settings().tenant_id || request_id.is_empty() || request_id.len() > 128
        || request_id.chars().any(char::is_control)
    {
        return Err(ApiError(StatusCode::BAD_REQUEST, "identity request binding is invalid".into(), "invalid_request", None));
    }
    Ok(())
}

async fn identity_result(
    service: &QueryService,
    plan: crate::planner::NativeQueryPlan,
    request_id: &str,
    route: &str,
    page_limit: usize,
    started: Instant,
) -> ApiResult {
    let snapshot = service.identity_snapshot.as_ref().expect("identity route checked its snapshot");
    let query_sha256 = plan.query_sha256.clone();
    let _slot = service.admit().await?;
    let output = service.engine().execute(plan).await?;
    let rows = super::engine::decode_rows(&output.data)?;
    if rows.len() > page_limit {
        return Err(ApiError(StatusCode::INTERNAL_SERVER_ERROR, "identity result exceeded its row bound".into(), "internal", None));
    }
    let wall_seconds = started.elapsed().as_secs_f64();
    Ok(Json(json!({
        "ok": true, "schema_version": 1, "request_id": request_id,
        "tenant_id": service.engine().settings().tenant_id, "route": route,
        "snapshot_id": snapshot.snapshot_id(), "snapshot_version": snapshot.snapshot_version(),
        "wall_seconds": wall_seconds, "query_sha256": query_sha256,
        "budget": {"decision": "allow", "estimated_scan_bytes": snapshot.bytes(), "estimate_kind": "immutable-identity-snapshot"},
        "result": {"result_rows": rows.len(), "rows": rows, "page_offset": 0,
            "page_limit": page_limit, "page_has_more": false,
            "engine_seconds": output.elapsed.as_secs_f64(),
            "storage_rows": output.storage_rows_read, "storage_bytes": output.storage_bytes_read,
            "wall_seconds": wall_seconds},
    })))
}

/// NAN-3058: without a gen1 snapshot (every lean cell), identity routes
/// answer from the part identity observation index
/// ([`super::identity`]). The envelope's `identity_index` says whether every
/// part of the lookback window was covered (`complete`) or some are still
/// being backfilled; the rows are exact over the covered parts either way.
async fn identity_index_result(
    service: &Arc<QueryService>,
    request_id: &str,
    route: &str,
    entity_type: &str,
    raw_items: Vec<(String, String)>,
    deny: &BTreeSet<String>,
) -> ApiResult {
    let started = Instant::now();
    let kind = super::identity::LookupKind::parse(entity_type)?;
    let items = super::identity::normalize_items(kind, &raw_items)?;
    let denied = super::identity::normalize_denied(deny)?;
    let _slot = service.admit().await?;
    service.refresh().await?;
    let (rows, mut index) = super::identity::lookup(service.engine(), &service.state_dir, kind, &items, &denied).await?;
    // NAN-3394: per-phase numbers ride in `planner`, which the search
    // service's debug evidence records (numeric fields only).
    let planner = index.as_object_mut().and_then(|index| index.remove("timing")).unwrap_or_else(|| json!({}));
    let mut planner = json!({"planner": planner});
    crate::perf_overrides::annotate(&mut planner);
    let planner = planner["planner"].take();
    Ok(Json(json!({
        "ok": true, "schema_version": 1, "request_id": request_id,
        "tenant_id": service.engine().settings().tenant_id, "route": route,
        "source_mode": "parts", "identity_index": index, "planner": planner,
        "wall_seconds": started.elapsed().as_secs_f64(),
        "result": {"result_rows": rows.len(), "rows": rows, "page_offset": 0,
            "page_limit": items.len(), "page_has_more": false},
    })))
}

async fn identity_resolve(State(state): State<AppState>, Json(request): Json<IdentityResolveHttpRequest>) -> ApiResult {
    let service = &state.service;
    let _inflight = service.begin();
    identity_binding(service, &request.request_id, &request.tenant_id)?;
    let Some(snapshot) = service.identity_snapshot.as_ref() else {
        return identity_index_result(&state.service, &request.request_id, "identity", "ip",
            vec![(request.ip.clone(), request.reference_time.clone())], &request.deny_source_types).await;
    };
    let started = Instant::now();
    let plan = plan_identity_resolve(&service.engine().limits_tenant(), snapshot, &IdentityResolveRequest {
        snapshot_id: request.snapshot_id.as_deref().unwrap_or(snapshot.snapshot_id()),
        ip: &request.ip, reference_time: &request.reference_time, deny_source_types: &request.deny_source_types,
    }).map_err(identity_error)?;
    identity_result(service, plan, &request.request_id, "identity", 1, started).await
}

async fn identity_resolve_batch(State(state): State<AppState>, Json(request): Json<IdentityBatchHttpRequest>) -> ApiResult {
    let service = &state.service;
    let _inflight = service.begin();
    identity_binding(service, &request.request_id, &request.tenant_id)?;
    let Some(snapshot) = service.identity_snapshot.as_ref() else {
        let items = request.items.iter().map(|item| (item.ip.clone(), item.reference_time.clone())).collect();
        return identity_index_result(&state.service, &request.request_id, "identity_batch", "ip", items, &request.deny_source_types).await;
    };
    let started = Instant::now();
    let items = request.items.iter().map(|item| IdentityBatchItem { ip: item.ip.clone(), reference_time: item.reference_time.clone() }).collect::<Vec<_>>();
    let plan = plan_identity_batch(&service.engine().limits_tenant(), snapshot, &IdentityBatchRequest {
        snapshot_id: request.snapshot_id.as_deref().unwrap_or(snapshot.snapshot_id()),
        items: &items, deny_source_types: &request.deny_source_types,
    }).map_err(identity_error)?;
    identity_result(service, plan, &request.request_id, "identity_batch", items.len(), started).await
}

async fn identity_resolve_entity_batch(State(state): State<AppState>, Json(request): Json<IdentityEntityBatchHttpRequest>) -> ApiResult {
    let service = &state.service;
    let _inflight = service.begin();
    identity_binding(service, &request.request_id, &request.tenant_id)?;
    let Some(snapshot) = service.identity_snapshot.as_ref() else {
        let items = request.items.iter().map(|item| (item.value.clone(), item.reference_time.clone())).collect();
        return identity_index_result(&state.service, &request.request_id, "identity_entity_batch", &request.entity_type, items,
            &request.deny_source_types).await;
    };
    let started = Instant::now();
    let items = request.items.iter().map(|item| IdentityEntityBatchItem { value: item.value.clone(), reference_time: item.reference_time.clone() }).collect::<Vec<_>>();
    let plan = plan_identity_entity_batch(&service.engine().limits_tenant(), snapshot, &IdentityEntityBatchRequest {
        snapshot_id: request.snapshot_id.as_deref().unwrap_or(snapshot.snapshot_id()),
        entity_type: &request.entity_type, items: &items, deny_source_types: &request.deny_source_types,
    }).map_err(identity_error)?;
    identity_result(service, plan, &request.request_id, "identity_entity_batch", items.len(), started).await
}

async fn job_page(State(state): State<AppState>, Json(request): Json<ResultPageRequest>) -> ApiResult {
    state.service.require_job_state()?;
    if request.tenant_id != state.service.engine().settings().tenant_id {
        return Err(ApiError(StatusCode::BAD_REQUEST, "request tenant is not this process's tenant".into(), "invalid_request", None));
    }
    let results = state.service.job_results()?;
    let attempt_id = result_attempt_id(results.root(), &request.reference.manifest_uri,
        &request.tenant_id, &request.job_id)?;
    let key = job_key(&JobControlRequest {
        tenant_id: request.tenant_id.clone(), job_id: request.job_id.clone(), attempt_id,
    }, &state.service.engine().settings().tenant_id)?;
    let allowed = {
        let records = state.service.jobs.lock().expect("search job records");
        job_page_record_allows(&records, &key, &request.reference)
    };
    if !allowed {
        return Err(ApiError(StatusCode::CONFLICT, "search job result is not completed".into(), "job_not_completed", None));
    }
    Ok(Json(jobs::result_page(&results, &request.reference, &request.job_id, &request.tenant_id, request.page).await?))
}

/// NAN-3809: may Search re-serve this finished job's result pages for an
/// identical settled search? Yes only when the reuse marker the job wrote
/// next to its result names this tenant, job and result, the window is still
/// settled, and the window's current data identity (refreshed part set, read
/// schema, query artifacts, enrichment read authority) equals the one the
/// job read. Search re-checks ownership, deny set and caller authority; the
/// result pages re-check retention and enrichment authority when read.
async fn job_reuse_check(State(state): State<AppState>, Json(request): Json<ReuseCheckRequest>) -> ApiResult {
    state.service.require_job_state()?;
    if request.tenant_id != state.service.engine().settings().tenant_id {
        return Err(ApiError(StatusCode::BAD_REQUEST, "request tenant is not this process's tenant".into(), "invalid_request", None));
    }
    let answer = |reusable: bool, reason: &str| Json(json!({
        "ok": true, "tenant_id": request.tenant_id, "job_id": request.job_id, "reusable": reusable, "reason": reason,
    }));
    let results = state.service.job_results()?;
    let marker = match jobs::read_reuse_marker(&results, &request.tenant_id, &request.job_id).await {
        Ok(Some(marker)) => marker,
        Ok(None) => return Ok(answer(false, "no_marker")),
        Err(error) => {
            tracing::debug!(job_id = %request.job_id, error = %format!("{error:#}"), "reuse marker unreadable; not reusable");
            return Ok(answer(false, "marker_unavailable"));
        }
    };
    let _inflight = state.service.begin();
    state.service.refresh().await?;
    state.service.require_ready()?;
    let (head, schema_fingerprint) = state.service.engine().head_and_schema_fingerprint().await;
    let pin = jobs::PartJobPin::at_head(
        head, schema_fingerprint.as_deref(), &state.service.compiler_sha256, &state.service.native_artifact_sha256,
    )?;
    let current = jobs::window_reuse_identity(state.service.engine(), &pin, &request.tenant_id, marker.from_us, marker.to_us)
        .await
        .map_err(ApiError::from)?;
    let reusable = marker.admits(&request.tenant_id, &request.job_id, &request.manifest_sha256, &current, chrono::Utc::now());
    Ok(answer(reusable, if reusable { "settled" } else { "changed" }))
}

/// A retained result can outlive the bounded local attempt map. When an
/// attempt is still recorded, its terminal status and exact reference take
/// precedence over a caller-supplied manifest URI (including after restart).
fn job_page_record_allows(
    records: &BTreeMap<(String, String), JobRecord>,
    key: &(String, String),
    reference: &crate::job::ResultArtifactRef,
) -> bool {
    records.get(key).is_none_or(|record| {
        record.status == "completed" && record.result.as_ref() == Some(reference)
    })
}

/// The tenant's stored field inventory (NAN-2997): every typed leaf of the
/// part-log read schema, i.e. exactly what this process's compiler accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SchemaInventory {
    /// SHA-256 over the canonical JSON of `field_types` (key order), so a
    /// caller memoizes on it and rebuilds only when the field SET changed.
    digest: String,
    field_types: BTreeMap<String, String>,
}

/// Longest leaf path served (the `field_names` route's bound).
const MAX_INVENTORY_PATH_BYTES: usize = 1_024;

fn schema_inventory(mut field_types: BTreeMap<String, String>) -> Result<SchemaInventory> {
    field_types.retain(|path, _| path.len() <= MAX_INVENTORY_PATH_BYTES);
    let canonical = serde_json::to_vec(&field_types).context("encode field inventory")?;
    Ok(SchemaInventory { digest: hex::encode(Sha256::digest(&canonical)), field_types })
}

impl QueryService {
    /// The inventory at `fingerprint`, derived once per read schema.
    async fn schema_inventory_at(&self, fingerprint: &str) -> std::result::Result<Arc<SchemaInventory>, ApiError> {
        if let Some((cached, inventory)) = self.schema_inventory.lock().expect("schema inventory").as_ref() {
            if cached == fingerprint {
                return Ok(inventory.clone());
            }
        }
        let inventory = Arc::new(schema_inventory(self.engine.field_types().await?)?);
        *self.schema_inventory.lock().expect("schema inventory") = Some((fingerprint.to_string(), inventory.clone()));
        Ok(inventory)
    }
}

/// `GET /v1/schema/manifest` (NAN-2997): the gen1 worker's schema-manifest
/// shape (`schema_digest`, `field_types`) over this tenant's part schema, so
/// Search's front door validates, lists and types exactly the leaves this
/// tenant stores (`prevalence_*` stamp columns, `enrichments.data.*`,
/// `unmapped.*`). The process is bound to one tenant, so there is nothing to
/// select: the response names that tenant and Search checks it. Needs no
/// prewarm (it reads the log head only).
async fn schema_manifest(State(state): State<AppState>) -> ApiResult {
    let service = &state.service;
    let _inflight = service.begin();
    service.refresh().await?;
    let (head, fingerprint) = service.engine().head_and_schema_fingerprint().await;
    let Some(fingerprint) = fingerprint else {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "tenant part log has no schema yet".into(), "no_schema", None));
    };
    let inventory = service.schema_inventory_at(&fingerprint).await?;
    Ok(Json(json!({
        "ok": true,
        "schema_version": 1,
        "tenant_id": service.engine().settings().tenant_id,
        "source_mode": "parts",
        "log_head": head.map(|(seq, sha)| json!({"seq": seq, "sha256": sha})),
        "schema_fingerprint": fingerprint,
        "schema_digest": inventory.digest,
        "field_types": inventory.field_types,
    })))
}

/// NAN-3662: `POST /v1/ingest/refusals`, a window in epoch milliseconds.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusalsRequest {
    start_ms: i64,
    end_ms: i64,
}

/// NAN-3662: rows ingest[T] refused at admission, per source lane and
/// 5-minute bucket (refusal time), from the verified part log's `reject`
/// entries: the lean counterpart of the gen1 per-source refusal counters.
/// Value-free (reason code and OCSF attribute path only). `complete_since_ms`
/// is the time from which every refusal is in the answer (`null` while the
/// older log is still being read after a cold start).
async fn ingest_refusals(State(state): State<AppState>, Json(request): Json<RefusalsRequest>) -> ApiResult {
    let service = &state.service;
    service.require_ready()?;
    if request.start_ms >= request.end_ms || request.end_ms - request.start_ms > super::log_view::REFUSAL_RETAIN_MS {
        return Err(ApiError(StatusCode::BAD_REQUEST, "refusal window must be non-empty and at most 49 hours".into(), "invalid_request", None));
    }
    let _inflight = service.begin();
    service.refresh().await?;
    let now = i64::try_from(now_ms()).unwrap_or(i64::MAX);
    let (rows, complete_since_ms) = service.engine().refusals(request.start_ms, request.end_ms, now).await;
    Ok(Json(json!({
        "format": "nano.lake-refusals.v1",
        "bucket_secs": crate::parts::refusal_tally::BUCKET_MS / 1_000,
        "complete_since_ms": complete_since_ms,
        "rows": rows,
    })))
}

async fn status(State(state): State<AppState>) -> ApiResult {
    let service = &state.service;
    if !service.readiness.is_ready() {
        return Err(ApiError(StatusCode::SERVICE_UNAVAILABLE, "query prewarm is incomplete".into(), "not_ready", None));
    }
    service.refresh().await?;
    service.require_ready()?;
    let (head, schema_fingerprint) = service.engine().head_and_schema_fingerprint().await;
    let live_parts = service.engine().live_totals().await;
    let hot_gate = service.engine().fetcher().hot_window_gate();
    let pin = jobs::PartJobPin::at_head(
        head.clone(), schema_fingerprint.as_deref(), &service.compiler_sha256, &service.native_artifact_sha256,
    )?;
    Ok(Json(json!({
        "ok": true,
        "status": "ok",
        "tenant_id": service.engine().settings().tenant_id,
        "source_mode": "parts",
        "log_head": head.map(|(seq, sha)| json!({"seq": seq, "sha256": sha})),
        "generation_id": pin.generation_id,
        "generation_snapshot_id": pin.snapshot_id,
        "event_config_sha256": pin.event_config_sha256,
        "compiler_sha256": pin.compiler_sha256,
        "native_artifact_sha256": pin.native_artifact_sha256,
        "durable_jobs_ready": job_storage_ready(service),
        "ready": service.readiness.is_ready(),
        "prewarm_hours": service.prewarm_hours,
        "prewarm_wall_ms": service.prewarm_wall_ms.load(Ordering::Relaxed),
        "selection_evidence_cache": service.engine().selection_evidence_status(),
        "inflight": service.inflight.load(Ordering::Relaxed),
        "answered": service.answered.load(Ordering::Relaxed),
        "cache": service.engine().fetcher().cache().stats(),
        "local_hot_window": service.engine().fetcher().hot_coverage.lock().unwrap_or_else(|e| e.into_inner()).clone(),
        // NAN-3164: the cell's startup warm latch waits on this (bounded by
        // NANO_LAKE_LOCAL_HOT_WINDOW_WARM_TIMEOUT_SECONDS). `ready` above is
        // unchanged, so a lone pod still serves while it hydrates.
        "hot_window_gate": hot_gate,
        "hot_window_warm": hot_gate.is_none_or(|gate| gate.warm()),
        "range_fetch": super::range_fetch::stats_json(),
        "product_demand_inbox_writable": super::product_publish::demand_inbox_writable(),
        "verified_in_place_bytes": service.engine().fetcher().verified_in_place_bytes(),
        "memory": process_memory(),
        // NAN-3020: the lean tenant's storage facts (the API has no
        // control-DB receipt for lean parts).
        "live_parts": live_parts,
    })))
}

#[cfg(test)]
mod embedded_dir_tests {
    #[test]
    fn removes_only_stale_embedded_dirs() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("clickhouse-embedded-1/tmp")).unwrap();
        std::fs::write(dir.path().join("clickhouse-embedded-1/tmp/spill"), b"x").unwrap();
        std::fs::create_dir(dir.path().join("cache")).unwrap();
        std::fs::write(dir.path().join("clickhouse-embedded-file"), b"keep").unwrap();
        assert_eq!(super::remove_stale_embedded_dirs(dir.path()), 1);
        assert!(!dir.path().join("clickhouse-embedded-1").exists());
        assert!(dir.path().join("cache").exists() && dir.path().join("clickhouse-embedded-file").exists());
    }
}

#[cfg(test)]
mod contract_tests {
    use super::{job_key, job_page_record_allows, resolve_detect_bootstrap, load_identity_snapshot, load_job_records, persist_job_records,
        request_cell_job_cancel, result_attempt_id, validate_enrichment_credential,
        validate_query_credential, EngineBoot, ExchangedCredential, JobControlRequest, JobRecord,
        LayeredStore, QueryBootstrap, QueryIdentitySnapshotBoot, Role, BOOTSTRAP_FORMAT};
    use super::PrewarmReadiness;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use sha2::Digest;
    use crate::parts::part_log::{LocalObjectStore, ObjectStore};

    /// NAN-2997: the inventory is the part read schema's typed leaves,
    /// including the prevalence stamp columns, producer-defined json_t keys
    /// under `enrichments.data`, and dotted `unmapped.*` keys.
    #[test]
    fn schema_inventory_reflects_prevalence_enrichment_and_unmapped_leaves() {
        let events = [
            serde_json::json!({
                "time": 1_790_000_000_000_000_i64, "class_uid": 4001,
                "dst_endpoint": {"ip": "8.8.8.8", "port": 53},
                "prevalence_dest_ip": 2, "prevalence_min": 2,
                "enrichments": [{"name": "dst_endpoint.ip", "value": "8.8.8.8", "data": {"host_count": 3}}],
                "unmapped": {"vendor": {"event_id": "4624"}, "Logon.Type": "3"},
            }),
            serde_json::json!({"time": 1_790_000_000_000_001_i64, "class_uid": 4001, "unmapped": {"late_key": true}}),
        ];
        let refs = events.iter().collect::<Vec<_>>();
        let schema = crate::part_ingest::schema::infer_schema(&refs).unwrap();
        let inventory = super::schema_inventory(crate::generation::schema_leaf_types(&schema)).unwrap();
        let types = &inventory.field_types;
        assert_eq!(types.get("prevalence_dest_ip").map(String::as_str), Some("integer"));
        assert_eq!(types.get("prevalence_min").map(String::as_str), Some("integer"));
        assert_eq!(types.get("dst_endpoint.ip").map(String::as_str), Some("string"));
        assert_eq!(types.get("dst_endpoint.port").map(String::as_str), Some("long"));
        assert_eq!(types.get("time").map(String::as_str), Some("timestamp"));
        // Leaves under a repeated object are arrays at rest.
        assert_eq!(types.get("enrichments.data.host_count").map(String::as_str), Some("array"));
        assert_eq!(types.get("unmapped.vendor.event_id").map(String::as_str), Some("string"));
        // A producer key that itself contains a dot stays one leaf.
        assert_eq!(types.get("unmapped.Logon.Type").map(String::as_str), Some("string"));
        assert_eq!(types.get("unmapped.late_key").map(String::as_str), Some("boolean"));
        // Objects are not leaves.
        assert!(!types.contains_key("unmapped") && !types.contains_key("dst_endpoint"));

        // The digest is content-addressed: same set, same digest; a new leaf
        // (new parts widened the schema) changes it.
        let again = super::schema_inventory(types.clone()).unwrap();
        assert_eq!(again.digest, inventory.digest);
        let mut widened = types.clone();
        widened.insert("unmapped.new_key".into(), "string".into());
        assert_ne!(super::schema_inventory(widened).unwrap().digest, inventory.digest);
        // Over-long paths are not served.
        let mut long = types.clone();
        long.insert(format!("unmapped.{}", "k".repeat(2_000)), "string".into());
        assert_eq!(super::schema_inventory(long).unwrap().digest, inventory.digest);
    }

    #[test]
    fn cell_r2_result_path_survives_move_and_rejects_foreign_artifacts() {
        let tenant = uuid::Uuid::from_u128(0x42).to_string();
        let root = format!("s3://nano-shared-r2-{tenant}/{tenant}/durable-query-result/v1");
        assert_eq!(crate::part_query::job_results::job_results_root(&tenant), root);
        let digest = hex::encode(sha2::Sha256::digest(tenant.as_bytes()));
        let manifest = format!("{root}/tenant-{digest}/job-job1/attempt-a/manifest.json");
        // A new cell has no local result directory; its tenant route can still
        // verify the stable R2 URI and read the manifest by digest.
        assert_eq!(result_attempt_id(&root, &manifest, &tenant, "job1").unwrap(), "a");
        assert!(result_attempt_id(&root, &manifest, &tenant, "job2").is_err());
        assert!(result_attempt_id(&root, &manifest.replace("attempt-a", "attempt-a/../attempt-b"), &tenant, "job1").is_err());
        let other = uuid::Uuid::from_u128(0x43).to_string();
        assert!(result_attempt_id(&crate::part_query::job_results::job_results_root(&other), &manifest, &tenant, "job1").is_err());
    }

    /// NAN-3042: no `job_results` grant is a typed, retryable 503 the
    /// runner reports by reason, never an `internal` 500.
    #[test]
    fn missing_job_results_grant_maps_to_result_storage_unavailable() {
        let error = anyhow::Error::new(crate::part_query::job_results::JobResultStorageUnavailable).context("commit");
        let mapped = super::ApiError::from(error);
        assert_eq!((mapped.0.as_u16(), mapped.2), (503, "result_storage_unavailable"));
    }

    #[test]
    fn cell_cancel_flag_is_observed_by_the_running_executor() {
        let cancelled = Arc::new(AtomicBool::new(false));
        let mut record = JobRecord { status: "running", cancelled: cancelled.clone(), result: None };
        assert!(request_cell_job_cancel(&mut record));
        assert!(cancelled.load(Ordering::Acquire));
        assert_eq!(record.status, "cancel_requested");
        assert!(!request_cell_job_cancel(&mut record));
    }

    fn credential(permission: &str, prefixes: Vec<String>) -> ExchangedCredential {
        ExchangedCredential {
            credential_class: "lake_part_read".into(),
            endpoint: "https://objects.invalid".into(),
            region: "auto".into(),
            bucket: "parts".into(),
            permission: permission.into(),
            prefixes,
            access_key_id: "id".into(),
            secret_access_key: "secret".into(),
            session_token: String::new(),
            expires_at: None,
        }
    }

    const T: &str = "b464ceb9-28a6-4249-8e29-3489627ac5f6";

    fn class(name: &str, permission: &str, prefixes: &[String]) -> serde_json::Value {
        serde_json::json!({"credential_class": name, "endpoint": "https://objects.invalid", "region": "auto",
            "bucket": format!("nano-shared-r2-{T}"), "permission": permission, "prefixes": prefixes,
            "access_key_id": "id", "secret_access_key": "secret", "session_token": "", "expires_at": null})
    }

    /// The credentials the platform mints per role (`LEAN_LAKE_CELL_ROLE_CLASSES`).
    fn creds(role: &str, enrichment: bool) -> Vec<serde_json::Value> {
        let root = format!("lake/parts/v1/tenant={T}/");
        let mut out = vec![class("lake_part_read", "object-read-only", &[root.clone()])];
        if role == "detect" {
            // NAN-2916: finding parts and receipts only; never log/entries.
            out.push(class("lake_part", "object-read-write",
                &[format!("{root}parts/"), format!("{root}finding-outbox/receipts/")]));
        }
        if enrichment {
            out.push(class("enrichment_reader", "object-read-only", &[format!("lake/enrichment/v1/tenant_id={T}/")]));
        }
        out
    }

    fn response(role: &str, credentials: Vec<serde_json::Value>) -> super::QueryExchangeResponse {
        serde_json::from_value(serde_json::json!({
            "schema_version": 1, "tenant_id": T, "role": role, "credentials": credentials, "trusted_keys": [],
            "query_engine": {"chdb_library": "/native", "chdb_sha256": "a".repeat(64), "compiler": "/compiler"}
        })).unwrap()
    }

    fn accept(response: super::QueryExchangeResponse, role: Role) -> anyhow::Result<QueryBootstrap> {
        super::bootstrap_from_exchange(response, T, role)
    }

    #[test]
    fn exchange_request_names_the_assignment_role() {
        assert_eq!(super::exchange_request_body(T, Role::Query).unwrap(), serde_json::json!({
            "tenant_id": T, "role": "query", "accepts": ["lake_part_read", "enrichment_reader", "job_results"]}));
        assert_eq!(super::exchange_request_body(T, Role::Detect).unwrap(), serde_json::json!({
            "tenant_id": T, "role": "detect", "accepts": ["lake_part_read", "lake_part", "enrichment_reader"]}));
        assert!(super::exchange_request_body(T, Role::Ingest).is_err());
    }

    #[test]
    fn query_exchange_accepts_exactly_its_set() {
        for enrichment in [false, true] {
            let boot = accept(response("query", creds("query", enrichment)), Role::Query).unwrap();
            assert!(boot.r2.is_some());
            assert_eq!(boot.enrichment_r2.is_some(), enrichment);
            assert!(boot.part_write_r2.is_none() && boot.part_log_r2.is_none());
        }
        // Detect's write classes are never accepted by query.
        assert!(accept(response("query", creds("detect", true)), Role::Query).is_err());
        assert!(accept(response("query", vec![]), Role::Query).is_err());
    }

    #[test]
    fn detect_exchange_accepts_exactly_its_set() {
        for enrichment in [false, true] {
            let boot = accept(response("detect", creds("detect", enrichment)), Role::Detect).unwrap();
            assert!(boot.r2.is_some() && boot.part_write_r2.is_some() && boot.part_log_r2.is_none());
            assert_eq!(boot.enrichment_r2.is_some(), enrichment);
        }
        // Missing any required class, a duplicate, or an unknown class: refused.
        for drop in ["lake_part_read", "lake_part"] {
            let set = creds("detect", true).into_iter().filter(|c| c["credential_class"] != drop).collect();
            assert!(accept(response("detect", set), Role::Detect).is_err(), "missing {drop}");
        }
        let mut dup = creds("detect", false);
        dup.push(dup[1].clone());
        assert!(accept(response("detect", dup), Role::Detect).is_err());
        let mut unknown = creds("detect", false);
        unknown.push(class("query_reader", "object-read-only", &[]));
        let error = accept(response("detect", unknown), Role::Detect).err().unwrap();
        assert!(format!("{error:#}").contains("undeclared"), "{error:#}");
        // NAN-2916: a detect exchange that mints lake_part_log is over-granted.
        let mut with_log = creds("detect", false);
        with_log.push(class("lake_part_log", "object-read-write", &[format!("lake/parts/v1/tenant={T}/log/entries/")]));
        let error = accept(response("detect", with_log), Role::Detect).err().unwrap();
        assert!(format!("{error:#}").contains("undeclared class \"lake_part_log\""), "{error:#}");
        // Every class the request declares is accepted when minted.
        let declared = super::exchange_request_body(T, Role::Detect).unwrap()["accepts"].as_array().unwrap().len();
        assert_eq!(creds("detect", true).len(), declared);
    }

    #[test]
    fn detect_write_credentials_are_exactly_scoped() {
        let root = format!("lake/parts/v1/tenant={T}/");
        let mut widened = creds("detect", false);
        widened[1]["prefixes"] = serde_json::json!([root.clone()]);
        assert!(accept(response("detect", widened), Role::Detect).is_err(), "tenant-root write refused");
        for leaf in ["log/HEAD", "log/checkpoints/", "log/entries/"] {
            let mut extra = creds("detect", false);
            extra[1]["prefixes"].as_array_mut().unwrap().push(serde_json::json!(format!("{root}{leaf}")));
            assert!(accept(response("detect", extra), Role::Detect).is_err(), "detect write on {leaf} refused");
        }
        let mut read_only = creds("detect", false);
        read_only[1]["permission"] = serde_json::json!("object-read-only");
        assert!(accept(response("detect", read_only), Role::Detect).is_err());
        let mut other_bucket = creds("detect", false);
        other_bucket[1]["bucket"] = serde_json::json!("nano-shared-r2-other");
        assert!(accept(response("detect", other_bucket), Role::Detect).is_err());
        let mut reordered = creds("detect", false);
        reordered[1]["prefixes"].as_array_mut().unwrap().reverse();
        assert!(accept(response("detect", reordered), Role::Detect).is_ok(), "prefix order is not significant");
    }

    /// The cell image advertises `lean_enrichment_reader_v1`; the platform then
    /// mints `enrichment_reader` for query and detect. Both must accept it.
    #[test]
    fn cell_feature_lean_enrichment_reader_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_enrichment_reader_v1"));
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_platform_bundle_dir_v1"));
        for role in [Role::Query, Role::Detect] {
            assert!(super::role_credential_set(role).unwrap().1.contains(&"enrichment_reader"));
            let boot = accept(response(role.as_str(), creds(role.as_str(), true)), role).unwrap();
            assert!(boot.enrichment_r2.is_some());
        }
    }

    /// A token bound to one role, exchanged by a process of the other: the
    /// response is bound to the token's role and is refused.
    #[test]
    fn cross_role_exchange_is_refused() {
        assert!(accept(response("detect", creds("detect", true)), Role::Query).is_err(), "query config, detect token");
        assert!(accept(response("query", creds("query", true)), Role::Detect).is_err(), "detect config, query token");
        // Even with the right label, the other role's credential set is refused.
        assert!(accept(response("detect", creds("query", true)), Role::Detect).is_err());
        assert!(accept(response("query", creds("detect", false)), Role::Query).is_err());
        assert!(accept(response("query", creds("query", false)), Role::Ingest).is_err());
    }

    #[test]
    fn enrichment_reader_is_exactly_tenant_scoped() {
        let tenant = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
        let mut reader = credential("object-read-only", vec![format!("lake/enrichment/v1/tenant_id={tenant}/")]);
        reader.credential_class = "enrichment_reader".into();
        assert!(validate_enrichment_credential(&reader, tenant).is_ok());
        assert!(validate_enrichment_credential(&reader, "different-tenant").is_err());
        reader.prefixes = vec!["lake/enrichment/v1/".into()];
        assert!(validate_enrichment_credential(&reader, tenant).is_err());
    }

    #[test]
    fn query_credential_requires_read_only_exact_tenant_prefix() {
        let tenant = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
        let exact = format!("lake/parts/v1/tenant={tenant}/");
        assert!(validate_query_credential(&credential("object-read-only", vec![exact.clone()]), tenant).is_ok());
        assert!(validate_query_credential(&credential("read-write", vec![exact.clone()]), tenant).is_err());
        assert!(validate_query_credential(&credential("object-read-only", vec!["lake/parts/v1/".into()]), tenant).is_err());
        assert!(validate_query_credential(&credential("object-read-only", vec![exact.clone(), "lake/".into()]), tenant).is_err());
        assert!(validate_query_credential(&credential("object-read-only", vec![format!("lake/parts/v1/tenant={tenant}")]), tenant).is_err());
        let mut wrong_class = credential("object-read-only", vec![exact]);
        wrong_class.credential_class = "lake_part_write".into();
        assert!(validate_query_credential(&wrong_class, tenant).is_err());
    }

    #[tokio::test]
    async fn detect_exchange_refuses_log_write_and_requires_tenant_finding_authority() {
        let tenant = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
        let prefix = format!("lake/parts/v1/tenant={tenant}/");
        let expiry = "2099-01-01T00:00:00Z";
        let mut body = serde_json::json!({
            "schema_version": 1, "tenant_id": tenant, "role": "detect",
            "assignment_generation": 4, "writer_epoch": 5,
            "credentials": [
                {"credential_class":"lake_part_read", "permission":"object-read-only", "prefixes":[prefix],
                 "endpoint":"https://objects.invalid", "region":"auto", "bucket":"parts", "access_key_id":"r", "secret_access_key":"s", "session_token":"t", "expires_at": expiry},
                {"credential_class":"lake_part", "permission":"object-read-write",
                 "prefixes":[format!("{prefix}parts/"), format!("{prefix}finding-outbox/receipts/")],
                 "endpoint":"https://objects.invalid", "region":"auto", "bucket":"parts", "access_key_id":"w", "secret_access_key":"s", "session_token":"t", "expires_at": expiry}
            ],
            "trusted_keys": [],
            "query_engine": {"chdb_library":"/native", "chdb_sha256":"a".repeat(64), "compiler":"/compiler"},
            "owner_sign": {"token":"owner", "audience":"owner", "scope":"lake-parts:sign", "expires_at":expiry},
            "finding_drain": {"tenant_id":tenant, "capability":"finding_drain", "database_url":"postgres://drain@db/tenant", "expires_at":expiry}
        });
        async fn exchange(body: serde_json::Value, tenant: &str) -> bool {
            let expected_tenant = tenant.to_owned();
            let app = axum::Router::new().route("/v1/lake/cells/cell/credential-exchange",
                axum::routing::post(move |headers: axum::http::HeaderMap, axum::Json(request): axum::Json<serde_json::Value>| {
                    let expected_tenant = expected_tenant.clone();
                    let body = body.clone();
                    async move {
                        assert_eq!(headers.get(axum::http::header::AUTHORIZATION).unwrap(), "Bearer token");
                        assert_eq!(request, serde_json::json!({"tenant_id": expected_tenant, "role": "detect",
                            "accepts": ["lake_part_read", "lake_part", "enrichment_reader"]}));
                        axum::Json(body)
                    }
                }));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            let ok = resolve_detect_bootstrap(b"token", tenant, "cell", Some(&format!("http://{addr}"))).await.is_ok();
            server.abort();
            ok
        }
        assert!(exchange(body.clone(), tenant).await);
        let mut with_log = body.clone();
        with_log["credentials"].as_array_mut().unwrap().push(serde_json::json!({
            "credential_class":"lake_part_log", "permission":"object-read-write", "prefixes":[format!("{prefix}log/entries/")],
            "endpoint":"https://objects.invalid", "region":"auto", "bucket":"parts", "access_key_id":"l", "secret_access_key":"s", "session_token":"t", "expires_at": expiry
        }));
        assert!(!exchange(with_log, tenant).await);
        body["credentials"][1]["prefixes"][1] = serde_json::json!("lake/parts/v1/");
        assert!(!exchange(body.clone(), tenant).await);
        body["credentials"][1]["prefixes"][1] = serde_json::json!(format!("{prefix}finding-outbox/receipts/"));
        body["finding_drain"]["tenant_id"] = serde_json::json!("00000000-0000-4000-8000-000000000002");
        assert!(!exchange(body, tenant).await);
    }

    #[tokio::test]
    async fn prevalence_reader_cannot_open_another_tenants_part_or_log() {
        let dir = tempfile::tempdir().unwrap();
        let local = LocalObjectStore::new(dir.path()).unwrap();
        let own = "lake/parts/v1/tenant=aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/";
        let other = "lake/parts/v1/tenant=bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/";
        let own_key = format!("{own}parts/l0/prevalence.parquet");
        let other_key = format!("{other}parts/l0/prevalence.parquet");
        let other_log = format!("{other}log/0000000000000000.json");
        local.put(&own_key, b"own").await.unwrap();
        local.put(&other_key, b"other").await.unwrap();
        local.put(&other_log, b"other log").await.unwrap();
        let reader = LayeredStore { local: Some(local), remote: None, tenant_prefix: own.into() };
        assert_eq!(reader.get(&own_key).await.unwrap().as_deref(), Some(b"own".as_slice()));
        assert!(reader.get(&other_key).await.is_err());
        assert!(reader.get(&other_log).await.is_err());
    }

    /// NAN-2984: new parts (every L0 flush and merge) must not turn query[T]
    /// not-ready; only the startup prewarm gates readiness.
    #[test]
    fn incremental_prewarm_keeps_readiness() {
        let readiness = PrewarmReadiness::default();
        assert!(!readiness.is_ready(), "a fresh process is not ready");
        let startup = readiness.request(true);
        assert!(!readiness.is_ready());
        readiness.complete(startup);
        assert!(readiness.is_ready());

        // A new part arrives: the background prewarm keeps the process ready
        // while it runs, and after.
        let incremental = readiness.request(false);
        assert!(readiness.is_ready());
        assert!(readiness.is_current(incremental));
        readiness.complete(incremental);
        assert!(readiness.is_ready());

        // A superseded prewarm stops early; the newest one's completion counts.
        let older = readiness.request(false);
        let newer = readiness.request(false);
        assert!(!readiness.is_current(older));
        readiness.complete(older);
        readiness.complete(newer);
        assert!(readiness.is_ready());
    }

    /// NAN-2989 lazy startup: ready immediately; the background prewarm
    /// neither withdraws nor delays it.
    #[test]
    fn lazy_startup_is_ready_before_its_prewarm_finishes() {
        let readiness = PrewarmReadiness::default();
        readiness.mark_ready();
        let background = readiness.request(false);
        assert!(readiness.is_ready());
        readiness.complete(background);
        assert!(readiness.is_ready());
    }

    #[test]
    fn startup_prewarm_superseded_by_an_incremental_one_still_becomes_ready() {
        let readiness = PrewarmReadiness::default();
        let startup = readiness.request(true);
        // Parts land before the startup prewarm finishes.
        let incremental = readiness.request(false);
        assert!(!readiness.is_ready(), "still gated by the startup prewarm");
        assert!(!readiness.is_current(startup));
        readiness.complete(startup);
        assert!(!readiness.is_ready(), "the superseded startup prewarm does not count");
        // The incremental prewarm covers every live part, startup's included.
        readiness.complete(incremental);
        assert!(readiness.is_ready());
    }

    #[test]
    fn startup_prewarm_window_defaults_to_24_hours_and_is_configurable() {
        let engine = serde_json::json!({
            "chdb_library": "/native", "chdb_sha256": "a".repeat(64), "compiler": "/compiler"
        });
        let default: EngineBoot = serde_json::from_value(engine.clone()).unwrap();
        assert_eq!(default.prewarm_hours, 24);
        assert!(!default.prewarm_gates_readiness, "NAN-2989: startup prewarm is lazy by default");
        let mut custom = engine;
        custom["prewarm_hours"] = serde_json::json!(48);
        let custom: EngineBoot = serde_json::from_value(custom).unwrap();
        assert_eq!(custom.prewarm_hours, 48);
    }

    #[test]
    fn job_specs_need_the_routers_admission() {
        use crate::part_query::server::job_spec_admission;
        use axum::http::StatusCode;
        use nanosiem_lake_cell::tenant_token::{JOB_AUTH_LEGACY, JOB_AUTH_SIGNED};
        let mut spec = crate::job::tests::spec();
        assert_eq!(job_spec_admission(None, &spec).unwrap_err().0, StatusCode::FORBIDDEN, "no router verdict");
        assert_eq!(job_spec_admission(Some("signed-ish"), &spec).unwrap_err().0, StatusCode::FORBIDDEN);
        assert!(job_spec_admission(Some(JOB_AUTH_LEGACY), &spec).is_ok(), "legacy router mode");
        assert_eq!(job_spec_admission(Some(JOB_AUTH_SIGNED), &spec).unwrap_err().0, StatusCode::BAD_REQUEST,
            "a signed spec without a retention proof");
        spec.retention_proof = Some(nanosiem_core::search::DurableResultRetentionProof {
            retention_revision: 1, retention_days: 30, irreversible_event_time_floor_micros: 0,
            evaluated_at_micros: 0, cutoff_micros: 0, min_event_time_micros: 0, max_event_time_micros: 1,
        });
        assert!(job_spec_admission(Some(JOB_AUTH_SIGNED), &spec).is_ok());
    }

    #[test]
    fn job_control_is_tenant_bound_and_rejects_unsafe_ids() {
        let tenant = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
        let mut request = JobControlRequest { tenant_id: tenant.into(), job_id: "job-1".into(), attempt_id: "attempt-1".into() };
        assert!(job_key(&request, tenant).is_ok());
        assert!(job_key(&request, "another-tenant").is_err());
        request.attempt_id = "../other".into();
        assert!(job_key(&request, tenant).is_err());
    }

    #[test]
    fn cell_job_attempts_survive_restart_without_resuming_inflight_work() {
        let state = tempfile::tempdir().unwrap();
        let tenant = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
        let mut jobs = BTreeMap::new();
        jobs.insert(("completed".into(), "attempt-1".into()), JobRecord {
            status: "completed", cancelled: Arc::new(AtomicBool::new(false)),
            result: Some(crate::job::ResultArtifactRef {
                manifest_uri: "file:///tenant/result/manifest.json".into(),
                manifest_sha256: "a".repeat(64), rows: 2, parts: 1,
                has_more: false, page_rows: 100,
            }),
        });
        jobs.insert(("running".into(), "attempt-2".into()), JobRecord {
            status: "running", cancelled: Arc::new(AtomicBool::new(false)), result: None,
        });
        jobs.insert(("cancel".into(), "attempt-3".into()), JobRecord {
            status: "cancel_requested", cancelled: Arc::new(AtomicBool::new(true)), result: None,
        });
        persist_job_records(state.path(), tenant, &jobs).unwrap();
        let recovered = load_job_records(state.path(), tenant).unwrap();
        assert_eq!(recovered[&("completed".into(), "attempt-1".into())].status, "completed");
        assert_eq!(recovered[&("completed".into(), "attempt-1".into())].result.as_ref().unwrap().rows, 2);
        assert_eq!(recovered[&("running".into(), "attempt-2".into())].status, "failed");
        assert_eq!(recovered[&("cancel".into(), "attempt-3".into())].status, "cancelled");
        assert!(load_job_records(state.path(), "another-tenant").is_err());
    }

    #[test]
    fn cell_result_page_refuses_known_cancelled_or_mismatched_attempt() {
        let state = tempfile::tempdir().unwrap();
        let tenant = "b464ceb9-28a6-4249-8e29-3489627ac5f6";
        let reference = crate::job::ResultArtifactRef {
            manifest_uri: "file:///tenant/result/manifest.json".into(),
            manifest_sha256: "a".repeat(64), rows: 2, parts: 1,
            has_more: false, page_rows: 100,
        };
        let completed = ("job".to_string(), "completed".to_string());
        let cancelled = ("job".to_string(), "cancelled".to_string());
        let mut records = BTreeMap::new();
        records.insert(completed.clone(), JobRecord {
            status: "completed", cancelled: Arc::new(AtomicBool::new(false)),
            result: Some(reference.clone()),
        });
        records.insert(cancelled.clone(), JobRecord {
            status: "cancelled", cancelled: Arc::new(AtomicBool::new(true)), result: None,
        });
        persist_job_records(state.path(), tenant, &records).unwrap();
        let recovered = load_job_records(state.path(), tenant).unwrap();
        assert!(job_page_record_allows(&recovered, &completed, &reference));
        assert!(!job_page_record_allows(&recovered, &cancelled, &reference));
        let mut changed = reference.clone();
        changed.manifest_sha256 = "b".repeat(64);
        assert!(!job_page_record_allows(&recovered, &completed, &changed));
        // The coordinator can retain an older result after this local map's
        // 1,024-entry trim; its manifest still has tenant/job/digest checks.
        assert!(job_page_record_allows(&recovered, &("old".into(), "attempt".into()), &reference));
    }

    #[test]
    fn identity_snapshot_is_verified_and_confined_to_the_tenant_state_dir() {
        let root = tempfile::tempdir().unwrap();
        let identity = root.path().join("identity");
        std::fs::create_dir(&identity).unwrap();
        let path = identity.join("by-ip.parquet");
        std::fs::write(&path, b"fixture").unwrap();
        let digest = crate::native::file_sha256(&path).unwrap();
        let mut boot = QueryBootstrap {
            format: BOOTSTRAP_FORMAT.into(), tenant_id: "tenant".into(), bucket: "bucket".into(), r2: None, enrichment_r2: None, part_write_r2: None, part_log_r2: None, job_results_r2: None, trusted_local_job_results: None,
            trusted_signer_keys: vec![],
            engine: EngineBoot { chdb_library: "/unused".into(), chdb_sha256: "0".repeat(64),
                compiler: "/unused".into(), max_query_bytes: 1_024, max_execution_seconds: 1,
                cache_bytes: None, cache_query_bytes: None, cache_heavy_concurrency: None, prewarm_hours: 24, prewarm_gates_readiness: false },
            identity_snapshot: Some(QueryIdentitySnapshotBoot { snapshot_id: "s1".into(),
                by_ip: crate::config::VerifiedArtifact { path: path.clone(), sha256: digest } }),
            expires_at: None,
        };
        assert!(load_identity_snapshot(&boot, root.path()).unwrap().is_some());
        boot.identity_snapshot.as_mut().unwrap().by_ip.sha256 = "f".repeat(64);
        assert!(load_identity_snapshot(&boot, root.path()).is_err());
        let sibling = tempfile::tempdir().unwrap();
        boot.identity_snapshot.as_mut().unwrap().by_ip.path = sibling.path().join("by-ip.parquet");
        std::fs::write(sibling.path().join("by-ip.parquet"), b"fixture").unwrap();
        assert!(load_identity_snapshot(&boot, root.path()).is_err());
    }

}

/// VmRSS / RssAnon / VmHWM in bytes (the section 4 budget facts).
pub fn process_memory() -> Value {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut out = serde_json::Map::new();
    for line in status.lines() {
        if let Some((key, value)) = line.split_once(':') {
            if matches!(key, "VmRSS" | "RssAnon" | "RssFile" | "VmHWM") {
                let kib = value.split_whitespace().next().and_then(|value| value.parse::<u64>().ok()).unwrap_or(0);
                out.insert(key.to_string(), json!(kib * 1024));
            }
        }
    }
    Value::Object(out)
}

#[async_trait::async_trait]
impl nanosiem_lake_cell::child::TenantService for QueryService {
    async fn handle_rpc(self: Arc<Self>, _request_id: u64, stream: tokio::net::UnixStream) {
        self.serve_stream(stream).await;
    }

    async fn wake(self: Arc<Self>, reason: nanosiem_lake_cell::contract::WakeReason) {
        // Data arrival (a local notify from ingest via the supervisor),
        // a due detection, or pre-warm: all start with a log catch-up.
        if let Err(error) = self.refresh_now().await {
            tracing::warn!(reason = reason.as_str(), error = %error, "part log catch-up failed on wake");
        } else {
            self.last_progress_ms.store(now_ms(), Ordering::Relaxed);
            if matches!(reason, nanosiem_lake_cell::contract::WakeReason::Prewarm)
                && self.readiness.is_ready() {
                self.clone().spawn_incremental_prewarm();
            }
        }
    }

    fn heartbeat(&self) -> nanosiem_lake_cell::contract::Heartbeat {
        let inflight = self.inflight.load(Ordering::Relaxed);
        nanosiem_lake_cell::contract::Heartbeat {
            startup_progress: None,
            busy: inflight > 0,
            lag_seconds: 0.0,
            oldest_unmerged_l0_age_seconds: 0.0,
            l0_merge_overdue_seconds: 0.0,
            prevalence_behind_seconds: 0.0,
            prevalence_behind_entries: 0,
            prevalence_degraded_seconds: 0.0,
            prevalence_degraded_seconds_total: 0.0,
            last_progress_unix_ms: self.last_progress_ms.load(Ordering::Relaxed),
            queue_depth: inflight,
            objects_rejected: 0,
            rows_rejected: 0,
            retrying: false,
            detail: None,
            part_gc_blocked: None,
            part_gc_deleted_total: 0,
            rows_committed_total: 0,
            credential_refresh_at_risk: self.credentials.get().is_some_and(|credentials| credentials.refresher.at_risk()),
            identity_directory: None,
            selection_evidence_cache: Some(self.engine().selection_evidence_status()),
        }
    }

    /// A fresh bootstrap secret (after `request_secrets`): re-exchange and
    /// swap the read credentials in place (NAN-3017).
    async fn secrets(self: Arc<Self>, secret: zeroize::Zeroizing<Vec<u8>>) {
        match self.credentials.get() {
            Some(credentials) => credentials.on_secret(&secret).await,
            None => tracing::warn!("fresh bootstrap secret arrived but this query process holds no refreshable credentials"),
        }
    }

    /// Drain (NAN-3177): the supervisor routes nothing new to a stopping
    /// process, so let the requests already in flight answer, up to `grace`
    /// (the supervisor kills at `grace` + 500 ms).
    async fn shutdown(self: Arc<Self>, grace: Duration) {
        let deadline = Instant::now() + grace;
        while self.inflight.load(Ordering::SeqCst) > 0 && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        let left = self.inflight.load(Ordering::SeqCst);
        if left > 0 {
            tracing::warn!(inflight = left, grace_ms = grace.as_millis() as u64, "query shutdown: requests still in flight at the grace bound");
        }
    }
}

/// NAN-2916: cross-tenant denial over a real S3-compatible object store.
///
/// A disposable RustFS container stands in for R2. Its STS AssumeRole with an
/// inline session policy plays the Cloudflare temporary-credential issuer:
/// each tenant gets exactly the scoped credentials the detect exchange hands
/// out (tenant read-only, plus read-write on `parts/` and
/// `finding-outbox/receipts/`). Everything after the issuer is the production
/// path: the detect credential exchange and its validation, then
/// `R2PartStore::new_split_read` for finding/risk part reads and checksummed
/// conditional PUTs. Run by `scripts/validate-risk-object-store-scope.sh`.
#[cfg(test)]
mod object_store_scope_tests {
    use super::{resolve_detect_bootstrap, ExchangedCredential};
    use crate::part_ingest::r2_put::{uri_encode_path, R2PartStore, SigV4, TerminalPutError};
    use crate::part_ingest::s3_store::S3Location;
    use crate::parts::format::{PartId, PartKeys};
    use crate::parts::levels::Level;
    use crate::parts::part_log::{ObjectStore, WriterClass};
    use sha2::{Digest, Sha256};

    const A: &str = "00000000-0000-4000-8000-00000000000a";
    const B: &str = "00000000-0000-4000-8000-00000000000b";
    /// Fixture-only root credentials of the disposable container.
    pub(crate) const FIXTURE_ACCESS_KEY: &str = "nanofixtureaccess";
    pub(crate) const FIXTURE_SECRET_KEY: &str = "nanofixturesecret-only";
    const REGION: &str = "us-east-1";
    const BUCKET: &str = "nano-risk-scope";

    fn endpoint() -> String {
        let endpoint = std::env::var("NANO_RISK_S3_ENDPOINT").expect("disposable S3 endpoint");
        assert!(endpoint.starts_with("http://127.0.0.1:"), "loopback fixture only");
        endpoint
    }

    fn encode(value: &str) -> String {
        uri_encode_path(value).replace('/', "%2F")
    }

    fn xml(text: &str, tag: &str) -> String {
        text.split(&format!("<{tag}>")).nth(1).and_then(|rest| rest.split(&format!("</{tag}>")).next())
            .unwrap_or_else(|| panic!("STS response lacks {tag}: {text}")).to_owned()
    }

    /// One signed request with the fixture root identity.
    async fn root_request(method: reqwest::Method, service: &str, path: &str, body: String, form: bool) -> reqwest::Response {
        let endpoint = endpoint();
        let host = endpoint.trim_start_matches("http://").to_owned();
        let date = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
        let payload = hex::encode(Sha256::digest(body.as_bytes()));
        let mut headers = vec![("host".to_owned(), host), ("x-amz-date".to_owned(), date.clone()),
            ("x-amz-content-sha256".to_owned(), payload.clone())];
        if form {
            headers.push(("content-type".to_owned(), "application/x-www-form-urlencoded".to_owned()));
        }
        let signer = SigV4 { access_key_id: FIXTURE_ACCESS_KEY.into(), secret_access_key: FIXTURE_SECRET_KEY.into(),
            session_token: None, region: REGION.into(), service: service.into() };
        let authorization = signer.authorization(method.as_str(), path, &headers, &payload, &date).unwrap();
        let mut request = reqwest::Client::new().request(method, format!("{endpoint}{path}"))
            .header(reqwest::header::AUTHORIZATION, authorization);
        for (name, value) in headers.iter().filter(|(name, _)| name != "host") {
            request = request.header(name.as_str(), value.as_str());
        }
        request.body(body).send().await.unwrap()
    }

    /// The issuer stand-in: a temporary credential whose session policy
    /// grants `permission` on exactly `prefixes`, like R2's `prefixes`.
    async fn issue(class: &str, permission: &str, prefixes: &[String]) -> serde_json::Value {
        let actions: &[&str] = match permission {
            "object-read-only" => &["s3:GetObject"],
            "object-read-write" => &["s3:GetObject", "s3:PutObject"],
            other => panic!("unknown permission {other}"),
        };
        let resources: Vec<String> = prefixes.iter().map(|prefix| format!("arn:aws:s3:::{BUCKET}/{prefix}*")).collect();
        let policy = serde_json::json!({"Version": "2012-10-17", "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resources}]}).to_string();
        let body = format!("Action=AssumeRole&Version=2011-06-15&DurationSeconds=3600&RoleSessionName={}&Policy={}",
            encode(&format!("nan2916-{class}")), encode(&policy));
        let response = root_request(reqwest::Method::POST, "sts", "/", body, true).await;
        let status = response.status();
        let text = response.text().await.unwrap();
        assert!(status.is_success(), "AssumeRole refused ({status}): {text}");
        serde_json::json!({
            "credential_class": class, "permission": permission, "prefixes": prefixes,
            "endpoint": endpoint(), "region": REGION, "bucket": BUCKET,
            "access_key_id": xml(&text, "AccessKeyId"), "secret_access_key": xml(&text, "SecretAccessKey"),
            "session_token": xml(&text, "SessionToken"),
            "expires_at": (chrono::Utc::now() + chrono::Duration::minutes(50)).to_rfc3339(),
        })
    }

    async fn detect_exchange(tenant: &str) -> serde_json::Value {
        let prefix = format!("lake/parts/v1/tenant={tenant}/");
        let expiry = "2099-01-01T00:00:00Z";
        serde_json::json!({
            "schema_version": 1, "tenant_id": tenant, "role": "detect",
            "assignment_generation": 1, "writer_epoch": 1,
            "credentials": [
                issue("lake_part_read", "object-read-only", &[prefix.clone()]).await,
                issue("lake_part", "object-read-write",
                    &[format!("{prefix}parts/"), format!("{prefix}finding-outbox/receipts/")]).await,
            ],
            "trusted_keys": [],
            "query_engine": {"chdb_library":"/native", "chdb_sha256":"a".repeat(64), "compiler":"/compiler"},
            "owner_sign": {"token":"owner", "audience":"owner", "scope":"lake-parts:sign", "expires_at":expiry},
            "finding_drain": {"tenant_id":tenant, "capability":"finding_drain",
                "database_url":"postgres://drain@127.0.0.1/tenant", "expires_at":expiry}
        })
    }

    /// Serve `body` as the cell credential exchange and resolve it through
    /// the production detect bootstrap.
    async fn exchange(tenant: &str, body: serde_json::Value) -> anyhow::Result<super::DetectBootstrap> {
        let app = axum::Router::new().route("/v1/lake/cells/cell/credential-exchange",
            axum::routing::post(move || { let body = body.clone(); async move { axum::Json(body) } }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let result = resolve_detect_bootstrap(b"token", tenant, "cell", Some(&format!("http://{addr}"))).await;
        server.abort();
        result
    }

    fn location(credential: &ExchangedCredential) -> S3Location {
        // Same mapping as lake_part_query's detect drain.
        S3Location { endpoint: credential.endpoint.clone(), region: credential.region.clone(),
            bucket: credential.bucket.clone(), prefix: String::new(),
            access_key_id: credential.access_key_id.clone(), secret_access_key: credential.secret_access_key.clone(),
            session_token: Some(credential.session_token.clone()) }
    }

    fn store(bootstrap: &super::DetectBootstrap, bound_tenant: &str, spill: &std::path::Path) -> R2PartStore {
        R2PartStore::new_split_read(&location(&bootstrap.part), &location(&bootstrap.log), bound_tenant, spill).unwrap()
    }

    fn finding_keys(tenant: &str, label: &str) -> (String, String) {
        let hour = (chrono::Utc::now().timestamp() / 3_600) as i32;
        let part = PartId::new(chrono::Utc::now().timestamp_millis()).unwrap();
        let keys = PartKeys::new(tenant, Level::L0, hour, &part).unwrap();
        let receipt = hex::encode(Sha256::digest(format!("{tenant}/{label}").as_bytes()));
        (keys.file("partials/risk.parquet"),
            format!("lake/parts/v1/tenant={tenant}/finding-outbox/receipts/{receipt}.json"))
    }

    async fn put(store: &R2PartStore, dir: &std::path::Path, key: &str, bytes: &[u8]) -> anyhow::Result<bool> {
        let path = dir.join(hex::encode(Sha256::digest(key.as_bytes())));
        std::fs::write(&path, bytes).unwrap();
        store.put_file_if_absent(key, &path, &hex::encode(Sha256::digest(bytes)), bytes.len() as u64, WriterClass::LakePart).await
    }

    fn status_403(error: &anyhow::Error) -> bool {
        error.downcast_ref::<TerminalPutError>().is_some_and(|put| put.status == 403)
    }

    #[tokio::test]
    #[ignore = "requires scripts/validate-risk-object-store-scope.sh (disposable RustFS)"]
    async fn tenant_b_credentials_cannot_read_or_write_tenant_a_finding_parts() {
        let created = root_request(reqwest::Method::PUT, "s3", &format!("/{BUCKET}"), String::new(), false).await;
        assert!(created.status().is_success(), "fixture bucket: {}", created.status());
        let dir = tempfile::tempdir().unwrap();
        let a = exchange(A, detect_exchange(A).await).await.expect("tenant A detect exchange");
        let b = exchange(B, detect_exchange(B).await).await.expect("tenant B detect exchange");

        // The exchange itself refuses B's credentials presented as A's.
        let mut foreign = detect_exchange(B).await;
        foreign["tenant_id"] = serde_json::json!(A);
        foreign["finding_drain"]["tenant_id"] = serde_json::json!(A);
        assert!(exchange(A, foreign).await.is_err(), "B-scoped credentials accepted for tenant A");

        // Tenant A: its own finding risk partial and receipt round-trip.
        let store_a = store(&a, A, &dir.path().join("spill-a"));
        let (a_part, a_receipt) = finding_keys(A, "a");
        for (key, body) in [(&a_part, b"tenant-a risk partial".as_slice()), (&a_receipt, b"{\"tenant\":\"a\"}".as_slice())] {
            assert!(put(&store_a, dir.path(), key, body).await.unwrap(), "A write {key}");
            assert_eq!(store_a.get(key).await.unwrap().as_deref(), Some(body), "A read {key}");
        }

        // Tenant B's properly bound store: refused before any request.
        let store_b = store(&b, B, &dir.path().join("spill-b"));
        let (b_part, _) = finding_keys(B, "b");
        assert!(put(&store_b, dir.path(), &b_part, b"tenant-b").await.unwrap(), "B's own prefix works");
        assert!(store_b.get(&b_part).await.unwrap().is_some());
        let (a_new_part, a_new_receipt) = finding_keys(A, "from-b");
        for key in [&a_part, &a_receipt] {
            assert!(store_b.get(key).await.is_err(), "B store read {key}");
        }
        for key in [&a_new_part, &a_new_receipt, &a_part] {
            assert!(put(&store_b, dir.path(), key, b"forged").await.is_err(), "B store write {key}");
        }

        // B's credentials wired to tenant A's prefix (a misbound store):
        // the object store itself denies both directions.
        let misbound = store(&b, A, &dir.path().join("spill-misbound"));
        for key in [&a_part, &a_receipt] {
            let error = misbound.get(key).await.expect_err("B credential read A's object");
            assert!(error.to_string().contains("PermissionDenied") || error.to_string().contains("403"), "{error:#}");
        }
        for key in [&a_new_part, &a_new_receipt, &a_part] {
            let error = put(&misbound, dir.path(), key, b"forged").await.expect_err("B credential wrote A's prefix");
            assert!(status_403(&error), "{error:#}");
        }

        // Nothing B attempted exists or changed under A.
        assert_eq!(store_a.get(&a_part).await.unwrap().as_deref(), Some(b"tenant-a risk partial".as_slice()));
        assert_eq!(store_a.get(&a_receipt).await.unwrap().as_deref(), Some(b"{\"tenant\":\"a\"}".as_slice()));
        for key in [&a_new_part, &a_new_receipt] {
            assert_eq!(store_a.get(key).await.unwrap(), None, "{key} was created");
        }
        // A's read-only credential cannot reach B either.
        let a_misbound = store(&a, B, &dir.path().join("spill-a-misbound"));
        assert!(a_misbound.get(&b_part).await.is_err());
    }
}

#[cfg(test)]
mod cold_budget_tests {
    use super::*;

    /// NAN-3644: only the reader's ceiling refuses a cold read; its body
    /// carries the bytes and the durable ceiling a background job would get.
    #[tokio::test]
    async fn cold_ceiling_http_preserves_metadata_for_fetch_and_anyhow_paths() {
        let typed = PartQueryError::ColdScanTooLarge { needed_bytes: 14_800_000_000, ceiling_bytes: 4_800_000_000, background_bytes: 9_600_000_000 };
        let again = PartQueryError::ColdScanTooLarge { needed_bytes: 14_800_000_000, ceiling_bytes: 4_800_000_000, background_bytes: 9_600_000_000 };
        for error in [
            ApiError::from(typed),
            ApiError::from(anyhow::Error::new(again).context("job read")),
            ApiError::from(anyhow::Error::new(crate::reader_object_cache::ReaderCacheError::ScanTooLarge {
                required_bytes: 14_800_000_000, ceiling_bytes: 4_800_000_000, background_bytes: 9_600_000_000,
            }).context("fetch selected parts")),
        ] {
            let response = error.into_response();
            assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
            assert!(!response.headers().contains_key(axum::http::header::RETRY_AFTER));
            let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["reason"], "cold_scan_too_large");
            assert_eq!(body["needed_bytes"], 14_800_000_000_u64);
            assert_eq!(body["ceiling_bytes"], 4_800_000_000_u64);
            assert_eq!(body["background_ceiling_bytes"], 9_600_000_000_u64);
            assert_eq!(body["retryable"], false);
        }
    }

    /// NAN-3272: a job statement that waited out the read-write lane is a
    /// typed retryable refusal, whether the executor error survived typed or
    /// was flattened to text by a view read (`anyhow!(error.to_string())`).
    #[tokio::test]
    async fn lane_wait_timeout_is_a_typed_retryable_refusal() {
        let typed = anyhow::Error::new(crate::executor::ExecutorError::LaneWaitTimeout).context("view read");
        let flattened = anyhow::anyhow!("Search dependency is temporarily unavailable: {}",
            crate::executor::ExecutorError::LaneWaitTimeout);
        for error in [typed, flattened] {
            assert!(is_lane_wait_timeout(&error));
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["reason"], "lane_wait_timeout");
        }
        assert!(!is_lane_wait_timeout(&anyhow::anyhow!("query execution failed: syntax")));
    }

    /// NAN-3883: a durable job's cold fetch that outlived its deadline is a
    /// typed retryable refusal (the runner re-sends it warm), typed or
    /// flattened to the part path's "temporarily unavailable" text.
    #[tokio::test]
    async fn cold_fetch_timeout_is_a_typed_retryable_refusal() {
        let typed = anyhow::Error::new(crate::reader_object_cache::ReaderCacheError::FetchTimeout).context("fetch selected parts");
        let flattened = anyhow::anyhow!("part data is temporarily unavailable: {}",
            crate::reader_object_cache::ReaderCacheError::FetchTimeout);
        for error in [typed, flattened] {
            assert!(is_cold_fetch_timeout(&error));
            let response = ApiError::from(error).into_response();
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let bytes = axum::body::to_bytes(response.into_body(), 4096).await.unwrap();
            let body: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(body["reason"], "cold_fetch_timeout");
        }
        assert!(!is_cold_fetch_timeout(&anyhow::anyhow!("cold object fetch failed: 403")));
    }
}

/// NAN-3141: a request future's poll frame lives on a tokio worker stack.
/// The `query` handler future reached ~1 MiB (nested wrappers holding their
/// work inline 2-3x each) and its poll frame (~2.3 MiB in release)
/// overflowed the worker stack: SIGSEGV on the guard page. Every route's
/// future must stay small; wrap large inner work in `Box::pin`.
#[cfg(test)]
mod future_size_tests {
    use super::*;

    /// Per-future budget. The fixed handlers are a few KiB.
    pub(crate) const FUTURE_BUDGET_BYTES: usize = 256 * 1024;

    fn r1<A, R>(_: impl FnOnce(A) -> R) -> usize { std::mem::size_of::<R>() }
    fn r2<A, B, R>(_: impl FnOnce(A, B) -> R) -> usize { std::mem::size_of::<R>() }
    fn r3<A, B, C, R>(_: impl FnOnce(A, B, C) -> R) -> usize { std::mem::size_of::<R>() }
    fn s1<A: 'static + ?Sized, R>(_: impl FnOnce(&'static A) -> R) -> usize { std::mem::size_of::<R>() }
    fn s2<A: 'static + ?Sized, B: 'static + ?Sized, R>(_: impl FnOnce(&'static A, &'static B) -> R) -> usize { std::mem::size_of::<R>() }

    #[test]
    fn request_futures_stay_under_the_stack_budget() {
        let sizes: Vec<(&str, usize)> = vec![
            ("query", r3(query)),
            ("query_pages", r3(query_pages)),
            ("count", r2(count)),
            ("prevalence_lookup", r2(prevalence_lookup)),
            ("prevalence_detail", r2(prevalence_detail)),
            ("prevalence_explorer", r2(prevalence_explorer)),
            ("entity_ranges", r2(entity_ranges)),
            ("risk_route", r2(risk_route)),
            ("ioc_lookup", r2(ioc_lookup)),
            ("ioc_indicator_sets", r2(ioc_indicator_sets)),
            ("ioc_source_records", r2(ioc_source_records)),
            ("detection_plan", r2(detection_plan)),
            ("detection_commit", r2(detection_commit)),
            ("detection_reset", r2(detection_reset)),
            ("job_search", r3(job_search)),
            ("job_status", r2(job_status)),
            ("job_cancel", r2(job_cancel)),
            ("identity_resolve", r2(identity_resolve)),
            ("identity_resolve_batch", r2(identity_resolve_batch)),
            ("identity_resolve_entity_batch", r2(identity_resolve_entity_batch)),
            ("job_page", r2(job_page)),
            ("schema_manifest", r1(schema_manifest)),
            ("status", r1(status)),
            ("cached_broad_npl", s2::<QueryService, BroadNplRequest, _>(cached_broad_npl)),
            ("service.refresh", s1::<Arc<QueryService>, _>(QueryService::refresh)),
            ("service.serve_stream", r2(QueryService::serve_stream)),
            ("engine.broad_npl", s2::<PartQueryEngine, BroadNplRequest, _>(PartQueryEngine::broad_npl)),
            ("engine.explain_npl", s2::<PartQueryEngine, BroadNplRequest, _>(PartQueryEngine::explain_npl)),
            ("engine.fetch_log", s2::<PartQueryEngine, FetchLogRequest, _>(PartQueryEngine::fetch_log)),
            ("risk::broad_npl", r3(|e: &'static PartQueryEngine, d: &'static Path, r: &'static BroadNplRequest| risk::broad_npl(e, d, r))),
        ];
        for (name, size) in &sizes {
            eprintln!("future {name}: {size} bytes");
        }
        let over: Vec<_> = sizes.iter().filter(|(_, size)| *size > FUTURE_BUDGET_BYTES).collect();
        assert!(over.is_empty(), "request futures over the {FUTURE_BUDGET_BYTES}-byte stack budget (Box::pin the large inner work): {over:?}");
    }
}
