// SPDX-License-Identifier: AGPL-3.0-or-later

//! `ingest[T]` as a lean-lake cell child (NAN-2871 contract).
//!
//! The supervisor starts the binary with `--cell-control-fd 3`; `main` calls
//! `nanosiem_lake_cell::child::bootstrap()` before any runtime or thread, so
//! the process is already jailed (tenant uid, landlock, seccomp) when this
//! module runs. The only secret is the bootstrap blob delivered over the
//! sealed memfd; it never touches argv, env or a file.
//!
//! Discovery is DO-notified: a `Wake(DataArrival)` from the supervisor makes
//! the loop pull pending notices from the tenant's raw-handoff DO
//! ([`DoNoticeQueue`]) and ack them after the log commit. The bucket is never
//! listed.

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use ed25519_dalek::{SigningKey, VerifyingKey};
use nanosiem_lake_cell::child::{ControlChannel, TenantService};
use nanosiem_lake_cell::contract::{Assignment, Heartbeat, PartSigning, Role, WakeReason};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::io::AsyncReadExt;
use zeroize::Zeroizing;

use super::discovery::{NoticeHandle, NoticeQueue, SourceNotice};
use super::ingest::{seed_schema, FindingAppendContext, IngestConfig, Ingestor};
use super::finding_append::{FindingAppendRequest, MAX_REQUEST_BYTES};
use super::finding_gate::{FindingGate, FindingGateConfig};
use super::stall_watchdog::{EDGE_STALL_HARD_AFTER, EDGE_STALL_RESTART_AFTER, EDGE_STALL_SAMPLE_EVERY};
use super::part_gc_cell::{CellSanctionedPartGc, LakePartGcAccess};
use super::part_gc_gate::{ExchangedGrantAuthority, LakePartDeleteGrant, SanctionedPartGc};
use super::s3_store::{S3Location, S3ObjectStore};
use super::prevalence_owner_store::{OwnerAccess, PrevalenceAccess};
use crate::cell_refresh::CredentialRefresher;
#[cfg(test)]
use crate::cell_refresh::RefreshState;
use crate::enrichment::BronzeIngestEnricher;
use crate::lean_enrichment_snapshot::{LeanEnrichmentSnapshots, SnapshotPointer};
use crate::lean_ip_context::LeanIpContextSnapshots;
use crate::identity_enrichment::{IdentityDirectoryHandle, LeanIdentityDirectories};
use crate::lean_platform_bundle::{PlatformBundle, PlatformBundleSource, TenantPlatformPolicy};
use crate::parts::part_log::{LocalObjectStore, ObjectStore};
use crate::parts::provenance::{
    plan_sign_requests, Ed25519Signature, LocalPartSigner, PartSigner, ProvenanceRecord, SignRequest, SignResponse,
    SignedProvenance, TenantKeySet, OWNER_SIGN_BODY_MAX_BYTES, SIGN_REQUEST_BUDGET_BYTES,
};

pub const LAB_CREDENTIALS_KIND: &str = "nano.lake.ingest-lab-credentials.v1";
/// Exit after this long with no admitted rows, pending notices or merges.
pub const IDLE_EXIT: Duration = Duration::from_secs(600);

/// The raw-handoff DO's notice endpoint for this tenant.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoticeEndpoint {
    pub url: String,
    pub bearer: String,
}

/// The owner-sign bearer the credential exchange returns for role=ingest
/// (the platform): scoped to `lake-parts:sign` + tenant + cell + role,
/// TTL ≤ 10 min. Where to send it and which keys to trust come from the
/// release-pinned `Assignment::part_signing`, never from the exchange.
#[derive(Clone, Deserialize)]
pub struct OwnerSignBearer {
    pub token: String,
    pub audience: String,
    pub scope: String,
    /// Absent: re-exchanged on the conservative schedule
    /// (`cell_refresh::owner_bearer_expiry`), never held until a 401.
    #[serde(default)]
    pub expires_at: String,
}

/// One R2 credential from the exchange (the platform `LakeCellCredential`).
#[derive(Clone, Deserialize)]
pub struct ExchangedR2Credential {
    pub credential_class: String,
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    pub permission: String,
    pub prefixes: Vec<String>,
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: String,
    pub expires_at: String,
}

/// `POST {control_url}/v1/lake/cells/{cell_id}/credential-exchange` response.
#[derive(Deserialize)]
pub struct ExchangeResponse {
    #[serde(default)]
    pub owner_write: Option<super::native_writer::WritePermission>,
    pub schema_version: u8,
    pub tenant_id: String,
    pub role: String,
    /// The committed assignment writer epoch. Optional: live the platform does
    /// not send it yet (see [`ingest_writer_epoch`]).
    #[serde(default)]
    pub writer_epoch: Option<u64>,
    pub credentials: Vec<ExchangedR2Credential>,
    #[serde(default)]
    pub owner_sign: Option<OwnerSignBearer>,
    #[serde(default)]
    pub prevalence_owner: Option<OwnerAccess>,
    #[serde(default)]
    pub notices: Option<NoticeEndpoint>,
    /// Lean tenants (no bronze): the edge-log consumer credential (the platform
    /// #1556). Held in memory only.
    #[serde(default)]
    pub edge_log_consumer_token: Option<String>,
    #[serde(default)]
    pub edge_log_consumer_endpoint: Option<String>,
    /// The tenant's lake_part delete grant (LEAN-CELL-FEATURES-NANO-MAIN.md
    /// section 7). Kept raw: an unreadable grant closes the delete gate
    /// instead of failing the exchange (`part_gc_gate`).
    #[serde(default)]
    pub lake_part_delete_grant: Option<serde_json::Value>,
    /// The sanctioned delete route (`lean_part_gc_sanctioned_v1`,
    /// LAKE-PART-GC-NANO-MAIN.md). Kept raw like the grant: unreadable
    /// withholds the route, never fails the exchange.
    #[serde(default)]
    pub lake_part_gc: Option<serde_json::Value>,
    /// NAN-3867: the tenant's `publish` data-path login for its erasure work
    /// orders (`lean_erasure_v1` images only). Kept raw: unreadable leaves
    /// the executor idle, never fails the exchange.
    #[serde(default)]
    pub erasure_ledger: Option<serde_json::Value>,
    /// NAN-4137, role=landing only: the tenant Worker's landing credential
    /// (`NANO_LANDING_AUTH_TOKEN`; TZ-FRONT CONTRACT.md B): the ledger
    /// routes `/landing-ledger/v1/*` and the producer route
    /// `/edge-log/v1/produce`, never pull/commit. Held in memory only.
    #[serde(default)]
    pub landing_token: Option<String>,
    /// The tenant Worker origin serving those routes (`https://<slug>.ingest.nano.rs`).
    #[serde(default)]
    pub landing_endpoint: Option<String>,
}

/// Credential class that reads the tenant's Vector bronze objects.
/// Read-only only: ingest never falls back to a read-write class for bronze
/// reads (the platform's exchange must grant `bronze_reader` to role ingest).
pub const BRONZE_READ_CLASSES: &[&str] = &["bronze_reader"];

/// The only R2 classes a lean (edge-log) tenant's ingest receives.
pub const LEAN_EDGE_CLASSES: &[&str] = &["lake_part", "lake_part_log", "lake_prevalence_state"];

/// Every credential class ingest can consume, declared in the exchange
/// request as `accepts`. The platform mints nothing outside it, and a
/// response carrying any other class (or one class twice) is refused.
pub const INGEST_ACCEPTS: &[&str] = &["bronze_reader", "lake_part", "lake_part_log", "lake_prevalence_state", "enrichment_reader"];

/// What ingest runs with. Only the lab form carries a signing seed.
/// Where ingest[T] reads its input.
pub enum InputCreds {
    /// Lab / legacy: Vector bronze objects announced on a notice endpoint.
    Bronze { bronze: S3Location, notices: NoticeEndpoint },
    /// Lean tenants: the tenant's edge-log Durable Object.
    Edge { endpoint: String, token: Zeroizing<String> },
    /// Trusted-local single-tenant installs (NAN-3492): Vector bronze
    /// objects discovered by listing the tenant prefix with a durable
    /// cursor ([`super::bronze_list::BronzeListQueue`]). Lab credentials
    /// only; no exchange ever returns it.
    BronzeListed { bronze: S3Location, settings: super::bronze_list::BronzeListSettings },
}

/// The `lake_part` / `lake_part_log` write credentials (the tenant's
/// `lake/parts/v1/` prefix).
#[derive(Clone)]
pub struct PartCreds {
    pub part: S3Location,
    pub log: S3Location,
}

pub struct IngestCredentials {
    pub native_writer: Option<Arc<super::native_writer::NativePartWriter>>,
    pub writer_epoch: u64,
    pub input: InputCreds,
    /// R2 part-store credentials; `None` in the lab (local parts dir).
    pub parts: Option<PartCreds>,
    pub prevalence: Option<PrevalenceAccess>,
    pub enrichment: Option<S3Location>,
    pub signer: Box<dyn PartSigner>,
    pub trusted: TenantKeySet,
    /// When the shortest-lived credential (R2 or bearer) expires; `None`
    /// for lab credentials.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// The owner-sign bearer (production only).
    pub bearer: Option<Zeroizing<String>>,
    /// The raw lake_part delete grant from the exchange, if any.
    pub part_delete_grant: Option<serde_json::Value>,
    /// The sanctioned lake-part delete route, if delivered and readable.
    pub part_gc: Option<LakePartGcAccess>,
    pub local_gc: Option<LocalGcConfig>,
    /// NAN-3867: the erasure work-order ledger login, if delivered.
    pub erasure_ledger: Option<super::lean_erasure::ErasureLedgerCredential>,
}

/// Opt-in open-core retention. Only parsed from local credentials, never
/// from hosted credential exchange. The URL stays in the root-owned key file.
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalGcConfig {
    pub database_url: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LabCredentials {
    kind: String,
    tenant_id: String,
    writer_epoch: u64,
    #[serde(default)]
    bronze: Option<S3Location>,
    #[serde(default)]
    enrichment: Option<S3Location>,
    #[serde(default)]
    notices: Option<NoticeEndpoint>,
    /// Trusted-local (NAN-3492): list `bronze` instead of pulling notices.
    #[serde(default)]
    bronze_list: Option<super::bronze_list::BronzeListSettings>,
    #[serde(default)]
    edge_log_consumer_token: Option<String>,
    #[serde(default)]
    edge_log_consumer_endpoint: Option<String>,
    /// Lab only: an in-process stand-in for the owner signer.
    lab_signer_key_id: String,
    lab_signer_seed_hex: String,
    #[serde(default)]
    local_gc: Option<LocalGcConfig>,
}

/// The trusted key set from the release-pinned cell config.
pub fn trusted_from(signing: &PartSigning) -> Result<TenantKeySet> {
    let mut out = Vec::new();
    for key in &signing.trusted_keys {
        let bytes: [u8; 32] =
            hex::decode(&key.public_key_hex)?.try_into().map_err(|_| anyhow::anyhow!("public key must be 32 bytes"))?;
        out.push((key.key_id.clone(), VerifyingKey::from_bytes(&bytes)?));
    }
    ensure!(!out.is_empty(), "no trusted signer keys");
    Ok(TenantKeySet::new(out))
}

/// The fresh credentials one exchange yields (production path).
pub struct Exchanged {
    pub write_permission: Option<super::native_writer::WritePermission>,
    pub writer_epoch: u64,
    pub input: InputCreds,
    pub parts: Option<PartCreds>,
    pub prevalence: Option<PrevalenceAccess>,
    pub enrichment: Option<S3Location>,
    pub bearer: OwnerSignBearer,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub part_delete_grant: Option<serde_json::Value>,
    pub part_gc: Option<LakePartGcAccess>,
    pub erasure_ledger: Option<super::lean_erasure::ErasureLedgerCredential>,
}

/// The ingest writer epoch (part log, finding appends, prevalence owner).
/// Live the platform sends neither field today, so both are optional:
/// - top-level `writer_epoch` wins when present;
/// - else `prevalence_owner.writer_epoch`;
/// - else the pre-owner value 1.
/// When both are present they must agree: one committed assignment epoch
/// fences every writer (NAN-2915/2916). A present epoch must be positive.
pub(crate) fn ingest_writer_epoch(top_level: Option<u64>, owner: Option<i64>) -> Result<u64> {
    ensure!(top_level != Some(0), "ingest exchange writer epoch is invalid");
    let owner = owner
        .map(|epoch| u64::try_from(epoch).ok().filter(|epoch| *epoch > 0).context("prevalence owner writer epoch is invalid"))
        .transpose()?;
    match (top_level, owner) {
        (Some(top), Some(owner)) => {
            ensure!(top == owner, "prevalence owner writer epoch {owner} differs from the exchange writer epoch {top}");
            Ok(top)
        }
        (Some(epoch), None) | (None, Some(epoch)) => Ok(epoch),
        (None, None) => Ok(1),
    }
}

/// Pick the input mode: an edge-log credential wins; otherwise bronze +
/// notices; otherwise refuse.
fn input_from(
    edge_endpoint: Option<String>,
    edge_token: Option<String>,
    bronze: Option<S3Location>,
    notices: Option<NoticeEndpoint>,
) -> Result<InputCreds> {
    match (edge_endpoint, edge_token, bronze, notices) {
        (Some(endpoint), Some(token), _, _) => Ok(InputCreds::Edge { endpoint, token: Zeroizing::new(token) }),
        (None, None, Some(bronze), Some(notices)) => {
            ensure!(notices_url_ok(&notices.url), "raw-handoff notice endpoint must use https");
            Ok(InputCreds::Bronze { bronze, notices })
        }
        (Some(_), None, _, _) | (None, Some(_), _, _) => bail!("exchange returned an incomplete edge-log consumer credential"),
        _ => bail!("credentials name no input: neither an edge-log consumer nor bronze + notices"),
    }
}

/// The trusted-local listing input: bronze only, never mixed with an edge
/// credential or a notice endpoint (one input per process).
fn lab_bronze_listed(
    edge: bool,
    notices: bool,
    bronze: Option<S3Location>,
    settings: super::bronze_list::BronzeListSettings,
) -> Result<InputCreds> {
    ensure!(!edge && !notices, "bronze listing excludes an edge-log credential and a notice endpoint");
    let bronze = bronze.context("bronze listing requires a bronze location")?;
    settings.validate()?;
    Ok(InputCreds::BronzeListed { bronze, settings })
}

pub(crate) fn location_of(credential: &ExchangedR2Credential) -> S3Location {
    S3Location {
        endpoint: credential.endpoint.clone(),
        region: credential.region.clone(),
        bucket: credential.bucket.clone(),
        prefix: String::new(),
        access_key_id: credential.access_key_id.clone(),
        secret_access_key: credential.secret_access_key.clone(),
        session_token: Some(credential.session_token.clone()),
    }
}

/// Read the tenant's published internal DNS suffixes (NAN-3226) and install
/// them process-wide for domain prevalence. No document = built-ins only.
async fn refresh_internal_domains(store: &S3ObjectStore, tenant: &str) -> Result<()> {
    let tenant_uuid: uuid::Uuid = tenant.parse().context("lean enrichment tenant must be a UUID")?;
    let internal = match crate::internal_domains_snapshot::read(store, tenant_uuid).await? {
        Some(document) => document.internal_domains(),
        None => nanosiem_core::internal_domains::InternalDomains::builtin(),
    };
    let count = internal.tenant_suffixes().len();
    if crate::ocsf_domains::set_internal_domains(Arc::new(internal)) {
        tracing::info!(tenant_suffixes = count, "tenant internal domains installed");
    }
    Ok(())
}

fn enrichment_location(credential: &ExchangedR2Credential, tenant: &str) -> Result<S3Location> {
    let expected = format!("lake/enrichment/v1/tenant_id={tenant}/");
    ensure!(credential.permission == "object-read-only", "enrichment credential must be read-only");
    ensure!(credential.prefixes == [expected.clone()], "enrichment credential must name exactly this tenant prefix");
    let mut location = location_of(credential);
    location.prefix = expected;
    Ok(location)
}

fn notices_url_ok(url: &str) -> bool {
    url.starts_with("https://") || cfg!(test)
}

/// Lifetime of a supervisor-minted bootstrap token (the platform
/// `LAKE_CELL_BOOTSTRAP_TOKEN_TTL_SECONDS`).
pub const BOOTSTRAP_TOKEN_TTL: Duration = Duration::from_secs(180);

/// A 401 on a token presented at least this long after the process received
/// it is classified `token_expired` (the mint happened before the receipt,
/// so the token's true age is larger still). Control answers one uniform
/// 401 for unknown, spent and expired tokens.
pub const TOKEN_EXPIRED_AFTER: Duration = Duration::from_secs(BOOTSTRAP_TOKEN_TTL.as_secs() - 60);

/// The control plane refused an exchange. The presented token is never
/// re-presented; a retry asks the supervisor for a fresh one.
#[derive(Debug, thiserror::Error)]
#[error("credential exchange refused with HTTP {status} ({}); {}", self.reason(), self.detail())]
pub struct ExchangeRefused {
    pub status: u16,
    /// How long after the process received the token it was presented.
    pub token_age: Option<Duration>,
}

impl ExchangeRefused {
    pub fn new(status: u16) -> Self {
        Self { status, token_age: None }
    }

    pub fn with_token_age(status: u16, token_age: Duration) -> Self {
        Self { status, token_age: Some(token_age) }
    }

    /// A 401 on a token presented after [`TOKEN_EXPIRED_AFTER`]: it expired
    /// in this process before the exchange left (a starved runtime), not a
    /// spent or unknown token.
    pub fn token_expired(&self) -> bool {
        self.status == 401 && self.token_age.is_some_and(|age| age >= TOKEN_EXPIRED_AFTER)
    }

    /// Stable reason code for logs and alerts.
    pub fn reason(&self) -> &'static str {
        match self.status {
            401 if self.token_expired() => "token_expired",
            401 => "token_refused",
            403 => "forbidden",
            503 => "unavailable",
            _ => "refused",
        }
    }

    fn detail(&self) -> String {
        let age = self.token_age.map(|age| format!("presented {} s after receipt, ", age.as_secs())).unwrap_or_default();
        match self.status {
            401 if self.token_expired() => format!(
                "{age}past its {} s lifetime; a fresh bootstrap token is requested",
                BOOTSTRAP_TOKEN_TTL.as_secs()
            ),
            401 => format!("{age}the bootstrap token is unknown, spent or expired"),
            503 => "retried with a fresh bootstrap token".to_string(),
            _ => "the bootstrap token is not re-presented".to_string(),
        }
    }

    /// 401/403 are final (bad token, or the tenant left this cell), except
    /// a token that merely expired before it was presented; 503 is retried
    /// with a fresh bootstrap.
    pub fn is_final(&self) -> bool {
        matches!(self.status, 401 | 403) && !self.token_expired()
    }
}

/// The owner refused a `lake-parts:sign` call (typed so a caller can tell an
/// expired bearer, 401, from everything else and re-exchange instead of dying).
#[derive(Debug, thiserror::Error)]
#[error("lake-parts:sign refused: HTTP {status}")]
pub struct OwnerSignRefused {
    pub status: u16,
}

impl OwnerSignRefused {
    /// 401: the bearer is expired or unknown (`cell_bearer_expired`); a
    /// fresh exchange mints a new one.
    pub fn is_bearer_rejected(&self) -> bool {
        self.status == 401
    }
}

/// Backoff between refresh attempts after a 503 (seconds). The total covers
/// the owner's 660 s drain/move fence (bearer TTL + 30 s + 30 s skew) with
/// margin; every attempt uses a fresh bootstrap token.
/// Every step is at least the supervisor's 60 s refresh rate limit, so no
/// request is silently dropped: 13 x 60 s = 780 s.
pub const REFRESH_BACKOFF_S: [u64; 13] = [60; 13];

/// A refresh request with no answer after this long is considered lost (the
/// supervisor could not mint, or dropped it) and may be asked again.
pub const REFRESH_ANSWER_TIMEOUT: chrono::Duration = chrono::Duration::seconds(90);

/// Credentials count as expired this long before `expires_at`.
pub const EXPIRY_SKEW: chrono::Duration = chrono::Duration::seconds(30);

/// Exchange a single-use bootstrap token. 401/403/503 are final for this
/// token: it is never re-presented; the caller asks for a fresh one.
pub async fn exchange(token: &[u8], assignment: &Assignment) -> Result<Exchanged> {
    exchange_received(token, assignment, Instant::now()).await
}

/// [`exchange`] of a token the process received at `received` (for the
/// `token_expired` classification of a 401).
pub async fn exchange_received(token: &[u8], assignment: &Assignment, received: Instant) -> Result<Exchanged> {
    let tenant = assignment.tenant.as_str();
    let control_url = assignment.control_url.as_deref().context("assignment has no control_url for the credential exchange")?;
    ensure!(control_url.starts_with("https://") || cfg!(test), "credential exchange must use https");
    let token = std::str::from_utf8(token).context("bootstrap token is not text")?.trim();
    let url = format!("{}/v1/lake/cells/{}/credential-exchange", control_url.trim_end_matches('/'), assignment.cell_id);
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()?
        .post(url)
        .bearer_auth(token)
        .json(&serde_json::json!({ "tenant_id": tenant, "role": "ingest", "accepts": INGEST_ACCEPTS, "accepts_owner_scopes": ["lake-parts:sign", "lake-parts:write"] }))
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let refused = ExchangeRefused::with_token_age(status.as_u16(), received.elapsed());
        if refused.token_expired() {
            tracing::error!(reason = "token_expired", token_age_s = received.elapsed().as_secs(),
                "bootstrap token expired before the credential exchange left the process");
        }
        return Err(refused.into());
    }
    let body = Zeroizing::new(response.bytes().await?.to_vec());
    let exchange: ExchangeResponse = serde_json::from_slice(&body).context("credential exchange response")?;
    ensure!(
        exchange.schema_version == 1 && exchange.tenant_id == tenant && exchange.role == "ingest",
        "exchange response binding differs"
    );
    let writer_epoch = ingest_writer_epoch(
        exchange.writer_epoch,
        exchange.prevalence_owner.as_ref().map(|owner| owner.writer_epoch),
    )?;
    let mut seen = std::collections::BTreeSet::new();
    for credential in &exchange.credentials {
        let name = credential.credential_class.as_str();
        ensure!(INGEST_ACCEPTS.contains(&name), "exchange returned undeclared credential class {name:?}");
        ensure!(seen.insert(name), "exchange returned credential class {name:?} twice");
    }
    let class = |name: &str| exchange.credentials.iter().find(|c| c.credential_class == name);
    // Least privilege: bronze reads only through the read-only class.
    let bronze = BRONZE_READ_CLASSES.iter().find_map(|name| class(name)).map(location_of);
    let parts = match (class("lake_part"), class("lake_part_log")) {
        (Some(part), Some(log)) => Some(PartCreds { part: location_of(part), log: location_of(log) }),
        (None, None) => None,
        _ => bail!("exchange returned only one of lake_part / lake_part_log"),
    };
    let prevalence = class("lake_prevalence_state").map(|credential| {
        let mut location = location_of(credential);
        location.prefix = format!("lake/prevalence-state/v1/tenant={tenant}/");
        (credential, location)
    });
    if let Some((credential, _)) = &prevalence {
        ensure!(credential.permission == "object-read-only"
            && credential.prefixes == [format!("lake/prevalence-state/v1/tenant={tenant}/")],
            "prevalence credential must be exact-prefix read-only for this tenant");
    }
    // A grant naming another tenant is refused outright. A missing half is
    // not: until the platform serves the prevalence owner, ingest runs with
    // prevalence unstamped instead of crash-looping the tenant (NAN-2915).
    let prevalence = match (prevalence, exchange.prevalence_owner) {
        (Some((_, read)), Some(owner)) => {
            ensure!(owner.tenant_id == tenant, "prevalence owner is bound to another tenant");
            // Same owner endpoint and private CA as part signing (#4734).
            let owner_ca_file = assignment.part_signing.as_ref().and_then(|signing| signing.ca_file.clone());
            Some(PrevalenceAccess { read, owner, owner_ca_file })
        }
        (None, None) => None,
        (read, owner) => {
            tracing::warn!(read = read.is_some(), owner = owner.is_some(),
                "exchange returned only half of the prevalence grant; prevalence stays unstamped");
            None
        }
    };
    let enrichment = class("enrichment_reader").map(|credential| enrichment_location(credential, tenant)).transpose()?;
    let bearer = exchange.owner_sign.clone().context("exchange returned no owner-sign bearer (lake-parts:sign disabled?)")?;
    ensure!(bearer.audience == "owner" && bearer.scope == "lake-parts:sign", "owner-sign bearer scope differs");
    let mut expires_at = crate::cell_refresh::owner_bearer_expiry(&bearer.expires_at, chrono::Utc::now());
    for credential in &exchange.credentials {
        expires_at = expires_at.min(chrono::DateTime::parse_from_rfc3339(&credential.expires_at)?.with_timezone(&chrono::Utc));
    }
    if exchange.lake_part_gc.is_none()
        && exchange.lake_part_delete_grant.as_ref()
            .and_then(|value| LakePartDeleteGrant::parse(value, tenant).ok())
            .is_some_and(|grant| grant.enabled)
    {
        tracing::warn!(detail = "lake_part_gc_not_delivered", "credential exchange omitted sanctioned GC route; owner_delete and retention_authority are unavailable");
    }
    let part_gc = exchange.lake_part_gc.as_ref().and_then(|value| match LakePartGcAccess::parse(value) {
        Ok(access) => Some(access),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "lake_part_gc route unreadable; part deletes stay blocked");
            None
        }
    });
    // The owner delete bearer is refreshed with everything else.
    if let Some(at) = part_gc.as_ref().and_then(|access| access.owner_expires_at().ok()) {
        expires_at = expires_at.min(at);
    }
    let input = input_from(
        exchange.edge_log_consumer_endpoint.clone(),
        exchange.edge_log_consumer_token.clone(),
        bronze,
        exchange.notices.clone(),
    )?;
    if matches!(input, InputCreds::Edge { .. }) {
        // Lean tenant contract (the platform): lake_part + lake_part_log,
        // the owner-sign bearer and the edge-log consumer only. Anything
        // else is over-granted; it is never used, but say so.
        let extra = exchange
            .credentials
            .iter()
            .map(|c| c.credential_class.as_str())
            .filter(|class| !LEAN_EDGE_CLASSES.contains(class) && *class != "enrichment_reader")
            .collect::<Vec<_>>();
        if !extra.is_empty() || exchange.notices.is_some() {
            tracing::warn!(?extra, notices = exchange.notices.is_some(), "edge tenant exchange grants more than the lean contract; ignoring it");
        }
        ensure!(parts.is_some(), "edge tenant exchange returned no lake_part / lake_part_log credentials");
        if prevalence.is_none() {
            tracing::warn!("edge tenant exchange returned no prevalence grant; ingest runs with prevalence unstamped");
        }
    }
    let write_permission = exchange.owner_write.clone();
    if let Some(permission) = &write_permission {
        permission.validate(tenant, &assignment.cell_id)?;
        expires_at = expires_at.min(permission.expires_at());
    }
    let erasure_ledger = super::lean_erasure::ledger_from_exchange(exchange.erasure_ledger.as_ref(), tenant);
    if let Some(at) = erasure_ledger.as_ref().and_then(|ledger| ledger.validate(tenant, chrono::Utc::now()).ok()) {
        expires_at = expires_at.min(at);
    }
    Ok(Exchanged { write_permission, writer_epoch, input, parts, prevalence, enrichment, bearer, expires_at,
        part_delete_grant: exchange.lake_part_delete_grant, part_gc, erasure_ledger })
}

/// Turn the memfd secret into credentials.
/// - Production: the secret is the opaque single-use bootstrap token
///   ([`exchange`]); signing goes to `Assignment::part_signing`.
/// - Lab: `nano.lake.ingest-lab-credentials.v1` JSON from a dev key dir.
pub async fn credentials_from_secret(secret: &[u8], assignment: &Assignment) -> Result<IngestCredentials> {
    let tenant = assignment.tenant.as_str();
    // Lab credentials (a local signer from the secret itself) are accepted
    // only when the cell renders no release-pinned signing config.
    if let (None, None, Ok(lab)) = (&assignment.control_url, &assignment.part_signing, serde_json::from_slice::<LabCredentials>(secret)) {
        ensure!(lab.kind == LAB_CREDENTIALS_KIND, "unknown lab credential kind");
        ensure!(lab.tenant_id == tenant, "credentials are for another tenant");
        let seed = Zeroizing::new(hex::decode(&lab.lab_signer_seed_hex)?);
        let seed: [u8; 32] = seed.as_slice().try_into().context("lab signer seed must be 32 bytes")?;
        let signer = LocalPartSigner::new(&lab.lab_signer_key_id, SigningKey::from_bytes(&seed))?;
        let trusted = signer.trusted();
        let input = match lab.bronze_list {
            Some(settings) => lab_bronze_listed(lab.edge_log_consumer_endpoint.is_some() || lab.edge_log_consumer_token.is_some(),
                lab.notices.is_some(), lab.bronze, settings)?,
            None => input_from(lab.edge_log_consumer_endpoint, lab.edge_log_consumer_token, lab.bronze, lab.notices)?,
        };
        return Ok(IngestCredentials {
            native_writer: None,
            writer_epoch: lab.writer_epoch,
            input,
            parts: None,
            prevalence: None,
            enrichment: lab.enrichment,
            signer: Box::new(signer),
            trusted,
            expires_at: None,
            bearer: None,
            part_delete_grant: None,
            part_gc: None,
            local_gc: lab.local_gc,
            erasure_ledger: None,
        });
    }
    let signing = assignment.part_signing.as_ref().context("assignment has no part_signing config")?;
    let trusted = trusted_from(signing)?;
    // Build the signer (and so check the CA bundle) before spending the
    // single-use bootstrap token.
    let signer = HttpPartSigner::new(&signing.url, "", &signing.signer_key_id, trusted.clone(), signing.ca_file.as_deref())?;
    let fresh = exchange(secret, assignment).await?;
    // The part log, finding appends and the prevalence owner share the
    // committed assignment writer epoch (`ingest_writer_epoch` derives it and
    // checks the two copies agree): a cell move bumps it, fencing the old writer.
    signer.set_bearer(&fresh.bearer.token);
    ensure!(fresh.parts.is_some(), "pinned part signing requires lake_part / lake_part_log credentials");
    let native_writer = Arc::new(super::native_writer::NativePartWriter::new(
        &super::native_writer::owner_origin(&signing.url)?, signing.ca_file.as_deref(), tenant,
        &assignment.cell_id, &fresh.parts.as_ref().context("parts")?.part.bucket,
        fresh.write_permission.clone().context("signed ingest exchange omitted owner_write")?, &assignment.state_dir)?
        .with_ingest_eps(assignment.eps)?);
    // PartLog may discover the already uploaded LOG without beginning it again.
    // Recover completion evidence using the freshly exchanged owner permission.
    native_writer.replay_pending().await?;
    Ok(IngestCredentials {
        native_writer: Some(native_writer),
        writer_epoch: fresh.writer_epoch,
        input: fresh.input,
        parts: fresh.parts,
        prevalence: fresh.prevalence,
        enrichment: fresh.enrichment,
        signer: Box::new(signer),
        trusted,
        expires_at: Some(fresh.expires_at),
        bearer: Some(Zeroizing::new(fresh.bearer.token.clone())),
        part_delete_grant: fresh.part_delete_grant,
        part_gc: fresh.part_gc,
        local_gc: None,
        erasure_ledger: fresh.erasure_ledger,
    })
}

/// `lake-parts:sign` over HTTPS with the exchange's owner-sign bearer. The
/// bearer is swapped in place on refresh.
///
/// The owner serves a private-CA certificate, so the client trusts ONLY the
/// release-pinned `part_signing.ca_file` bundle (never system roots), with
/// hostname verification on. The bundle is re-read on every credential
/// refresh ([`Self::reload_ca`]) so a CA rotation needs no restart.
pub struct HttpPartSigner {
    tls: super::owner_tls::OwnerTlsClient,
    url: String,
    bearer: std::sync::RwLock<Zeroizing<String>>,
    key_id: String,
    trusted: TenantKeySet,
}

const OWNER_SIGN_TIMEOUT: Duration = Duration::from_secs(30);

impl HttpPartSigner {
    /// `ca_file` is required for an `https` URL; there is no fallback to
    /// system roots. (Plain `http` is accepted only in tests.)
    pub fn new(url: &str, bearer: &str, key_id: &str, trusted: TenantKeySet, ca_file: Option<&std::path::Path>) -> Result<Self> {
        ensure!(url.starts_with("https://") || cfg!(test), "owner sign route must use https");
        ensure!(crate::parts::provenance::valid_key_id(key_id), "signer key id is malformed");
        Ok(Self {
            tls: super::owner_tls::OwnerTlsClient::new(url, ca_file, OWNER_SIGN_TIMEOUT)?,
            url: url.to_string(),
            bearer: std::sync::RwLock::new(Zeroizing::new(bearer.to_string())),
            key_id: key_id.to_string(),
            trusted,
        })
    }

    pub fn set_bearer(&self, bearer: &str) {
        *self.bearer.write().expect("bearer lock") = Zeroizing::new(bearer.to_string());
    }

    /// Re-read the CA bundle and rebuild the client if it changed. Returns
    /// whether the client was replaced. On any error the current client is
    /// kept (a half-written or bad bundle never drops working trust).
    pub fn reload_ca(&self) -> Result<bool> {
        self.tls.reload_ca()
    }

    /// [`Self::reload_ca`], logged; for the refresh path.
    pub fn reload_ca_logged(&self) {
        self.tls.reload_ca_logged("owner sign");
    }
}

#[async_trait]
impl PartSigner for HttpPartSigner {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    async fn sign(&self, tenant_id: &str, records: &[ProvenanceRecord]) -> Result<Vec<Ed25519Signature>> {
        // Byte-bounded calls whatever the caller passed (NAN-3006): the
        // owner refuses an over-cap body whole with 413.
        let mut signatures = Vec::with_capacity(records.len());
        for plan in plan_sign_requests(tenant_id, records, SIGN_REQUEST_BUDGET_BYTES)? {
            signatures.extend(self.sign_request(&plan.request, plan.body_bytes, &records[plan.records]).await?);
        }
        Ok(signatures)
    }

    async fn sign_counts(&self, tenant_id: &str, records: &[crate::parts::count_record::CountRecord]) -> Result<Vec<Ed25519Signature>> {
        let mut signatures = Vec::with_capacity(records.len());
        for chunk in records.chunks(COUNT_SIGN_MAX_RECORDS) {
            signatures.extend(self.sign_counts_request(tenant_id, chunk).await?);
        }
        Ok(signatures)
    }
}

/// the platform refuses more than 64 records per `lake-part-counts:sign`.
const COUNT_SIGN_MAX_RECORDS: usize = 64;

/// The count route beside a `…/lake-parts:sign` URL.
fn count_sign_url(url: &str) -> Result<String> {
    let base = url.strip_suffix("lake-parts:sign").context("owner sign URL does not end in lake-parts:sign")?;
    Ok(format!("{base}lake-part-counts:sign"))
}

#[derive(Serialize)]
struct CountSignRequest<'a> {
    schema_version: u32,
    request_id: String,
    tenant_id: &'a str,
    records: Vec<CountSignItem>,
}

#[derive(Serialize)]
struct CountSignItem {
    part_id: String,
    record_sha256: String,
    record_base64: String,
}

#[derive(Deserialize)]
struct CountSignResponse {
    results: Vec<CountSignResult>,
}

#[derive(Deserialize)]
struct CountSignResult {
    part_id: String,
    record_sha256: String,
    signature: Option<Ed25519Signature>,
    error: Option<String>,
}

impl HttpPartSigner {
    /// One `lake-part-counts:sign` call. 404/405: an owner release without
    /// the route; 403: the route is off. Both are
    /// [`crate::parts::provenance::CountSigningUnsupported`] so the caller
    /// falls back to a full count rewrite.
    async fn sign_counts_request(&self, tenant_id: &str, records: &[crate::parts::count_record::CountRecord]) -> Result<Vec<Ed25519Signature>> {
        use base64::Engine as _;
        use sha2::Digest as _;
        let mut items = Vec::with_capacity(records.len());
        for record in records {
            let bytes = record.canonical_bytes()?;
            items.push(CountSignItem {
                part_id: record.part_id.to_string(),
                record_sha256: hex::encode(sha2::Sha256::digest(&bytes)),
                record_base64: base64::engine::general_purpose::STANDARD.encode(&bytes),
            });
        }
        let request = CountSignRequest { schema_version: 1, request_id: uuid::Uuid::new_v4().to_string(), tenant_id, records: items };
        let url = count_sign_url(&self.url)?;
        let bearer = self.bearer.read().expect("bearer lock").to_string();
        let response = self.tls.client().post(&url).bearer_auth(bearer).json(&request).send().await?;
        let status = response.status().as_u16();
        if matches!(status, 403 | 404 | 405) {
            return Err(anyhow::Error::new(crate::parts::provenance::CountSigningUnsupported)
                .context(format!("lake-part-counts:sign: HTTP {status}")));
        }
        if !response.status().is_success() {
            return Err(anyhow::Error::new(OwnerSignRefused { status })
                .context(format!("lake-part-counts:sign refused: HTTP {status} ({} records)", records.len())));
        }
        let body: CountSignResponse = response.json().await?;
        ensure!(body.results.len() == records.len(), "count sign response has the wrong number of results");
        let mut signatures = Vec::with_capacity(records.len());
        for ((item, result), record) in request.records.iter().zip(body.results).zip(records) {
            ensure!(result.part_id == item.part_id && result.record_sha256 == item.record_sha256, "count sign result order differs");
            let signature = result.signature.with_context(|| format!("owner refused the count record of part {}: {}",
                item.part_id, result.error.unwrap_or_default()))?;
            // Verify before trusting: a bad signature must never be stored.
            crate::parts::count_record::SignedCountRecord::assemble(record.clone(), signature.clone(), &self.trusted)?;
            signatures.push(signature);
        }
        Ok(signatures)
    }
}

impl HttpPartSigner {
    /// One `lake-parts:sign` call.
    async fn sign_request(&self, request: &SignRequest, body_bytes: usize, records: &[ProvenanceRecord]) -> Result<Vec<Ed25519Signature>> {
        let body = serde_json::to_vec(request)?;
        debug_assert_eq!(body.len(), body_bytes);
        if body.len() > SIGN_REQUEST_BUDGET_BYTES {
            tracing::warn!(body_bytes = body.len(), parts = request.parts.len(), budget = SIGN_REQUEST_BUDGET_BYTES,
                cap = OWNER_SIGN_BODY_MAX_BYTES, "lake-parts:sign body is over the cell budget, near the owner cap");
        } else {
            tracing::debug!(body_bytes = body.len(), parts = request.parts.len(), "lake-parts:sign request");
        }
        // Refuse locally rather than earn a 413 that names nothing.
        ensure!(
            body.len() <= OWNER_SIGN_BODY_MAX_BYTES,
            "lake-parts:sign body {} bytes exceeds the owner cap {OWNER_SIGN_BODY_MAX_BYTES} ({} parts)",
            body.len(),
            request.parts.len()
        );
        let bearer = self.bearer.read().expect("bearer lock").to_string();
        let client = self.tls.client();
        let response = client
            .post(&self.url)
            .bearer_auth(bearer)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body)
            .send()
            .await?;
        if !response.status().is_success() {
            let status = response.status();
            return Err(anyhow::Error::new(OwnerSignRefused { status: status.as_u16() }).context(format!(
                "lake-parts:sign refused: {status} ({body_bytes} body bytes, {} parts)",
                request.parts.len()
            )));
        }
        let body: SignResponse = response.json().await?;
        ensure!(body.schema_version == 1 && body.request_id == request.request_id, "sign response binding differs");
        ensure!(body.results.len() == request.parts.len(), "sign response has the wrong number of results");
        let mut signatures = Vec::with_capacity(records.len());
        for ((part, result), record) in request.parts.iter().zip(body.results).zip(records) {
            ensure!(result.part_id == part.part_id && result.record_sha256 == part.record_sha256, "sign result order differs");
            let signature = result
                .signature
                .with_context(|| format!("owner refused part {}: {}", part.part_id, result.error.unwrap_or_default()))?;
            // Verify before trusting: a bad signature must never be stored.
            SignedProvenance::assemble(record.clone(), signature.clone(), &self.trusted)?;
            signatures.push(signature);
        }
        Ok(signatures)
    }
}

/// Wire format of the raw-handoff DO notice endpoint:
///
/// ```text
/// GET  {url}/v1/tenants/{t}/parsed-objects?limit=N   → {"notices":[{"id":"…","notice":SourceNotice}]}
/// POST {url}/v1/tenants/{t}/parsed-objects:ack {"ids":[…]} → 2xx
/// ```
///
/// Both carry `Authorization: Bearer <tenant-scoped token>`. Delivery is
/// at-least-once; unacked notices are redelivered.
pub struct DoNoticeQueue {
    client: reqwest::Client,
    base: String,
    tenant: String,
    bearer: std::sync::RwLock<Zeroizing<String>>,
}

#[derive(Serialize, Deserialize)]
pub struct DoNotice {
    pub id: String,
    pub notice: SourceNotice,
}

#[derive(Serialize, Deserialize)]
pub struct DoNotices {
    pub notices: Vec<DoNotice>,
}

impl DoNoticeQueue {
    fn bearer_now(&self) -> String {
        self.bearer.read().expect("bearer lock").to_string()
    }

    /// Swap in a refreshed bearer.
    pub fn set_bearer(&self, bearer: &str) {
        *self.bearer.write().expect("bearer lock") = Zeroizing::new(bearer.to_string());
    }

    pub fn new(endpoint: &NoticeEndpoint, tenant: &str) -> Result<Self> {
        Ok(Self {
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .build()?,
            base: endpoint.url.trim_end_matches('/').to_string(),
            tenant: tenant.to_string(),
            bearer: std::sync::RwLock::new(Zeroizing::new(endpoint.bearer.clone())),
        })
    }
}

#[async_trait]
impl NoticeQueue for DoNoticeQueue {
    async fn pending(&self, max: usize) -> Result<Vec<(NoticeHandle, SourceNotice)>> {
        let url = format!("{}/v1/tenants/{}/parsed-objects?limit={}", self.base, self.tenant, max.min(1_000));
        let response = self.client.get(url).bearer_auth(self.bearer_now()).send().await?;
        ensure!(response.status().is_success(), "notice pull failed: {}", response.status());
        let body: DoNotices = response.json().await?;
        body.notices
            .into_iter()
            .map(|n| {
                ensure!(n.notice.tenant_id == self.tenant, "DO returned a notice for another tenant");
                Ok((NoticeHandle(n.id), n.notice))
            })
            .collect()
    }

    async fn ack(&self, handles: &[NoticeHandle]) -> Result<()> {
        if handles.is_empty() {
            return Ok(());
        }
        let url = format!("{}/v1/tenants/{}/parsed-objects:ack", self.base, self.tenant);
        let ids = handles.iter().map(|h| h.0.as_str()).collect::<Vec<_>>();
        let response = self
            .client
            .post(url)
            .bearer_auth(self.bearer_now())
            .json(&serde_json::json!({ "ids": ids }))
            .send()
            .await?;
        ensure!(response.status().is_success(), "notice ack failed: {}", response.status());
        Ok(())
    }
}

/// The cell-facing service.
pub struct IngestService {
    ingestor: tokio::sync::Mutex<Ingestor<'static>>,
    /// Finding appends from detect[T]: bounded, deadline-limited, and never
    /// holding the ingestor beyond their commit (`finding_gate`).
    finding_gate: FindingGate,
    finding_context: FindingAppendContext<'static>,
    /// A refreshed prevalence credential (or its withdrawal) waiting for the
    /// ingestor: the credential swap never waits for a tick to finish.
    pending_prevalence: std::sync::Mutex<Option<PrevalenceUpdate>>,
    /// Set once the process must exit for a respawn (refresh gave up, edge
    /// stall); `run` watches it from outside the ingest loop.
    terminal: tokio::sync::watch::Sender<Option<String>>,
    /// Edge tenants: the edge-log consumer the stall watchdog samples.
    edge_source: Option<Arc<crate::edge_log::EdgeLogSource<crate::edge_log::HttpEdgeLogClient>>>,
    /// Kernel-held, tenant-private lock prevents overlapping ingest process
    /// generations from owning the same part log.
    _append_lock: std::fs::File,
    writer_epoch: u64,
    epoch_changed: AtomicBool,
    active_appends: AtomicUsize,
    wake: Arc<tokio::sync::Notify>,
    heartbeat: std::sync::Mutex<Heartbeat>,
    pipeline_diagnostics: super::ingest::PipelineDiagnostics,
    native_writer_diagnostics: Option<Arc<super::native_writer::NativePartWriter>>,
    assignment: Assignment,
    /// Exit after IDLE_EXIT with nothing to do (see `Assignment::ingest_idle_exit`).
    idle_exit: bool,
    /// Production only: refreshable stores and signer.
    refresh: Option<Refreshable>,
    enrichment: Option<LeanEnrichmentSnapshots<'static>>,
    initial_enrichment_pointer: Option<SnapshotPointer>,
    platform_paths: Option<PlatformPaths>,
    initial_platform: Option<(Arc<PlatformBundle>, TenantPlatformPolicy)>,
    custom_context_root: Option<std::path::PathBuf>,
    initial_custom_assignment: Option<(std::path::PathBuf, String)>,
    /// Tenant-published custom IP context in the tenant R2 enrichment prefix
    /// (same `enrichment_reader` credential as IOC). Used only when no
    /// `custom_context_root` mount is configured.
    ip_context: Option<LeanIpContextSnapshots<'static>>,
    initial_ip_context_pointer: Option<SnapshotPointer>,
    /// NAN-3503 (cell flag `identity_directory_enrich`): the tenant identity
    /// directory in the same R2 enrichment prefix, and the handle its
    /// background refresh fills. Every enricher generation reads the handle;
    /// the ingest loop and its lock never touch the directory.
    identity: Option<(&'static LeanIdentityDirectories<'static>, IdentityDirectoryHandle)>,
    /// Tenant enrichment prefix holding `internal_domains/current.json`
    /// (NAN-3226), re-read on every enrichment refresh.
    internal_domains_store: Option<&'static S3ObjectStore>,
    /// The lake-part delete gate, re-fed on every credential refresh.
    part_gc: Arc<ExchangedGrantAuthority>,
    /// The sanctioned delete route behind the gate (R2 part store only),
    /// re-fed on every credential refresh.
    part_gc_route: Option<Arc<CellSanctionedPartGc>>,
    /// NAN-3867: the erasure ledger login, re-fed on every credential refresh.
    erasure_ledger: super::lean_erasure::ErasureLedgerSlot,
    /// NAN-4052: the cell writer lease every part-log append checks.
    writer_lease: Option<Arc<super::writer_lease::WriterLease>>,
    /// NAN-4129: its renewer, running since the lease was acquired (setup
    /// included); `run` stops it on teardown, and dropping it stops it too.
    lease_renewer: Option<super::writer_lease::LeaseRenewer>,
}

/// NAN-4052: take the cell writer lease when the supervisor asks for one
/// (cells with the writer handover) and the exchange delivered the tenant's
/// `publish` login. Held by another pod generation, or Postgres unreachable:
/// a standby error (the supervisor retries without counting a crash).
/// Without the login, or before the lease functions exist on the database
/// (migration 9013980 not applied yet), ingest runs on the peer lease alone,
/// as before.
async fn acquire_writer_lease(
    assignment: &Assignment,
    ledger: &super::lean_erasure::ErasureLedgerSlot,
) -> Result<Option<Arc<super::writer_lease::WriterLease>>> {
    use super::writer_lease::{LeaseKey, LeaseLost, PgLeaseStore, WriterLease};
    let Some(lease) = &assignment.writer_lease else { return Ok(None) };
    let key = LeaseKey { cell_id: assignment.cell_id.clone(), holder: lease.holder.clone() };
    let ttl = Duration::from_millis(lease.ttl_ms);
    if !key.valid() || !(super::writer_lease::MIN_TTL..=super::writer_lease::MAX_TTL).contains(&ttl) {
        tracing::warn!(cell = %key.cell_id, ttl_ms = lease.ttl_ms, "cell writer lease key or TTL unusable; writing on the peer lease alone");
        return Ok(None);
    }
    if ledger.get().is_none() {
        tracing::warn!("no lake publish login delivered; writing on the peer lease alone (no cell writer lease)");
        return Ok(None);
    }
    let store: Arc<dyn super::writer_lease::LeaseStore> = Arc::new(PgLeaseStore::new(assignment.tenant.as_str(), ledger.clone()));
    let mut attempt = 0;
    loop {
        attempt += 1;
        match WriterLease::acquire(store.clone(), key.clone(), ttl).await {
            Ok(lease) => return Ok(Some(lease)),
            Err(error) if super::writer_lease::is_standby(&error) => return Err(error),
            Err(error) if super::writer_lease::lease_functions_missing(&error) => {
                tracing::warn!(error = %format!("{error:#}"), "cell writer lease functions unavailable on the database; writing on the peer lease alone");
                return Ok(None);
            }
            Err(error) if attempt < 3 => {
                tracing::warn!(error = %format!("{error:#}"), attempt, "cell writer lease acquire failed; retrying");
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => {
                return Err(anyhow::Error::from(LeaseLost { epoch: 0, reason: format!("lease store unreachable: {error:#}") }));
            }
        }
    }
}

fn custom_context_assignment(root: &std::path::Path, tenant: &str) -> Result<(std::path::PathBuf, String)> {
    ensure!(root.is_absolute(), "custom IP context root must be absolute");
    ensure!(root.is_dir(), "custom IP context root is missing");
    crate::ip_context::current_assignment_pointer(root, tenant)?
        .context("configured custom IP context has no tenant assignment")
}

/// The shared bundle source (fixed file or content-addressed dir) and this
/// tenant's policy file.
type PlatformPaths = (PlatformBundleSource, std::path::PathBuf);

fn load_platform(tenant: &str, paths: &PlatformPaths) -> Result<(Arc<PlatformBundle>, TenantPlatformPolicy)> {
    let tenant: uuid::Uuid = tenant.parse().context("platform tenant must be UUID")?;
    let policy = TenantPlatformPolicy::read_for_query(&paths.1, tenant)?;
    open_platform(paths, policy)
}

fn open_platform(paths: &PlatformPaths, policy: TenantPlatformPolicy) -> Result<(Arc<PlatformBundle>, TenantPlatformPolicy)> {
    let bundle = Arc::new(paths.0.open(&policy.bundle_sha256)?);
    Ok((bundle, policy))
}

fn platform_paths(assignment: &Assignment) -> Result<Option<PlatformPaths>> {
    let source = PlatformBundleSource::from_paths(assignment.platform_bundle_file.as_deref(), assignment.platform_bundle_dir.as_deref())?;
    match (source, &assignment.platform_policy_file) {
        (None, None) => Ok(None),
        (Some(source), Some(policy)) => {
            ensure!(policy.is_absolute(), "platform policy path must be absolute");
            Ok(Some((source, policy.clone())))
        }
        _ => bail!("platform bundle and tenant policy must be configured together"),
    }
}

/// The enrichment revisions the running ingestor was built from.
struct EnrichmentPins {
    pointer: Option<SnapshotPointer>,
    platform: Option<(Arc<PlatformBundle>, TenantPlatformPolicy)>,
    custom_assignment: Option<(std::path::PathBuf, String)>,
    ip_context_pointer: Option<SnapshotPointer>,
}

struct EnrichmentRotation {
    enricher: BronzeIngestEnricher,
    pointer: Option<SnapshotPointer>,
    custom_assignment: Option<(std::path::PathBuf, String)>,
    ip_context_pointer: Option<SnapshotPointer>,
}

type PlatformPin = Option<(Arc<PlatformBundle>, TenantPlatformPolicy)>;

/// Read every enrichment input and build the next enricher when any pin moved.
/// Pure with respect to `pins`: any refusal (over-cap snapshot, rolled-back
/// policy, unreachable store) returns an error before anything is replaced.
async fn plan_enrichment_refresh(
    enrichment: Option<&LeanEnrichmentSnapshots<'static>>,
    platform_paths: Option<&PlatformPaths>,
    custom_context_root: Option<&std::path::Path>,
    ip_context: Option<&LeanIpContextSnapshots<'static>>,
    tenant: &str,
    pins: &EnrichmentPins,
) -> Result<(Option<EnrichmentRotation>, PlatformPin)> {
    ensure!(
        custom_context_root.is_none() || ip_context.is_none(),
        "custom IP context has both a mount and a tenant R2 source"
    );
    let current = match enrichment {
        Some(snapshots) => snapshots.current().await?,
        None => None,
    };
    let next_platform = match platform_paths {
        Some(paths) => {
            let tenant_uuid = tenant.parse().context("platform tenant must be UUID")?;
            let candidate = TenantPlatformPolicy::read_for_query(&paths.1, tenant_uuid)?;
            if let Some((_, old)) = &pins.platform {
                candidate.validate_successor(old)?;
            }
            if pins.platform.as_ref().is_some_and(|(bundle, policy)| policy.revision == candidate.revision && bundle.digest() == candidate.bundle_sha256) {
                pins.platform.clone()
            } else {
                Some(open_platform(paths, candidate)?)
            }
        }
        None => None,
    };
    let platform_changed = pins.platform.as_ref().map(|(b, p)| (b.digest(), p.revision))
        != next_platform.as_ref().map(|(b, p)| (b.digest(), p.revision));
    let next_custom_assignment = custom_context_root.map(|root| custom_context_assignment(root, tenant)).transpose()?;
    let next_ip_context = match ip_context {
        Some(snapshots) => snapshots.current().await?,
        None => None,
    };
    if current == pins.pointer
        && !platform_changed
        && next_custom_assignment == pins.custom_assignment
        && next_ip_context == pins.ip_context_pointer
    {
        return Ok((None, next_platform));
    }
    let next = match (enrichment, &current) {
        (Some(snapshots), Some(pointer)) => Some(snapshots.load(pointer).await?),
        _ => None,
    };
    let next_custom = match (&next_custom_assignment, ip_context, &next_ip_context) {
        (Some((path, digest)), _, _) => Some(crate::ip_context::IpContextSnapshot::open_lean(path, digest)?),
        (None, Some(snapshots), Some(pointer)) => Some(snapshots.load(pointer).await?),
        _ => None,
    };
    let mut enricher = BronzeIngestEnricher::new(None, next, next_custom);
    if let Some((bundle, policy)) = &next_platform {
        enricher = enricher.with_lean_platform(bundle.clone(), policy.clone());
    }
    Ok((
        Some(EnrichmentRotation {
            enricher,
            pointer: current,
            custom_assignment: next_custom_assignment,
            ip_context_pointer: next_ip_context,
        }),
        next_platform,
    ))
}

/// The ingest role's sanctioned part GC, wired from its assignment exactly as
/// [`IngestService::start`] does: only beside the R2 part store with pinned
/// part signing, with the view on the hot volume (`part_gc_state_dir`) when
/// the cell mounts one. NAN-4195: the boot-path test drives this, so a
/// constructor change that panics every ingest role (NAN-4194) fails CI.
fn assignment_part_gc(
    assignment: &Assignment,
    gc_store: Option<&Arc<super::r2_put::R2PartStore>>,
    trusted: TenantKeySet,
) -> Option<Arc<CellSanctionedPartGc>> {
    match (gc_store, &assignment.part_signing) {
        (Some(store), Some(signing)) => sanctioned_part_gc(
            assignment.tenant.as_str(), store.clone(), signing, trusted, &assignment.state_dir,
            assignment.part_gc_state_dir.as_deref(),
        ),
        _ => None,
    }
}

/// The sanctioned lake-part GC pass over the cell's R2 part store and the
/// release-pinned owner (`lean_part_gc_sanctioned_v1`). A wiring failure is
/// logged and leaves the gate at `sanctioned_path_unavailable`; it never
/// stops ingest.
///
/// `store` is the pass's OWN part store (same credentials as ingest's,
/// refreshed with it, but its own HTTP client), so none of its connections
/// live on the ingest runtime; the pass runs on its own thread and persists
/// its folded view under `view_dir` when the supervisor grants one (NAN-4183:
/// the persistent A/B hot volume, so a roll resumes the view instead of
/// refolding the log from seq 0), else under the per-pod `state_dir`.
fn sanctioned_part_gc(
    tenant: &str,
    store: Arc<super::r2_put::R2PartStore>,
    signing: &PartSigning,
    trusted: TenantKeySet,
    state_dir: &std::path::Path,
    view_dir: Option<&std::path::Path>,
) -> Option<Arc<CellSanctionedPartGc>> {
    let wired = (|| -> Result<CellSanctionedPartGc> {
        if let Some(dir) = view_dir {
            tracing::info!(dir = %dir.display(), "lake-part GC keeps its folded view on the persistent hot volume");
        }
        CellSanctionedPartGc::new_guarded(
            tenant, &signing.url, signing.ca_file.clone(), store, trusted, state_dir, view_dir,
        )
    })();
    match wired {
        Ok(pass) => Some(Arc::new(pass)),
        Err(error) => {
            tracing::error!(error = %format!("{error:#}"), "sanctioned lake-part GC could not be wired; part deletes stay blocked");
            None
        }
    }
}

/// What a credential refresh changes about the prevalence state.
enum PrevalenceUpdate {
    Rotate(PrevalenceAccess),
    Withdraw,
}

struct Refreshable {
    sources: Option<&'static S3ObjectStore>,
    notices: Option<&'static DoNoticeQueue>,
    /// Edge tenants: the edge-log source, whose consumer token rotates with
    /// every exchange (`HttpEdgeLogClient::set_token`), and its endpoint.
    edge: Option<(Arc<crate::edge_log::EdgeLogSource<crate::edge_log::HttpEdgeLogClient>>, String)>,
    parts: Option<&'static super::r2_put::R2PartStore>,
    /// The sanctioned GC pass's own part store (same credentials).
    gc_parts: Option<Arc<super::r2_put::R2PartStore>>,
    enrichment: Option<&'static S3ObjectStore>,
    signer: &'static HttpPartSigner,
    /// The shared refresh schedule (`crate::cell_refresh`, NAN-3017).
    refresher: Arc<CredentialRefresher>,
}

/// Refresh once this fraction of the credential lifetime has passed.
pub const REFRESH_AT_FRACTION: f64 = 0.5;

fn now_ms() -> i64 {
    chrono::Utc::now().timestamp_millis()
}

impl IngestService {
    /// Build from a jailed assignment and its bootstrap secret.
    pub async fn start(assignment: &Assignment, secret: Zeroizing<Vec<u8>>) -> Result<Arc<Self>> {
        ensure!(assignment.role == Role::Ingest, "this binary serves the ingest role only");
        use std::os::fd::AsRawFd;
        let lock = std::fs::OpenOptions::new().create(true).write(true)
            .open(assignment.state_dir.join("part-log-appender.lock"))?;
        // SAFETY: flock only changes the advisory lock on our owned fd.
        ensure!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another tenant ingest process owns the part-log appender");
        let credentials = credentials_from_secret(&secret, assignment).await?;
        super::startup::advance("credentials ready");
        drop(secret);
        // NAN-3867: the tenant's `publish` login (erasure orders, credential
        // activity and, NAN-4052, the cell writer lease), re-fed on refresh.
        let erasure_ledger = super::lean_erasure::ErasureLedgerSlot::default();
        erasure_ledger.set(credentials.erasure_ledger.clone());
        // NAN-4052: the cell writer lease, before anything that could fence
        // a live writer on the peer pod (the edge-log DO lease, the part log).
        let writer_lease = acquire_writer_lease(assignment, &erasure_ledger).await?;
        super::startup::advance("writer lease");
        // NAN-4129: renew from now on, not from the run loop. Setup can
        // outlast the TTL on a slow node (TX: ~9.2 s against 8 s), and a lease
        // that lapses during setup stops ingest in a loop. A loss during setup
        // drops the setup at once (standby): nothing runs past it without the
        // lease. A failed or dropped setup drops the renewer, which stops it.
        let lease_renewer = writer_lease.clone().map(super::writer_lease::LeaseRenewer::start);
        let lost = lease_renewer.as_ref().map(|renewer| renewer.lost_signal());
        let service = super::writer_lease::abort_setup_on_loss(
            lost,
            Self::open_with_lease(assignment, credentials, lock, erasure_ledger, writer_lease, lease_renewer),
        )
        .await?;
        if let Some(renewer) = &service.lease_renewer {
            let held_for = renewer.held_for();
            let ttl = renewer.lease().ttl();
            let deadline = ttl.saturating_sub(super::writer_lease::margin(ttl));
            if held_for >= deadline {
                tracing::warn!(setup_ms = held_for.as_millis() as u64, ttl_ms = ttl.as_millis() as u64, epoch = renewer.lease().epoch(),
                    "ingest setup outlasted the cell writer lease TTL; the lease was renewed in the background during setup");
            } else {
                tracing::info!(setup_ms = held_for.as_millis() as u64, ttl_ms = ttl.as_millis() as u64, epoch = renewer.lease().epoch(),
                    "ingest setup finished under the cell writer lease");
            }
        }
        Ok(service)
    }

    /// Everything [`Self::start`] does once the writer lease is held (or the
    /// cell runs without one). Runs while the lease renews in the
    /// background; [`Self::start`] drops it the moment the lease is lost.
    async fn open_with_lease(
        assignment: &Assignment,
        credentials: IngestCredentials,
        lock: std::fs::File,
        erasure_ledger: super::lean_erasure::ErasureLedgerSlot,
        writer_lease: Option<Arc<super::writer_lease::WriterLease>>,
        lease_renewer: Option<super::writer_lease::LeaseRenewer>,
    ) -> Result<Arc<Self>> {
        let tenant = assignment.tenant.as_str();
        // Setup checkpoints: never open anything that could fence the peer
        // (the edge-log DO lease, the part log) without a live lease.
        let ensure_lease = |phase: &str| lease_renewer.as_ref().map_or(Ok(()), |renewer| renewer.ensure_held(phase));
        // Enrichment is additive: a cell whose control plane does not yet mint
        // `enrichment_reader` (or render the platform mounts) keeps ingesting
        // unenriched, exactly as before enrichment shipped, instead of
        // crash-looping every lean tenant on an image roll.
        let lean_production = credentials.expires_at.is_some() && matches!(&credentials.input, InputCreds::Edge { .. });
        if lean_production && credentials.enrichment.is_none() {
            tracing::warn!("lean ingest has no enrichment_reader credential; tenant IOC and custom IP context enrichment are disabled");
        }
        // Process-lifetime singletons: the process exits when the service ends.
        // Parts go to R2 (checksummed single PUTs) whenever signing is pinned;
        // the cell's local parts dir is the lab store.
        type R2Handle = Option<(&'static super::r2_put::R2PartStore, Arc<super::r2_put::R2PartStore>)>;
        let (parts, r2_handle): (&'static dyn ObjectStore, R2Handle) =
            match (&assignment.part_signing, &credentials.parts) {
                (Some(_), Some(creds)) => {
                    let spill = assignment.state_dir.join("spill");
                    // Process lifetime.
                    let store: &'static super::r2_put::R2PartStore =
                        Box::leak(Box::new(super::r2_put::R2PartStore::new_split(&creds.part, &creds.log, tenant, &spill)?.with_native_writer(credentials.native_writer.clone().context("production ingest has no native writer")?)?.with_producer_cache(&assignment.parts_dir, cache_bytes_for(assignment) / 2)));
                    // The sanctioned GC pass reads through its own store and
                    // HTTP client, never ingest's (see `sanctioned_part_gc`).
                    let gc = Arc::new(super::r2_put::R2PartStore::new_split(&creds.part, &creds.log, tenant, &spill)?);
                    (store, Some((store, gc)))
                }
                (Some(_), None) => bail!("pinned part signing requires R2 part credentials"),
                (None, _) => (Box::leak(Box::new(LocalObjectStore::new(&assignment.parts_dir)?)), None),
            };
        let r2_parts = r2_handle.as_ref().map(|(store, _)| *store);
        type EdgeHandle = (Arc<crate::edge_log::EdgeLogSource<crate::edge_log::HttpEdgeLogClient>>, String);
        let (sources, queue, s3_sources, notice_queue, edge): (
            &'static dyn ObjectStore,
            &'static dyn NoticeQueue,
            Option<&'static S3ObjectStore>,
            Option<&'static DoNoticeQueue>,
            Option<EdgeHandle>,
        ) = match &credentials.input {
            InputCreds::Bronze { bronze, notices } => {
                let s3: &'static S3ObjectStore = Box::leak(Box::new(S3ObjectStore::new(bronze)?));
                let dq: &'static DoNoticeQueue = Box::leak(Box::new(DoNoticeQueue::new(notices, tenant)?));
                (s3, dq, Some(s3), Some(dq), None)
            }
            InputCreds::BronzeListed { bronze, settings } => {
                let s3: &'static S3ObjectStore = Box::leak(Box::new(S3ObjectStore::new(bronze)?));
                let queue: &'static super::bronze_list::BronzeListQueue<&'static S3ObjectStore> = Box::leak(Box::new(
                    super::bronze_list::BronzeListQueue::open(s3, tenant, &assignment.state_dir, settings)?,
                ));
                tracing::info!(watermark = ?queue.watermark(), settle_s = settings.settle().as_secs(), "trusted-local bronze listing input");
                (s3, queue, None, None, None)
            }
            InputCreds::Edge { endpoint, token } => {
                ensure_lease("edge source open")?;
                // Resume from the part log's edge point (or where edge mode
                // last ended); genesis on a fresh tenant.
                let live = crate::parts::part_log::load_log(parts, tenant).await?;
                let point = live.edge_point().or(live.edge_ended()).cloned();
                let client = crate::edge_log::HttpEdgeLogClient::new(endpoint, token.clone())?;
                let source = Arc::new(
                    crate::edge_log::EdgeLogSource::open(
                        client,
                        tenant,
                        "ingest",
                        point.as_ref(),
                        super::ingest::edge_source_config(super::ingest::flush_depth_from_env(
                            std::env::var(super::ingest::FLUSH_DEPTH_ENV).ok().as_deref())),
                    )
                    .await?,
                );
                let queue: &'static super::edge::EdgeQueue<crate::edge_log::HttpEdgeLogClient> =
                    Box::leak(Box::new(super::edge::EdgeQueue::new(source.clone(), tenant)));
                let segments: &'static super::edge::EdgeSegments<crate::edge_log::HttpEdgeLogClient> =
                    Box::leak(Box::new(super::edge::EdgeSegments::new(source.clone())));
                (segments, queue, None, None, Some((source, endpoint.clone())))
            }
        };
        super::startup::advance("edge source ready");
        let enrichment = credentials.enrichment.as_ref().map(|location| {
            let store: &'static S3ObjectStore = Box::leak(Box::new(S3ObjectStore::new(location)?));
            let tenant_uuid = tenant.parse().context("lean enrichment tenant must be a UUID")?;
            let snapshots = LeanEnrichmentSnapshots::new(tenant_uuid, store, &assignment.state_dir.join("enrichment"))?;
            Ok::<_, anyhow::Error>((store, snapshots))
        }).transpose()?;
        let initial_enrichment_pointer = match &enrichment {
            Some((_, snapshots)) => snapshots.current().await?,
            None => None,
        };
        let internal_domains_store = enrichment.as_ref().map(|(store, _)| *store);
        if let Some(store) = internal_domains_store {
            // Non-fatal: an unreadable list keeps the built-ins until the next refresh.
            if let Err(error) = refresh_internal_domains(store, tenant).await {
                tracing::warn!(error = %format!("{error:#}"), "tenant internal domains unavailable at startup; using built-ins");
            }
        }
        let initial_ioc = match (&enrichment, &initial_enrichment_pointer) {
            (Some((_, snapshots)), Some(pointer)) => Some(snapshots.load(pointer).await?),
            _ => None,
        };
        super::startup::advance("IOC snapshot ready");
        let platform_paths = platform_paths(assignment)?;
        if lean_production && platform_paths.is_none() {
            tracing::warn!("lean ingest has no platform bundle/policy mounts; platform enrichment is disabled");
        }
        let initial_platform = platform_paths.as_ref().map(|paths| load_platform(tenant, paths)).transpose()?;
        // Optional tenant-private mount containing current.json and its
        // digest-named Parquet snapshot. The manifest binds it to this process
        // tenant; a configured but missing assignment fails startup/refresh.
        let custom_context_root = assignment.custom_context_root.clone();
        let initial_custom_assignment = custom_context_root.as_ref()
            .map(|root| custom_context_assignment(root, tenant)).transpose()?;
        // Without a mount, the tenant's published custom IP context comes from
        // its R2 enrichment prefix, pinned by revision like the IOC snapshot.
        let ip_context = match (&custom_context_root, &enrichment) {
            (None, Some((store, _))) => {
                let tenant_uuid = tenant.parse().context("lean enrichment tenant must be a UUID")?;
                Some(LeanIpContextSnapshots::new(tenant_uuid, *store, &assignment.state_dir.join("enrichment").join("ip_context"))?)
            }
            (Some(_), Some(_)) => {
                tracing::warn!("custom_context_root mount is configured; tenant R2 custom IP context is not read");
                None
            }
            _ => None,
        };
        let initial_ip_context_pointer = match &ip_context {
            Some(snapshots) => snapshots.current().await?,
            None => None,
        };
        let initial_custom = match (&initial_custom_assignment, &ip_context, &initial_ip_context_pointer) {
            (Some((path, digest)), _, _) => Some(crate::ip_context::IpContextSnapshot::open_lean(path, digest)?),
            (None, Some(snapshots), Some(pointer)) => Some(snapshots.load(pointer).await?),
            _ => None,
        };
        // NAN-3503: directory identity stamping, only with the cell flag and
        // the tenant enrichment reader. Off: no store, no reads, no change.
        // Cold start never waits on a build: the handle starts empty and
        // `run` installs the directory from a background task.
        let identity = match (assignment.identity_directory_enrich, &enrichment) {
            (true, Some((store, _))) => {
                let tenant_uuid = tenant.parse().context("lean enrichment tenant must be a UUID")?;
                // Process lifetime.
                let directories: &'static LeanIdentityDirectories<'static> = Box::leak(Box::new(
                    LeanIdentityDirectories::new(tenant_uuid, *store, &assignment.state_dir.join("enrichment").join("ingest-identity"))?,
                ));
                Some((directories, IdentityDirectoryHandle::default()))
            }
            (true, None) => {
                tracing::warn!("identity_directory_enrich is on but ingest has no enrichment_reader credential; identity stamping is disabled");
                None
            }
            (false, _) => None,
        };
        let identity_handle = identity.as_ref().map(|(_, handle)| handle.clone());
        super::startup::advance("enrichment ready");
        let edge_source = edge.as_ref().map(|(source, _)| source.clone());
        let (signer, refresh): (&'static dyn PartSigner, Option<Refreshable>) = match credentials.expires_at {
            Some(expires_at) => {
                // Production: the signer is the HTTP one; keep a typed handle.
                let key_id = credentials.signer.key_id().to_string();
                drop(credentials.signer);
                let signing = assignment.part_signing.as_ref().context("part_signing")?;
                ensure!(signing.signer_key_id == key_id);
                let bearer = credentials.bearer.clone().context("production credentials carry a bearer")?;
                let http: &'static HttpPartSigner = Box::leak(Box::new(HttpPartSigner::new(
                    &signing.url,
                    &bearer,
                    &signing.signer_key_id,
                    credentials.trusted.clone(),
                    signing.ca_file.as_deref(),
                )?));
                (http, Some(Refreshable {
                        sources: s3_sources,
                        notices: notice_queue,
                        edge,
                        parts: r2_parts,
                        gc_parts: r2_handle.as_ref().map(|(_, gc)| gc.clone()),
                        enrichment: enrichment.as_ref().map(|(store, _)| *store),
                        signer: http,
                        refresher: CredentialRefresher::new(expires_at),
                    }))
            }
            None => (Box::leak(credentials.signer), None),
        };
        // Edge tenants stay up by default: nothing wakes an exited ingest
        // until the metrics-only wake token lands (NAN follow-up).
        // Detect may publish after the last source notice. Its sole append
        // owner must remain reachable even when bronze ingestion is idle.
        let idle_exit = if assignment.part_signing.is_some() { false } else {
            // Nothing wakes an exited edge or listing ingest: both stay up.
            assignment.ingest_idle_exit.unwrap_or(!matches!(credentials.input, InputCreds::Edge { .. } | InputCreds::BronzeListed { .. }))
        };
        let mut cfg = IngestConfig::new(tenant, &assignment.state_dir)
            .with_owner_requires_checksum(assignment.owner_requires_checksum);
        cfg.merge_policy.day_merges = assignment.ingest_day_merges;
        apply_merge_policy(&mut cfg, assignment.ingest_merge_policy.as_ref())?;
        // Merges never hold the tick (admission, flushes, edge commits).
        cfg.background_merges = true;
        // NAN-3032: every part writer of this process (L0, merges, findings)
        // emits v2 token block indexes.
        crate::parts::block_index::set_enabled(assignment.ingest_keyword_index);
        // ... and v3 per-minute counts of dense keyword tokens, which serve
        // single-keyword histograms and totals without a scan.
        crate::parts::token_counts::set_enabled(assignment.ingest_keyword_index);
        // NAN-3058: every part writer of this process (L0, merges that
        // rebuild partials from rows, findings) derives identity observations.
        crate::identity_observations::set_enabled(assignment.identity_observations);
        cfg.flush_policy = flush_policy_for(assignment)?;
        cfg.source_key_prefix = Some(format!("tenant_id={tenant}/"));
        if matches!(credentials.input, InputCreds::Edge { .. }) {
            // Edge segment keys are checked by the edge contract instead.
            cfg.source_key_prefix = None;
        }
        // Share the existing ingest disk allocation between merge inputs and
        // fresh producer objects instead of doubling the tenant's footprint.
        cfg.cache_max_bytes = if r2_parts.is_some() { cache_bytes_for(assignment) / 2 } else { cache_bytes_for(assignment) };
        cfg.max_window_uids = super::dedup::window_cap_for(assignment.memory_cap_bytes);
        cfg.buffer_budget_bytes = super::ingest::buffer_budget_for(assignment.memory_cap_bytes);
        // NAN-3619: flushes in flight at once (default 1; the edge source
        // above is opened with the same depth).
        cfg.flush_depth = super::ingest::flush_depth_from_env(std::env::var(super::ingest::FLUSH_DEPTH_ENV).ok().as_deref());
        cfg.commit_when_ready = super::ingest::commit_when_ready_from_env(std::env::var(super::ingest::COMMIT_WHEN_READY_ENV).ok().as_deref());
        // NAN-3662: per-source refusal counts in `reject` details (default off).
        cfg.refusal_source_counts = crate::parts::refusal_tally::write_enabled_from_env(
            std::env::var(crate::parts::refusal_tally::WRITE_ENV).ok().as_deref());
        // NAN-3183 OOM: bound glibc's retention of freed catch-up buffers.
        super::memory::tune_allocator();
        super::merge::set_memory_budget(assignment.memory_cap_bytes);
        cfg.writer_epoch = credentials.writer_epoch;
        cfg.prevalence_location = credentials.prevalence.clone();
        // Production without a prevalence grant runs unstamped; only the lab
        // (no R2 part credentials) uses a local prevalence DB.
        cfg.prevalence_enabled = credentials.prevalence.is_some() || credentials.parts.is_none();
        // NAN-3492: the tenant's stored threshold, else 3 (every mode).
        cfg.prevalence_rarity_threshold = crate::prevalence::assignment_rarity_threshold(assignment);
        let local_gc = if let Some(config) = &credentials.local_gc {
            ensure!(assignment.control_url.is_none() && assignment.part_signing.is_none() && r2_handle.is_none(),
                "local GC is forbidden with hosted credentials");
            let pool = nanosiem_core::db::pooler::connect_lazy(nanosiem_core::db::connection_budget::pool_options(1), &config.database_url)?;
            let authority = crate::lake_part_gc::local::LocalDeleteAuthority::new(
                Arc::new(LocalObjectStore::new(&assignment.parts_dir)?), tenant,
                credentials.trusted.clone(), crate::lake_part_gc::GcPolicy::default(), Some(pool),
            )?;
            if let Some(source) = s3_sources {
                authority.attach_bronze(crate::lake_part_gc::local_bronze::LocalBronzeRetention::new(
                    source, tenant, assignment.state_dir.join("bronze-list-cursor.json"),
                )?);
            }
            Some(authority)
        } else { None };
        let part_gc_route = assignment_part_gc(assignment, r2_handle.as_ref().map(|(_, gc)| gc), credentials.trusted.clone());
        super::startup::advance("ingestor open");
        ensure_lease("ingestor open")?;
        let mut ingestor = Ingestor::open(
            cfg,
            parts,
            sources,
            queue,
            signer,
            credentials.trusted,
            match &initial_platform {
                Some((bundle, policy)) => BronzeIngestEnricher::new(None, initial_ioc, initial_custom).with_identity_handle(identity_handle.clone()).with_lean_platform(bundle.clone(), policy.clone()),
                None => BronzeIngestEnricher::new(None, initial_ioc, initial_custom).with_identity_handle(identity_handle.clone()),
            },
            &seed_schema(),
            now_ms(),
        )
        .await?;
        let pipeline_diagnostics = ingestor.diagnostics();
        ingestor.set_initial_enrichment_revision(initial_enrichment_pointer.as_ref().map(|pointer| pointer.revision.to_string()))?;
        // NAN-3077: the old-hour reindex fetches in the background with the
        // cell's 'static part store (it stays off unless enabled).
        ingestor.set_background_store(parts);
        ingestor.set_background_signer(signer);
        // NAN-3619 (commit-when-ready flag): a finished flight wakes the
        // loop to commit it now. Off: the loop wakes as before.
        let wake = Arc::new(tokio::sync::Notify::new());
        if super::ingest::commit_when_ready_from_env(std::env::var(super::ingest::COMMIT_WHEN_READY_ENV).ok().as_deref()) {
            ingestor.set_flight_wake(wake.clone());
        }
        // Deletes only through the sanctioned route, only while the grant is
        // enabled (`part_gc_gate`); without a delivered route the gate says
        // `sanctioned_path_unavailable` and every part is kept.
        if let Some(route) = &part_gc_route {
            route.update(credentials.part_gc.as_ref(), credentials.part_delete_grant.as_ref());
            // NAN-3810: the route exists only beside the R2 part store, whose
            // production ingest writes always go through the native writer
            // ("production ingest has no native writer" above): a committed
            // create means control accepted the entry's completion receipt.
            ingestor.set_receipted_appends(route.receipted_appends());
        }
        let part_gc = Arc::new(ExchangedGrantAuthority::new(
            tenant,
            part_gc_route.clone().map(|route| route as Arc<dyn SanctionedPartGc>),
        ));
        part_gc.update(credentials.part_delete_grant.as_ref());
        if let Some(local_gc) = local_gc {
            ingestor.set_local_gc(local_gc);
        } else {
            ingestor.set_part_gc_authority(part_gc.clone());
        }
        // NAN-3867: ingest[T] executes the tenant's erasure orders when the
        // platform delivers the ledger login (it declares this cell the
        // executor only for `lean_erasure_v1` images).
        ingestor.set_erasure_ledger(erasure_ledger.clone(), format!("lean-cell:{}", assignment.cell_id));
        // NAN-3899: hosted lean ingest records per-credential activity (the
        // Credentials table's last seen / 24 h events) through the same
        // tenant-bound `publish` login; nothing is written without it.
        if assignment.control_url.is_some() {
            ingestor.set_credential_activity(super::credential_activity::ActivityExec::from_ledger(
                tenant, Some(&assignment.state_dir), erasure_ledger.clone()));
        }
        if let Some(lease) = &writer_lease {
            ingestor.set_append_gate(lease.clone());
        }
        // NAN-4338: quarantined edge segments are reported to the tenant's
        // landing ledger over the edge-log consumer credential.
        if let Some(source) = &edge_source {
            ingestor.set_quarantine_ledger(source.clone());
        }
        ensure_lease("setup done")?;
        let finding_context = ingestor.finding_context();
        Ok(Arc::new(Self {
            ingestor: tokio::sync::Mutex::new(ingestor),
            finding_gate: FindingGate::new(FindingGateConfig::default()),
            finding_context,
            pending_prevalence: std::sync::Mutex::new(None),
            terminal: tokio::sync::watch::channel(None).0,
            edge_source,
            _append_lock: lock,
            writer_epoch: credentials.writer_epoch,
            epoch_changed: AtomicBool::new(false),
            active_appends: AtomicUsize::new(0),
            wake,
            heartbeat: std::sync::Mutex::new(Heartbeat::default()),
            pipeline_diagnostics,
            native_writer_diagnostics: credentials.native_writer.clone(),
            assignment: assignment.clone(),
            idle_exit,
            refresh,
            enrichment: enrichment.map(|(_, snapshots)| snapshots),
            initial_enrichment_pointer,
            platform_paths,
            initial_platform,
            custom_context_root,
            initial_custom_assignment,
            ip_context,
            initial_ip_context_pointer,
            identity,
            internal_domains_store,
            part_gc,
            part_gc_route,
            erasure_ledger,
            writer_lease,
            lease_renewer,
        }))
    }

    /// `(expired, given_up)`: past expiry (minus skew) ingest stops
    /// uploading, admitting and acking until a refresh succeeds; once refresh
    /// has also given up, the process exits so a respawn starts fresh.
    fn credentials_state(&self) -> (bool, bool) {
        self.refresh.as_ref().map_or((false, false), |r| r.refresher.status())
    }

    /// Credential refresh runs on its own thread and runtime
    /// (`cell_refresh::priority_runtime`), so neither a long synchronous
    /// merge nor any other CPU-heavy work on the ingest runtime delays it. It
    /// asks for a fresh bootstrap once half of the credential lifetime passed
    /// (or when a transient backoff elapsed). Once refresh gives up on a final
    /// refusal, no later refresh will come: the process
    /// exits NOW for a respawn with a fresh bootstrap, instead of idling to
    /// expiry (or, as on 2026-09-29, forever).
    pub fn spawn_refresher(self: &Arc<Self>, control: ControlChannel) -> tokio::task::JoinHandle<()> {
        let refresher = self.refresh.as_ref().map(|r| r.refresher.clone());
        let this = self.clone();
        crate::cell_refresh::spawn_prioritized(async move {
            let Some(refresher) = refresher else { return };
            if let Err(error) = refresher.run_until_given_up(control).await {
                this.terminate(format!("credential refresh: {error:#}"));
            }
        })
    }

    /// The edge-log stall watchdog (`stall_watchdog`), outside the ingest
    /// loop: no committed progress for [`EDGE_STALL_RESTART_AFTER`] while
    /// the edge holds data past the committed point, and no loop progress
    /// either (bounded by [`EDGE_STALL_HARD_AFTER`], NAN-3387) → restart.
    fn spawn_stall_watchdog(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let Some(source) = self.edge_source.clone() else { return tokio::spawn(async {}) };
        let this = self.clone();
        tokio::spawn(async move {
            let stall = super::stall_watchdog::watch(EDGE_STALL_RESTART_AFTER, EDGE_STALL_HARD_AFTER, EDGE_STALL_SAMPLE_EVERY, || {
                let source = source.clone();
                async move { source.try_status().map(|status| super::stall_watchdog::position(&status)) }
            }, super::stall_watchdog::progress)
            .await;
            tracing::error!(stall = %stall, signal = "ingest_edge_log_stalled", "ingest edge-log stall watchdog fired; restarting");
            {
                let mut heartbeat = this.heartbeat.lock().expect("heartbeat lock");
                heartbeat.busy = true;
                heartbeat.detail = Some(format!("edge_log_stalled: {stall}").chars().take(200).collect());
            }
            this.terminate(format!("edge-log stall watchdog: {stall}"));
        })
    }

    /// Ask `run` to exit (non-zero) so the supervisor respawns ingest.
    fn terminate(&self, reason: String) {
        self.terminal.send_if_modified(|current| {
            if current.is_some() {
                return false;
            }
            *current = Some(reason);
            true
        });
    }

    /// The ingest loop: tick on wake or every second; exit after
    /// [`IDLE_EXIT`] with nothing to do.
    ///
    /// A failing tick is retried in-process with backoff (the buffer is
    /// held: commits are idempotent across retries, nothing is acked). Only
    /// a fencing conflict (another writer owns the log), or failures lasting
    /// longer than [`MAX_RETRY_WINDOW`], are fatal.
    ///
    /// The loop runs in its own task; this future only waits for it or for a
    /// terminal condition (refresh gave up, edge stall), so neither a long
    /// tick nor a blocked thread can keep a wedged process alive.
    pub async fn run(self: Arc<Self>, control: ControlChannel) -> Result<()> {
        let mut terminal = self.terminal.subscribe();
        let refresher = self.spawn_refresher(control.clone());
        let watchdog = self.spawn_stall_watchdog();
        // NAN-3503: the identity directory refreshes in its own task.
        let identity_refresh = self.identity.as_ref().map(|(directories, handle)| {
            tokio::spawn(crate::identity_enrichment::run_identity_refresh(
                *directories,
                handle.clone(),
                self.assignment.tenant.as_str().to_string(),
                crate::identity_enrichment::IDENTITY_REFRESH_EVERY,
            ))
        });
        // NAN-4052: losing the cell writer lease stops this writer. NAN-4129:
        // the renewer has run since the lease was acquired (`start`); this
        // only watches it.
        let lease_renewer = self.lease_renewer.as_ref().map(|renewer| {
            let lost = renewer.lost_signal();
            let this = self.clone();
            tokio::spawn(async move {
                let lost = lost.await;
                this.wake.notify_one();
                this.terminate(lost.to_string());
            })
        });
        let mut work = tokio::spawn({
            let this = self.clone();
            let control = control.clone();
            async move { this.run_loop(&control).await }
        });
        let result = tokio::select! {
            joined = &mut work => joined.unwrap_or_else(|error| Err(anyhow::anyhow!("ingest loop task: {error}"))),
            reason = terminal.wait_for(Option::is_some) => {
                if let Some(lost) = self.writer_lease.as_ref().and_then(|lease| lease.lost()) {
                    // Standby, not a failure: no fatal report; the binary exits
                    // with the standby code and the supervisor retries later.
                    std::thread::spawn(|| {
                        std::thread::sleep(Duration::from_secs(30));
                        std::process::exit(nanosiem_lake_cell::contract::WRITER_STANDBY_EXIT_CODE);
                    });
                    work.abort();
                    refresher.abort();
                    watchdog.abort();
                    if let Some(task) = &lease_renewer {
                        task.abort();
                    }
                    self.stop_lease_renewer();
                    if let Some(task) = &identity_refresh {
                        task.abort();
                    }
                    return Err(lost.into());
                }
                let reason = reason.map(|reason| reason.clone().unwrap_or_default())
                    .unwrap_or_else(|_| "terminal channel closed".into());
                tracing::error!(reason = %reason, "ingest exiting for a respawn");
                let _ = tokio::time::timeout(Duration::from_secs(5), control.fatal(&reason)).await;
                // The binary exits as soon as this returns; should anything
                // hold it up (a blocked thread), exit regardless.
                std::thread::spawn(|| {
                    std::thread::sleep(Duration::from_secs(30));
                    std::process::exit(75);
                });
                work.abort();
                Err(anyhow::anyhow!(reason))
            }
        };
        refresher.abort();
        watchdog.abort();
        if let Some(task) = lease_renewer {
            task.abort();
        }
        self.stop_lease_renewer();
        if let Some(task) = identity_refresh {
            task.abort();
        }
        result
    }

    /// NAN-4129: teardown stops renewing the cell writer lease.
    fn stop_lease_renewer(&self) {
        if let Some(renewer) = &self.lease_renewer {
            renewer.stop();
        }
    }

    async fn handle_finding_rpc(&self, mut stream: tokio::net::UnixStream) -> Result<()> {
        // The supervisor grants this stream only to an authenticated Detect
        // child for the same tenant. A full queue refuses at once; the rows
        // stay in detect's outbox and its drain retries.
        let admitted = self.finding_gate.admit()?;
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(10),
            (&mut stream).take(MAX_REQUEST_BYTES + 1).read_to_end(&mut bytes)).await??;
        ensure!(bytes.len() as u64 <= MAX_REQUEST_BYTES, "finding append request is too large");
        let request: FindingAppendRequest = serde_json::from_slice(&bytes)?;
        let ack = self.finding_gate.append(admitted, &self.ingestor, &self.finding_context, request, now_ms).await?;
        let response = serde_json::to_vec(&ack)?;
        stream.write_all(&response).await?;
        stream.shutdown().await?;
        Ok(())
    }

    /// Apply a prevalence credential change queued by [`TenantService::secrets`].
    async fn apply_pending_prevalence(&self, ingestor: &mut Ingestor<'static>) {
        let Some(update) = self.pending_prevalence.lock().expect("prevalence lock").take() else { return };
        match update {
            PrevalenceUpdate::Rotate(location) => {
                if let Err(error) = ingestor.refresh_prevalence_credential(&location).await {
                    tracing::error!(error = %format!("{error:#}"), "could not reopen tenant prevalence state with refreshed credentials; re-exchanging");
                    if let Some(refresh) = &self.refresh {
                        refresh.refresher.request_now();
                    }
                }
            }
            // Keep the part and signing refresh: losing the prevalence
            // grant must not expire the tenant's ingest. The old
            // prevalence credential (read key + owner bearer, <= 10 min)
            // expires before the next refresh, so it is never kept
            // (NAN-3017): prevalence is suspended (rows unstamped, the
            // state's replay cursor stays put) and resumes in-process
            // when a later exchange carries the grant again.
            PrevalenceUpdate::Withdraw => {
                if ingestor.suspend_prevalence().await {
                    tracing::error!("refreshed exchange withheld the prevalence grant (lake_prevalence_state + prevalence_owner); \
                        prevalence suspended, rows unstamped until an exchange grants it again");
                } else {
                    tracing::debug!("refreshed exchange has no prevalence grant; prevalence stays unstamped");
                }
            }
        }
    }

    /// Re-read the tenant IOC pointer, platform policy and custom context.
    /// `pins` changes only after the new enricher is installed, so an error
    /// leaves the active enricher and its pinned revisions untouched.
    async fn refresh_enrichment(&self, ingestor: &mut Ingestor<'static>, pins: &mut EnrichmentPins) -> Result<()> {
        let (rotation, next_platform) = plan_enrichment_refresh(
            self.enrichment.as_ref(),
            self.platform_paths.as_ref(),
            self.custom_context_root.as_deref(),
            self.ip_context.as_ref(),
            self.assignment.tenant.as_str(),
            pins,
        )
        .await?;
        if let Some(rotation) = rotation {
            // The identity handle carries over: a directory swap alone never
            // rotates the enricher or cuts a part.
            let enricher = rotation.enricher.with_identity_handle(self.identity.as_ref().map(|(_, handle)| handle.clone()));
            ingestor.replace_enricher(enricher, rotation.pointer.as_ref().map(|pointer| pointer.revision.to_string()), now_ms()).await?;
            pins.pointer = rotation.pointer;
            pins.custom_assignment = rotation.custom_assignment;
            pins.ip_context_pointer = rotation.ip_context_pointer;
        }
        pins.platform = next_platform;
        if let Some(store) = self.internal_domains_store {
            // Independent of the IOC/platform pins: a bad document keeps the
            // active internal-domain set and never fails the enrichment refresh.
            if let Err(error) = refresh_internal_domains(store, self.assignment.tenant.as_str()).await {
                tracing::warn!(error = %format!("{error:#}"), "tenant internal domains refresh failed; keeping the active set");
            }
        }
        Ok(())
    }

    // Close one static INFO span per tick so jailed children feed stdout tracing.
    #[tracing::instrument(name = "cell.ingest.tick", skip_all)]
    async fn phased_tick(&self) -> Result<super::ingest::TickReport> {
        self.ingestor.lock().await.tick_prevalence(now_ms()).await;
        let (mut report, pending) = self.ingestor.lock().await.tick_ingest(now_ms()).await?;
        self.ingestor.lock().await.tick_maintain(now_ms(), &pending, &mut report).await?;
        Ok(report)
    }

    async fn run_loop(&self, control: &ControlChannel) -> Result<()> {
        let mut last_work = Instant::now();
        let mut failing_since: Option<Instant> = None;
        let mut failures = 0_u32;
        let mut enrichment = EnrichmentPins {
            pointer: self.initial_enrichment_pointer.clone(),
            platform: self.initial_platform.clone(),
            custom_assignment: self.initial_custom_assignment.clone(),
            ip_context_pointer: self.initial_ip_context_pointer.clone(),
        };
        let mut next_enrichment_check = Instant::now();
        let mut enrichment_failing_since: Option<Instant> = None;
        let mut enrichment_failures = 0_u32;
        let mut last_dedupe_health_log = Instant::now();
        // NAN-3522: the over-commit hold (placement `ingest_hold_eps`).
        let mut hold = super::hold::IngestHold::new(self.assignment.ingest_hold_eps, Instant::now());
        if let Some(h) = &hold {
            tracing::warn!(hold_eps = h.eps(), "over-commit hold: admitting at most hold_eps rows/s; the rest waits in the source");
        }
        loop {
            if let Some(lost) = self.writer_lease.as_ref().and_then(|lease| lease.lost()) {
                tracing::warn!(epoch = lost.epoch, reason = %lost.reason, "ingest stops: the cell writer lease is gone (standby)");
                return Err(lost.into());
            }
            if self.epoch_changed.load(Ordering::Relaxed) {
                let error = anyhow::anyhow!("ingest writer epoch changed; restart required");
                let _ = control.fatal(&format!("{error:#}")).await;
                return Err(error);
            }
            tokio::select! {
                _ = self.wake.notified() => {}
                _ = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
            let (expired, given_up) = self.credentials_state();
            if expired && given_up {
                let error = anyhow::anyhow!("credentials expired and refresh gave up");
                tracing::error!("ingest exiting: credentials expired and refresh gave up");
                let _ = control.fatal(&format!("{error:#}")).await;
                return Err(error);
            }
            if expired {
                // Nothing that could not be signed is uploaded, nothing new is
                // admitted, nothing is acked (the DO keeps the notices). The
                // heartbeat reports stalled so the supervisor pages.
                let mut heartbeat = self.heartbeat.lock().expect("heartbeat lock");
                heartbeat.busy = true;
                heartbeat.detail = Some("credentials_expired".into());
                last_work = Instant::now();
                continue;
            }
            let mut ingestor = self.ingestor.lock().await;
            self.apply_pending_prevalence(&mut ingestor).await;
            if Instant::now() >= next_enrichment_check {
                // A failed refresh (R2 blip, owner 503 on the rotation's
                // flush, refused over-cap candidate, unreadable policy) keeps
                // the active enricher and its pinned revisions.
                match self.refresh_enrichment(&mut ingestor, &mut enrichment).await {
                    Ok(()) => {
                        if let Some(since) = enrichment_failing_since.take() {
                            tracing::info!(failures = enrichment_failures, failed_for_s = since.elapsed().as_secs(), "enrichment refresh recovered");
                        }
                        enrichment_failures = 0;
                        next_enrichment_check = Instant::now() + ENRICHMENT_CHECK_INTERVAL;
                    }
                    Err(error) if enrichment_refresh_may_ingest(&enrichment) => {
                        // NAN-3723: a pinned snapshot is enriching rows, so
                        // keep ingesting on it and retry the refresh with
                        // backoff. Holding here stalled search freshness for
                        // minutes on an owner blip during a cell roll; rows
                        // enriched minutes stale are the lesser harm.
                        let since = *enrichment_failing_since.get_or_insert_with(Instant::now);
                        enrichment_failures += 1;
                        let delay = retry_delay(enrichment_failures);
                        tracing::error!(error = %format!("{error:#}"), failures = enrichment_failures,
                            failing_for_s = since.elapsed().as_secs(), retry_in_s = delay.as_secs(),
                            "enrichment refresh failed; ingesting on the pinned enrichment snapshot and retrying");
                        next_enrichment_check = Instant::now() + delay;
                    }
                    Err(error) => {
                        // No snapshot pinned yet: nothing can enrich the rows,
                        // so do not admit them; retry in-process like a
                        // failing tick, fatal only after MAX_RETRY_WINDOW.
                        let since = *enrichment_failing_since.get_or_insert_with(Instant::now);
                        if since.elapsed() >= MAX_RETRY_WINDOW {
                            tracing::error!(error = %format!("{error:#}"), "ingest exiting: enrichment refresh failing longer than MAX_RETRY_WINDOW");
                            let _ = control.fatal(&format!("enrichment refresh: {error:#}")).await;
                            return Err(error);
                        }
                        enrichment_failures += 1;
                        let delay = retry_delay(enrichment_failures);
                        tracing::error!(error = %format!("{error:#}"), failures = enrichment_failures, delay_s = delay.as_secs(), "enrichment refresh failed; holding ingest and retrying in-process");
                        {
                            let mut heartbeat = self.heartbeat.lock().expect("heartbeat lock");
                            heartbeat.busy = true;
                            heartbeat.retrying = true;
                            heartbeat.detail = Some(format!("enrichment refresh: {error:#}").chars().take(200).collect());
                        }
                        drop(ingestor);
                        last_work = Instant::now();
                        tokio::time::sleep(delay).await;
                        continue;
                    }
                }
            }
            // The tick's three phases each take the ingestor lock on their
            // own (tokio's mutex is FIFO): a finding append waits for at
            // most one phase, never a whole tick, a prevalence rebuild step
            // plus a catch-up flush plus merges (NAN-3067).
            if let Some(h) = hold.as_mut() {
                let paused = !h.may_admit(Instant::now());
                ingestor.set_admission_hold(Some(h.byte_budget(Instant::now())), paused);
                // A paused admission is the hold working, not a wedge: paused
                // time counts toward neither stall bound (a large object at a
                // low hold rate is hours of debt; the committed point cannot
                // move meanwhile, and a restart would only replay it).
                if paused {
                    super::stall_watchdog::note_hold_pause();
                }
            }
            drop(ingestor);
            let phased = self.phased_tick().await;
            ingestor = self.ingestor.lock().await;
            let report = match phased {
                Ok(report) => {
                    failing_since = None;
                    failures = 0;
                    if let Some(h) = hold.as_mut() {
                        h.spend(report.admitted_rows, report.admitted_bytes, Instant::now());
                    }
                    report
                }
                Err(error) => {
                    // Fenced, a double consume, or a store refusal no retry
                    // can fix (403, 400 BadDigest): fail-stop now.
                    let fenced = super::ingest::fatal_ingest_error(&error);
                    let since = *failing_since.get_or_insert_with(Instant::now);
                    if fenced || since.elapsed() >= MAX_RETRY_WINDOW || self.epoch_changed.load(Ordering::Relaxed) {
                        if super::writer_lease::is_standby(&error) {
                            tracing::warn!(error = %format!("{error:#}"), "ingest stops: the cell writer lease is gone (standby)");
                            return Err(error);
                        }
                        tracing::error!(error = %format!("{error:#}"), fenced, failing_for_s = since.elapsed().as_secs(), "ingest exiting: tick failure is fatal (fenced, or failing longer than MAX_RETRY_WINDOW)");
                        let _ = control.fatal(&format!("{error:#}")).await;
                        return Err(error);
                    }
                    // Classification precedes maintenance: fatal errors and
                    // an exhausted retry window must never start a new pass.
                    ingestor.tick_gc(now_ms()).await;
                    failures += 1;
                    let delay = retry_delay(failures);
                    tracing::error!(error = %format!("{error:#}"), failures, delay_s = delay.as_secs(), "ingest tick failed; retrying in-process");
                    {
                        let health = ingestor.health();
                        let mut heartbeat = self.heartbeat.lock().expect("heartbeat lock");
                        heartbeat.busy = true;
                        heartbeat.retrying = true;
                        heartbeat.objects_rejected = health.objects_rejected_total;
                        heartbeat.rows_rejected = health.rows_rejected_total;
                        update_gc_heartbeat(&mut heartbeat, health);
                        heartbeat.detail = Some(format!("{error:#}").chars().take(200).collect());
                    }
                    drop(ingestor);
                    last_work = Instant::now();
                    tokio::time::sleep(delay).await;
                    continue;
                }
            };
            // A tick that admitted or flushed is draining a backlog: tick
            // again without the 1 s idle wait (NAN-3183: two idle waits per
            // flush cost ~2 s of every ~33 s catch-up cycle).
            // Held and in debt: no immediate re-tick (the 1 s wait paces the
            // flushes and maintenance that still run).
            let held_back = hold.as_mut().is_some_and(|h| !h.may_admit(Instant::now()));
            if (report.admitted_rows > 0 || report.flushed_parts > 0) && !held_back {
                self.wake.notify_one();
            }
            let health = ingestor.health().clone();
            if last_dedupe_health_log.elapsed() >= DEDUPE_HEALTH_LOG_INTERVAL {
                last_dedupe_health_log = Instant::now();
                tracing::info!(tenant = %health.tenant_id, counters = %dedupe_health_counters(&health), "ingest dedupe health");
            }
            let busy = health.pending_notices > 0 || health.buffered_rows > 0 || health.merge_backlog > 0;
            if busy || report.admitted_rows > 0 || report.merges > 0 {
                last_work = Instant::now();
            }
            *self.heartbeat.lock().expect("heartbeat lock") = Heartbeat {
                ingest_diagnostics: None,
                startup_progress: None,
                busy,
                lag_seconds: health.lag_ms as f64 / 1_000.0,
                oldest_unmerged_l0_age_seconds: health.oldest_unmerged_l0_age_ms as f64 / 1_000.0,
                l0_merge_overdue_seconds: health.l0_merge_overdue_ms as f64 / 1_000.0,
                prevalence_behind_seconds: health.prevalence_behind_ms as f64 / 1_000.0,
                prevalence_behind_entries: health.prevalence_behind_entries,
                prevalence_degraded_seconds: health.prevalence_degraded_ms as f64 / 1_000.0,
                prevalence_degraded_seconds_total: health.prevalence_degraded_ms_total as f64 / 1_000.0,
                last_progress_unix_ms: health.last_commit_ms.unwrap_or(0).max(0) as u64,
                queue_depth: (health.pending_notices + health.merge_backlog) as u64,
                objects_rejected: health.objects_rejected_total,
                rows_rejected: health.rows_rejected_total,
                retrying: false,
                detail: Some({
                    let mut detail = match &hold {
                        // `held=` tells the supervisor and the platform the lag is the
                        // over-commit hold draining, not a stall.
                        Some(h) => format!("live_parts={} window_uids={} prevalence={} held={}", health.live_parts, health.window_uids, health.prevalence_status, h.eps()),
                        None => format!("live_parts={} window_uids={} prevalence={}", health.live_parts, health.window_uids, health.prevalence_status),
                    };
                    if enrichment_failures > 0 {
                        // Ingesting on the pinned snapshot while its refresh fails.
                        detail.push_str(&format!(" enrichment_refresh_failures={enrichment_failures}"));
                    }
                    detail
                }),
                part_gc_blocked: health.part_gc_blocked.clone(),
                part_gc_deleted_total: health.part_gc_deleted_total,
                rows_committed_total: health.rows_committed_total,
                credential_refresh_at_risk: false,
                identity_directory: None,
                selection_evidence_cache: None,
                // Filled in by `heartbeat()`.
                writer_lease_epoch: None,
                writer_ready: false,
                landing: None,
            };
            if self.idle_exit && !busy && last_work.elapsed() >= IDLE_EXIT {
                ingestor.flush_now(now_ms()).await?;
                tracing::info!("ingest idle; exiting");
                return Ok(());
            }
        }
    }
}

/// The local part cache budget: the cell's per-tenant disk budget (the
/// supervisor derives it from eps; `Assignment` carries memory, so scale
/// the design anchors: 1 GiB at 20 eps, 8 GiB at 300 eps, 30 GiB at 1,200).
pub fn cache_bytes_for(assignment: &Assignment) -> u64 {
    const GIB: f64 = 1_073_741_824.0;
    let eps = assignment.eps.max(1.0);
    let bytes = if eps <= 300.0 { 1.0 * GIB + (eps - 20.0).max(0.0) / 280.0 * 7.0 * GIB } else { 8.0 * GIB + (eps - 300.0) / 900.0 * 22.0 * GIB };
    // Leave a quarter for the parts dir, sources and state.
    (bytes * 0.75) as u64
}

// Copy after polling, including clearing a previously blocked state.
fn update_gc_heartbeat(heartbeat: &mut Heartbeat, health: &super::ingest::IngestHealth) {
    heartbeat.part_gc_blocked = health.part_gc_blocked.clone();
    heartbeat.part_gc_deleted_total = health.part_gc_deleted_total;
}

/// How often a healthy ingest loop re-reads its enrichment pointers.
const ENRICHMENT_CHECK_INTERVAL: Duration = Duration::from_secs(30);

/// NAN-3723: whether a failed enrichment refresh may leave ingest running on
/// the active enricher. True once any enrichment snapshot (tenant IOC
/// pointer, platform bundle + policy, custom or IP context) is pinned: rows
/// keep being enriched from it while the refresh retries. With nothing
/// pinned yet the refresh is the enrichment, so ingest holds as before.
fn enrichment_refresh_may_ingest(pins: &EnrichmentPins) -> bool {
    pins.pointer.is_some() || pins.platform.is_some() || pins.custom_assignment.is_some() || pins.ip_context_pointer.is_some()
}

/// How often the ingest loop logs [`dedupe_health_counters`].
const DEDUPE_HEALTH_LOG_INTERVAL: Duration = Duration::from_secs(60);

/// NAN-3723: the dedupe counters of [`super::ingest::IngestHealth`] for the
/// periodic "ingest dedupe health" line, so the NAN-3703 late-hour tier and
/// the NAN-3704 / NAN-3719 same-uid payload check can be read live from the
/// cell's logs. Cumulative since the ingest process started; counts only.
fn dedupe_health_counters(health: &super::ingest::IngestHealth) -> serde_json::Value {
    serde_json::json!({
        "rows_committed_total": health.rows_committed_total,
        "duplicates_dropped_total": health.duplicates_dropped_total,
        "same_uid_payload_diff_total": health.same_uid_payload_diff_total,
        "window_uids": health.window_uids,
        "window_hours": health.window_hours,
        "late_dedup_parts_unfetched_total": health.late_dedup_parts_unfetched_total,
        "late_dedup_tier_duplicates_total": health.late_dedup_tier_duplicates_total,
        "late_dedup_unverified_rows_total": health.late_dedup_unverified_rows_total,
        "late_dedup_beyond_horizon_rows_total": health.late_dedup_beyond_horizon_rows_total,
        "late_dedup_tier_hours": health.late_dedup_tier_hours,
        "late_dedup_tier_uids": health.late_dedup_tier_uids,
        "late_dedup_tier_bloom_bytes": health.late_dedup_tier_bloom_bytes,
        "late_dedup_tier_ready": health.late_dedup_tier_ready,
        "late_dedup_tier_spills_total": health.late_dedup_tier_spills_total,
        "late_dedup_tier_folds_total": health.late_dedup_tier_folds_total,
        "late_dedup_tier_fold_failures_total": health.late_dedup_tier_fold_failures_total,
        "late_dedup_tier_hours_dropped_over_budget_total": health.late_dedup_tier_hours_dropped_over_budget_total,
    })
}

/// In-process retries of a failing tick stop (fatal) after this long.
pub const MAX_RETRY_WINDOW: Duration = Duration::from_secs(30 * 60);

/// Cap of the in-process tick retry backoff. Every retry of a held buffer
/// is time its rows are not searchable, so after a dependency recovers
/// (owner sign, R2) data resumes within this long (NAN-2984; was 60 s,
/// which alone spent half the 2-minute visibility ceiling). At the cap a
/// failing tenant makes 4 attempts/min.
pub const MAX_RETRY_DELAY: Duration = Duration::from_secs(15);

/// 1 s doubling to [`MAX_RETRY_DELAY`].
pub fn retry_delay(failures: u32) -> Duration {
    Duration::from_secs(1_u64 << failures.saturating_sub(1).min(6)).min(MAX_RETRY_DELAY)
}

/// Apply the assignment's `ingest_merge_policy` overrides (cell feature
/// `ingest_merge_policy_v1`); absent fields keep the code defaults. Refuses
/// a policy outside the cell's bounds (a mismatched supervisor).
pub fn apply_merge_policy(cfg: &mut IngestConfig, policy: Option<&nanosiem_lake_cell::contract::IngestMergePolicy>) -> Result<()> {
    let Some(policy) = policy else { return Ok(()) };
    policy.validate().context("ingest_merge_policy")?;
    let ms = |v: u64| i64::try_from(v).context("ingest_merge_policy value");
    if let Some(v) = policy.hour_seal_ms {
        cfg.merge_policy.hour_seal_ms = ms(v)?;
    }
    if let Some(v) = policy.sealed_remerge_debounce_ms {
        cfg.merge_policy.sealed_remerge_debounce_ms = ms(v)?;
    }
    if let Some(v) = policy.sealed_remerge_max_defer_ms {
        cfg.merge_policy.sealed_remerge_max_defer_ms = ms(v)?;
    }
    if let Some(v) = policy.max_merges_per_tick {
        cfg.max_merges_per_tick = v as usize;
    }
    Ok(())
}

/// The assignment's L0 flush policy (`ingest_flush`), or the code default.
/// A policy outside the bounds is refused (the cell config validates the
/// same bounds, so this only trips on a mismatched supervisor).
pub fn flush_policy_for(assignment: &Assignment) -> Result<crate::parts::levels::FlushPolicy> {
    let Some(flush) = assignment.ingest_flush else { return Ok(crate::parts::levels::FlushPolicy::default()) };
    let policy = crate::parts::levels::FlushPolicy {
        min_age_ms: i64::try_from(flush.min_age_ms).context("ingest_flush.min_age_ms")?,
        max_age_ms: i64::try_from(flush.max_age_ms).context("ingest_flush.max_age_ms")?,
        target_rows: flush.target_rows,
    };
    policy.validate().context("ingest_flush")?;
    Ok(policy)
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/admin/count-backfill", tag = "lake-admin",
    params(("tenant" = String, Path)), responses((status = 200, body = serde_json::Value)),
    security(("operator_bearer" = [])))]
async fn count_backfill_status(axum::extract::State(service): axum::extract::State<Arc<IngestService>>) -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::to_value(service.ingestor.lock().await.health()).unwrap_or_default())
}

#[utoipa::path(post, path = "/v1/tenants/{tenant}/admin/count-backfill", tag = "lake-admin",
    params(("tenant" = String, Path)), request_body = Option<super::reindex::CountBackfill>,
    responses((status = 200, body = serde_json::Value), (status = 400, description = "Invalid window, writer disabled, or rewrite in flight"),
        (status = 403, description = "Full operator token required")), security(("operator_bearer" = [])))]
async fn start_count_backfill(axum::extract::State(service): axum::extract::State<Arc<IngestService>>, request: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    let bytes = match axum::body::to_bytes(request.into_body(), 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "invalid backfill request").into_response(),
    };
    let now = chrono::Utc::now().timestamp_millis();
    let window = if bytes.is_empty() {
        super::reindex::CountBackfill { start_ms: now - 7 * 86_400_000, end_ms: now }
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(window) => window,
            Err(_) => return (axum::http::StatusCode::BAD_REQUEST, "invalid backfill window").into_response(),
        }
    };
    let mut ingestor = service.ingestor.lock().await;
    match ingestor.start_count_backfill(window, now).await {
        Ok(()) => axum::Json(ingestor.health().clone()).into_response(),
        Err(error) => (axum::http::StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

/// NAN-3864: rows ingested unstamped before the restamp existed (tenant-a
/// 2026-10-14 05Z-21:35Z) are restamped by marking their hours owed; the
/// ingest loop rewrites them one sealed hour at a time once the prevalence
/// state is at the log head. Only rows without a stamp change.
#[utoipa::path(post, path = "/v1/tenants/{tenant}/admin/prevalence-restamp", tag = "lake-admin",
    params(("tenant" = String, Path)), request_body = super::reindex::CountBackfill,
    responses((status = 200, body = serde_json::Value), (status = 400, description = "Invalid window or no prevalence grant"),
        (status = 403, description = "Full operator token required")), security(("operator_bearer" = [])))]
async fn start_prevalence_restamp(axum::extract::State(service): axum::extract::State<Arc<IngestService>>, request: axum::extract::Request) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), 1024).await else {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid restamp request").into_response();
    };
    let Ok(window) = serde_json::from_slice::<super::reindex::CountBackfill>(&bytes) else {
        return (axum::http::StatusCode::BAD_REQUEST, "invalid restamp window").into_response();
    };
    let now = chrono::Utc::now().timestamp_millis();
    let mut ingestor = service.ingestor.lock().await;
    match ingestor.queue_prevalence_restamp(window, now) {
        Ok(hours) => axum::Json(serde_json::json!({
            "queued_hours": hours,
            "owed_hours": ingestor.prevalence_owed_hours(),
            "health": ingestor.health(),
        })).into_response(),
        Err(error) => (axum::http::StatusCode::BAD_REQUEST, error.to_string()).into_response(),
    }
}

#[utoipa::path(get, path = "/v1/tenants/{tenant}/admin/prevalence-restamp", tag = "lake-admin",
    params(("tenant" = String, Path)), responses((status = 200, body = serde_json::Value)),
    security(("operator_bearer" = [])))]
async fn prevalence_restamp_status(axum::extract::State(service): axum::extract::State<Arc<IngestService>>) -> axum::Json<serde_json::Value> {
    let ingestor = service.ingestor.lock().await;
    axum::Json(serde_json::json!({ "owed_hours": ingestor.prevalence_owed_hours(), "health": ingestor.health() }))
}

/// NAN-3643: an operator replay of one quarantined bronze object. The
/// tenant must be this ingest's own (the router already bound the path).
#[derive(Debug, serde::Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct BronzeQuarantineReplay {
    pub tenant_id: String,
    /// The quarantined object's SHA-256 (its `id` in the listing).
    pub id: String,
}

/// NAN-3643: bronze objects admission refused whole, kept for 7 days.
#[utoipa::path(get, path = "/v1/tenants/{tenant}/admin/bronze-quarantine", tag = "lake-admin",
    params(("tenant" = String, Path)),
    responses((status = 200, body = serde_json::Value), (status = 403, description = "Full operator token required"),
        (status = 503, description = "Quarantine unavailable")), security(("operator_bearer" = [])))]
async fn bronze_quarantine_list(axum::extract::State(service): axum::extract::State<Arc<IngestService>>) -> axum::response::Response {
    use axum::response::IntoResponse;
    let ingestor = service.ingestor.lock().await;
    match ingestor.quarantine_entries() {
        Ok(entries) => axum::Json(serde_json::json!({
            "entries": entries,
            "objects_quarantined_total": ingestor.health().objects_quarantined_total,
            "quarantine_replays_total": ingestor.health().quarantine_replays_total,
        })).into_response(),
        Err(error) => (axum::http::StatusCode::SERVICE_UNAVAILABLE, error.to_string()).into_response(),
    }
}

/// NAN-3643: replay a quarantined object through normal admission once its
/// cause is fixed. It is admitted alone, deduped like any object, and
/// dropped from the quarantine when its flush commits.
#[utoipa::path(post, path = "/v1/tenants/{tenant}/admin/bronze-quarantine/replay", tag = "lake-admin",
    params(("tenant" = String, Path)), request_body = BronzeQuarantineReplay,
    responses((status = 202, body = serde_json::Value), (status = 400, description = "Malformed request or id"),
        (status = 403, description = "Full operator token required, or another tenant's quarantine"),
        (status = 404, description = "No quarantined object with that id"),
        (status = 503, description = "Quarantine unavailable")), security(("operator_bearer" = [])))]
async fn bronze_quarantine_replay(axum::extract::State(service): axum::extract::State<Arc<IngestService>>, request: axum::extract::Request) -> axum::response::Response {
    use super::quarantine::ReplayRefused;
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let Ok(bytes) = axum::body::to_bytes(request.into_body(), 1024).await else {
        return (StatusCode::BAD_REQUEST, "invalid replay request").into_response();
    };
    let Ok(replay) = serde_json::from_slice::<BronzeQuarantineReplay>(&bytes) else {
        return (StatusCode::BAD_REQUEST, "invalid replay request").into_response();
    };
    let now = chrono::Utc::now().timestamp_millis();
    let result = service.ingestor.lock().await.request_quarantine_replay(&replay.tenant_id, &replay.id, now);
    match result {
        Ok(entry) => {
            service.wake.notify_one();
            (StatusCode::ACCEPTED, axum::Json(serde_json::json!({ "queued": entry }))).into_response()
        }
        Err(error) => {
            let status = match error.downcast_ref::<ReplayRefused>() {
                Some(ReplayRefused::CrossTenant) => StatusCode::FORBIDDEN,
                Some(ReplayRefused::InvalidId) => StatusCode::BAD_REQUEST,
                Some(ReplayRefused::NotFound) => StatusCode::NOT_FOUND,
                None => StatusCode::SERVICE_UNAVAILABLE,
            };
            (status, error.to_string()).into_response()
        }
    }
}

#[derive(utoipa::OpenApi)]
#[openapi(paths(count_backfill_status, start_count_backfill, prevalence_restamp_status, start_prevalence_restamp,
    bronze_quarantine_list, bronze_quarantine_replay),
    components(schemas(super::reindex::CountBackfill, BronzeQuarantineReplay, super::quarantine::QuarantineEntry)))]
pub struct CountBackfillApiDoc;

#[async_trait]
impl TenantService for IngestService {
    async fn handle_rpc(self: Arc<Self>, _request_id: u64, stream: tokio::net::UnixStream) {
        let app = axum::Router::new()
            .route("/v1/admin/count-backfill", axum::routing::get(count_backfill_status).post(start_count_backfill))
            .route("/v1/admin/prevalence-restamp", axum::routing::get(prevalence_restamp_status).post(start_prevalence_restamp))
            .route("/v1/admin/bronze-quarantine", axum::routing::get(bronze_quarantine_list))
            .route("/v1/admin/bronze-quarantine/replay", axum::routing::post(bronze_quarantine_replay))
            .with_state(self);
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(hyper_util::rt::TokioIo::new(stream), hyper_util::service::TowerToHyperService::new(app)).await;
    }

    async fn finding_append(self: Arc<Self>, request_id: u64, stream: tokio::net::UnixStream, control: ControlChannel) {
        self.active_appends.fetch_add(1, Ordering::SeqCst);
        struct Active<'a>(&'a AtomicUsize);
        impl Drop for Active<'_> {
            fn drop(&mut self) { self.0.fetch_sub(1, Ordering::SeqCst); }
        }
        let _active = Active(&self.active_appends);
        if let Err(error) = self.handle_finding_rpc(stream).await {
            tracing::warn!(request_id, error = %format!("{error:#}"), "finding append refused");
        }
        let _ = control.finding_append_complete(request_id).await;
    }

    async fn wake(self: Arc<Self>, reason: WakeReason) {
        // NAN-3795: the supervisor relays the tenant's running searches so
        // background count backfill yields; that is not new data to tick on.
        if reason == WakeReason::Query {
            super::merge_quota::note_search_activity();
            return;
        }
        self.wake.notify_one();
    }

    fn heartbeat(&self) -> Heartbeat {
        let mut heartbeat = self.heartbeat.lock().expect("heartbeat lock").clone();
        let mut diagnostics = self.pipeline_diagnostics.snapshot();
        if let Some(writer) = &self.native_writer_diagnostics {
            diagnostics["native_writer"] = writer.diagnostics();
        }
        heartbeat.ingest_diagnostics = Some(diagnostics);
        heartbeat.busy |= self.active_appends.load(Ordering::SeqCst) > 0;
        heartbeat.credential_refresh_at_risk = self.refresh.as_ref().is_some_and(|refresh| refresh.refresher.at_risk());
        heartbeat.identity_directory = self.identity.as_ref().map(|(_, handle)| handle.status());
        // NAN-4052: start-up is over, so this process is the tenant's writer here.
        heartbeat.writer_ready = self.writer_lease.as_ref().is_none_or(|lease| lease.lost().is_none());
        heartbeat.writer_lease_epoch = self.writer_lease.as_ref().map(|lease| lease.epoch());
        heartbeat
    }

    async fn secrets(self: Arc<Self>, secret: Zeroizing<Vec<u8>>) {
        let received = Instant::now();
        let Some(refresh) = &self.refresh else { return };
        // Pick up a rotated owner CA bundle on the refresh cadence, whether
        // or not this exchange succeeds.
        refresh.signer.reload_ca_logged();
        // The single-use token lives 180 s: the POST runs on the refresh
        // thread, never queued behind work on the ingest runtime.
        let assignment = self.assignment.clone();
        let exchanged = crate::cell_refresh::run_prioritized(async move {
            exchange_received(&secret, &assignment, received).await
        })
        .await;
        match exchanged {
            Ok(fresh) => {
                // Cancel the old GC generation before any refresh branch can
                // return or replace credentials. Re-enable only after a fully
                // usable GC credential refresh below.
                if let Some(route) = &self.part_gc_route {
                    route.suspend_requests();
                }
                if fresh.writer_epoch != self.writer_epoch {
                    self.epoch_changed.store(true, Ordering::Relaxed);
                    self.wake.notify_one();
                    return;
                }
                // The input mode is fixed for the process: a refresh that
                // names the other one swaps nothing (the supervisor restarts
                // ingest when the current credentials run out).
                match (&fresh.input, &refresh.edge, refresh.sources) {
                    (InputCreds::Edge { endpoint, token }, Some((source, current)), _) => {
                        if endpoint != current {
                            tracing::warn!("refreshed edge-log endpoint differs; keeping the current one until restart");
                        }
                        if let Err(error) = source.transport().set_token(token.clone()) {
                            tracing::error!(error = %error, "could not swap the refreshed edge-log consumer token");
                            return;
                        }
                    }
                    (InputCreds::Bronze { bronze, notices }, None, Some(store)) => {
                        if let Err(error) = store.replace(bronze) {
                            tracing::error!(error = %error, "could not swap refreshed bronze credentials");
                            return;
                        }
                        if let Some(queue) = refresh.notices {
                            queue.set_bearer(&notices.bearer);
                        }
                    }
                    _ => {
                        tracing::error!("refreshed credentials name a different input mode; not swapping");
                        return;
                    }
                }
                if let (Some(store), Some(creds)) = (refresh.parts, &fresh.parts) {
                    let Some(permission) = fresh.write_permission.clone() else {
                        tracing::error!("refresh omitted native write permission; not swapping"); return;
                    };
                    if let Err(error) = store.replace_write_permission(permission) {
                        tracing::error!(error = %error, "could not refresh native writer permission"); return;
                    }
                    if let Err(error) = store.replace_split(&creds.part, &creds.log) {
                        tracing::error!(error = %error, "could not swap refreshed part credentials");
                        return;
                    }
                }
                let mut gc_credentials_ready = refresh.gc_parts.is_none();
                if let (Some(store), Some(creds)) = (&refresh.gc_parts, &fresh.parts) {
                    match store.replace_split(&creds.part, &creds.log) {
                        Ok(()) => gc_credentials_ready = true,
                        Err(error) => {
                            tracing::error!(error = %error, "could not swap refreshed lake-part GC credentials");
                        }
                    }
                }
                // The owner-sign bearer first: a tick may be signing right now
                // (an expired bearer there is `lake-parts:sign 401`).
                refresh.signer.set_bearer(&fresh.bearer.token);
                if gc_credentials_ready {
                    if let Some(route) = &self.part_gc_route {
                        route.update(fresh.part_gc.as_ref(), fresh.part_delete_grant.as_ref());
                    }
                }
                self.part_gc.update(fresh.part_delete_grant.as_ref());
                self.erasure_ledger.set(fresh.erasure_ledger.clone());
                // Applied by the ingest loop at its next iteration (on the
                // ingest runtime, which owns the prevalence state): this swap
                // must never wait for a tick, a merge or a finding append
                // holding the ingestor (the 2026-09-29 wedge processed
                // exchanges ~20 min late, credentials already expired).
                *self.pending_prevalence.lock().expect("prevalence lock") = Some(match &fresh.prevalence {
                    Some(location) => PrevalenceUpdate::Rotate(location.clone()),
                    None => PrevalenceUpdate::Withdraw,
                });
                match (refresh.enrichment, fresh.enrichment.as_ref()) {
                    (Some(store), Some(creds)) => {
                        if let Err(error) = store.replace(creds) {
                            tracing::error!(error = %error, "could not swap refreshed enrichment credentials");
                            return;
                        }
                    }
                    (None, None) => {}
                    _ => {
                        tracing::error!("refreshed enrichment credential presence differs; not swapping");
                        return;
                    }
                }
                refresh.refresher.refreshed(fresh.expires_at);
                tracing::info!(expires_at = %fresh.expires_at, "credentials refreshed");
                self.wake.notify_one();
            }
            Err(error) => {
                let refused = error.downcast_ref::<ExchangeRefused>();
                let is_final = refused.is_some_and(ExchangeRefused::is_final);
                let reason = refused.map_or("exchange_failed", ExchangeRefused::reason);
                let retrying = refresh.refresher.failed(is_final);
                tracing::error!(error = %format!("{error:#}"), reason, retrying, "credential refresh failed");
            }
        }
    }

    async fn shutdown(self: Arc<Self>, _grace: Duration) {
        let mut ingestor = self.ingestor.lock().await;
        if let Err(error) = ingestor.flush_now(now_ms()).await {
            tracing::error!(error = %error, "flush on shutdown failed; unacked notices will replay");
        }
        // NAN-4052: no commit after this; the peer takes the lease at once.
        if let Some(lease) = &self.writer_lease {
            lease.release().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-3723: a failed enrichment refresh holds ingest only while no
    /// enrichment snapshot is pinned; any pinned source keeps rows flowing.
    #[test]
    fn enrichment_refresh_failure_holds_only_without_a_pinned_snapshot() {
        let empty = EnrichmentPins { pointer: None, platform: None, custom_assignment: None, ip_context_pointer: None };
        assert!(!enrichment_refresh_may_ingest(&empty), "nothing pinned: hold as before");
        let custom = EnrichmentPins {
            custom_assignment: Some((std::path::PathBuf::from("/ctx/tenant.bin"), "d".repeat(64))),
            ..empty
        };
        assert!(enrichment_refresh_may_ingest(&custom), "a pinned snapshot keeps ingest running");
    }

    /// NAN-3723: the periodic "ingest dedupe health" line carries
    /// `same_uid_payload_diff_total` and every `late_dedup_*` counter of
    /// IngestHealth, so they can be checked live.
    #[test]
    fn dedupe_health_line_carries_every_dedupe_counter() {
        let health = super::super::ingest::IngestHealth {
            same_uid_payload_diff_total: 3,
            late_dedup_tier_duplicates_total: 5,
            late_dedup_unverified_rows_total: 7,
            late_dedup_tier_ready: true,
            ..Default::default()
        };
        let counters = dedupe_health_counters(&health);
        assert_eq!(counters["same_uid_payload_diff_total"], 3);
        assert_eq!(counters["late_dedup_tier_duplicates_total"], 5);
        assert_eq!(counters["late_dedup_unverified_rows_total"], 7);
        assert_eq!(counters["late_dedup_tier_ready"], true);
        // Every late_dedup_* field of IngestHealth is on the line.
        let serialized = serde_json::to_value(&health).unwrap();
        let fields: Vec<&String> = serialized.as_object().unwrap().keys()
            .filter(|key| key.starts_with("late_dedup_") || key.as_str() == "same_uid_payload_diff_total").collect();
        assert!(fields.len() >= 13, "IngestHealth dedupe fields: {fields:?}");
        for field in fields {
            assert_eq!(counters.get(field.as_str()), serialized.get(field.as_str()), "{field} missing from the dedupe health line");
        }
    }

    #[test]
    fn retry_heartbeat_carries_polled_gc_health() {
        let mut heartbeat = Heartbeat { retrying: true, ..Heartbeat::default() };
        let mut health = super::super::ingest::IngestHealth::default();
        health.part_gc_deleted_total = 7;
        health.part_gc_blocked = Some(nanosiem_lake_cell::contract::PartGcBlocked {
            reason: "sanctioned_pass_paused".into(), parts: 2, bytes: 10,
            detail: String::new(), blocked_seconds: 12,
        });
        update_gc_heartbeat(&mut heartbeat, &health);
        assert!(heartbeat.retrying);
        assert_eq!(heartbeat.part_gc_deleted_total, 7);
        assert_eq!(heartbeat.part_gc_blocked.as_ref().unwrap().reason, "sanctioned_pass_paused");
        health.part_gc_blocked = None;
        health.part_gc_deleted_total = 8;
        update_gc_heartbeat(&mut heartbeat, &health);
        assert!(heartbeat.part_gc_blocked.is_none());
        assert_eq!(heartbeat.part_gc_deleted_total, 8);
    }

    #[tokio::test]
    async fn refused_enrichment_refresh_keeps_pins_and_does_not_rotate() {
        let root = tempfile::tempdir().unwrap();
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let custom = root.path().join(tenant);
        let store = crate::ip_context::IpContextStore::new(custom.clone(), tenant.into()).unwrap();
        let input = |network: String| crate::ip_context::IpContextInput {
            network, source_id: "tenant-cmdb".into(),
            country_code: "US".into(), updated_at: chrono::Utc::now(), deleted: false,
            country: String::new(), continent: String::new(), continent_code: String::new(),
            asn: String::new(), as_name: String::new(), as_domain: String::new(),
        };
        store.upsert(vec![input("8.8.8.8/32".into())]).unwrap();
        let active = custom_context_assignment(&custom, tenant).unwrap();
        let pins = EnrichmentPins { pointer: None, platform: None, custom_assignment: Some(active.clone()), ip_context_pointer: None };
        // Unchanged inputs: no rotation.
        let (rotation, _) = plan_enrichment_refresh(None, None, Some(&custom), None, tenant, &pins).await.unwrap();
        assert!(rotation.is_none());
        // A gen1-limit publisher advances the pointer past the lean row cap:
        // the refresh is refused and the caller's pins are untouched.
        let cap = crate::lean_enrichment_snapshot::TENANT_SNAPSHOT_LIMIT_ROWS;
        store.upsert((0..=cap).map(|i| input(format!("10.{}.{}.{}/32", (i >> 16) & 255, (i >> 8) & 255, i & 255))).collect()).unwrap();
        assert_ne!(custom_context_assignment(&custom, tenant).unwrap(), active);
        let error = plan_enrichment_refresh(None, None, Some(&custom), None, tenant, &pins).await.err().expect("over-cap rotation refused");
        assert!(format!("{error:#}").contains("rows"), "{error:#}");
        assert_eq!(pins.custom_assignment, Some(active));
        // An unreadable platform policy is likewise a retryable refusal.
        let missing = (PlatformBundleSource::File(root.path().join("bundle")), root.path().join("missing").join("policy.json"));
        assert!(plan_enrichment_refresh(None, Some(&missing), None, None, tenant, &pins).await.is_err());
    }

    /// `platform_bundle_dir`: the policy selects a content-addressed bundle;
    /// a newer policy + bundle rotates on refresh, and a newer policy naming
    /// an unverifiable bundle is refused while the old bundle stays pinned.
    #[tokio::test]
    async fn platform_bundle_dir_rotates_to_newer_bundle_and_keeps_old_on_bad_one() {
        use crate::lean_platform_bundle::{bundle_file_name, PlatformGrant};
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let feeds = root.path().join("feeds");
        let policy_dir = root.path().join("policy").join(tenant);
        std::fs::create_dir_all(&feeds).unwrap();
        std::fs::create_dir_all(&policy_dir).unwrap();
        let policy_file = policy_dir.join("policy.json");
        let publish = |feed_revision: i64| {
            let staging = feeds.join(format!(".staging-{feed_revision}"));
            let row = crate::enrichment::IocSnapshotInput {
                ioc_value: "8.8.8.8".into(), ioc_type: "ip".into(), source_id: "threatfox".into(), ..Default::default()
            };
            let digest = PlatformBundle::publish(&staging, None, &[row], std::collections::BTreeMap::from([("threatfox".into(), feed_revision)])).unwrap();
            std::fs::rename(&staging, feeds.join(bundle_file_name(&digest).unwrap())).unwrap();
            digest
        };
        let write_policy = |revision: u64, digest: &str, feed_revision: i64| {
            let policy = TenantPlatformPolicy {
                tenant_id: tenant.parse().unwrap(), revision, bundle_sha256: digest.into(),
                grants: std::collections::BTreeMap::from([("threatfox".into(), PlatformGrant {
                    feed_revision, valid_until: chrono::Utc::now() + chrono::Duration::hours(1), premium: None,
                })]),
            };
            std::fs::write(&policy_file, serde_json::to_vec(&policy).unwrap()).unwrap();
        };
        let assignment_paths = (PlatformBundleSource::Dir(feeds.clone()), policy_file.clone());
        let first = publish(1);
        write_policy(1, &first, 1);
        let initial = load_platform(tenant, &assignment_paths).unwrap();
        assert_eq!(initial.0.digest(), first);
        let mut pins = EnrichmentPins { pointer: None, platform: Some(initial), custom_assignment: None, ip_context_pointer: None };
        // Unchanged policy: no rotation, same bundle.
        let (rotation, next) = plan_enrichment_refresh(None, Some(&assignment_paths), None, None, tenant, &pins).await.unwrap();
        assert!(rotation.is_none());
        assert_eq!(next.as_ref().unwrap().0.digest(), first);
        // A newer bundle lands next to the old one; the newer policy selects it.
        let second = publish(2);
        write_policy(2, &second, 2);
        let (rotation, next) = plan_enrichment_refresh(None, Some(&assignment_paths), None, None, tenant, &pins).await.unwrap();
        assert!(rotation.is_some(), "a newer bundle rotates the enricher");
        assert_eq!(next.as_ref().unwrap().0.digest(), second);
        pins.platform = next;
        // A newer policy names a bundle whose content does not match its name:
        // refused, and the pinned bundle is untouched.
        let forged = "e".repeat(64);
        let forged_path = feeds.join(bundle_file_name(&forged).unwrap());
        std::fs::copy(feeds.join(bundle_file_name(&first).unwrap()), &forged_path).unwrap();
        std::fs::set_permissions(&forged_path, std::fs::Permissions::from_mode(0o444)).unwrap();
        write_policy(3, &forged, 1);
        let error = plan_enrichment_refresh(None, Some(&assignment_paths), None, None, tenant, &pins).await.err().expect("forged bundle refused");
        assert!(format!("{error:#}").contains("digest mismatch"), "{error:#}");
        assert_eq!(pins.platform.as_ref().unwrap().0.digest(), second);
        // A newer policy naming a bundle that is not there yet is refused too.
        write_policy(4, &"d".repeat(64), 1);
        assert!(plan_enrichment_refresh(None, Some(&assignment_paths), None, None, tenant, &pins).await.is_err());
        assert_eq!(pins.platform.as_ref().unwrap().1.revision, 2);
        // An older policy (rollback to the first bundle) is refused.
        write_policy(1, &first, 1);
        assert!(plan_enrichment_refresh(None, Some(&assignment_paths), None, None, tenant, &pins).await.is_err());
    }

    #[tokio::test]
    async fn tenant_r2_ip_context_rotates_on_refresh_and_refusal_keeps_old_revision() {
        use crate::lean_ip_context::{LeanIpContextPublisher, LeanIpContextSnapshots};
        let root = tempfile::tempdir().unwrap();
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let tenant_uuid: uuid::Uuid = tenant.parse().unwrap();
        // The tenant-rooted store stands in for the prefix-scoped R2 credential.
        let objects: &'static LocalObjectStore = Box::leak(Box::new(
            LocalObjectStore::new(root.path().join("r2").join(format!("tenant_id={tenant}"))).unwrap(),
        ));
        let reader: &'static LeanIpContextSnapshots<'static> = Box::leak(Box::new(
            LeanIpContextSnapshots::new(tenant_uuid, objects, &root.path().join("ingest")).unwrap(),
        ));
        let publisher = LeanIpContextPublisher::new(tenant_uuid, &root.path().join("coordinator")).unwrap();
        let input = |network: &str, country: &str| crate::ip_context::IpContextInput {
            network: network.into(), source_id: "tenant-cmdb".into(),
            country_code: country.into(), updated_at: chrono::Utc::now(), deleted: false,
            country: String::new(), continent: String::new(), continent_code: String::new(),
            asn: String::new(), as_name: String::new(), as_domain: String::new(),
        };
        let mut pins = EnrichmentPins { pointer: None, platform: None, custom_assignment: None, ip_context_pointer: None };
        // Nothing published: no rotation.
        let (rotation, _) = plan_enrichment_refresh(None, None, None, Some(reader), tenant, &pins).await.unwrap();
        assert!(rotation.is_none());
        // A mount and an R2 source together are ambiguous and refused.
        assert!(plan_enrichment_refresh(None, None, Some(root.path()), Some(reader), tenant, &pins).await.is_err());
        let first = publisher.upsert(objects, vec![input("8.8.8.0/24", "US")]).await.unwrap();
        let (rotation, _) = plan_enrichment_refresh(None, None, None, Some(reader), tenant, &pins).await.unwrap();
        let rotation = rotation.expect("new revision rotates the enricher");
        let pinned = rotation.ip_context_pointer.clone().unwrap();
        assert_eq!(Some(pinned.revision.to_string()), first.snapshot_id);
        let mut event = serde_json::json!({"src_endpoint": {"ip": "8.8.8.8"}});
        let mut metrics = rotation.enricher.initial_metrics();
        rotation.enricher.enrich(&mut event, &mut metrics).unwrap();
        assert_eq!(event["src_endpoint"]["location"]["country"], "US");
        assert_eq!(metrics.ip_context_snapshot_sha256.as_deref(), Some(pinned.sha256.as_str()));
        pins.ip_context_pointer = rotation.ip_context_pointer;
        // Same revision: no rotation.
        let (rotation, _) = plan_enrichment_refresh(None, None, None, Some(reader), tenant, &pins).await.unwrap();
        assert!(rotation.is_none());
        // The pointer advances to a revision whose snapshot is unreadable
        // (missing object): the refresh is refused and the pins stay put.
        let broken = crate::lean_enrichment_snapshot::SnapshotPointer {
            tenant_id: tenant_uuid, revision: uuid::Uuid::now_v7(), sha256: "ab".repeat(32), bytes: 10,
        };
        objects.put(&format!("ip_context/revisions/{}.json", broken.revision), &serde_json::to_vec(&broken).unwrap()).await.unwrap();
        objects.put("ip_context/current.json", &serde_json::to_vec(&broken).unwrap()).await.unwrap();
        assert!(plan_enrichment_refresh(None, None, None, Some(reader), tenant, &pins).await.is_err());
        assert_eq!(pins.ip_context_pointer.as_ref(), Some(&pinned));
        // A pointer naming another tenant is refused the same way.
        let foreign = crate::lean_enrichment_snapshot::SnapshotPointer { tenant_id: uuid::Uuid::new_v4(), ..pinned.clone() };
        objects.put("ip_context/current.json", &serde_json::to_vec(&foreign).unwrap()).await.unwrap();
        assert!(plan_enrichment_refresh(None, None, None, Some(reader), tenant, &pins).await.is_err());
        assert_eq!(pins.ip_context_pointer.as_ref(), Some(&pinned));
    }

    /// NAN-3503: the identity directory is built and installed by a
    /// background task into a shared handle. Ingest starts without one (cold
    /// start never waits), keeps enriching while a slow build runs, picks the
    /// directory up without rotating the enricher, and only ever sees its own
    /// tenant's directory.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn identity_directory_installs_in_the_background_and_is_tenant_bound() {
        use crate::lean_identity_snapshot::{IdentityRow, IdentityStore, SourceKind};
        let root = tempfile::tempdir().unwrap();
        let tenant_a = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f0a";
        let tenant_b = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f0b";
        let (uuid_a, uuid_b): (uuid::Uuid, uuid::Uuid) = (tenant_a.parse().unwrap(), tenant_b.parse().unwrap());
        // Tenant-rooted stores stand in for the prefix-scoped R2 credentials.
        let prefix = |tenant: &str| -> &'static LocalObjectStore {
            Box::leak(Box::new(LocalObjectStore::new(root.path().join("r2").join(format!("tenant_id={tenant}"))).unwrap()))
        };
        let (objects_a, objects_b) = (prefix(tenant_a), prefix(tenant_b));
        let reader = |tenant: uuid::Uuid, objects: &'static LocalObjectStore, name: &str, delay: Duration| -> &'static LeanIdentityDirectories<'static> {
            Box::leak(Box::new(
                LeanIdentityDirectories::new(tenant, objects, &root.path().join(name))
                    .unwrap()
                    .with_min_rebuild_interval(Duration::ZERO)
                    .with_build_delay(delay),
            ))
        };
        let person = |feed: &str, id: &str, email: &str, department: &str, version: i64| {
            let mut row = IdentityRow::new(feed, id, SourceKind::Pull, version);
            row.email = email.into();
            row.department = department.into();
            row.company = "Corp".into();
            row
        };
        let stamped = |enricher: &BronzeIngestEnricher, email: &str| {
            let mut event = serde_json::json!({"user": {"name": email, "email_addr": email}});
            let mut metrics = enricher.initial_metrics();
            enricher.enrich(&mut event, &mut metrics).unwrap();
            event["user"]["org"]["ou_name"].as_str().map(str::to_string)
        };
        let writer_a = IdentityStore::new(uuid_a, objects_a, &root.path().join("coordinator-a")).unwrap();
        let first = writer_a.append_delta(None, vec![person("gws:users", "1", "alice@a.example", "Engineering", 1)]).await.unwrap();

        // Cold start: the enricher serves with an empty handle.
        let handle_a = IdentityDirectoryHandle::default();
        let enricher_a = BronzeIngestEnricher::disabled().with_identity_handle(Some(handle_a.clone()));
        assert_eq!(stamped(&enricher_a, "alice@a.example"), None);
        assert_eq!(enricher_a.initial_metrics().identity_revision, None);

        // A slow build (test hook) runs in the background while events keep
        // being enriched, promptly and unstamped.
        let slow = reader(uuid_a, objects_a, "ingest-a", Duration::from_millis(600));
        let build = tokio::spawn({
            let handle = handle_a.clone();
            async move { slow.refresh_into(&handle, tenant_a).await }
        });
        let mut enriched_during_build = 0;
        while !build.is_finished() {
            let started = Instant::now();
            assert_eq!(stamped(&enricher_a, "alice@a.example"), None);
            assert!(started.elapsed() < Duration::from_millis(100), "enrichment waited on the build");
            enriched_during_build += 1;
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(enriched_during_build > 10, "{enriched_during_build}");
        assert!(build.await.unwrap(), "the build installed a directory");
        // The same enricher (no rotation, no part cut) now stamps.
        assert_eq!(stamped(&enricher_a, "alice@a.example").as_deref(), Some("Engineering"));
        assert_eq!(enricher_a.initial_metrics().identity_revision, Some(first.manifest.revision.to_string()));
        // The locked refresh path knows nothing about identity: no rotation.
        let pins = EnrichmentPins { pointer: None, platform: None, custom_assignment: None, ip_context_pointer: None };
        let (rotation, _) = plan_enrichment_refresh(None, None, None, None, tenant_a, &pins).await.unwrap();
        assert!(rotation.is_none());

        // Same revision: nothing new installed. A new revision is.
        let reader_a = reader(uuid_a, objects_a, "ingest-a2", Duration::ZERO);
        assert!(!slow.refresh_into(&handle_a, tenant_a).await);
        let second = writer_a
            .append_delta(Some(first.manifest.revision), vec![person("gws:users", "1", "alice@a.example", "Security", 2)])
            .await
            .unwrap();
        assert!(reader_a.refresh_into(&handle_a, tenant_a).await);
        assert_eq!(stamped(&enricher_a, "alice@a.example").as_deref(), Some("Security"));
        // A tampered pointer (revision record missing) keeps the installed
        // directory.
        let mut tampered = second.manifest.clone();
        tampered.revision = uuid::Uuid::now_v7();
        objects_a.put("identity/current.json", &serde_json::to_vec(&tampered).unwrap()).await.unwrap();
        assert!(!reader_a.refresh_into(&handle_a, tenant_a).await);
        assert_eq!(handle_a.current().unwrap().revision(), second.manifest.revision);
        objects_a.put("identity/current.json", &serde_json::to_vec(&second.manifest).unwrap()).await.unwrap();

        // Tenant B: its own prefix only; tenant A's person never stamps it.
        let handle_b = IdentityDirectoryHandle::default();
        let enricher_b = BronzeIngestEnricher::disabled().with_identity_handle(Some(handle_b.clone()));
        let reader_b = reader(uuid_b, objects_b, "ingest-b", Duration::ZERO);
        assert!(!reader_b.refresh_into(&handle_b, tenant_b).await, "no directory yet");
        let writer_b = IdentityStore::new(uuid_b, objects_b, &root.path().join("coordinator-b")).unwrap();
        writer_b.append_delta(None, vec![person("okta:users", "9", "bob@b.example", "Finance", 1)]).await.unwrap();
        assert!(reader_b.refresh_into(&handle_b, tenant_b).await);
        assert_eq!(stamped(&enricher_b, "bob@b.example").as_deref(), Some("Finance"));
        assert_eq!(stamped(&enricher_b, "alice@a.example"), None, "tenant A's identity never stamps tenant B");
        // A tenant B reader mis-rooted at tenant A's prefix refuses A's
        // manifest, and a directory built for A is never installed for B.
        let fresh = IdentityDirectoryHandle::default();
        let misrooted = reader(uuid_b, objects_a, "ingest-misrooted", Duration::ZERO);
        assert!(!misrooted.refresh_into(&fresh, tenant_b).await);
        assert!(!reader_a.refresh_into(&fresh, tenant_b).await);
        assert!(fresh.current().is_none());
        // Flag off (no handle): nothing stamped, nothing pinned.
        let off = BronzeIngestEnricher::disabled().with_identity_handle(None);
        assert_eq!(stamped(&off, "alice@a.example"), None);
    }

    #[test]
    fn custom_context_mount_is_tenant_bound_and_rotates_immutable_digest() {
        let root = tempfile::tempdir().unwrap();
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let store = crate::ip_context::IpContextStore::new(root.path().to_path_buf(), tenant.into()).unwrap();
        let input = |network: &str| crate::ip_context::IpContextInput {
            network: network.into(), source_id: "tenant-cmdb".into(),
            country_code: "US".into(), updated_at: chrono::Utc::now(), deleted: false,
            country: String::new(), continent: String::new(), continent_code: String::new(),
            asn: String::new(), as_name: String::new(), as_domain: String::new(),
        };
        store.upsert(vec![input("8.8.8.8/32")]).unwrap();
        let first = custom_context_assignment(root.path(), tenant).unwrap();
        assert!(crate::ip_context::IpContextSnapshot::open(&first.0, &first.1).is_ok());
        assert!(custom_context_assignment(root.path(), "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f01").is_err());
        store.upsert(vec![input("9.9.9.9/32")]).unwrap();
        let second = custom_context_assignment(root.path(), tenant).unwrap();
        assert_ne!(first.1, second.1);
        assert!(crate::ip_context::IpContextSnapshot::open(&second.0, &second.1).is_ok());
    }

    #[test]
    fn enrichment_credentials_reject_other_tenant_or_write_scope() {
        let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
        let mut credential = ExchangedR2Credential {
            credential_class: "enrichment_reader".into(), endpoint: "https://r2.example".into(),
            region: "auto".into(), bucket: "test".into(), permission: "object-read-only".into(),
            prefixes: vec![format!("lake/enrichment/v1/tenant_id={tenant}/")],
            access_key_id: "a".into(), secret_access_key: "s".into(), session_token: "t".into(),
            expires_at: "2026-09-26T20:00:00Z".into(),
        };
        assert_eq!(enrichment_location(&credential, tenant).unwrap().prefix, credential.prefixes[0]);
        assert!(enrichment_location(&credential, "other-tenant").is_err());
        credential.permission = "object-read-write".into();
        assert!(enrichment_location(&credential, tenant).is_err());
    }

    #[test]
    fn partial_edge_credential_never_falls_back_to_bronze() {
        let bronze = S3Location {
            endpoint: "https://example.com".into(),
            region: "auto".into(),
            bucket: "test".into(),
            prefix: String::new(),
            access_key_id: "test".into(),
            secret_access_key: "test".into(),
            session_token: None,
        };
        let notices = NoticeEndpoint { url: "https://example.com".into(), bearer: "test".into() };
        for (endpoint, token) in [(Some("https://example.com".into()), None), (None, Some("test".into()))] {
            let error = input_from(endpoint, token, Some(bronze.clone()), Some(notices.clone())).err().unwrap();
            assert!(error.to_string().contains("incomplete edge-log consumer credential"));
        }
    }

    /// NAN-2984: the flush policy defaults in code and is overridable per
    /// cell; an out-of-bounds override is refused.
    #[test]
    fn flush_policy_defaults_and_overrides() {
        use crate::parts::levels::FlushPolicy;
        use nanosiem_lake_cell::contract::IngestFlush;
        let tenant = "11111111-2222-4333-8444-555555555555";
        let mut a = assignment(tenant, None);
        assert_eq!(flush_policy_for(&a).unwrap(), FlushPolicy::default());
        assert_eq!(flush_policy_for(&a).unwrap().interval_ms(20.0), 10_000);
        a.ingest_flush = Some(IngestFlush { min_age_ms: 2_000, max_age_ms: 20_000, target_rows: 1_000 });
        let policy = flush_policy_for(&a).unwrap();
        assert_eq!(policy.interval_ms(20.0), 20_000);
        assert_eq!(policy.interval_ms(1_000.0), 2_000);
        a.ingest_flush = Some(IngestFlush { min_age_ms: 2_000, max_age_ms: 600_000, target_rows: 1_000 });
        assert!(flush_policy_for(&a).is_err());
    }

    /// NAN-2984: after a dependency recovers, a held buffer is retried
    /// within 15 s (was up to 60 s).
    #[test]
    fn tick_retry_backoff_is_capped_at_15_s() {
        let delays = (1..=10).map(|n| retry_delay(n).as_secs()).collect::<Vec<_>>();
        assert_eq!(delays, vec![1, 2, 4, 8, 15, 15, 15, 15, 15, 15]);
        assert_eq!(retry_delay(u32::MAX), MAX_RETRY_DELAY);
    }

    fn assignment(tenant: &str, control_url: Option<&str>) -> Assignment {
        use nanosiem_lake_cell::contract::{JailSpec, TenantId};
        let dir = std::path::PathBuf::from("/nonexistent");
        Assignment {
            tenant: TenantId::new(tenant).unwrap(),
            role: Role::Ingest,
            cell_id: "cell-a".into(),
            tenant_dir: dir.clone(),
            parts_dir: dir.clone(),
            state_dir: dir.clone(),
            tmp_dir: dir.clone(),
            feed_dir: None,
            platform_bundle_file: None, platform_bundle_dir: None,
            platform_policy_file: None,
            custom_context_root: None,
            memory_cap_bytes: 0,
            cpu_millis: 0,
            eps: 0.0,
            jail: JailSpec {
                uid: 0, gid: 0, rw_paths: vec![], ro_paths: vec![], system_ro_paths: vec![], tcp_connect_ports: vec![],
                cgroup_dir: None, require_landlock: false, max_processes: None, max_open_files: 0,
            },
            control_url: control_url.map(str::to_string),
            prevalence_rarity_threshold: None,
            part_signing: None,
            owner_requires_checksum: false,
            ingest_idle_exit: None,
            ingest_day_merges: false,
            ingest_keyword_index: false,
            identity_observations: false,
            identity_directory_enrich: false,
            ingest_flush: None,
            ingest_merge_policy: None,
            ingest_hold_eps: None,
            query_prewarm_before_ready: false,
            detect_runs_rules: false,
            product_state_role: false,
            product_dir: None,
            trusted_local: false,
            writer_lease: None,
            part_gc_state_dir: None,
        }
    }

    /// NAN-4195 (NAN-4194 regression guard): boot the ingest role's
    /// sanctioned part GC through the production wiring (`assignment_part_gc`
    /// -> `new_guarded`, R2 store guard installed), with and without the
    /// persistent hot-volume `part_gc_state_dir`, then run one pass. T57
    /// panicked every ingest role here (`Arc::get_mut` after the R2 guard took
    /// its weak reference) while the unit test on the unguarded constructor
    /// passed.
    #[tokio::test]
    async fn ingest_role_boots_the_sanctioned_part_gc_through_the_production_wiring() {
        use super::super::part_gc_cell::transport_tests as gc;
        for hot_volume in [false, true] {
            let f = gc::fixture(64, Duration::ZERO, 200).await;
            let pod = tempfile::tempdir().unwrap();
            let hot = tempfile::tempdir().unwrap();
            let mut assignment = assignment(gc::TENANT_UUID, Some("https://control.invalid"));
            assignment.state_dir = pod.path().to_path_buf();
            assignment.part_gc_state_dir = hot_volume.then(|| hot.path().to_path_buf());
            assignment.part_signing = Some(PartSigning {
                // Nothing listens: the pass folds the log, then pauses.
                url: "http://127.0.0.1:1/".into(),
                signer_key_id: "fixture".into(),
                trusted_keys: vec![],
                ca_file: None,
            });
            assert!(assignment_part_gc(&assignment, None, gc::fixture_keys()).is_none(), "no R2 part store, no route");
            let route = assignment_part_gc(&assignment, Some(&f.store), gc::fixture_keys())
                .expect("the ingest role wires its sanctioned part GC");
            gc::permission(&route, 200, chrono::Duration::minutes(10));
            let report = route.run_pass_now(chrono::Utc::now().timestamp_millis()).await
                .unwrap_or_else(|error| panic!("hot_volume={hot_volume}: one GC pass: {error:#}"));
            assert_eq!(report.deleted, 0, "hot_volume={hot_volume}");
            assert!(route.reads() > 0, "hot_volume={hot_volume}: the pass read the part log");
            let (view_on, not_on) = if hot_volume { (hot.path(), pod.path()) } else { (pod.path(), hot.path()) };
            assert!(view_on.join("lake-part-gc").exists(), "hot_volume={hot_volume}: view under {}", view_on.display());
            assert!(!not_on.join("lake-part-gc").exists(), "hot_volume={hot_volume}: no view under {}", not_on.display());
            // NAN-4188: the same production-wired GC follows its writer's
            // receipted appends into control's index.
            gc::assert_follower_publishes_per_receipted_append(&route, 63).await;
        }
    }

    #[test]
    fn merge_policy_overrides_apply_and_are_bounded() {
        use nanosiem_lake_cell::contract::IngestMergePolicy;
        let dir = tempfile::tempdir().unwrap();
        let mut cfg = IngestConfig::new("t", dir.path());
        let defaults = cfg.merge_policy;
        apply_merge_policy(&mut cfg, None).unwrap();
        assert_eq!(cfg.merge_policy, defaults);
        assert_eq!(defaults.sealed_remerge_debounce_ms as u64, IngestMergePolicy::DEFAULT_DEBOUNCE_MS);
        assert_eq!(defaults.sealed_remerge_max_defer_ms as u64, IngestMergePolicy::DEFAULT_MAX_DEFER_MS);
        let policy = IngestMergePolicy { sealed_remerge_debounce_ms: Some(900_000), max_merges_per_tick: Some(1), ..Default::default() };
        apply_merge_policy(&mut cfg, Some(&policy)).unwrap();
        assert_eq!(cfg.merge_policy.sealed_remerge_debounce_ms, 900_000);
        assert_eq!(cfg.merge_policy.hour_seal_ms, defaults.hour_seal_ms);
        assert_eq!(cfg.max_merges_per_tick, 1);
        let bad = IngestMergePolicy { max_merges_per_tick: Some(0), ..Default::default() };
        assert!(apply_merge_policy(&mut cfg, Some(&bad)).is_err());
    }

    #[test]
    fn input_mode_prefers_the_edge_log_and_needs_one_input() {
        let edge = input_from(Some("https://t.ingest.nano.rs".into()), Some("tok".into()), None, None).unwrap();
        assert!(matches!(edge, InputCreds::Edge { .. }));
        assert!(input_from(None, None, None, None).is_err(), "a tenant with no input is refused");
        assert!(input_from(Some("https://x".into()), None, None, None).is_err(), "endpoint without token");
    }

    /// A 401 on a token that aged past its lifetime in this process is
    /// `token_expired` and retried with a fresh token; a prompt 401 is not
    /// told apart from spent/unknown and stays final. Never "spent" for an
    /// expired token.
    #[test]
    fn an_expired_bootstrap_token_is_reported_as_token_expired_and_retried() {
        let expired = ExchangeRefused::with_token_age(401, Duration::from_secs(200));
        assert!(expired.token_expired());
        assert_eq!(expired.reason(), "token_expired");
        assert!(!expired.is_final(), "a fresh token fixes an expired one");
        let text = expired.to_string();
        assert!(text.contains("token_expired") && !text.contains("spent"), "{text}");

        let prompt = ExchangeRefused::with_token_age(401, Duration::from_secs(2));
        assert_eq!(prompt.reason(), "token_refused");
        assert!(prompt.is_final());
        assert!(!ExchangeRefused::new(401).token_expired());
        assert!(ExchangeRefused::with_token_age(403, Duration::from_secs(600)).is_final());
        assert!(!ExchangeRefused::with_token_age(503, Duration::from_secs(600)).is_final());
    }

    /// The exchange measures the token's age from its receipt: a POST that
    /// leaves late and is refused 401 is classified `token_expired`.
    #[tokio::test]
    async fn a_late_exchange_401_is_classified_token_expired() {
        use axum::{http::StatusCode, routing::post, Router};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new().route("/v1/lake/cells/{cell}/credential-exchange", post(|| async { StatusCode::UNAUTHORIZED }));
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let assignment = assignment("t1", Some(&format!("http://{addr}")));
        let late = Instant::now() - Duration::from_secs(170);
        let error = exchange_received(b"nlcb1.token", &assignment, late).await.err().unwrap();
        let refused = error.downcast_ref::<ExchangeRefused>().unwrap();
        assert_eq!(refused.reason(), "token_expired", "{error:#}");
        let error = exchange_received(b"nlcb1.token", &assignment, Instant::now()).await.err().unwrap();
        assert_eq!(error.downcast_ref::<ExchangeRefused>().unwrap().reason(), "token_refused");
    }

    /// The refresh runtime is its own thread: a future run there makes
    /// progress while the caller's (current-thread) runtime is blocked.
    #[tokio::test(flavor = "current_thread")]
    async fn the_exchange_runs_off_the_service_runtime() {
        let (tx, rx) = std::sync::mpsc::channel();
        let handle = crate::cell_refresh::spawn_prioritized(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            tx.send(std::thread::current().name().map(str::to_string)).unwrap();
        });
        // Block this runtime's only worker: the refresh must not need it.
        let name = rx.recv_timeout(Duration::from_secs(5)).expect("refresh starved by a blocked service runtime");
        assert_eq!(name.as_deref(), Some("cell-refresh"));
        handle.await.unwrap();
    }

    #[test]
    fn refresh_backoff_covers_the_owner_fence_and_stops_on_final_refusals() {
        let total: u64 = REFRESH_BACKOFF_S.iter().sum();
        assert!(total >= 12 * 60, "startup retries span the owner's drain/move fence");
        let now = chrono::Utc::now();
        let mut state = RefreshState::fresh(now + chrono::Duration::hours(6));
        state.issued = now;
        assert!(!state.due(now));
        assert!(state.due(now + chrono::Duration::hours(3)), "due at half of the TTL");
        // Refresh retries are lifetime bounded, not startup-budget bounded.
        for _ in 0..REFRESH_BACKOFF_S.len() + 2 {
            assert!(state.failed(now, false));
        }
        assert!(!state.given_up);
        let mut lost = RefreshState::fresh(now + chrono::Duration::minutes(10));
        lost.outstanding = true;
        lost.requested_at = Some(now);
        assert!(!lost.due(now + chrono::Duration::seconds(30)));
        assert!(lost.due(now + chrono::Duration::seconds(91)));
        let mut refused = RefreshState::fresh(now + chrono::Duration::minutes(10));
        assert!(!refused.failed(now, ExchangeRefused::new(403).is_final()));
        assert!(refused.expired(now + chrono::Duration::seconds(571)), "expiry includes the 30 s skew");
    }

    #[tokio::test]
    async fn exchange_parses_the_nano_main_response_and_takes_the_earliest_expiry() {
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/v1/lake/cells/{cell}/credential-exchange",
            post(|axum::extract::Path(cell): axum::extract::Path<String>, headers: axum::http::HeaderMap, Json(body): Json<serde_json::Value>| async move {
                assert_eq!(cell, "cell-a");
                assert_eq!(headers["authorization"], "Bearer nlcb1.token");
                assert_eq!(body, serde_json::json!({"tenant_id": "t1", "role": "ingest",
                    "accepts": ["bronze_reader", "lake_part", "lake_part_log", "lake_prevalence_state", "enrichment_reader"],
                    "accepts_owner_scopes": ["lake-parts:sign", "lake-parts:write"]}));
                Json(serde_json::json!({
                    "schema_version": 1, "tenant_id": "t1", "role": "ingest", "writer_epoch": 3,
                    "credentials": [{
                        "credential_class": "bronze_reader", "endpoint": "https://acct.r2.cloudflarestorage.com",
                        "region": "auto", "bucket": "nano-shared-r2-t1", "permission": "object-read-only",
                        "prefixes": ["p/"], "access_key_id": "a", "secret_access_key": "s", "session_token": "t",
                        "expires_at": "2026-09-25T18:00:00.000Z"
                    }],
                    "owner_sign": {"token": "owner-bearer", "audience": "owner", "scope": "lake-parts:sign",
                                   "expires_at": "2026-09-25T12:10:00.000Z"},
                    "notices": {"url": "https://do.example", "bearer": "n"}
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let fresh = exchange(b"nlcb1.token\n", &assignment("t1", Some(&format!("http://{addr}")))).await.unwrap();
        assert_eq!(fresh.bearer.token, "owner-bearer");
        assert_eq!(fresh.writer_epoch, 3);
        assert_eq!(fresh.expires_at.to_rfc3339(), "2026-09-25T12:10:00+00:00");
        let InputCreds::Bronze { bronze, .. } = &fresh.input else { panic!("bronze input expected") };
        assert_eq!(bronze.bucket, "nano-shared-r2-t1");
        assert!(fresh.parts.is_none());
    }

    #[tokio::test]
    async fn exchange_refuses_a_class_ingest_did_not_declare() {
        let mut body = serde_json::json!({
            "schema_version": 1, "tenant_id": "t1", "role": "ingest", "writer_epoch": 3,
            "credentials": [r2_class("lake_part", "object-read-write"), r2_class("lake_part_log", "object-read-write"),
                            r2_class("lake_part_read", "object-read-only")],
            "owner_sign": {"token": "b", "audience": "owner", "scope": "lake-parts:sign", "expires_at": "2026-09-25T12:10:00.000Z"},
            "edge_log_consumer_token": "e", "edge_log_consumer_endpoint": "https://t1.ingest.nano.rs"
        });
        let url = exchange_server(body.clone()).await;
        let error = exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.err().expect("undeclared class refused");
        assert!(format!("{error:#}").contains("undeclared"), "{error:#}");
        // The same class twice is refused too.
        body["credentials"] = serde_json::json!([r2_class("lake_part", "object-read-write"),
            r2_class("lake_part_log", "object-read-write"), r2_class("lake_part_log", "object-read-write")]);
        let url = exchange_server(body).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
    }

    /// Serve one fixed exchange response.
    async fn exchange_server(response: serde_json::Value) -> String {
        use axum::{routing::post, Json, Router};
        let app = Router::new().route(
            "/v1/lake/cells/{cell}/credential-exchange",
            post(move || {
                let response = response.clone();
                async move { Json(response) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn r2_class(class: &str, permission: &str) -> serde_json::Value {
        let prefix = if class == "lake_prevalence_state" {
            "lake/prevalence-state/v1/tenant=t1/"
        } else {
            "lake/parts/v1/tenant_id=t1/"
        };
        serde_json::json!({
            "credential_class": class, "endpoint": "https://acct.r2.cloudflarestorage.com",
            "region": "auto", "bucket": "nano-shared-r2-t1", "permission": permission,
            "prefixes": [prefix], "access_key_id": "a", "secret_access_key": "s",
            "session_token": "t", "expires_at": "2026-09-25T18:00:00.000Z"
        })
    }

    #[tokio::test]
    async fn a_lean_tenant_exchange_is_parts_owner_sign_and_the_edge_log_only() {
        // the platform: lake_part + lake_part_log, the owner-sign bearer and
        // the edge-log consumer; no bronze_reader, notices or tail_compactor_rw.
        let lean = serde_json::json!({
            "schema_version": 1, "tenant_id": "t1", "role": "ingest", "writer_epoch": 3,
            "credentials": [r2_class("lake_part", "object-read-write"), r2_class("lake_part_log", "object-read-write"), r2_class("lake_prevalence_state", "object-read-only")],
            "prevalence_owner": {"url":"https://owner.example/v1/prevalence-state/mutate", "bearer":"owner-write",
                                  "tenant_id":"t1", "assignment_generation":2, "writer_epoch":3},
            "owner_sign": {"token": "owner-bearer", "audience": "owner", "scope": "lake-parts:sign",
                           "expires_at": "2026-09-25T12:10:00.000Z"},
            "edge_log_consumer_token": "edge-consumer-token",
            "edge_log_consumer_endpoint": "https://t1.ingest.nano.rs"
        });
        let url = exchange_server(lean.clone()).await;
        let fresh = exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.unwrap();
        assert_eq!(fresh.writer_epoch, 3);
        let InputCreds::Edge { endpoint, token } = &fresh.input else { panic!("edge input expected") };
        assert_eq!((endpoint.as_str(), token.as_str()), ("https://t1.ingest.nano.rs", "edge-consumer-token"));
        let parts = fresh.parts.as_ref().expect("part credentials");
        assert_eq!((parts.part.bucket.as_str(), parts.log.bucket.as_str()), ("nano-shared-r2-t1", "nano-shared-r2-t1"));
        let mut no_epoch = lean.clone();
        no_epoch["writer_epoch"] = serde_json::json!(0);
        let url = exchange_server(no_epoch).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
        // The owner's epoch must be the exchange's committed epoch.
        let mut owner_epoch = lean.clone();
        owner_epoch["prevalence_owner"]["writer_epoch"] = serde_json::json!(4);
        let url = exchange_server(owner_epoch).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
        assert_eq!(fresh.prevalence.as_ref().unwrap().read.prefix, "lake/prevalence-state/v1/tenant=t1/");
        let mut direct_write = lean.clone();
        direct_write["credentials"][2]["permission"] = serde_json::json!("object-read-write");
        let url = exchange_server(direct_write).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
        let mut missing_owner = lean.clone();
        missing_owner.as_object_mut().unwrap().remove("prevalence_owner");
        let url = exchange_server(missing_owner).await;
        // the platform has not shipped the owner yet: degrade, never crash-loop.
        let degraded = exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.unwrap();
        assert!(degraded.prevalence.is_none() && degraded.parts.is_some());
        let mut missing_prevalence = lean.clone();
        missing_prevalence["credentials"] = serde_json::json!([
            r2_class("lake_part", "object-read-write"),
            r2_class("lake_part_log", "object-read-write")
        ]);
        let url = exchange_server(missing_prevalence.clone()).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.unwrap().prevalence.is_none());
        missing_prevalence.as_object_mut().unwrap().remove("prevalence_owner");
        let url = exchange_server(missing_prevalence).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.unwrap().prevalence.is_none());
        let mut other_owner = lean.clone();
        other_owner["prevalence_owner"]["tenant_id"] = serde_json::json!("t2");
        let url = exchange_server(other_owner).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
        let mut other_tenant = lean.clone();
        other_tenant["credentials"][2]["prefixes"] = serde_json::json!(["lake/prevalence-state/v1/tenant=t2/"]);
        let url = exchange_server(other_tenant).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
        // An edge tenant without part credentials has nowhere to write.
        let mut no_parts = lean.clone();
        no_parts["credentials"] = serde_json::json!([]);
        let url = exchange_server(no_parts).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
        // Half a part grant is refused too.
        let mut half = lean;
        half["credentials"] = serde_json::json!([r2_class("lake_part", "object-read-write")]);
        let url = exchange_server(half).await;
        assert!(exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.is_err());
    }

    #[test]
    fn ingest_writer_epoch_is_optional_falls_back_and_must_agree() {
        // Neither field (live the platform today): the pre-owner epoch 1.
        assert_eq!(ingest_writer_epoch(None, None).unwrap(), 1);
        // Top-level only.
        assert_eq!(ingest_writer_epoch(Some(7), None).unwrap(), 7);
        // Owner only.
        assert_eq!(ingest_writer_epoch(None, Some(5)).unwrap(), 5);
        // Both present: equal is accepted, a mismatch is refused.
        assert_eq!(ingest_writer_epoch(Some(4), Some(4)).unwrap(), 4);
        assert!(ingest_writer_epoch(Some(4), Some(3)).is_err());
        // A present epoch must be positive.
        assert!(ingest_writer_epoch(Some(0), None).is_err());
        assert!(ingest_writer_epoch(None, Some(0)).is_err());
        assert!(ingest_writer_epoch(None, Some(-1)).is_err());
    }

    #[tokio::test]
    async fn the_exchange_derives_the_writer_epoch_from_either_field() {
        let base = serde_json::json!({
            "schema_version": 1, "tenant_id": "t1", "role": "ingest",
            "credentials": [r2_class("lake_part", "object-read-write"), r2_class("lake_part_log", "object-read-write"), r2_class("lake_prevalence_state", "object-read-only")],
            "prevalence_owner": {"url":"https://owner.example/v1/prevalence-state/mutate", "bearer":"owner-write",
                                  "tenant_id":"t1", "assignment_generation":2, "writer_epoch":3},
            "owner_sign": {"token": "owner-bearer", "audience": "owner", "scope": "lake-parts:sign",
                           "expires_at": "2026-09-25T12:10:00.000Z"},
            "edge_log_consumer_token": "edge-consumer-token",
            "edge_log_consumer_endpoint": "https://t1.ingest.nano.rs"
        });
        async fn epoch(response: serde_json::Value) -> Result<u64> {
            let url = exchange_server(response).await;
            exchange(b"nlcb1.token", &assignment("t1", Some(&url))).await.map(|fresh| fresh.writer_epoch)
        }
        // Neither: live today (no top-level epoch, owner withheld).
        let mut neither = base.clone();
        neither.as_object_mut().unwrap().remove("prevalence_owner");
        assert_eq!(epoch(neither.clone()).await.unwrap(), 1);
        // Top-level only.
        let mut top_only = neither;
        top_only["writer_epoch"] = serde_json::json!(6);
        assert_eq!(epoch(top_only).await.unwrap(), 6);
        // Owner only.
        let owner_only = base.clone();
        let fresh_epoch = epoch(owner_only).await.unwrap();
        assert_eq!(fresh_epoch, 3);
        // Both equal, then both mismatched.
        let mut both = base;
        both["writer_epoch"] = serde_json::json!(3);
        assert_eq!(epoch(both.clone()).await.unwrap(), 3);
        both["writer_epoch"] = serde_json::json!(4);
        assert!(epoch(both).await.is_err());
    }

    #[tokio::test]
    async fn lab_credentials_bind_the_tenant_and_production_needs_https_control() {
        let secret = serde_json::json!({
            "kind": LAB_CREDENTIALS_KIND,
            "tenant_id": "t1",
            "writer_epoch": 3,
            "bronze": {"endpoint": "https://r2.example", "region": "auto", "bucket": "b", "prefix": "p",
                       "access_key_id": "a", "secret_access_key": "s"},
            "notices": {"url": "https://do.example", "bearer": "x"},
            "lab_signer_key_id": "lab-signer-0001",
            "lab_signer_seed_hex": hex::encode([1_u8; 32])
        })
        .to_string();
        let creds = credentials_from_secret(secret.as_bytes(), &assignment("t1", None)).await.unwrap();
        assert_eq!(creds.writer_epoch, 3);
        assert_eq!(creds.signer.key_id(), "lab-signer-0001");
        assert!(credentials_from_secret(secret.as_bytes(), &assignment("t2", None)).await.is_err());
        // An opaque token needs a control_url, and only https.
        assert!(credentials_from_secret(b"nlcb1.opaque", &assignment("t1", None)).await.is_err());
        assert!(credentials_from_secret(b"nlcb1.opaque", &assignment("t1", Some("http://control"))).await.is_err());
    }

    #[tokio::test]
    async fn lab_credentials_select_the_trusted_local_bronze_listing() {
        let lab = |extra: serde_json::Value| {
            let mut secret = serde_json::json!({
                "kind": LAB_CREDENTIALS_KIND,
                "tenant_id": "t1",
                "writer_epoch": 1,
                "bronze": {"endpoint": "http://lake-object-store:9000", "region": "us-east-1", "bucket": "nano-lake",
                           "prefix": "bronze-v2", "access_key_id": "a", "secret_access_key": "s"},
                "bronze_list": {"settle_secs": 600},
                "lab_signer_key_id": "lab-signer-0001",
                "lab_signer_seed_hex": hex::encode([1_u8; 32])
            });
            for (key, value) in extra.as_object().unwrap() {
                secret[key] = value.clone();
            }
            secret.to_string()
        };
        let creds = credentials_from_secret(lab(serde_json::json!({})).as_bytes(), &assignment("t1", None)).await.unwrap();
        let InputCreds::BronzeListed { bronze, settings } = &creds.input else { panic!("listing input expected") };
        // Plain http is fine here: the local object store, never a notice URL.
        assert_eq!(bronze.endpoint, "http://lake-object-store:9000");
        assert_eq!(settings.settle(), Duration::from_secs(600));
        // One input per process: no notice endpoint or edge credential beside it.
        let with_notices = lab(serde_json::json!({"notices": {"url": "https://do.example", "bearer": "x"}}));
        assert!(credentials_from_secret(with_notices.as_bytes(), &assignment("t1", None)).await.is_err());
        let with_edge = lab(serde_json::json!({"edge_log_consumer_token": "x", "edge_log_consumer_endpoint": "https://e"}));
        assert!(credentials_from_secret(with_edge.as_bytes(), &assignment("t1", None)).await.is_err());
        let no_bronze = lab(serde_json::json!({"bronze": null}));
        assert!(credentials_from_secret(no_bronze.as_bytes(), &assignment("t1", None)).await.is_err());
        let bad_settle = lab(serde_json::json!({"bronze_list": {"settle_secs": 1}}));
        assert!(credentials_from_secret(bad_settle.as_bytes(), &assignment("t1", None)).await.is_err());
        // Never with a release-pinned control plane.
        assert!(credentials_from_secret(lab(serde_json::json!({})).as_bytes(), &assignment("t1", Some("https://control"))).await.is_err());
    }

    /// A stand-in owner `lake-parts:sign` route that signs with `key`.
    fn owner_sign_app(key: SigningKey, key_id: &'static str) -> axum::Router {
        use crate::parts::provenance::{owner_check_part, SignResult};
        use axum::{routing::post, Json, Router};
        use ed25519_dalek::Signer;
        Router::new().route(
            "/sign",
            post(move |Json(request): Json<SignRequest>| {
                let key = key.clone();
                async move {
                    let results = request
                        .parts
                        .iter()
                        .map(|part| {
                            let record = owner_check_part(&request.tenant_id, part, None, key_id, crate::parts::provenance::OwnerCaller::CellBearer).unwrap();
                            let sig = key.sign(&record.signing_message().unwrap());
                            SignResult {
                                part_id: part.part_id.clone(),
                                record_sha256: part.record_sha256.clone(),
                                signature: Some(Ed25519Signature {
                                    alg: "ed25519".into(),
                                    key_id: key_id.into(),
                                    sig: base64::Engine::encode(&base64::engine::general_purpose::STANDARD, sig.to_bytes()),
                                }),
                                error: None,
                            }
                        })
                        .collect();
                    Json(SignResponse { schema_version: 1, request_id: request.request_id, results })
                }
            }),
        )
    }

    fn signing_record(key_id: &str) -> ProvenanceRecord {
        let mut record = crate::parts::provenance::tests::sample_record();
        record.signer_key_id = key_id.into();
        record
    }

    #[tokio::test]
    async fn http_signer_verifies_owner_signatures() {
        let key = SigningKey::from_bytes(&[5; 32]);
        let key_id = "platform-release-test";
        let app = owner_sign_app(key.clone(), key_id);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let trusted = TenantKeySet::new([(key_id.to_string(), key.verifying_key())]);
        let signer = HttpPartSigner::new(&format!("http://{addr}/sign"), "b", key_id, trusted, None).unwrap();
        let record = signing_record(key_id);
        let signatures = signer.sign(&record.tenant_id.clone(), std::slice::from_ref(&record)).await.unwrap();
        assert_eq!(signatures.len(), 1);
        // A signer trusting a different key refuses the owner's signature.
        let other = TenantKeySet::new([(key_id.to_string(), SigningKey::from_bytes(&[6; 32]).verifying_key())]);
        let wrong = HttpPartSigner::new(&format!("http://{addr}/sign"), "b", key_id, other, None).unwrap();
        assert!(wrong.sign(&record.tenant_id.clone(), std::slice::from_ref(&record)).await.is_err());
    }

    /// NAN-3801: the count route beside the sign route (the platform's
    /// wire shape); an owner without it is `CountSigningUnsupported`.
    #[tokio::test]
    async fn http_signer_signs_count_records_or_reports_the_route_unsupported() {
        use axum::{Json, Router};
        use base64::Engine as _;
        use ed25519_dalek::Signer;
        use sha2::Digest as _;
        assert_eq!(count_sign_url("https://o/internal/v1/enterprise-shared/lake-parts:sign").unwrap(),
            "https://o/internal/v1/enterprise-shared/lake-part-counts:sign");
        assert!(count_sign_url("https://o/other").is_err());
        let key = SigningKey::from_bytes(&[5; 32]);
        let key_id = "platform-release-test";
        let signing_key = key.clone();
        // Route paths with ':' are path params to axum; match the path by hand.
        let app = Router::new().fallback(move |uri: axum::http::Uri, Json(body): Json<serde_json::Value>| {
            let key = signing_key.clone();
            async move {
                assert_eq!(uri.path(), "/lake-part-counts:sign");
                assert!(uuid::Uuid::parse_str(body["request_id"].as_str().unwrap()).is_ok());
                let results = body["records"].as_array().unwrap().iter().map(|item| {
                    let bytes = base64::engine::general_purpose::STANDARD.decode(item["record_base64"].as_str().unwrap()).unwrap();
                    assert_eq!(hex::encode(sha2::Sha256::digest(&bytes)), item["record_sha256"].as_str().unwrap());
                    let mut message = crate::parts::count_record::COUNT_SIGNATURE_DOMAIN.to_vec();
                    message.extend_from_slice(&bytes);
                    serde_json::json!({"part_id": item["part_id"], "record_sha256": item["record_sha256"], "error": null,
                        "signature": {"alg": "ed25519", "key_id": key_id,
                            "sig": base64::engine::general_purpose::STANDARD.encode(key.sign(&message).to_bytes())}})
                }).collect::<Vec<_>>();
                Json(serde_json::json!({"schema_version": 1, "request_id": body["request_id"], "results": results}))
            }
        });
        // An owner release without the route: 404 for everything.
        let old_owner = Router::new();
        let mut addrs = Vec::new();
        for app in [app, old_owner] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            addrs.push(listener.local_addr().unwrap());
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        }
        let trusted = TenantKeySet::new([(key_id.to_string(), key.verifying_key())]);
        let tenant = crate::parts::provenance::tests::TENANT;
        let part = crate::parts::part_log::PartRef {
            part_id: crate::parts::format::PartId::new(1_790_000_000_000).unwrap(), level: crate::parts::levels::Level::Hour,
            event_hour: 497_222, event_day: None, rows: 10, min_time_us: 1, max_time_us: 2, schema_fingerprint: String::new(),
            provenance_sha256: "ab".repeat(32), merkle_root: String::new(), sorted: true, data_bytes: 1, row_groups: 1, data_files: 1,
        };
        let sha256 = "cd".repeat(32);
        let file = crate::parts::provenance::FileDigest { name: crate::parts::count_record::count_file_name(&sha256).unwrap(), bytes: 9, sha256 };
        let record = crate::parts::count_record::CountRecord::new(&part, tenant, key_id, 3, 4, file, 1).unwrap();
        let signer = HttpPartSigner::new(&format!("http://{}/lake-parts:sign", addrs[0]), "b", key_id, trusted.clone(), None).unwrap();
        let signatures = signer.sign_counts(tenant, std::slice::from_ref(&record)).await.unwrap();
        crate::parts::count_record::SignedCountRecord::assemble(record.clone(), signatures[0].clone(), &trusted).unwrap();
        let old = HttpPartSigner::new(&format!("http://{}/lake-parts:sign", addrs[1]), "b", key_id, trusted, None).unwrap();
        let error = old.sign_counts(tenant, std::slice::from_ref(&record)).await.unwrap_err();
        assert!(error.chain().any(|cause| cause.is::<crate::parts::provenance::CountSigningUnsupported>()), "{error:#}");
    }

    /// A stand-in owner whose bearers stop verifying `ttl` after their mint
    /// (`auth_rejected` / `cell_bearer_expired` → 401), like the owner's
    /// LAKE_CELL_OWNER_SIGN_TTL_SECONDS.
    struct ExpiringOwner {
        ttl: Duration,
        minted: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
        next: std::sync::atomic::AtomicU64,
        rejected: std::sync::atomic::AtomicU64,
    }

    impl ExpiringOwner {
        fn new(ttl: Duration) -> Arc<Self> {
            Arc::new(Self { ttl, minted: Default::default(), next: Default::default(), rejected: Default::default() })
        }

        fn mint(&self) -> String {
            let token = format!("owner-bearer-{}", self.next.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
            self.minted.lock().unwrap().insert(token.clone(), std::time::Instant::now());
            token
        }

        fn current(&self, header: Option<&str>) -> bool {
            let token = header.and_then(|value| value.strip_prefix("Bearer ")).unwrap_or_default();
            self.minted.lock().unwrap().get(token).is_some_and(|at| at.elapsed() <= self.ttl)
        }

        async fn serve(self: &Arc<Self>, key: SigningKey, key_id: &'static str) -> std::net::SocketAddr {
            let owner = self.clone();
            let app = owner_sign_app(key, key_id).layer(axum::middleware::from_fn(
                move |request: axum::extract::Request, next: axum::middleware::Next| {
                    let owner = owner.clone();
                    async move {
                        let header = request.headers().get(reqwest::header::AUTHORIZATION).and_then(|v| v.to_str().ok());
                        if !owner.current(header) {
                            owner.rejected.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            return axum::response::IntoResponse::into_response((
                                axum::http::StatusCode::UNAUTHORIZED,
                                r#"{"event":"auth_rejected","stage":"cell_bearer_expired"}"#,
                            ));
                        }
                        next.run(request).await
                    }
                },
            ));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
            addr
        }
    }

    /// The supervisor + credential exchange: each refresh request mints a
    /// fresh owner bearer, swaps it into the signer and reschedules, reporting
    /// `reported` as the new credential lifetime.
    struct FakeExchange {
        owner: Arc<ExpiringOwner>,
        signer: Arc<HttpPartSigner>,
        refresher: Arc<crate::cell_refresh::CredentialRefresher>,
        reported: chrono::Duration,
        exchanges: std::sync::atomic::AtomicUsize,
    }

    #[async_trait]
    impl crate::cell_refresh::SecretRequester for Arc<FakeExchange> {
        async fn request_secrets(&self) -> std::io::Result<()> {
            let this = self.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(30)).await;
                this.signer.set_bearer(&this.owner.mint());
                this.refresher.refreshed(chrono::Utc::now() + this.reported);
                this.exchanges.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            });
            Ok(())
        }
    }

    /// detect[T]'s finding drain against an owner whose bearers expire
    /// after 1 s: the drain keeps signing across several expiries. `reported`
    /// is the lifetime the exchange reports; `long_pass` holds the "drain"
    /// busy past a whole bearer lifetime between two signs, which is what
    /// starved the old in-loop refresh.
    async fn drain_signs_across_expiries(reported: chrono::Duration, long_pass: bool) -> (Arc<ExpiringOwner>, Arc<FakeExchange>, usize) {
        use crate::cell_refresh::{CredentialRefresher, RefreshingSigner};
        let key = SigningKey::from_bytes(&[5; 32]);
        let key_id = "platform-release-test";
        let owner = ExpiringOwner::new(Duration::from_secs(1));
        let addr = owner.serve(key.clone(), key_id).await;
        let trusted = TenantKeySet::new([(key_id.to_string(), key.verifying_key())]);
        let http = Arc::new(HttpPartSigner::new(&format!("http://{addr}/sign"), &owner.mint(), key_id, trusted, None).unwrap());
        let refresher = CredentialRefresher::new(chrono::Utc::now() + reported);
        refresher.set_poll(Duration::from_millis(20));
        refresher.set_min_request_interval(Duration::ZERO);
        let exchange = Arc::new(FakeExchange { owner: owner.clone(), signer: http.clone(), refresher: refresher.clone(),
            reported, exchanges: Default::default() });
        let schedule = tokio::spawn(refresher.clone().run(exchange.clone()));
        let signer = RefreshingSigner::new(http.clone(), refresher.clone()).with_wait(Duration::from_secs(5));
        let record = signing_record(key_id);
        let started = std::time::Instant::now();
        let mut signed = 0;
        while started.elapsed() < Duration::from_millis(4_500) {
            let signatures = signer.sign(&record.tenant_id.clone(), std::slice::from_ref(&record)).await
                .unwrap_or_else(|error| panic!("sign failed after {signed} signs: {error:#}"));
            assert_eq!(signatures.len(), 1);
            signed += 1;
            let pause = if long_pass && signed == 2 { 1_500 } else { 100 };
            tokio::time::sleep(Duration::from_millis(pause)).await;
        }
        schedule.abort();
        (owner, exchange, signed)
    }

    /// The exchange reports the owner bearer's real lifetime: the shared
    /// schedule re-exchanges at half of it, so the owner never sees an
    /// expired bearer, even across a pass longer than the bearer lives.
    #[tokio::test]
    async fn detect_drain_re_exchanges_before_every_owner_bearer_expiry() {
        let (owner, exchange, signed) = drain_signs_across_expiries(chrono::Duration::seconds(1), true).await;
        let exchanges = exchange.exchanges.load(std::sync::atomic::Ordering::SeqCst);
        assert!(exchanges >= 4, "one re-exchange per half of the 1 s bearer over 4.5 s, got {exchanges}");
        assert_eq!(owner.rejected.load(std::sync::atomic::Ordering::SeqCst), 0, "no sign ever used an expired bearer");
        assert!(signed >= 10);
    }

    /// The schedule is wrong (a 6 h expiry, as when it followed the R2
    /// credential): every expired bearer earns a 401, which re-exchanges at
    /// once and retries the sign; no sign fails and the process lives on.
    #[tokio::test]
    async fn owner_401_re_exchanges_now_and_retries_the_sign_once() {
        let (owner, exchange, signed) = drain_signs_across_expiries(chrono::Duration::hours(6), true).await;
        let rejected = owner.rejected.load(std::sync::atomic::Ordering::SeqCst);
        let exchanges = exchange.exchanges.load(std::sync::atomic::Ordering::SeqCst) as u64;
        assert!(rejected >= 3, "the owner expired the bearer several times, got {rejected} rejections");
        assert_eq!(exchanges, rejected, "exactly one urgent re-exchange per 401");
        assert!(signed >= 10);
    }

    #[test]
    fn owner_bearer_expiry_is_bounded_and_has_a_conservative_fallback() {
        use crate::cell_refresh::{owner_bearer_expiry, OWNER_BEARER_FALLBACK_LIFETIME, OWNER_BEARER_MAX_LIFETIME};
        let now = chrono::DateTime::parse_from_rfc3339("2026-09-29T16:59:14Z").unwrap().with_timezone(&chrono::Utc);
        assert_eq!(owner_bearer_expiry("2026-09-29T17:09:14Z", now), now + chrono::Duration::seconds(600));
        assert_eq!(owner_bearer_expiry("2026-09-29T17:04:14Z", now), now + chrono::Duration::seconds(300));
        // Longer than the owner ever verifies (e.g. an R2 expiry): capped.
        assert_eq!(owner_bearer_expiry("2026-09-29T22:59:14Z", now), now + OWNER_BEARER_MAX_LIFETIME);
        // Absent: re-exchanged every 225 s (half of 450 s).
        assert_eq!(owner_bearer_expiry("", now), now + OWNER_BEARER_FALLBACK_LIFETIME);
        let bearer: OwnerSignBearer = serde_json::from_value(serde_json::json!(
            {"token": "t", "audience": "owner", "scope": "lake-parts:sign"})).unwrap();
        assert_eq!(bearer.expires_at, "");
    }

    /// NAN-3006: the owner refuses a body over 64 KiB whole (413). Handed a
    /// batch whose inline records add up past it, the HTTP signer splits it
    /// into several calls, each within the cell budget, and signs them all.
    #[tokio::test]
    async fn http_signer_splits_a_batch_under_the_owner_body_fence() {
        use crate::parts::provenance::{owner_check_part, OwnerCaller, SignResult, SourceObject, OWNER_SIGN_BODY_MAX_BYTES};
        use axum::{http::StatusCode, response::IntoResponse, routing::post, Json, Router};
        use ed25519_dalek::Signer;
        let key = SigningKey::from_bytes(&[5; 32]);
        let key_id = "platform-release-test";
        let bodies = Arc::new(std::sync::Mutex::new(Vec::<usize>::new()));
        let seen = bodies.clone();
        let owner_key = key.clone();
        let app = Router::new()
            .route(
                "/sign",
                post(move |body: axum::body::Bytes| {
                    let (key, seen) = (owner_key.clone(), seen.clone());
                    async move {
                        seen.lock().unwrap().push(body.len());
                        if body.len() > OWNER_SIGN_BODY_MAX_BYTES {
                            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
                        }
                        let request: SignRequest = serde_json::from_slice(&body).unwrap();
                        let results = request
                            .parts
                            .iter()
                            .map(|part| {
                                let record = owner_check_part(&request.tenant_id, part, None, key_id, OwnerCaller::CellBearer).unwrap();
                                SignResult {
                                    part_id: part.part_id.clone(),
                                    record_sha256: part.record_sha256.clone(),
                                    signature: Some(Ed25519Signature {
                                        alg: "ed25519".into(),
                                        key_id: key_id.into(),
                                        sig: base64::Engine::encode(
                                            &base64::engine::general_purpose::STANDARD,
                                            key.sign(&record.signing_message().unwrap()).to_bytes(),
                                        ),
                                    }),
                                    error: None,
                                }
                            })
                            .collect();
                        Json(SignResponse { schema_version: 1, request_id: request.request_id, results }).into_response()
                    }
                }),
            )
            .layer(axum::extract::DefaultBodyLimit::max(1024 * 1024));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let trusted = TenantKeySet::new([(key_id.to_string(), key.verifying_key())]);
        let signer = HttpPartSigner::new(&format!("http://{addr}/sign"), "b", key_id, trusted, None).unwrap();
        // Six inline records of ~30 KiB base64 each: ~180 KiB in one count-only call.
        let records = (0..6_u32)
            .map(|i| {
                let mut record = signing_record(key_id);
                record.part_id = crate::parts::format::PartId::parse(&format!("179033040012{i}-9f86d081884c7d65")).unwrap();
                if let crate::parts::provenance::PartInputs::Sources { sources, .. } = &mut record.inputs {
                    let one = sources[0].clone();
                    *sources = (0..75)
                        .map(|s| SourceObject { key: format!("bronze-v2/shard=0/tenant_id={}/{:0>100}-{s:05}.parquet", record.tenant_id, i), ..one.clone() })
                        .collect();
                }
                record
            })
            .collect::<Vec<_>>();
        let signatures = signer.sign(&records[0].tenant_id.clone(), &records).await.unwrap();
        assert_eq!(signatures.len(), records.len());
        for (record, signature) in records.iter().zip(signatures) {
            SignedProvenance::assemble(record.clone(), signature, &signer.trusted).unwrap();
        }
        let bodies = bodies.lock().unwrap().clone();
        assert!(bodies.len() >= 4, "one count-only call would be ~180 KiB: {bodies:?}");
        assert!(bodies.iter().all(|b| *b <= SIGN_REQUEST_BUDGET_BYTES), "{bodies:?}");
    }

    /// Private-CA TLS for the owner sign route (the owner serves a cert from
    /// its own SERVER CA with a single cluster-DNS SAN).
    mod owner_ca_tls {
        use super::*;
        use rcgen::{BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair};

        struct Ca {
            issuer: CertifiedIssuer<'static, KeyPair>,
        }

        impl Ca {
            fn new(name: &str) -> Self {
                let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
                params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
                params.distinguished_name.push(DnType::CommonName, name);
                Self { issuer: CertifiedIssuer::self_signed(params, KeyPair::generate().unwrap()).unwrap() }
            }

            fn pem(&self) -> String {
                self.issuer.pem()
            }

            /// A server leaf for `san`.
            fn leaf(&self, san: &str) -> (Vec<u8>, KeyPair) {
                let key = KeyPair::generate().unwrap();
                let cert = CertificateParams::new(vec![san.to_string()]).unwrap().signed_by(&key, &self.issuer).unwrap();
                (cert.der().to_vec(), key)
            }
        }

        /// Serve the owner sign app over TLS with `leaf`; returns the port.
        async fn serve_tls(leaf: (Vec<u8>, KeyPair), key: SigningKey, key_id: &'static str) -> u16 {
            use hyper_util::rt::TokioIo;
            use hyper_util::service::TowerToHyperService;
            use tokio_rustls::rustls;
            let (der, leaf_key) = leaf;
            let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
            let config = rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(der)],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(leaf_key.serialize_der()).into(),
                )
                .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let app = owner_sign_app(key, key_id);
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((tcp, _)) = listener.accept().await else { return };
                    let (acceptor, app) = (acceptor.clone(), app.clone());
                    tokio::spawn(async move {
                        // A client that rejects the certificate aborts the handshake.
                        let Ok(tls) = acceptor.accept(tcp).await else { return };
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(tls), TowerToHyperService::new(app))
                            .await;
                    });
                }
            });
            port
        }

        struct Fixture {
            _dir: tempfile::TempDir,
            ca_file: std::path::PathBuf,
            key: SigningKey,
            key_id: &'static str,
        }

        impl Fixture {
            fn new(bundle: &str) -> Self {
                let dir = tempfile::tempdir().unwrap();
                let ca_file = dir.path().join("ca.crt");
                std::fs::write(&ca_file, bundle).unwrap();
                Self { _dir: dir, ca_file, key: SigningKey::from_bytes(&[5; 32]), key_id: "platform-release-test" }
            }

            fn signer(&self, port: u16, ca_file: Option<&std::path::Path>) -> Result<HttpPartSigner> {
                let trusted = TenantKeySet::new([(self.key_id.to_string(), self.key.verifying_key())]);
                HttpPartSigner::new(&format!("https://localhost:{port}/sign"), "b", self.key_id, trusted, ca_file)
            }

            async fn serve(&self, leaf: (Vec<u8>, KeyPair)) -> u16 {
                serve_tls(leaf, self.key.clone(), self.key_id).await
            }
        }

        async fn sign(signer: &HttpPartSigner) -> Result<Vec<Ed25519Signature>> {
            let record = signing_record(signer.key_id());
            signer.sign(&record.tenant_id.clone(), std::slice::from_ref(&record)).await
        }

        #[tokio::test]
        async fn signs_only_through_the_pinned_private_ca() {
            let ca = Ca::new("NAN2361 test owner SERVER CA");
            let f = Fixture::new(&ca.pem());
            let port = f.serve(ca.leaf("localhost")).await;
            assert_eq!(sign(&f.signer(port, Some(&f.ca_file)).unwrap()).await.unwrap().len(), 1);
            // No CA file with an https URL: refused at construction, never
            // falling back to system roots.
            let err = f.signer(port, None).err().expect("https without a CA file is refused");
            assert!(format!("{err:#}").contains("ca_file"), "{err:#}");
            // A CA bundle that did not issue the owner cert: the handshake fails.
            let other = Fixture::new(&Ca::new("some other CA").pem());
            assert!(sign(&other.signer(port, Some(&other.ca_file)).unwrap()).await.is_err());
            // An empty or garbage bundle is refused up front.
            for bad in ["", "not a pem"] {
                let bad = Fixture::new(bad);
                assert!(bad.signer(port, Some(&bad.ca_file)).is_err());
            }
        }

        /// The prevalence owner proxy is the same owner endpoint: its client
        /// trusts only `part_signing.ca_file`, never system roots.
        #[tokio::test]
        async fn prevalence_owner_client_trusts_only_the_part_signing_ca() {
            use crate::part_ingest::prevalence_owner_store::{OwnerAccess, OwnerStore, PrevalenceAccess};
            use slatedb::object_store::{path::Path, ObjectStore as _, PutMode};
            let ca = Ca::new("owner CA");
            let f = Fixture::new(&ca.pem());
            let port = f.serve(ca.leaf("localhost")).await;
            let tenant = "6f1c1e2a-5b8e-4d4c-9a3e-0e2b7c9d1f00";
            let access = |ca_file: Option<std::path::PathBuf>| PrevalenceAccess {
                read: S3Location {
                    endpoint: "https://r2.example".into(), region: "auto".into(), bucket: "b".into(),
                    prefix: format!("lake/prevalence-state/v1/tenant={tenant}/"),
                    access_key_id: "a".into(), secret_access_key: "s".into(), session_token: None,
                },
                owner: OwnerAccess {
                    url: format!("https://localhost:{port}/v1/prevalence-state/mutate"), bearer: "b".into(),
                    tenant_id: tenant.into(), assignment_generation: 1, writer_epoch: 1, expires_at: None,
                },
                owner_ca_file: ca_file,
            };
            let reads: Arc<dyn slatedb::object_store::ObjectStore> = Arc::new(slatedb::object_store::memory::InMemory::new());
            let dir = tempfile::tempdir().unwrap();
            let put = |store: OwnerStore| async move {
                store.put_opts(&Path::from("db/wal/00000000000000000001.sst"), b"x".to_vec().into(), PutMode::Create.into())
                    .await.unwrap_err().to_string()
            };
            let err = OwnerStore::new(reads.clone(), access(None), &dir.path().join("none")).unwrap_err();
            assert!(format!("{err:#}").contains("ca_file"), "{err:#}");
            // Pinned CA: the TLS handshake succeeds and the owner answers
            // (this sign-only fixture has no mutate route).
            let pinned = put(OwnerStore::new(reads.clone(), access(Some(f.ca_file.clone())), &dir.path().join("pinned")).unwrap()).await;
            assert!(pinned.contains("owner mutation status"), "{pinned}");
            // A CA that did not issue the owner cert: refused before any status.
            let other = Fixture::new(&Ca::new("some other CA").pem());
            let refused = put(OwnerStore::new(reads.clone(), access(Some(other.ca_file.clone())), &dir.path().join("other")).unwrap()).await;
            assert!(!refused.contains("owner mutation status"), "{refused}");
        }

        #[tokio::test]
        async fn hostname_verification_stays_on() {
            let ca = Ca::new("owner CA");
            let f = Fixture::new(&ca.pem());
            let port = f.serve(ca.leaf("staging-owner.staging-control.svc")).await;
            let err = sign(&f.signer(port, Some(&f.ca_file)).unwrap()).await.expect_err("a SAN that is not the URL host is refused");
            assert!(format!("{err:?}").to_lowercase().contains("certificate"), "{err:?}");
        }

        #[tokio::test]
        async fn rotated_bundle_trusts_old_and_new_and_reloads_without_restart() {
            let (old, new) = (Ca::new("owner CA 1"), Ca::new("owner CA 2"));
            let old_port = {
                let f = Fixture::new("");
                f.serve(old.leaf("localhost")).await
            };
            let new_port = {
                let f = Fixture::new("");
                f.serve(new.leaf("localhost")).await
            };
            // Overlap bundle: both owners (pre- and post-rotation) are trusted.
            let both = Fixture::new(&format!("{}{}", old.pem(), new.pem()));
            assert!(sign(&both.signer(old_port, Some(&both.ca_file)).unwrap()).await.is_ok());
            assert!(sign(&both.signer(new_port, Some(&both.ca_file)).unwrap()).await.is_ok());

            // Old-only bundle, rotated in place: the running signer picks it up
            // on reload; a broken bundle keeps the current client.
            let f = Fixture::new(&old.pem());
            let signer = f.signer(new_port, Some(&f.ca_file)).unwrap();
            assert!(sign(&signer).await.is_err(), "new owner cert is not yet trusted");
            assert!(!signer.reload_ca().unwrap(), "unchanged bundle keeps the client");
            std::fs::write(&f.ca_file, format!("{}{}", old.pem(), new.pem())).unwrap();
            assert!(signer.reload_ca().unwrap());
            assert!(sign(&signer).await.is_ok(), "rotated bundle is live without a restart");
            std::fs::write(&f.ca_file, "garbage").unwrap();
            assert!(signer.reload_ca().is_err());
            assert!(sign(&signer).await.is_ok(), "a bad reload keeps the working client");
            std::fs::remove_file(&f.ca_file).unwrap();
            assert!(signer.reload_ca().is_err());
            assert!(sign(&signer).await.is_ok());
        }
    }

    #[test]
    fn cell_feature_lean_prevalence_state_v1_is_backed() {
        assert!(nanosiem_lake_cell::features::CELL_FEATURES.contains(&"lean_prevalence_state_v1"));
        assert!(INGEST_ACCEPTS.contains(&"lake_prevalence_state"));
        assert!(LEAN_EDGE_CLASSES.contains(&"lake_prevalence_state"));
    }

    #[tokio::test]
    async fn do_notice_queue_pulls_and_acks() {
        use axum::extract::{Path, State};
        use axum::routing::{get, post};
        use axum::{Json, Router};
        use std::sync::Mutex;
        type Acked = Arc<Mutex<Vec<String>>>;
        let acked: Acked = Arc::default();
        let app = Router::new()
            .route(
                "/v1/tenants/{t}/parsed-objects",
                get(|Path(t): Path<String>| async move {
                    Json(DoNotices {
                        notices: vec![DoNotice {
                            id: "n1".into(),
                            notice: SourceNotice {
                                tenant_id: t,
                                key: "k".into(),
                                version: "1".into(),
                                bytes: 1,
                                sha256: None,
                                edge_sha256: None,
                                notified_at_ms: 5,
                            },
                        }],
                    })
                }),
            )
            .route(
                "/v1/tenants/{t}/parsed-objects:ack",
                post(|State(acked): State<Acked>, Json(body): Json<serde_json::Value>| async move {
                    for id in body["ids"].as_array().unwrap() {
                        acked.lock().unwrap().push(id.as_str().unwrap().to_string());
                    }
                }),
            )
            .with_state(acked.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let queue = DoNoticeQueue::new(&NoticeEndpoint { url: format!("http://{addr}"), bearer: "b".into() }, "t1").unwrap();
        let pending = queue.pending(10).await.unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].1.key, "k");
        queue.ack(&[pending[0].0.clone()]).await.unwrap();
        assert_eq!(*acked.lock().unwrap(), vec!["n1".to_string()]);
    }
    #[tokio::test]
    async fn native_exchange_exact_permission_binding_and_expiry_floor_over_http() {
        use axum::{routing::post, Json, Router};
        let now = chrono::Utc::now(); let expiry = now + chrono::Duration::minutes(4);
        let credentials: Vec<_> = ["lake_part", "lake_part_log"].into_iter().map(|class| serde_json::json!({
            "credential_class":class,"endpoint":"https://acct.r2.cloudflarestorage.com","region":"auto",
            "bucket":"nano-shared-r2-t1","permission":"object-read-write","prefixes":["lake/parts/v1/tenant=t1/"],
            "access_key_id":"test-access","secret_access_key":"test-secret","session_token":"","expires_at":(now+chrono::Duration::minutes(9)).to_rfc3339()
        })).collect();
        let base = serde_json::json!({"schema_version":1, "tenant_id":"t1", "role":"ingest", "credentials":credentials,
            "owner_sign":{"token":"sign-secret", "audience":"owner", "scope":"lake-parts:sign", "expires_at":(now+chrono::Duration::minutes(9)).to_rfc3339()},
            "edge_log_consumer_endpoint":"https://edge.example", "edge_log_consumer_token":"edge-secret",
            "owner_write":{"token":"write-secret", "audience":"owner", "scope":"lake-parts:write", "tenantId":"t1",
                "tenantKey":"logical", "cellId":"cell-a", "principalId":"principal", "role":"ingest", "expiresAt":expiry.to_rfc3339()}});
        for bad in [None, Some(("scope", serde_json::json!("lake-parts:sign"))), Some(("tenantId", serde_json::json!("foreign"))),
            Some(("expiresAt", serde_json::json!((now-chrono::Duration::minutes(1)).to_rfc3339())))] {
            let mut response = base.clone(); if let Some((field, value)) = &bad { response["owner_write"][*field] = value.clone(); }
            let app = Router::new().route("/v1/lake/cells/{cell}/credential-exchange", post(move || { let response=response.clone(); async move { Json(response) } }));
            let listener=tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap(); let addr=listener.local_addr().unwrap();
            let task=tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
            let result=exchange_received(b"bootstrap-secret", &assignment("t1", Some(&format!("http://{addr}"))), Instant::now()).await;
            if bad.is_some() { let error=result.err().unwrap(); assert!(error.to_string().contains("permission differs or expired"), "{error:#}"); assert!(!format!("{error:#}").contains("secret")); }
            else { let fresh=result.unwrap(); assert_eq!(fresh.expires_at, expiry); assert!(fresh.write_permission.is_some()); }
            task.abort();
        }
    }

}
