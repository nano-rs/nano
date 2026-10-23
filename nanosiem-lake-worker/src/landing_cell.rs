// SPDX-License-Identifier: AGPL-3.0-or-later

//! `landing[T]`: the hosted OCSF bucket-drop converter as a lean-cell child
//! (NAN-3885 design step 3, NAN-4137; cell feature `lean_tenzir_landing_v1`).
//!
//! The supervisor starts it only for a tenant placed with `landing: true`
//! on a `tenzir_landing` cell that writes for the tenant. It is jailed like
//! every tenant role: its OWN uid, Landlock with no tenant path but its own
//! state dir (never `parts/`, the feed, the policy or custom context),
//! seccomp, its own cgroup leaf with fixed ceilings on top of the tenant's.
//!
//! Its authority is one credential exchange, `role: "landing"`, accepting
//! only [`LANDING_ACCEPTS`]:
//! - `landing_reader`: object read/write on exactly the tenant's landing and
//!   refused prefixes (read and delete landed files, move refused ones
//!   aside). R2 temporary credentials have no delete-only permission, so
//!   `object-read-write` scoped to those two prefixes is the narrowest grant.
//!   A response that names any other prefix (`lake/parts/...`) or class is
//!   refused whole ([`grant_from`]);
//! - the landing-ledger token (lease / next / commit on the tenant's ledger);
//! - the edge-log PRODUCER token (append only).
//!
//! No owner-sign, part, log, delete, consumer, prevalence or erasure grant
//! is accepted. Credentials refresh in place before they expire (NAN-3017:
//! a fresh bootstrap from the supervisor, then a new exchange) on their own
//! task, so a long conversion never delays a refresh.

use anyhow::{bail, ensure, Context, Result};
use async_trait::async_trait;
use nanosiem_core::parsers::landing_ocsf::LandingOcsfStage;
use nanosiem_lake_cell::child::{ControlChannel, TenantService};
use nanosiem_lake_cell::contract::{Assignment, Heartbeat, WakeReason};
use opendal::layers::RetryLayer;
use opendal::Operator;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use crate::landing::{Engine, LANDING_PREFIX, REFUSED_PREFIX};
use crate::landing_hosted::{
    EdgeAppend, HttpEdgeLogProducer, HttpLandingLedger, LandingCounters, LedgerFenced, LeaseDiscover, MAX_LEASE_FILES,
};
use crate::part_ingest::cell::{ExchangeRefused, ExchangeResponse, ExchangedR2Credential};

/// The only class landing[T] accepts.
pub const LANDING_ACCEPTS: &[&str] = &["landing_reader"];
/// The only permission R2 temporary credentials offer that can delete.
pub const LANDING_READER_PERMISSION: &str = "object-read-write";

/// Empty polls wait this long; a tick that found files runs again at once.
const POLL: Duration = Duration::from_secs(10);
/// Refresh at this fraction of the grant's lifetime.
const REFRESH_AT_FRACTION: f64 = 2.0 / 3.0;
const REFRESH_RETRY: Duration = Duration::from_secs(15);

/// The exact prefixes of the tenant's `landing_reader` credential.
pub fn landing_prefixes(tenant: &str) -> [String; 2] {
    [format!("{LANDING_PREFIX}tenant_id={tenant}/"), format!("{REFUSED_PREFIX}tenant_id={tenant}/")]
}

/// A validated landing exchange.
pub struct LandingGrant {
    pub reader: ExchangedR2Credential,
    /// The tenant Worker origin (ledger and producer routes).
    pub endpoint: String,
    /// `NANO_LANDING_AUTH_TOKEN`: one credential for both route families.
    pub token: Zeroizing<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

/// Exchange a single-use bootstrap token for the landing grant.
pub async fn exchange_landing(token: &[u8], assignment: &Assignment, received: Instant) -> Result<LandingGrant> {
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
        .json(&serde_json::json!({ "tenant_id": tenant, "role": "landing", "accepts": LANDING_ACCEPTS }))
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        return Err(ExchangeRefused::with_token_age(status.as_u16(), received.elapsed()).into());
    }
    let body = Zeroizing::new(response.bytes().await?.to_vec());
    let exchange: ExchangeResponse = serde_json::from_slice(&body).context("credential exchange response")?;
    grant_from(exchange, tenant)
}

fn worker_endpoint(endpoint: Option<String>, what: &str) -> Result<String> {
    let endpoint = endpoint.with_context(|| format!("landing exchange has no {what} endpoint"))?;
    let url = reqwest::Url::parse(&endpoint).with_context(|| format!("landing {what} endpoint is not a URL"))?;
    ensure!(url.scheme() == "https" || cfg!(test), "landing {what} endpoint must use https");
    ensure!(url.path() == "/" && url.query().is_none() && url.username().is_empty(),
        "landing {what} endpoint must be a bare Worker origin");
    Ok(endpoint)
}

/// `NANO_LANDING_AUTH_TOKEN`'s alphabet: `[A-Za-z0-9_-]{32,256}` (CONTRACT.md A1).
fn token(token: Option<String>, what: &str) -> Result<Zeroizing<String>> {
    let token = Zeroizing::new(token.with_context(|| format!("landing exchange has no {what} token"))?);
    ensure!(
        (32..=256).contains(&token.len()) && token.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "landing {what} token is malformed"
    );
    Ok(token)
}

/// Validate a landing exchange: exactly the `landing_reader` credential on
/// exactly the tenant's two landing prefixes, plus the Worker landing
/// token and origin. Anything else is refused whole.
pub fn grant_from(exchange: ExchangeResponse, tenant: &str) -> Result<LandingGrant> {
    ensure!(
        exchange.schema_version == 1 && exchange.tenant_id == tenant && exchange.role == "landing",
        "exchange response binding differs"
    );
    ensure!(
        exchange.owner_sign.is_none() && exchange.owner_write.is_none() && exchange.notices.is_none()
            && exchange.prevalence_owner.is_none() && exchange.edge_log_consumer_token.is_none()
            && exchange.edge_log_consumer_endpoint.is_none() && exchange.lake_part_delete_grant.is_none()
            && exchange.lake_part_gc.is_none() && exchange.erasure_ledger.is_none(),
        "landing exchange carries a grant the landing role must not hold"
    );
    let [reader] = exchange.credentials.as_slice() else {
        bail!("landing exchange must return exactly one credential");
    };
    let mut prefixes = reader.prefixes.clone();
    prefixes.sort();
    let mut want = landing_prefixes(tenant).to_vec();
    want.sort();
    ensure!(
        reader.credential_class == "landing_reader" && reader.permission == LANDING_READER_PERMISSION && prefixes == want,
        "landing credential must be landing_reader on exactly the tenant's landing prefixes"
    );
    ensure!(reader.endpoint.starts_with("https://") || cfg!(test), "landing object-store endpoint must use https");
    let expires_at = chrono::DateTime::parse_from_rfc3339(&reader.expires_at)
        .context("landing credential expiry")?
        .with_timezone(&chrono::Utc);
    Ok(LandingGrant {
        reader: reader.clone(),
        endpoint: worker_endpoint(exchange.landing_endpoint, "Worker")?,
        token: token(exchange.landing_token, "Worker")?,
        expires_at,
    })
}

/// The landing_reader store (bucket root; the credential confines it).
pub fn reader_store(reader: &ExchangedR2Credential) -> Result<Operator> {
    let builder = opendal::services::S3::default()
        .bucket(&reader.bucket)
        .region(&reader.region)
        .endpoint(&reader.endpoint)
        .access_key_id(&reader.access_key_id)
        .secret_access_key(&reader.secret_access_key)
        .session_token(&reader.session_token)
        .disable_config_load()
        .disable_ec2_metadata();
    Ok(Operator::new(builder)?.layer(RetryLayer::new().with_max_times(3)).finish())
}

/// The cell-facing landing service.
pub struct LandingService {
    assignment: Assignment,
    counters: Arc<LandingCounters>,
    stage: LandingOcsfStage,
    store: std::sync::RwLock<Operator>,
    ledger: Arc<HttpLandingLedger>,
    producer: Arc<HttpEdgeLogProducer>,
    secrets: tokio::sync::mpsc::Sender<Zeroizing<Vec<u8>>>,
    secrets_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Zeroizing<Vec<u8>>>>,
    issued_ms: AtomicI64,
    expires_ms: AtomicI64,
    last_progress_ms: AtomicU64,
    queue_depth: AtomicU64,
}

impl LandingService {
    pub async fn start(assignment: &Assignment, secret: Zeroizing<Vec<u8>>) -> Result<Arc<Self>> {
        let issued = chrono::Utc::now();
        let grant = exchange_landing(&secret, assignment, Instant::now()).await?;
        let tenant = assignment.tenant.as_str();
        let (secrets, secrets_rx) = tokio::sync::mpsc::channel(2);
        let service = Self {
            assignment: assignment.clone(),
            counters: Arc::new(LandingCounters::default()),
            // Hosted segments are single-shard (the edge log's contract).
            stage: LandingOcsfStage::new(1).map_err(|e| anyhow::anyhow!("compile the lake storage stage: {e}"))?,
            store: std::sync::RwLock::new(reader_store(&grant.reader)?),
            ledger: Arc::new(HttpLandingLedger::new(&grant.endpoint, grant.token.clone())?),
            producer: Arc::new(HttpEdgeLogProducer::new(&grant.endpoint, tenant, grant.token.clone())?),
            secrets,
            secrets_rx: tokio::sync::Mutex::new(secrets_rx),
            issued_ms: AtomicI64::new(issued.timestamp_millis()),
            expires_ms: AtomicI64::new(grant.expires_at.timestamp_millis()),
            last_progress_ms: AtomicU64::new(now_ms()),
            queue_depth: AtomicU64::new(0),
        };
        Ok(Arc::new(service))
    }

    fn refresh_due_in(&self) -> Duration {
        let (issued, expires) = (self.issued_ms.load(Ordering::Relaxed), self.expires_ms.load(Ordering::Relaxed));
        let at = issued + ((expires - issued).max(0) as f64 * REFRESH_AT_FRACTION) as i64;
        Duration::from_millis((at - chrono::Utc::now().timestamp_millis()).max(0) as u64)
    }

    /// Get a fresh bootstrap from the supervisor, re-exchange, and swap the
    /// new grant into the live store and clients.
    async fn refresh(&self, control: &ControlChannel) -> Result<()> {
        control.request_secrets().await?;
        let secret = tokio::time::timeout(Duration::from_secs(90), async { self.secrets_rx.lock().await.recv().await })
            .await
            .context("no fresh bootstrap token from the supervisor")?
            .context("secrets channel closed")?;
        let issued = chrono::Utc::now();
        let grant = exchange_landing(&secret, &self.assignment, Instant::now()).await?;
        self.ledger.set_token(grant.token.clone())?;
        self.producer.set_token(grant.token.clone())?;
        *self.store.write().map_err(|_| anyhow::anyhow!("landing store lock is poisoned"))? = reader_store(&grant.reader)?;
        self.issued_ms.store(issued.timestamp_millis(), Ordering::Relaxed);
        self.expires_ms.store(grant.expires_at.timestamp_millis(), Ordering::Relaxed);
        Ok(())
    }

    /// The refresh loop, on its own task. A final refusal (401/403) or an
    /// expired grant ends the process for a respawn.
    async fn refresh_loop(self: Arc<Self>, control: ControlChannel) -> Result<()> {
        loop {
            tokio::time::sleep(self.refresh_due_in()).await;
            match self.refresh(&control).await {
                Ok(()) => tracing::info!("landing credentials refreshed"),
                Err(error) => {
                    let fatal = error.downcast_ref::<ExchangeRefused>().is_some_and(ExchangeRefused::is_final)
                        || self.expires_ms.load(Ordering::Relaxed) <= chrono::Utc::now().timestamp_millis();
                    tracing::error!(error = %format!("{error:#}"), fatal, "landing credential refresh failed");
                    if fatal {
                        let _ = control.fatal(&format!("{error:#}")).await;
                        return Err(error.context("landing credential refresh"));
                    }
                    tokio::time::sleep(REFRESH_RETRY).await;
                }
            }
        }
    }

    /// Convert until the process ends. A fenced ledger lease (a newer
    /// landing[T] took over) ends the process; every other failure is
    /// retried on the next tick.
    pub async fn run(self: Arc<Self>, control: ControlChannel) -> Result<()> {
        let refresher = tokio::spawn(self.clone().refresh_loop(control.clone()));
        let tenant = self.assignment.tenant.as_str().to_string();
        let consumer_id = format!("{}:{}", self.assignment.cell_id, std::process::id());
        let discover = LeaseDiscover::new(self.ledger.clone(), &tenant, &consumer_id, self.counters.clone());
        let emit = EdgeAppend::new(self.producer.clone(), self.counters.clone());
        loop {
            if refresher.is_finished() {
                return match refresher.await {
                    Ok(Ok(())) => Ok(()),
                    Ok(Err(error)) => Err(error),
                    Err(join) => Err(anyhow::anyhow!("landing refresh task: {join}")),
                };
            }
            let store = self.store.read().map_err(|_| anyhow::anyhow!("landing store lock is poisoned"))?.clone();
            let engine = Engine {
                store: &store,
                discover: &discover,
                emit: &emit,
                stage: &self.stage,
                tenant_id: &tenant,
                max_files_per_tick: MAX_LEASE_FILES,
            };
            let again = match engine.tick().await {
                Ok(report) => {
                    if report.listed > 0 {
                        tracing::info!(?report, "landing tick");
                    }
                    self.queue_depth.store(report.listed as u64, Ordering::Relaxed);
                    report.listed > 0 && report.held == 0 && report.failed < report.listed
                }
                Err(error) if error.downcast_ref::<LedgerFenced>().is_some() => {
                    tracing::warn!("landing ledger lease taken by a newer converter; exiting");
                    let _ = control.fatal("landing ledger lease fenced").await;
                    return Err(error);
                }
                Err(error) => {
                    self.counters.ticks_failed.fetch_add(1, Ordering::Relaxed);
                    tracing::warn!(error = %format!("{error:#}"), "landing tick failed; retrying");
                    false
                }
            };
            self.last_progress_ms.store(now_ms(), Ordering::Relaxed);
            if !again {
                tokio::time::sleep(POLL).await;
            }
        }
    }

    pub fn counters(&self) -> &Arc<LandingCounters> {
        &self.counters
    }
}

fn now_ms() -> u64 {
    chrono::Utc::now().timestamp_millis().max(0) as u64
}

#[async_trait]
impl TenantService for LandingService {
    async fn handle_rpc(self: Arc<Self>, _request_id: u64, mut stream: tokio::net::UnixStream) {
        use tokio::io::AsyncWriteExt;
        let _ = stream.write_all(b"HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n").await;
    }

    async fn wake(self: Arc<Self>, _reason: WakeReason) {}

    fn heartbeat(&self) -> Heartbeat {
        let (issued, expires) = (self.issued_ms.load(Ordering::Relaxed), self.expires_ms.load(Ordering::Relaxed));
        let now = chrono::Utc::now().timestamp_millis();
        let status = self.counters.status();
        Heartbeat {
            busy: true,
            last_progress_unix_ms: self.last_progress_ms.load(Ordering::Relaxed),
            credential_refresh_at_risk: now >= expires - (expires - issued).max(0) / 10,
            queue_depth: self.queue_depth.load(Ordering::Relaxed),
            detail: Some(format!(
                "accepted={} refused={} held={}",
                status.files_accepted, status.files_refused, status.files_held
            )),
            landing: Some(status),
            ..Default::default()
        }
    }

    async fn secrets(self: Arc<Self>, secret: Zeroizing<Vec<u8>>) {
        let _ = self.secrets.send(secret).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const TENANT: &str = "6f1d2c3b-4a59-4e6f-8a7b-9c0d1e2f3a4b";
    const LANDING_TOKEN: &str = "lnd_0123456789abcdefghijklmnopqrstuvwxyz";

    fn credential(class: &str, permission: &str, prefixes: Vec<String>) -> serde_json::Value {
        json!({"credential_class": class, "endpoint": "https://acct.r2.cloudflarestorage.com", "region": "auto",
            "bucket": format!("nano-shared-r2-{TENANT}"), "permission": permission, "prefixes": prefixes,
            "access_key_id": "AK", "secret_access_key": "SK", "session_token": "ST", "expires_at": "2099-01-01T00:00:00Z"})
    }

    fn exchange(credentials: Vec<serde_json::Value>) -> serde_json::Value {
        json!({"schema_version": 1, "tenant_id": TENANT, "role": "landing", "credentials": credentials,
            "landing_token": LANDING_TOKEN, "landing_endpoint": "https://acme.ingest.nano.rs"})
    }

    fn grant(value: serde_json::Value) -> Result<LandingGrant> {
        grant_from(serde_json::from_value(value).unwrap(), TENANT)
    }

    fn reader() -> serde_json::Value {
        credential("landing_reader", "object-read-write", landing_prefixes(TENANT).to_vec())
    }

    #[test]
    fn the_landing_grant_is_exactly_the_reader_on_the_landing_prefixes() {
        let ok = grant(exchange(vec![reader()])).unwrap();
        assert_eq!(ok.reader.prefixes, landing_prefixes(TENANT).to_vec());
        assert_eq!(ok.token.as_str(), LANDING_TOKEN);
        assert_eq!(ok.endpoint, "https://acme.ingest.nano.rs");
        assert_eq!(landing_prefixes(TENANT), [
            format!("landing-ocsf-v1/tenant_id={TENANT}/"),
            format!("landing-ocsf-v1-refused/tenant_id={TENANT}/"),
        ]);
    }

    /// The credential landing[T] accepts can never reach `lake/parts` (or
    /// any prefix but its tenant's two landing prefixes): such a grant, or
    /// one with an extra class or authority, is refused whole.
    #[test]
    fn a_grant_that_could_read_lake_parts_or_more_is_refused() {
        let parts = format!("lake/parts/v1/tenant={TENANT}/");
        let [landing, refused] = landing_prefixes(TENANT);
        let other_tenant = landing_prefixes("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d");
        let refusals = [
            // A prefix outside landing, alone or alongside.
            exchange(vec![credential("landing_reader", "object-read-write", vec![landing.clone(), refused.clone(), parts.clone()])]),
            exchange(vec![credential("landing_reader", "object-read-write", vec![parts.clone()])]),
            // The bucket root, a broader landing prefix, another tenant's.
            exchange(vec![credential("landing_reader", "object-read-write", vec![String::new()])]),
            exchange(vec![credential("landing_reader", "object-read-write", vec!["landing-ocsf-v1/".into(), "landing-ocsf-v1-refused/".into()])]),
            exchange(vec![credential("landing_reader", "object-read-write", other_tenant.to_vec())]),
            // Another class, or a second credential next to the reader.
            exchange(vec![credential("lake_part_read", "object-read-only", vec![parts.clone()])]),
            exchange(vec![reader(), credential("lake_part_read", "object-read-only", vec![parts.clone()])]),
            // Read-only cannot delete; the wrong role or tenant binding.
            exchange(vec![credential("landing_reader", "object-read-only", landing_prefixes(TENANT).to_vec())]),
            { let mut e = exchange(vec![reader()]); e["role"] = json!("ingest"); e },
            { let mut e = exchange(vec![reader()]); e["tenant_id"] = json!("0a1b2c3d-4e5f-4a6b-8c7d-8e9f0a1b2c3d"); e },
            // Grants the landing role must never hold.
            { let mut e = exchange(vec![reader()]); e["edge_log_consumer_token"] = json!("consumer"); e },
            { let mut e = exchange(vec![reader()]); e["owner_sign"] = json!({"token": "t", "audience": "a", "scope": "s"}); e },
            { let mut e = exchange(vec![reader()]); e["lake_part_delete_grant"] = json!({}); e },
            // Missing Worker authority, a malformed token, or a non-origin endpoint.
            { let mut e = exchange(vec![reader()]); e.as_object_mut().unwrap().remove("landing_token"); e },
            { let mut e = exchange(vec![reader()]); e.as_object_mut().unwrap().remove("landing_endpoint"); e },
            { let mut e = exchange(vec![reader()]); e["landing_token"] = json!("short"); e },
            { let mut e = exchange(vec![reader()]); e["landing_token"] = json!(format!("{LANDING_TOKEN} x")); e },
            { let mut e = exchange(vec![reader()]); e["landing_endpoint"] = json!("https://acme.ingest.nano.rs/elsewhere"); e },
        ];
        for (i, value) in refusals.into_iter().enumerate() {
            assert!(grant(value).is_err(), "refusal {i} was accepted");
        }
    }
}
