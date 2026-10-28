// SPDX-License-Identifier: AGPL-3.0-or-later
//! Native conditional PUT receipts. The owner verifies provider HEAD before
//! registering a receipt; unresolved PUT outcomes never become successful writes.
use anyhow::{ensure, Context, Result};
use chrono::{SecondsFormat, TimeZone, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{path::{Path, PathBuf}, sync::RwLock, time::Duration};
use super::owner_tls::OwnerTlsClient;
use crate::parts::part_log::WriteHints;

/// NAN-4592: write-behind completion and coalesced authorization of part
/// objects (a child module: it shares this writer's private journal).
#[path = "native_lanes.rs"]
mod lanes;
pub use lanes::{NATIVE_AUTHORIZE_BATCH_PATH, NATIVE_BATCH_MAX_ITEMS, NATIVE_COMPLETE_BATCH_PATH};

const AUTHORIZE_PATH: &str = "/internal/v1/enterprise-shared/lake-writers:authorize";
const COMPLETE_PATH: &str = "/internal/v1/enterprise-shared/lake-writers:complete";
/// The single routes' response cap (one identity or receipt).
const OWNER_RESPONSE_CAP: usize = 65536;

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WritePermission {
    token: String,
    audience: String,
    scope: String,
    tenant_id: String,
    tenant_key: String,
    cell_id: String,
    principal_id: String,
    role: String,
    expires_at: chrono::DateTime<Utc>,
}
impl Drop for WritePermission {
    fn drop(&mut self) { use zeroize::Zeroize; self.token.zeroize(); }
}
impl WritePermission {
    pub fn expires_at(&self) -> chrono::DateTime<Utc> { self.expires_at }
    pub(crate) fn validate(&self, tenant: &str, cell: &str) -> Result<()> {
        ensure!(self.audience == "owner" && self.scope == "lake-parts:write" && self.role == "ingest"
            && self.tenant_id == tenant && self.cell_id == cell && !self.principal_id.is_empty()
            && !self.tenant_key.is_empty() && self.tenant_key.len() <= 63
            && !self.token.is_empty() && self.token.len() <= 8192 && !self.token.chars().any(char::is_control)
            && self.expires_at > Utc::now() && self.expires_at <= Utc::now() + chrono::Duration::minutes(10),
            "native writer permission differs or expired");
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
struct Intent { request: Value, identity: Value, object: Option<Value>, registered: Option<Value> }
/// NAN-4676: has the owner's completion window for `identity` closed? Only a
/// schema-3 identity carries `completion_deadline_at`; anything else (or an
/// unparseable value) is never treated as expired.
fn completion_window_closed(identity: &Value) -> bool {
    identity["completion_deadline_at"].as_str()
        .and_then(|deadline| chrono::DateTime::parse_from_rfc3339(deadline).ok())
        .is_some_and(|deadline| deadline.with_timezone(&Utc) <= Utc::now())
}
/// NAN-4676: the owner refused this exact request for good (409 conflict,
/// 410 gone, 422 refused reservation). Auth (401/403), a missing route
/// (404), rate limits, 5xx and transport errors say nothing about the
/// request itself and never abandon an intent.
fn owner_refused_permanently(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<OwnerRefused>()
        .is_some_and(|refused| matches!(refused.status, 409 | 410 | 422)))
}
fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|v| v.len() == 64 && v != "0".repeat(64)
        && v.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()))
}
fn same_time(left: &Value, right: &Value) -> bool {
    match (left.as_str(), right.as_str()) {
        (Some(left), Some(right)) => match (chrono::DateTime::parse_from_rfc3339(left), chrono::DateTime::parse_from_rfc3339(right)) {
            (Ok(left), Ok(right)) => left == right,
            _ => false,
        },
        _ => false,
    }
}
/// Derive only the pinned listener origin; credentials never follow a URL authority override.
pub fn owner_origin(signing_url: &str) -> Result<String> {
    let url = reqwest::Url::parse(signing_url).context("invalid pinned owner URL")?;
    ensure!((url.scheme() == "https" || (cfg!(test) && url.scheme() == "http"))
        && url.host_str().is_some() && url.port_or_known_default().is_some()
        && url.username().is_empty() && url.password().is_none()
        && url.query().is_none() && url.fragment().is_none(), "invalid pinned owner origin");
    Ok(url.origin().ascii_serialization())
}
/// A journaled authorization has no successful PUT evidence. Never retry
/// this identity's PUT or claim it was registered without evidence; its
/// enclosing unpublished part must be rebuilt under a fresh identity
/// instead. NAN-4444: the R2 part store first reads the object back, and an
/// object holding exactly these bytes completes the attempt (its strong ETag
/// is the PUT evidence); only an absent or unreadable object surfaces this.
#[derive(Debug, thiserror::Error)]
#[error("native PUT outcome unresolved; owner recovery required")]
pub struct NativePutUnresolved {
    pub key: String,
}

/// The owner answered a native writer call with a non-success status.
#[derive(Debug, thiserror::Error)]
#[error("native writer owner refused HTTP {status}")]
pub struct OwnerRefused {
    pub status: u16,
}

/// NAN-4336: the owner's answer when NanoSIEM refused a writer reservation
/// itself (control `r2_writers.reserve` HTTP 400, e.g. a `max_event_time`
/// more than 5 min past control's clock): `422 writer_reservation_refused`,
/// `retryable: false`. A replay of the same request reaches the same verdict.
pub const OWNER_RESERVATION_REFUSED_STATUS: u16 = 422;

impl OwnerRefused {
    /// NAN-4336: a permanent refusal of this object's reservation.
    pub fn is_reservation_refused(&self) -> bool {
        self.status == OWNER_RESERVATION_REFUSED_STATUS
    }
}

/// NAN-4336: does `error` carry the owner's permanent reservation refusal?
pub fn reservation_refused(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| cause.downcast_ref::<OwnerRefused>().is_some_and(OwnerRefused::is_reservation_refused))
}

/// NAN-3723: how long one native writer call keeps retrying an owner that
/// answers "temporarily unavailable" (502/503/504) before the error reaches
/// the caller. Every owner route the writer calls is idempotent per
/// `request_id` (authorize returns the same reservation, complete the same
/// receipt), and an unavailable answer committed nothing, so a short retry is
/// safe. It absorbs the transient refusals an owner returns while its
/// control-plane database sheds a lock conflict, instead of failing the
/// flush, quarantining a merge or holding ingest for a whole tick backoff.
pub const OWNER_UNAVAILABLE_RETRY_WINDOW: Duration = Duration::from_secs(20);
const OWNER_UNAVAILABLE_FIRST_DELAY: Duration = Duration::from_millis(250);
const OWNER_UNAVAILABLE_MAX_DELAY: Duration = Duration::from_secs(4);

/// The owner answered "try again shortly" rather than refusing the request.
pub(crate) fn owner_unavailable(status: u16) -> bool {
    matches!(status, 502..=504)
}

/// Delay before retry `attempt` (1-based) of an unavailable owner, or `None`
/// once `elapsed` plus the delay would pass `window`.
pub(crate) fn owner_unavailable_delay(attempt: u32, elapsed: Duration, window: Duration) -> Option<Duration> {
    let delay = OWNER_UNAVAILABLE_FIRST_DELAY
        .saturating_mul(1_u32 << attempt.saturating_sub(1).min(8))
        .min(OWNER_UNAVAILABLE_MAX_DELAY);
    (elapsed + delay <= window).then_some(delay)
}

#[derive(Default)]
struct WriterCounters {
    timings: super::timing::Timings,
    replay_started: std::sync::atomic::AtomicU64,
    replay_completed: std::sync::atomic::AtomicU64,
    authorize_started: std::sync::atomic::AtomicU64,
    authorize_completed: std::sync::atomic::AtomicU64,
    complete_started: std::sync::atomic::AtomicU64,
    complete_completed: std::sync::atomic::AtomicU64,
    put_started: std::sync::atomic::AtomicU64,
    put_completed: std::sync::atomic::AtomicU64,
    /// NAN-4592: one count per batch call and one per object it carried.
    authorize_batch_started: std::sync::atomic::AtomicU64,
    authorize_batch_completed: std::sync::atomic::AtomicU64,
    authorize_batch_objects: std::sync::atomic::AtomicU64,
    complete_batch_started: std::sync::atomic::AtomicU64,
    complete_batch_completed: std::sync::atomic::AtomicU64,
    complete_batch_objects: std::sync::atomic::AtomicU64,
    /// Batch calls that fell back to the single routes.
    batch_fallbacks: std::sync::atomic::AtomicU64,
    /// Part-object completions taken off the write path (write-behind).
    completion_deferred: std::sync::atomic::AtomicU64,
    /// NAN-4676: journaled intents whose completion window closed before the
    /// owner registered them, renewed and completed under a fresh identity.
    expired_renewed: std::sync::atomic::AtomicU64,
    /// NAN-4676: expired part-object intents the owner would not renew,
    /// quarantined so their unpublished part is rebuilt under a new part ID.
    expired_abandoned: std::sync::atomic::AtomicU64,
}
pub struct NativePartWriter {
    counters: WriterCounters,
    /// One tenant/process envelope, shared by data/provenance/log writes and
    /// every overlapping publication. Acquired per write, never per group.
    writes: tokio::sync::Semaphore,
    /// Shared by authorize, complete, journal replay and retries. Starts at
    /// twenty native RPC/s under the smallest control allowance (3072/min); scales
    /// with assignment EPS. No burst after an idle gap.
    next_owner_call: tokio::sync::Mutex<tokio::time::Instant>,
    owner_call_interval: Duration,
    origin: String, tenant: String, cell: String, bucket: String,
    permission: RwLock<WritePermission>, tls: OwnerTlsClient, dir: PathBuf, archive: PathBuf,
    /// NAN-4676: evidence of journaled intents the owner refused after their
    /// completion window closed (`<request_id>.superseded.<owner_reservation_sha256>.json` per refused attempt once
    /// renewed, `<request_id>.abandoned.json` when it could not be). Never
    /// replayed and never deleted by the writer.
    quarantine: PathBuf,
    /// Writes hold this shared, so independent objects upload concurrently
    /// (a part's files, ingest flushes beside merges). Journal replay holds
    /// it exclusively: no write is in flight while pending intents are read.
    gate: tokio::sync::RwLock<()>,
    /// Same-key writes stay serialized: a second attempt of an identical
    /// request must observe the first one's archived receipt, never its
    /// unresolved in-flight intent.
    keys: std::sync::Mutex<std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
    /// Set at open and after any failed write: the next write replays the
    /// journal first (exclusive). Healthy writes never wait on a replay, so
    /// they no longer queue behind one another (each is ~0.6 s of owner
    /// authorize/complete; serial, they capped a cell at ~1 object/s).
    pub(super) needs_replay: std::sync::atomic::AtomicBool,
    /// [`OWNER_UNAVAILABLE_RETRY_WINDOW`]; tests shorten it.
    unavailable_retry_window: Duration,
    /// NAN-4592: write-behind owner completions of part objects. A part
    /// object's PUT returns once its evidence is journaled; its completion
    /// runs here, coalesced with its neighbours, and every part-log entry or
    /// checkpoint waits for all of them before it is authorized to land.
    lane: lanes::CompletionLane,
    /// NAN-4592: concurrent part-object authorizations, coalesced.
    authorizer: lanes::AuthorizeCoalescer,
    /// Whether the owner serves the batch routes (re-probed when not).
    batch: lanes::BatchSupport,
    /// How long calls that arrive together are gathered into one batch.
    coalesce_window: Duration,
    /// NAN-4713: write-behind completion hold cap (see `lanes::COMPLETION_HOLD_MAX`).
    completion_hold: Duration,
    /// Test-only: complete every write on its own write path, as before
    /// NAN-4592 (the throughput comparison's baseline).
    #[cfg(test)]
    synchronous_completion: bool,
}
/// Held for one native write: the shared gate plus the key's own lock.
pub struct WriteGuard<'a> {
    _permit: tokio::sync::SemaphorePermit<'a>,
    _gate: tokio::sync::RwLockReadGuard<'a, ()>,
    _key: tokio::sync::OwnedMutexGuard<()>,
    key: String,
    writer: &'a NativePartWriter,
}
impl Drop for WriteGuard<'_> {
    fn drop(&mut self) {
        let mut keys = self.writer.keys.lock().expect("native key locks");
        // Ours plus the map's: nobody else waits on this key.
        if keys.get(&self.key).is_some_and(|lock| std::sync::Arc::strong_count(lock) <= 2) {
            keys.remove(&self.key);
        }
    }
}
pub struct NativeAttempt { path: PathBuf, request: Value, identity: Value }
impl NativePartWriter {
    pub fn new(origin: &str, ca: Option<&Path>, tenant: &str, cell: &str, bucket: &str,
        permission: WritePermission, state: &Path) -> Result<Self> {
        permission.validate(tenant, cell)?;
        ensure!(owner_origin(origin)? == origin.trim_end_matches('/'), "native writer requires exact owner origin");
        let root = state.join("native-writer-receipts");
        let dir = root.join("pending");
        let archive = root.join("registered");
        let quarantine = root.join("quarantined");
        for path in [&root, &dir, &archive, &quarantine] {
            std::fs::create_dir_all(path)?;
            ensure!(std::fs::symlink_metadata(path)?.file_type().is_dir(), "native journal requires directories");
            std::fs::File::open(path)?.sync_all()?;
        }
        std::fs::File::open(state)?.sync_all()?;
        #[cfg(unix)] { use std::os::unix::fs::PermissionsExt;
            for path in [&root, &dir, &archive, &quarantine] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
                std::fs::File::open(path)?.sync_all()?;
            } }
        Ok(Self { counters: WriterCounters::default(), writes: tokio::sync::Semaphore::new(super::writer::PUBLISH_CONCURRENCY), next_owner_call: tokio::sync::Mutex::new(tokio::time::Instant::now()), owner_call_interval: Duration::from_millis(50), origin: origin.trim_end_matches('/').into(), tenant: tenant.into(), cell: cell.into(),
            bucket: bucket.into(), permission: RwLock::new(permission),
            tls: OwnerTlsClient::new(origin, ca, Duration::from_secs(30))?, dir, archive, quarantine, gate: Default::default(),
            keys: Default::default(), needs_replay: std::sync::atomic::AtomicBool::new(true),
            unavailable_retry_window: OWNER_UNAVAILABLE_RETRY_WINDOW, lane: Default::default(),
            authorizer: Default::default(), batch: Default::default(), coalesce_window: lanes::COALESCE_WINDOW,
            completion_hold: lanes::COMPLETION_HOLD_MAX,
            #[cfg(test)] synchronous_completion: false })
    }
    /// Match the existing owner admission envelope without changing contract
    /// EPS. Reserve 21.875% for signing/control traffic and retries elsewhere.
    /// Higher-volume tenants retain their proportionally larger budget.
    pub fn with_ingest_eps(mut self, eps: f64) -> Result<Self> {
        ensure!(eps.is_finite() && (0.0..=1_000_000.0).contains(&eps), "invalid native writer EPS");
        let requests_per_minute = ((eps * 60.0 / 500.0).ceil() * 8.0).max(3072.0);
        // Authorize performs reserve+verify; complete performs complete+register.
        // Pace both as two control calls conservatively: reserve/verify/complete
        // charge the tenant bucket; registration charges the shared global bucket.
        self.owner_call_interval = Duration::from_secs_f64(120.0 / (requests_per_minute * (2400.0 / 3072.0)));
        Ok(self)
    }
    /// Process-local attempts and successful replies. Retried HTTP requests
    /// count separately; counters include failures and never reset on a tick.
    pub fn diagnostics(&self) -> Value {
        use std::sync::atomic::Ordering::Relaxed;
        let c = &self.counters;
        json!({"replay_started_total": c.replay_started.load(Relaxed), "replay_completed_total": c.replay_completed.load(Relaxed),
            "authorize_started_total": c.authorize_started.load(Relaxed), "authorize_completed_total": c.authorize_completed.load(Relaxed),
            "complete_started_total": c.complete_started.load(Relaxed), "complete_completed_total": c.complete_completed.load(Relaxed),
            "put_started_total": c.put_started.load(Relaxed), "put_completed_total": c.put_completed.load(Relaxed),
            "authorize_batch_started_total": c.authorize_batch_started.load(Relaxed),
            "authorize_batch_completed_total": c.authorize_batch_completed.load(Relaxed),
            "authorize_batch_objects_total": c.authorize_batch_objects.load(Relaxed),
            "complete_batch_started_total": c.complete_batch_started.load(Relaxed),
            "complete_batch_completed_total": c.complete_batch_completed.load(Relaxed),
            "complete_batch_objects_total": c.complete_batch_objects.load(Relaxed),
            "batch_fallbacks_total": c.batch_fallbacks.load(Relaxed),
            "completion_deferred_total": c.completion_deferred.load(Relaxed),
            "expired_intent_renewed_total": c.expired_renewed.load(Relaxed),
            "expired_intent_abandoned_total": c.expired_abandoned.load(Relaxed),
            "completion_outstanding": self.lane.outstanding(),
            "batch_routes": self.batch.diagnostics(),
            "timings": c.timings.snapshot()})
    }
    pub(super) fn put_started(&self) -> super::timing::ElapsedGuard {
        self.counters.put_started.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.counters.timings.start("put")
    }
    pub(crate) fn put_completed(&self) { self.counters.put_completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed); }

    pub fn check_store_binding(&self, prefix: &str, location: &super::s3_store::S3Location) -> Result<()> {
        ensure!(prefix == format!("lake/parts/v1/tenant={}/", self.tenant) && location.bucket == self.bucket && location.prefix.is_empty(), "native store binding differs");
        Ok(())
    }
    pub fn replace_permission(&self, permission: WritePermission) -> Result<()> {
        permission.validate(&self.tenant, &self.cell)?;
        ensure!(permission.tenant_key == self.permission.read().expect("write permission").tenant_key,
            "native writer logical tenant changed");
        self.tls.reload_ca()?;
        *self.permission.write().expect("write permission") = permission;
        Ok(())
    }
    /// Exclusive: no native write is in flight while this is held.
    pub async fn lock(&self) -> tokio::sync::RwLockWriteGuard<'_, ()> { self.gate.write().await }
    /// Begin one write of `key`: replay the journal first when a previous
    /// write failed (or nothing has replayed since open), then hold the gate
    /// shared and the key exclusively.
    pub async fn write_guard(&self, key: &str) -> Result<WriteGuard<'_>> {
        use std::sync::atomic::Ordering;
        if self.needs_replay.load(Ordering::Acquire) {
            let _exclusive = self.lock().await;
            if self.needs_replay.swap(false, Ordering::AcqRel) {
                if let Err(error) = self.replay_pending_locked().await {
                    self.needs_replay.store(true, Ordering::Release);
                    return Err(error);
                }
            }
        }
        let _wait = self.counters.timings.start("write_slot_wait");
        let permit = self.writes.acquire().await.context("native write envelope closed")?;
        drop(_wait);
        let gate = self.gate.read().await;
        let lock = self.keys.lock().expect("native key locks").entry(key.to_string()).or_default().clone();
        let key_guard = lock.lock_owned().await;
        Ok(WriteGuard { _permit: permit, _gate: gate, _key: key_guard, key: key.to_string(), writer: self })
    }
    /// A write failed after it may have journaled an intent: replay before
    /// the next one.
    pub fn mark_needs_replay(&self) {
        self.needs_replay.store(true, std::sync::atomic::Ordering::Release);
    }
    #[cfg(test)]
    pub(crate) fn with_unavailable_retry_window(mut self, window: Duration) -> Self {
        self.unavailable_retry_window = window;
        self
    }
    /// A wider gathering window, so a test's concurrent writes are
    /// deterministically one batch.
    #[cfg(test)]
    pub(crate) fn with_coalesce_window(mut self, window: Duration) -> Self {
        self.coalesce_window = window;
        self
    }
    /// NAN-4713: the write-behind completion hold cap.
    #[cfg(test)]
    pub(crate) fn with_completion_hold(mut self, hold: Duration) -> Self {
        self.completion_hold = hold;
        self
    }
    /// The pre-NAN-4592 write path: every completion on its own write.
    #[cfg(test)]
    pub(crate) fn with_synchronous_completion(mut self) -> Self {
        self.synchronous_completion = true;
        self
    }
    /// Waits until every write-behind completion has settled.
    #[cfg(test)]
    pub(crate) async fn write_behind_idle_for_tests(&self) {
        self.lane.idle().await;
    }
    /// One owner call, retried within [`OWNER_UNAVAILABLE_RETRY_WINDOW`] while
    /// the owner answers 502/503/504. Any other refusal, a transport error or
    /// an exhausted window returns at once. The permission is re-read on every
    /// attempt, so a rotation during the window is picked up.
    async fn post(&self, route: &str, body: &Value) -> Result<Value> {
        self.post_paced(route, body, 1, OWNER_RESPONSE_CAP).await
    }
    /// [`Self::post`] for a call that carries `slots` objects: it takes
    /// `slots` places in the owner pacing budget (each object still costs the
    /// owner its own control calls) and may answer up to `cap` bytes.
    async fn post_paced(&self, route: &str, body: &Value, slots: u32, cap: usize) -> Result<Value> {
        let started = std::time::Instant::now();
        let mut attempt = 0_u32;
        loop {
            match self.post_once(route, body, slots, cap).await {
                Err(error) => {
                    let Some(status) = error.downcast_ref::<OwnerRefused>().map(|refused| refused.status)
                        .filter(|status| owner_unavailable(*status)) else { return Err(error) };
                    attempt += 1;
                    let Some(delay) = owner_unavailable_delay(attempt, started.elapsed(), self.unavailable_retry_window) else {
                        tracing::warn!(route, status, attempts = attempt, waited_ms = started.elapsed().as_millis() as u64,
                            "native writer owner still unavailable after the retry window");
                        return Err(error);
                    };
                    tracing::info!(route, status, attempt, delay_ms = delay.as_millis() as u64,
                        "native writer owner unavailable; retrying");
                    tokio::time::sleep(delay).await;
                }
                done => {
                    if attempt > 0 {
                        tracing::info!(route, attempts = attempt + 1, waited_ms = started.elapsed().as_millis() as u64,
                            "native writer owner recovered within the retry window");
                    }
                    return done;
                }
            }
        }
    }
    async fn pace_owner_call(&self) {
        self.pace_owner_calls(1).await
    }
    /// One place per object in the shared budget: a batch of `slots` objects
    /// moves the next call `slots` intervals out, never bursting past it.
    async fn pace_owner_calls(&self, slots: u32) {
        let _timing = self.counters.timings.start("pacer_wait");
        let mut next = self.next_owner_call.lock().await;
        tokio::time::sleep_until(*next).await;
        *next = tokio::time::Instant::now() + self.owner_call_interval.saturating_mul(slots.max(1));
    }
    async fn post_once(&self, route: &str, body: &Value, slots: u32, cap: usize) -> Result<Value> {
        use std::sync::atomic::Ordering::Relaxed;
        self.pace_owner_calls(slots).await;
        let c = &self.counters;
        let (label, started, completed) = if route == NATIVE_AUTHORIZE_BATCH_PATH {
            c.authorize_batch_objects.fetch_add(u64::from(slots), Relaxed);
            ("authorize_batch", &c.authorize_batch_started, &c.authorize_batch_completed)
        } else if route == NATIVE_COMPLETE_BATCH_PATH {
            c.complete_batch_objects.fetch_add(u64::from(slots), Relaxed);
            ("complete_batch", &c.complete_batch_started, &c.complete_batch_completed)
        } else if route.ends_with(":authorize") {
            ("authorize", &c.authorize_started, &c.authorize_completed)
        } else { ("complete", &c.complete_started, &c.complete_completed) };
        let _timing = c.timings.start(label);
        started.fetch_add(1, Relaxed);
        let token = { let permission = self.permission.read().expect("write permission");
            permission.validate(&self.tenant, &self.cell)?; zeroize::Zeroizing::new(permission.token.clone()) };
        let bearer = zeroize::Zeroizing::new(format!("Bearer {}", token.as_str()));
        let mut authorization = reqwest::header::HeaderValue::from_str(bearer.as_str())?;
        authorization.set_sensitive(true);
        let response = self.tls.client().post(format!("{}{route}", self.origin))
            .header(reqwest::header::AUTHORIZATION, authorization).json(body).send().await?;
        if !response.status().is_success() {
            return Err(OwnerRefused { status: response.status().as_u16() }.into());
        }
        use futures::TryStreamExt;
        let mut stream = response.bytes_stream(); let mut bytes = Vec::new();
        while let Some(chunk) = stream.try_next().await? {
            ensure!(bytes.len() + chunk.len() <= cap, "native writer owner response exceeds cap");
            bytes.extend_from_slice(&chunk);
        }
        let value = serde_json::from_slice(&bytes)?;
        completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(value)
    }
    fn save(&self, path: &Path, intent: &Intent) -> Result<()> {
        use std::io::Write;
        let parent = path.parent().context("native journal parent missing")?;
        let mut temp = tempfile::NamedTempFile::new_in(parent)?;
        temp.write_all(&serde_json::to_vec(intent)?)?; temp.as_file().sync_all()?;
        temp.persist(path).map_err(|e| e.error)?;
        std::fs::File::open(parent)?.sync_all()?;
        Ok(())
    }
    fn load(path: &Path) -> Result<Option<Intent>> {
        use std::io::Read;
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK); }
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        ensure!(file.metadata()?.is_file(), "native receipt requires regular files");
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 65536, "native receipt intent exceeds cap");
        Ok(Some(serde_json::from_slice(&bytes)?))
    }
    fn validate_put_evidence(intent: &Intent) -> Result<()> {
        let etag = intent.object.as_ref().and_then(|object| object["etag"].as_str())
            .context("native PUT outcome unresolved; strong ETag missing")?;
        ensure!(etag.len() >= 3 && etag.len() <= 128 && etag.starts_with('"') && etag.ends_with('"')
            && !etag[1..etag.len()-1].chars().any(|c| c == '"' || c.is_control()),
            "native PUT ETag is not strong");
        Ok(())
    }
    fn validate_registered(intent: &Intent) -> Result<()> {
        Self::validate_put_evidence(intent)?;
        let receipt = intent.registered.as_ref().context("native registered acknowledgement missing")?;
        ensure!(intent.object.is_some() && receipt["schema_version"] == 1 && receipt["status"] == "registered"
            && receipt["request_id"] == intent.request["request_id"]
            && receipt["deletion_unit_id"] == intent.identity["deletion_unit_id"]
            && receipt["completion_receipt_id"].as_str().is_some_and(|v| uuid::Uuid::parse_str(v).is_ok())
            && receipt["artifact_id"].as_str().is_some_and(|v| uuid::Uuid::parse_str(v).is_ok())
            && digest(&receipt["completion_receipt_sha256"]), "native writer completion receipt differs");
        Ok(())
    }
    fn archive_registered(&self, path: &Path, intent: &Intent) -> Result<()> {
        Self::validate_registered(intent)?;
        let destination = self.archive.join(path.file_name().context("native intent name missing")?);
        // A saved acknowledgement is replayable locally even if the move did not happen.
        std::fs::rename(path, destination)?;
        // Persist the destination before persisting removal from pending.
        std::fs::File::open(&self.archive)?.sync_all()?;
        std::fs::File::open(&self.dir)?.sync_all()?;
        Ok(())
    }
    /// Replay only saved successful PUT evidence, under the same write serialization.
    pub async fn replay_pending(&self) -> Result<()> {
        let _guard = self.lock().await;
        let replayed = self.replay_pending_locked().await;
        if replayed.is_ok() {
            self.needs_replay.store(false, std::sync::atomic::Ordering::Release);
        }
        replayed
    }
    pub(crate) async fn replay_pending_locked(&self) -> Result<()> {
        self.counters.replay_started.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tokio::time::timeout(Duration::from_secs(60), async {
            self.permission.read().expect("write permission").validate(&self.tenant, &self.cell)?;
            // NAN-4592: a write-behind completion may still be running on a
            // journaled intent (writes are excluded, so no new one starts).
            // Let it settle first so one intent is never completed twice.
            self.lane.idle().await;
            let mut count = 0usize;
            let mut total = 0u64;
            for entry in std::fs::read_dir(&self.dir)? {
                let entry = entry?;
                count += 1;
                ensure!(count <= 1024, "native receipt replay entry cap exceeded");
                let path = entry.path();
                ensure!(entry.file_type()?.is_file(), "native receipt replay requires regular files");
                // Atomic-save temporary files are not completion records.
                if path.extension().and_then(|v| v.to_str()) != Some("json") { continue; }
                let intent = Self::load(&path)?.context("native pending intent disappeared")?;
                total += std::fs::symlink_metadata(&path)?.len();
                ensure!(total <= 8 * 1024 * 1024, "native receipt replay byte cap exceeded");
                if intent.registered.is_some() {
                    self.archive_registered(&path, &intent)?;
                    continue;
                }
                if intent.object.is_none() { continue; }
                ensure!(intent.request["tenant_id"] == self.permission.read().expect("write permission").tenant_key
                    && intent.request["object_bucket"] == self.bucket
                    && intent.identity["tenant_uuid"] == self.tenant,
                    "native receipt replay binding differs");
                match self.complete_intent(&path, intent).await {
                    // NAN-4676: an expired part-object intent the owner would
                    // not renew is quarantined (evidence kept) and no longer
                    // pending: its unpublished part is rebuilt under a new part
                    // ID, so it must not hold every later write hostage.
                    Err(error) if error.downcast_ref::<NativePutUnresolved>().is_some() && !path.exists() => {
                        tracing::warn!(error = %format!("{error:#}"),
                            "native replay quarantined an expired part-object intent; its part is rebuilt");
                    }
                    other => other?,
                }
            }
            Ok::<(), anyhow::Error>(())
        }).await.context("native receipt replay time cap exceeded")??;
        // Every journaled completion (a failed write-behind one included)
        // is registered now: part-log writes may land again.
        self.lane.clear_failure();
        self.counters.replay_completed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
    /// The deterministic owner request for one object write (its
    /// `request_id` is the digest of everything else).
    fn request_for(&self, key: &str, sha: &str, bytes: u64, hints: &WriteHints) -> Result<Value> {
        let tenant_key = { self.permission.read().expect("write permission").tenant_key.clone() };
        let stamp = |ms| chrono::DateTime::<Utc>::from_timestamp_millis(ms)
            .map(|v| v.to_rfc3339_opts(SecondsFormat::Millis, true)).context("invalid native event time");
        ensure!(hints.min_time_ms <= hints.max_time_ms, "native event bounds reversed");
        let family = if key.contains("/log/checkpoints/") { "lake_part_log_checkpoint" }
            else if key.contains("/log/entries/") { "lake_part_log_entry" } else { "lake_part_file" };
        let class = if family == "lake_part_log_entry" { "lake_part_log" } else { "lake_part" };
        ensure!((hints.class == crate::parts::part_log::WriterClass::LakePartLog) == (class == "lake_part_log"),
            "native writer class differs from key");
        let hour = Utc.timestamp_opt(i64::from(hints.event_hour) * 3600, 0).single().context("invalid native hour")?;
        let mut request = json!({"schema_version":1,"tenant_id":tenant_key,"object_bucket":self.bucket,
            "object_key":key,"writer_class":class,"key_family":family,
            "event_hour":hour.to_rfc3339_opts(SecondsFormat::Secs,true),
            "min_event_time":stamp(hints.min_time_ms)?,"max_event_time":stamp(hints.max_time_ms)?,
            "content_length":bytes,"content_sha256":sha});
        let request_id = format!("writer_{}", hex::encode(Sha256::digest(serde_json::to_vec(&request)?)));
        request["request_id"] = json!(request_id);
        Ok(request)
    }
    /// NAN-4444: the journaled attempt of exactly this write whose PUT outcome
    /// is unresolved (authorized, no PUT evidence). The caller has read the
    /// object back and verified it holds these bytes; [`Self::finish`] with
    /// the stored object's strong ETag then completes it, and the owner still
    /// HEADs the provider (ETag, length, SHA-256) before registering.
    /// `None` when no such unresolved attempt is journaled.
    pub fn unresolved_attempt(&self, key: &str, sha: &str, bytes: u64, hints: &WriteHints) -> Result<Option<NativeAttempt>> {
        let request = self.request_for(key, sha, bytes, hints)?;
        let request_id = request["request_id"].as_str().context("native request id missing")?;
        let path = self.dir.join(format!("{request_id}.json"));
        let Some(intent) = Self::load(&path)? else { return Ok(None) };
        ensure!(intent.request == request, "native pending request differs");
        if intent.object.is_some() || intent.registered.is_some() {
            return Ok(None);
        }
        Ok(Some(NativeAttempt { path, request, identity: intent.identity }))
    }
    pub async fn begin(&self, key: &str, sha: &str, bytes: u64, hints: &WriteHints) -> Result<Option<NativeAttempt>> {
        self.begin_with(key, sha, bytes, hints, None).await
    }
    /// [`Self::begin`] for the store's write path (NAN-4592): a part object
    /// authorizes together with the part objects written beside it (one
    /// `authorize-native-batch` call when the owner serves it).
    pub async fn begin_coalesced(self: &std::sync::Arc<Self>, key: &str, sha: &str, bytes: u64, hints: &WriteHints)
        -> Result<Option<NativeAttempt>> {
        self.begin_with(key, sha, bytes, hints, Some(self)).await
    }
    async fn begin_with(&self, key: &str, sha: &str, bytes: u64, hints: &WriteHints,
        coalesce: Option<&std::sync::Arc<Self>>) -> Result<Option<NativeAttempt>> {
        let request = self.request_for(key, sha, bytes, hints)?;
        let request_id = request["request_id"].as_str().context("native request id missing")?.to_string();
        let family = request["key_family"].as_str().context("native key family missing")?.to_string();
        // A write-behind completion of this exact request may still be
        // running (a retried publication): let it land before reading the
        // journal, so the intent is never completed twice.
        self.lane.settled(&request_id).await;
        let path = self.dir.join(format!("{request_id}.json"));
        let archived = self.archive.join(format!("{request_id}.json"));
        if let Some(intent) = Self::load(&archived)? {
            ensure!(intent.request == request, "native registered request differs");
            Self::validate_registered(&intent)?;
            return Ok(None);
        }
        if let Some(intent) = Self::load(&path)? {
            ensure!(intent.request == request, "native pending request differs");
            if intent.registered.is_some() { self.archive_registered(&path, &intent)?; return Ok(None); }
            if intent.object.is_none() {
                return Err(NativePutUnresolved { key: key.to_string() }.into());
            }
            self.complete_intent(&path, intent).await?;
            return Ok(None);
        }
        // NAN-4676: the owner refused this exact write after its window
        // closed and would not renew it. Its bytes may sit under the key, but
        // no receipt can ever be issued for this request: report the outcome
        // unresolved so the enclosing unpublished part is rebuilt under a
        // fresh part ID (never re-authorized, never re-PUT).
        if self.quarantine.join(format!("{request_id}.abandoned.json")).exists() {
            return Err(NativePutUnresolved { key: key.to_string() }.into());
        }
        let identity = if family == lanes::DEFERRABLE_FAMILY {
            match coalesce {
                Some(writer) => lanes::AuthorizeCoalescer::authorize(writer, &request).await?,
                None => self.post(AUTHORIZE_PATH, &request).await?,
            }
        } else {
            // NAN-4592: a part-log entry or checkpoint makes the parts it
            // names live. It lands only after every write-behind part
            // completion begun before it is registered (or the write fails
            // closed). The wait overlaps its own authorization.
            let (identity, settled) = tokio::join!(self.post(AUTHORIZE_PATH, &request), async {
                let _timing = self.counters.timings.start("completion_barrier_wait");
                self.lane.barrier().await
            });
            match identity {
                Ok(identity) => { settled?; identity }
                // NAN-3181: a 409 for a part-log entry/checkpoint key is an
                // earlier attempt's open reservation of the same sequence number
                // (a dead process, a failed PUT), never a commit. Typed so the
                // part log retries it instead of treating it as a fence.
                Err(error) if error.downcast_ref::<OwnerRefused>().is_some_and(|refused| refused.status == 409) =>
                    return Err(crate::parts::part_log::LogKeyHeld { key: key.to_string() }.into()),
                Err(error) => return Err(error),
            }
        };
        self.validate_identity(&request, &identity, key, sha, bytes)?;
        self.save(&path, &Intent { request: request.clone(), identity: identity.clone(), object: None, registered: None })?;
        Ok(Some(NativeAttempt { path, request, identity }))
    }
    /// The owner's identity for `request` binds exactly this tenant, bucket,
    /// key, bytes, class and event bounds, and is still inside its window.
    fn validate_identity(&self, request: &Value, identity: &Value, key: &str, sha: &str, bytes: u64) -> Result<()> {
        let expires = chrono::DateTime::parse_from_rfc3339(identity["authorization_expires_at"].as_str()
            .context("native authorization expiry missing")?)?;
        ensure!(expires > Utc::now() && digest(&identity["owner_reservation_sha256"]),
            "native authorization expired or authority digest invalid");
        ensure!(identity["schema_version"] == 3 && identity["request_id"] == request["request_id"]
            && identity["tenant_uuid"] == self.tenant && identity["tenant_id"] == request["tenant_id"]
            && identity["bucket"] == self.bucket && identity["key"] == key
            && identity["sha256"] == sha && identity["content_length"] == bytes
            && identity["writer_class"] == request["writer_class"] && identity["key_family"] == request["key_family"]
            && same_time(&identity["event_hour"], &request["event_hour"])
            && same_time(&identity["min_event_time"], &request["min_event_time"]) && same_time(&identity["max_event_time"], &request["max_event_time"]),
            "native owner authorization identity differs");
        Ok(())
    }
    async fn complete_intent(&self, path: &Path, intent: Intent) -> Result<()> {
        Self::validate_put_evidence(&intent)?;
        let refusal = match self.post(COMPLETE_PATH, &Self::completion_body(&intent)).await {
            Ok(receipt) => return self.register_receipt(path, intent, receipt),
            Err(error) => error,
        };
        // NAN-4676: the owner refuses every completion past the identity's
        // completion deadline (409 "completion differs from the stable
        // owner-authorized writer"), so a replay of that exact body can never
        // succeed. FP-INC-1027: the control DB was read-only for 5 h, every
        // completion answered 503 until the 70-minute window closed, and the
        // replay at cell start then crash-looped ingest on the 409.
        let expired = refusal.downcast_ref::<OwnerRefused>().is_some_and(|refused| refused.status == 409)
            && completion_window_closed(&intent.identity);
        if !expired {
            return Err(refusal);
        }
        self.renew_expired_intent(path, intent, &refusal).await
    }
    fn register_receipt(&self, path: &Path, mut intent: Intent, receipt: Value) -> Result<()> {
        intent.registered = Some(receipt);
        Self::validate_registered(&intent)?;
        self.save(path, &intent)?;
        self.archive_registered(path, &intent)
    }
    /// NAN-4676: complete an intent whose completion window closed before the
    /// owner registered it. The PUT landed (its strong ETag is journaled), so
    /// the same request — same key, bytes and digest — is renewed by the
    /// owner's append-only stale-attempt renewal (`stale_recovery: "renew"`,
    /// migration 9000123: a fresh window, an advanced attempt revision and
    /// stable identity) and the journaled PUT evidence is completed under that
    /// fresh owner-authorized identity. The owner still HEADs the provider
    /// (ETag, length, SHA-256) before registering. The refused intent is
    /// quarantined first, so its identity, PUT evidence and the refusal stay
    /// on disk. Nothing is re-PUT and the key never changes, so the object is
    /// registered once (no duplicate rows) and no landed byte is dropped.
    ///
    /// When the owner refuses the renewal itself (e.g. its renewal limit), a
    /// part object (`lake_part_file`: a random part ID, never named by the log
    /// before it is registered) is abandoned: the intent leaves the pending
    /// journal for quarantine and the write reports [`NativePutUnresolved`],
    /// so the enclosing unpublished part is rebuilt under a new part ID. A
    /// part-log entry or checkpoint (a deterministic key the log may already
    /// name) is never abandoned: it stays pending and fails closed.
    async fn renew_expired_intent(&self, path: &Path, intent: Intent, refusal: &anyhow::Error) -> Result<()> {
        let request = &intent.request;
        let request_id = request["request_id"].as_str().context("native request id missing")?.to_string();
        let key = request["object_key"].as_str().context("native object key missing")?.to_string();
        let sha = request["content_sha256"].as_str().context("native content digest missing")?.to_string();
        let bytes = request["content_length"].as_u64().context("native content length missing")?;
        let deferrable = request["key_family"] == lanes::DEFERRABLE_FAMILY;
        // One superseded record per refused owner attempt (its reservation
        // digest), never one per retry: while the owner cannot renew (e.g. a
        // control outage answering 503), every replay comes back here, and a
        // timestamped name would grow the quarantine without bound.
        let attempt = intent.identity["owner_reservation_sha256"].as_str()
            .filter(|_| digest(&intent.identity["owner_reservation_sha256"]))
            .context("native refused identity authority digest invalid")?;
        let superseded = format!("{request_id}.superseded.{attempt}.json");
        if !self.quarantine.join(&superseded).exists() {
            self.quarantine_intent(&superseded, &intent, refusal)?;
        }
        tracing::warn!(key = %key, request_id = %request_id,
            completion_deadline_at = %intent.identity["completion_deadline_at"],
            "native writer intent expired before the owner registered it; renewing the exact request");
        let mut renewal = request.clone();
        renewal["stale_recovery"] = json!("renew");
        let renewed = self.post(AUTHORIZE_PATH, &renewal).await.and_then(|identity| {
            self.validate_identity(request, &identity, &key, &sha, bytes)?;
            ensure!(!completion_window_closed(&identity), "native stale-attempt renewal did not open a fresh window");
            Ok(identity)
        });
        let identity = match renewed {
            Ok(identity) => identity,
            Err(error) if deferrable && owner_refused_permanently(&error) => {
                self.quarantine_intent(&format!("{request_id}.abandoned.json"), &intent, &error)?;
                std::fs::remove_file(path)?;
                std::fs::File::open(&self.dir)?.sync_all()?;
                self.counters.expired_abandoned.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                tracing::error!(key = %key, request_id = %request_id, error = %format!("{error:#}"),
                    "owner refused to renew an expired part-object intent; quarantined, its part is rebuilt under a new part ID");
                return Err(NativePutUnresolved { key }.into());
            }
            Err(error) => return Err(error.context("renew expired native writer intent")),
        };
        let mut object = intent.object.clone().context("native PUT evidence missing")?;
        object["writer_authority_sha256"] = identity["owner_reservation_sha256"].clone();
        let renewed = Intent { request: intent.request, identity, object: Some(object), registered: None };
        // The renewed intent replaces the pending one (the refused one is in
        // quarantine): a crash from here replays the renewed identity.
        self.save(path, &renewed)?;
        let receipt = self.post(COMPLETE_PATH, &Self::completion_body(&renewed)).await
            .context("complete renewed native writer intent")?;
        self.register_receipt(path, renewed, receipt)?;
        self.counters.expired_renewed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::warn!(key = %key, request_id = %request_id, "expired native writer intent completed under a renewed owner identity");
        Ok(())
    }
    /// Durably record a refused intent and the refusal (no secret: the
    /// journal never holds the bearer).
    fn quarantine_intent(&self, name: &str, intent: &Intent, refusal: &anyhow::Error) -> Result<()> {
        use std::io::Write;
        let status = refusal.chain().find_map(|cause| cause.downcast_ref::<OwnerRefused>().map(|refused| refused.status));
        let record = json!({"schema_version":1,"quarantined_at":Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            "owner_status":status,"refusal":format!("{refusal:#}"),"intent":intent});
        let mut temp = tempfile::NamedTempFile::new_in(&self.quarantine)?;
        temp.write_all(&serde_json::to_vec(&record)?)?; temp.as_file().sync_all()?;
        temp.persist(self.quarantine.join(name)).map_err(|e| e.error)?;
        std::fs::File::open(&self.quarantine)?.sync_all()?;
        Ok(())
    }
    /// The exact single-route completion body of a journaled intent.
    fn completion_body(intent: &Intent) -> Value {
        json!({"schema_version":1,"request":intent.request,"identity":intent.identity,"object":intent.object})
    }
    /// Journal the PUT evidence of `attempt` (its strong ETag) durably.
    fn record_put(&self, attempt: NativeAttempt, etag: &str) -> Result<(PathBuf, Intent)> {
        ensure!(etag.len() >= 3 && etag.len() <= 128 && etag.starts_with('"') && etag.ends_with('"')
            && !etag[1..etag.len()-1].chars().any(|c| c == '"' || c.is_control()), "native PUT ETag is not strong");
        let authority = attempt.identity["owner_reservation_sha256"].as_str().context("native signed authority digest missing")?;
        let object = json!({"version_id":format!("r2-etag-sha256:{}",hex::encode(Sha256::digest(etag.as_bytes()))),
            "etag":etag,"size_bytes":attempt.request["content_length"],"sha256":attempt.request["content_sha256"],
            "writer_authority_sha256":authority});
        let intent = Intent { request: attempt.request, identity: attempt.identity, object: Some(object), registered: None };
        self.save(&attempt.path, &intent)?;
        Ok((attempt.path, intent))
    }
    pub async fn finish(&self, attempt: NativeAttempt, etag: &str) -> Result<()> {
        let (path, intent) = self.record_put(attempt, etag)?;
        self.complete_intent(&path, intent).await
    }
    /// [`Self::finish`] for the store's write path (NAN-4592). A part object
    /// (`parts/…`: data files, provenance, staged sign payloads) returns as
    /// soon as its PUT evidence is journaled; its owner completion is
    /// write-behind, coalesced with its neighbours, and the next part-log
    /// entry or checkpoint waits for it (see [`Self::begin_with`]). So no
    /// part is ever named by the log before its object is registered, and a
    /// failed completion fails the next log write closed until the journal
    /// replays it. Log entries and checkpoints complete here, as before:
    /// the part-log index feed counts an append receipted only once its
    /// completion returned (`lake_part_gc::index::ReceiptedAppends`).
    pub async fn finish_deferred(self: &std::sync::Arc<Self>, attempt: NativeAttempt, etag: &str) -> Result<()> {
        let deferrable = attempt.request["key_family"] == lanes::DEFERRABLE_FAMILY;
        let (path, intent) = self.record_put(attempt, etag)?;
        #[cfg(test)]
        if self.synchronous_completion {
            return self.complete_intent(&path, intent).await;
        }
        if !deferrable {
            return self.complete_intent(&path, intent).await;
        }
        self.counters.completion_deferred.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.lane.enqueue(self, path, intent);
        Ok(())
    }
}

#[cfg(test)]
#[path = "native_expired_intent_tests.rs"]
mod expired_intent_tests;

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{routing::post, Json, Router};
    use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};

    async fn fixture(fail_first: bool) -> (NativePartWriter, tempfile::TempDir, Arc<AtomicUsize>, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        fixture_for(fail_first, "tenant-uuid", "bucket").await
    }
    pub(crate) async fn fixture_for(fail_first: bool, tenant: &str, bucket: &str) -> (NativePartWriter, tempfile::TempDir, Arc<AtomicUsize>, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let tenant = tenant.to_string();
        let owner_tenant = tenant.clone();
        let authorizations = Arc::new(AtomicUsize::new(0));
        let completions = Arc::new(AtomicUsize::new(0));
        let a = authorizations.clone();
        let c = completions.clone();
        let saved_completion = Arc::new(std::sync::Mutex::new(None::<Value>));
        let router = Router::new()
            .route("/internal/v1/enterprise-shared/lake-writers:authorize", post(move |Json(request): Json<Value>| {
                let a = a.clone();
                let tenant = owner_tenant.clone();
                async move {
                    a.fetch_add(1, Ordering::SeqCst);
                    let mut identity = request.clone();
                    identity["schema_version"] = json!(3);
                    identity["tenant_uuid"] = json!(tenant);
                    identity["bucket"] = request["object_bucket"].clone();
                    identity["key"] = request["object_key"].clone();
                    identity["sha256"] = request["content_sha256"].clone();
                    identity["authorization_expires_at"] = json!((Utc::now() + chrono::Duration::minutes(4)).to_rfc3339());
                    identity["owner_reservation_sha256"] = json!("a".repeat(64));
                    identity["deletion_unit_id"] = json!("00000000-0000-4000-8000-000000000001");
                    Json(identity)
                }
            }))
            .route("/internal/v1/enterprise-shared/lake-writers:complete", post(move |Json(body): Json<Value>| {
                let c = c.clone();
                let saved_completion = saved_completion.clone();
                async move {
                    let call = c.fetch_add(1, Ordering::SeqCst);
                    if fail_first {
                        let mut saved = saved_completion.lock().unwrap();
                        if let Some(previous) = saved.as_ref() { assert_eq!(previous, &body, "replay must preserve the entire saved completion"); }
                        else { *saved = Some(body.clone()); }
                    }
                    assert_eq!(body["object"]["writer_authority_sha256"], body["identity"]["owner_reservation_sha256"]);
                    assert_eq!(body["object"]["etag"], "\"actual-put-etag\"");
                    if fail_first && call == 0 {
                        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
                    }
                    (axum::http::StatusCode::OK, Json(json!({"schema_version":1,"status":"registered",
                        "request_id":body["request"]["request_id"], "deletion_unit_id":body["identity"]["deletion_unit_id"],
                        "completion_receipt_id":"00000000-0000-4000-8000-000000000002",
                        "artifact_id":"00000000-0000-4000-8000-000000000003", "completion_receipt_sha256":"b".repeat(64)})))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap();
        let permission: WritePermission = serde_json::from_value(json!({"token":"test-only-token",
            "audience":"owner","scope":"lake-parts:write","tenantId":tenant,"tenantKey":"logical-tenant",
            "cellId":"cell","principalId":"principal","role":"ingest",
            "expiresAt":(Utc::now()+chrono::Duration::minutes(5)).to_rfc3339()})).unwrap();
        let mut writer = NativePartWriter::new(&origin, None, &tenant, "cell", bucket, permission, dir.path()).unwrap();
        if fail_first {
            // The first completion's failure must reach the caller, not be
            // absorbed by the unavailable-owner retry.
            writer = writer.with_unavailable_retry_window(Duration::ZERO);
        }
        (writer, dir, authorizations, completions, task)
    }

    /// An owner that answers 503 to the first `unavailable` authorize calls.
    async fn unavailable_owner(unavailable: usize, window: Duration)
        -> (NativePartWriter, tempfile::TempDir, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let router = Router::new()
            .route("/internal/v1/enterprise-shared/lake-writers:authorize", post(move |Json(request): Json<Value>| {
                let counted = counted.clone();
                async move {
                    if counted.fetch_add(1, Ordering::SeqCst) < unavailable {
                        return (axum::http::StatusCode::SERVICE_UNAVAILABLE, Json(json!({"error":"writer_owner_unavailable"})));
                    }
                    let mut identity = request.clone();
                    identity["schema_version"] = json!(3);
                    identity["tenant_uuid"] = json!("tenant-uuid");
                    identity["bucket"] = request["object_bucket"].clone();
                    identity["key"] = request["object_key"].clone();
                    identity["sha256"] = request["content_sha256"].clone();
                    identity["authorization_expires_at"] = json!((Utc::now() + chrono::Duration::minutes(4)).to_rfc3339());
                    identity["owner_reservation_sha256"] = json!("a".repeat(64));
                    identity["deletion_unit_id"] = json!("00000000-0000-4000-8000-000000000001");
                    (axum::http::StatusCode::OK, Json(identity))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap();
        let permission: WritePermission = serde_json::from_value(json!({"token":"test-only-token",
            "audience":"owner","scope":"lake-parts:write","tenantId":"tenant-uuid","tenantKey":"logical-tenant",
            "cellId":"cell","principalId":"principal","role":"ingest",
            "expiresAt":(Utc::now()+chrono::Duration::minutes(5)).to_rfc3339()})).unwrap();
        let writer = NativePartWriter::new(&origin, None, "tenant-uuid", "cell", "bucket", permission, dir.path())
            .unwrap().with_unavailable_retry_window(window);
        (writer, dir, calls, task)
    }

    /// NAN-3723: an owner 503 (its control database shedding a lock
    /// conflict during a roll) is retried inside the short window, so the
    /// write succeeds instead of failing the flush and holding ingest.
    #[tokio::test]
    async fn owner_503_is_retried_inside_the_window() {
        let (writer, _dir, calls, task) = unavailable_owner(2, Duration::from_secs(10)).await;
        let attempt = writer.begin("tenant/parts/p/data-00000.parquet", &"c".repeat(64), 7, &hints()).await.unwrap();
        assert!(attempt.is_some(), "the third authorize answers");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
        task.abort();
    }

    /// The window is bounded: an owner that stays unavailable surfaces its
    /// 503 to the caller (whose own tick retry takes over), nothing journaled.
    #[tokio::test]
    async fn owner_503_past_the_window_reaches_the_caller() {
        let (writer, dir, calls, task) = unavailable_owner(usize::MAX, Duration::from_millis(300)).await;
        let started = std::time::Instant::now();
        let error = writer.begin("tenant/parts/p/data-00000.parquet", &"c".repeat(64), 7, &hints()).await.err().unwrap();
        assert_eq!(error.downcast_ref::<OwnerRefused>().map(|refused| refused.status), Some(503));
        assert!(started.elapsed() < Duration::from_secs(2), "bounded by the window");
        // 0 ms, then +250 ms; +500 ms would pass the 300 ms window.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert_eq!(writer.diagnostics()["authorize_started_total"], 2);
        assert_eq!(writer.diagnostics()["authorize_completed_total"], 0);
        let timings = writer.diagnostics();
        assert_eq!(timings["timings"]["authorize"]["finished_total"], 2);
        assert_eq!(timings["timings"]["authorize"]["in_flight"], 0);
        assert_eq!(timings["timings"]["pacer_wait"]["finished_total"], 2);
        assert_eq!(std::fs::read_dir(dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
        task.abort();
    }

    #[tokio::test]
    async fn native_pacing_scales_with_existing_eps_without_inflating_it() {
        let (writer, _dir, _, task) = unavailable_owner(0, Duration::from_secs(10)).await;
        assert_eq!(writer.owner_call_interval, Duration::from_millis(50));
        let writer = writer.with_ingest_eps(15_500.0).unwrap();
        let admitted_rpm = 120.0 / writer.owner_call_interval.as_secs_f64();
        assert!(admitted_rpm > 11_600.0 && admitted_rpm < 11_630.0);
        assert!(writer.with_ingest_eps(f64::NAN).is_err());
        task.abort();
    }

    #[tokio::test]
    async fn owner_calls_share_a_paced_budget_without_idle_bursts() {
        let (writer, _dir, _, task) = unavailable_owner(0, Duration::from_secs(10)).await;
        let started = tokio::time::Instant::now();
        futures::future::join_all((0..9).map(|_| writer.pace_owner_call())).await;
        assert!(started.elapsed() >= Duration::from_millis(400));
        tokio::time::sleep(Duration::from_millis(75)).await;
        let started = tokio::time::Instant::now();
        futures::future::join_all((0..3).map(|_| writer.pace_owner_call())).await;
        assert!(started.elapsed() >= Duration::from_millis(100), "idle time never accumulates burst tokens");
        let timings = writer.diagnostics();
        assert_eq!(timings["timings"]["pacer_wait"]["finished_total"], 12);
        assert_eq!(timings["timings"]["pacer_wait"]["in_flight"], 0);
        assert!(timings["timings"]["pacer_wait"]["elapsed_us_total"].as_u64().unwrap() >= 500_000);
        assert!(timings["timings"]["authorize"].is_null(), "pacer wait is not HTTP latency");
        task.abort();
    }

    #[test]
    fn only_unavailable_statuses_retry_and_the_backoff_is_bounded() {
        assert!(owner_unavailable(503) && owner_unavailable(502) && owner_unavailable(504));
        for status in [400, 401, 403, 404, 409, 412, 429, 500] {
            assert!(!owner_unavailable(status), "{status} is not retried");
        }
        let window = OWNER_UNAVAILABLE_RETRY_WINDOW;
        let mut elapsed = Duration::ZERO;
        let mut delays = Vec::new();
        for attempt in 1.. {
            let Some(delay) = owner_unavailable_delay(attempt, elapsed, window) else { break };
            delays.push(delay);
            elapsed += delay;
        }
        assert_eq!(&delays[..5], &[250, 500, 1000, 2000, 4000].map(Duration::from_millis));
        assert!(delays.iter().all(|delay| *delay <= Duration::from_secs(4)));
        assert!(elapsed <= window && elapsed + Duration::from_secs(4) > window, "uses the window, never passes it");
    }

    fn hints() -> WriteHints {
        WriteHints { class: crate::parts::part_log::WriterClass::LakePart, event_hour: 1, min_time_ms: 3600000, max_time_ms: 3600001 }
    }

    #[tokio::test]
    async fn completion_failure_replays_saved_put_without_reauthorization() {
        let (writer, _dir, a, c, task) = fixture(true).await;
        let sha = "c".repeat(64);
        let log_hints = WriteHints { class: crate::parts::part_log::WriterClass::LakePartLog, ..hints() };
        let attempt = writer.begin("tenant/log/entries/00000000000000000001.json", &sha, 7, &log_hints).await.unwrap().unwrap();
        assert!(writer.finish(attempt, "\"actual-put-etag\"").await.is_err());
        // Reopen the persisted receipt after a process-equivalent client restart.
        let permission = writer.permission.read().unwrap().clone();
        let reopened = NativePartWriter::new(&writer.origin, None, &writer.tenant, &writer.cell,
            &writer.bucket, permission, _dir.path()).unwrap();
        drop(writer);
        let writer = reopened;
        writer.replay_pending().await.unwrap();
        writer.replay_pending().await.unwrap();
        assert_eq!(a.load(Ordering::SeqCst), 1);
        assert_eq!(c.load(Ordering::SeqCst), 2);
        let counters = writer.diagnostics();
        assert_eq!(counters["replay_started_total"], 2);
        assert_eq!(counters["replay_completed_total"], 2);
        assert_eq!(counters["authorize_started_total"], 0);
        assert_eq!(counters["complete_started_total"], 1);
        assert_eq!(counters["complete_completed_total"], 1);
        task.abort();
    }

    /// NAN-3181: an owner 409 on a part-log entry or checkpoint key is an
    /// earlier attempt's open reservation (typed, retried); on a part file
    /// it stays a plain owner refusal.
    #[tokio::test]
    async fn owner_409_on_a_log_key_is_a_held_key_not_a_fence() {
        let router = Router::new().route("/internal/v1/enterprise-shared/lake-writers:authorize",
            post(|| async { (axum::http::StatusCode::CONFLICT, Json(json!({"error":"writer_request_conflict"}))) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap(); });
        let dir = tempfile::tempdir().unwrap();
        let permission: WritePermission = serde_json::from_value(json!({"token":"test-only-token",
            "audience":"owner","scope":"lake-parts:write","tenantId":"tenant-uuid","tenantKey":"logical-tenant",
            "cellId":"cell","principalId":"principal","role":"ingest",
            "expiresAt":(Utc::now()+chrono::Duration::minutes(5)).to_rfc3339()})).unwrap();
        let writer = NativePartWriter::new(&origin, None, "tenant-uuid", "cell", "bucket", permission, dir.path()).unwrap();
        let sha = "c".repeat(64);
        let log_hints = WriteHints { class: crate::parts::part_log::WriterClass::LakePartLog, ..hints() };
        let entry = writer.begin("tenant/log/entries/00000000000000000001.json", &sha, 7, &log_hints).await.err().unwrap();
        let held = entry.downcast_ref::<crate::parts::part_log::LogKeyHeld>().expect("entry 409 is a held key");
        assert_eq!(held.key, "tenant/log/entries/00000000000000000001.json");
        assert!(!crate::part_ingest::ingest::fatal_ingest_error(&entry));
        let checkpoint = writer.begin("tenant/log/checkpoints/00000000000000001024.json", &sha, 7, &hints()).await.err().unwrap();
        assert!(checkpoint.downcast_ref::<crate::parts::part_log::LogKeyHeld>().is_some());
        let part = writer.begin("tenant/parts/p/data-00000.parquet", &sha, 7, &hints()).await.err().unwrap();
        assert!(part.downcast_ref::<crate::parts::part_log::LogKeyHeld>().is_none());
        assert_eq!(part.downcast_ref::<OwnerRefused>().map(|refused| refused.status), Some(409));
        assert_eq!(part.to_string(), "native writer owner refused HTTP 409");
        // Nothing was journaled: the next attempt is a fresh authorize.
        assert_eq!(std::fs::read_dir(dir.path().join("native-writer-receipts/pending")).unwrap().count(), 0);
        task.abort();
    }

    /// Distinct objects write concurrently; the same key and a journal replay
    /// still exclude (NAN-3120 replay semantics, without serializing every
    /// write behind every other one).
    #[tokio::test]
    async fn distinct_keys_write_concurrently_while_same_key_and_replay_exclude() {
        let (writer, _dir, a, _c, task) = fixture(false).await;
        let wait = |ms| std::time::Duration::from_millis(ms);
        let first = writer.write_guard("tenant/parts/a").await.unwrap();
        assert_eq!(a.load(Ordering::SeqCst), 0, "opening replay reads the journal only");
        let second = tokio::time::timeout(wait(500), writer.write_guard("tenant/parts/b")).await
            .expect("a distinct key must not wait for an in-flight write").unwrap();
        assert!(tokio::time::timeout(wait(100), writer.write_guard("tenant/parts/a")).await.is_err(),
            "the same key stays serialized");
        writer.mark_needs_replay();
        assert!(tokio::time::timeout(wait(100), writer.write_guard("tenant/parts/c")).await.is_err(),
            "a replay waits for every in-flight write");
        drop(first);
        drop(second);
        let third = tokio::time::timeout(wait(2_000), writer.write_guard("tenant/parts/c")).await.unwrap().unwrap();
        assert!(!writer.needs_replay.load(Ordering::SeqCst));
        drop(third);
        assert!(writer.keys.lock().unwrap().is_empty(), "key locks are released");
        task.abort();
    }

    /// NAN-4539: two overlapping flush publications (and merges) share ONE
    /// 32-write envelope per production writer: never 64 at once. A permit
    /// is taken per write (no partial group is held while waiting), a
    /// cancelled waiter or a failed write gives its permit back, and replay
    /// stays exclusive.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn overlapping_publications_share_one_32_write_envelope() {
        let (writer, _dir, _a, _c, task) = fixture(false).await;
        let writer = Arc::new(writer);
        let envelope = crate::part_ingest::writer::PUBLISH_CONCURRENCY;
        let (held, peak) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let release = Arc::new(tokio::sync::Notify::new());
        // Two publications of `envelope` writes each, started together.
        let mut writes = Vec::new();
        for publication in 0..2 {
            for object in 0..envelope {
                let (writer, held, peak, release) = (writer.clone(), held.clone(), peak.clone(), release.clone());
                writes.push(tokio::spawn(async move {
                    let guard = writer.write_guard(&format!("tenant/parts/p{publication}/o{object}")).await.unwrap();
                    let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                    peak.fetch_max(now, Ordering::SeqCst);
                    release.notified().await;
                    held.fetch_sub(1, Ordering::SeqCst);
                    drop(guard);
                }));
            }
        }
        let started = std::time::Instant::now();
        while held.load(Ordering::SeqCst) < envelope {
            assert!(started.elapsed().as_secs() < 30, "the first {envelope} writes never started");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert_eq!(held.load(Ordering::SeqCst), envelope, "the envelope is shared, not per publication");
        assert_eq!(writer.writes.available_permits(), 0);
        // A waiter that is dropped (a cancelled publication) and a write that
        // fails both return their permits.
        let cancelled = tokio::time::timeout(std::time::Duration::from_millis(50), writer.write_guard("tenant/parts/cancelled")).await;
        assert!(cancelled.is_err(), "a 65th write waits for a permit");
        // Let every write finish, one wave at a time.
        while writes.iter().any(|write| !write.is_finished()) {
            release.notify_waiters();
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
        for write in writes {
            write.await.unwrap();
        }
        assert_eq!(peak.load(Ordering::SeqCst), envelope, "never more than {envelope} native writes in flight");
        {
            let failed = writer.write_guard("tenant/parts/failed").await.unwrap();
            writer.mark_needs_replay();
            drop(failed);
        }
        assert_eq!(writer.writes.available_permits(), envelope, "cancelled and failed writes return their permits");
        // The replay after the failure still takes the gate exclusively and
        // the next write proceeds.
        let next = tokio::time::timeout(std::time::Duration::from_secs(5), writer.write_guard("tenant/parts/next")).await
            .expect("replay then write").unwrap();
        assert!(!writer.needs_replay.load(Ordering::SeqCst));
        drop(next);
        assert!(writer.keys.lock().unwrap().is_empty(), "key locks are released");
        let timings = writer.diagnostics()["timings"].clone();
        assert!(timings.get("write_slot_wait").is_some(), "the envelope wait is timed under a fixed label: {timings}");
        task.abort();
    }

    #[tokio::test]
    async fn unknown_put_outcome_never_registers_or_reauthorizes() {
        let (writer, _dir, a, c, task) = fixture(false).await;
        let sha = "c".repeat(64);
        assert!(writer.begin("tenant/parts/object", &sha, 7, &hints()).await.unwrap().is_some());
        let error = writer.begin("tenant/parts/object", &sha, 7, &hints()).await.err().unwrap();
        assert_eq!(error.downcast_ref::<NativePutUnresolved>().unwrap().key, "tenant/parts/object");
        assert_eq!(a.load(Ordering::SeqCst), 1);
        writer.replay_pending().await.unwrap();
        assert_eq!(c.load(Ordering::SeqCst), 0);
        task.abort();
    }
    #[tokio::test]
    async fn replay_bounds_local_parsing_without_owner_io() {
        let dir = tempfile::tempdir().unwrap();
        let permission: WritePermission = serde_json::from_value(json!({"token":"test-only-token",
            "audience":"owner","scope":"lake-parts:write","tenantId":"tenant","tenantKey":"logical",
            "cellId":"cell","principalId":"principal","role":"ingest",
            "expiresAt":(Utc::now()+chrono::Duration::minutes(5)).to_rfc3339()})).unwrap();
        let writer = NativePartWriter::new("http://127.0.0.1:1", None, "tenant", "cell", "bucket", permission, dir.path()).unwrap();
        let path = writer.dir.join("writer_test.json");
        std::fs::write(&path, vec![b' '; 65537]).unwrap();
        assert!(writer.replay_pending().await.unwrap_err().to_string().contains("intent exceeds cap"));
        std::fs::write(&path, b"{").unwrap();
        assert!(writer.replay_pending().await.is_err());
        std::fs::write(&path, br#"{"request":{},"identity":{},"object":null,"registered":null}"#).unwrap();
        writer.replay_pending().await.unwrap();
        for n in 0..1024 { std::fs::write(writer.dir.join(format!("temp-{n}")), b"").unwrap(); }
        assert!(writer.replay_pending().await.unwrap_err().to_string().contains("entry cap"));
    }

    #[tokio::test]
    async fn archived_history_does_not_cap_pending_replay_or_new_writes() {
        let (writer, _dir, a, c, task) = fixture(false).await;
        let sha = "c".repeat(64);
        // More lifetime successes than the pending replay cap, each through the real transition.
        for n in 0..1025 {
            let key = format!("tenant/parts/archive-{n}");
            let attempt = writer.begin(&key, &sha, 7, &hints()).await.unwrap().unwrap();
            writer.finish(attempt, "\"actual-put-etag\"").await.unwrap();
        }
        assert_eq!(std::fs::read_dir(&writer.dir).unwrap().count(), 0);
        assert_eq!(std::fs::read_dir(&writer.archive).unwrap().count(), 1025);
        let attempt = writer.begin("tenant/parts/pending", &sha, 7, &hints()).await.unwrap().unwrap();
        let object = json!({"etag":"\"actual-put-etag\"", "writer_authority_sha256":attempt.identity["owner_reservation_sha256"]});
        writer.save(&attempt.path, &Intent { request: attempt.request, identity: attempt.identity,
            object: Some(object), registered: None }).unwrap();
        writer.replay_pending().await.unwrap();
        assert!(writer.begin("tenant/parts/archive-0", &sha, 7, &hints()).await.unwrap().is_none());
        let attempt = writer.begin("tenant/parts/next", &sha, 7, &hints()).await.unwrap().unwrap();
        writer.finish(attempt, "\"actual-put-etag\"").await.unwrap();
        assert_eq!(a.load(Ordering::SeqCst), 1027);
        assert_eq!(c.load(Ordering::SeqCst), 1027);
        task.abort();
    }

    #[tokio::test]
    async fn saved_acknowledgement_recovers_move_without_owner_calls() {
        let (writer, _dir, a, c, task) = fixture(false).await;
        let sha = "c".repeat(64);
        let key = "tenant/parts/crash";
        let attempt = writer.begin(key, &sha, 7, &hints()).await.unwrap().unwrap();
        let pending = attempt.path.clone();
        writer.finish(attempt, "\"actual-put-etag\"").await.unwrap();
        let archived = writer.archive.join(pending.file_name().unwrap());
        let permission = writer.permission.read().unwrap().clone();
        // Simulate crash after saving acknowledgement, before its move.
        std::fs::rename(&archived, &pending).unwrap();
        let reopened = NativePartWriter::new(&writer.origin, None, &writer.tenant, &writer.cell,
            &writer.bucket, permission, _dir.path()).unwrap();
        reopened.replay_pending().await.unwrap();
        assert!(!pending.exists());
        assert!(reopened.begin(key, &sha, 7, &hints()).await.unwrap().is_none());
        // The direct begin path also recovers the same interrupted transition.
        std::fs::rename(&archived, &pending).unwrap();
        assert!(reopened.begin(key, &sha, 7, &hints()).await.unwrap().is_none());
        // Simulate a surviving pending name after the archive destination is durable.
        std::fs::copy(&archived, &pending).unwrap();
        assert!(reopened.begin(key, &sha, 7, &hints()).await.unwrap().is_none());
        reopened.replay_pending().await.unwrap();
        assert_eq!(a.load(Ordering::SeqCst), 1);
        assert_eq!(c.load(Ordering::SeqCst), 1);
        task.abort();
    }

    #[tokio::test]
    async fn missing_etag_intent_remains_closed() {
        let (writer, _dir, a, c, task) = fixture(false).await;
        let sha = "c".repeat(64);
        let key = "tenant/parts/no-etag";
        let attempt = writer.begin(key, &sha, 7, &hints()).await.unwrap().unwrap();
        writer.save(&attempt.path, &Intent { request: attempt.request, identity: attempt.identity,
            object: Some(json!({})), registered: None }).unwrap();
        assert!(writer.replay_pending().await.is_err());
        assert!(writer.begin(key, &sha, 7, &hints()).await.is_err());
        assert_eq!(a.load(Ordering::SeqCst), 1);
        assert_eq!(c.load(Ordering::SeqCst), 0);
        task.abort();
    }

    #[cfg(unix)]
    #[test]
    fn journal_load_refuses_symlinks_and_nonregular_files() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        std::fs::write(&target, br#"{"request":{},"identity":{},"object":null,"registered":null}"#).unwrap();
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(NativePartWriter::load(&link).is_err());
        assert!(NativePartWriter::load(dir.path()).is_err());
        assert!(NativePartWriter::load(&target).unwrap().is_some());
    }

    #[test]
    fn write_permission_rejects_wrong_scope_tenant_cell_and_expiry() {
        let good = json!({"token":"secret", "audience":"owner", "scope":"lake-parts:write",
            "tenantId":"tenant", "tenantKey":"logical", "cellId":"cell", "principalId":"principal",
            "role":"ingest", "expiresAt":(Utc::now()+chrono::Duration::minutes(5)).to_rfc3339()});
        for (field, value) in [("scope", json!("lake-parts:sign")), ("tenantId", json!("other")),
            ("cellId", json!("other")), ("audience", json!("foreign")), ("role", json!("detect")),
            ("expiresAt", json!((Utc::now()-chrono::Duration::seconds(1)).to_rfc3339())),
            ("expiresAt", json!((Utc::now()+chrono::Duration::minutes(11)).to_rfc3339()))] {
            let mut bad = good.clone(); bad[field] = value;
            let permission: WritePermission = serde_json::from_value(bad).unwrap();
            assert!(permission.validate("tenant", "cell").is_err(), "{field}");
        }
        let permission: WritePermission = serde_json::from_value(good).unwrap();
        assert!(permission.validate("tenant", "cell").is_ok());
    }
    #[test]
    fn pinned_origin_uses_scheme_host_and_effective_port_only() {
        assert_eq!(owner_origin("https://owner.example:443/internal/sign").unwrap(), "https://owner.example");
        assert_eq!(owner_origin("https://owner.example:9443/internal/sign").unwrap(), "https://owner.example:9443");
        for bad in ["https://user:secret@owner.example/sign", "https://owner.example/sign?token=x",
            "https://owner.example/sign#foreign", "file:///sign"] { assert!(owner_origin(bad).is_err()); }
    }

}
