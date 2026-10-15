// SPDX-License-Identifier: AGPL-3.0-or-later

//! Zero-downtime cell rolls (NAN-3004, cell feature `cell_zero_downtime_roll_v1`).
//!
//! A cell roll runs two pods of the same cell side by side for a short while
//! (Deployment `RollingUpdate`, `maxSurge: 1`, `maxUnavailable: 0`). The
//! gen1 reader rolls taught the shape (`serving_readiness.rs`,
//! `worker_identity.rs` peers, NAN-2653/NAN-2658): the new pod warms while
//! the old one serves, becomes Ready only when warm, and the old pod drains
//! after its readiness is withdrawn. This module adds what gen1 never had:
//! a **writer handover** between the two pods.
//!
//! Roles split into two classes:
//!
//! - **query[T]** runs in both pods at once. Every query process reads the
//!   same verified part log from R2 (local parts are only a first-read cache),
//!   so two readers are just two caches. The pod reports Ready (`/readyz`)
//!   only after every resident tenant's query process opened its engine and
//!   finished its startup prewarm, so the Service never routes a search to a
//!   cold pod.
//! - **ingest[T], detect[T] and maintenance[T]** are writers: exactly one
//!   pod runs them per tenant. Storage already fences a second writer (edge-log DO lease: the
//!   newest lease wins and the old consumer's pull/commit answer `fenced`;
//!   part-log appends are a conditional create per sequence number; SlateDB
//!   prevalence: the newest open fences the old client), so a double writer
//!   can never commit twice. This module makes sure it never *tries*: a pod
//!   starts a writer for `T` only when no peer of the same cell may be
//!   writing `T`.
//!
//! Peers find each other through the cell's headless peer Service
//! (`dns:` peers; `publishNotReadyAddresses`) and read each other's
//! `GET /v1/handover` view (full router token). The rules
//! ([`writer_verdict`]):
//!
//! 1. A draining pod (SIGTERM) starts no writers; it releases its writers at
//!    once (`Shutdown`: ingest flushes, commits and exits) and reports each
//!    tenant `writing` until its process has exited.
//! 2. A pod starts no writer before its first complete peer round (or
//!    `discovery_grace_secs`).
//! 3. A peer blocks tenant `T` while it reports `T` writing and has answered
//!    within `writer_lease_ttl_secs`; a peer whose answer could not be read
//!    (unauthorized, garbage) or that is listed but never answered blocks
//!    every tenant for the same TTL (fail closed).
//! 4. Among serving pods the senior (smallest `(boot_unix_ms, boot_id)`)
//!    claims an unowned tenant at once; a junior claims only after the tenant
//!    has been unowned for a whole TTL. A roll therefore moves every writer
//!    exactly once: old pod drains, the new pod is the only serving pod left,
//!    it claims each tenant the moment the old one reports it released.
//!
//! The handover gap per tenant is the old writer's flush plus one poll
//! (`peer_poll_ms`). Nothing is lost while nobody writes: the edge log keeps
//! everything past the committed point and the successor resumes from the
//! part log (`EdgeLogSource::open`), with deterministic event uids.

use crate::contract::TenantId;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{AUTHORIZATION, HOST};
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Wire format of `GET /v1/handover`.
pub const VIEW_FORMAT: &str = "nano.cell-handover.v1";

/// Largest peer view accepted (tenant lists are bounded by placement).
const MAX_VIEW_BYTES: usize = 1024 * 1024;

fn default_poll_ms() -> u64 {
    1000
}
fn default_ttl() -> u64 {
    30
}
fn default_discovery_grace() -> u64 {
    10
}
fn default_drain() -> u64 {
    15
}
fn default_inflight() -> u64 {
    30
}
fn default_standby_wait() -> u64 {
    30
}

/// `zero_downtime_roll` in `cell.json`. Present = the feature is on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandoverConfig {
    /// Where the other pods of this cell answer: `dns:<host>:<port>` (every
    /// address the name resolves to; the headless peer Service),
    /// `tcp:<ip>:<port>`, or `unix:<path>`. The pod's own address may be
    /// listed: a view carrying our own boot id is skipped.
    pub peers: Vec<String>,
    #[serde(default = "default_poll_ms")]
    pub peer_poll_ms: u64,
    /// How long a peer that stopped answering may still be writing (and how
    /// long a junior waits on an unowned tenant).
    #[serde(default = "default_ttl")]
    pub writer_lease_ttl_secs: u64,
    /// Upper bound on waiting for the first complete peer round at boot.
    #[serde(default = "default_discovery_grace")]
    pub discovery_grace_secs: u64,
    /// SIGTERM: keep serving queries this long after readiness is withdrawn
    /// (endpoint propagation), after the writers are released.
    #[serde(default = "default_drain")]
    pub drain_secs: u64,
    /// Then wait at most this long for in-flight queries.
    #[serde(default = "default_inflight")]
    pub inflight_secs: u64,
    /// A detect request that lands on a standby pod waits this long for the
    /// writer to move here before answering 503.
    #[serde(default = "default_standby_wait")]
    pub standby_request_wait_secs: u64,
}

impl HandoverConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(!self.peers.is_empty() && self.peers.len() <= 64, "zero_downtime_roll.peers: 1..=64 entries");
        for p in &self.peers {
            PeerTarget::parse(p)?;
        }
        anyhow::ensure!((100..=10_000).contains(&self.peer_poll_ms), "zero_downtime_roll.peer_poll_ms must be 100..=10000");
        anyhow::ensure!(
            (5..=600).contains(&self.writer_lease_ttl_secs),
            "zero_downtime_roll.writer_lease_ttl_secs must be 5..=600"
        );
        anyhow::ensure!(
            self.writer_lease_ttl_secs * 1000 >= 3 * self.peer_poll_ms,
            "zero_downtime_roll.writer_lease_ttl_secs must cover at least three peer polls"
        );
        anyhow::ensure!(self.discovery_grace_secs <= 300, "zero_downtime_roll.discovery_grace_secs must be <= 300");
        anyhow::ensure!(self.drain_secs <= 120 && self.inflight_secs <= 600, "zero_downtime_roll drain windows too long");
        anyhow::ensure!(self.standby_request_wait_secs <= 120, "zero_downtime_roll.standby_request_wait_secs must be <= 120");
        Ok(())
    }

    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.writer_lease_ttl_secs)
    }

    pub fn poll(&self) -> Duration {
        Duration::from_millis(self.peer_poll_ms)
    }
}

/// One configured peer source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerTarget {
    Dns { host: String, port: u16 },
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl PeerTarget {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        if let Some(rest) = s.strip_prefix("dns:") {
            let (host, port) = rest.rsplit_once(':').ok_or_else(|| anyhow::anyhow!("peer {s:?}: want dns:<host>:<port>"))?;
            anyhow::ensure!(
                !host.is_empty() && host.len() <= 253 && host.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.'),
                "peer {s:?}: bad host"
            );
            return Ok(Self::Dns { host: host.to_owned(), port: port.parse()? });
        }
        if let Some(rest) = s.strip_prefix("tcp:") {
            return Ok(Self::Tcp(rest.parse()?));
        }
        if let Some(rest) = s.strip_prefix("unix:") {
            let p = PathBuf::from(rest);
            anyhow::ensure!(p.is_absolute(), "peer {s:?}: unix path must be absolute");
            return Ok(Self::Unix(p));
        }
        anyhow::bail!("peer {s:?}: want dns:, tcp: or unix:")
    }
}

/// A resolved address to ask.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PeerAddr {
    Tcp(SocketAddr),
    Unix(PathBuf),
}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Tcp(a) => write!(f, "tcp:{a}"),
            PeerAddr::Unix(p) => write!(f, "unix:{}", p.display()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Serving,
    Draining,
}

/// `GET /v1/handover`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandoverView {
    pub format: String,
    pub cell_id: String,
    pub boot_id: String,
    pub boot_unix_ms: u64,
    pub phase: Phase,
    /// Readiness (warm and serving).
    pub ready: bool,
    /// Tenants with a writer (ingest, detect or maintenance) alive or starting here,
    /// including one that is still flushing after `Shutdown`.
    pub writing: BTreeSet<TenantId>,
    /// NAN-3569: this view includes maintenance as well as ingest/detect.
    /// Older peers omit it; their empty writer list is not release evidence.
    #[serde(default)]
    pub all_writers: bool,
    /// Tenants whose writer this pod released while draining.
    #[serde(default)]
    pub released: BTreeSet<TenantId>,
}

/// What this pod knows about one peer address.
#[derive(Debug, Clone)]
pub struct PeerObs {
    pub addr: PeerAddr,
    pub first_seen: Instant,
    /// Last time the address answered at all (any HTTP response).
    pub last_contact: Option<Instant>,
    /// The last readable view and when it was read. `None` with a contact
    /// means the peer answered but its view was unreadable (fail closed).
    pub view: Option<(HandoverView, Instant)>,
    pub last_error: Option<String>,
}

impl PeerObs {
    fn alive(&self, now: Instant, ttl: Duration) -> bool {
        self.last_contact.is_some_and(|t| now.duration_since(t) < ttl)
    }

    /// Whether this peer may be writing `t`.
    fn blocks(&self, t: &TenantId, now: Instant, ttl: Duration) -> bool {
        match (&self.view, self.last_contact) {
            // Listed but never answered: unknown for one TTL.
            (_, None) => now.duration_since(self.first_seen) < ttl,
            // Answered, but its last contact was unreadable: unknown.
            (None, Some(_)) => self.alive(now, ttl),
            (Some((view, read_at)), Some(contact)) => {
                if !self.alive(now, ttl) {
                    return false;
                }
                // A later unreadable contact than the view: unknown.
                if contact > *read_at {
                    return true;
                }
                !view.all_writers || view.writing.contains(t)
            }
        }
    }

    fn serving_view(&self, now: Instant, ttl: Duration) -> Option<&HandoverView> {
        let (view, read_at) = self.view.as_ref()?;
        (self.alive(now, ttl) && now.duration_since(*read_at) < ttl && view.phase == Phase::Serving).then_some(view)
    }
}

/// Why this pod may not start a writer for a tenant now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Standby {
    Draining,
    Discovering,
    PeerWriting(String),
    JuniorWaiting { unowned_for: Duration },
}

impl std::fmt::Display for Standby {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Standby::Draining => f.write_str("cell is draining (writer released)"),
            Standby::Discovering => f.write_str("cell is discovering its peers"),
            Standby::PeerWriting(p) => write!(f, "peer {p} holds the writer"),
            Standby::JuniorWaiting { unowned_for } => {
                write!(f, "a senior peer serves this cell; tenant unowned for {} s", unowned_for.as_secs())
            }
        }
    }
}

/// This pod's identity for seniority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfId {
    pub cell_id: String,
    pub boot_id: String,
    pub boot_unix_ms: u64,
}

/// The pure writer rule (module docs, rules 3 and 4). `unowned_for` is how
/// long this pod has seen `t` unblocked (0 = just now).
pub fn writer_verdict(
    me: &SelfId,
    peers: &[PeerObs],
    t: &TenantId,
    now: Instant,
    ttl: Duration,
    unowned_for: Duration,
) -> Result<(), Standby> {
    for p in peers {
        if p.blocks(t, now, ttl) {
            let who = p.view.as_ref().map(|(v, _)| v.boot_id.clone()).unwrap_or_else(|| p.addr.to_string());
            return Err(Standby::PeerWriting(who));
        }
    }
    let senior_exists = peers.iter().filter_map(|p| p.serving_view(now, ttl)).any(|v| {
        (v.boot_unix_ms, v.boot_id.as_str()) < (me.boot_unix_ms, me.boot_id.as_str())
    });
    if senior_exists && unowned_for < ttl {
        return Err(Standby::JuniorWaiting { unowned_for });
    }
    Ok(())
}

/// NAN-3164: should the startup warm latch also wait for each query
/// process's local hot window (its newest hours resident)? Only while a
/// serving, Ready peer can carry search — or before discovery has told us
/// whether one exists. A lone pod (first boot, full outage) never waits on
/// hydration: cold search beats no search. The query process bounds the wait
/// itself (`NANO_LAKE_LOCAL_HOT_WINDOW_WARM_TIMEOUT_SECONDS`).
pub fn hot_window_gate_applies(peers: &[PeerObs], discovered: bool, now: Instant, ttl: Duration) -> bool {
    !discovered || peers.iter().any(|p| p.serving_view(now, ttl).is_some_and(|v| v.ready))
}

/// Handover state of one cell supervisor.
pub struct Handover {
    pub cfg: HandoverConfig,
    pub me: SelfId,
    targets: Vec<PeerTarget>,
    started: Instant,
    phase: AtomicU8,
    /// A full peer round completed since boot.
    discovered: AtomicBool,
    /// Startup warm latch: every resident tenant's query was warm once.
    warm: AtomicBool,
    warm_pending: Mutex<BTreeSet<TenantId>>,
    peers: Mutex<BTreeMap<PeerAddr, PeerObs>>,
    /// Addresses that answered with our own boot id (never peers).
    self_addrs: Mutex<BTreeSet<PeerAddr>>,
    unowned_since: Mutex<HashMap<TenantId, Instant>>,
    released: Mutex<BTreeSet<TenantId>>,
}

fn now_unix_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

impl Handover {
    pub fn new(cell_id: &str, cfg: HandoverConfig) -> anyhow::Result<Self> {
        cfg.validate()?;
        let targets = cfg.peers.iter().map(|p| PeerTarget::parse(p)).collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            me: SelfId { cell_id: cell_id.to_owned(), boot_id: uuid::Uuid::now_v7().to_string(), boot_unix_ms: now_unix_ms() },
            cfg,
            targets,
            started: Instant::now(),
            phase: AtomicU8::new(0),
            discovered: AtomicBool::new(false),
            warm: AtomicBool::new(false),
            warm_pending: Mutex::new(BTreeSet::new()),
            peers: Mutex::new(BTreeMap::new()),
            self_addrs: Mutex::new(BTreeSet::new()),
            unowned_since: Mutex::new(HashMap::new()),
            released: Mutex::new(BTreeSet::new()),
        })
    }

    pub fn phase(&self) -> Phase {
        if self.phase.load(Ordering::SeqCst) == 0 {
            Phase::Serving
        } else {
            Phase::Draining
        }
    }

    pub fn draining(&self) -> bool {
        self.phase() == Phase::Draining
    }

    /// SIGTERM: readiness off, no new writers from here on.
    pub fn begin_drain(&self) {
        self.phase.store(1, Ordering::SeqCst);
    }

    pub fn note_released(&self, t: &TenantId) {
        self.released.lock().unwrap().insert(t.clone());
    }

    pub fn released(&self) -> BTreeSet<TenantId> {
        self.released.lock().unwrap().clone()
    }

    pub fn discovered(&self) -> bool {
        self.discovered.load(Ordering::SeqCst) || self.started.elapsed() >= Duration::from_secs(self.cfg.discovery_grace_secs)
    }

    /// Startup warm: record what is still cold; latch once nothing is.
    pub fn set_warm_pending(&self, pending: BTreeSet<TenantId>) -> bool {
        let done = pending.is_empty();
        *self.warm_pending.lock().unwrap() = pending;
        if done && !self.warm.swap(true, Ordering::SeqCst) {
            tracing::info!(warm_secs = self.started.elapsed().as_secs_f64(), "cell warm: ready for traffic");
        }
        self.warm.load(Ordering::SeqCst)
    }

    pub fn warm(&self) -> bool {
        self.warm.load(Ordering::SeqCst)
    }

    /// See [`hot_window_gate_applies`].
    pub fn hot_window_gate_applies(&self) -> bool {
        let peers: Vec<PeerObs> = self.peers.lock().unwrap().values().cloned().collect();
        hot_window_gate_applies(&peers, self.discovered(), Instant::now(), self.cfg.ttl())
    }

    pub fn warm_pending(&self) -> BTreeSet<TenantId> {
        self.warm_pending.lock().unwrap().clone()
    }

    /// Ready for Service traffic: warm and not draining.
    pub fn ready(&self) -> bool {
        self.warm() && !self.draining()
    }

    /// May this pod start a writer (ingest / detect) for `t` now?
    pub fn may_write(&self, t: &TenantId) -> Result<(), Standby> {
        if self.draining() {
            return Err(Standby::Draining);
        }
        if !self.discovered() {
            return Err(Standby::Discovering);
        }
        let now = Instant::now();
        let peers: Vec<PeerObs> = self.peers.lock().unwrap().values().cloned().collect();
        let ttl = self.cfg.ttl();
        let blocked = peers.iter().any(|p| p.blocks(t, now, ttl));
        let unowned_for = {
            let mut u = self.unowned_since.lock().unwrap();
            if blocked {
                u.remove(t);
                Duration::ZERO
            } else {
                now.duration_since(*u.entry(t.clone()).or_insert(now))
            }
        };
        writer_verdict(&self.me, &peers, t, now, ttl, unowned_for)
    }

    /// Our view, as peers read it.
    pub fn view(&self, writing: BTreeSet<TenantId>) -> HandoverView {
        HandoverView {
            format: VIEW_FORMAT.to_owned(),
            cell_id: self.me.cell_id.clone(),
            boot_id: self.me.boot_id.clone(),
            boot_unix_ms: self.me.boot_unix_ms,
            phase: self.phase(),
            ready: self.ready(),
            writing,
            all_writers: true,
            released: self.released(),
        }
    }

    /// Peers as last observed (status).
    pub fn peer_status(&self) -> Vec<PeerStatus> {
        let now = Instant::now();
        let ttl = self.cfg.ttl();
        self.peers
            .lock()
            .unwrap()
            .values()
            .map(|p| PeerStatus {
                addr: p.addr.to_string(),
                alive: p.alive(now, ttl),
                boot_id: p.view.as_ref().map(|(v, _)| v.boot_id.clone()),
                phase: p.view.as_ref().map(|(v, _)| v.phase),
                ready: p.view.as_ref().map(|(v, _)| v.ready),
                writing: p.view.as_ref().map(|(v, _)| v.writing.len()),
                last_error: p.last_error.clone(),
            })
            .collect()
    }

    async fn resolve(&self) -> Vec<PeerAddr> {
        let mut out = BTreeSet::new();
        for t in &self.targets {
            match t {
                PeerTarget::Tcp(a) => {
                    out.insert(PeerAddr::Tcp(*a));
                }
                PeerTarget::Unix(p) => {
                    out.insert(PeerAddr::Unix(p.clone()));
                }
                PeerTarget::Dns { host, port } => match tokio::net::lookup_host((host.as_str(), *port)).await {
                    Ok(addrs) => out.extend(addrs.map(PeerAddr::Tcp)),
                    // NXDOMAIN while the Service has no endpoints is normal.
                    Err(e) => tracing::debug!(%host, error = %e, "peer lookup failed"),
                },
            }
        }
        out.into_iter().collect()
    }

    /// One peer round: resolve, ask every address (listed now or seen
    /// within a TTL), fold the answers.
    pub async fn poll_once(&self, token: Option<std::sync::Arc<zeroize::Zeroizing<String>>>) {
        let now = Instant::now();
        let ttl = self.cfg.ttl();
        let mut listed = self.resolve().await;
        {
            let mine = self.self_addrs.lock().unwrap();
            listed.retain(|a| !mine.contains(a));
        }
        let addrs: BTreeSet<PeerAddr> = {
            let mut peers = self.peers.lock().unwrap();
            for a in &listed {
                peers.entry(a.clone()).or_insert_with(|| PeerObs {
                    addr: a.clone(),
                    first_seen: now,
                    last_contact: None,
                    view: None,
                    last_error: None,
                });
            }
            // Forget an address neither listed nor heard from within a TTL.
            peers.retain(|a, p| {
                listed.contains(a) || p.last_contact.map_or(now.duration_since(p.first_seen) < ttl, |c| now.duration_since(c) < ttl)
            });
            peers.keys().cloned().collect()
        };
        let timeout = self.cfg.poll().max(Duration::from_millis(500)).min(Duration::from_secs(3));
        let results = futures_join(addrs.into_iter().map(|a| {
            let token = token.clone();
            async move {
            let r = tokio::time::timeout(timeout, fetch_view(&a, token.as_deref().map(|t| t.as_str()))).await.unwrap_or(Err(FetchError::Unreachable("timeout".into())));
            (a, r)
            }
        }))
        .await;
        let at = Instant::now();
        let mut peers = self.peers.lock().unwrap();
        for (a, r) in results {
            match r {
                Ok(view) if view.boot_id == self.me.boot_id => {
                    // Ourselves (the peer Service lists every pod).
                    peers.remove(&a);
                    self.self_addrs.lock().unwrap().insert(a);
                }
                Ok(view) if view.cell_id != self.me.cell_id || view.format != VIEW_FORMAT => {
                    tracing::warn!(peer = %a, cell = %view.cell_id, "peer belongs to another cell; ignored");
                    peers.remove(&a);
                }
                Ok(view) => {
                    if let Some(p) = peers.get_mut(&a) {
                        if p.view.as_ref().is_none_or(|(v, _)| v.boot_id != view.boot_id) {
                            tracing::info!(peer = %a, boot_id = %view.boot_id, phase = ?view.phase, writing = view.writing.len(), "cell peer seen");
                        }
                        p.last_contact = Some(at);
                        p.view = Some((view, at));
                        p.last_error = None;
                    }
                }
                Err(FetchError::Unreadable(e)) => {
                    if let Some(p) = peers.get_mut(&a) {
                        p.last_contact = Some(at);
                        p.last_error = Some(e);
                    }
                }
                Err(FetchError::Unreachable(e)) => {
                    if let Some(p) = peers.get_mut(&a) {
                        p.last_error = Some(e);
                    }
                }
            }
        }
        drop(peers);
        if !self.discovered.swap(true, Ordering::SeqCst) {
            tracing::info!(peers = self.peer_status().len(), "first peer round complete");
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct PeerStatus {
    pub addr: String,
    pub alive: bool,
    pub boot_id: Option<String>,
    pub phase: Option<Phase>,
    pub ready: Option<bool>,
    pub writing: Option<usize>,
    pub last_error: Option<String>,
}

/// `handover` in `/v1/status`.
#[derive(Debug, Clone, Serialize)]
pub struct HandoverStatus {
    pub boot_id: String,
    pub boot_unix_ms: u64,
    pub phase: Phase,
    pub ready: bool,
    pub warm: bool,
    pub warm_pending: usize,
    /// Resident tenants whose writer runs on a peer (this pod is standby).
    pub standby: BTreeMap<TenantId, String>,
    pub released: BTreeSet<TenantId>,
    pub peers: Vec<PeerStatus>,
}

enum FetchError {
    /// No HTTP answer (connect refused, timeout): counts toward the TTL.
    Unreachable(String),
    /// An HTTP answer we cannot trust (401, garbage): alive, unknown.
    Unreadable(String),
}

async fn futures_join<F, T>(futs: impl Iterator<Item = F>) -> Vec<T>
where
    F: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    let handles: Vec<_> = futs.map(tokio::spawn).collect();
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        if let Ok(v) = h.await {
            out.push(v);
        }
    }
    out
}

async fn fetch_view(addr: &PeerAddr, token: Option<&str>) -> Result<HandoverView, FetchError> {
    let unreachable = |e: &dyn std::fmt::Display| FetchError::Unreachable(e.to_string());
    let (mut sender, conn) = match addr {
        PeerAddr::Tcp(a) => {
            let s = tokio::net::TcpStream::connect(a).await.map_err(|e| unreachable(&e))?;
            hyper::client::conn::http1::handshake(TokioIo::new(s)).await.map_err(|e| unreachable(&e))?
        }
        PeerAddr::Unix(p) => {
            let s = tokio::net::UnixStream::connect(p).await.map_err(|e| unreachable(&e))?;
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(s)).await.map_err(|e| unreachable(&e))?;
            tokio::spawn(conn);
            return send(&mut sender, token).await;
        }
    };
    tokio::spawn(conn);
    send(&mut sender, token).await
}

async fn send(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    token: Option<&str>,
) -> Result<HandoverView, FetchError> {
    let mut req = Request::builder().method("GET").uri("/v1/handover").header(HOST, "cell");
    if let Some(t) = token {
        req = req.header(AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = req.body(Full::new(Bytes::new())).map_err(|e| FetchError::Unreachable(e.to_string()))?;
    let resp = sender.send_request(req).await.map_err(|e| FetchError::Unreachable(e.to_string()))?;
    let status = resp.status();
    let body = http_body_util::Limited::new(resp.into_body(), MAX_VIEW_BYTES)
        .collect()
        .await
        .map_err(|e| FetchError::Unreadable(format!("body: {e}")))?
        .to_bytes();
    if !status.is_success() {
        return Err(FetchError::Unreadable(format!("HTTP {}", status.as_u16())));
    }
    serde_json::from_slice(&body).map_err(|e| FetchError::Unreadable(format!("view: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tid(s: &str) -> TenantId {
        TenantId::new(s).unwrap()
    }

    fn me(ms: u64) -> SelfId {
        SelfId { cell_id: "c".into(), boot_id: format!("boot-{ms}"), boot_unix_ms: ms }
    }

    fn peer(ms: u64, phase: Phase, writing: &[&str], contact_ago: Duration, now: Instant) -> PeerObs {
        let at = now - contact_ago;
        PeerObs {
            addr: PeerAddr::Unix(format!("/p{ms}").into()),
            first_seen: now - Duration::from_secs(600),
            last_contact: Some(at),
            view: Some((
                HandoverView {
                    format: VIEW_FORMAT.into(),
                    cell_id: "c".into(),
                    boot_id: format!("boot-{ms}"),
                    boot_unix_ms: ms,
                    phase,
                    ready: true,
                    writing: writing.iter().map(|t| tid(t)).collect(),
                    all_writers: true,
                    released: BTreeSet::new(),
                },
                at,
            )),
            last_error: None,
        }
    }

    const TTL: Duration = Duration::from_secs(30);

    #[test]
    fn a_new_pod_waits_while_the_old_pod_writes_then_claims_at_release() {
        let now = Instant::now();
        let t = tid("t1");
        let new = me(2000);
        // Old (senior) pod writes t1: the new pod is standby.
        let old = peer(1000, Phase::Serving, &["t1"], Duration::from_millis(500), now);
        assert!(matches!(writer_verdict(&new, &[old], &t, now, TTL, Duration::ZERO), Err(Standby::PeerWriting(_))));
        // SIGTERM: old drains but is still flushing t1: still blocked.
        let flushing = peer(1000, Phase::Draining, &["t1"], Duration::from_millis(500), now);
        assert!(writer_verdict(&new, &[flushing], &t, now, TTL, Duration::ZERO).is_err());
        // Released: the draining pod is no senior; the new pod claims at once.
        let released = peer(1000, Phase::Draining, &[], Duration::from_millis(500), now);
        assert_eq!(writer_verdict(&new, &[released], &t, now, TTL, Duration::ZERO), Ok(()));
    }

    #[test]
    fn a_legacy_peer_cannot_release_an_unreported_maintenance_writer() {
        let now = Instant::now();
        let t = tid("t");
        let mut old = peer(1, Phase::Draining, &[], Duration::ZERO, now);
        // Decode the exact old wire shape: it ignores the new field when
        // reading us, and we default its omitted marker to false.
        let mut wire = serde_json::to_value(&old.view.as_ref().unwrap().0).unwrap();
        wire.as_object_mut().unwrap().remove("all_writers");
        old.view.as_mut().unwrap().0 = serde_json::from_value(wire).unwrap();
        assert_eq!(writer_verdict(&me(2), std::slice::from_ref(&old), &t, now, TTL, TTL),
            Err(Standby::PeerWriting("boot-1".into())));
        assert!(writer_verdict(&me(2), &[old], &t, now + TTL, TTL, TTL).is_ok());
    }

    #[test]
    fn a_vanished_writer_is_taken_over_after_one_ttl() {
        let now = Instant::now();
        let t = tid("t1");
        let new = me(2000);
        let recent = peer(1000, Phase::Serving, &["t1"], Duration::from_secs(29), now);
        assert!(writer_verdict(&new, &[recent], &t, now, TTL, Duration::ZERO).is_err());
        let gone = peer(1000, Phase::Serving, &["t1"], Duration::from_secs(31), now);
        assert_eq!(writer_verdict(&new, &[gone], &t, now, TTL, Duration::ZERO), Ok(()));
    }

    #[test]
    fn the_senior_claims_unowned_tenants_and_a_junior_waits_a_ttl() {
        let now = Instant::now();
        let t = tid("t1");
        let senior = me(1000);
        let junior = peer(2000, Phase::Serving, &[], Duration::from_millis(100), now);
        assert_eq!(writer_verdict(&senior, &[junior], &t, now, TTL, Duration::ZERO), Ok(()));
        let junior_me = me(2000);
        let senior_peer = peer(1000, Phase::Serving, &[], Duration::from_millis(100), now);
        assert!(matches!(
            writer_verdict(&junior_me, std::slice::from_ref(&senior_peer), &t, now, TTL, Duration::from_secs(5)),
            Err(Standby::JuniorWaiting { .. })
        ));
        assert_eq!(writer_verdict(&junior_me, &[senior_peer], &t, now, TTL, TTL), Ok(()));
        // Equal boot times: the boot id breaks the tie, the same way on both sides.
        let a = SelfId { cell_id: "c".into(), boot_id: "a".into(), boot_unix_ms: 5 };
        let mut pb = peer(5, Phase::Serving, &[], Duration::ZERO, now);
        pb.view.as_mut().unwrap().0.boot_id = "b".into();
        assert_eq!(writer_verdict(&a, &[pb], &t, now, TTL, Duration::ZERO), Ok(()));
    }

    #[test]
    fn unknown_peers_fail_closed_for_one_ttl() {
        let now = Instant::now();
        let t = tid("t1");
        let new = me(2000);
        // Listed, never answered.
        let silent = PeerObs { addr: PeerAddr::Unix("/x".into()), first_seen: now - Duration::from_secs(3),
            last_contact: None, view: None, last_error: Some("refused".into()) };
        assert!(writer_verdict(&new, std::slice::from_ref(&silent), &t, now, TTL, Duration::ZERO).is_err());
        let silent_long = PeerObs { first_seen: now - Duration::from_secs(40), ..silent };
        assert_eq!(writer_verdict(&new, &[silent_long], &t, now, TTL, Duration::ZERO), Ok(()));
        // Answered 401: alive and unknown blocks every tenant.
        let unauthorized = PeerObs { addr: PeerAddr::Unix("/y".into()), first_seen: now - Duration::from_secs(40),
            last_contact: Some(now), view: None, last_error: Some("HTTP 401".into()) };
        assert!(writer_verdict(&new, &[unauthorized], &t, now, TTL, Duration::ZERO).is_err());
        // A readable view followed by an unreadable answer is unknown again.
        let mut stale = peer(1000, Phase::Draining, &[], Duration::from_secs(2), now);
        stale.last_contact = Some(now);
        assert!(writer_verdict(&new, &[stale], &t, now, TTL, Duration::ZERO).is_err());
        // Another tenant's writer does not block this one.
        let other = peer(1000, Phase::Draining, &["t2"], Duration::ZERO, now);
        assert_eq!(writer_verdict(&new, &[other], &t, now, TTL, Duration::ZERO), Ok(()));
    }

    #[test]
    fn hot_window_gate_waits_only_while_a_ready_peer_serves() {
        let now = Instant::now();
        // Before discovery we cannot know: wait (bounded by discovery grace).
        assert!(hot_window_gate_applies(&[], false, now, TTL));
        // Lone pod: never hold search on hydration.
        assert!(!hot_window_gate_applies(&[], true, now, TTL));
        // Old pod serving and Ready: the new pod warms its cache first.
        let old = peer(1000, Phase::Serving, &["t1"], Duration::from_millis(500), now);
        assert!(hot_window_gate_applies(std::slice::from_ref(&old), true, now, TTL));
        // Old pod draining, not Ready, or gone: nobody else serves; don't wait.
        let draining = peer(1000, Phase::Draining, &[], Duration::from_millis(500), now);
        assert!(!hot_window_gate_applies(&[draining], true, now, TTL));
        let mut unready = old.clone();
        unready.view.as_mut().unwrap().0.ready = false;
        assert!(!hot_window_gate_applies(&[unready], true, now, TTL));
        let gone = peer(1000, Phase::Serving, &[], Duration::from_secs(31), now);
        assert!(!hot_window_gate_applies(&[gone], true, now, TTL));
    }

    #[test]
    fn config_is_validated() {
        let ok: HandoverConfig = serde_json::from_value(serde_json::json!({"peers": ["dns:nano-cell-a-peers.nano-lake-cells.svc:8790"]})).unwrap();
        ok.validate().unwrap();
        assert_eq!((ok.peer_poll_ms, ok.writer_lease_ttl_secs, ok.drain_secs), (1000, 30, 15));
        for bad in [
            serde_json::json!({"peers": []}),
            serde_json::json!({"peers": ["http://x"]}),
            serde_json::json!({"peers": ["unix:relative"]}),
            serde_json::json!({"peers": ["dns:bad_host!:1"]}),
            serde_json::json!({"peers": ["tcp:1.2.3.4:1"], "writer_lease_ttl_secs": 2}),
            serde_json::json!({"peers": ["tcp:1.2.3.4:1"], "peer_poll_ms": 5000, "writer_lease_ttl_secs": 10}),
        ] {
            let c: HandoverConfig = serde_json::from_value(bad.clone()).unwrap();
            assert!(c.validate().is_err(), "{bad}");
        }
        assert!(serde_json::from_value::<HandoverConfig>(serde_json::json!({"peers": ["tcp:1.2.3.4:1"], "nope": 1})).is_err());
        assert_eq!(PeerTarget::parse("tcp:10.0.0.1:8790").unwrap(), PeerTarget::Tcp("10.0.0.1:8790".parse().unwrap()));
    }

    #[test]
    fn may_write_tracks_draining_discovery_and_unowned_time() {
        let cfg: HandoverConfig = serde_json::from_value(serde_json::json!({"peers": ["unix:/nonexistent/peer.sock"],
            "discovery_grace_secs": 0})).unwrap();
        let h = Handover::new("c", cfg).unwrap();
        let t = tid("t1");
        assert_eq!(h.may_write(&t), Ok(()), "no peers: the only pod writes");
        assert!(!h.ready(), "not warm yet");
        assert!(h.set_warm_pending(BTreeSet::new()));
        assert!(h.ready());
        h.begin_drain();
        assert_eq!(h.may_write(&t), Err(Standby::Draining));
        assert!(!h.ready(), "draining withdraws readiness");
        let v = h.view([t.clone()].into());
        assert_eq!((v.phase, v.ready, v.writing.len()), (Phase::Draining, false, 1));
    }
}
