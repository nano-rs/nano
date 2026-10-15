// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3094: one progressive, shared scan behind the lean Asset page.
//!
//! Before: the page's dossier, artifact summary and artifact occurrence
//! endpoints each ran an identity-discovery scan plus a 50k-row host scan,
//! and the artifact summary added up to 250 more tenant-wide scans (one per
//! borderline artifact, four at a time). The events summary ran three more
//! scans in parallel. On query[T] a chatty host costs ~3-10 s of scan per
//! hour of window, so a 4 h page queued 8+ scans behind the cell's
//! interactive lanes: 422 "exhausted its concurrency budget", 504s, and a
//! dossier that never rendered.
//!
//! Now every one of those views reads ONE snapshot per
//! `(tenant, scope, asset, identities, window)`:
//!
//! - The snapshot is built by one detached task that issues its lake calls
//!   strictly one at a time: the window is read newest-first in chunks of at
//!   most [`CHUNK`] (so every call stays far inside the 55 s interactive
//!   deadline, whatever the window), then the prevalence lookup, the identity
//!   resolution and one bounded global-prevalence read.
//! - Identity widening (NAN-2361) is learned from the rows as they arrive:
//!   an IP seen on the asset's own endpoint joins the predicate for the
//!   remaining chunks, and the chunk that revealed it is re-read for rows only
//!   the widened predicate matches. The separate discovery scan is gone.
//! - Views poll it: a request waits a few seconds, then answers with what the
//!   snapshot covers so far plus `progress` (`complete: false`,
//!   `retry_after_ms`). The client renders and asks again. No request ever
//!   holds a gateway connection for a whole window scan.
//! - Handles live in the process-wide registry for two minutes (a reload or a
//!   second panel reads the same snapshot); a failed snapshot is dropped so
//!   the next request starts over.
//!
//! NAN-3252: each view completes at the stage it actually depends on
//! ([`Stage`]). The event summary is final once the rows are read, the
//! dossier once the prevalence baseline is in, and only the artifact summary
//! waits for the host-identity resolution and the tenant-wide global read.
//! Those two run concurrently under one [`ENRICH_BUDGET`]: before, they ran
//! one after the other after full coverage (identity resolution unbounded --
//! one event scan per distinct row timestamp while a cell's identity index
//! backfills -- then up to 20 s of tenant-wide global read), and every view
//! reported `complete: false` until both finished.
//!
//! NAN-3262: the dossier no longer waits for the event read at all. Before
//! it, the snapshot reads the dossier cards as lake aggregates
//! (`lake_asset_cards.rs`, under their own tenant permits), publishing each
//! as it lands, so a poll paints identity and timeline within seconds and the
//! dossier is final once every card and its rarity are in. Every read goes
//! through hintable predicate slices (`build_lake_asset_predicate_slices`),
//! so the worker prunes to the parts the asset's identifiers appear in.
//! Requests for the same asset (same resolved predicate) whose windows are
//! within [`window_tolerance`] share one snapshot.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::StreamExt;
use serde_json::{json, Value};

use super::super::lake_view_cache::{
    lake_view_cache_key, lake_view_forget, lake_view_handle, lake_view_peek, lake_view_pin,
};
use super::cards::{self, Section};
use super::*;

/// Widest single lake read. ~3-10 s on a chatty host at 300 eps.
const CHUNK: chrono::Duration = chrono::Duration::hours(1);
/// Narrowest chunk a refused read is bisected to.
const MIN_CHUNK: chrono::Duration = chrono::Duration::minutes(5);
/// Newest window a snapshot reads. Older time is reported, not scanned.
const MAX_SCANNED: chrono::Duration = chrono::Duration::hours(24);

/// Exact summaries must use the durable lane when the page snapshot omits time.
pub(super) fn summary_requires_durable(window: &TimeRange) -> bool {
    window.end - window.start > MAX_SCANNED
}
/// Retries of one chunk refused for lane capacity (not for its size).
const TRANSIENT_RETRIES: usize = 3;
/// Snapshots one tenant builds at once, process-wide.
const TENANT_SNAPSHOT_PERMITS: usize = 2;
/// NAN-3262: snapshots one tenant reads dossier cards for at once. A separate
/// pool: a new page's cards (seconds) never queue behind another snapshot's
/// long event read.
const TENANT_CARD_PERMITS: usize = 2;
/// NAN-3262: how long the cards' prevalence lookup may take before the
/// dossier falls back to the event read's baseline for rarity.
const CARD_RARITY_BUDGET: Duration = Duration::from_secs(5);
/// Borderline artifacts resolved by the bounded global read.
const GLOBAL_CANDIDATES: usize = 50;
/// Newest time the global read covers.
const GLOBAL_WINDOW: chrono::Duration = chrono::Duration::hours(1);
/// Row bound of the global read.
const GLOBAL_ROW_CAP: usize = 5_000;
/// NAN-3252: how long the best-effort artifact enrichment (host-identity
/// resolution and the global read, run concurrently) may take after the
/// prevalence baseline is in. Either one that has not answered by then is
/// dropped: the artifact summary keeps its baseline / in-window / raw-IP
/// lower bounds, which is what a failed read already produced.
const ENRICH_BUDGET: Duration = Duration::from_secs(5);
/// NAN-3291: an IP joins a host's identity only if at most this many
/// distinct hosts carry it in the window (NAT, proxy, loopback, DHCP churn
/// otherwise widen a workstation to everyone behind the same address).
const WIDEN_MAX_HOSTS_PER_IP: usize = 3;
/// NAN-3291: most identity values (hosts, IPs, MACs, users) a widened asset
/// binds. Widening stops (quietly, with a note) rather than grow past it.
const WIDEN_MAX_VALUES: usize = 32;
/// NAN-3291: most new IPs one widening step checks the fan-out of.
const WIDEN_MAX_IP_CHECKS: usize = 16;
/// NAN-3291: IPs per fan-out read (one hintable equality each).
const WIDEN_FANOUT_IPS_PER_READ: usize = 8;
/// NAN-3291: group bound of one fan-out read. A read that reaches it proves
/// nothing about its quieter IPs, so none of them is accepted.
const WIDEN_FANOUT_GROUP_CAP: usize = 1_000;
/// NAN-3291: the analyst-facing note when widening stops at its cap.
pub(super) const WIDENING_CAPPED_NOTE: &str =
    "Many linked identities \u{2014} matching on this asset's own host/IP";
/// How often a client polls an incomplete view.
pub(super) const RETRY_AFTER_MS: u64 = 1_500;

#[derive(Debug, Clone)]
enum Failure {
    Exhausted(String),
    Unavailable(String),
    Invalid(String),
    /// NAN-3282: the typed view-memory refusals keep their HTTP contract
    /// (413 narrow-the-window / 503 retry) through the shared snapshot.
    TooLarge { view: String, needed_bytes: u64, budget_bytes: u64 },
    MemoryBusy { view: String, waited_ms: u64 },
}

impl Failure {
    fn from_error(error: &SearchError) -> Self {
        match error {
            SearchError::ResourceExhausted(message) => Self::Exhausted(message.clone()),
            SearchError::ServiceUnavailable(message) => Self::Unavailable(message.clone()),
            SearchError::ViewTooLarge { view, needed_bytes, budget_bytes } => Self::TooLarge {
                view: view.clone(),
                needed_bytes: *needed_bytes,
                budget_bytes: *budget_bytes,
            },
            SearchError::ViewMemoryBusy { view, waited_ms } => {
                Self::MemoryBusy { view: view.clone(), waited_ms: *waited_ms }
            }
            other => Self::Invalid(other.to_string()),
        }
    }

    fn to_error(&self) -> SearchError {
        match self {
            Self::Exhausted(message) => SearchError::ResourceExhausted(message.clone()),
            Self::Unavailable(message) => SearchError::ServiceUnavailable(message.clone()),
            Self::Invalid(message) => SearchError::SqlValidationError(message.clone()),
            Self::TooLarge { view, needed_bytes, budget_bytes } => SearchError::ViewTooLarge {
                view: view.clone(),
                needed_bytes: *needed_bytes,
                budget_bytes: *budget_bytes,
            },
            Self::MemoryBusy { view, waited_ms } => {
                SearchError::ViewMemoryBusy { view: view.clone(), waited_ms: *waited_ms }
            }
        }
    }
}

/// Environment prevalence of one artifact from the snapshot's lookup.
#[derive(Debug, Clone)]
pub(super) struct BaselinePrevalence {
    pub host_count: u64,
    pub is_rare: bool,
    pub score: u8,
    pub first_seen: DateTime<Utc>,
}

/// The build stage a view depends on (NAN-3252).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Stage {
    /// Every row the snapshot will read is read (event count + facets).
    Rows,
    /// Rows plus the prevalence baseline (the dossier's rarity).
    Baseline,
    /// Everything, including identity resolution and the global read.
    All,
}

/// Per-phase cost of one snapshot, for the build log line (NAN-3262).
#[derive(Default, Debug, Clone, Copy)]
struct Timing {
    card_queue_ms: u128,
    ident_ms: u128,
    ident_rows: usize,
    ident_bytes: usize,
    cards_ms: u128,
    card_rows: usize,
    card_bytes: usize,
    card_reads: usize,
    rows_queue_ms: u128,
}

#[derive(Default)]
struct State {
    rows: Arc<Vec<Value>>,
    /// NAN-3262: dossier cards read so far (lake aggregates).
    cards: BTreeMap<Section, Arc<Vec<Value>>>,
    /// Cards that failed; their sections come from the rows.
    card_failed: BTreeSet<Section>,
    /// NAN-3276: cards that reached their group cap. They keep their busiest
    /// groups (lower bounds) and the dossier says so; they never fall back
    /// to the rows.
    card_truncated: BTreeSet<Section>,
    /// Every card read has finished (read or failed).
    cards_done: bool,
    /// The cards' artifacts have their prevalence baseline.
    card_rarity: bool,
    timing: Timing,
    covered_start: Option<DateTime<Utc>>,
    rows_done: bool,
    baseline_done: bool,
    complete: bool,
    failure: Option<Failure>,
    notes: Vec<String>,
    /// NAN-3271: the rarity baseline lookup failed; the views finish
    /// without it and say so.
    rarity_note: Option<String>,
    baseline: Arc<BTreeMap<String, BaselinePrevalence>>,
    in_window: Option<Arc<BTreeMap<String, BTreeSet<String>>>>,
    global: Arc<BTreeMap<String, u64>>,
    /// NAN-3291: the full-window count aggregates (`Section::Counts`,
    /// `Section::CountUsers`) read so far, with whether each stayed under
    /// its group cap.
    counts: BTreeMap<Section, (Arc<Vec<Value>>, bool)>,
    /// NAN-3291: count reads that failed (the summary falls back to rows).
    counts_failed: BTreeSet<Section>,
    /// NAN-3291: identity values widening already rejected (shared IPs), so
    /// later chunks do not re-check them.
    widening_rejected: BTreeSet<(String, String)>,
    /// NAN-3291: widening reached [`WIDEN_MAX_VALUES`].
    widening_capped: bool,
}

pub(super) struct AssetSnapshot {
    window: TimeRange,
    enrich_budget: Duration,
    state: Mutex<State>,
    version: tokio::sync::watch::Sender<u64>,
}

/// What a view reads from a snapshot at one instant.
pub(super) struct SnapshotView {
    /// Newest first, deduplicated by `metadata.uid`.
    pub rows: Arc<Vec<Value>>,
    /// Every row the snapshot will read is in `rows` (NAN-3252).
    pub rows_complete: bool,
    /// The prevalence baseline is in `baseline` (NAN-3252).
    pub baseline_complete: bool,
    pub complete: bool,
    pub window: TimeRange,
    pub covered_start: Option<DateTime<Utc>>,
    pub note: Option<String>,
    /// NAN-3271: why rarity is missing, when the baseline lookup failed.
    pub rarity_note: Option<String>,
    pub baseline: Arc<BTreeMap<String, BaselinePrevalence>>,
    /// Resolved in-window host sets; `None` until the scan completes (views
    /// then count unresolved hosts from the rows).
    pub in_window: Option<Arc<BTreeMap<String, BTreeSet<String>>>>,
    pub global: Arc<BTreeMap<String, u64>>,
    /// NAN-3262: the dossier cards read so far.
    pub cards: BTreeMap<Section, Arc<Vec<Value>>>,
    /// Every card was read in full and its rarity is known: the dossier is
    /// final from the cards alone, whatever the event read is doing.
    pub cards_complete: bool,
    /// The cards' artifacts have their prevalence baseline.
    pub card_rarity: bool,
    /// NAN-3276: cards that reached their group cap (lower bounds).
    pub card_truncated: BTreeSet<Section>,
    /// NAN-3291: the full-window count aggregates read so far.
    pub counts: BTreeMap<Section, (Arc<Vec<Value>>, bool)>,
    /// NAN-3291: count reads that failed.
    pub counts_failed: BTreeSet<Section>,
}

impl SnapshotView {
    /// Whether everything `stage` depends on has been built.
    pub fn reached(&self, stage: Stage) -> bool {
        match stage {
            Stage::Rows => self.rows_complete,
            Stage::Baseline => self.rows_complete && self.baseline_complete,
            Stage::All => self.complete,
        }
    }

    /// Progress of the whole snapshot (the artifact summary's stage).
    pub fn progress(&self) -> ProductViewProgress {
        self.progress_at(Stage::All)
    }

    /// Progress of a view that depends on `stage` only: it is final as soon
    /// as that stage is, whatever later enrichment is still running.
    pub fn progress_at(&self, stage: Stage) -> ProductViewProgress {
        let complete = self.reached(stage);
        ProductViewProgress {
            complete,
            covered_start: self
                .covered_start
                .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true)),
            covered_end: Some(
                self.window
                    .end
                    .to_rfc3339_opts(chrono::SecondsFormat::Micros, true),
            ),
            retry_after_ms: (!complete).then_some(RETRY_AFTER_MS),
            note: self.note.clone(),
        }
    }
}

impl AssetSnapshot {
    fn new(window: TimeRange) -> Self {
        Self::with_enrich_budget(window, ENRICH_BUDGET)
    }

    fn with_enrich_budget(window: TimeRange, enrich_budget: Duration) -> Self {
        Self {
            window,
            enrich_budget,
            state: Mutex::new(State::default()),
            version: tokio::sync::watch::channel(0).0,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn finished(&self) -> bool {
        let state = self.lock();
        state.complete || state.failure.is_some()
    }

    fn update(&self, apply: impl FnOnce(&mut State)) {
        apply(&mut self.lock());
        self.version.send_modify(|version| *version += 1);
    }

    #[cfg(test)]
    fn view(&self) -> Result<SnapshotView, SearchError> {
        self.view_with(false)
    }

    /// `cards_suffice`: a reader that needs only the dossier cards (the
    /// dossier) still reads a snapshot whose later event read failed, once
    /// every card is in.
    fn view_with(&self, cards_suffice: bool) -> Result<SnapshotView, SearchError> {
        let state = self.lock();
        if let Some(failure) = &state.failure {
            let cards_complete = state.cards_done
                && state.card_rarity
                && state.card_failed.is_empty();
            if !(cards_suffice && cards_complete) {
                return Err(failure.to_error());
            }
        }
        Ok(SnapshotView {
            rows: state.rows.clone(),
            rows_complete: state.rows_done || state.complete,
            baseline_complete: state.baseline_done || state.complete,
            complete: state.complete,
            window: self.window.clone(),
            covered_start: state.covered_start,
            note: (!state.notes.is_empty()).then(|| state.notes.join("; ")),
            rarity_note: state.rarity_note.clone(),
            baseline: state.baseline.clone(),
            in_window: state.in_window.clone(),
            global: state.global.clone(),
            cards: state.cards.clone(),
            cards_complete: state.cards_done
                && state.card_rarity
                && state.card_failed.is_empty()
                && Section::CARDS
                    .iter()
                    .chain([&Section::Identity])
                    .all(|section| state.cards.contains_key(section)),
            card_rarity: state.card_rarity,
            card_truncated: state.card_truncated.clone(),
            counts: state.counts.clone(),
            counts_failed: state.counts_failed.clone(),
        })
    }

    fn failed(&self) -> bool {
        self.lock().failure.is_some()
    }

    /// Anything a view can paint: rows or a dossier card (NAN-3262).
    fn paintable(&self) -> bool {
        let state = self.lock();
        !state.rows.is_empty() || !state.cards.is_empty()
    }

    #[cfg(test)]
    async fn wait(&self, budget: Duration) -> Result<SnapshotView, SearchError> {
        self.wait_with(budget, false).await
    }

    async fn wait_with(
        &self,
        budget: Duration,
        cards_suffice: bool,
    ) -> Result<SnapshotView, SearchError> {
        let mut changes = self.version.subscribe();
        let deadline = tokio::time::Instant::now() + budget;
        // A completed chunk is paintable evidence: do not hold it until the
        // whole dossier/prevalence scan completes or the wait budget expires.
        while !self.finished() && !self.paintable() {
            match tokio::time::timeout_at(deadline, changes.changed()).await {
                Ok(Ok(())) => continue,
                // Timed out, or the builder is gone (it always finishes the
                // state first, so a dropped sender means finished).
                _ => break,
            }
        }
        self.view_with(cards_suffice)
    }
}

fn tenant_permits(pool: &'static str, tenant: &str) -> Arc<tokio::sync::Semaphore> {
    static PERMITS: OnceLock<
        Mutex<BTreeMap<(&'static str, String), Arc<tokio::sync::Semaphore>>>,
    > = OnceLock::new();
    let permits = if pool == "cards" {
        TENANT_CARD_PERMITS
    } else {
        TENANT_SNAPSHOT_PERMITS
    };
    PERMITS
        .get_or_init(|| Mutex::new(BTreeMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .entry((pool, tenant.to_string()))
        .or_insert_with(|| Arc::new(tokio::sync::Semaphore::new(permits)))
        .clone()
}

/// NAN-3262: how far apart two windows of the same asset may be and still
/// share one snapshot: a "last hour" re-sent a few seconds later (a second
/// panel, a script, a reload) must join the snapshot in flight, not start
/// another one that queues behind it for the same tenant permits.
fn window_tolerance(window: &TimeRange) -> chrono::Duration {
    ((window.end - window.start) / 60)
        .max(chrono::Duration::seconds(5))
        .min(chrono::Duration::seconds(120))
}

fn windows_close(left: &TimeRange, right: &TimeRange) -> bool {
    let tolerance = window_tolerance(left).min(window_tolerance(right));
    (left.start - right.start).abs() <= tolerance && (left.end - right.end).abs() <= tolerance
}

/// NAN-3262: the single-flight snapshot for `base` (tenant, scope and the
/// asset's predicate) over `window`. A live snapshot of the same asset whose
/// window is within [`window_tolerance`] is shared; otherwise one is created
/// under the exact window's key. `fresh` (an explicit refresh) replaces a
/// finished snapshot but still joins one in flight; a failed one is never
/// joined (it is already forgotten). Returns `(key, handle, created)`.
fn shared_snapshot(
    base: &str,
    window: &TimeRange,
    fresh: bool,
) -> (String, Arc<AssetSnapshot>, bool) {
    static ALIASES: OnceLock<Mutex<HashMap<String, Vec<(TimeRange, String)>>>> = OnceLock::new();
    let mut aliases = ALIASES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    aliases.retain(|_, entries| {
        entries.retain(|(_, key)| lake_view_peek::<AssetSnapshot>(key).is_some());
        !entries.is_empty()
    });
    let entries = aliases.entry(base.to_string()).or_default();
    for (existing_window, key) in entries.iter() {
        if !windows_close(existing_window, window) {
            continue;
        }
        if let Some(handle) = lake_view_peek::<AssetSnapshot>(key) {
            if !handle.failed() && !(fresh && handle.finished()) {
                return (key.clone(), handle, false);
            }
        }
    }
    let key = lake_view_cache_key(&[
        base,
        &window.start.timestamp_micros().to_string(),
        &window.end.timestamp_micros().to_string(),
    ]);
    let (handle, created) = lake_view_handle(
        &key,
        |existing: &AssetSnapshot| existing.failed() || (fresh && existing.finished()),
        || AssetSnapshot::new(window.clone()),
    );
    if created {
        entries.retain(|(_, existing)| existing != &key);
        entries.push((window.clone(), key.clone()));
    }
    (key, handle, created)
}

/// One card read's result.
struct CardRead {
    rows: Vec<Value>,
    exact: bool,
    bytes: usize,
}

fn json_bytes(rows: &[Value]) -> usize {
    serde_json::to_vec(rows).map_or(0, |bytes| bytes.len())
}

/// Newest-first chunks tiling `[start, end]`, reading at most
/// [`MAX_SCANNED`] back from `end`. The second value is the skipped older
/// range's end when the window is longer than that.
fn chunks(window: &TimeRange) -> (Vec<(DateTime<Utc>, DateTime<Utc>)>, Option<DateTime<Utc>>) {
    let floor = (window.end - MAX_SCANNED).max(window.start);
    let mut out = Vec::new();
    let mut boundary = window.end;
    while boundary > floor {
        let start = (boundary - CHUNK).max(floor);
        out.push((start, boundary));
        boundary = start;
    }
    if out.is_empty() {
        out.push((window.start, window.end));
    }
    (out, (floor > window.start).then_some(floor))
}

/// Identities that belong to the asset: an endpoint's IP/MAC paired with the
/// SAME endpoint's hostname (and, for a user asset, the row's user on the
/// source endpoint).
///
/// Unlike `collect_identity_dtos` this never pairs an endpoint IP with
/// `device.hostname`: on a logon (3002) or an inbound connection the device
/// is the asset while `src_endpoint.ip` is the REMOTE peer, so that pairing
/// widened a server to every client that touched it (and past the identity
/// cap).
fn widening_identities(rows: &[Value]) -> Vec<Value> {
    let mut out = BTreeMap::<(String, String, String, String), Value>::new();
    for row in rows {
        let user = lake_string(row, "actor.user.name")
            .or_else(|| lake_string(row, "user.name"))
            .unwrap_or_default();
        let time = lake_string(row, "time").unwrap_or_default();
        let source = lake_string(row, "metadata.log_source").unwrap_or_default();
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            let ip = lake_string(row, &format!("{endpoint}.ip")).unwrap_or_default();
            let hostname = lake_string(row, &format!("{endpoint}.hostname")).unwrap_or_default();
            let mac = lake_string(row, &format!("{endpoint}.mac")).unwrap_or_default();
            // The acting user is paired with the SOURCE endpoint only: the
            // destination of a user's connection is someone else's machine.
            let user = if endpoint == "src_endpoint" {
                user.clone()
            } else {
                String::new()
            };
            if hostname.is_empty() && user.is_empty() {
                continue;
            }
            if ip.is_empty() && mac.is_empty() {
                continue;
            }
            out.entry((ip.clone(), hostname.clone(), user.clone(), mac.clone()))
                .or_insert_with(|| {
                    json!({
                        "ip": ip, "hostname": hostname, "user": user, "mac": mac,
                        "first_seen": time, "last_seen": time, "source": source,
                    })
                });
        }
    }
    out.into_values().collect()
}

fn row_uid(row: &Value) -> Option<String> {
    lake_string(row, "metadata.uid").filter(|uid| !uid.is_empty())
}

fn transient(error: &SearchError) -> bool {
    match error {
        SearchError::ResourceExhausted(message) => message.contains("concurrency"),
        SearchError::ServiceUnavailable(_)
        | SearchError::TenantLakePublicationDegraded(_)
        // NAN-3282: other views hold the process memory budget; pause, retry.
        | SearchError::ViewMemoryBusy { .. } => true,
        _ => false,
    }
}

fn splittable(error: &SearchError) -> bool {
    matches!(
        error,
        SearchError::ResourceExhausted(_) | SearchError::Timeout(_)
    ) && !transient(error)
}

/// An exact count alone does not prove that a limited page contains every
/// matching row. Only a fully returned exact result can supply snapshot totals.
fn chunk_complete(response: &SearchResponse) -> bool {
    response.total_count_exact && response.total_count == response.results.len() as u64
}

/// The Asset event summary (count + facets) over snapshot rows, with the same
/// labels as the grouped aggregate (`asset_facets_from_grouped_rows`).
pub(super) fn facets_from_rows(rows: &[Value]) -> (u64, AssetFacets) {
    let mut kinds = BTreeMap::<&'static str, u64>::new();
    let mut sources = BTreeMap::<String, u64>::new();
    let mut users = BTreeMap::<String, u64>::new();
    for row in rows {
        let kind = match lake_u64(row, "class_uid") {
            Some(1001) => "FILE",
            Some(1007) => "PROCESS",
            Some(3002) if lake_status_failed(row) => "AUTH_FAILURE",
            Some(3002) => "AUTH_SUCCESS",
            Some(4001) => "NETWORK",
            Some(4003) => "DNS",
            Some(6003) => "CLOUD_API",
            _ => "OTHER",
        };
        *kinds.entry(kind).or_default() += 1;
        if let Some(source) = lake_string(row, "metadata.log_source").filter(|v| !v.is_empty()) {
            *sources.entry(source).or_default() += 1;
        }
        if let Some(user) = lake_string(row, "actor.user.name")
            .or_else(|| lake_string(row, "user.name"))
            .filter(|v| !v.is_empty())
        {
            *users.entry(user).or_default() += 1;
        }
    }
    let ranked = |counts: BTreeMap<String, u64>| {
        let mut values = counts.into_iter().collect::<Vec<_>>();
        values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        values.truncate(50);
        values
    };
    let mut event_kind = kinds
        .into_iter()
        .map(|(kind, count)| (kind.to_string(), count))
        .collect::<Vec<_>>();
    event_kind.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    (
        rows.len() as u64,
        AssetFacets {
            source_type: ranked(sources),
            event_kind,
            user: ranked(users),
        },
    )
}

/// NAN-3291: where the event-stream total and facets stand.
pub(super) enum StreamCounts {
    /// The count aggregates are still being read.
    Pending,
    /// Exact over the whole window, from the count aggregates.
    Exact(u64, AssetFacets),
    /// The aggregates failed (or could not be exact): the summary falls back
    /// to the snapshot rows and their notes.
    Unavailable,
}

/// NAN-3291: the event-stream total and facets from the full-window count
/// aggregates, never from the capped rows.
pub(super) fn stream_counts(view: &SnapshotView) -> StreamCounts {
    if view.counts_failed.contains(&Section::Counts) {
        return StreamCounts::Unavailable;
    }
    let Some((rows, exact)) = view.counts.get(&Section::Counts) else {
        return StreamCounts::Pending;
    };
    if !exact {
        return StreamCounts::Unavailable;
    }
    let users = match view.counts.get(&Section::CountUsers) {
        Some((users, _)) => asset_facets_from_grouped_rows(users).1.user,
        // The total and type / source facets stand without the user facet.
        None if view.counts_failed.contains(&Section::CountUsers) => Vec::new(),
        None => return StreamCounts::Pending,
    };
    let (total, mut facets) = asset_facets_from_grouped_rows(rows);
    facets.user = users;
    StreamCounts::Exact(total, facets)
}

/// NAN-3291: the progress of exact stream counts: complete over the whole
/// scanned window, with no note (nothing about them is partial).
pub(super) fn stream_counts_progress(view: &SnapshotView) -> ProductViewProgress {
    let micros = |time: DateTime<Utc>| time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
    let floor = (view.window.end - MAX_SCANNED).max(view.window.start);
    ProductViewProgress {
        complete: true,
        covered_start: Some(micros(floor)),
        covered_end: Some(micros(view.window.end)),
        retry_after_ms: None,
        note: None,
    }
}

/// A count rendered with thousands separators (`50,000`).
fn thousands(value: usize) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// NAN-3291: is `ip` an address that can identify one host? Loopback,
/// unspecified, link-local, multicast and broadcast addresses are carried by
/// every host and never widen an asset.
fn widenable_ip(ip: &str) -> bool {
    match ip.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(ip)) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_link_local()
                || ip.is_multicast()
                || ip.is_broadcast())
        }
        Ok(std::net::IpAddr::V6(ip)) => {
            !(ip.is_loopback()
                || ip.is_unspecified()
                || ip.is_multicast()
                || (ip.segments()[0] & 0xffc0) == 0xfe80)
        }
        Err(_) => false,
    }
}

/// The short, lower-case form of a hostname: `WS-1.corp.local` and `ws-1`
/// are one host when counting an IP's hosts.
fn short_host(host: &str) -> String {
    host.trim()
        .split('.')
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
}

/// NAN-3291: distinct hosts per IP from fan-out group rows (`<endpoint>.ip`,
/// `<endpoint>.hostname`), both endpoints pooled.
fn ip_host_fanout(rows: &[Value]) -> BTreeMap<String, BTreeSet<String>> {
    let mut hosts = BTreeMap::<String, BTreeSet<String>>::new();
    for row in rows {
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            let (Some(ip), Some(host)) = (
                lake_string(row, &format!("{endpoint}.ip")).filter(|v| !v.is_empty()),
                lake_string(row, &format!("{endpoint}.hostname"))
                    .map(|host| short_host(&host))
                    .filter(|v| !v.is_empty()),
            ) else {
                continue;
            };
            hosts.entry(ip.trim().to_ascii_lowercase()).or_default().insert(host);
        }
    }
    hosts
}

/// NAN-3291: one bounded widening step's candidates. `learned` are endpoint
/// tuples (see [`widening_identities`]); only those DIRECTLY related to the
/// seed that add a value the asset does not bind yet survive, one minimal
/// identity per new value: `(kind, lower-case value, identity)`.
fn widening_candidates(
    identifier_field: &str,
    identifier_value: &str,
    identities: &[Value],
    learned: &[Value],
    rejected: &BTreeSet<(String, String)>,
) -> Vec<(String, String, Value)> {
    let Some(semantic) = asset_semantic(identifier_field) else {
        return Vec::new();
    };
    let Ok(current) = asset_identity_values(identifier_field, identifier_value, identities) else {
        return Vec::new();
    };
    let bound = |kind: &str, value: &str| {
        current
            .get(kind)
            .is_some_and(|values| values.iter().any(|v| v.eq_ignore_ascii_case(value)))
    };
    // The field that relates a tuple to the seed stays on every candidate.
    let relating = match semantic {
        "host" => "hostname",
        other => other,
    };
    let mut seen = BTreeSet::<(String, String)>::new();
    let mut out = Vec::new();
    for identity in learned {
        let Some(anchor) = identity.get(relating).and_then(Value::as_str) else {
            continue;
        };
        for (kind, value) in related_identity_values(semantic, identifier_value, identity) {
            let key = (kind.to_string(), value.to_ascii_lowercase());
            if bound(kind, &value) || rejected.contains(&key) || !seen.insert(key.clone()) {
                continue;
            }
            let field = if kind == "host" { "hostname" } else { kind };
            let mut candidate = serde_json::Map::new();
            candidate.insert(relating.to_string(), json!(anchor));
            candidate.insert(field.to_string(), json!(value));
            out.push((key.0, key.1, Value::Object(candidate)));
        }
    }
    out
}

/// NAN-3291: what one widening step decided.
struct Widening {
    identities: Vec<Value>,
    changed: bool,
    capped: bool,
}

/// Per-artifact `(count, first_ts, last_ts, is_hash)` over the rows.
fn artifact_occurrence_summary(rows: &[Value]) -> BTreeMap<String, (u64, String, String, bool)> {
    let (hashes, domains) = collect_artifact_occurrences(rows);
    let mut occurrences = BTreeMap::<String, (u64, String, String, bool)>::new();
    for (artifact, timestamp, is_hash) in hashes
        .iter()
        .map(|(value, time)| (value, time, true))
        .chain(domains.iter().map(|(value, time)| (value, time, false)))
    {
        let entry = occurrences.entry(artifact.clone()).or_insert((
            0,
            timestamp.clone(),
            timestamp.clone(),
            is_hash,
        ));
        entry.0 += 1;
        if timestamp < &entry.1 {
            entry.1 = timestamp.clone();
        }
        if timestamp > &entry.2 {
            entry.2 = timestamp.clone();
        }
    }
    occurrences
}

/// The artifact summary JSON the `asset-artifacts` handler reads, from a
/// snapshot view. Host counts take the largest of three lower bounds: the
/// prevalence baseline, the distinct hosts in this asset's own rows, and the
/// bounded global read (see `query_lake_asset_artifact_summary` history,
/// NAN-2361 layers 1-3).
pub(super) fn artifact_summary_json(view: &SnapshotView) -> Value {
    let occurrences = artifact_occurrence_summary(&view.rows);
    let unresolved;
    let in_window = match &view.in_window {
        Some(resolved) => resolved.as_ref(),
        None => {
            unresolved = in_window_host_counts(&view.rows);
            &unresolved
        }
    };
    let mut hash_rows = Vec::new();
    let mut domain_rows = Vec::new();
    for (artifact, (count, first_ts, last_ts, is_hash)) in occurrences {
        let baseline = view.baseline.get(&artifact);
        let in_window_hosts = in_window.get(&artifact).map(|hosts| hosts.len() as u64);
        let (mut host_count, mut source) = match (baseline, in_window_hosts) {
            (Some(baseline), Some(hosts)) if hosts > baseline.host_count => (hosts, "in-window"),
            (Some(baseline), _) => (baseline.host_count, "baseline"),
            (None, Some(hosts)) if hosts > 0 => (hosts, "in-window"),
            _ => (0, "none"),
        };
        if let Some(global) = view.global.get(&artifact).copied() {
            if global > host_count {
                host_count = global;
                source = "global";
            }
        }
        let env_first_seen = baseline.map(|baseline| {
            baseline
                .first_seen
                .to_rfc3339_opts(chrono::SecondsFormat::Micros, true)
        });
        let row = json!({
            "artifact": artifact,
            "first_ts": lake_time_rfc3339(&first_ts),
            "last_ts": lake_time_rfc3339(&last_ts),
            "count": count,
            "host_count": host_count,
            "prevalence_source": source,
            "in_window_hosts": in_window_hosts,
            "env_first_seen": env_first_seen,
        });
        if is_hash {
            hash_rows.push(row);
        } else {
            domain_rows.push(row);
        }
    }
    let mut progress = view.progress();
    with_rarity_note(&mut progress, view);
    json!({
        "hash_total": hash_rows.len(),
        "domain_total": domain_rows.len(),
        "hashes": hash_rows,
        "domains": domain_rows,
        "progress": progress,
    })
}

/// The dossier over a snapshot view.
pub(super) fn dossier_from_view(view: &SnapshotView) -> Result<AssetDossier, SearchError> {
    // Read rows means the snapshot stopped reading, not that it covered every
    // event. Paint partials while it reads; once it stops with incomplete
    // coverage, the handler must admit the exact durable assembler. (The
    // notes are final once the rows are: enrichment never adds one.)
    // NAN-3262: complete cards aggregate the whole window in the lake, so a
    // capped event read no longer makes the dossier incomplete.
    if !view.cards_complete && view.reached(Stage::Rows) && view.note.is_some() {
        return Err(SearchError::ResourceExhausted(
            "Asset dossier snapshot is incomplete and requires the durable lane".to_string(),
        ));
    }
    let prevalence = view
        .baseline
        .iter()
        .map(|(artifact, baseline)| {
            (
                artifact.clone(),
                (baseline.host_count, baseline.is_rare, baseline.score),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut dossier =
        SearchService::assemble_lake_asset_dossier_from(&view.rows, &view.window, &prevalence);
    // NAN-3262: every card read so far replaces its section; sections whose
    // card is missing keep what the rows give.
    cards::overlay_cards(&mut dossier, &view.cards, &view.window, &prevalence);
    // Rarity needs a prevalence lookup (the cards' or the rows'): until then
    // no process or domain can be proven common, so the partial dossier
    // leaves the rare lists empty rather than calling everything rare.
    // The dossier never reads the identity resolution or the global read, so
    // it is final once the baseline is in (NAN-3252).
    // NAN-3271: a failed baseline lookup proves nothing common either.
    if !(view.card_rarity || (view.reached(Stage::Baseline) && view.rarity_note.is_none())) {
        dossier.processes.rare = 0;
        dossier.processes.rare_list.clear();
        dossier.network.new_domains = 0;
    }
    dossier.progress = Some(dossier_progress(view));
    Ok(dossier)
}

/// The note for a failed rarity baseline lookup (NAN-3271). Kept apart from
/// the coverage notes: those mark a short event read (and send an
/// incomplete dossier to the durable lane), a missing rarity does not.
fn rarity_unavailable_note(error: &str) -> String {
    if error.contains("product_state_warming") {
        format!("{RARITY_UNAVAILABLE} prevalence is still warming")
    } else {
        format!("{RARITY_UNAVAILABLE} the prevalence lookup failed")
    }
}

/// The dossier's progress: final once every card is in (NAN-3262), or, when
/// a card failed, once the event read's baseline is (NAN-3252).
fn dossier_progress(view: &SnapshotView) -> ProductViewProgress {
    let mut progress = dossier_coverage_progress(view);
    // The cards' own lookup succeeded: their rarity stands.
    if !view.card_rarity {
        with_rarity_note(&mut progress, view);
    }
    progress
}

/// NAN-3271: a finished view whose rarity baseline lookup failed says so.
fn with_rarity_note(progress: &mut ProductViewProgress, view: &SnapshotView) {
    if let Some(rarity) = &view.rarity_note {
        progress.note = Some(match progress.note.take() {
            Some(note) => format!("{note}; {rarity}"),
            None => rarity.clone(),
        });
    }
}

fn dossier_coverage_progress(view: &SnapshotView) -> ProductViewProgress {
    if view.cards_complete {
        let micros = |time: DateTime<Utc>| time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true);
        let floor = (view.window.end - MAX_SCANNED).max(view.window.start);
        return ProductViewProgress {
            complete: true,
            covered_start: Some(micros(floor)),
            covered_end: Some(micros(view.window.end)),
            retry_after_ms: None,
            note: {
                let notes = [
                    (floor > view.window.start).then(|| {
                        format!(
                            "covers the newest {} h of the window",
                            MAX_SCANNED.num_hours()
                        )
                    }),
                    cards::truncation_note(&view.card_truncated),
                ]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>();
                (!notes.is_empty()).then(|| notes.join("; "))
            },
        };
    }
    view.progress_at(Stage::Baseline)
}

/// Artifacts that still look rare after the baseline and the in-window
/// counts, busiest first, bounded to [`GLOBAL_CANDIDATES`]: the only ones the
/// tenant-wide global read is worth spending on.
fn global_candidates(
    occurrences: &BTreeMap<String, (u64, String, String, bool)>,
    baseline: &BTreeMap<String, BaselinePrevalence>,
    in_window: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<(String, bool, u64)> {
    let mut candidates = occurrences
        .iter()
        .filter(|(artifact, _)| {
            let from_baseline = baseline.get(*artifact).map_or(0, |b| b.host_count);
            let from_window = in_window
                .get(*artifact)
                .map_or(0, |hosts| hosts.len() as u64);
            from_baseline.max(from_window) <= ASSET_GLOBAL_DISCOVERY_HOST_CEILING
        })
        .map(|(artifact, (count, _, _, is_hash))| (artifact.clone(), *is_hash, *count))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| right.2.cmp(&left.2).then_with(|| left.0.cmp(&right.0)));
    candidates.truncate(GLOBAL_CANDIDATES);
    candidates
}

fn baseline_map(
    found: Vec<crate::prevalence::PrevalenceData>,
) -> BTreeMap<String, BaselinePrevalence> {
    found
        .into_iter()
        .map(|row| {
            (
                row.artifact,
                BaselinePrevalence {
                    host_count: row.host_count,
                    is_rare: row.is_rare,
                    score: row.prevalence_score,
                    first_seen: row.first_seen,
                },
            )
        })
        .collect()
}

/// The bounded global read's nPL: distinct hosts per candidate artifact.
/// NAN-3276: one path-grouped predicate (see
/// [`build_global_artifacts_predicate`]), so the query compiles for any
/// candidate count; the candidates themselves stay capped at
/// [`GLOBAL_CANDIDATES`] (the busiest still-rare artifacts).
fn global_artifact_hosts_query(candidates: &[(String, bool, u64)]) -> Result<String, SearchError> {
    let predicate = build_global_artifacts_predicate(
        candidates
            .iter()
            .map(|(artifact, is_hash, _)| (artifact.as_str(), *is_hash)),
    )?;
    Ok(format!(
        "{predicate} | stats count() by file.hashes.value, process.file.hashes.value, \
         actor.process.file.hashes.value, query.hostname, http_request.url.hostname, \
         url.hostname, dst_endpoint.hostname, device.hostname, src_endpoint.hostname, \
         src_endpoint.ip"
    ))
}

/// Everything that identifies one snapshot's result.
pub(super) struct SnapshotRequest<'a> {
    pub identifier_field: &'a str,
    pub identifier_value: &'a str,
    pub identities: &'a [Value],
    pub time_range: &'a TimeRange,
    pub scope: &'a ScopeSet,
}

impl SearchService {
    /// NAN-3262: the snapshot identity without its window. Keyed on the
    /// resolved predicate, not the raw request: two requests that bind the
    /// same identities (another identifier field of the same host, the same
    /// identities in another order or with other metadata) read the same
    /// events and share one snapshot.
    fn asset_snapshot_base(&self, predicate: &str, scope: &ScopeSet) -> String {
        let tenant = self
            .lake_query
            .assigned_tenant_id()
            .unwrap_or("dedicated")
            .to_string();
        lake_view_cache_key(&["asset-snapshot-v2", &tenant, &format!("{scope:?}"), predicate])
    }

    /// The shared snapshot for this asset view, started if needed, after
    /// waiting at most `wait` for it to finish.
    pub(super) async fn lake_asset_snapshot(
        &self,
        request: SnapshotRequest<'_>,
        fresh: bool,
        wait: Duration,
    ) -> Result<SnapshotView, SearchError> {
        self.lake_asset_snapshot_with(request, fresh, wait, false).await
    }

    /// [`Self::lake_asset_snapshot`] for a reader that needs only the dossier
    /// cards (see [`AssetSnapshot::view_with`]).
    pub(super) async fn lake_asset_snapshot_with(
        &self,
        request: SnapshotRequest<'_>,
        fresh: bool,
        wait: Duration,
        cards_suffice: bool,
    ) -> Result<SnapshotView, SearchError> {
        // Validate before anything is registered or spawned.
        let predicate = build_lake_asset_predicate(
            request.identifier_field,
            request.identifier_value,
            request.identities,
            &self.lake_asset_rangeless(),
        )?;
        let base = self.asset_snapshot_base(&predicate, request.scope);
        let (key, handle, created) = shared_snapshot(&base, request.time_range, fresh);
        if created {
            // A long window takes longer than the TTL to build: pin the
            // handle while it builds so a poll never starts a second build;
            // the TTL starts when it finishes.
            lake_view_pin(&key, &handle, true);
            let service = self.clone();
            let handle = handle.clone();
            let tenant = self
                .lake_query
                .assigned_tenant_id()
                .unwrap_or("dedicated")
                .to_string();
            let field = request.identifier_field.to_string();
            let value = request.identifier_value.to_string();
            let identities = request.identities.to_vec();
            let scope = request.scope.clone();
            // NAN-3282: the shared build outlives the request that started
            // it, so it carries its own view-memory ledger: every lake answer
            // it reads (cards + rows) is charged before decode and reserved
            // from the process budget until the build finishes.
            let ledger = crate::search::view_memory::ViewMemoryBudget::global().ledger("asset-snapshot");
            tokio::spawn(crate::search::view_memory::scope(ledger, async move {
                // NAN-3262: the dossier cards first, under their own permits,
                // then the event read (which starts from the cards' widening).
                let queued = std::time::Instant::now();
                let card_permits = tenant_permits("cards", &tenant);
                let card_permit = card_permits.acquire_owned().await;
                handle.update(|state| state.timing.card_queue_ms = queued.elapsed().as_millis());
                let identities = service
                    .build_asset_cards(&handle, &field, &value, identities, &scope)
                    .await;
                drop(card_permit);
                let queued = std::time::Instant::now();
                let permits = tenant_permits("rows", &tenant);
                let _permit = permits.acquire_owned().await;
                handle.update(|state| state.timing.rows_queue_ms = queued.elapsed().as_millis());
                let result = service
                    .build_asset_snapshot(&handle, &field, &value, identities, &scope)
                    .await;
                match result {
                    Ok(()) => {
                        handle.update(|state| state.complete = true);
                        lake_view_pin(&key, &handle, false);
                    }
                    Err(error) => {
                        tracing::warn!(error = %error, "lean asset snapshot failed");
                        let too_large = matches!(error, SearchError::ViewTooLarge { .. });
                        handle.update(|state| state.failure = Some(Failure::from_error(&error)));
                        if too_large {
                            // NAN-3282: deterministic for this window. Keep the
                            // refusal for the cache TTL so a polling client
                            // gets it again instead of re-reading the same
                            // over-budget window every poll.
                            lake_view_pin(&key, &handle, false);
                        } else {
                            lake_view_forget(&key, &handle);
                        }
                    }
                }
            }));
        }
        handle.wait_with(wait, cards_suffice).await
    }

    /// NAN-3262: the dossier cards, as lake aggregates, before the event read.
    ///
    /// 1. The identity card over the asset's own predicate. Its endpoint
    ///    tuples widen the asset to its own IPs / MACs (the same pairing as
    ///    the event read's `widening_identities`).
    /// 2. Every other card over the widened predicate, at most
    ///    [`cards::CARD_CONCURRENCY`] in flight, each published as it lands.
    /// 3. The prevalence baseline of the cards' artifacts (rarity).
    ///
    /// Best effort: a card that fails is recorded and its section comes from
    /// the event read. A card over its group cap keeps its busiest groups and
    /// is marked truncated (NAN-3276). Returns the widened identities the
    /// event read starts from.
    async fn build_asset_cards(
        &self,
        handle: &AssetSnapshot,
        identifier_field: &str,
        identifier_value: &str,
        identities: Vec<Value>,
        scope: &ScopeSet,
    ) -> Vec<Value> {
        let started = std::time::Instant::now();
        let window = handle.window.clone();
        let floor = (window.end - MAX_SCANNED).max(window.start);
        let range = TimeRange::new(floor, window.end);
        let fail_all = |error: &SearchError| {
            tracing::warn!(error = %error, "lean asset dossier cards unavailable; the dossier reads the event rows");
            handle.update(|state| {
                state.card_failed.insert(Section::Identity);
                state.card_failed.extend(Section::CARDS);
                state.counts_failed.extend([Section::Counts, Section::CountUsers]);
                state.cards_done = true;
            });
        };
        let slices = match build_lake_asset_predicate_slices(
            identifier_field,
            identifier_value,
            &identities,
            &self.lake_asset_rangeless(),
        ) {
            Ok(slices) => slices,
            Err(error) => {
                fail_all(&error);
                return identities;
            }
        };

        // 1. Identity + widening.
        let phase = std::time::Instant::now();
        let queries = slices.iter().map(|slice| cards::identity_query(slice)).collect::<Vec<_>>();
        let mut identities = identities;
        let mut card_reads = 0usize;
        match self
            .read_card(Section::Identity, &queries, cards::CARD_GROUP_CAP, &range, scope)
            .await
        {
            Ok(read) => {
                card_reads += queries.len();
                // NAN-3291: bounded -- only identities tightly bound to the
                // seed (no shared IPs), never past the cap.
                let learned = widening_identities(&read.rows);
                let widened = self
                    .widen_identities(
                        handle,
                        identifier_field,
                        identifier_value,
                        &identities,
                        &learned,
                        &range,
                        scope,
                    )
                    .await;
                identities = widened.identities;
                let (rows, bytes, exact) = (read.rows.len(), read.bytes, read.exact);
                handle.update(|state| {
                    state.cards.insert(Section::Identity, Arc::new(read.rows));
                    if !exact {
                        state.card_truncated.insert(Section::Identity);
                    }
                    state.timing.ident_ms = phase.elapsed().as_millis();
                    state.timing.ident_rows = rows;
                    state.timing.ident_bytes = bytes;
                });
            }
            Err(error) => {
                tracing::warn!(error = %error, "lean asset identity card failed");
                handle.update(|state| {
                    state.card_failed.insert(Section::Identity);
                });
            }
        }

        // 2. Every other card over the widened predicate.
        let phase = std::time::Instant::now();
        let slices = build_lake_asset_predicate_slices(identifier_field, identifier_value, &identities, &self.lake_asset_rangeless())
            .unwrap_or(slices);
        let mut plan = cards::card_plan(&slices, &window);
        // NAN-3291: the stream's exact total and facets right after the
        // timeline (both are the page's first paint); the user facet last.
        let mut counts = cards::count_plan(&slices).into_iter();
        if let Some(total) = counts.next() {
            plan.insert(1.min(plan.len()), total);
        }
        plan.extend(counts);
        let (mut card_rows, mut card_bytes) = (0usize, 0usize);
        let card_range = &range;
        let mut reads = futures::stream::iter(plan.into_iter().map(|card| async move {
            let result = self
                .read_card(card.section, &card.queries, card.limit, card_range, scope)
                .await;
            (card.section, card.queries.len(), result)
        }))
        .buffer_unordered(cards::CARD_CONCURRENCY);
        while let Some((section, calls, result)) = reads.next().await {
            if matches!(section, Section::Counts | Section::CountUsers) {
                match result {
                    Ok(read) => {
                        card_reads += calls;
                        card_bytes += read.bytes;
                        if !read.exact {
                            tracing::warn!(view = section.view(), cap = cards::CARD_GROUP_CAP, "lean asset count read reached its group cap");
                        }
                        handle.update(|state| {
                            state.counts.insert(section, (Arc::new(read.rows), read.exact));
                        });
                    }
                    Err(error) => {
                        tracing::warn!(view = section.view(), error = %error, "lean asset count read failed; the stream counts read the event rows");
                        handle.update(|state| {
                            state.counts_failed.insert(section);
                        });
                    }
                }
                continue;
            }
            match result {
                Ok(read) => {
                    card_reads += calls;
                    card_rows += read.rows.len();
                    card_bytes += read.bytes;
                    // NAN-3276: a card over its group cap keeps its busiest
                    // groups as a bounded aggregate (the timeline is bucket x
                    // lane counts; it never needs rows). Falling back to the
                    // event read sent a busy host's dossier to the durable
                    // lane, which then exceeded its heap envelope.
                    let exact = read.exact;
                    handle.update(|state| {
                        state.cards.insert(section, Arc::new(read.rows));
                        if !exact {
                            state.card_truncated.insert(section);
                        }
                    });
                    if !exact {
                        tracing::warn!(card = section.view(), cap = cards::CARD_GROUP_CAP, "lean asset card reached its group cap; that section shows its busiest groups as lower bounds");
                    }
                }
                Err(error) => {
                    tracing::warn!(card = section.view(), error = %error, "lean asset card failed; that section reads the event rows");
                    handle.update(|state| {
                        state.card_failed.insert(section);
                    });
                }
            }
        }
        drop(reads);
        let cards_ms = phase.elapsed().as_millis();

        // 3. Rarity for the cards' artifacts.
        let phase = std::time::Instant::now();
        let artifacts = cards::card_artifacts(&handle.lock().cards);
        let rarity = match (artifacts.is_empty(), self.prevalence_lookup.as_ref()) {
            (true, _) | (_, None) => Some(BTreeMap::new()),
            (false, Some(lookup)) => match tokio::time::timeout(
                CARD_RARITY_BUDGET,
                lookup.lookup(
                    &artifacts,
                    PrevalenceTimeWindow::TwentyFourHours,
                    &ArtifactScope::from_scope(scope),
                ),
            )
            .await
            {
                Ok(Ok(found)) => Some(baseline_map(found)),
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "lean asset card prevalence lookup failed; rarity waits for the event read");
                    None
                }
                Err(_) => {
                    tracing::warn!("lean asset card prevalence lookup exceeded its budget; rarity waits for the event read");
                    None
                }
            },
        };
        let rarity_ms = phase.elapsed().as_millis();
        let failed = {
            let mut failed = 0;
            handle.update(|state| {
                if let Some(found) = rarity {
                    let mut merged = state.baseline.as_ref().clone();
                    merged.extend(found);
                    state.baseline = Arc::new(merged);
                    state.card_rarity = true;
                }
                state.cards_done = true;
                state.timing.cards_ms = cards_ms;
                state.timing.card_rows = card_rows;
                state.timing.card_bytes = card_bytes;
                state.timing.card_reads = card_reads;
                failed = state.card_failed.len();
            });
            failed
        };
        let timing = handle.lock().timing;
        tracing::info!(
            slices = slices.len(),
            card_reads,
            failed_cards = failed,
            artifacts = artifacts.len(),
            queue_ms = timing.card_queue_ms,
            ident_ms = timing.ident_ms,
            ident_rows = timing.ident_rows,
            ident_bytes = timing.ident_bytes,
            cards_ms,
            card_rows,
            card_bytes,
            rarity_ms,
            total_ms = started.elapsed().as_millis(),
            "lean asset dossier cards built"
        );
        identities
    }

    /// One card: its query over every predicate slice, concatenated (the
    /// slices are disjoint). A grouped card is exact only when no slice's
    /// groups reached `limit`; a recent-events page keeps the newest
    /// [`cards::CARD_RECENT`]. A refusal for lane capacity is retried like an
    /// event chunk.
    async fn read_card(
        &self,
        section: Section,
        queries: &[String],
        limit: usize,
        range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<CardRead, SearchError> {
        let mut out = CardRead {
            rows: Vec::new(),
            exact: true,
            bytes: 0,
        };
        for query in queries {
            let mut attempts = 0usize;
            let response = loop {
                let result = if section.is_page() {
                    self.execute_lake_view_query_cursor_page_projected(
                        query.clone(),
                        range,
                        scope,
                        section.view(),
                        limit,
                        0,
                        None,
                    )
                    .await
                } else {
                    self.execute_lake_view_query(query.clone(), range, scope, section.view(), limit)
                        .await
                };
                match result {
                    Err(error) if transient(&error) && attempts < TRANSIENT_RETRIES => {
                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(500 * attempts as u64)).await;
                    }
                    other => break other?,
                }
            };
            out.bytes += json_bytes(&response.results);
            if !section.is_page() {
                out.exact &= response.total_count_exact && response.results.len() < limit;
            }
            out.rows.extend(response.results);
        }
        if section.is_page() {
            out.rows = cards::newest_first(out.rows);
            out.rows.truncate(cards::CARD_RECENT);
        }
        Ok(out)
    }

    async fn build_asset_snapshot(
        &self,
        handle: &AssetSnapshot,
        identifier_field: &str,
        identifier_value: &str,
        identities: Vec<Value>,
        scope: &ScopeSet,
    ) -> Result<(), SearchError> {
        let started = std::time::Instant::now();
        let window = handle.window.clone();
        let (chunks, skipped_before) = chunks(&window);
        if let Some(floor) = skipped_before {
            handle.update(|state| {
                state.notes.push(format!(
                    "Showing detail from the newest {} h of the window (since {})",
                    MAX_SCANNED.num_hours(),
                    floor.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                ))
            });
        }
        let mut identities = identities;
        let mut widening = true;
        // NAN-3291: the window widening measures an IP's hosts over.
        let scanned = TimeRange::new((window.end - MAX_SCANNED).max(window.start), window.end);
        let mut predicate =
            build_lake_asset_predicate(identifier_field, identifier_value, &identities, &self.lake_asset_rangeless())?;
        // NAN-3262: read through hintable slices (see
        // `build_lake_asset_predicate_slices`).
        let mut slices =
            build_lake_asset_predicate_slices(identifier_field, identifier_value, &identities, &self.lake_asset_rangeless())?;
        let mut seen = HashSet::<String>::new();
        let mut total = 0usize;
        let mut scan_bytes = 0usize;
        let mut scan_reads = 0usize;
        for (start, end) in chunks {
            scan_reads += slices.len();
            let (mut rows, mut chunk_exact) =
                self.scan_asset_slices(&slices, start, end, scope).await?;
            if widening {
                // NAN-3291: the same bounded step as the identity card: only
                // identities tightly bound to the seed, never past the cap.
                let learned = widening_identities(&rows);
                let widened = self
                    .widen_identities(
                        handle,
                        identifier_field,
                        identifier_value,
                        &identities,
                        &learned,
                        &scanned,
                        scope,
                    )
                    .await;
                if widened.capped {
                    widening = false;
                }
                if widened.changed {
                    let next = build_lake_asset_predicate(
                        identifier_field,
                        identifier_value,
                        &widened.identities,
                        &self.lake_asset_rangeless(),
                    )?;
                    if next != predicate {
                        // Rows only the widened predicate matches, in the
                        // chunk that revealed the new identities.
                        let next_slices = build_lake_asset_predicate_slices(
                            identifier_field,
                            identifier_value,
                            &widened.identities,
                            &self.lake_asset_rangeless(),
                        )?;
                        let delta = next_slices
                            .iter()
                            .map(|slice| format!("({slice}) AND NOT ({predicate})"))
                            .collect::<Vec<_>>();
                        scan_reads += delta.len();
                        let (delta_rows, delta_exact) =
                            self.scan_asset_slices(&delta, start, end, scope).await?;
                        rows.extend(delta_rows);
                        chunk_exact &= delta_exact;
                        rows.sort_by(|left, right| {
                            lake_string(right, "time").cmp(&lake_string(left, "time"))
                        });
                        predicate = next;
                        slices = next_slices;
                    }
                    identities = widened.identities;
                }
            }
            let mut kept = Vec::with_capacity(rows.len());
            for row in rows {
                if let Some(uid) = row_uid(&row) {
                    if !seen.insert(uid) {
                        continue;
                    }
                }
                kept.push(row);
            }
            let room = LAKE_ASSET_SCAN_CAP.saturating_sub(total);
            let full = kept.len() >= room;
            kept.truncate(room);
            total += kept.len();
            scan_bytes += json_bytes(&kept);
            let covered = if full {
                kept.last()
                    .and_then(|row| lake_string(row, "time"))
                    .and_then(|time| parse_lake_asset_time(&time))
                    .unwrap_or(start)
            } else {
                start
            };
            handle.update(|state| {
                Arc::make_mut(&mut state.rows).extend(kept);
                state.covered_start = Some(covered);
                // NAN-3291: analyst-facing; the stream counts come from the
                // full-window aggregates, so these only qualify event detail.
                if !chunk_exact && !full {
                    state.notes.push(format!(
                        "Some events between {} and {} could not be read in time; detail there may be partial",
                        start.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                        end.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ));
                }
                if full {
                    state.notes.push(format!(
                        "Showing detail from the newest {} events (since {}); counts cover the full window",
                        thousands(LAKE_ASSET_SCAN_CAP),
                        covered.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                    ));
                }
            });
            if full {
                break;
            }
        }
        let rows = handle.lock().rows.clone();
        let scan_ms = started.elapsed().as_millis();
        // NAN-3252: the event summary (count + facets) is final now.
        handle.update(|state| state.rows_done = true);

        // Prevalence baseline for every artifact on the asset (one call).
        let phase = std::time::Instant::now();
        let occurrences = artifact_occurrence_summary(&rows);
        if !occurrences.is_empty() {
            if let Some(lookup) = self.prevalence_lookup.as_ref() {
                let artifacts = occurrences.keys().cloned().collect::<Vec<_>>();
                // NAN-3271: rarity is best-effort. A failed baseline (the
                // cell answers `product_state_warming` until its 24h window
                // is published) must not fail the snapshot: the timeline,
                // panels and completion do not depend on it.
                match lookup
                    .lookup(
                        &artifacts,
                        PrevalenceTimeWindow::TwentyFourHours,
                        &ArtifactScope::from_scope(scope),
                    )
                    .await
                {
                    Ok(found) => {
                        let baseline = baseline_map(found);
                        // The cards' lookup may already hold some of these.
                        handle.update(|state| {
                            let mut merged = state.baseline.as_ref().clone();
                            merged.extend(baseline);
                            state.baseline = Arc::new(merged);
                        });
                    }
                    Err(error) => {
                        tracing::warn!(
                            error = %error,
                            artifacts = artifacts.len(),
                            "lean asset snapshot prevalence lookup failed; completing without the rarity baseline"
                        );
                        let note = rarity_unavailable_note(&error.to_string());
                        handle.update(|state| state.rarity_note = Some(note));
                    }
                }
            }
        }
        // The dossier (identity, panels and rarity) is final now.
        handle.update(|state| state.baseline_done = true);
        let baseline_ms = phase.elapsed().as_millis();

        // Best-effort artifact enrichment: the host-identity resolution and
        // the bounded global read run CONCURRENTLY under one budget. The
        // global candidates are chosen from the raw in-window counts (rows
        // without a host name count as one "unknown" host), so the global
        // read does not wait for the resolution.
        let phase = std::time::Instant::now();
        let baseline = handle.lock().baseline.clone();
        let raw_in_window = in_window_host_counts(&rows);
        let candidates = global_candidates(&occurrences, &baseline, &raw_in_window);
        let deadline = tokio::time::Instant::now() + handle.enrich_budget;
        let global_read = async {
            if candidates.is_empty() {
                return None;
            }
            match tokio::time::timeout_at(
                deadline,
                self.global_artifact_hosts(&candidates, &window, scope),
            )
            .await
            {
                Ok(Ok(global)) => Some(global),
                Ok(Err(error)) => {
                    tracing::warn!(error = %error, "asset global prevalence read failed; keeping baseline/in-window counts");
                    None
                }
                Err(_) => {
                    tracing::warn!("asset global prevalence read exceeded the enrichment budget; keeping baseline/in-window counts");
                    None
                }
            }
        };
        let (widened, global) = tokio::join!(
            self.resolve_asset_host_identities(&rows, &window, scope, deadline),
            global_read,
        );
        let in_window = in_window_host_counts(&widened);
        handle.update(|state| {
            state.in_window = Some(Arc::new(in_window));
            if let Some(global) = global {
                state.global = Arc::new(global);
            }
        });
        let timing = handle.lock().timing;
        tracing::info!(
            rows = rows.len(),
            artifacts = occurrences.len(),
            global_candidates = candidates.len(),
            card_queue_ms = timing.card_queue_ms,
            ident_ms = timing.ident_ms,
            ident_rows = timing.ident_rows,
            ident_bytes = timing.ident_bytes,
            cards_ms = timing.cards_ms,
            card_reads = timing.card_reads,
            card_rows = timing.card_rows,
            card_bytes = timing.card_bytes,
            rows_queue_ms = timing.rows_queue_ms,
            scan_reads,
            scan_rows = total,
            scan_bytes,
            scan_ms,
            baseline_ms,
            enrich_ms = phase.elapsed().as_millis(),
            total_ms = started.elapsed().as_millis(),
            "lean asset snapshot built"
        );
        Ok(())
    }

    /// NAN-3291: one bounded identity-widening step from `learned` endpoint
    /// tuples. An identity joins only when it is DIRECTLY related to the seed
    /// and adds a value the asset does not bind yet; an IP only when it can
    /// identify one host (not loopback / link-local / multicast) and at most
    /// [`WIDEN_MAX_HOSTS_PER_IP`] hosts carry it in `range` (one bounded
    /// fan-out aggregate); for an IP seed, its hosts only when the seed IP
    /// itself is that tight. The bound set never grows past
    /// [`WIDEN_MAX_VALUES`]: at the cap widening stops and the snapshot says
    /// so in plain words ([`WIDENING_CAPPED_NOTE`]).
    async fn widen_identities(
        &self,
        handle: &AssetSnapshot,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        learned: &[Value],
        range: &TimeRange,
        scope: &ScopeSet,
    ) -> Widening {
        let mut out = Widening {
            identities: identities.to_vec(),
            changed: false,
            capped: false,
        };
        let known_rejected = handle.lock().widening_rejected.clone();
        let mut candidates = widening_candidates(
            identifier_field,
            identifier_value,
            identities,
            learned,
            &known_rejected,
        );
        if candidates.is_empty() {
            return out;
        }
        let semantic = asset_semantic(identifier_field).unwrap_or_default();
        let seed_ip = identifier_value.trim().to_ascii_lowercase();
        let mut rejected = BTreeSet::<(String, String)>::new();
        candidates.retain(|(kind, value, _)| {
            let keep = kind != "ip" || widenable_ip(value);
            if !keep {
                rejected.insert((kind.clone(), value.clone()));
            }
            keep
        });
        let new_hosts = candidates.iter().filter(|(kind, _, _)| kind == "host").count();
        let mut check = candidates
            .iter()
            .filter(|(kind, _, _)| kind == "ip")
            .map(|(_, value, _)| value.clone())
            .collect::<Vec<_>>();
        if semantic == "ip" && new_hosts > 0 {
            check.insert(0, seed_ip.clone());
        }
        let mut unique = BTreeSet::new();
        check.retain(|ip| unique.insert(ip.clone()));
        if check.len() > WIDEN_MAX_IP_CHECKS {
            check.truncate(WIDEN_MAX_IP_CHECKS);
            out.capped = true;
        }
        let tight = if check.is_empty() {
            BTreeSet::new()
        } else {
            self.tight_ips(&check, range, scope).await
        };
        let seed_ip_tight = semantic == "ip"
            && widenable_ip(&seed_ip)
            && tight.contains(&seed_ip)
            && new_hosts <= WIDEN_MAX_HOSTS_PER_IP;
        candidates.retain(|(kind, value, _)| {
            let keep = match kind.as_str() {
                "ip" => tight.contains(value),
                "host" if semantic == "ip" => seed_ip_tight,
                _ => true,
            };
            if !keep {
                rejected.insert((kind.clone(), value.clone()));
            }
            keep
        });
        let bound = asset_identity_values(identifier_field, identifier_value, identities)
            .map(|values| values.values().map(BTreeSet::len).sum::<usize>())
            .unwrap_or(usize::MAX);
        let room = WIDEN_MAX_VALUES
            .saturating_sub(bound)
            .min(LAKE_ASSET_IDENTITY_CAP.saturating_sub(identities.len()));
        if candidates.len() > room {
            out.capped = true;
            for (kind, value, _) in candidates.drain(room..) {
                rejected.insert((kind, value));
            }
        }
        if !candidates.is_empty() {
            let mut next = identities.to_vec();
            next.extend(candidates.into_iter().map(|(_, _, identity)| identity));
            if build_lake_asset_predicate(identifier_field, identifier_value, &next, &self.lake_asset_rangeless()).is_ok() {
                out.identities = next;
                out.changed = true;
            } else {
                out.capped = true;
            }
        }
        let capped = out.capped;
        handle.update(|state| {
            state.widening_rejected.extend(rejected);
            if capped && !state.widening_capped {
                state.widening_capped = true;
                state.notes.push(WIDENING_CAPPED_NOTE.to_string());
            }
        });
        out
    }

    /// NAN-3291: the IPs of `ips` that at most [`WIDEN_MAX_HOSTS_PER_IP`]
    /// distinct hosts carry (on the same endpoint) in `range`. One grouped
    /// aggregate per endpoint and batch; a batch that reaches its group cap
    /// is re-read IP by IP, and an IP whose own read reaches it is shared.
    /// Best effort: a failed read accepts nothing.
    async fn tight_ips(
        &self,
        ips: &[String],
        range: &TimeRange,
        scope: &ScopeSet,
    ) -> BTreeSet<String> {
        let mut tight = BTreeSet::new();
        for batch in ips.chunks(WIDEN_FANOUT_IPS_PER_READ) {
            match self.ip_fanout_read(batch, range, scope).await {
                Ok((rows, true)) => {
                    let fanout = ip_host_fanout(&rows);
                    tight.extend(batch.iter().filter(|ip| {
                        fanout.get(*ip).map_or(0, BTreeSet::len) <= WIDEN_MAX_HOSTS_PER_IP
                    }).cloned());
                }
                Ok((_, false)) if batch.len() > 1 => {
                    for ip in batch {
                        match self.ip_fanout_read(std::slice::from_ref(ip), range, scope).await {
                            Ok((rows, true))
                                if ip_host_fanout(&rows).get(ip).map_or(0, BTreeSet::len)
                                    <= WIDEN_MAX_HOSTS_PER_IP =>
                            {
                                tight.insert(ip.clone());
                            }
                            Ok(_) => {}
                            Err(error) => {
                                tracing::warn!(error = %error, "lean asset widening fan-out read failed; not widening to that IP");
                            }
                        }
                    }
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(error = %error, "lean asset widening fan-out read failed; not widening to those IPs");
                }
            }
        }
        tight
    }

    /// One fan-out read: `(endpoint ip, endpoint hostname)` groups for
    /// `ips` on both endpoints, and whether every group fit.
    async fn ip_fanout_read(
        &self,
        ips: &[String],
        range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, bool), SearchError> {
        let literals = ips
            .iter()
            .map(|ip| safe_literal(ip, "asset identity IP"))
            .collect::<Result<Vec<_>, _>>()?;
        let mut rows = Vec::new();
        let mut complete = true;
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            let query = format!(
                "({}) | stats count() as {} by {endpoint}.ip, {endpoint}.hostname",
                literals
                    .iter()
                    .map(|literal| format!("{endpoint}.ip={literal}"))
                    .collect::<Vec<_>>()
                    .join(" OR "),
                cards::CARD_WEIGHT,
            );
            let response = self
                .execute_lake_view_query(
                    query,
                    range,
                    scope,
                    "asset-widening-fanout",
                    WIDEN_FANOUT_GROUP_CAP,
                )
                .await?;
            complete &= response.total_count_exact
                && response.results.len() < WIDEN_FANOUT_GROUP_CAP;
            rows.extend(response.results);
        }
        Ok((rows, complete))
    }

    /// One chunk read through every predicate slice, newest first. The slices
    /// are disjoint, so their rows concatenate without duplicates.
    async fn scan_asset_slices(
        &self,
        slices: &[String],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, bool), SearchError> {
        if let [slice] = slices {
            return self.scan_asset_chunk(slice, start, end, scope).await;
        }
        let mut rows = Vec::new();
        let mut exact = true;
        for slice in slices {
            let (slice_rows, slice_exact) = self.scan_asset_chunk(slice, start, end, scope).await?;
            rows.extend(slice_rows);
            exact &= slice_exact;
        }
        rows.sort_by(|left, right| lake_string(right, "time").cmp(&lake_string(left, "time")));
        Ok((rows, exact))
    }

    /// One newest-first chunk of projected asset rows. A chunk refused for
    /// its size is bisected (newer half first); one refused for lane capacity
    /// is retried after a short pause. Every call is a single lake request.
    async fn scan_asset_chunk(
        &self,
        predicate: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, bool), SearchError> {
        let query = format!(
            "{predicate} | table {} | sort -time",
            LAKE_ASSET_ROW_PROJECTION.join(",")
        );
        let mut out = Vec::new();
        let mut exact = true;
        // Stack: the newest range is on top.
        let mut pending = vec![(start, end, 0usize)];
        while let Some((from, to, attempts)) = pending.pop() {
            let result = self
                .execute_lake_view_query(
                    query.clone(),
                    &TimeRange::new(from, to),
                    scope,
                    "asset-snapshot",
                    LAKE_ASSET_SCAN_CAP,
                )
                .await;
            let width = to - from;
            match result {
                // A sorted response already filling the snapshot's entire row
                // budget is the newest preview we can retain. Splitting it
                // would reread the same dense range without making this capped
                // snapshot complete; the dossier will use the durable lane.
                Ok(response) if response.results.len() >= LAKE_ASSET_SCAN_CAP => {
                    exact = false;
                    out.extend(response.results);
                    out.truncate(LAKE_ASSET_SCAN_CAP);
                    break;
                }
                Ok(response) if chunk_complete(&response) || width <= MIN_CHUNK => {
                    exact &= chunk_complete(&response);
                    out.extend(response.results);
                    // The newest rows suffice once the snapshot row budget
                    // is full; never keep scanning older split ranges.
                    if out.len() >= LAKE_ASSET_SCAN_CAP {
                        exact &= out.len() == LAKE_ASSET_SCAN_CAP && pending.is_empty();
                        out.truncate(LAKE_ASSET_SCAN_CAP);
                        break;
                    }
                }
                Ok(_) => {
                    let middle = from + width / 2;
                    pending.push((from, middle, 0));
                    pending.push((middle, to, 0));
                }
                Err(error) if transient(&error) && attempts < TRANSIENT_RETRIES => {
                    tokio::time::sleep(Duration::from_millis(1_000 * (attempts as u64 + 1))).await;
                    pending.push((from, to, attempts + 1));
                }
                Err(error) if splittable(&error) && width > MIN_CHUNK => {
                    let middle = from + width / 2;
                    pending.push((from, middle, 0));
                    pending.push((middle, to, 0));
                }
                Err(error) => return Err(error),
            }
        }
        Ok((out, exact))
    }

    /// Distinct hosts per candidate artifact across the whole tenant, over
    /// the newest [`GLOBAL_WINDOW`] of the view: ONE lake call for every
    /// candidate (it replaced up to 250 full-window calls). A lower bound,
    /// like the other two layers; the largest of the three is reported.
    async fn global_artifact_hosts(
        &self,
        candidates: &[(String, bool, u64)],
        window: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<BTreeMap<String, u64>, SearchError> {
        let query = global_artifact_hosts_query(candidates)?;
        let range = TimeRange::new((window.end - GLOBAL_WINDOW).max(window.start), window.end);
        let response = self
            .execute_lake_view_query(
                query,
                &range,
                scope,
                "asset-artifact-global",
                GLOBAL_ROW_CAP,
            )
            .await?;
        let wanted = candidates
            .iter()
            .map(|(artifact, _, _)| artifact.clone())
            .collect::<BTreeSet<_>>();
        let mut hosts = BTreeMap::<String, BTreeSet<String>>::new();
        let mut unresolved = BTreeMap::<std::net::IpAddr, Vec<String>>::new();
        for row in &response.results {
            let mut artifacts = BTreeSet::new();
            for prefix in ["file", "process.file", "actor.process.file"] {
                artifacts.extend(
                    lake_hash_values(row, prefix)
                        .into_iter()
                        .map(|v| v.to_ascii_lowercase()),
                );
            }
            for path in LAKE_ASSET_DOMAIN_PATHS {
                if let Some(value) = lake_string(row, path) {
                    artifacts.insert(value.trim().to_ascii_lowercase());
                }
            }
            let matched = artifacts.intersection(&wanted).cloned().collect::<Vec<_>>();
            if matched.is_empty() {
                continue;
            }
            // Source side only: for a domain artifact the destination host
            // IS the artifact (see `discover_global_host_count`).
            let host = ["device.hostname", "src_endpoint.hostname"]
                .iter()
                .find_map(|path| lake_string(row, path).filter(|v| !v.trim().is_empty()))
                .map(|host| host.trim().to_ascii_lowercase());
            match host {
                Some(host) => {
                    for artifact in matched {
                        hosts.entry(artifact).or_default().insert(host.clone());
                    }
                }
                None => {
                    if let Some(ip) = lake_string(row, "src_endpoint.ip")
                        .and_then(|ip| ip.trim().parse::<std::net::IpAddr>().ok())
                    {
                        unresolved.entry(ip).or_default().extend(matched);
                    }
                }
            }
        }
        if !unresolved.is_empty() {
            let items = unresolved
                .keys()
                .map(|ip| (*ip, range.end))
                .collect::<Vec<_>>();
            let names = match self
                .resolve_lake_identity_ips(&items, scope.deny_set())
                .await
            {
                Ok(answers) => answers,
                Err(error) => {
                    tracing::warn!(error = %error, "global host identity resolution failed; counting raw IPs");
                    vec![None; items.len()]
                }
            };
            for ((ip, artifacts), answer) in unresolved.into_iter().zip(names) {
                let identity = answer
                    .map(|observation| observation.hostname.trim().to_ascii_lowercase())
                    .filter(|host| !host.is_empty())
                    .unwrap_or_else(|| ip.to_string());
                for artifact in artifacts {
                    hosts.entry(artifact).or_default().insert(identity.clone());
                }
            }
        }
        Ok(hosts
            .into_iter()
            .map(|(artifact, hosts)| (artifact, hosts.len() as u64))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(value: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(value)
            .unwrap()
            .with_timezone(&Utc)
    }

    #[tokio::test]
    async fn wait_returns_the_first_chunk_while_snapshot_work_continues() {
        let range = TimeRange::new(t("2026-09-30T00:00:00Z"), t("2026-09-30T01:00:00Z"));
        let handle = Arc::new(AssetSnapshot::new(range.clone()));
        let publisher = handle.clone();
        let task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            publisher.update(|state| {
                state.rows = Arc::new(vec![json!({"metadata.uid":"first"})]);
                state.covered_start = Some(range.end - chrono::Duration::minutes(5));
            });
        });
        let view = tokio::time::timeout(Duration::from_secs(1), handle.wait(Duration::from_secs(8)))
            .await.expect("first chunk must not wait for completion").unwrap();
        assert_eq!(view.rows.len(), 1);
        assert!(!view.complete);
        assert!(!view.progress().complete);
        task.await.unwrap();
        // Polls with paintable rows do not start another wait cycle.
        assert!(tokio::time::timeout(Duration::from_millis(100), handle.wait(Duration::from_secs(8))).await.is_ok());
    }

    #[test]
    fn exact_count_does_not_make_a_limited_chunk_complete() {
        let mut response: SearchResponse = serde_json::from_value(json!({
            "results": [{"metadata.uid": "one"}],
            "total_count": 2, "total_count_exact": true,
            "execution_time_ms": 0, "fields": [],
        }))
        .unwrap();
        assert!(!chunk_complete(&response));
        response.total_count = 1;
        assert!(chunk_complete(&response));
        response.total_count_exact = false;
        assert!(!chunk_complete(&response));
        response.results.clear();
        response.total_count = 0;
        assert!(
            !chunk_complete(&response),
            "an unverified empty page is not a miss"
        );
        response.total_count_exact = true;
        assert!(chunk_complete(&response));
    }

    #[cfg(feature = "enterprise")]
    #[tokio::test]
    async fn minimum_chunk_preserves_inexactness_and_source_scope() {
        use wiremock::{
            matchers::{header, method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let token_dir = tempfile::tempdir().unwrap();
        let token_file = token_dir.path().join("router.token");
        let token = "asset-snapshot-fixture-router-token";
        std::fs::write(&token_file, token).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool =
            crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ))
            .await
            .unwrap();
        let route = crate::search::LakeCellRoute {
            tenant_id: tenant,
            assignment_generation: 1,
            part_log_writer_epoch: 1,
            worker_revision: 1,
            assignment_fenced: true,
            cell_origin: server.uri(),
            query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
            router_token_file: token_file,
        };
        let service = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &route,
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        let scope = ScopeSet::from_denied(BTreeSet::from(["hidden-source".to_string()]));
        // A wide summary must reach the handler's durable fallback before any
        // snapshot scan; a recent page alone cannot establish its exact total.
        let week = TimeRange::new(t("2026-09-23T12:00:00Z"), t("2026-09-30T12:00:00Z"));
        for filters in [None, Some(AssetEventFilters::default())] {
            let result = service
                .query_lake_asset_events_summary(
                    "device.hostname", "host", &[], &week, filters.as_ref(), &scope, true,
                )
                .await;
            assert!(matches!(result, Err(SearchError::ResourceExhausted(_))));
        }
        for fresh in [false, true] {
            let result = service
                .query_lake_asset_dossier("device.hostname", "host", &[], &week, &scope, fresh)
                .await;
            assert!(matches!(result, Err(SearchError::ResourceExhausted(_))));
        }
        assert!(server.received_requests().await.unwrap().is_empty());
        assert!(!summary_requires_durable(&TimeRange::new(week.end - MAX_SCANNED, week.end)));
        assert!(summary_requires_durable(&TimeRange::new(
            week.end - MAX_SCANNED - chrono::Duration::microseconds(1), week.end,
        )));
        for has_more in [true, false] {
            Mock::given(method("POST"))
                .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
                .and(header("authorization", format!("Bearer {token}").as_str()))
                .respond_with(move |request: &wiremock::Request| {
                    let body: Value = serde_json::from_slice(&request.body).unwrap();
                    assert_eq!(body["tenant_id"], tenant.to_string());
                    assert_eq!(body["deny_source_types"], json!(["hidden-source"]));
                    ResponseTemplate::new(200).set_body_json(json!({
                        "ok": true, "request_id": body["request_id"], "tenant_id": tenant,
                        "route": "broad_npl", "source_mode": "parts",
                        "result": {"result_rows": 1,
                            "rows": [{"time": "2026-09-30 12:00:00.000000", "metadata.uid": "one"}],
                            "page_offset": 0, "page_limit": LAKE_ASSET_SCAN_CAP,
                            "page_has_more": has_more},
                    }))
                })
                .expect(2)
                .mount(&server)
                .await;
            let (rows, exact) = service
                .scan_asset_chunk(
                    "device.hostname=\"host\"",
                    t("2026-09-30T11:55:00Z"),
                    t("2026-09-30T12:00:00Z"),
                    &scope,
                )
                .await
                .unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(exact, !has_more);
            let snapshot = AssetSnapshot::new(TimeRange::new(
                t("2026-09-30T11:55:00Z"),
                t("2026-09-30T12:00:00Z"),
            ));
            service
                .build_asset_snapshot(&snapshot, "device.hostname", "host", vec![], &scope)
                .await
                .unwrap();
            snapshot.update(|state| state.complete = true);
            let view = snapshot.view().unwrap();
            assert_eq!(view.rows.len(), 1);
            assert_eq!(view.note.is_some(), has_more);
            let progress = view.progress();
            // The handler uses this exact predicate to advertise a total.
            assert_eq!(progress.complete && progress.note.is_none(), !has_more);
            let dossier = dossier_from_view(&view);
            if has_more {
                assert!(matches!(dossier, Err(SearchError::ResourceExhausted(_))));
            } else {
                assert!(dossier.unwrap().progress.unwrap().complete);
            }
            // The same inexact view remains paintable while it is still read.
            snapshot.update(|state| {
                state.complete = false;
                state.rows_done = false;
                state.baseline_done = false;
            });
            assert!(!dossier_from_view(&snapshot.view().unwrap()).unwrap().progress.unwrap().complete);
            server.reset().await;
        }

        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/query")))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["deny_source_types"], json!(["hidden-source"]));
                let rows = (0..LAKE_ASSET_SCAN_CAP).map(|index| json!({
                    "time": "2026-09-30 12:00:00.000000", "metadata.uid": format!("dense-{index}"),
                })).collect::<Vec<_>>();
                ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": tenant,
                    "route": "broad_npl", "source_mode": "parts",
                    "result": {"rows": rows, "result_rows": LAKE_ASSET_SCAN_CAP, "page_has_more": true},
                }))
            }).expect(1).mount(&server).await;
        let (rows, exact) = service.scan_asset_chunk(
            "device.hostname=\"host\"", t("2026-09-30T11:00:00Z"), t("2026-09-30T12:00:00Z"), &scope,
        ).await.unwrap();
        assert_eq!(rows.len(), LAKE_ASSET_SCAN_CAP);
        assert!(!exact, "a full preview must never claim exact coverage");
        server.verify().await;
        server.reset().await;

        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/tenants/{tenant}/query/v1/identity/resolve-batch"
            )))
            .and(header("authorization", format!("Bearer {token}").as_str()))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(body["tenant_id"], tenant.to_string());
                assert_eq!(body["deny_source_types"], json!(["hidden-source"]));
                let items = body["items"].as_array().unwrap();
                assert_eq!(
                    items.len(),
                    2,
                    "share duplicate time bindings, not different times"
                );
                let rows = items
                    .iter()
                    .enumerate()
                    .map(|(ordinal, item)| {
                        let early = item["reference_time"] == "2026-09-30T11:45:00+00:00";
                        json!({"ordinal": ordinal, "ip": item["ip"],
                            "hostname": if early {"old-host"} else {"new-host"},
                            "user": "", "mac": "", "source": "windows_sysmon",
                            "observed_at": item["reference_time"],
                        })
                    })
                    .collect::<Vec<_>>();
                ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": tenant,
                    "route": "identity_batch", "identity_index": {"state": "complete"},
                    "result": {"result_rows": rows.len(), "rows": rows},
                }))
            })
            .expect(1)
            .mount(&server)
            .await;
        let rows = vec![
            json!({"time": "2026-09-30T11:55:00Z", "src_endpoint.ip": "10.1.3.7", "query.hostname": "example.test"}),
            json!({"time": "2026-09-30T12:00:00Z", "src_endpoint.ip": "10.1.3.7", "query.hostname": "example.test"}),
            json!({"time": "2026-09-30T11:55:00Z", "src_endpoint.ip": "10.1.3.7", "query.hostname": "example.test"}),
        ];
        let widened = service
            .resolve_asset_host_identities(
                &rows,
                &TimeRange::new(t("2026-09-30T11:55:00Z"), t("2026-09-30T12:00:00Z")),
                &scope,
                tokio::time::Instant::now() + Duration::from_secs(30),
            )
            .await;
        assert_eq!(
            lake_string(&widened[0], "device.hostname").as_deref(),
            Some("old-host")
        );
        assert_eq!(
            lake_string(&widened[1], "device.hostname").as_deref(),
            Some("new-host")
        );
        assert_eq!(
            lake_string(&widened[2], "device.hostname").as_deref(),
            Some("old-host")
        );
        assert_eq!(in_window_host_counts(&widened)["example.test"].len(), 2);
    }

    #[test]
    fn chunks_tile_the_window_newest_first_and_cap_the_scan() {
        let window = TimeRange::new(t("2026-09-30T08:30:00Z"), t("2026-09-30T12:00:00Z"));
        let (chunks, skipped) = chunks(&window);
        assert_eq!(skipped, None);
        assert_eq!(chunks.first().unwrap().1, window.end);
        assert_eq!(chunks.last().unwrap().0, window.start);
        for pair in chunks.windows(2) {
            assert_eq!(pair[0].0, pair[1].1, "chunks are contiguous");
        }
        assert!(chunks.iter().all(|(start, end)| *end - *start <= CHUNK));
        assert_eq!(chunks.len(), 4);

        let week = TimeRange::new(t("2026-09-23T12:00:00Z"), t("2026-09-30T12:00:00Z"));
        let (week_chunks, skipped) = super::chunks(&week);
        assert_eq!(week_chunks.len(), 24);
        assert_eq!(skipped, Some(t("2026-09-29T12:00:00Z")));
        assert_eq!(week_chunks.last().unwrap().0, t("2026-09-29T12:00:00Z"));
    }

    #[test]
    fn widening_never_pairs_a_remote_peer_with_the_logging_device() {
        let logon = json!({
            "time": "2026-09-30 12:00:00.000000",
            "class_uid": 3002,
            "device": {"hostname": "srv-db02.corp.local"},
            "src_endpoint": {"ip": "10.9.9.9"},
        });
        let connection = json!({
            "time": "2026-09-30 12:00:01.000000",
            "class_uid": 4001,
            "device.hostname": "srv-db02.corp.local",
            "src_endpoint.hostname": "srv-db02.corp.local",
            "src_endpoint.ip": "10.2.1.35",
            "dst_endpoint.ip": "10.9.9.9",
        });
        let identities = widening_identities(&[logon, connection]);
        assert_eq!(identities.len(), 1, "{identities:?}");
        assert_eq!(identities[0]["ip"], "10.2.1.35");
        assert_eq!(identities[0]["hostname"], "srv-db02.corp.local");
        // And the predicate built from it binds the asset's own IP only.
        let predicate =
            build_lake_asset_predicate("src_endpoint.hostname", "srv-db02.corp.local", &identities, LAKE_ASSET_RANGELESS_FIELDS)
                .unwrap();
        assert!(predicate.contains("\"10.2.1.35\""), "{predicate}");
        assert!(!predicate.contains("10.9.9.9"), "{predicate}");
        // NAN-3252: Sysmon (endpoint classes) names the host on
        // `device.hostname` and leaves `src_endpoint.hostname` null, so a
        // host asset typed on either field must match both.
        for field in ["device.hostname", "src_endpoint.hostname"] {
            assert!(
                predicate.contains(&format!("{field}=\"srv-db02.corp.local\"")),
                "{field} missing: {predicate}"
            );
        }
    }

    #[test]
    fn facets_from_rows_match_the_aggregate_labels() {
        let rows = vec![
            json!({"class_uid": 3002, "status": "Failure", "metadata.log_source": "windows_event", "user.name": "a"}),
            json!({"class_uid": 3002, "status": "Success", "metadata.log_source": "windows_event", "actor.user.name": "b"}),
            json!({"class_uid": 1007, "metadata.log_source": "windows_sysmon"}),
            json!({"class_uid": 201001, "metadata.log_source": "windows_sysmon"}),
        ];
        let (total, facets) = facets_from_rows(&rows);
        assert_eq!(total, 4);
        let kinds = facets
            .event_kind
            .iter()
            .cloned()
            .collect::<BTreeMap<_, _>>();
        assert_eq!(kinds["AUTH_FAILURE"], 1);
        assert_eq!(kinds["AUTH_SUCCESS"], 1);
        assert_eq!(kinds["PROCESS"], 1);
        assert_eq!(kinds["OTHER"], 1);
        assert_eq!(facets.source_type[0], ("windows_event".to_string(), 2));
        assert_eq!(facets.user.len(), 2);
    }

    #[test]
    fn artifact_summary_takes_the_largest_lower_bound_and_reports_progress() {
        let rows = vec![
            json!({"time": "2026-09-30 12:00:00.000000", "device.hostname": "h1", "query.hostname": "rare.example"}),
            json!({"time": "2026-09-30 11:00:00.000000", "device.hostname": "h1", "query.hostname": "rare.example"}),
        ];
        let mut global = BTreeMap::new();
        global.insert("rare.example".to_string(), 7);
        let view = SnapshotView {
            rows: Arc::new(rows),
            rows_complete: true,
            baseline_complete: true,
            complete: false,
            window: TimeRange::new(t("2026-09-30T08:00:00Z"), t("2026-09-30T12:30:00Z")),
            covered_start: Some(t("2026-09-30T11:30:00Z")),
            note: None,
            rarity_note: None,
            baseline: Arc::new(BTreeMap::new()),
            in_window: None,
            global: Arc::new(global),
            cards: BTreeMap::new(),
            cards_complete: false,
            card_rarity: false,
            card_truncated: BTreeSet::new(),
            counts: BTreeMap::new(),
            counts_failed: BTreeSet::new(),
        };
        let summary = artifact_summary_json(&view);
        assert_eq!(summary["domain_total"], 1);
        let domain = &summary["domains"][0];
        assert_eq!(domain["count"], 2);
        assert_eq!(domain["host_count"], 7);
        assert_eq!(domain["prevalence_source"], "global");
        assert_eq!(domain["in_window_hosts"], 1);
        assert_eq!(summary["progress"]["complete"], false);
        assert_eq!(summary["progress"]["retry_after_ms"], RETRY_AFTER_MS);
    }

    #[test]
    fn each_view_completes_at_the_stage_it_reads() {
        let mut view = SnapshotView {
            rows: Arc::new(vec![json!({"time": "2026-09-30 12:00:00.000000", "metadata.uid": "one"})]),
            rows_complete: false,
            baseline_complete: false,
            complete: false,
            window: TimeRange::new(t("2026-09-30T11:00:00Z"), t("2026-09-30T12:00:00Z")),
            covered_start: Some(t("2026-09-30T11:00:00Z")),
            note: None,
            rarity_note: None,
            baseline: Arc::new(BTreeMap::new()),
            in_window: None,
            global: Arc::new(BTreeMap::new()),
            cards: BTreeMap::new(),
            cards_complete: false,
            card_rarity: false,
            card_truncated: BTreeSet::new(),
            counts: BTreeMap::new(),
            counts_failed: BTreeSet::new(),
        };
        // Coverage alone is not completion: the chunk may still be widening.
        for stage in [Stage::Rows, Stage::Baseline, Stage::All] {
            assert!(!view.progress_at(stage).complete, "{stage:?}");
            assert_eq!(view.progress_at(stage).retry_after_ms, Some(RETRY_AFTER_MS));
        }
        view.rows_complete = true;
        assert!(view.progress_at(Stage::Rows).complete);
        assert_eq!(view.progress_at(Stage::Rows).retry_after_ms, None);
        assert!(!view.progress_at(Stage::Baseline).complete);
        let partial = dossier_from_view(&view).unwrap();
        assert!(!partial.progress.unwrap().complete);
        view.baseline_complete = true;
        let dossier = dossier_from_view(&view).unwrap();
        assert!(dossier.progress.unwrap().complete, "the dossier never waits on enrichment");
        assert!(!view.progress().complete, "the artifact summary still does");
        assert_eq!(artifact_summary_json(&view)["progress"]["complete"], false);
        view.complete = true;
        assert_eq!(artifact_summary_json(&view)["progress"]["complete"], true);
        // Incomplete coverage sends the dossier to the durable lane as soon
        // as reading stops, not after the enrichment.
        view.complete = false;
        view.note = Some("limited to the newest 50000 events".to_string());
        assert!(matches!(dossier_from_view(&view), Err(SearchError::ResourceExhausted(_))));
    }

    #[test]
    fn global_candidates_keep_the_busiest_rare_artifacts() {
        let occurrences = (0..(GLOBAL_CANDIDATES + 10))
            .map(|index| {
                (
                    format!("d{index:03}.example"),
                    (index as u64, String::new(), String::new(), false),
                )
            })
            .chain([("common.example".to_string(), (10_000, String::new(), String::new(), false))])
            .collect::<BTreeMap<_, _>>();
        let mut baseline = BTreeMap::new();
        baseline.insert(
            "common.example".to_string(),
            BaselinePrevalence {
                host_count: 400,
                is_rare: false,
                score: 100,
                first_seen: t("2026-09-01T00:00:00Z"),
            },
        );
        let candidates = global_candidates(&occurrences, &baseline, &BTreeMap::new());
        assert_eq!(candidates.len(), GLOBAL_CANDIDATES);
        assert!(candidates.iter().all(|(artifact, _, _)| artifact != "common.example"));
        assert_eq!(candidates[0].0, format!("d{:03}.example", GLOBAL_CANDIDATES + 9));
    }

    struct EmptyPrevalence;

    #[async_trait::async_trait]
    impl crate::prevalence::PrevalenceLookup for EmptyPrevalence {
        async fn rarity_threshold(&self) -> u64 {
            5
        }

        async fn lookup(
            &self,
            _artifacts: &[String],
            _time_window: PrevalenceTimeWindow,
            _scope: &ArtifactScope,
        ) -> Result<Vec<crate::prevalence::PrevalenceData>, crate::prevalence::PrevalenceError> {
            Ok(Vec::new())
        }
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3252: a stalled identity resolution (a cell whose identity index
    /// is backfilling scans once per distinct row time) and a stalled
    /// tenant-wide global read no longer hold the page. The summary and the
    /// dossier are final as soon as the rows and the baseline are in; the
    /// artifact summary completes within the enrichment budget, both stalled
    /// reads running concurrently, with its in-window/raw-IP lower bounds.
    #[tokio::test]
    async fn stalled_enrichment_is_bounded_and_never_gates_the_summary_or_dossier() {
        use wiremock::{
            matchers::{body_string_contains, method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let token_dir = tempfile::tempdir().unwrap();
        let token_file = token_dir.path().join("router.token");
        std::fs::write(&token_file, "asset-snapshot-budget-router-token").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool =
            crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ))
            .await
            .unwrap();
        let route = crate::search::LakeCellRoute {
            tenant_id: tenant,
            assignment_generation: 1,
            part_log_writer_epoch: 1,
            worker_revision: 1,
            assignment_fenced: true,
            cell_origin: server.uri(),
            query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
            router_token_file: token_file,
        };
        let mut service = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &route,
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        service.set_prevalence_lookup(Arc::new(EmptyPrevalence));
        let scope = ScopeSet::from_denied(BTreeSet::new());
        let query_path = format!("/v1/tenants/{tenant}/query/v1/query");
        let stall = Duration::from_secs(30);

        // The tenant-wide global read stalls.
        Mock::given(method("POST"))
            .and(path(query_path.clone()))
            .and(body_string_contains("stats count() by"))
            .respond_with(ResponseTemplate::new(200).set_delay(stall).set_body_json(json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;
        // The asset's own rows answer at once: Sysmon rows naming the host on
        // `device.hostname`, plus an IP-only DNS row that needs resolution.
        Mock::given(method("POST"))
            .and(path(query_path.clone()))
            .and(body_string_contains("sort -time"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let rows = json!([
                    {"time": "2026-09-30 11:59:00.000000", "metadata.uid": "sysmon-1", "class_uid": 1007,
                     "metadata.log_source": "windows_sysmon", "device.hostname": "ws-it-083.corp.local",
                     "process.name": "svchost.exe"},
                    {"time": "2026-09-30 11:58:00.000000", "metadata.uid": "dns-1", "class_uid": 4003,
                     "metadata.log_source": "dns", "src_endpoint.ip": "10.1.3.7",
                     "query.hostname": "rare.example"},
                ]);
                ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": tenant,
                    "route": "broad_npl", "source_mode": "parts",
                    "result": {"result_rows": 2, "rows": rows, "page_offset": 0,
                        "page_limit": LAKE_ASSET_SCAN_CAP, "page_has_more": false},
                }))
            })
            .mount(&server)
            .await;
        // The identity resolution stalls.
        Mock::given(method("POST"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/identity/resolve-batch")))
            .respond_with(ResponseTemplate::new(200).set_delay(stall).set_body_json(json!({"ok": true})))
            .expect(1)
            .mount(&server)
            .await;

        let budget = Duration::from_millis(600);
        let snapshot = Arc::new(AssetSnapshot::with_enrich_budget(
            TimeRange::new(t("2026-09-30T11:00:00Z"), t("2026-09-30T12:00:00Z")),
            budget,
        ));
        let builder = {
            let service = service.clone();
            let snapshot = snapshot.clone();
            let scope = scope.clone();
            tokio::spawn(async move {
                service
                    .build_asset_snapshot(&snapshot, "src_endpoint.hostname", "ws-it-083.corp.local", vec![], &scope)
                    .await
            })
        };
        let started = std::time::Instant::now();
        let mut changes = snapshot.version.subscribe();
        // The summary and the dossier complete while both enrichment reads stall.
        loop {
            let view = snapshot.view().unwrap();
            if view.reached(Stage::Baseline) {
                assert!(!view.complete, "enrichment is still running");
                assert!(view.progress_at(Stage::Rows).complete);
                let dossier = dossier_from_view(&view).unwrap();
                assert!(dossier.progress.unwrap().complete);
                assert_eq!(
                    dossier.identity.hostname.as_deref(),
                    Some("ws-it-083.corp.local"),
                    "Sysmon names the host on device.hostname"
                );
                assert!(!artifact_summary_json(&view)["progress"]["complete"].as_bool().unwrap());
                break;
            }
            tokio::time::timeout(Duration::from_secs(5), changes.changed())
                .await
                .expect("rows and baseline must not wait on the stalled reads")
                .unwrap();
        }
        assert!(started.elapsed() < budget, "{:?}", started.elapsed());

        tokio::time::timeout(budget + Duration::from_secs(3), builder)
            .await
            .expect("the enrichment budget bounds the stalled reads")
            .unwrap()
            .unwrap();
        // One budget for both: they ran concurrently, not back to back.
        assert!(started.elapsed() < budget * 2, "{:?}", started.elapsed());
        snapshot.update(|state| state.complete = true);
        let summary = artifact_summary_json(&snapshot.view().unwrap());
        assert_eq!(summary["progress"]["complete"], true);
        let domain = &summary["domains"][0];
        assert_eq!(domain["artifact"], "rare.example");
        // The raw-IP fallback stands in for the unresolved host.
        assert_eq!(domain["in_window_hosts"], 1);
        assert_eq!(domain["prevalence_source"], "in-window");
    }

    /// The cell answers `product_state_warming` (its 24h window is not
    /// published yet, or the route waited on a longer one: NAN-3271).
    struct WarmingPrevalence;

    #[async_trait::async_trait]
    impl crate::prevalence::PrevalenceLookup for WarmingPrevalence {
        async fn rarity_threshold(&self) -> u64 {
            5
        }

        async fn lookup(
            &self,
            _artifacts: &[String],
            _time_window: PrevalenceTimeWindow,
            _scope: &ArtifactScope,
        ) -> Result<Vec<crate::prevalence::PrevalenceData>, crate::prevalence::PrevalenceError>
        {
            Err(crate::prevalence::PrevalenceError::Backend(
                "lake prevalence lookup: product_state_warming".to_string(),
            ))
        }
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3271: a failed rarity baseline lookup no longer fails the whole
    /// snapshot. The rows, the timeline and the panels finish, the dossier
    /// completes with a note, nothing is called rare without a baseline, and
    /// the finished view is not cached by the handler (the snapshot itself
    /// lives only the short lake-view TTL).
    #[tokio::test]
    async fn warming_prevalence_completes_the_snapshot_with_a_rarity_note() {
        use wiremock::{
            matchers::{body_string_contains, method, path},
            Mock, MockServer, ResponseTemplate,
        };

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let token_dir = tempfile::tempdir().unwrap();
        let token_file = token_dir.path().join("router.token");
        std::fs::write(&token_file, "asset-snapshot-warming-router-token").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool =
            crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ))
            .await
            .unwrap();
        let route = crate::search::LakeCellRoute {
            tenant_id: tenant,
            assignment_generation: 1,
            part_log_writer_epoch: 1,
            worker_revision: 1,
            assignment_fenced: true,
            cell_origin: server.uri(),
            query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
            router_token_file: token_file,
        };
        let mut service = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &route,
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        service.set_prevalence_lookup(Arc::new(WarmingPrevalence));
        let scope = ScopeSet::from_denied(BTreeSet::new());
        let query_path = format!("/v1/tenants/{tenant}/query/v1/query");

        Mock::given(method("POST"))
            .and(path(query_path.clone()))
            .and(body_string_contains("stats count() by"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(query_path.clone()))
            .and(body_string_contains("sort -time"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let rows = json!([
                    {"time": "2026-09-30 11:59:00.000000", "metadata.uid": "sysmon-1", "class_uid": 1007,
                     "metadata.log_source": "windows_sysmon", "device.hostname": "ws-it-083.corp.local",
                     "process.name": "svchost.exe"},
                    {"time": "2026-09-30 11:58:00.000000", "metadata.uid": "dns-1", "class_uid": 4003,
                     "metadata.log_source": "dns", "src_endpoint.ip": "10.1.3.7",
                     "query.hostname": "rare.example"},
                ]);
                ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "request_id": body["request_id"], "tenant_id": tenant,
                    "route": "broad_npl", "source_mode": "parts",
                    "result": {"result_rows": 2, "rows": rows, "page_offset": 0,
                        "page_limit": LAKE_ASSET_SCAN_CAP, "page_has_more": false},
                }))
            })
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(format!(
                "/v1/tenants/{tenant}/query/v1/identity/resolve-batch"
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
            .mount(&server)
            .await;

        let snapshot = Arc::new(AssetSnapshot::with_enrich_budget(
            TimeRange::new(t("2026-09-30T11:00:00Z"), t("2026-09-30T12:00:00Z")),
            Duration::from_secs(2),
        ));
        tokio::time::timeout(
            Duration::from_secs(10),
            service.build_asset_snapshot(
                &snapshot,
                "src_endpoint.hostname",
                "ws-it-083.corp.local",
                vec![],
                &scope,
            ),
        )
        .await
        .expect("the snapshot finishes")
        .expect("a warming prevalence lookup must not fail the snapshot");
        snapshot.update(|state| state.complete = true);

        let view = snapshot.view().unwrap();
        assert!(view.reached(Stage::Baseline) && view.complete);
        assert_eq!(view.rows.len(), 2, "the timeline rows are in");
        assert!(
            view.note.is_none(),
            "a missing rarity is not a coverage gap"
        );
        let dossier =
            dossier_from_view(&view).expect("no durable-lane fallback for missing rarity");
        let progress = dossier.progress.clone().unwrap();
        assert!(progress.complete, "the dossier completes without rarity");
        assert_eq!(
            progress.note.as_deref(),
            Some("rarity unavailable: prevalence is still warming")
        );
        assert!(
            !progress.cacheable(),
            "a dossier without rarity is not cached"
        );
        assert_eq!(
            dossier.processes.rare, 0,
            "nothing is proven rare without a baseline"
        );
        assert!(dossier.processes.rare_list.is_empty());
        assert_eq!(dossier.network.new_domains, 0);
        assert!(!dossier.timeline.points.is_empty(), "timeline points fill");

        let summary = artifact_summary_json(&view);
        assert_eq!(summary["progress"]["complete"], true);
        assert_eq!(
            summary["progress"]["note"],
            "rarity unavailable: prevalence is still warming"
        );
        assert_eq!(summary["domains"][0]["artifact"], "rare.example");

        assert!(snapshot.finished());
    }

    #[test]
    fn rarity_notes_name_the_warming_case() {
        assert_eq!(
            rarity_unavailable_note("Prevalence backend error: product_state_warming"),
            "rarity unavailable: prevalence is still warming"
        );
        assert_eq!(
            rarity_unavailable_note("Prevalence backend error: connection reset"),
            "rarity unavailable: the prevalence lookup failed"
        );
        let healthy = ProductViewProgress {
            complete: true,
            ..Default::default()
        };
        assert!(healthy.cacheable());
        let degraded = ProductViewProgress {
            complete: true,
            note: Some("covers the newest 24 h of the window; rarity unavailable: the prevalence lookup failed".into()),
            ..Default::default()
        };
        assert!(!degraded.cacheable());
    }

    #[test]
    fn capacity_refusals_retry_and_size_refusals_split() {
        let lanes = SearchError::ResourceExhausted("concurrency".to_string());
        assert!(transient(&lanes) && !splittable(&lanes));
        let memory = SearchError::ResourceExhausted("memory".to_string());
        assert!(!transient(&memory) && splittable(&memory));
        assert!(splittable(&SearchError::Timeout(55_000)));
        assert!(!splittable(&SearchError::SqlValidationError(
            "bad".to_string()
        )));
    }

    /// NAN-3262: the first identity / timeline cards make the dossier
    /// paintable (non-empty, `complete: false`) long before the event read,
    /// and every card in with its rarity completes it with no rows at all.
    #[tokio::test]
    async fn dossier_paints_cards_before_rows_and_completes_from_cards() {
        let window = TimeRange::new(t("2026-10-07T22:13:00Z"), t("2026-10-07T23:13:00Z"));
        let handle = Arc::new(AssetSnapshot::new(window.clone()));
        // Nothing read yet: the wait budget expires with an empty partial.
        let empty = handle.wait_with(Duration::from_millis(20), true).await.unwrap();
        assert!(!dossier_from_view(&empty).unwrap().progress.unwrap().complete);

        let publisher = handle.clone();
        let task = tokio::spawn(async move {
            tokio::task::yield_now().await;
            publisher.update(|state| {
                state.cards.insert(Section::Identity, Arc::new(vec![json!({
                    "time": "2026-10-07 23:10:00.000000", "device.hostname": "ws-it-083.corp.local",
                    "src_endpoint.ip": "10.1.2.3", "asset_n": 5,
                })]));
            });
        });
        // The identity card alone ends the wait: polls never block on rows.
        let view = tokio::time::timeout(
            Duration::from_secs(1),
            handle.wait_with(Duration::from_secs(8), true),
        )
        .await
        .expect("a card must end the wait")
        .unwrap();
        task.await.unwrap();
        assert!(view.rows.is_empty());
        let partial = dossier_from_view(&view).unwrap();
        assert_eq!(partial.identity.hostname.as_deref(), Some("ws-it-083.corp.local"));
        assert_eq!(partial.identity.ip.as_deref(), Some("10.1.2.3"));
        let progress = partial.progress.unwrap();
        assert!(!progress.complete);
        assert_eq!(progress.retry_after_ms, Some(RETRY_AFTER_MS));

        handle.update(|state| {
            state.cards.insert(Section::Timeline, Arc::new(vec![json!({
                "asset_bucket": 26.0, "class_uid": 1007, "metadata.log_source": "sysmon", "asset_n": 87,
                "time": "2026-10-07 23:10:00.000000", "asset_first": "2026-10-07 22:14:00.000000",
            })]));
            state.cards.insert(Section::Processes, Arc::new(vec![json!({
                "process.name": "cmd.exe", "asset_n": 87, "time": "2026-10-07 23:10:00.000000",
                "asset_proc_hash": ["ABCD"],
            })]));
            state.cards.insert(Section::Network, Arc::new(vec![json!({
                "class_uid": 4001, "dst_endpoint.ip": "203.0.113.9", "asset_n": 1551,
                "asset_bytes_in": 1, "asset_bytes_out": 2,
            })]));
        });
        let partial = dossier_from_view(&handle.view_with(true).unwrap()).unwrap();
        assert_eq!(partial.timeline.points, vec![[26, 1, 3]]);
        assert_eq!(partial.identity.log_sources[0].event_count, 87);
        assert_eq!(partial.processes.unique, 1);
        assert_eq!(partial.network.total_conns, 1551);
        // No rarity yet: nothing is called rare before a lookup proves it.
        assert!(partial.processes.rare_list.is_empty());
        assert!(!partial.progress.unwrap().complete);

        handle.update(|state| {
            for section in [Section::Dns, Section::Auth, Section::AuthRecent, Section::Files, Section::FilesRecent] {
                state.cards.insert(section, Arc::new(Vec::new()));
            }
            state.cards_done = true;
            state.card_rarity = true;
        });
        let view = handle.view_with(true).unwrap();
        assert!(view.cards_complete);
        assert!(!view.reached(Stage::Rows), "the event read is still running");
        let done = dossier_from_view(&view).unwrap();
        let progress = done.progress.unwrap();
        assert!(progress.complete);
        assert_eq!(progress.retry_after_ms, None);
        assert_eq!(done.processes.rare, 1, "an unseen hash is rare once rarity is known");
        // The capped event read no longer sends a complete dossier durable,
        // and a failed event read leaves it readable for the dossier only.
        handle.update(|state| {
            state.rows_done = true;
            state.notes.push("limited to the newest 50000 events".to_string());
            state.failure = Some(Failure::Unavailable("lake".to_string()));
        });
        assert!(dossier_from_view(&handle.view_with(true).unwrap()).is_ok());
        assert!(handle.view().is_err(), "row views still see the failure");
        // A failed card leaves its section to the rows: not complete from cards.
        handle.update(|state| {
            state.failure = None;
            state.card_failed.insert(Section::Files);
        });
        assert!(!handle.view_with(true).unwrap().cards_complete);
    }

    /// NAN-3262: requests for the same asset share one snapshot while it is
    /// live, including a "last hour" re-sent seconds later; a refresh starts
    /// over only once it finished, and a far window gets its own.
    #[test]
    fn same_asset_requests_share_one_in_flight_snapshot() {
        let base = lake_view_cache_key(&["asset-snapshot-test", &uuid::Uuid::new_v4().to_string()]);
        let window = TimeRange::new(t("2026-10-07T22:13:00Z"), t("2026-10-07T23:13:00Z"));
        let (key, first, created) = shared_snapshot(&base, &window, true);
        assert!(created);
        let (again_key, again, created) = shared_snapshot(&base, &window, false);
        assert!(!created);
        assert_eq!(again_key, key);
        assert!(Arc::ptr_eq(&first, &again));
        // A poll whose "last hour" was computed 20 s later joins it.
        let shifted = TimeRange::new(
            window.start + chrono::Duration::seconds(20),
            window.end + chrono::Duration::seconds(20),
        );
        let (_, joined, created) = shared_snapshot(&base, &shifted, false);
        assert!(!created);
        assert!(Arc::ptr_eq(&first, &joined));
        // An explicit refresh joins it while it is still building...
        let (_, refreshed, created) = shared_snapshot(&base, &shifted, true);
        assert!(!created);
        assert!(Arc::ptr_eq(&first, &refreshed));
        // ...and replaces it once it finished.
        first.update(|state| state.complete = true);
        let (_, rebuilt, created) = shared_snapshot(&base, &shifted, true);
        assert!(created);
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        // A different window (beyond the tolerance) is its own snapshot.
        let other = TimeRange::new(
            window.start - chrono::Duration::hours(1),
            window.end - chrono::Duration::hours(1),
        );
        let (_, separate, created) = shared_snapshot(&base, &other, false);
        assert!(created);
        assert!(!Arc::ptr_eq(&rebuilt, &separate));
        // A failed snapshot is never joined: a poll reads the finished
        // snapshot still live for the same asset instead.
        rebuilt.update(|state| state.failure = Some(Failure::Unavailable("lake".to_string())));
        let (_, retried, created) = shared_snapshot(&base, &shifted, false);
        assert!(!created);
        assert!(!Arc::ptr_eq(&rebuilt, &retried));
        assert!(Arc::ptr_eq(&first, &retried));
        // With nothing else live, a failed snapshot is rebuilt.
        let lone = lake_view_cache_key(&["asset-snapshot-test", &uuid::Uuid::new_v4().to_string()]);
        let (_, failed, _) = shared_snapshot(&lone, &window, false);
        failed.update(|state| state.failure = Some(Failure::Unavailable("lake".to_string())));
        let (_, rebuilt_lone, created) = shared_snapshot(&lone, &window, false);
        assert!(created);
        assert!(!Arc::ptr_eq(&failed, &rebuilt_lone));
        // Tolerance scales with the window and is bounded.
        assert_eq!(window_tolerance(&window), chrono::Duration::seconds(60));
        let day = TimeRange::new(window.end - chrono::Duration::hours(24), window.end);
        assert_eq!(window_tolerance(&day), chrono::Duration::seconds(120));
        let minute = TimeRange::new(window.end - chrono::Duration::minutes(1), window.end);
        assert_eq!(window_tolerance(&minute), chrono::Duration::seconds(5));
    }

    /// NAN-3262: the asset predicate is hintable (an OR of at most eight
    /// equalities) and a wider identity set splits into disjoint hintable
    /// slices whose union is the predicate.
    #[test]
    fn asset_predicate_slices_fit_the_compiler_hint_budget() {
        let host = build_lake_asset_predicate("device.hostname", "ws-it-083.corp.local", &[], LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        assert!(!host.contains(" IN ("), "{host}");
        assert_eq!(host.matches(" OR ").count(), 5, "fqdn + short name on 3 fields: {host}");
        let identity = |ip: &str, mac: &str| json!({"ip": ip, "hostname": "ws-it-083.corp.local", "mac": mac});
        let identities = vec![identity("10.1.2.3", "aa:bb:cc:dd:ee:ff"), identity("10.1.2.4", "")];
        let slices =
            build_lake_asset_predicate_slices("device.hostname", "ws-it-083.corp.local", &identities, LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        // 6 host + 4 ip + 2 mac equalities = 12 terms -> 2 slices of <= 8.
        assert_eq!(slices.len(), 2, "{slices:?}");
        assert_eq!(slices[0].matches('=').count(), 8, "{}", slices[0]);
        assert!(slices[1].contains(" AND NOT ("), "{}", slices[1]);
        let exclusion = slices[1].split(" AND NOT ").nth(1).unwrap();
        assert!(exclusion.contains(slices[0].as_str()), "the later slice excludes the earlier one");
        // Past the slice budget it is one IN predicate, as before.
        let many = (0..20).map(|i| identity(&format!("10.1.3.{i}"), "")).collect::<Vec<_>>();
        let slices = build_lake_asset_predicate_slices("device.hostname", "ws-it-083.corp.local", &many, LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        assert_eq!(slices.len(), 1);
        assert!(slices[0].contains(" IN ("), "{}", slices[0]);
    }

    /// NAN-3276: the global prevalence read's predicate nested one level per
    /// artifact (`((a OR b) OR c) …` in the SQL) and the lake compiler's
    /// grouped-page parse refused it at 50 artifacts ("recursion limit
    /// exceeded"). Grouped by path and emitted as flat chains / IN lists, it
    /// parses for any artifact count with sqlparser's DEFAULT depth limit.
    #[test]
    fn global_prevalence_read_compiles_for_any_artifact_count() {
        let candidates = (0..8_000_u64)
            .map(|i| {
                // Fits nPL's 1 MiB query bound: the lists repeat per path.
                if i % 8 == 0 {
                    (format!("{i:064x}"), true, 8_000 - i)
                } else {
                    (format!("d{i}.example"), false, 8_000 - i)
                }
            })
            .collect::<Vec<_>>();
        let query = global_artifact_hosts_query(&candidates).unwrap();
        // A fixed number of path legs, not one group per artifact.
        assert_eq!(
            query.matches(" IN (").count(),
            3 + LAKE_ASSET_DOMAIN_PATHS.len(),
            "{}",
            &query[..400]
        );
        assert!(!query.contains(") OR ("), "no per-artifact groups");
        let parsed = crate::query::parse_query(&query).unwrap();
        let generator = crate::query::ClickHouseSqlGenerator::with_table("__nano_lake_source__")
            .with_profile(Arc::new(crate::schema::OcsfProfile::lake_1_9()));
        let sql = generator
            .generate(
                &parsed,
                &TimeRange::new(t("2026-10-07T00:00:00Z"), t("2026-10-08T00:00:00Z")),
            )
            .unwrap();
        assert!(!sql.contains("((((("), "the SQL must not nest per value");
        let statements =
            sqlparser::parser::Parser::parse_sql(&sqlparser::dialect::ClickHouseDialect {}, &sql)
                .expect("generated global prevalence SQL parses at the default depth");
        assert_eq!(statements.len(), 1);
        // Every candidate is matched, under every path of its kind.
        for (artifact, is_hash, _) in [&candidates[0], &candidates[1], &candidates[7_999]] {
            assert!(
                sql.contains(&format!("'{artifact}'")),
                "{artifact} (hash: {is_hash})"
            );
        }
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3276: a busy host's network and timeline cards came back over
    /// their group cap; each was dropped and "that section reads the event
    /// rows", the capped row read sent the dossier to the durable lane, and
    /// that lane's row read blew its heap envelope. A card over its cap now
    /// keeps its groups as a bounded aggregate, marked as lower bounds, and
    /// the dossier completes from the cards without any event-row read.
    #[tokio::test]
    async fn group_cap_overflow_keeps_bounded_aggregates_and_reads_no_rows() {
        use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let token_dir = tempfile::tempdir().unwrap();
        let token_file = token_dir.path().join("router.token");
        std::fs::write(&token_file, "asset-card-cap-fixture-router-token-nan3276").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool =
            crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ))
            .await
            .unwrap();
        let route = crate::search::LakeCellRoute {
            tenant_id: tenant,
            assignment_generation: 1,
            part_log_writer_epoch: 1,
            worker_revision: 1,
            assignment_fenced: true,
            cell_origin: server.uri(),
            query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
            router_token_file: token_file,
        };
        let service = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &route,
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        let scope = ScopeSet::default();
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let id = body["request_id"].as_str().unwrap().to_string();
                // NAN-3291: plus the stream's count aggregates; never rows.
                assert!(
                    id.starts_with("asset-card-") || id.starts_with("asset-counts"),
                    "only card and count aggregates are read: {id}"
                );
                // The network and timeline cards are over their group cap:
                // the lake answers a full page that has more groups.
                let (rows, more) = if id.starts_with("asset-card-network") {
                    (vec![json!({"class_uid": 4001, "dst_endpoint.ip": "203.0.113.9",
                        "asset_n": 900, "asset_bytes_in": 10, "asset_bytes_out": 20})], true)
                } else if id.starts_with("asset-card-timeline") {
                    (vec![json!({"asset_bucket": 26.0, "class_uid": 3002, "metadata.log_source": "winsec",
                        "asset_n": 4_000, "time": "2026-10-07 23:10:00.000000",
                        "asset_first": "2026-10-07 22:14:00.000000"})], true)
                } else if id.starts_with("asset-card-identity") {
                    (vec![json!({"time": "2026-10-07 23:10:00.000000",
                        "device.hostname": "ws-it-083", "asset_n": 4_900})], false)
                } else {
                    (Vec::new(), false)
                };
                ResponseTemplate::new(200).set_body_json(json!({
                    "ok": true, "request_id": id, "tenant_id": tenant,
                    "route": "broad_npl", "source_mode": "parts",
                    "result": {"result_rows": rows.len(), "rows": rows, "page_offset": 0,
                        "page_limit": cards::CARD_GROUP_CAP, "page_has_more": more},
                }))
            })
            .mount(&server)
            .await;

        let window = TimeRange::new(t("2026-10-07T22:13:00Z"), t("2026-10-07T23:13:00Z"));
        let handle = AssetSnapshot::new(window);
        service
            .build_asset_cards(&handle, "device.hostname", "ws-it-083", vec![], &scope)
            .await;
        {
            let state = handle.lock();
            assert!(state.card_failed.is_empty(), "{:?}", state.card_failed);
            assert_eq!(
                state.card_truncated,
                BTreeSet::from([Section::Timeline, Section::Network])
            );
            assert!(state.cards.contains_key(&Section::Network));
            assert!(state.cards.contains_key(&Section::Timeline));
            assert!(
                state.rows.is_empty() && !state.rows_done,
                "no event row was read"
            );
        }
        let view = handle.view_with(true).unwrap();
        assert!(
            view.cards_complete,
            "a truncated card still completes the dossier"
        );
        let dossier = dossier_from_view(&view).unwrap();
        let progress = dossier.progress.clone().unwrap();
        assert!(progress.complete);
        assert_eq!(progress.retry_after_ms, None);
        let note = progress.note.unwrap();
        assert!(
            note.contains("timeline, network show the busiest"),
            "{note}"
        );
        assert!(note.contains("lower bounds"), "{note}");
        // The timeline is the bucket x lane aggregate, never rows.
        assert_eq!(dossier.timeline.points, vec![[26, 0, 3]]);
        assert_eq!(dossier.network.total_conns, 900);
        let requests = server.received_requests().await.unwrap();
        assert!(!requests.is_empty());
        for request in requests {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let id = body["request_id"].as_str().unwrap();
            assert!(
                !id.starts_with("asset-snapshot"),
                "event rows were read: {id}"
            );
        }
    }

    /// NAN-3276: the durable dossier folds the same card reads (identity
    /// first, every slice) and marks a capped card as lower bounds.
    #[test]
    fn durable_card_reads_fold_like_the_interactive_cards() {
        let window = TimeRange::new(t("2026-10-07T22:13:00Z"), t("2026-10-07T23:13:00Z"));
        let reads = SearchService::lake_asset_dossier_card_reads(
            "device.hostname",
            "ws-it-083",
            &[],
            &window,
        )
        .unwrap();
        let views = reads.iter().map(|read| read.view).collect::<Vec<_>>();
        assert_eq!(views[0], Section::Identity.view());
        assert_eq!(
            views[1..],
            Section::CARDS
                .iter()
                .map(|section| section.view())
                .collect::<Vec<_>>()[..]
        );
        for read in &reads {
            assert!(!read.queries.is_empty());
            assert!(
                !read.queries.iter().any(|query| query.contains("| table")),
                "{:?}",
                read.queries
            );
        }
        let mut cards = LakeAssetCards::new();
        for read in &reads {
            let (rows, exact) = match read.view {
                "asset-card-timeline" => (
                    vec![
                        json!({"asset_bucket": 3.0, "class_uid": 3002, "metadata.log_source": "winsec",
                        "asset_n": 12, "time": "2026-10-07 22:20:00.000000",
                        "asset_first": "2026-10-07 22:20:00.000000"}),
                    ],
                    false,
                ),
                "asset-card-auth" => (
                    vec![json!({"class_uid": 3002, "status": "Failure", "asset_n": 12})],
                    true,
                ),
                _ => (Vec::new(), true),
            };
            cards.insert(read, rows, exact);
        }
        let dossier = cards.dossier(&window, &BTreeMap::new());
        assert_eq!(dossier.timeline.points, vec![[3, 0, 3]]);
        assert_eq!(dossier.auth.failure, 12);
        let note = dossier.progress.unwrap().note.unwrap();
        assert!(note.starts_with("timeline shows the busiest"), "{note}");
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3291: a cell-routed service over `server`. The token file lives
    /// in the returned directory.
    async fn nan3291_service(
        server: &wiremock::MockServer,
        tenant: uuid::Uuid,
    ) -> (SearchService, tempfile::TempDir) {
        let token_dir = tempfile::tempdir().unwrap();
        let token_file = token_dir.path().join("router.token");
        std::fs::write(&token_file, "asset-counts-fixture-router-token-nan3291").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token_file, std::fs::Permissions::from_mode(0o400)).unwrap();
        }
        let pool =
            crate::db::DualPool::new_lake_control_plane(&crate::db::DualPoolConfig::with_auth(
                "postgres://unused:unused@127.0.0.1:1/nanosiem",
                "http://127.0.0.1:1",
                "nanosiem",
                "unused",
                "nanosiem",
            ))
            .await
            .unwrap();
        let route = crate::search::LakeCellRoute {
            tenant_id: tenant,
            assignment_generation: 1,
            part_log_writer_epoch: 1,
            worker_revision: 1,
            assignment_fenced: true,
            cell_origin: server.uri(),
            query_base_url: format!("{}/v1/tenants/{tenant}/query", server.uri()),
            router_token_file: token_file,
        };
        let service = SearchService::with_dual_pool(&pool)
            .enterprise_shared_cell_tenant_view(
                &route,
                crate::search::SearchTenantScope::enterprise_shared_retained(tenant, 1, 90, 0)
                    .unwrap(),
                Arc::new(crate::search::InMemoryJobStore::new()),
            )
            .unwrap();
        (service, token_dir)
    }

    fn nan3291_answer(tenant: uuid::Uuid, id: &str, rows: Vec<Value>, more: bool) -> wiremock::ResponseTemplate {
        wiremock::ResponseTemplate::new(200).set_body_json(json!({
            "ok": true, "request_id": id, "tenant_id": tenant,
            "route": "broad_npl", "source_mode": "parts",
            "result": {"result_rows": rows.len(), "rows": rows, "page_offset": 0,
                "page_limit": LAKE_ASSET_SCAN_CAP, "page_has_more": more},
        }))
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3291: a busy workstation (~55k events/h) over a 6 h window: the
    /// row snapshot stops at its 50k cap, but the stream's total and facets
    /// come from the full-window count aggregates and are exact. The notes
    /// are plain language and the counts carry none.
    #[tokio::test]
    async fn busy_asset_beyond_the_scan_cap_gets_exact_full_window_counts() {
        use wiremock::{matchers::method, Mock, MockServer};

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let (service, _token) = nan3291_service(&server, tenant).await;
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let id = body["request_id"].as_str().unwrap().to_string();
                let (rows, more) = if id.starts_with("asset-counts-users") {
                    (vec![
                        json!({"asset_user": "CORP\\alice", "event_count": 200_000}),
                        json!({"asset_user": "SYSTEM", "event_count": 90_000}),
                    ], false)
                } else if id.starts_with("asset-counts") {
                    (vec![
                        json!({"metadata.log_source": "windows_sysmon", "class_uid": 1007,
                            "asset_auth_failure": 0, "event_count": 250_000}),
                        json!({"metadata.log_source": "windows_sysmon", "class_uid": 4001,
                            "asset_auth_failure": 0, "event_count": 50_000}),
                        json!({"metadata.log_source": "winsec", "class_uid": 3002,
                            "asset_auth_failure": 1, "event_count": 30_000}),
                    ], false)
                } else if id.starts_with("asset-card-identity") {
                    (vec![json!({"time": "2026-10-08 10:50:00.000000",
                        "device.hostname": "ws-it-083.corp.local", "asset_n": 330_000})], false)
                } else if id.starts_with("asset-snapshot") {
                    // Every hour of the window holds more than the cap.
                    let rows = (0..LAKE_ASSET_SCAN_CAP).map(|index| json!({
                        "time": "2026-10-08 10:50:00.000000",
                        "metadata.uid": format!("busy-{index}"),
                        "device.hostname": "ws-it-083.corp.local",
                        "class_uid": 1007, "metadata.log_source": "windows_sysmon",
                    })).collect::<Vec<_>>();
                    (rows, true)
                } else {
                    (Vec::new(), false)
                };
                nan3291_answer(tenant, &id, rows, more)
            })
            .mount(&server)
            .await;

        let window = TimeRange::new(t("2026-10-08T04:53:27Z"), t("2026-10-08T10:53:27Z"));
        let scope = ScopeSet::default();
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        let (total, facets, progress) = loop {
            let (total, facets, progress) = service
                .query_lake_asset_events_summary(
                    "device.hostname", "ws-it-083.corp.local", &[], &window, None, &scope, true,
                )
                .await
                .unwrap();
            let progress = progress.unwrap();
            if progress.complete {
                break (total, facets, progress);
            }
            assert!(std::time::Instant::now() < deadline, "the counts never completed");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(total, 330_000, "the full window, not the 50k-row snapshot");
        // The handler's `total_count_exact` predicate.
        assert!(progress.complete && progress.note.is_none(), "{progress:?}");
        assert_eq!(progress.retry_after_ms, None);
        assert_eq!(facets.event_kind[0], ("PROCESS".to_string(), 250_000));
        assert!(facets.event_kind.contains(&("AUTH_FAILURE".to_string(), 30_000)));
        assert_eq!(facets.source_type[0], ("windows_sysmon".to_string(), 300_000));
        assert_eq!(facets.user[0], ("CORP\\alice".to_string(), 200_000));

        // The capped row snapshot says so in plain words (for event detail),
        // never with internal error text.
        let view = loop {
            let view = service
                .lake_asset_snapshot(
                    SnapshotRequest {
                        identifier_field: "device.hostname",
                        identifier_value: "ws-it-083.corp.local",
                        identities: &[],
                        time_range: &window,
                        scope: &scope,
                    },
                    false,
                    Duration::from_millis(200),
                )
                .await
                .unwrap();
            if view.reached(Stage::Rows) {
                break view;
            }
            assert!(std::time::Instant::now() < deadline, "the rows never completed");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        assert_eq!(view.rows.len(), LAKE_ASSET_SCAN_CAP, "row memory stays capped");
        let note = view.note.clone().unwrap();
        assert!(note.contains("newest 50,000 events (since 2026-10-08T10:50:00Z)"), "{note}");
        assert!(note.contains("counts cover the full window"), "{note}");
        assert!(!note.contains("SQL validation") && !note.contains("lower bounds"), "{note}");
        // Only bounded aggregates and the capped newest-first row read ran:
        // one row request for the first (full) hour, no older hour.
        let requests = server.received_requests().await.unwrap();
        let row_reads = requests
            .iter()
            .filter(|request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                body["request_id"].as_str().unwrap().starts_with("asset-snapshot")
            })
            .count();
        assert_eq!(row_reads, 1);
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3291: a workstation behind a shared address. Its identity card
    /// pairs its hostname with its own IP, a NAT / proxy IP that 40 hosts
    /// carry, loopback, and a link-local address, plus hundreds of peers and
    /// users. Widening binds only its own IP: the shared IP and the
    /// host-agnostic addresses are excluded and nothing hits the cap.
    #[tokio::test]
    async fn nat_shared_ip_widening_stays_bounded_and_excludes_the_shared_ip() {
        use wiremock::{matchers::method, Mock, MockServer};

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let (service, _token) = nan3291_service(&server, tenant).await;
        let fanout_queries = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = fanout_queries.clone();
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let id = body["request_id"].as_str().unwrap().to_string();
                let text = body.to_string();
                let rows = if id.starts_with("asset-card-identity") {
                    let mut rows = vec![
                        json!({"src_endpoint.hostname": "ws-it-083.corp.local", "src_endpoint.ip": "10.1.2.3", "asset_n": 900}),
                        json!({"src_endpoint.hostname": "ws-it-083.corp.local", "src_endpoint.ip": "10.9.9.9", "asset_n": 400}),
                        json!({"src_endpoint.hostname": "ws-it-083.corp.local", "src_endpoint.ip": "127.0.0.1", "asset_n": 50}),
                        json!({"src_endpoint.hostname": "ws-it-083.corp.local", "src_endpoint.ip": "fe80::1", "asset_n": 5}),
                    ];
                    for index in 0..300 {
                        // Peers on the destination side, and users on the
                        // asset's own endpoint: neither adds an identity.
                        rows.push(json!({"src_endpoint.hostname": "ws-it-083.corp.local",
                            "src_endpoint.ip": "10.1.2.3", "actor.user.name": format!("user{index}"),
                            "dst_endpoint.hostname": format!("peer-{index}.corp.local"),
                            "dst_endpoint.ip": format!("10.2.{}.{}", index / 200, index % 200),
                            "asset_n": 1}));
                    }
                    rows
                } else if id.starts_with("asset-widening-fanout") {
                    seen.lock().unwrap().push(text.clone());
                    let endpoint = if text.contains("dst_endpoint.ip=") { "dst_endpoint" } else { "src_endpoint" };
                    let mut rows = Vec::new();
                    if text.contains("10.9.9.9") {
                        for index in 0..40 {
                            rows.push(json!({format!("{endpoint}.ip"): "10.9.9.9",
                                format!("{endpoint}.hostname"): format!("ws-{index}"), "asset_n": 3}));
                        }
                    }
                    if text.contains("10.1.2.3") {
                        // Both spellings of the asset are one host.
                        rows.push(json!({format!("{endpoint}.ip"): "10.1.2.3",
                            format!("{endpoint}.hostname"): "ws-it-083.corp.local", "asset_n": 900}));
                        rows.push(json!({format!("{endpoint}.ip"): "10.1.2.3",
                            format!("{endpoint}.hostname"): "WS-IT-083", "asset_n": 9}));
                    }
                    rows
                } else {
                    Vec::new()
                };
                nan3291_answer(tenant, &id, rows, false)
            })
            .mount(&server)
            .await;

        let window = TimeRange::new(t("2026-10-08T06:53:27Z"), t("2026-10-08T10:53:27Z"));
        let handle = AssetSnapshot::new(window);
        let identities = service
            .build_asset_cards(&handle, "device.hostname", "ws-it-083.corp.local", vec![], &ScopeSet::default())
            .await;
        let values = asset_identity_values("device.hostname", "ws-it-083.corp.local", &identities).unwrap();
        assert_eq!(values["ip"], BTreeSet::from(["10.1.2.3".to_string()]), "{values:?}");
        let bound = values.values().map(BTreeSet::len).sum::<usize>();
        assert!(bound <= WIDEN_MAX_VALUES, "{bound}");
        assert!(identities.len() <= 2, "one identity per new value, not per tuple: {identities:?}");
        // Loopback / link-local never cost a read; the shared IP was measured.
        let fanout = fanout_queries.lock().unwrap().clone();
        assert!(!fanout.is_empty());
        assert!(fanout.iter().all(|query| !query.contains("127.0.0.1") && !query.contains("fe80")));
        {
            let state = handle.lock();
            assert!(state.widening_rejected.contains(&("ip".to_string(), "10.9.9.9".to_string())));
            assert!(!state.widening_capped);
            assert!(state.notes.is_empty(), "{:?}", state.notes);
        }
        // Every later card reads the widened predicate without the shared IP.
        for request in server.received_requests().await.unwrap() {
            let body: Value = serde_json::from_slice(&request.body).unwrap();
            let id = body["request_id"].as_str().unwrap();
            if id.starts_with("asset-card-timeline") || id.starts_with("asset-counts") {
                let text = body.to_string();
                assert!(text.contains("10.1.2.3"), "{id}");
                assert!(!text.contains("10.9.9.9") && !text.contains("127.0.0.1"), "{id}");
            }
        }

        // A second step over the same tuples re-reads nothing.
        let before = fanout_queries.lock().unwrap().len();
        let learned = widening_identities(&[json!({
            "src_endpoint.hostname": "ws-it-083.corp.local", "src_endpoint.ip": "10.9.9.9",
        })]);
        let again = service
            .widen_identities(&handle, "device.hostname", "ws-it-083.corp.local", &identities,
                &learned, &handle.window, &ScopeSet::default())
            .await;
        assert!(!again.changed && !again.capped);
        assert_eq!(fanout_queries.lock().unwrap().len(), before);
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3291: an asset with more linked identities than the cap stops
    /// widening quietly: the bound set never passes [`WIDEN_MAX_VALUES`] and
    /// the note is plain language, never "SQL validation error".
    #[tokio::test]
    async fn widening_stops_at_its_cap_with_a_plain_note() {
        use wiremock::{matchers::method, Mock, MockServer};

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let (service, _token) = nan3291_service(&server, tenant).await;
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let id = body["request_id"].as_str().unwrap().to_string();
                // Every IP is tight: one host each.
                nan3291_answer(tenant, &id, Vec::new(), false)
            })
            .mount(&server)
            .await;
        let window = TimeRange::new(t("2026-10-08T06:53:27Z"), t("2026-10-08T10:53:27Z"));
        let handle = AssetSnapshot::new(window.clone());
        // DHCP churn: the host carried 250 addresses in the window.
        let learned = widening_identities(
            &(0..250)
                .map(|index| json!({"src_endpoint.hostname": "ws-it-083",
                    "src_endpoint.ip": format!("10.3.{}.{}", index / 200, index % 200 + 1)}))
                .collect::<Vec<_>>(),
        );
        let mut identities = Vec::new();
        for _ in 0..4 {
            let step = service
                .widen_identities(&handle, "device.hostname", "ws-it-083", &identities, &learned,
                    &window, &ScopeSet::default())
                .await;
            identities = step.identities;
        }
        let values = asset_identity_values("device.hostname", "ws-it-083", &identities).unwrap();
        let bound = values.values().map(BTreeSet::len).sum::<usize>();
        assert!(bound <= WIDEN_MAX_VALUES, "{bound}");
        assert!(values["ip"].len() >= 1);
        let notes = handle.lock().notes.clone();
        assert_eq!(notes, vec![WIDENING_CAPPED_NOTE.to_string()], "noted once");
        assert!(notes.iter().all(|note| !note.contains("SQL validation") && !note.contains("limited to")));
        assert!(build_lake_asset_predicate("device.hostname", "ws-it-083", &identities, LAKE_ASSET_RANGELESS_FIELDS).is_ok());
    }

    #[cfg(feature = "enterprise")]
    /// NAN-3291: an IP seed widens to its hosts only while the seed IP is
    /// tight; a NAT address never pulls in the hosts behind it.
    #[tokio::test]
    async fn an_ip_seed_widens_to_its_host_only_when_the_ip_is_not_shared() {
        use wiremock::{matchers::method, Mock, MockServer};

        let server = MockServer::start().await;
        let tenant = uuid::Uuid::new_v4();
        let (service, _token) = nan3291_service(&server, tenant).await;
        Mock::given(method("POST"))
            .respond_with(move |request: &wiremock::Request| {
                let body: Value = serde_json::from_slice(&request.body).unwrap();
                let id = body["request_id"].as_str().unwrap().to_string();
                let text = body.to_string();
                let endpoint = if text.contains("dst_endpoint.ip=") { "dst_endpoint" } else { "src_endpoint" };
                let hosts = if text.contains("10.9.9.9") { 40 } else { 1 };
                let rows = (0..hosts)
                    .map(|index| json!({format!("{endpoint}.ip"): if hosts == 1 {"10.1.2.3"} else {"10.9.9.9"},
                        format!("{endpoint}.hostname"): format!("ws-{index}")}))
                    .collect::<Vec<_>>();
                nan3291_answer(tenant, &id, rows, false)
            })
            .mount(&server)
            .await;
        let window = TimeRange::new(t("2026-10-08T06:53:27Z"), t("2026-10-08T10:53:27Z"));
        for (seed, widens) in [("10.1.2.3", true), ("10.9.9.9", false)] {
            let handle = AssetSnapshot::new(window.clone());
            let learned = widening_identities(&[json!({
                "src_endpoint.hostname": "ws-0", "src_endpoint.ip": seed,
            })]);
            let step = service
                .widen_identities(&handle, "src_endpoint.ip", seed, &[], &learned, &window, &ScopeSet::default())
                .await;
            assert_eq!(step.changed, widens, "{seed}");
            let values = asset_identity_values("src_endpoint.ip", seed, &step.identities).unwrap();
            assert_eq!(values.contains_key("host"), widens, "{seed}: {values:?}");
        }
    }

    #[test]
    fn widening_helpers_reject_host_agnostic_ips_and_format_counts() {
        for ip in ["127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "255.255.255.255", "::1", "fe80::1", "not-an-ip"] {
            assert!(!widenable_ip(ip), "{ip}");
        }
        for ip in ["10.1.2.3", "192.168.0.7", "2001:db8::1"] {
            assert!(widenable_ip(ip), "{ip}");
        }
        assert_eq!(thousands(50_000), "50,000");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1_234_567), "1,234,567");
        let fanout = ip_host_fanout(&[
            json!({"src_endpoint.ip": "10.1.2.3", "src_endpoint.hostname": "WS-1.corp.local"}),
            json!({"dst_endpoint.ip": "10.1.2.3", "dst_endpoint.hostname": "ws-1"}),
            json!({"src_endpoint.ip": "10.1.2.3", "src_endpoint.hostname": ""}),
        ]);
        assert_eq!(fanout["10.1.2.3"].len(), 1, "spellings of one host count once");
    }
}
