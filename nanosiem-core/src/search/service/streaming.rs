// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::auth::ScopeSet;
use crate::search::query_processing::{
    apply_profile_product_semantics, enforce_source_scope, enforce_source_scope_with_field,
};

fn enforce_stream_source_scope(
    query: &str,
    dataset: crate::query::Dataset,
    lake_mode: LakeQueryMode,
    scope: &ScopeSet,
) -> Result<String, SearchError> {
    if dataset != crate::query::Dataset::Logs {
        // Native spans and metrics intentionally have no log-source dimension.
        // Risk applies this same deny-set while constructing its derived grain.
        return Ok(query.to_string());
    }
    if lake_mode == LakeQueryMode::Primary {
        enforce_source_scope_with_field(query, scope.deny_set(), "metadata.log_source")
    } else {
        enforce_source_scope(query, scope.deny_set())
    }
}

fn follow_query_supported(query: &crate::query::Query) -> bool {
    match query {
        crate::query::Query::Search(_) => true,
        crate::query::Query::Piped { source, command } => {
            matches!(command, crate::query::Command::Where { .. })
                && follow_query_supported(source)
        }
    }
}

#[derive(Debug)]
enum FollowScanError {
    Search(SearchError),
    MissingIdentity,
    Exhausted,
    Disconnected,
    Cancelled,
    /// A page did not answer within [`FOLLOW_PAGE_DEADLINE`] (NAN-3264).
    Slow,
}

impl FollowScanError {
    /// A cell that is over budget or slow right now: retry the head with a
    /// smaller page instead of ending the stream (NAN-3264).
    fn is_transient(&self) -> bool {
        matches!(
            self,
            Self::Slow | Self::Search(SearchError::ResourceExhausted(_) | SearchError::Timeout(_))
        )
    }
}

struct FollowCancelGuard {
    id: String,
    registry: std::sync::Arc<dashmap::DashMap<String, tokio::sync::watch::Sender<bool>>>,
}

impl Drop for FollowCancelGuard {
    fn drop(&mut self) {
        self.registry.remove(&self.id);
    }
}

/// NAN-3244: how far behind the newest delivered event a later head is
/// re-read, so a late event that sorts just below the watermark is still
/// delivered. Older late arrivals are out of a tail's scope.
const FOLLOW_LATE_GRACE_SECS: i64 = crate::search::settled_reuse::LATE_ARRIVAL_GRACE_SECS;
/// NAN-3244: at most this many pages are read per committed head. Each
/// later page is fenced by the previous page's oldest instant (NAN-3264), not
/// an offset, so every page is a shallow `LIMIT page + 1`.
const FOLLOW_MAX_PAGES_PER_HEAD: usize = 4;
/// NAN-3264: largest initial page. The client asks for 500.
const FOLLOW_INITIAL_MAX_ROWS: usize = 500;
/// NAN-3264: rows per page on later heads. Measured on the lean load-test tenant cell
/// (apache_access, ~15 eps, full-event rows): a compiled `LIMIT` of 1000 or
/// more (limit, or offset + limit) over a busy window ran past 30 s and ended
/// in "Interactive query exhausted its memory budget", while 200–750 answered
/// in 0.5–0.8 s. The NAN-3244 follow read later heads in 1000-row offset
/// pages, so it stalled on the first busy head and died a minute later.
const FOLLOW_HEAD_PAGE_ROWS: usize = 250;
/// NAN-3264: a transient refusal halves the page, never below this.
const FOLLOW_MIN_PAGE_ROWS: usize = 50;
/// NAN-3264: a single page answering slower than this is abandoned and the
/// head retried with a smaller page. Healthy pages answer in under a second.
const FOLLOW_PAGE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(20);
/// NAN-3264: consecutive transient head failures before the stream ends with
/// the error (the client then polls and reconnects).
const FOLLOW_MAX_TRANSIENT_FAILURES: u32 = 4;
/// NAN-3264: the follow sends a `heartbeat` when it has sent nothing for this
/// long, so a client can detect a wedged follow.
const FOLLOW_HEARTBEAT_EVERY: std::time::Duration = std::time::Duration::from_secs(10);
/// NAN-3244: hard cap on remembered event IDs (dedupe state).
const FOLLOW_MAX_SEEN: usize = 50_000;
/// NAN-3244: a follow stream completes after this long; the client
/// reconnects, which also re-runs admission and re-reads the window.
const FOLLOW_MAX_LIFETIME: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// Below this an integer row time is epoch SECONDS, at or above it epoch
/// MILLISECONDS: 1e11 s is year 5138, while 1e11 ms is March 1973, so no real
/// event time is ambiguous between the two.
const FOLLOW_EPOCH_MS_THRESHOLD: i64 = 100_000_000_000;

/// Event time of a cell row (`time`, falling back to `timestamp`).
///
/// Lean cell rows render chDB `DateTime64` as a zone-less UTC string,
/// `"2026-10-07 22:11:05.000000"`, so that form (and its `T`-separated
/// variant) is parsed as UTC alongside RFC 3339 and integer epochs.
fn follow_row_time(row: &serde_json::Value) -> Option<chrono::DateTime<chrono::Utc>> {
    let value = row
        .get("time")
        .or_else(|| row.get("timestamp"))?;
    match value {
        serde_json::Value::String(text) => {
            let text = text.trim();
            if let Ok(time) = chrono::DateTime::parse_from_rfc3339(text) {
                return Some(time.with_timezone(&chrono::Utc));
            }
            ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
                .into_iter()
                .find_map(|format| chrono::NaiveDateTime::parse_from_str(text, format).ok())
                .map(|naive| naive.and_utc())
        }
        serde_json::Value::Number(number) => {
            let epoch = number.as_i64()?;
            if epoch.abs() < FOLLOW_EPOCH_MS_THRESHOLD {
                chrono::DateTime::<chrono::Utc>::from_timestamp(epoch, 0)
            } else {
                chrono::DateTime::<chrono::Utc>::from_timestamp_millis(epoch)
            }
        }
        _ => None,
    }
}

/// Bounded follow cursor (NAN-3244). The initial view is ONE page (the
/// caller's limit); each later head re-reads only
/// `[max(start, floor, newest - grace), now]`, newest first, and stops at the
/// first page that adds nothing. The dedupe set is pruned to that window and
/// capped, so neither the cell nor this process holds the whole window.
#[derive(Debug, Default)]
struct FollowState {
    seen: std::collections::HashMap<String, Option<chrono::DateTime<chrono::Utc>>>,
    newest: Option<chrono::DateTime<chrono::Utc>>,
    /// Events older than this are never delivered: the initial page (or a
    /// head that hit the page cap) was full, so its older backlog is skipped
    /// rather than replayed as if it were new.
    floor: Option<chrono::DateTime<chrono::Utc>>,
    batch_index: u32,
    delivered: u64,
}

impl FollowState {
    fn window_start(&self, start: chrono::DateTime<chrono::Utc>) -> chrono::DateTime<chrono::Utc> {
        let mut window = start;
        if let Some(floor) = self.floor {
            window = window.max(floor);
        }
        if let Some(newest) = self.newest {
            window = window.max(newest - chrono::Duration::seconds(FOLLOW_LATE_GRACE_SECS));
        }
        window
    }

    /// Forget IDs that can no longer appear in a window starting at `start`,
    /// then enforce the hard cap by dropping the oldest (untimed first).
    fn prune(&mut self, start: chrono::DateTime<chrono::Utc>) {
        self.seen.retain(|_, time| time.is_none_or(|time| time >= start));
        if self.seen.len() <= FOLLOW_MAX_SEEN {
            return;
        }
        self.seen.retain(|_, time| time.is_some());
        let excess = self.seen.len().saturating_sub(FOLLOW_MAX_SEEN);
        if excess == 0 {
            return;
        }
        let mut times: Vec<_> = self.seen.values().filter_map(|time| *time).collect();
        let (_, cutoff, _) = times.select_nth_unstable(excess);
        let cutoff = *cutoff;
        self.seen.retain(|_, time| time.is_some_and(|time| time >= cutoff));
    }

    fn remember(&mut self, uid: &str, time: Option<chrono::DateTime<chrono::Utc>>) -> bool {
        if self.seen.contains_key(uid) {
            return false;
        }
        self.seen.insert(uid.to_owned(), time);
        if let Some(time) = time {
            self.newest = Some(self.newest.map_or(time, |newest| newest.max(time)));
        }
        true
    }
}

/// Page sizing across heads (NAN-3264). The first scan reads one page of the
/// caller's limit; later scans read up to [`FOLLOW_MAX_PAGES_PER_HEAD`] pages
/// of [`FOLLOW_HEAD_PAGE_ROWS`]. A transient refusal (memory budget, slow
/// page) halves the page and re-reads the head on the next tick; a success
/// grows it back.
#[derive(Debug)]
struct FollowPacing {
    head_rows: usize,
    page_rows: usize,
    initial_done: bool,
    failures: u32,
}

impl FollowPacing {
    fn new(initial_rows: usize, head_rows: usize) -> Self {
        Self { head_rows, page_rows: initial_rows, initial_done: false, failures: 0 }
    }

    /// `(page rows, max pages)` for the next scan.
    fn next_scan(&self) -> (usize, usize) {
        if self.initial_done {
            (self.page_rows, FOLLOW_MAX_PAGES_PER_HEAD)
        } else {
            (self.page_rows, 1)
        }
    }

    fn page_rows(&self) -> usize { self.page_rows }

    fn retry_pending(&self) -> bool { self.failures > 0 }

    fn succeeded(&mut self) {
        self.failures = 0;
        if !self.initial_done {
            self.initial_done = true;
            self.page_rows = self.head_rows.min(self.page_rows);
        } else {
            self.page_rows = (self.page_rows * 2).min(self.head_rows);
        }
    }

    /// Returns the consecutive failure count.
    fn failed(&mut self) -> u32 {
        self.failures += 1;
        self.page_rows = (self.page_rows / 2).max(FOLLOW_MIN_PAGE_ROWS.min(self.page_rows));
        self.failures
    }
}

/// Scan one committed view newest first, reading at most `max_pages` pages of
/// `page_size` rows inside the bounded follow window. This is also exercised
/// against a real cell HTTP client in the test below.
///
/// NAN-3264: every page is `offset 0`. A later page is fenced by the oldest
/// instant of the page before it (that instant kept), so the cell
/// never compiles more than `page_size + 1` rows; rows tied at that instant
/// come back once more and are recognised as this scan's own.
#[allow(clippy::too_many_arguments)]
async fn scan_cell_follow_view<F, Fut>(
    request: &mut SearchRequest,
    window_start: chrono::DateTime<chrono::Utc>,
    page_size: usize,
    max_pages: usize,
    state: &mut FollowState,
    event_tx: &tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
    cancellation: &mut tokio::sync::watch::Receiver<bool>,
    mut search_page: F,
) -> Result<(), FollowScanError>
where
    F: FnMut(SearchRequest) -> Fut,
    Fut: std::future::Future<Output = Result<SearchResponse, SearchError>>,
{
    use crate::search::streaming::SearchStreamEvent;

    let start = state.window_start(window_start);
    state.prune(start);
    let window_end = request.time_range.end;
    request.time_range.start = start.min(window_end);
    request.limit = Some(page_size);
    request.offset = Some(0);
    // IDs this scan delivered: a fenced page re-reads the rows tied at the
    // previous page's oldest instant, which is not the earlier frontier.
    let mut scanned = std::collections::HashSet::new();
    let mut oldest_on_page = None;
    let result = async {
        for _ in 0..max_pages {
            if *cancellation.borrow() { return Err(FollowScanError::Cancelled); }
            let response = tokio::select! {
                biased;
                _ = event_tx.closed() => return Err(FollowScanError::Disconnected),
                _ = cancellation.changed() => return Err(FollowScanError::Cancelled),
                result = tokio::time::timeout(FOLLOW_PAGE_DEADLINE, search_page(request.clone())) => match result {
                    Ok(result) => result.map_err(FollowScanError::Search)?,
                    Err(_) => return Err(FollowScanError::Slow),
                },
            };
            let page_len = response.results.len();
            if page_len > page_size { return Err(FollowScanError::Exhausted); }
            let mut fresh = Vec::new();
            let mut reached_frontier = false;
            let previous_oldest = oldest_on_page;
            oldest_on_page = None;
            for row in response.results {
                let uid = row.get("metadata.uid").and_then(serde_json::Value::as_str)
                    .or_else(|| row.pointer("/metadata/uid").and_then(serde_json::Value::as_str))
                    .ok_or(FollowScanError::MissingIdentity)?;
                let time = follow_row_time(&row);
                if let Some(time) = time {
                    oldest_on_page = Some(oldest_on_page.map_or(time, |oldest: chrono::DateTime<chrono::Utc>| oldest.min(time)));
                }
                if state.remember(uid, time) {
                    scanned.insert(uid.to_owned());
                    fresh.push(row);
                } else if !scanned.contains(uid) {
                    reached_frontier = true;
                }
            }
            if !fresh.is_empty() {
                if *cancellation.borrow() { return Err(FollowScanError::Cancelled); }
                state.delivered += fresh.len() as u64;
                tokio::select! {
                    biased;
                    _ = cancellation.changed() => return Err(FollowScanError::Cancelled),
                    result = event_tx.send(SearchStreamEvent::Rows {
                        rows: fresh,
                        batch_index: state.batch_index,
                        cumulative_count: state.delivered,
                    }) => result.map_err(|_| FollowScanError::Disconnected)?,
                }
                state.batch_index = state.batch_index.saturating_add(1);
            }
            // A short page is the end of the window. A page holding an event an
            // EARLIER head delivered reached the previous frontier: everything
            // below it was delivered then (late events that sort inside this
            // page were just caught). Only a full page above the frontier
            // continues, fenced at its oldest instant.
            if page_len < page_size || reached_frontier {
                return Ok(());
            }
            match oldest_on_page {
                // The fence must move down, or a page of ties would repeat.
                Some(oldest) if previous_oldest.is_none_or(|previous| oldest < previous) => {
                    // +1 µs: the end bound must keep the instant itself,
                    // whether the cell reads `end` inclusively or not.
                    request.time_range.end =
                        (oldest + chrono::Duration::microseconds(1)).max(request.time_range.start);
                }
                _ => break,
            }
        }
        // Page cap reached on a full page: skip the older backlog for good
        // instead of paging deeper.
        if let Some(oldest) = oldest_on_page {
            state.floor = Some(state.floor.map_or(oldest, |floor| floor.max(oldest)));
        }
        Ok(())
    }.await;
    request.time_range.end = window_end;
    result
}

impl SearchService {
    /// Admission-gated wrapper around [`SearchService::search_streaming`]
    /// (NAN-2039).
    ///
    /// The SSE streaming path previously called `search_streaming` directly,
    /// bypassing the admission boundary that both the synchronous and the
    /// async batch paths go through ([`search_with_admission`] /
    /// [`search_async_with_admission`]): it never acquired a permit, never
    /// entered the per-user / global queue, and never installed the
    /// per-priority ClickHouse settings (`max_execution_time`, priority, …). A
    /// caller with search access could therefore open unbounded parallel SSE
    /// searches that ran outside the concurrency limits and with default CH
    /// limits.
    ///
    /// This mirrors [`search_with_admission`] exactly:
    /// - apply the priority's admit delay so Interactive wins the admit race;
    /// - acquire a permit, held for the WHOLE stream — `search_streaming` runs
    ///   to completion (it awaits every ClickHouse chunk and forwards all
    ///   events) before returning, so `_permit` drops only when the stream
    ///   finishes, freeing the slot then;
    /// - run streaming on a clone whose `active_ch_settings` carry the
    ///   priority's ClickHouse limits (the streaming chunk + count + histogram
    ///   queries all read `active_ch_settings`).
    ///
    /// With no admission controller wired up it falls back to the direct path,
    /// preserving pre-NAN-2039 behavior for un-migrated deployments.
    ///
    /// [`search_with_admission`]: SearchService::search_with_admission
    /// [`search_async_with_admission`]: SearchService::search_async_with_admission
    pub async fn search_streaming_with_admission(
        &self,
        request: SearchRequest,
        event_tx: tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
        user_id: uuid::Uuid,
        priority: super::admission::QueryPriority,
        scope: &ScopeSet,
        follow: bool,
    ) {
        // Lower-priority requests yield briefly before claiming a slot so
        // Interactive requests win the initial admit burst (see
        // `search_with_admission` / NAN-709).
        if let Some(delay) = priority.admit_delay() {
            tokio::time::sleep(delay).await;
        }

        // Dedicated/open-core keeps the historical direct fallback. A shared
        // tenant view fails closed instead of silently converting a missing
        // cell controller into unlimited SSE execution.
        let controller = match self.required_admission_controller() {
            Ok(controller) => controller,
            Err(error) => {
                let _ = event_tx
                    .send(stream_error_event(&error))
                    .await;
                return;
            }
        };
        let Some(controller) = controller else {
            self.search_streaming(request, event_tx, scope, follow).await;
            return;
        };

        let job_id = uuid::Uuid::now_v7().to_string();
        // NAN-2039 (codex P1): when global admission is saturated, `acquire`
        // parks this request in the queue for up to the acquire timeout. If the
        // SSE client disconnects while we are queued, only `event_rx` is
        // dropped — this detached worker would otherwise keep holding its queue
        // slot for the full timeout, making live searches wait or fail with
        // `QueueFull`. Race the acquire against the sender closing (the receiver
        // is dropped when the SSE response is dropped) and, on disconnect,
        // release the queue slot via `cancel_queued` and bail.
        let _permit = tokio::select! {
            biased;
            _ = event_tx.closed() => {
                controller
                    .cancel_queued_for_scope(&job_id, self.admission_scope)
                    .await;
                return;
            }
            result = self.acquire_search_admission(&controller, &job_id, user_id, priority) => match result {
                Ok(permit) => permit,
                Err(e) => {
                    // The SSE response is already open. Preserve the same
                    // unavailable-vs-denied distinction in its terminal event.
                    let error = SearchError::from(e);
                    if matches!(error, SearchError::AdmissionBackendUnavailable) {
                        tracing::warn!(reason = "admission_backend_unavailable", "stream admission failed closed");
                        metrics::counter!("nanosiem_search_jobs_rejected_total", "reason" => "admission_backend_unavailable").increment(1);
                    }
                    let _ = event_tx
                        .send(stream_error_event(&error))
                        .await;
                    return;
                }
            }
        };

        let mut service = self.clone();
        service.active_ch_settings = Some(priority.to_ch_settings());
        // `_permit` is held across the whole stream and drops when
        // `search_streaming` returns (stream complete), freeing the slot.
        service.search_streaming(request, event_tx, scope, follow).await;
    }

    /// Execute a streaming search, sending events through an mpsc channel.
    ///
    /// For streamable queries (non-aggregate, no lookup/prevalence/tree/asset post-processing),
    /// rows are sent incrementally as ClickHouse returns them. For non-streamable queries,
    /// the full search is executed and all rows are delivered in a single batch.
    ///
    /// Progress events are sent periodically by polling ClickHouse system.processes.
    /// The caller receives `SearchStreamEvent` variants and should forward them as SSE events.
    ///
    /// `scope` (NAN-1799): the caller's source-scope deny-set. The STREAMING
    /// path enforces it on the cleaned query text below (chunk SQL, count
    /// companion and histogram all derive from that text / its parse); the
    /// BUFFERED path passes the ORIGINAL request through to
    /// [`SearchService::search`], which enforces it itself — exactly one
    /// injection on either path.
    pub async fn search_streaming(
        &self,
        mut request: SearchRequest,
        event_tx: tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
        scope: &ScopeSet,
        follow: bool,
    ) {
        use crate::search::streaming::{is_query_streamable, SearchStreamEvent};

        match self.retention_bound_input_range(&request.time_range, chrono::Utc::now()) {
            Ok(Some(range)) => request.time_range = range,
            Ok(None) => {
                let _ = event_tx
                    .send(SearchStreamEvent::Completed {
                        total_rows_delivered: 0,
                    })
                    .await;
                return;
            }
            Err(error) => {
                let _ = event_tx
                    .send(SearchStreamEvent::Error {
                        code: "RETENTION_AUTHORITY_UNAVAILABLE".to_string(),
                        message: error.to_string(),
                    })
                    .await;
                return;
            }
        }

        let start_time = Instant::now();
        let query_id = request
            .request_id
            .clone()
            .unwrap_or_else(|| uuid::Uuid::now_v7().to_string());
        let job_id = uuid::Uuid::now_v7().to_string();

        // Register for cancellation
        if request.request_id.is_some() {
            self.query_tracker
                .register(request.request_id.clone().unwrap(), query_id.clone());
        }

        // Helper to send an event, returning false if receiver disconnected
        macro_rules! send_event {
            ($event:expr) => {
                if event_tx.send($event).await.is_err() {
                    tracing::info!("Streaming search: client disconnected");
                    if let Some(ref req_id) = request.request_id {
                        self.query_tracker.unregister(req_id);
                    }
                    let _ = self.cancel_query(&query_id).await;
                    return;
                }
            };
        }

        // Validate time range
        if let Err(e) = request.time_range.validate() {
            send_event!(SearchStreamEvent::Error {
                code: "VALIDATION_ERROR".to_string(),
                message: e.to_string(),
            });
            return;
        }

        // Extract time modifiers and parse query
        let (cleaned_query, earliest_offset, latest_offset) =
            extract_time_modifiers(&request.query);

        // NAN-1799: gate the streaming path's query text with the caller's
        // source-scope deny-set BEFORE the parse below — chunk SQL, the count
        // companion and the histogram all derive from it. Empty deny-set
        // returns the text unchanged (byte-identical). The buffered path
        // deliberately re-runs `search()` on the ORIGINAL request so this is
        // never a double injection.
        let request_dataset =
            crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
        let cleaned_query = match enforce_stream_source_scope(
            &cleaned_query,
            request_dataset,
            self.lake_query.mode,
            scope,
        ) {
            Ok(q) => q,
            Err(e) => {
                send_event!(SearchStreamEvent::Error {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("{}", e),
                });
                return;
            }
        };
        let mut adjusted_time_range = request.time_range.clone();
        if let Some(offset_secs) = earliest_offset {
            adjusted_time_range.start = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
        }
        if let Some(offset_secs) = latest_offset {
            adjusted_time_range.end = chrono::Utc::now() + chrono::Duration::seconds(offset_secs);
        }

        let mut query = match parse_query(&cleaned_query) {
            Ok(q) => q,
            Err(e) => {
                send_event!(SearchStreamEvent::Error {
                    code: "PARSE_ERROR".to_string(),
                    message: format!("{}", e),
                });
                return;
            }
        };

        // NAN-2004: run the SAME input-side field-name validation the batch path
        // applies (core_search.rs, NAN-1354/NAN-1992) so a malformed /
        // injection-shaped field or `rex` capture-group name (e.g. a comma/paren
        // name using `/**/` for whitespace) is rejected HERE too, instead of
        // compiling to a single garbage-named column. `escape_identifier` already
        // neutralizes it in codegen (the payload collapses to one inert quoted
        // alias — no sub-select/currentUser executes), but the streaming path was
        // the one sink that skipped this pre-check; validating on BOTH paths keeps
        // them from drifting if that escape ever regresses. Surfaced as an Error
        // event, matching how this path already reports parse/OOM/time-range
        // errors (the batch path returns an equivalent 400).
        let query_profile = self.dataset_profile(request.dataset.as_deref());
        // NAN-2361: resolve profile-dependent product semantics BEFORE validating,
        // exactly as the batch path does (core_search.rs). A named preset
        // (`tree process` / `tree web`) parses to its UDM-spelled defaults
        // (`parent_process_guid`, `process_guid`, …); under strict canonical OCSF
        // those are not real fields, so validating first rejected the query with
        // "Field not found: parent_process_guid" even though the preset resolves
        // to canonical columns (`actor.process.uid`, `process.uid`). The batch
        // endpoint applied the rewrite and worked; the stream endpoint -- which
        // the UI actually calls -- did not, so `| tree process` failed only in
        // the browser. Another instance of the batch/stream validation drift
        // NAN-2004 fixed for field-name validation.
        if query_profile.uses_strict_canonical_fields() {
            apply_profile_product_semantics(&mut query, query_profile.as_ref());
        }
        if let Err(e) = validate_query_field_names(&query, query_profile.as_ref()) {
            send_event!(SearchStreamEvent::Error {
                code: "VALIDATION_ERROR".to_string(),
                message: format!("{}", e),
            });
            return;
        }

        // NAN-806: apply implicit sort after a trailing `stats`/`chart` with a
        // `by` clause so the outer LIMIT returns top-N groups instead of an
        // arbitrary hash-bucket slice. Streamable queries aren't aggregations,
        // so this only changes behavior on the buffered-aggregate path.
        // Warning emission for the streaming path is deferred (would require a
        // dedicated stream event) — the table-view `search()` endpoint already
        // surfaces it.
        let (query, _auto_sort_decision) = apply_auto_sort(query);

        // Pre-execution guardrail: reject queries that would cause unbounded memory usage (OOM)
        if let Some(risk) = detect_oom_risk(&query) {
            send_event!(SearchStreamEvent::Error {
                code: "VALIDATION_ERROR".to_string(),
                message: risk.message(),
            });
            return;
        }

        // Analyze query for streamability
        let lookup_commands = extract_lookup_commands(&query);
        let inputlookup_commands = extract_inputlookup_commands(&query);
        let prevalence_commands = extract_prevalence_commands(&query);
        let tree_command = extract_tree_command(&query);
        let asset_command = extract_asset_command(&query);
        let cloud_command = extract_cloud_command(&query);
        let ai_command = extract_ai_command(&query);
        let lateral_command = extract_lateral_command(&query);
        let funnel_command = extract_funnel_command(&query);
        // NAN-1868: `| baseline` re-queries in post-processing like asset/cloud —
        // must route through the buffered path or it streams the throwaway fetch.
        let baseline_command = extract_baseline_command(&query);

        // Command-page directives (NAN-1560) short-circuit to a synthetic marker
        // in core_search — force them onto the non-streaming (buffered) path.
        // Single source of truth so a new marker page can't fall through here.
        let is_command_page = is_command_page_marker(determine_display_type(&query));

        let streamable = is_query_streamable(
            &query,
            !lookup_commands.is_empty(),
            !inputlookup_commands.is_empty(),
            !prevalence_commands.is_empty(),
            tree_command.is_some(),
            asset_command.is_some(),
            cloud_command.is_some(),
            ai_command.is_some(),
            lateral_command.is_some(),
            funnel_command.is_some(),
            baseline_command.is_some(),
            is_command_page,
        )
            // NAN-1798 P2: the risk dataset is a derived entity grain whose
            // time bound is constant-true — the streaming path's day-chunk
            // loop relies on the time bound to partition rows, so every chunk
            // would re-emit the SAME full entity set (duplicate rows). Force
            // risk requests onto the buffered path; the grain is
            // entity-cardinality, well within a single response. (A LOGS
            // stream carrying a `[dataset=risk …]` bracket chunks fine — the
            // OUTER logs bound partitions the rows.)
            && request_dataset != crate::query::Dataset::Risk;

        let display_type = determine_display_type(&query);
        let column_order = get_column_order(&query);

        if follow {
            if !streamable
                || !follow_query_supported(&query)
                || query_has_aggregation(&query)
                || request_dataset != crate::query::Dataset::Logs
                || request.offset.unwrap_or(0) != 0
                || self.lake_query.mode != LakeQueryMode::Primary
                || !self.lake_query.client.as_ref().is_some_and(|client| client.is_lake_cell())
            {
                send_event!(SearchStreamEvent::Error {
                    code: "VALIDATION_ERROR".to_string(),
                    message: "Part-log follow requires a cell log event filter without result-changing commands or offset".to_string(),
                });
                return;
            }
        }

        // Send started event
        send_event!(SearchStreamEvent::Started {
            job_id: job_id.clone(),
            query_id: query_id.clone(),
            is_streaming: streamable,
        });

        if follow {
            let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
            let cancel_id = query_id.clone();
            match self.follow_cancellations.entry(cancel_id.clone()) {
                dashmap::mapref::entry::Entry::Vacant(slot) => { slot.insert(cancel_tx); }
                dashmap::mapref::entry::Entry::Occupied(_) => {
                    send_event!(SearchStreamEvent::Error {
                        code: "FOLLOW_ALREADY_ACTIVE".into(),
                        message: "A follow stream with this request ID is already active".into(),
                    });
                    return;
                }
            }
            let _guard = FollowCancelGuard {
                id: cancel_id,
                registry: self.follow_cancellations.clone(),
            };
            self.execute_cell_follow_path(request.clone(), &event_tx, scope, &mut cancel_rx).await;
            if let Some(ref req_id) = request.request_id {
                self.query_tracker.unregister(req_id);
            }
            return;
        }

        let uses_primary_lake = self.lake_query.mode == LakeQueryMode::Primary
            && matches!(
                request_dataset,
                crate::query::Dataset::Logs | crate::query::Dataset::Risk
            );
        let clickhouse_stream_available = self.ch_executor.is_some()
            && !uses_primary_lake
            && (self.backend == SearchBackend::ClickHouse
                || matches!(
                    request_dataset,
                    crate::query::Dataset::Spans | crate::query::Dataset::Metrics
                ));

        if streamable && clickhouse_stream_available {
            // ===== STREAMING PATH: Non-aggregate queries =====
            self.execute_streaming_path(
                &request,
                &query,
                &cleaned_query,
                &adjusted_time_range,
                &query_id,
                &event_tx,
                start_time,
                display_type,
                column_order,
                scope,
            )
            .await;
        } else {
            // ===== BUFFERED PATH: Aggregate / enriched queries =====
            // Execute full search and deliver all results at once
            self.execute_buffered_path(
                request.clone(),
                &query,
                &cleaned_query,
                &adjusted_time_range,
                &query_id,
                &event_tx,
                start_time,
                display_type,
                column_order,
                scope,
            )
            .await;
        }

        // Unregister from tracker
        if let Some(ref req_id) = request.request_id {
            self.query_tracker.unregister(req_id);
        }
    }

    /// Follow committed part-log heads (NAN-3244). The first head delivers ONE
    /// page (the caller's limit, newest first); every later head re-reads only
    /// a short window behind the newest delivered event, newest first, and
    /// stops at the first page that adds nothing. Logical event IDs make
    /// re-reads idempotent across merges. The previous design replayed the
    /// whole requested window in offset pages up to 100k rows on every head,
    /// which exhausted the cell's interactive memory budget within a minute.
    /// The stream completes after [`FOLLOW_MAX_LIFETIME`] so clients reconnect.
    async fn execute_cell_follow_path(
        &self,
        mut request: SearchRequest,
        event_tx: &tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
        scope: &ScopeSet,
        cancellation: &mut tokio::sync::watch::Receiver<bool>,
    ) {
        use crate::search::streaming::SearchStreamEvent;

        let Some(client) = self.lake_query.client.as_ref() else { return };
        let page_size = self.config.max_limit.min(1_000);
        if page_size == 0 {
            let _ = event_tx.send(SearchStreamEvent::Error {
                code: "FOLLOW_WINDOW_EXHAUSTED".into(),
                message: "No result page capacity is configured for part-log follow".into(),
            }).await;
            return;
        }
        let initial_limit = request
            .limit
            .unwrap_or(page_size)
            .clamp(1, page_size.min(FOLLOW_INITIAL_MAX_ROWS));
        let head_page_rows = page_size.min(FOLLOW_HEAD_PAGE_ROWS);
        let window_start = request.time_range.start;
        let mut state = FollowState::default();
        let mut pacing = FollowPacing::new(initial_limit, head_page_rows);
        let mut last_head: Option<Option<(u64, String)>> = None;
        let deadline = tokio::time::Instant::now() + FOLLOW_MAX_LIFETIME;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(2));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_sent = tokio::time::Instant::now();
        request.skip_histogram = true;
        request.skip_field_stats = true;
        request.use_cache = false;
        request.table_view = false;

        loop {
            if *cancellation.borrow() {
                let _ = event_tx.send(SearchStreamEvent::Error {
                    code: "QUERY_CANCELLED".into(), message: "Query was cancelled".into(),
                }).await;
                return;
            }
            tokio::select! {
                _ = event_tx.closed() => return,
                _ = cancellation.changed() => continue,
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = event_tx.send(SearchStreamEvent::Completed {
                        total_rows_delivered: state.delivered,
                    }).await;
                    return;
                }
                _ = interval.tick() => {}
            }
            // NAN-3264: liveness from the follow loop itself, so a client
            // can tell "nothing new" from "the follow is stuck".
            if last_sent.elapsed() >= FOLLOW_HEARTBEAT_EVERY {
                if event_tx.send(SearchStreamEvent::Heartbeat { delivered: state.delivered }).await.is_err() {
                    return;
                }
                last_sent = tokio::time::Instant::now();
            }
            let head = match tokio::select! {
                _ = event_tx.closed() => return,
                _ = cancellation.changed() => continue,
                head = client.lake_cell_part_log_head() => head,
            } {
                Ok(head) => head,
                Err(error) => {
                    let _ = event_tx.send(stream_error_event(&error)).await;
                    return;
                }
            };
            // A head whose scan failed transiently is re-read even if the
            // part log has not moved since.
            if last_head.as_ref() == Some(&head) && !pacing.retry_pending() { continue; }
            if let (Some(Some((previous, _))), Some((current, _))) = (&last_head, &head) {
                if current < previous {
                    let _ = event_tx.send(SearchStreamEvent::Error {
                        code: "PART_LOG_REGRESSED".into(),
                        message: "The tenant part log moved backwards; reconnect and retry".into(),
                    }).await;
                    return;
                }
            }
            last_head = Some(head);
            request.time_range.end = chrono::Utc::now();
            let (limit, pages) = pacing.next_scan();
            let delivered_before = state.delivered;
            let outcome = scan_cell_follow_view(
                &mut request, window_start, limit, pages, &mut state,
                event_tx, cancellation, |page| self.search(page, scope),
            ).await;
            if state.delivered != delivered_before {
                last_sent = tokio::time::Instant::now();
            }
            let error = match outcome {
                Ok(()) => {
                    pacing.succeeded();
                    continue;
                }
                Err(error) if error.is_transient() => {
                    let failures = pacing.failed();
                    tracing::warn!(
                        error = ?error, failures, next_page_rows = pacing.page_rows(),
                        "lean follow head refused or slow; retrying with a smaller page"
                    );
                    if failures < FOLLOW_MAX_TRANSIENT_FAILURES {
                        continue;
                    }
                    error
                }
                Err(error) => error,
            };
            match error {
                FollowScanError::Disconnected => return,
                FollowScanError::Cancelled => {
                    let _ = event_tx.send(SearchStreamEvent::Error {
                        code: "QUERY_CANCELLED".into(), message: "Query was cancelled".into(),
                    }).await;
                    return;
                }
                FollowScanError::Search(error) => {
                    let _ = event_tx.send(stream_error_event(&error)).await;
                    return;
                }
                FollowScanError::Slow => {
                    let _ = event_tx.send(SearchStreamEvent::Error {
                        code: "FOLLOW_SLOW".into(),
                        message: "The follow stream's reads kept timing out; reconnect and retry".into(),
                    }).await;
                    return;
                }
                FollowScanError::MissingIdentity => {
                    let _ = event_tx.send(SearchStreamEvent::Error {
                        code: "PART_LOG_IDENTITY_MISSING".into(),
                        message: "A cell event has no stable metadata.uid".into(),
                    }).await;
                    return;
                }
                FollowScanError::Exhausted => {
                    let _ = event_tx.send(SearchStreamEvent::Error {
                        code: "FOLLOW_WINDOW_EXHAUSTED".into(),
                        message: "The follow window is too large to replay safely; narrow the time range".into(),
                    }).await;
                    return;
                }
            }
        }
    }

    /// Spawn a background task that polls ClickHouse `system.processes` every 500ms
    /// and sends `SearchStreamEvent::Progress` through the given channel.
    /// Returns a `JoinHandle` — caller should `.abort()` it when the query finishes.
    fn spawn_progress_poller(
        ch_client: Option<clickhouse::Client>,
        query_id: &str,
        progress_tx: tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
    ) -> tokio::task::JoinHandle<()> {
        use crate::search::streaming::SearchStreamEvent;

        // Validate query_id is alphanumeric/hyphens only (UUIDs) to prevent SQL injection
        let safe_qid: String = query_id
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .collect();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
            interval.tick().await; // Skip immediate tick

            loop {
                interval.tick().await;

                if let Some(ref client) = ch_client {
                    // NAN-2330: cluster fan-out is performed by the narrow
                    // SQL SECURITY DEFINER view. The runtime key never receives
                    // ClickHouse's broad REMOTE privilege.
                    let progress_source = crate::db::dual_pool::system_processes_source();
                    let progress_sql = format!(
                        "SELECT read_rows, total_rows_approx, elapsed \
                         FROM {} WHERE query_id = '{}'",
                        progress_source, safe_qid
                    );
                    if let Ok(mut cursor) = client.query(&progress_sql).fetch_bytes("JSONEachRow") {
                        let mut bytes = Vec::new();
                        while let Ok(Some(chunk)) = cursor.next().await {
                            bytes.extend_from_slice(&chunk);
                        }
                        if let Ok(text) = String::from_utf8(bytes) {
                            if let Some(line) = text.lines().next() {
                                if let Ok(row) = serde_json::from_str::<serde_json::Value>(line) {
                                    let rows_scanned =
                                        row.get("read_rows").and_then(|v| v.as_u64()).unwrap_or(0);
                                    let rows_total = row
                                        .get("total_rows_approx")
                                        .and_then(|v| v.as_u64())
                                        .unwrap_or(0);
                                    let elapsed =
                                        row.get("elapsed").and_then(|v| v.as_f64()).unwrap_or(0.0);
                                    let percent = if rows_total > 0 {
                                        ((rows_scanned as f64 / rows_total as f64) * 100.0)
                                            .min(99.0) as u8
                                    } else {
                                        0
                                    };

                                    if progress_tx
                                        .send(SearchStreamEvent::Progress {
                                            rows_scanned,
                                            rows_total,
                                            percent,
                                            elapsed_ms: (elapsed * 1000.0) as u64,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        // Receiver dropped — stop polling
                                        return;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        })
    }

    /// Streaming execution path: sends result rows incrementally as ClickHouse returns them.
    ///
    /// Splits the time range into daily chunks (newest first) matching ClickHouse's
    /// `toYYYYMMDD(timestamp)` partitions. Each single-partition query sorts quickly
    /// and streams rows immediately instead of buffering the full ORDER BY across the
    /// entire time range.
    async fn execute_streaming_path(
        &self,
        request: &SearchRequest,
        query: &crate::query::Query,
        cleaned_query: &str,
        adjusted_time_range: &TimeRangeInput,
        query_id: &str,
        event_tx: &tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
        start_time: Instant,
        display_type: DisplayType,
        column_order: Option<Vec<String>>,
        scope: &ScopeSet,
    ) {
        use crate::query::QueryOptions;
        use crate::search::streaming::{compute_daily_chunks, SearchStreamEvent, StreamingChunk};

        let ch_executor = match self.ch_executor.as_ref() {
            Some(e) => e,
            None => {
                let _ = event_tx
                    .send(SearchStreamEvent::Error {
                        code: "CONFIG_ERROR".to_string(),
                        message: "ClickHouse not configured".to_string(),
                    })
                    .await;
                return;
            }
        };

        let is_aggregation = query_has_aggregation(query);

        let page_limit = request
            .limit
            .unwrap_or(self.config.default_limit)
            .min(self.config.max_limit);
        // Keep the same two-limit contract as buffered search: generated
        // aggregate SQL has an independent high-cardinality safety ceiling,
        // while request.limit is applied by an outer wrapper to the rows sent.
        let generator_limit = if is_aggregation {
            AGGREGATE_OUTPUT_CAP
        } else {
            page_limit
        };
        let options = QueryOptions {
            use_cache: request.use_cache,
            table_view: request.table_view,
            limit: Some(generator_limit),
            unordered: false,
        };

        let full_time_range =
            crate::query::TimeRange::new(adjusted_time_range.start, adjusted_time_range.end);

        // NAN-1555: thread the observability dataset (logs|spans|metrics) into the
        // streaming generator. The table-view FIRST PAGE streams, so without this
        // the `dataset` selector was silently ignored on the streaming path (only
        // the non-streaming `core_search` path threaded it) — a `dataset=spans`
        // search ran against `logs` and returned 0. `Dataset::Logs` is left
        // untouched (byte-identical). Streamed queries are non-aggregate, so the
        // metrics rollup routing (aggregate-only) does not apply here.
        let stream_gen = {
            let dataset =
                crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
            // NAN-1798 P2: the derived risk base needs the per-request
            // decay/cleared config resolved BEFORE any dataset swap, same as
            // core_search — otherwise a streamed table-view first page (or a
            // streamed logs query carrying a `[dataset=risk …]` bracket)
            // would silently compute default-config scores. Same cheap
            // textual pre-filter as core_search for the subsearch case.
            // NAN-2009 (F20/F21): carry the caller's source-scope deny-set so the
            // resolve_identity ASOF join to identity_observations (a dataset the
            // nPL-text gate does not cover) filters its build side. Empty
            // deny-set = byte-identical SQL.
            let mut generator = self
                .ch_sql_generator
                .clone()
                .with_source_scope_deny(scope.deny_set().clone());
            if super::touches_risk_dataset(request.dataset.as_deref(), &request.query) {
                generator = generator.with_risk_config(self.risk_query_config.resolve().await);
            }
            if dataset == crate::query::Dataset::Logs {
                generator
            } else {
                generator.with_dataset(dataset)
            }
        };

        // For non-aggregate queries, run a count query in parallel so metadata
        // reports the real total. For aggregation, the total is the row count
        // of the streamed output (number of groups).
        // NAN-1428: companions carry derived ids ({query_id}-count / -hist) and
        // the resolved per-priority settings, so a disconnect/cancel kills them
        // along with the chunk queries and admission limits bound them.
        let count_handle = if !is_aggregation {
            // NAN-1635 (finding 3.4): the companion must count the FULL match
            // set. The data `options` bake `limit: Some(page)` — counting that
            // SQL as-is would report min(total, page). Regenerate with
            // `limit: None` (user `| head N` caps survive: they are query
            // semantics per the QueryOptions contract) and `unordered` (the
            // trailing ORDER BY is dead weight under the count(*) wrap).
            let count_options = QueryOptions {
                limit: None,
                unordered: true,
                ..options.clone()
            };
            let count_sql = stream_gen
                .generate_with_options(query, &full_time_range, &count_options)
                .ok();
            let count_executor = ch_executor.clone();
            let count_qid = format!("{query_id}-count");
            let count_settings = self.active_ch_settings.clone();
            Some(tokio::spawn(super::super::request_actor::inherit(async move {
                if let Some(sql) = count_sql {
                    count_executor
                        .quick_count(&sql, Some(&count_qid), count_settings.as_ref())
                        .await
                        .ok()
                } else {
                    None
                }
            })))
        } else {
            None
        };

        // Start histogram query in parallel with chunk streaming — it only needs
        // the base query and full time range, so it can run independently.
        //
        // NAN-1429: skipped when the UI never renders a timeline for this
        // display type (same gate as the sync path in core_search.rs).
        let histogram_handle = if !request.skip_histogram
            && super::display_type_renders_timeline(display_type)
        {
            let search_service = self.clone();
            let histogram_query = cleaned_query.to_string();
            let histogram_time_range = adjusted_time_range.clone();
            let hist_qid = format!("{query_id}-hist");
            // NAN-1557: the timeline reads the same dataset as the results.
            let histogram_dataset =
                crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"));
            let histogram_deny_source_types = scope.deny_set().clone();
            Some(tokio::spawn(super::super::request_actor::inherit(async move {
                match search_service
                    .generate_histogram(
                        &histogram_query,
                        &histogram_time_range,
                        Some(&hist_qid),
                        histogram_dataset,
                        &histogram_deny_source_types,
                    )
                    .await
                {
                    Ok(h) => Some(h),
                    Err(e) => {
                        tracing::warn!("Parallel histogram query failed: {}", e);
                        None
                    }
                }
            })))
        } else {
            None
        };

        let mut batch_index: u32 = 0;
        let mut cumulative_count: u64 = 0;
        let mut aggregate_total_count: Option<u64> = None;
        let mut chunks_queried: usize = 0;

        // Aggregation queries run a single query across the full time range —
        // daily chunking would produce partial aggregates.
        // Non-aggregate queries split into daily chunks for partition-aligned streaming.
        let chunk_ranges: Vec<(chrono::DateTime<chrono::Utc>, chrono::DateTime<chrono::Utc>)> =
            if is_aggregation {
                vec![(adjusted_time_range.start, adjusted_time_range.end)]
            } else {
                compute_daily_chunks(adjusted_time_range.start, adjusted_time_range.end)
            };

        for (chunk_idx, (chunk_start, chunk_end)) in chunk_ranges.iter().enumerate() {
            let remaining = page_limit.saturating_sub(cumulative_count as usize);
            if remaining == 0 {
                break;
            }
            chunks_queried += 1;

            // Generate SQL for this chunk's time range
            let chunk_time_range = crate::query::TimeRange::new(*chunk_start, *chunk_end);
            let chunk_sql =
                match stream_gen.generate_with_options(query, &chunk_time_range, &options) {
                    Ok(s) => s,
                    Err(e) => {
                        let _ = event_tx
                            .send(SearchStreamEvent::Error {
                                code: "SQL_GEN_ERROR".to_string(),
                                message: e.to_string(),
                            })
                            .await;
                        return;
                    }
                };

            // Inject per-chunk LIMIT with offset=0.  Streaming delivers rows
            // newest-first across partition chunks, so the global request.offset
            // is intentionally not applied here (offset-based pagination is only
            // meaningful for the non-streaming path).
            let paginated_sql = if is_aggregation {
                // The generated LIMIT is the internal aggregate-output cap.
                // Apply the caller page outside it and carry the bounded total
                // in-band so normal pages remain one ClickHouse query.
                super::execution::clickhouse_executor::wrap_aggregation_with_pagination(
                    &chunk_sql, remaining, 0,
                )
            } else {
                debug_assert!(
                    request.offset.unwrap_or(0) == 0,
                    "streaming path does not support offset-based pagination"
                );
                super::execution::clickhouse_executor::inject_limit_offset(&chunk_sql, remaining, 0)
            };

            // Each chunk gets a unique query_id for cancellation/progress tracking
            let chunk_qid = format!("{}-chunk-{}", query_id, chunk_idx);

            // Spawn progress polling for this chunk
            let progress_handle =
                Self::spawn_progress_poller(self.ch_client.clone(), &chunk_qid, event_tx.clone());

            // Create channel for streaming chunks from executor
            let (chunk_tx, mut chunk_rx) = tokio::sync::mpsc::channel::<StreamingChunk>(32);

            // Spawn the ClickHouse streaming executor for this chunk
            let executor = ch_executor.clone();
            let sql_clone = paginated_sql.clone();
            let qid_clone = chunk_qid.clone();
            let settings = self.active_ch_settings.clone();
            // NAN-1848: same contract as the buffered path — a grouped query's
            // keys are its rows' identity and must not be pruned when empty.
            let grouped_output = query_produces_grouped_rows(query);
            let exec_handle = tokio::spawn(super::super::request_actor::inherit(async move {
                executor
                    .execute_dynamic_query_streaming(
                        &sql_clone,
                        &qid_clone,
                        settings.as_ref(),
                        chunk_tx,
                        grouped_output,
                    )
                    .await
            }));

            // Forward streaming chunks as SSE events
            let mut chunk_errored = false;
            while let Some(chunk) = chunk_rx.recv().await {
                match chunk {
                    StreamingChunk::Rows(mut rows) => {
                        if is_aggregation {
                            aggregate_total_count =
                                take_aggregation_total(&mut rows).or(aggregate_total_count);
                        }
                        let count = rows.len() as u64;
                        cumulative_count += count;
                        if event_tx
                            .send(SearchStreamEvent::Rows {
                                rows,
                                batch_index,
                                cumulative_count,
                            })
                            .await
                            .is_err()
                        {
                            // Client disconnected — abort
                            progress_handle.abort();
                            exec_handle.abort();
                            let _ = ch_executor.cancel_query(&chunk_qid).await;
                            return;
                        }
                        batch_index += 1;
                    }
                    StreamingChunk::Error(msg) => {
                        let _ = event_tx
                            .send(SearchStreamEvent::Error {
                                code: "QUERY_ERROR".to_string(),
                                message: msg,
                            })
                            .await;
                        progress_handle.abort();
                        chunk_errored = true;
                        break;
                    }
                }
            }

            // Clean up this chunk's progress poller and executor
            progress_handle.abort();
            if chunk_errored {
                return;
            }
            if let Ok(Err(e)) = exec_handle.await {
                let _ = event_tx
                    .send(stream_error_event(&e))
                    .await;
                return;
            }

            // If we've hit the limit, stop querying further chunks
            if cumulative_count as usize >= page_limit {
                break;
            }
        }

        // Detect if we stopped early (didn't query all chunks) due to LIMIT
        let chunks_queried_all = is_aggregation || chunks_queried >= chunk_ranges.len();

        let execution_time_ms = start_time.elapsed().as_millis() as u64;

        // For non-aggregate queries, use the parallel count query result.
        // For aggregation, the total is just how many groups were streamed.
        let real_total = if let Some(handle) = count_handle {
            handle
                .await
                .ok()
                .flatten()
                .unwrap_or(cumulative_count)
                .min(self.config.max_limit as u64)
        } else {
            aggregate_total_count.unwrap_or(cumulative_count)
        };

        // Collect histogram from the parallel task spawned before chunk streaming
        let histogram = if let Some(handle) = histogram_handle {
            handle.await.ok().flatten()
        } else {
            None
        };

        // Analyze query cost and merge with runtime warnings
        let cost_analysis = crate::query::analyze_query_cost(query);
        let mut all_warnings: Vec<QueryWarningOutput> = cost_analysis
            .warnings
            .iter()
            .map(|w| QueryWarningOutput {
                severity: match w.severity {
                    WarningSeverity::Info => "info".to_string(),
                    WarningSeverity::Warning => "warning".to_string(),
                    WarningSeverity::Error => "error".to_string(),
                },
                code: w.code.clone(),
                message: w.message.clone(),
                suggestion: w.suggestion.clone(),
                impact: w.impact.clone(),
            })
            .collect();

        // See `should_emit_partial_time_range_warning` for rationale.
        if should_emit_partial_time_range_warning(
            chunks_queried_all,
            cumulative_count,
            self.config.max_limit,
        ) {
            let total_chunks = chunk_ranges.len();
            let oldest_covered = chunk_ranges
                .iter()
                .take(chunks_queried)
                .last()
                .map(|(start, _)| start.format("%Y-%m-%d %H:%M:%S UTC").to_string())
                .unwrap_or_default();
            let requested_start = adjusted_time_range
                .start
                .format("%Y-%m-%d %H:%M:%S UTC")
                .to_string();
            all_warnings.push(QueryWarningOutput {
                severity: "warning".to_string(),
                code: "PARTIAL_TIME_RANGE".to_string(),
                message: format!(
                    "Query matched more than {} rows (the maximum). Scanned {} of {} daily partitions \
                     before hitting the cap. Only data from {} onward is included; the requested range \
                     started at {}.",
                    self.config.max_limit, chunks_queried, total_chunks, oldest_covered, requested_start
                ),
                suggestion: Some(
                    "Narrow the time range or add filters to scan the full requested range".to_string()
                ),
                impact: Some(
                    "Events from older days in the requested time range were not searched".to_string()
                ),
            });
        }

        let (warnings_output, cost_score) = if all_warnings.is_empty() {
            (None, None)
        } else {
            (Some(all_warnings), Some(cost_analysis.estimated_cost))
        };

        // Send metadata with real total (not just delivered rows)
        let _ = event_tx
            .send(SearchStreamEvent::Metadata {
                completeness: None,
                total_count: real_total,
                // The streaming ClickHouse path reports the count companion's
                // real total, not a page bound.
                total_count_exact: true,
                execution_time_ms,
                fields: Vec::new(), // Field stats calculated separately
                histogram,
                warnings: warnings_output,
                cost_score,
                display_type: Some(display_type),
                column_order,
                generated_sql: None,
            })
            .await;

        // Send completed
        let _ = event_tx
            .send(SearchStreamEvent::Completed {
                total_rows_delivered: cumulative_count,
            })
            .await;
    }

    /// Buffered execution path: runs the full search and delivers all results at once via SSE.
    ///
    /// `request` carries the ORIGINAL (un-enforced) query text: `search()`
    /// applies the source-scope injection itself, so passing the pre-enforced
    /// text here would double-gate (NAN-1799).
    async fn execute_buffered_path(
        &self,
        mut request: SearchRequest,
        query: &crate::query::Query,
        _cleaned_query: &str,
        adjusted_time_range: &TimeRangeInput,
        query_id: &str,
        event_tx: &tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
        _start_time: Instant,
        _display_type: DisplayType,
        _column_order: Option<Vec<String>>,
        scope: &ScopeSet,
    ) {
        use crate::search::streaming::SearchStreamEvent;

        // One exact full-window histogram companion rides on the single
        // Metadata event and the response cache; `search()` is told to skip
        // its own companion so this path never duplicates the work.
        //
        // The companion starts only AFTER the visible page is delivered. On a
        // lean cell both share the tenant's query CPU (3 vCPU) and two engine
        // lanes, and a bare-keyword histogram is a full-window text scan: run
        // side by side, the newest-first page (~0.5 s alone) finished with the
        // histogram, so a 24 h `powershell` showed its first row after ~7.7 s.
        // Sequenced, rows arrive as soon as the page is ready and the chart
        // follows; the stream still completes with one Metadata event.
        let run_lake_histogram = self.lake_query.mode == LakeQueryMode::Primary
            && crate::query::Dataset::from_selector(request.dataset.as_deref().unwrap_or("logs"))
                == crate::query::Dataset::Logs
            && !request.skip_histogram
            && request.offset.unwrap_or(0) == 0
            && super::lake_histogram_applies(query);
        if run_lake_histogram {
            request.skip_histogram = true;
        }
        let histogram_query = query.pretty_print();
        let histogram_query_id = format!("{query_id}-hist");

        // Spawn progress polling for this query too
        let progress_handle =
            Self::spawn_progress_poller(self.ch_client.clone(), query_id, event_tx.clone());
        // NAN-3644: a lean-cell read reports its cold-data progress (bytes
        // read of the bytes its admitted leases will read, and whether it is
        // queued for the cell's heavy cold-read slot). The cell keys it by
        // the request id its reads carry, so the read must carry this one.
        let cold_progress_handle = match self.lake_query.client.as_ref()
            .filter(|client| self.lake_query.mode == LakeQueryMode::Primary && client.is_lake_cell())
        {
            Some(client) => {
                if request.request_id.is_none() {
                    request.request_id = Some(query_id.to_string());
                }
                Some(spawn_cold_progress_poller(client.clone(), query_id.to_string(), event_tx.clone()))
            }
            None => None,
        };
        let progress_handle = AbortOnDrop(vec![progress_handle].into_iter().chain(cold_progress_handle).collect());

        // Execute the search. A lean-cell raw-event search pages through
        // query[T] (NAN-3046) and its pages arrive on the row sink while the
        // search runs; they are forwarded as they come, so neither this
        // process nor query[T] ever holds the whole result.
        let (sink_tx, mut sink_rx) = tokio::sync::mpsc::channel::<Vec<serde_json::Value>>(2);
        let search = crate::search::streaming::LATERAL_VIEW_SINK.scope(event_tx.clone(),
            super::core_search::LAKE_ROW_SINK.scope(sink_tx, self.search(request, scope)));
        tokio::pin!(search);
        let mut streamed = 0_u64;
        let mut batch_index = 0_u32;
        let result = loop {
            tokio::select! {
                result = &mut search => break result,
                Some(rows) = sink_rx.recv() => {
                    streamed += rows.len() as u64;
                    let event = SearchStreamEvent::Rows { rows, batch_index, cumulative_count: streamed };
                    batch_index = batch_index.saturating_add(1);
                    if event_tx.send(event).await.is_err() {
                        progress_handle.abort_all();
                        return;
                    }
                }
            }
        };
        while let Ok(rows) = sink_rx.try_recv() {
            streamed += rows.len() as u64;
            let event = SearchStreamEvent::Rows { rows, batch_index, cumulative_count: streamed };
            batch_index = batch_index.saturating_add(1);
            if event_tx.send(event).await.is_err() {
                progress_handle.abort_all();
                return;
            }
        }
        progress_handle.abort_all();

        match result {
            Ok(mut response) => {
                let rows = std::mem::take(&mut response.results);
                let row_count = streamed + rows.len() as u64;

                // Send the (remaining) rows in one batch
                if !rows.is_empty() {
                    if event_tx
                        .send(SearchStreamEvent::Rows {
                            rows,
                            batch_index,
                            cumulative_count: row_count,
                        })
                        .await
                        .is_err()
                    {
                        return;
                    }
                }

                if run_lake_histogram {
                    match self
                        .generate_histogram(
                            &histogram_query,
                            adjusted_time_range,
                            Some(&histogram_query_id),
                            crate::query::Dataset::Logs,
                            scope.deny_set(),
                        )
                        .await
                    {
                        Ok(histogram) => {
                            super::core_search::attach_lake_histogram(
                                &mut response,
                                histogram,
                                super::lake_histogram_counts_result_rows(query),
                            );
                        }
                        Err(error) => {
                            tracing::warn!(error = %error, "Lake histogram query failed");
                        }
                    }
                }

                // Send metadata
                let _ = event_tx
                    .send(SearchStreamEvent::Metadata {
                        completeness: response.completeness,
                        total_count: response.total_count,
                        total_count_exact: response.total_count_exact,
                        execution_time_ms: response.execution_time_ms,
                        fields: response.fields,
                        histogram: response.histogram,
                        warnings: response.warnings,
                        cost_score: response.cost_score,
                        display_type: response.display_type,
                        column_order: response.column_order,
                        generated_sql: response.generated_sql,
                    })
                    .await;

                // Send completed
                let _ = event_tx
                    .send(SearchStreamEvent::Completed {
                        total_rows_delivered: row_count,
                    })
                    .await;
            }
            Err(e) => {
                // SSE is the UI's default interactive surface, so it needs the same
                // classification the REST routes got: a dependency outage must not
                // read as "your query is wrong", and an internal error must not ship
                // its raw Display (which carries the worker URL from reqwest and raw
                // database text) to the analyst.
                let _ = event_tx
                    .send(stream_error_event(&e))
                    .await;
            }
        }
    }
}

/// Aborts its tasks when dropped, so every early return of the buffered path
/// stops its pollers.
struct AbortOnDrop(Vec<tokio::task::JoinHandle<()>>);

impl AbortOnDrop {
    fn abort_all(&self) {
        for handle in &self.0 {
            handle.abort();
        }
    }
}

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.abort_all();
    }
}

/// How often a lean-cell read's cold-data progress is polled.
const COLD_PROGRESS_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// NAN-3644: poll query[T] for the cold-read progress of `query_id`'s reads
/// and forward it as `progress` events (phase `cold_scan`) while they fetch
/// uncached data or wait for the cell's heavy cold-read slot. Warm reads
/// report nothing (no uncached bytes), so they send no event. Best effort: a
/// failed or missing poll is a skipped tick. The caller aborts the task.
fn spawn_cold_progress_poller(
    client: crate::search::lake::LakeQueryClient,
    query_id: String,
    event_tx: tokio::sync::mpsc::Sender<crate::search::streaming::SearchStreamEvent>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let started = Instant::now();
        let mut interval = tokio::time::interval(COLD_PROGRESS_POLL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        let mut last = None;
        loop {
            interval.tick().await;
            let Ok(Some(progress)) = client.lake_cell_cold_progress(&query_id).await else { continue };
            if progress.cold_bytes_total == 0 && !progress.queued {
                continue;
            }
            if last == Some(progress) {
                continue;
            }
            last = Some(progress);
            let event = crate::search::streaming::cold_scan_progress_event(
                progress.cold_bytes_read,
                progress.cold_bytes_total,
                progress.queued,
                started.elapsed().as_millis() as u64,
            );
            if event_tx.send(event).await.is_err() {
                return;
            }
        }
    })
}

/// Remove the executor's in-band aggregate total before rows cross the SSE API.
/// Every non-empty page carries the same window count, so reading the first is
/// sufficient and keeps aggregate pages to one ClickHouse query.
fn take_aggregation_total(rows: &mut [serde_json::Value]) -> Option<u64> {
    let mut total_count = None;
    for row in rows {
        if let Some(object) = row.as_object_mut() {
            if total_count.is_none() {
                total_count = object
                    .get("_total_count")
                    .and_then(serde_json::Value::as_u64);
            }
            object.remove("_total_count");
        }
    }
    total_count
}

/// Gate for the `PARTIAL_TIME_RANGE` warning.
///
/// The warning fires only when the scan stopped before covering every daily
/// partition *and* the row accumulator reached the global `max_limit` ceiling.
/// Early-exit that merely fills a smaller `request.limit` is not surfaced:
/// streaming reads newest partition first with `ORDER BY timestamp DESC`, so
/// the returned rows are the newest N matches in the range by definition,
/// and `total_count` metadata already reports the true total.
fn should_emit_partial_time_range_warning(
    chunks_queried_all: bool,
    cumulative_count: u64,
    max_limit: usize,
) -> bool {
    !chunks_queried_all && cumulative_count as usize >= max_limit
}

/// Classify a streaming failure for the client.
///
/// Mirrors `nanosiem-search`'s `mask_query_failure`: the outcomes whose status IS
/// their contract keep their identity, everything else is masked behind a stable
/// message so a transport or database detail never reaches the analyst.
fn stream_error_event(error: &SearchError) -> crate::search::streaming::SearchStreamEvent {
    use crate::search::streaming::SearchStreamEvent;
    if let SearchError::ColdScanTooLarge { needed_bytes, ceiling_bytes, background_ceiling_bytes } = error {
        return SearchStreamEvent::ColdScanError {
            code: "COLD_SCAN_TOO_LARGE",
            message: error.to_string(),
            reason: "cold_scan_too_large",
            needed_bytes: *needed_bytes,
            ceiling_bytes: *ceiling_bytes,
            background_ceiling_bytes: *background_ceiling_bytes,
            retryable: false,
        };
    }
    let (code, message) = stream_error_payload(error);
    SearchStreamEvent::Error { code: code.into(), message }
}

fn stream_error_payload(error: &SearchError) -> (&'static str, String) {
    match error {
        SearchError::ColdScanTooLarge { .. } => ("COLD_SCAN_TOO_LARGE", error.to_string()),
        SearchError::ResourceExhausted(_) => ("RESOURCE_EXHAUSTED", error.to_string()),
        SearchError::SearchAdmissionUnavailable(message) => {
            ("SEARCH_ADMISSION_UNAVAILABLE", message.clone())
        }
        SearchError::TenantLakePublicationDegraded(message) => {
            ("TENANT_LAKE_PUBLICATION_DEGRADED", message.clone())
        }
        SearchError::ServiceUnavailable(_) => (
            "SERVICE_UNAVAILABLE",
            "A required search service is temporarily unavailable; retry shortly".to_string(),
        ),
        SearchError::LakeWorkerNotReady(_) => (
            "TENANT_LAKE_WORKER_NOT_READY",
            "The tenant's lake query worker is not ready yet; retry shortly".to_string(),
        ),
        SearchError::AdmissionBackendUnavailable => ("ADMISSION_BACKEND_UNAVAILABLE", error.to_string()),
        SearchError::AdmissionDenied(message) => ("ADMISSION_DENIED", message.clone()),
        SearchError::Cancelled => ("QUERY_CANCELLED", "Query was cancelled".to_string()),
        // User-authored query faults carry their own guidance and are safe to echo.
        SearchError::ParseError(message)
        | SearchError::StructuredParseError {
            formatted: message, ..
        }
        | SearchError::SqlValidationError(message) => ("QUERY_ERROR", message.clone()),
        _ => ("QUERY_ERROR", "Query processing failed".to_string()),
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn cell_follow_replays_new_heads_without_reemitting_merged_parts() {
        use crate::search::lake::LakeQueryClient;
        use crate::search::lake_cell::LakeCellRoute;
        use crate::search::streaming::SearchStreamEvent;
        use std::collections::BTreeSet;
        use std::sync::Arc;
        use wiremock::matchers::{body_partial_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let tenant = uuid::Uuid::from_u128(0xa);
        let token_path = dir.path().join("router.token");
        std::fs::write(&token_path, "cell-test-router-token-cell-test-router-token").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o400)).unwrap();
        let route = LakeCellRoute::for_test(tenant, &server.uri(), token_path);
        let client = Arc::new(LakeQueryClient::new_lake_cell(&route, std::time::Duration::from_secs(5)).unwrap());
        let mut request: crate::search::SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "*", "time_range": {
                "start": "2026-09-25T00:00:00Z", "end": "2026-09-26T00:00:00Z"
            }
        })).unwrap();
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let (cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let mut state = super::FollowState::default();
        let window_start = request.time_range.start;

        for (seq, rows, expected) in [
            (1_u64, serde_json::json!([{"metadata.uid":"e2"}, {"metadata.uid":"e1"}]), vec!["e2", "e1"]),
            (2_u64, serde_json::json!([{"metadata.uid":"e3"}, {"metadata.uid":"e2"}, {"metadata.uid":"e1"}]), vec!["e3"]),
        ] {
            server.reset().await;
            let tenant_s = tenant.to_string();
            Mock::given(method("GET"))
                .and(path(format!("/v1/tenants/{tenant_s}/query/v1/status")))
                .and(header("authorization", "Bearer cell-test-router-token-cell-test-router-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true, "tenant_id": tenant_s, "source_mode": "parts",
                    "log_head": {"seq": seq, "sha256": "ab".repeat(32)}
                })))
                .expect(1).mount(&server).await;
            Mock::given(method("POST"))
                .and(path(format!("/v1/tenants/{tenant_s}/query/v1/query")))
                .and(body_partial_json(serde_json::json!({"tenant_id": tenant_s, "route": "broad_npl", "offset": 0})))
                .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                    "ok": true, "request_id": "follow-test", "tenant_id": tenant_s,
                    "route": "broad_npl", "source_mode": "parts",
                    "result": {"rows": rows, "page_offset": 0, "page_limit": 10, "page_has_more": false}
                })))
                .expect(1).mount(&server).await;

            assert_eq!(client.lake_cell_part_log_head().await.unwrap().unwrap().0, seq);
            let client_for_scan = client.clone();
            super::scan_cell_follow_view(
                &mut request, window_start, 10, super::FOLLOW_MAX_PAGES_PER_HEAD, &mut state, &tx, &mut cancel_rx,
                move |page| {
                    let client = client_for_scan.clone();
                    async move { client.search(&page, "follow-test", None, &BTreeSet::new()).await }
                },
            ).await.unwrap();
            match rx.recv().await.unwrap() {
                SearchStreamEvent::Rows { rows, cumulative_count, .. } => {
                    assert_eq!(rows.iter().map(|row| row["metadata.uid"].as_str().unwrap()).collect::<Vec<_>>(), expected);
                    assert_eq!(cumulative_count as usize, state.seen.len());
                }
                other => panic!("expected follow rows, got {other:?}"),
            }
        }
        assert_eq!(state.delivered, 3);
        cancel_tx.send(true).unwrap();
        let client_for_scan = client.clone();
        assert!(matches!(super::scan_cell_follow_view(
            &mut request, window_start, 10, super::FOLLOW_MAX_PAGES_PER_HEAD, &mut state, &tx, &mut cancel_rx,
            move |page| {
                let client = client_for_scan.clone();
                async move { client.search(&page, "follow-test", None, &BTreeSet::new()).await }
            },
        ).await, Err(super::FollowScanError::Cancelled)));
        let (_disconnect_tx, mut disconnected_rx) = tokio::sync::watch::channel(false);
        drop(rx);
        let client_for_scan = client.clone();
        assert!(matches!(super::scan_cell_follow_view(
            &mut request, window_start, 10, super::FOLLOW_MAX_PAGES_PER_HEAD, &mut state, &tx, &mut disconnected_rx,
            move |page| {
                let client = client_for_scan.clone();
                async move { client.search(&page, "follow-test", None, &BTreeSet::new()).await }
            },
        ).await, Err(super::FollowScanError::Disconnected)));

        // The same cell route must not follow a head answered for another tenant.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path(format!("/v1/tenants/{tenant}/query/v1/status")))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "tenant_id": uuid::Uuid::from_u128(0xb).to_string(),
                "source_mode": "parts", "log_head": {"seq": 3, "sha256": "cd".repeat(32)}
            })))
            .expect(1).mount(&server).await;
        assert!(client.lake_cell_part_log_head().await.is_err());
    }

    fn follow_page(results: Vec<serde_json::Value>) -> crate::search::SearchResponse {
        serde_json::from_value(serde_json::json!({
            "results": results, "total_count": 0, "execution_time_ms": 0,
            "fields": [], "generated_sql": null,
        })).unwrap()
    }

    /// NAN-3244: a tail over a busy 1h window must stay cheap forever. The
    /// old follow paged the WHOLE window (offset up to 100k) on the first
    /// head and again on every later head, which exhausted the cell's
    /// interactive memory budget ~35 s in. Simulate 2 hours of heads (one
    /// every 2 s) over a 10 eps source and assert: the initial view is one
    /// page of the caller's limit, later heads read only shallow offsets in a
    /// short window, every new event is delivered exactly once, and the
    /// dedupe state stays bounded.
    /// The exact shape a live lean cell row carries (chDB `DateTime64`, UTC).
    fn chdb_time(time: chrono::DateTime<chrono::Utc>) -> String {
        time.format("%Y-%m-%d %H:%M:%S%.6f").to_string()
    }

    #[test]
    fn follow_row_time_parses_every_cell_rendering() {
        let expected = chrono::DateTime::parse_from_rfc3339("2026-10-07T22:11:05Z").unwrap().with_timezone(&chrono::Utc);
        for value in [
            serde_json::json!("2026-10-07 22:11:05.000000"),
            serde_json::json!("2026-10-07T22:11:05.000000"),
            serde_json::json!("2026-10-07 22:11:05"),
            serde_json::json!("2026-10-07T22:11:05Z"),
            serde_json::json!("2026-10-08T00:11:05+02:00"),
            serde_json::json!(expected.timestamp_millis()),
            serde_json::json!(expected.timestamp()),
        ] {
            assert_eq!(super::follow_row_time(&serde_json::json!({"time": value})), Some(expected), "{value}");
        }
        assert_eq!(
            super::follow_row_time(&serde_json::json!({"time": "2026-10-07 22:11:05.123456"})),
            Some(expected + chrono::Duration::microseconds(123_456)),
        );
        assert_eq!(super::follow_row_time(&serde_json::json!({"timestamp": "2026-10-07 22:11:05.000000"})), Some(expected));
        assert_eq!(super::follow_row_time(&serde_json::json!({"time": "not a time"})), None);
    }

    #[tokio::test]
    async fn cell_follow_stays_bounded_over_a_long_busy_window() {
        // The production shape (chDB) and RFC 3339 must both bound the window.
        cell_follow_bounded_with(chdb_time).await;
        cell_follow_bounded_with(|time| time.to_rfc3339()).await;
    }

    async fn cell_follow_bounded_with(render: fn(chrono::DateTime<chrono::Utc>) -> String) {
        use crate::search::streaming::SearchStreamEvent;
        use std::sync::{Arc, Mutex};

        // Event i is committed at t0 + i/10 s with uid e{i}.
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-10-07T21:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let event_time = |i: u64| t0 + chrono::Duration::milliseconds(i as i64 * 100);
        let committed = Arc::new(std::sync::atomic::AtomicU64::new(36_000)); // 1h already present
        let max_offset = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let max_window_secs = Arc::new(Mutex::new(Vec::<i64>::new()));
        let search_page = {
            let committed = committed.clone();
            let max_offset = max_offset.clone();
            let windows = max_window_secs.clone();
            move |page: crate::search::SearchRequest| {
                let committed = committed.load(std::sync::atomic::Ordering::SeqCst);
                let offset = page.offset.unwrap_or(0);
                let limit = page.limit.unwrap();
                max_offset.fetch_max(offset, std::sync::atomic::Ordering::SeqCst);
                windows.lock().unwrap().push((page.time_range.end - page.time_range.start).num_seconds());
                // Newest first, inside [start, end].
                let results = (0..committed).rev()
                    .filter(|&i| event_time(i) >= page.time_range.start && event_time(i) <= page.time_range.end)
                    .skip(offset).take(limit)
                    .map(|i| serde_json::json!({"time": render(event_time(i)), "metadata": {"uid": format!("e{i}")}}))
                    .collect::<Vec<_>>();
                async move { Ok(follow_page(results)) }
            }
        };
        let mut request: crate::search::SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "*", "limit": 500, "time_range": {
                "start": t0.to_rfc3339(), "end": event_time(36_000).to_rfc3339()
            }
        })).unwrap();
        let window_start = request.time_range.start;
        let (tx, mut rx) = tokio::sync::mpsc::channel(1024);
        let (_cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let mut state = super::FollowState::default();
        let mut delivered_uids = std::collections::HashSet::new();
        let mut drain = |rx: &mut tokio::sync::mpsc::Receiver<SearchStreamEvent>| {
            let mut uids = Vec::new();
            while let Ok(event) = rx.try_recv() {
                match event {
                    SearchStreamEvent::Rows { rows, .. } => uids.extend(rows.iter().map(|row| row["metadata"]["uid"].as_str().unwrap().to_owned())),
                    other => panic!("unexpected follow event {other:?}"),
                }
            }
            for uid in &uids { assert!(delivered_uids.insert(uid.clone()), "{uid} delivered twice"); }
            uids
        };

        // Initial head: exactly one page of the caller's limit, offset 0.
        super::scan_cell_follow_view(&mut request, window_start, 500, 1, &mut state, &tx, &mut cancel_rx, &search_page).await.unwrap();
        let initial = drain(&mut rx);
        assert_eq!(initial.len(), 500);
        assert_eq!(initial[0], "e35999");
        assert_eq!(max_offset.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(state.floor, Some(event_time(35_500)), "the older backlog is skipped, not replayed");

        // Two hours of heads, one every 2 s (20 new events each).
        for head in 1..=3_600_u64 {
            committed.fetch_add(20, std::sync::atomic::Ordering::SeqCst);
            let now = committed.load(std::sync::atomic::Ordering::SeqCst);
            request.time_range.end = event_time(now);
            super::scan_cell_follow_view(
                &mut request, window_start, super::FOLLOW_HEAD_PAGE_ROWS, super::FOLLOW_MAX_PAGES_PER_HEAD, &mut state, &tx, &mut cancel_rx, &search_page,
            ).await.unwrap();
            let fresh = drain(&mut rx);
            assert_eq!(fresh.len(), 20, "head {head} must deliver exactly its new events");
            assert_eq!(fresh[0], format!("e{}", now - 1));
            assert!(state.seen.len() <= 3_100, "dedupe state grew to {} at head {head}", state.seen.len());
        }
        assert_eq!(state.delivered, 500 + 3_600 * 20);
        assert_eq!(max_offset.load(std::sync::atomic::Ordering::SeqCst), 0, "no deep offset paging");
        let windows = max_window_secs.lock().unwrap();
        assert!(windows[1..].iter().all(|secs| *secs <= super::FOLLOW_LATE_GRACE_SECS + 5),
            "later heads read only the late-grace window");
    }

    /// NAN-3244: a head with more new events than the per-head page cap reads
    /// at most the cap and skips the older backlog instead of paging deeper.
    /// NAN-3264: the later pages are time-fenced, never offset.
    #[tokio::test]
    async fn cell_follow_burst_is_capped_per_head() {
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-10-07T21:00:00Z").unwrap().with_timezone(&chrono::Utc);
        let event_time = |i: u64| t0 + chrono::Duration::milliseconds(i as i64);
        let pages = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let search_page = {
            let pages = pages.clone();
            move |page: crate::search::SearchRequest| {
                pages.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                assert_eq!(page.offset.unwrap_or(0), 0, "follow pages are never offset");
                let results = (0..100_000_u64).rev()
                    .filter(|&i| event_time(i) >= page.time_range.start && event_time(i) <= page.time_range.end)
                    .take(page.limit.unwrap())
                    .map(|i| serde_json::json!({"time": chdb_time(event_time(i)), "metadata.uid": format!("e{i}")}))
                    .collect::<Vec<_>>();
                async move { Ok(follow_page(results)) }
            }
        };
        let mut request: crate::search::SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "*", "time_range": {"start": t0.to_rfc3339(), "end": event_time(100_000).to_rfc3339()}
        })).unwrap();
        let end = request.time_range.end;
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let (_cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let mut state = super::FollowState::default();
        super::scan_cell_follow_view(
            &mut request, t0, 1_000, super::FOLLOW_MAX_PAGES_PER_HEAD, &mut state, &tx, &mut cancel_rx, &search_page,
        ).await.unwrap();
        let max_pages = super::FOLLOW_MAX_PAGES_PER_HEAD as u64;
        assert_eq!(pages.load(std::sync::atomic::Ordering::SeqCst) as u64, max_pages);
        // Each fenced page re-reads the one row at the previous oldest instant.
        assert_eq!(state.delivered, 1_000 + (max_pages - 1) * 999);
        assert_eq!(state.floor, Some(event_time(100_000 - state.delivered)));
        assert_eq!(request.time_range.end, end, "the caller's window end is restored");
        drop(tx);
        let mut uids = std::collections::HashSet::new();
        while let Some(event) = rx.recv().await {
            let crate::search::streaming::SearchStreamEvent::Rows { rows, .. } = event else { panic!("rows only") };
            for row in rows { assert!(uids.insert(row["metadata.uid"].as_str().unwrap().to_owned()), "delivered twice"); }
        }
        assert_eq!(uids.len() as u64, state.delivered);
    }

    /// NAN-3264: the live shape — apache_access at ~15-20 eps with
    /// whole-second event times (so every instant is a 20-way tie), a part-log head every
    /// 10 s, for the 30-minute stream lifetime. Every page must stay a shallow
    /// `offset 0` read of at most [`super::FOLLOW_HEAD_PAGE_ROWS`] rows inside
    /// the late-grace window (the 1000-row pages are what exhausted the cell),
    /// every event must be delivered exactly once, including a head with a
    /// backlog larger than one page, and the dedupe state must stay flat.
    #[tokio::test]
    async fn cell_follow_thirty_minutes_at_live_rate_stays_shallow_and_flat() {
        use crate::search::streaming::SearchStreamEvent;
        use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
        use std::sync::{Arc, Mutex};

        const EPS: u64 = 20;
        let t0 = chrono::DateTime::parse_from_rfc3339("2026-10-08T03:00:00Z").unwrap().with_timezone(&chrono::Utc);
        // Event i happens in whole second i / EPS.
        let event_time = |i: u64| t0 + chrono::Duration::seconds((i / EPS) as i64);
        let committed = Arc::new(AtomicU64::new(3_600 * EPS));
        let max_limit = Arc::new(AtomicUsize::new(0));
        let windows = Arc::new(Mutex::new(Vec::<i64>::new()));
        let search_page = {
            let (committed, max_limit, windows) = (committed.clone(), max_limit.clone(), windows.clone());
            move |page: crate::search::SearchRequest| {
                assert_eq!(page.offset.unwrap_or(0), 0, "follow pages are never offset");
                let limit = page.limit.unwrap();
                max_limit.fetch_max(limit, Ordering::SeqCst);
                windows.lock().unwrap().push((page.time_range.end - page.time_range.start).num_seconds());
                let results = (0..committed.load(Ordering::SeqCst)).rev()
                    .filter(|&i| event_time(i) >= page.time_range.start && event_time(i) <= page.time_range.end)
                    .take(limit)
                    .map(|i| serde_json::json!({"time": chdb_time(event_time(i)), "metadata.uid": format!("e{i}")}))
                    .collect::<Vec<_>>();
                async move { Ok(follow_page(results)) }
            }
        };
        let mut request: crate::search::SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "*", "limit": 500, "time_range": {"start": t0.to_rfc3339(), "end": event_time(3_600 * EPS).to_rfc3339()}
        })).unwrap();
        let window_start = request.time_range.start;
        let (tx, mut rx) = tokio::sync::mpsc::channel(4096);
        let (_cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let mut state = super::FollowState::default();
        let mut pacing = super::FollowPacing::new(500, super::FOLLOW_HEAD_PAGE_ROWS);
        let mut delivered = std::collections::HashSet::new();
        let mut drain = |rx: &mut tokio::sync::mpsc::Receiver<SearchStreamEvent>| {
            let mut count = 0;
            while let Ok(event) = rx.try_recv() {
                let SearchStreamEvent::Rows { rows, .. } = event else { panic!("rows only") };
                for row in rows {
                    assert!(delivered.insert(row["metadata.uid"].as_str().unwrap().to_owned()), "delivered twice");
                    count += 1;
                }
            }
            count
        };

        let (limit, pages) = pacing.next_scan();
        assert_eq!((limit, pages), (500, 1));
        super::scan_cell_follow_view(&mut request, window_start, limit, pages, &mut state, &tx, &mut cancel_rx, &search_page).await.unwrap();
        pacing.succeeded();
        assert_eq!(drain(&mut rx), 500);
        let mut seen_high_water = 0;
        for head in 1..=180_u64 {
            // Head 90 lands after a 30 s gap (a slow pack): 600 new events,
            // three fenced pages.
            let seconds = if head == 90 { 30 } else { 10 };
            let before = committed.fetch_add(seconds * EPS, Ordering::SeqCst);
            let now = before + seconds * EPS;
            request.time_range.end = event_time(now) + chrono::Duration::milliseconds(999);
            let (limit, pages) = pacing.next_scan();
            assert_eq!(limit, super::FOLLOW_HEAD_PAGE_ROWS);
            super::scan_cell_follow_view(&mut request, window_start, limit, pages, &mut state, &tx, &mut cancel_rx, &search_page).await.unwrap();
            pacing.succeeded();
            assert_eq!(drain(&mut rx) as u64, now - before, "head {head} delivers exactly its new events");
            seen_high_water = seen_high_water.max(state.seen.len());
        }
        assert_eq!(state.delivered, 500 + (179 * 10 + 30) * EPS);
        assert!(max_limit.load(Ordering::SeqCst) <= 500);
        assert!(seen_high_water <= ((super::FOLLOW_LATE_GRACE_SECS as u64 + 60) * EPS) as usize,
            "dedupe state is bounded by the grace window, got {seen_high_water}");
        let windows = windows.lock().unwrap();
        assert!(windows[1..].iter().all(|secs| *secs <= super::FOLLOW_LATE_GRACE_SECS + 60),
            "later heads read only the late-grace window");
    }

    /// NAN-3264: a refused or slow head halves the page and is retried; a
    /// success grows it back; the initial page is one page of the caller's
    /// limit.
    #[test]
    fn follow_pacing_backs_off_and_recovers() {
        let mut pacing = super::FollowPacing::new(500, 250);
        assert_eq!(pacing.next_scan(), (500, 1));
        assert_eq!(pacing.failed(), 1);
        assert!(pacing.retry_pending());
        assert_eq!(pacing.next_scan(), (250, 1), "initial page halves on refusal");
        pacing.succeeded();
        assert!(!pacing.retry_pending());
        assert_eq!(pacing.next_scan(), (250, super::FOLLOW_MAX_PAGES_PER_HEAD));
        for _ in 0..10 { pacing.failed(); }
        assert_eq!(pacing.page_rows(), super::FOLLOW_MIN_PAGE_ROWS);
        pacing.succeeded();
        pacing.succeeded();
        assert_eq!(pacing.page_rows(), 200);
        pacing.succeeded();
        assert_eq!(pacing.page_rows(), 250, "grows back to the head page, never past it");
        assert!(super::FollowScanError::Slow.is_transient());
        assert!(super::FollowScanError::Search(crate::search::SearchError::ResourceExhausted("memory".into())).is_transient());
        assert!(!super::FollowScanError::MissingIdentity.is_transient());
        assert!(!super::FollowScanError::Search(crate::search::SearchError::Cancelled).is_transient());
    }

    /// NAN-3264: a page that does not answer is abandoned as `Slow` (the
    /// caller retries smaller) instead of stalling the stream until the cell
    /// gives up on its memory budget.
    #[tokio::test(start_paused = true)]
    async fn cell_follow_slow_page_is_abandoned() {
        let mut request: crate::search::SearchRequest = serde_json::from_value(serde_json::json!({
            "query": "*", "time_range": {"start": "2026-10-08T03:00:00Z", "end": "2026-10-08T04:00:00Z"}
        })).unwrap();
        let start = request.time_range.start;
        let (tx, _rx) = tokio::sync::mpsc::channel(8);
        let (_cancel_tx, mut cancel_rx) = tokio::sync::watch::channel(false);
        let mut state = super::FollowState::default();
        let result = super::scan_cell_follow_view(&mut request, start, 250, 4, &mut state, &tx, &mut cancel_rx, |_page| async {
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
            Ok(follow_page(Vec::new()))
        }).await;
        assert!(matches!(result, Err(super::FollowScanError::Slow)), "{result:?}");
    }

    #[test]
    fn follow_heartbeat_is_a_named_event_without_tenant_data() {
        let event = crate::search::streaming::SearchStreamEvent::Heartbeat { delivered: 42 };
        assert_eq!(
            serde_json::to_value(&event).unwrap(),
            serde_json::json!({"event": "heartbeat", "data": {"delivered": 42}}),
        );
    }

    #[test]
    fn follow_dedupe_state_is_hard_capped() {
        let t0 = chrono::Utc::now();
        let mut state = super::FollowState::default();
        for i in 0..(super::FOLLOW_MAX_SEEN + 10) {
            state.remember(&format!("e{i}"), Some(t0 + chrono::Duration::milliseconds(i as i64)));
        }
        state.remember("untimed", None);
        state.prune(t0 - chrono::Duration::hours(1));
        assert!(state.seen.len() <= super::FOLLOW_MAX_SEEN);
        assert!(state.seen.contains_key(&format!("e{}", super::FOLLOW_MAX_SEEN + 9)), "newest IDs are kept");
        assert!(!state.seen.contains_key("e0"), "oldest IDs are dropped first");
    }

    #[test]
    fn admission_backend_outage_has_a_distinct_stream_code() {
        let error = crate::search::SearchError::from(crate::search::AdmissionError::Unavailable);
        assert_eq!(super::stream_error_payload(&error).0, "ADMISSION_BACKEND_UNAVAILABLE");
        let denied = crate::search::SearchError::from(crate::search::AdmissionError::UserLimitExceeded { limit: 1 });
        assert_eq!(super::stream_error_payload(&denied).0, "ADMISSION_DENIED");
    }

    use super::{
        enforce_stream_source_scope, should_emit_partial_time_range_warning as gate,
        take_aggregation_total,
    };
    use crate::auth::ScopeSet;
    use crate::query::Dataset;
    use crate::search::service::LakeQueryMode;
    use std::collections::BTreeSet;

    const MAX: usize = 1_000_000;

    #[test]
    fn primary_lake_stream_scope_uses_canonical_ocsf_provenance() {
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        let enforced = enforce_stream_source_scope(
            "metadata.log_source=windows_sysmon",
            Dataset::Logs,
            LakeQueryMode::Primary,
            &scope,
        )
        .unwrap();
        assert!(
            enforced.contains("metadata.log_source!=\"audit\""),
            "{enforced}"
        );
        assert!(!enforced.contains("source_type"), "{enforced}");
    }

    #[test]
    fn legacy_stream_scope_retains_legacy_provenance_field() {
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        let enforced = enforce_stream_source_scope(
            "source_type=windows_sysmon",
            Dataset::Logs,
            LakeQueryMode::Disabled,
            &scope,
        )
        .unwrap();
        assert!(enforced.contains("source_type!=\"audit\""), "{enforced}");
    }

    #[test]
    fn non_log_stream_scope_is_not_given_a_log_source_predicate() {
        let scope = ScopeSet::from_denied(BTreeSet::from(["audit".to_string()]));
        let query = "service.name=payments";
        assert_eq!(
            enforce_stream_source_scope(query, Dataset::Spans, LakeQueryMode::Primary, &scope)
                .unwrap(),
            query
        );
    }

    #[test]
    fn no_warning_when_ui_page_size_filled_from_newest_partition() {
        // User asked for 50, backend stopped after today's partition had 50.
        // Not all chunks queried, but cumulative is far below max_limit.
        assert!(!gate(false, 50, MAX));
    }

    #[test]
    fn no_warning_when_all_chunks_scanned() {
        // Every partition was scanned even if cumulative happened to hit max.
        // `chunks_queried_all` is true → never truncated the range.
        assert!(!gate(true, MAX as u64, MAX));
        assert!(!gate(true, 0, MAX));
    }

    #[test]
    fn warning_when_scan_hits_max_limit_and_range_incomplete() {
        // Genuinely broad query: cap reached, older partitions skipped.
        assert!(gate(false, MAX as u64, MAX));
    }

    #[test]
    fn no_warning_just_below_max_limit() {
        // Boundary: cumulative one row short of max does not trip the gate.
        assert!(!gate(false, (MAX - 1) as u64, MAX));
    }

    #[test]
    fn warning_when_cumulative_exceeds_max_limit() {
        // Should never happen in practice (per-chunk LIMIT caps scanning),
        // but if cumulative somehow exceeds max, still fire the warning.
        assert!(gate(false, (MAX + 1) as u64, MAX));
    }

    #[test]
    fn aggregation_path_never_warns() {
        // Aggregation sets chunks_queried_all=true unconditionally
        // (see execute_streaming_path) so this branch is unreachable for it.
        assert!(!gate(true, u64::MAX, MAX));
    }

    #[test]
    fn streaming_aggregation_uses_in_band_total_without_leaking_it() {
        let mut rows = vec![
            serde_json::json!({ "dest_ip": "10.0.0.1", "count": 9, "_total_count": 73 }),
            serde_json::json!({ "dest_ip": "10.0.0.2", "count": 8, "_total_count": 73 }),
        ];

        assert_eq!(take_aggregation_total(&mut rows), Some(73));
        assert!(rows.iter().all(|row| row.get("_total_count").is_none()));
    }

    #[test]
    fn streaming_path_rejects_rex_capture_name_injection() {
        // NAN-2004: `search_streaming` now runs the SAME field-name validation
        // (`validate_query_field_names`) the batch path does, so an
        // injection-shaped `rex` capture name — comma/paren using `/**/` for
        // whitespace, which slips past the space check — is rejected on the
        // streaming path instead of compiling to one inert garbage-named column.
        // `escape_identifier` still neutralizes it in codegen; this guards the
        // parse-time layer the streaming path was previously missing. The check is
        // profile-independent (a comma/paren name is invalid under any schema), so
        // the no-profile `validate_query_fields` is an exact proxy for the wrapper.
        use crate::query::{parse_query, validation::validate_query_fields};
        for q in [
            r#"* | stats count() as total | rex field=total "(?<a,version()/**/v,hostName()/**/h,currentUser()/**/u>\w+)""#,
            r#"* | stats count() as total | rex field=total "(?<a,(SELECT/**/count()/**/FROM/**/logs)/**/logrows,currentUser()/**/u>\w+)""#,
        ] {
            let query = parse_query(q).unwrap_or_else(|e| panic!("parse {q}: {e}"));
            assert!(
                !validate_query_fields(&query).is_empty(),
                "streaming path must reject injection-shaped rex capture name: {q}"
            );
        }
        // A legit capture name still validates cleanly on the streaming path.
        let ok = parse_query(r#"* | stats count() as total | rex field=total "(?<digits>\d+)""#)
            .unwrap();
        assert!(
            validate_query_fields(&ok).is_empty(),
            "legit rex capture name must not be rejected on the streaming path"
        );
    }

    #[test]
    fn streaming_path_resolves_tree_presets_before_validating() {
        // NAN-2361 applies preset semantics before streaming validation.
        // NAN-2447 also accepts the raw preset's product aliases through the
        // lake profile; both raw and canonical forms must now validate.
        use crate::query::parse_query;
        use crate::schema::OcsfProfile;
        use crate::search::query_processing::apply_profile_product_semantics;
        use crate::search::service::validate_query_field_names;

        let profile = OcsfProfile::lake_1_9();
        for preset in ["tree process", "tree web"] {
            let query = format!("metadata.log_source=windows_sysmon | {preset}");
            let raw = parse_query(&query).unwrap();
            assert!(
                validate_query_field_names(&raw, &profile).is_ok(),
                "NAN-2447 accepts raw preset product aliases: {preset}"
            );

            let mut resolved = parse_query(&query).unwrap();
            apply_profile_product_semantics(&mut resolved, &profile);
            validate_query_field_names(&resolved, &profile).unwrap_or_else(|e| {
                panic!("streaming path must accept `{preset}` after the rewrite: {e}")
            });
        }
    }
}

#[cfg(test)]
mod dependency_contract_tests {
    use super::*;

    #[test]
    fn streaming_preserves_actionable_dependency_reasons() {
        for (error, code, reason) in [
            (
                SearchError::SearchAdmissionUnavailable("Redis is not configured".into()),
                "SEARCH_ADMISSION_UNAVAILABLE",
                "Redis is not configured",
            ),
            (
                SearchError::TenantLakePublicationDegraded("bootstrap publication is incomplete".into()),
                "TENANT_LAKE_PUBLICATION_DEGRADED",
                "bootstrap publication is incomplete",
            ),
        ] {
            assert_eq!(stream_error_payload(&error), (code, reason.into()));
        }
    }
}

#[cfg(test)]
mod cold_budget_tests {
    #[test]
    fn cold_ceiling_sse_preserves_guidance_bytes_and_terminal_code() {
        let error = crate::SearchError::ColdScanTooLarge { needed_bytes: 14_800_000_000, ceiling_bytes: 9_600_000_000, background_ceiling_bytes: Some(9_600_000_000) };
        let event = serde_json::to_value(super::stream_error_event(&error)).unwrap();
        assert_eq!(event["event"], "error");
        assert_eq!(event["data"]["code"], "COLD_SCAN_TOO_LARGE");
        assert_eq!(event["data"]["reason"], "cold_scan_too_large");
        assert_eq!(event["data"]["needed_bytes"], 14_800_000_000_u64);
        assert_eq!(event["data"]["ceiling_bytes"], 9_600_000_000_u64);
        assert_eq!(event["data"]["retryable"], false);
        let message = event["data"]["message"].as_str().unwrap();
        assert!(message.contains("~14.8 GB") && message.contains("too large to run interactively"), "{message}");
    }

    /// NAN-3644: a lean-cell read's cold progress reaches the SSE stream as
    /// `progress` events while the read is queued and while it fetches.
    #[tokio::test]
    async fn cold_progress_poller_streams_queued_then_bytes() {
        use wiremock::{matchers::{method, path, query_param}, Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let dir = tempfile::tempdir().unwrap();
        let token = dir.path().join("token");
        std::fs::write(&token, "cold-progress-test-token-000000000000000").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&token, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let route = crate::search::lake_cell::LakeCellRoute::for_test(uuid::Uuid::from_u128(42), &server.uri(), token);
        let client = crate::search::lake::LakeQueryClient::new_lake_cell(&route, std::time::Duration::from_secs(5)).unwrap();
        let progress_path = format!("{}/v1/query/progress", route_query_path(&client));
        Mock::given(method("GET")).and(path(progress_path.clone())).and(query_param("request_id", "q-cold"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "requests": 1, "cold_bytes_read": 0, "cold_bytes_total": 0, "queued": true})))
            .up_to_n_times(1).mount(&server).await;
        Mock::given(method("GET")).and(path(progress_path)).and(query_param("request_id", "q-cold"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "ok": true, "requests": 1, "cold_bytes_read": 1_000_000_000_u64, "cold_bytes_total": 2_200_000_000_u64, "queued": false})))
            .mount(&server).await;
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        let poller = super::spawn_cold_progress_poller(client, "q-cold".into(), tx);
        let first = tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap();
        let first = serde_json::to_value(first).unwrap();
        assert_eq!(first["event"], "progress");
        assert_eq!(first["data"]["phase"], "cold_scan");
        assert_eq!(first["data"]["queued"], true);
        let second = serde_json::to_value(tokio::time::timeout(std::time::Duration::from_secs(5), rx.recv()).await.unwrap().unwrap()).unwrap();
        assert_eq!(second["data"]["queued"], false);
        assert_eq!(second["data"]["cold_bytes_read"], 1_000_000_000_u64);
        assert_eq!(second["data"]["cold_bytes_total"], 2_200_000_000_u64);
        assert_eq!(second["data"]["percent"], 45);
        poller.abort();
    }

    fn route_query_path(client: &crate::search::lake::LakeQueryClient) -> String {
        let base = client.lake_cell_query_base().unwrap();
        reqwest::Url::parse(base).unwrap().path().trim_end_matches('/').to_string()
    }
}
