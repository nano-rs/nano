// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled report service (NAN-1793).
//!
//! Orchestrates report definitions and their execution: runs a saved search or a
//! dashboard's panels server-side, renders bounded CSV/HTML artifacts, persists a
//! run record + artifacts, notifies the owner (in-app bell + `report_ready`
//! webhook), and prunes to the retention window.
//!
//! Distributed execution reuses the scheduled-jobs SKIP LOCKED claiming pattern:
//! one replica claims a due definition; the stale-claim timeout is floored at
//! 3× the per-run timeout so a running report can never have its claim reclaimed
//! mid-execution, and a pre-store claim renewal fences the durable write as a
//! backstop. Every execution is run inside a spawned task so a panic becomes a
//! recorded `failed` run rather than aborting the scheduler (NAN-1102).
//!
//! Execution identity: report queries execute AS THE REPORT OWNER's per-source
//! scope (NAN-1809). The owner's denied source set is resolved ONCE per run and
//! threaded through every search/panel execution — FAIL-CLOSED: if the scope
//! cannot be resolved (PG error), the run is recorded as `failed`; it never
//! falls back to an unrestricted (system) execution. Independently of source
//! scope, queries are stripped of audit-log access exactly as they would be
//! for a user WITHOUT `audit:view`, so a report can never surface audit data
//! regardless of the owner's scope.

use std::collections::BTreeSet;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde_json::{json, Value};
use sqlx::PgPool;
use thiserror::Error;
use tokio::sync::Semaphore;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::ScopeSet;
use crate::db::repository::SourceScopeRepository;
use crate::models::{NewNotification, NotificationType};
use crate::query::{parse_query, PrettyPrint, Query};
use crate::scheduler::{calculate_next_run, calculate_next_runs, validate_cron};
use crate::search::query_processing::enforce_non_audit_query;
use crate::shutdown::ShutdownToken;
use crate::webhooks::{WebhookRepository, WebhookService};
use crate::{Dashboard, RawSqlRequest, SearchRequest, SearchService, TimeRangeInput};

use super::render::{self, PanelOutput};
use super::repository::{ReportRepository, ReportRepositoryError};
use super::types::*;
use super::authz::MAX_DASHBOARD_PANELS;
use super::{
    dashboard_panel_executes_search_sql, ReportAuthorizationError, ReportAuthorizer,
    ReportExecutionAuthorization,
};

/// Max result rows fetched for a SEARCH report. Bounds ClickHouse work and
/// artifact size; the byte cap bounds the rest. A search returning exactly this
/// many rows with more matching flags the run `truncated`. The CSV artifact is
/// the consumer of this depth (the HTML table shows far fewer).
const REPORT_RESULT_ROW_CAP: usize = 50_000;

/// Max result rows fetched PER DASHBOARD PANEL — deliberately far lower than the
/// search cap. A dashboard report executes up to `MAX_DASHBOARD_PANELS` panels
/// and holds every panel's rows in memory at once before rendering; at the search
/// cap that would be 50 × 50k = 2.5M `serde_json::Value` rows (an OOM risk). The
/// renderer only ever shows `HTML_DISPLAY_ROW_CAP` (500) rows per table and
/// `SVG_MAX_POINTS` (200) chart points, so a deeper fetch buys nothing.
const REPORT_PANEL_ROW_CAP: usize = 2_000;

/// Hard per-artifact byte cap (5 MiB). Content beyond this is truncated by the
/// renderer and flagged `artifact_truncated` — never silently cut.
const REPORT_ARTIFACT_BYTE_CAP: usize = 5 * 1024 * 1024;

/// Default per-run execution timeout. Overridable via REPORT_RUN_TIMEOUT_SECS.
const DEFAULT_RUN_TIMEOUT_SECS: u64 = 300;

/// Default stale-claim reclaim timeout. Floored at 3× the run timeout so a live
/// run's claim can't be reclaimed mid-execution.
const DEFAULT_STALE_TIMEOUT_SECS: i64 = 900;

/// Minimum gap between two consecutive scheduled runs of one definition. A
/// `* * * * *` cron would otherwise queue a fresh (potentially 50k-row) report
/// every minute — faster than a run can finish — so the schedule is rejected at
/// definition time rather than melting the cluster at run time.
const MIN_CRON_INTERVAL_SECS: i64 = 300;

/// Reject cron expressions that fire more often than [`MIN_CRON_INTERVAL_SECS`],
/// measured as the gap between the next two occurrences.
pub(super) fn validate_cron_interval(expression: &str) -> Result<(), ReportError> {
    let upcoming = calculate_next_runs(expression, 2)
        .map_err(|e| ReportError::InvalidCron(e.to_string()))?;
    if upcoming.len() == 2 {
        let gap = (upcoming[1] - upcoming[0]).num_seconds();
        if gap < MIN_CRON_INTERVAL_SECS {
            return Err(ReportError::InvalidCron(format!(
                "schedule fires every {gap}s; reports require at least {MIN_CRON_INTERVAL_SECS}s between runs"
            )));
        }
    }
    Ok(())
}

#[derive(Debug, Error)]
pub enum ReportError {
    #[error("Repository error: {0}")]
    Repository(#[from] ReportRepositoryError),
    #[error("Invalid cron expression: {0}")]
    InvalidCron(String),
    #[error("Report definition not found: {0}")]
    NotFound(Uuid),
    #[error("Invalid report definition: {0}")]
    InvalidDefinition(String),
    #[error("Query execution failed: {0}")]
    Execution(String),
    #[error("Report run timed out")]
    Timeout,
    #[error("Distributed claim was lost")]
    ClaimLost,
    #[error("Too many report runs in flight; try again shortly")]
    Busy,
    #[error("Report authorization denied: {0}")]
    AuthorizationDenied(String),
    #[error("Report authorization could not be resolved: {0}")]
    AuthorizationResolution(String),
}

impl From<ReportAuthorizationError> for ReportError {
    fn from(error: ReportAuthorizationError) -> Self {
        match error {
            ReportAuthorizationError::Denied(message) => Self::AuthorizationDenied(message),
            ReportAuthorizationError::Resolution(message) => {
                Self::AuthorizationResolution(message)
            }
        }
    }
}

/// Concurrent report executions allowed PER PROCESS.
///
/// Each in-flight run can hold up to `REPORT_RESULT_ROW_CAP` rows plus multi-MiB
/// artifacts in memory, so unbounded concurrency is a memory-exhaustion vector: a
/// user spamming "Run now" would otherwise pile up arbitrarily many 50k-row
/// executions. Both the scheduler and manual triggers draw from this ONE pool —
/// manual triggers SHED (fail fast with `Busy`) rather than queue.
///
/// It is a process-global (not a `ReportService` field) precisely because the API
/// handlers construct a fresh `ReportService` per request; a per-instance
/// semaphore would bound nothing.
fn exec_semaphore() -> &'static Arc<Semaphore> {
    static SEM: OnceLock<Arc<Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| {
        let permits = std::env::var("REPORT_MAX_CONCURRENT_RUNS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(2)
            .max(1);
        Arc::new(Semaphore::new(permits))
    })
}

/// Terminal decision from an isolated execution.
enum ExecOutcome {
    Success,
    Failed(String),
    ClaimLost,
}

/// Everything a completed execution produced, ready to persist.
struct ExecutionOutput {
    artifacts: Vec<RenderedArtifact>,
    row_count: Option<i64>,
    result_truncated: bool,
    artifact_truncated: bool,
    /// F-31: the DISTINCT `source_type` manifest of the rendered artifacts —
    /// what a later source-access revocation is checked against at download.
    source_types: Vec<String>,
    /// F-31: whether `source_types` is a COMPLETE, trustworthy account of the
    /// artifact's provenance. `false` (aggregate/projection/SQL/dashboard rows
    /// that dropped `source_type`, or a companion that could not resolve) makes
    /// the download gate deny every source-restricted requester.
    source_types_complete: bool,
    /// NAN-2066: whether the authorized source snapshot executed raw SQL.
    requires_search_sql: bool,
}

/// F-31: authorization predicate for downloading (or seeing the artifact
/// metadata of) a stored report run, given the requester's per-source deny set
/// `denied` and the run's stored `source_types` manifest + completeness flag.
///
/// OWNERSHIP IS NOT AN EXEMPTION — this is applied to the owner and admins alike
/// (a source-scoped admin downloading someone else's report is exactly the leak
/// F-31 closes). Rules:
///
/// - `denied` empty (unrestricted requester) → allow.
/// - else if the manifest is COMPLETE and disjoint from `denied` → allow.
/// - else → deny. In particular an incomplete manifest (`complete == false`,
///   which every pre-feature run carries) denies any restricted requester,
///   because the frozen bytes may contain anything.
///
/// Pure so the matrix is unit-testable without a database.
pub fn report_artifact_download_allowed(
    denied: &BTreeSet<String>,
    run_source_types: &[String],
    complete: bool,
) -> bool {
    crate::auth::ArtifactScope::from_denied(denied).allows(run_source_types, complete)
}

/// Report service: definition CRUD + execution + the distributed scheduler loop.
#[derive(Clone)]
pub struct ReportService {
    pool: PgPool,
    repository: ReportRepository,
    search_service: SearchService,
    node_id: Option<String>,
}

impl ReportService {
    pub fn new(pool: PgPool, search_service: SearchService) -> Self {
        Self {
            repository: ReportRepository::new(pool.clone()),
            pool,
            search_service,
            node_id: None,
        }
    }

    pub fn with_node_id(pool: PgPool, search_service: SearchService, node_id: String) -> Self {
        Self {
            repository: ReportRepository::new(pool.clone()),
            pool,
            search_service,
            node_id: Some(node_id),
        }
    }

    pub fn repository(&self) -> &ReportRepository {
        &self.repository
    }

    // ==================== DEFINITION CRUD ====================

    pub async fn create_definition(
        &self,
        new: NewReportDefinition,
    ) -> Result<ReportDefinition, ReportError> {
        validate_cron(&new.cron_expression).map_err(|e| ReportError::InvalidCron(e.to_string()))?;
        validate_cron_interval(&new.cron_expression)?;
        self.validate_source(&new)?;
        let next_run_at = if new.enabled {
            calculate_next_run(&new.cron_expression)
                .map_err(|e| ReportError::InvalidCron(e.to_string()))?
        } else {
            None
        };
        Ok(self.repository.create_definition(&new, next_run_at).await?)
    }

    fn validate_source(&self, new: &NewReportDefinition) -> Result<(), ReportError> {
        match new.source_type {
            ReportSourceType::Search => {
                if new.source_query.as_ref().map_or(true, |q| q.trim().is_empty()) {
                    return Err(ReportError::InvalidDefinition(
                        "search report requires a non-empty query".into(),
                    ));
                }
            }
            ReportSourceType::Dashboard => {
                if new.source_dashboard_id.is_none() {
                    return Err(ReportError::InvalidDefinition(
                        "dashboard report requires a dashboard id".into(),
                    ));
                }
            }
        }
        if new.time_range_seconds <= 0 {
            return Err(ReportError::InvalidDefinition(
                "time_range_seconds must be positive".into(),
            ));
        }
        Ok(())
    }

    pub async fn get_definition(&self, id: Uuid) -> Result<ReportDefinition, ReportError> {
        self.repository
            .get_definition(id)
            .await
            .map_err(|e| match e {
                ReportRepositoryError::DefinitionNotFound(id) => ReportError::NotFound(id),
                other => other.into(),
            })
    }

    pub async fn list_definitions(
        &self,
        owner_id: Option<Uuid>,
    ) -> Result<Vec<ReportDefinition>, ReportError> {
        Ok(self.repository.list_definitions(owner_id).await?)
    }

    pub async fn update_definition(
        &self,
        id: Uuid,
        update: UpdateReportDefinition,
    ) -> Result<ReportDefinition, ReportError> {
        // Query edits mirror validate_source: only a search report has a query,
        // and it can never be blanked — an empty query would make every future
        // run fail. Fails closed on whitespace-only input.
        if let Some(ref query) = update.source_query {
            let existing = self.get_definition(id).await?;
            match existing.source_type {
                ReportSourceType::Search => {
                    if query.trim().is_empty() {
                        return Err(ReportError::InvalidDefinition(
                            "search report requires a non-empty query".into(),
                        ));
                    }
                }
                ReportSourceType::Dashboard => {
                    return Err(ReportError::InvalidDefinition(
                        "dashboard reports have no query; source_query cannot be set".into(),
                    ));
                }
            }
        }

        // Recompute next_run_at only when the cron changed.
        let next_run_at = if let Some(ref cron) = update.cron_expression {
            validate_cron(cron).map_err(|e| ReportError::InvalidCron(e.to_string()))?;
            validate_cron_interval(cron)?;
            calculate_next_run(cron).map_err(|e| ReportError::InvalidCron(e.to_string()))?
        } else {
            None
        };
        self.repository
            .update_definition(id, &update, next_run_at)
            .await
            .map_err(|e| match e {
                ReportRepositoryError::DefinitionNotFound(id) => ReportError::NotFound(id),
                other => other.into(),
            })
    }

    pub async fn delete_definition(&self, id: Uuid) -> Result<bool, ReportError> {
        Ok(self.repository.delete_definition(id).await?)
    }

    pub async fn list_runs(
        &self,
        definition_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ReportRun>, ReportError> {
        Ok(self.repository.list_runs(definition_id, limit.clamp(1, 500)).await?)
    }

    pub async fn get_run(&self, run_id: Uuid) -> Result<ReportRun, ReportError> {
        self.repository.get_run(run_id).await.map_err(|e| match e {
            ReportRepositoryError::RunNotFound(id) => ReportError::NotFound(id),
            other => other.into(),
        })
    }

    /// Resolve only authorization facts before loading run artifact metadata.
    pub async fn get_run_authorization_scope(
        &self,
        run_id: Uuid,
    ) -> Result<ReportRunAuthorizationScope, ReportError> {
        self.repository
            .get_run_authorization_scope(run_id)
            .await
            .map_err(|e| match e {
                ReportRepositoryError::RunNotFound(id) => ReportError::NotFound(id),
                other => other.into(),
            })
    }

    /// Resolve only authorization facts before loading artifact bytes.
    pub async fn get_artifact_scope(
        &self,
        artifact_id: Uuid,
    ) -> Result<ArtifactScope, ReportError> {
        self.repository
            .get_artifact_scope(artifact_id)
            .await
            .map_err(|e| match e {
                ReportRepositoryError::ArtifactNotFound(id) => ReportError::NotFound(id),
                other => other.into(),
            })
    }

    pub async fn get_artifact_content(
        &self,
        artifact_id: Uuid,
    ) -> Result<ReportArtifactContent, ReportError> {
        self.repository
            .get_artifact_bytes(artifact_id)
            .await
            .map_err(|e| match e {
                ReportRepositoryError::ArtifactNotFound(id) => ReportError::NotFound(id),
                other => other.into(),
            })
    }

    /// Authoritative owner authorization used for manual preflight and repeated
    /// inside every execution to close the trigger-to-run race.
    pub async fn authorize_execution(
        &self,
        definition: &ReportDefinition,
    ) -> Result<ReportExecutionAuthorization, ReportError> {
        ReportAuthorizer::new(self.pool.clone())
            .authorize_execution(definition)
            .await
            .map_err(Into::into)
    }

    /// Manually trigger a run now (fire-and-forget on this node). Returns the new
    /// run id so the caller can poll it. Panic-isolated like scheduled runs.
    ///
    /// Bounded: takes a permit from the process-global execution pool BEFORE
    /// spawning and SHEDS with [`ReportError::Busy`] when saturated, so repeated
    /// "Run now" clicks cannot pile up unbounded 50k-row executions.
    ///
    /// The requester's SQL capability is frozen with the trigger and checked
    /// again against the exact dashboard snapshot used by the spawned run. This
    /// closes a dashboard nPL-to-SQL change between handler preflight and work.
    pub async fn trigger_now(
        &self,
        id: Uuid,
        requester_can_search_sql: bool,
    ) -> Result<Uuid, ReportError> {
        let def = self.get_definition(id).await?;

        let permit = exec_semaphore()
            .clone()
            .try_acquire_owned()
            .map_err(|_| ReportError::Busy)?;

        let run_id = Uuid::now_v7();
        let svc = self.clone();
        tokio::spawn(async move {
            let _permit = permit; // held for the run's lifetime
            let _ = svc
                .execute_isolated(def, run_id, "manual", Some(requester_can_search_sql), None)
                .await;
        });
        Ok(run_id)
    }

    // ==================== EXECUTION ====================

    /// Run one execution fully isolated: a panic becomes a recorded `failed` run,
    /// never aborting the caller (NAN-1102).
    async fn execute_isolated(
        &self,
        def: ReportDefinition,
        run_id: Uuid,
        triggered_by: &'static str,
        // `Some` only for a request-triggered run; schedules authorize their
        // owner directly and have no separate requester identity.
        requester_can_search_sql: Option<bool>,
        fence: Option<(String, i64)>,
    ) -> ExecOutcome {
        let definition_id = def.id;
        let svc = self.clone();
        let task_fence = fence.clone();
        let handle = tokio::spawn(async move {
            let fence_ref = task_fence.as_ref().map(|(n, g)| (n.as_str(), *g));
            svc.run_and_record(
                &def,
                run_id,
                triggered_by,
                requester_can_search_sql,
                fence_ref,
            )
            .await
        });
        match handle.await {
            Ok(Ok(())) => ExecOutcome::Success,
            Ok(Err(ReportError::ClaimLost)) => ExecOutcome::ClaimLost,
            Ok(Err(e)) => ExecOutcome::Failed(e.to_string()),
            Err(_join) => {
                // Task panicked/cancelled. Record a failed run so the panic is
                // visible and never silently lost — but UNDER THE CLAIM FENCE, so
                // a paused-then-panicking node cannot stamp `failed` over a run a
                // reclaiming replica has already completed successfully.
                let fence_ref = fence.as_ref().map(|(n, g)| (n.as_str(), *g));
                match self
                    .repository
                    .store_run_failure(
                        run_id,
                        definition_id,
                        fence_ref,
                        0,
                        "report execution panicked",
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        warn!(definition_id = %definition_id, "Report panicked but its claim was already reclaimed; not overwriting the new owner's run");
                        return ExecOutcome::ClaimLost;
                    }
                    Err(e) => {
                        warn!(definition_id = %definition_id, error = %e, "Failed to record panicked report run")
                    }
                }
                ExecOutcome::Failed("report execution panicked".into())
            }
        }
    }

    /// Create/reset the run row, produce artifacts, then persist success or
    /// failure UNDER THE CLAIM FENCE.
    ///
    /// `fence` is `Some((node_id, generation))` for scheduled runs. The fence is
    /// applied *inside* the write transaction (see
    /// [`ReportRepository::store_run_success`]) rather than as a separate
    /// pre-write renew: a renew-then-write pair is a TOCTOU race where a paused
    /// node can renew, lose the claim to a stale-reclaim, and still clobber the
    /// new owner's result. A lost claim surfaces as `ClaimLost` with nothing
    /// written.
    async fn run_and_record(
        &self,
        def: &ReportDefinition,
        run_id: Uuid,
        triggered_by: &str,
        // See `trigger_now`: this is checked against `authorization`, the exact
        // source snapshot subsequently consumed by `produce`.
        requester_can_search_sql: Option<bool>,
        fence: Option<(&str, i64)>,
    ) -> Result<(), ReportError> {
        let started = Instant::now();
        self.repository
            .upsert_run_running(run_id, def.id, triggered_by)
            .await?;

        let timeout = Duration::from_secs(run_timeout_secs());
        // NAN-2065: every scheduler/manual execution re-resolves the owner's
        // active status, required capabilities, and dashboard ACL without a
        // cache. Authorization is checked after the run row is created so a
        // scheduled denial is observable as FAILED, but before source scope,
        // search, artifacts, notifications, or webhooks.
        let outcome = match self.authorize_execution(def).await {
            Err(e) => Err(e),
            Ok(authorization)
                if authorization.requires_search_sql()
                    && requester_can_search_sql == Some(false) =>
            {
                Err(ReportError::AuthorizationDenied(format!(
                    "manual report requester does not have required permission {}; run skipped",
                    crate::auth::permissions::SEARCH_SQL
                )))
            }
            Ok(authorization) => match self.owner_scope(def).await {
                Err(e) => Err(e),
                Ok(scope) => {
                    match tokio::time::timeout(timeout, self.produce(def, &scope, &authorization))
                        .await
                    {
                        Ok(res) => res,
                        Err(_) => Err(ReportError::Timeout),
                    }
                }
            },
        };

        let duration_ms = started.elapsed().as_millis() as i64;
        match outcome {
            Ok(out) => {
                let stored = self
                    .repository
                    .store_run_success(
                        run_id,
                        def.id,
                        fence,
                        duration_ms,
                        out.row_count,
                        out.result_truncated,
                        out.artifact_truncated,
                        &out.artifacts,
                        &out.source_types,
                        out.source_types_complete,
                        out.requires_search_sql,
                        true,
                    )
                    .await?;
                if !stored {
                    return Err(ReportError::ClaimLost);
                }

                // Retention prune (best-effort; a failure here doesn't fail the run).
                if let Err(e) = self
                    .repository
                    .prune_runs(def.id, def.retention_runs as i64)
                    .await
                {
                    warn!(definition_id = %def.id, error = %e, "Report retention prune failed");
                }

                // Notify owner + fire webhook (best-effort).
                self.notify_ready(def, out.row_count).await;
                Ok(())
            }
            Err(e) => {
                let msg = e.to_string();
                match self
                    .repository
                    .store_run_failure(run_id, def.id, fence, duration_ms, &msg)
                    .await
                {
                    // Claim was reclaimed mid-run: the new owner owns this run row.
                    Ok(false) => return Err(ReportError::ClaimLost),
                    Ok(true) => {}
                    Err(store_err) => {
                        warn!(definition_id = %def.id, error = %store_err, "Failed to record failed report run")
                    }
                }
                Err(e)
            }
        }
    }

    /// Resolve the report owner's per-source deny scope (NAN-1809).
    ///
    /// FAIL-CLOSED: any resolution error surfaces as a run-failing
    /// [`ReportError::Execution`] — never an unrestricted fallback. The error
    /// message is what analysts see on the failed run, so keep it legible.
    async fn owner_scope(&self, def: &ReportDefinition) -> Result<ScopeSet, ReportError> {
        let denied = SourceScopeRepository::new(self.pool.clone())
            .denied_for_user(def.owner_id)
            .await
            .map_err(|e| {
                ReportError::Execution(format!(
                    "could not resolve the report owner's source access ({e}); \
                     failing closed — the report was not run"
                ))
            })?;
        let deny: BTreeSet<String> = denied
            .into_iter()
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        Ok(ScopeSet::from_denied(deny))
    }

    /// F-31: snapshot the global restricted-`source_type` registry (best-effort,
    /// normalized). Used as the fail-closed stamp when a run's manifest cannot be
    /// trusted (`source_types_complete = false`). An error/empty registry yields
    /// an empty set — harmless, because an incomplete manifest already denies
    /// every restricted requester at download regardless of its contents.
    async fn restricted_registry(&self) -> BTreeSet<String> {
        match sqlx::query_scalar::<_, String>("SELECT source_type FROM restricted_source_types")
            .fetch_all(&self.pool)
            .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect(),
            Err(e) => {
                warn!(error = %e, "F-31: could not load restricted registry for report manifest; using empty set (incomplete manifest still denies restricted viewers)");
                BTreeSet::new()
            }
        }
    }

    /// F-31: derive `(source_types, complete)` for ONE rendered result set.
    ///
    /// - No rows → `({}, true)`: an empty artifact has nothing to protect.
    /// - Every row carries a non-empty `source_type` → the row-derived DISTINCT
    ///   set, `complete = true` (raw / grouped-raw / vendor pass-through).
    /// - Some/all rows LACK `source_type` (aggregates, `table`/`fields`
    ///   projections that dropped the column, SQL panels) → run the OWNER-scoped
    ///   companion `<base search> | stats count by source_type` to recover the
    ///   window's true source types. A trustworthy non-empty companion result →
    ///   `(row ∪ companion, true)`. If the query is not companionable (no nPL
    ///   base / SQL panel) or the companion fails/empties → `(row-derived, false)`
    ///   so the download gate denies every restricted requester.
    ///
    /// `companion_query` is the ORIGINAL nPL base (not audit-stripped); `None`
    /// for non-nPL (SQL) result sets, which are never companionable.
    async fn source_types_for_result(
        &self,
        companion_query: Option<&str>,
        rows: &[Value],
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> (BTreeSet<String>, bool) {
        if rows.is_empty() {
            return (BTreeSet::new(), true);
        }

        let lacks_source_type = |event: &Value| {
            event
                .get("source_type")
                .and_then(|v| v.as_str())
                .map_or(true, |s| s.trim().is_empty())
        };
        // Derive DIRECTLY over the slice — never clone up to REPORT_RESULT_ROW_CAP
        // (50k) rows just to read their source_type values.
        let direct = distinct_source_types_over(rows);

        // Fast path: every row already carries a per-event source_type.
        if !rows.iter().any(lacks_source_type) {
            return (direct, true);
        }

        // Rows dropped source_type — recover it via the owner-scoped companion.
        let base = match companion_query.and_then(|q| report_companion_query(q)) {
            Some(base) => base,
            None => return (direct, false),
        };
        // Audit-strip the companion exactly as the main query is stripped; a
        // strip error means we can't trust it → incomplete.
        let safe = match enforce_non_audit_query(&base) {
            Ok(q) => q,
            Err(_) => return (direct, false),
        };
        let req = SearchRequest {
            query: safe,
            time_range: TimeRangeInput::new(start, end),
            limit: Some(REPORT_PANEL_ROW_CAP),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: None,
        };
        match self.search_service.search(req, scope).await {
            Ok(resp) => {
                // NAN-2155: one classification, whose precedence rules live (and
                // are tested) in `companion_provenance`. `trustworthy` false =>
                // the window was not fully attributed, so the manifest is
                // incomplete and the download gate denies every restricted
                // requester — even if some groups DID name real sources
                // (codex round 7).
                let (companion_types, trustworthy) = companion_provenance(&resp.results);
                if !trustworthy {
                    return (direct, false);
                }
                let mut union = direct;
                union.extend(companion_types);
                (union, true)
            }
            Err(_) => (direct, false),
        }
    }

    async fn produce(
        &self,
        def: &ReportDefinition,
        scope: &ScopeSet,
        authorization: &ReportExecutionAuthorization,
    ) -> Result<ExecutionOutput, ReportError> {
        match def.source_type {
            ReportSourceType::Search => self.produce_search(def, scope).await,
            ReportSourceType::Dashboard => {
                let dashboard_authorization =
                    authorization.dashboard_authorization().ok_or_else(|| {
                        ReportError::AuthorizationResolution(
                            "authorized dashboard snapshot is unavailable; failing closed"
                                .to_string(),
                        )
                    })?;
                self.produce_dashboard(
                    def,
                    scope,
                    dashboard_authorization.dashboard(),
                    dashboard_authorization.requires_search_sql(),
                )
                .await
            }
        }
    }

    async fn produce_search(
        &self,
        def: &ReportDefinition,
        scope: &ScopeSet,
    ) -> Result<ExecutionOutput, ReportError> {
        let query = def
            .source_query
            .clone()
            .filter(|q| !q.trim().is_empty())
            .ok_or_else(|| ReportError::InvalidDefinition("search report has no query".into()))?;

        let now = Utc::now();
        let start = now - chrono::Duration::seconds(def.time_range_seconds.max(1));

        // Fail-closed audit stripping (execution identity seam): reports never
        // surface audit-log data (owner has no permission context here yet).
        let safe_query =
            enforce_non_audit_query(&query).map_err(|e| ReportError::Execution(e.to_string()))?;

        let req = SearchRequest {
            query: safe_query,
            time_range: TimeRangeInput::new(start, now),
            limit: Some(REPORT_RESULT_ROW_CAP),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: false,
            priority: None,
            dataset: None,
        };

        let resp = self
            .search_service
            // OWNER-SCOPED (NAN-1809): the report owner's per-source deny set,
            // resolved fail-closed in run_and_record. Audit exclusion is already
            // handled upstream (enforce_non_audit_query).
            .search(req, scope)
            .await
            .map_err(|e| ReportError::Execution(e.to_string()))?;

        let rows = resp.results;
        let columns = resp.column_order.unwrap_or_default();
        let result_truncated =
            rows.len() == REPORT_RESULT_ROW_CAP && resp.total_count > rows.len() as u64;

        let (csv_bytes, csv_trunc) =
            render::render_csv(&rows, &columns, REPORT_ARTIFACT_BYTE_CAP);
        // The HTML shows the ORIGINAL configured query (not the audit-stripped one).
        let (html_bytes, html_trunc) = render::render_search_html(
            &def.name,
            &query,
            start,
            now,
            now,
            &rows,
            &columns,
            resp.total_count,
            result_truncated,
            REPORT_ARTIFACT_BYTE_CAP,
        );

        let base = artifact_basename(&def.name, now);
        let artifacts = vec![
            RenderedArtifact {
                kind: "csv".into(),
                filename: format!("{base}.csv"),
                content_type: "text/csv; charset=utf-8".into(),
                content: csv_bytes,
            },
            RenderedArtifact {
                kind: "html".into(),
                filename: format!("{base}.html"),
                content_type: "text/html; charset=utf-8".into(),
                content: html_bytes,
            },
        ];

        // F-31: manifest of the source_types feeding these artifacts. Use the
        // ORIGINAL (not audit-stripped) query as the companion base; the
        // companion runs owner-scoped so it reflects exactly what the owner saw.
        let (mut source_types, complete) = self
            .source_types_for_result(Some(query.as_str()), &rows, start, now, scope)
            .await;
        if !complete {
            source_types.extend(self.restricted_registry().await);
        }

        Ok(ExecutionOutput {
            artifacts,
            row_count: Some(rows.len() as i64),
            result_truncated,
            artifact_truncated: csv_trunc || html_trunc,
            source_types: source_types.into_iter().collect(),
            source_types_complete: complete,
            requires_search_sql: false,
        })
    }

    async fn produce_dashboard(
        &self,
        def: &ReportDefinition,
        scope: &ScopeSet,
        dashboard: &Dashboard,
        requires_search_sql: bool,
    ) -> Result<ExecutionOutput, ReportError> {
        let now = Utc::now();
        let start = now - chrono::Duration::seconds(def.time_range_seconds.max(1));

        let panels = dashboard.panels.as_array().cloned().unwrap_or_default();
        let mut outputs = Vec::new();
        // F-31: the dashboard artifact aggregates every panel, so its manifest is
        // the UNION of the panels' source types, and it is COMPLETE only if every
        // panel that produced rows had a trustworthy per-panel manifest.
        let mut union: BTreeSet<String> = BTreeSet::new();
        let mut all_complete = true;
        for panel in panels.iter().take(MAX_DASHBOARD_PANELS) {
            let out = self.run_panel(panel, start, now, scope).await;
            // Only piped-mode panels with a query are companionable; SQL panels
            // (and query-less widgets) that dropped source_type force incomplete.
            let mode = panel.get("queryMode").and_then(|v| v.as_str()).unwrap_or("piped");
            let query = panel.get("query").and_then(|v| v.as_str()).unwrap_or("");
            let companion = if mode != "sql" && !query.trim().is_empty() {
                Some(query)
            } else {
                None
            };
            let (types, complete) = self
                .source_types_for_result(companion, &out.rows, start, now, scope)
                .await;
            union.extend(types);
            all_complete = all_complete && complete;
            outputs.push(out);
        }
        if !all_complete {
            union.extend(self.restricted_registry().await);
        }

        let (html_bytes, html_trunc) = render::render_dashboard_html(
            &def.name,
            &dashboard.name,
            start,
            now,
            now,
            &outputs,
            REPORT_ARTIFACT_BYTE_CAP,
        );

        let base = artifact_basename(&def.name, now);
        let artifacts = vec![RenderedArtifact {
            kind: "html".into(),
            filename: format!("{base}.html"),
            content_type: "text/html; charset=utf-8".into(),
            content: html_bytes,
        }];

        Ok(ExecutionOutput {
            artifacts,
            row_count: None,
            result_truncated: false,
            artifact_truncated: html_trunc,
            source_types: union.into_iter().collect(),
            source_types_complete: all_complete,
            requires_search_sql,
        })
    }

    /// Execute a single dashboard panel over the report window, scoped to the
    /// report OWNER's per-source deny set. Never returns an error: a failed /
    /// unsupported panel is rendered inline as such — including a restricted
    /// owner's raw-SQL panel, which trips `search_sql`'s fail-closed guard and
    /// renders its (analyst-legible) refusal in the artifact.
    async fn run_panel(
        &self,
        panel: &Value,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        scope: &ScopeSet,
    ) -> PanelOutput {
        let title = panel
            .get("title")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or("Panel")
            .to_string();
        let viz = panel
            .get("visualizationType")
            .and_then(|v| v.as_str())
            .unwrap_or("table")
            .to_string();

        // Metric widgets fetch from the metrics timeseries endpoint, not the
        // nPL/SQL panel-query path — not rendered in v1 reports.
        let is_metric = viz == "obs_metric"
            || panel.get("metricConfig").map_or(false, |v| !v.is_null());
        if is_metric {
            return PanelOutput {
                title,
                viz_type: viz,
                columns: vec![],
                rows: vec![],
                error: None,
                unsupported: Some("Metric widget — not rendered in v1 reports.".into()),
            };
        }

        let query = panel
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if query.trim().is_empty() {
            return PanelOutput {
                title,
                viz_type: viz,
                columns: vec![],
                rows: vec![],
                error: None,
                unsupported: Some("Panel has no query.".into()),
            };
        }

        let result = if dashboard_panel_executes_search_sql(panel) {
            // Bind SQL panels to the report window. NAN-2001: reports NEVER expose
            // audit — the SQL arm ALWAYS runs as the audit-hidden identity
            // (`RawSqlAuditAccess::Hidden`), independent of the owner's audit:view,
            // so the ClickHouse `source_type!='audit'` row policy strips audit
            // rows. The retired handler-side inject_audit_filter is gone.
            let expanded = crate::sql_hygiene::expand_sql_time_macros(&query, &start, &end);
            self.search_service
                .search_sql(
                    RawSqlRequest {
                        sql: expanded.trim_end_matches(';').to_string(),
                        time_range: TimeRangeInput::new(start, end),
                        limit: Some(REPORT_PANEL_ROW_CAP),
                        offset: None,
                    },
                    // OWNER-SCOPED (NAN-1809): a restricted owner trips
                    // search_sql's fail-closed guard here, and the refusal
                    // renders inline as this panel's error.
                    scope,
                    crate::search::RawSqlAuditAccess::Hidden,
                )
                .await
        } else {
            match enforce_non_audit_query(&query) {
                Ok(safe) => {
                    self.search_service
                        .search(SearchRequest {
                            query: safe,
                            time_range: TimeRangeInput::new(start, end),
                            limit: Some(REPORT_PANEL_ROW_CAP),
                            offset: None,
                            include_sql: Some(false),
                            skip_histogram: true,
                            skip_field_stats: true,
                            use_cache: false,
                            table_view: false,
                            request_id: None,
                            async_mode: false,
                            priority: None,
                            dataset: None,
                        },
                        // OWNER-SCOPED (NAN-1809): the report owner's per-source
                        // deny set, resolved fail-closed in run_and_record.
                        scope,
                    )
                        .await
                }
                Err(e) => Err(e),
            }
        };

        match result {
            Ok(resp) => PanelOutput {
                title,
                viz_type: viz,
                columns: resp.column_order.unwrap_or_default(),
                rows: resp.results,
                error: None,
                unsupported: None,
            },
            Err(e) => PanelOutput {
                title,
                viz_type: viz,
                columns: vec![],
                rows: vec![],
                error: Some(e.to_string()),
                unsupported: None,
            },
        }
    }

    /// Notify the owner in-app and fire the outbound `report_ready` webhook. Both
    /// best-effort — a delivery failure is logged and never fails the run.
    async fn notify_ready(&self, def: &ReportDefinition, row_count: Option<i64>) {
        // In-app bell link → the reports list (always a valid SPA route). The
        // outbound webhook carries the precise `/reports/{id}` deep link.
        let link = "/reports".to_string();
        let message = match def.source_type {
            ReportSourceType::Search => {
                format!("{} rows", row_count.unwrap_or(0))
            }
            ReportSourceType::Dashboard => "Dashboard report ready to download".to_string(),
        };

        let notif_repo = crate::db::repository::NotificationRepository::new(self.pool.clone());
        if let Err(e) = notif_repo
            .create(&NewNotification {
                user_id: def.owner_id,
                notification_type: NotificationType::ReportReady,
                title: format!("Report ready: {}", def.name),
                message: Some(message),
                link: Some(link),
                metadata: json!({
                    "report_id": crate::typeid::encode(crate::typeid::report::PREFIX, &def.id),
                    "source_type": def.source_type.as_str(),
                }),
            })
            .await
        {
            warn!(definition_id = %def.id, error = %e, "Failed to create report-ready notification");
        }

        let webhook = WebhookService::new(WebhookRepository::new(self.pool.clone()));
        webhook
            .fire_report_ready(
                def.id,
                &def.name,
                def.source_type.as_str(),
                "success",
                row_count,
                Utc::now(),
            )
            .await;
    }

    // ==================== SCHEDULER LOOP ====================

    /// Run the distributed report scheduler until cancelled. Requires a node id
    /// (set via [`with_node_id`]); without one the loop does not start.
    pub async fn run_scheduler_loop_with_shutdown(
        &self,
        poll_interval_secs: u64,
        shutdown: &ShutdownToken,
    ) {
        let node_id = match &self.node_id {
            Some(n) => n.clone(),
            None => {
                warn!("Report scheduler not started: no node_id configured");
                return;
            }
        };
        let stale_timeout = stale_timeout_secs();
        info!(node_id = %node_id, poll_interval_secs, "Starting report scheduler loop");

        loop {
            if shutdown.is_cancelled() {
                break;
            }

            // Take a run slot BEFORE claiming. Claiming first and then waiting for
            // capacity would hold a claim while blocked, risking a stale-reclaim
            // of work we haven't started. The permit is held across the run.
            let permit = match shutdown
                .run_until_cancelled(exec_semaphore().clone().acquire_owned())
                .await
            {
                None => break,
                Some(Ok(p)) => p,
                Some(Err(_)) => break, // semaphore closed — shutting down
            };

            let mut ran = false;
            let claim = self
                .repository
                .claim_due_definitions(1, &node_id, stale_timeout);
            match shutdown.run_until_cancelled(claim).await {
                None => break,
                Some(Ok(claimed)) => {
                    ran = !claimed.is_empty();
                    for c in claimed {
                        self.run_claimed(c, &node_id).await;
                    }
                }
                Some(Err(e)) => warn!(error = %e, "Report scheduler: failed to claim due definitions"),
            }
            drop(permit);

            if ran {
                tokio::task::yield_now().await;
                continue;
            }

            if shutdown
                .run_until_cancelled(tokio::time::sleep(Duration::from_secs(poll_interval_secs)))
                .await
                .is_none()
            {
                break;
            }
        }

        info!("Report scheduler loop stopped");
    }

    async fn run_claimed(&self, claimed: ClaimedReportDefinition, node_id: &str) {
        let def_id = claimed.definition.id;
        let enabled = claimed.definition.enabled;
        let cron = claimed.definition.cron_expression.clone();
        let generation = claimed.claim_generation;
        let run_id = claimed.claim_run_id;

        let outcome = self
            .execute_isolated(
                claimed.definition,
                run_id,
                "schedule",
                None,
                Some((node_id.to_string(), generation)),
            )
            .await;

        // Claim lost → another node reclaimed this run and owns its release.
        if matches!(outcome, ExecOutcome::ClaimLost) {
            warn!(definition_id = %def_id, "Report run claim lost; reclaimed by another node");
            return;
        }

        let (status, error) = match &outcome {
            ExecOutcome::Success => {
                info!(definition_id = %def_id, "Report run completed");
                (ReportRunStatus::Success, None)
            }
            ExecOutcome::Failed(msg) => {
                warn!(definition_id = %def_id, error = %msg, "Report run failed");
                (ReportRunStatus::Failed, Some(msg.clone()))
            }
            ExecOutcome::ClaimLost => unreachable!(),
        };

        let next_run_at = if enabled {
            calculate_next_run(&cron).ok().flatten()
        } else {
            None
        };

        match self
            .repository
            .release_claim(def_id, node_id, generation, status, error.as_deref(), next_run_at)
            .await
        {
            Ok(true) => {}
            Ok(false) => warn!(definition_id = %def_id, "Skipped stale report completion"),
            Err(e) => warn!(definition_id = %def_id, error = %e, "Failed to release report claim"),
        }
    }

    /// Start the scheduler as a background task.
    pub fn start_scheduler_with_shutdown(
        &self,
        poll_interval_secs: u64,
        shutdown: ShutdownToken,
    ) -> tokio::task::JoinHandle<()> {
        let service = self.clone();
        tokio::spawn(async move {
            service
                .run_scheduler_loop_with_shutdown(poll_interval_secs, &shutdown)
                .await;
        })
    }

    /// Release all claims held by this node (graceful shutdown).
    pub async fn release_all_claims(&self) -> Result<u64, ReportError> {
        if let Some(node_id) = &self.node_id {
            Ok(self.repository.release_all_claims(node_id).await?)
        } else {
            Ok(0)
        }
    }
}

/// Per-run execution timeout (env-overridable, floored at 30s).
fn run_timeout_secs() -> u64 {
    std::env::var("REPORT_RUN_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_RUN_TIMEOUT_SECS)
        .max(30)
}

/// Stale-claim reclaim timeout. Floored at 3× the run timeout so a running
/// report can't have its claim reclaimed mid-execution.
fn stale_timeout_secs() -> i64 {
    let floor = (run_timeout_secs() as i64).saturating_mul(3);
    std::env::var("REPORT_JOB_STALE_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_STALE_TIMEOUT_SECS)
        .max(floor)
}

/// F-31: DISTINCT normalized `source_type` values across a slice of event rows,
/// reading both the per-event `source_type` column and the aggregate
/// `_nano_source_types` stamp — the same two forms as
/// [`crate::db::repository::alerts::distinct_source_types`], but over a `&[Value]`
/// so a 50k-row search result is not deep-cloned into a `Value::Array` just to
/// read its source types. Trim + lowercase (OCSF `source_type` is not
/// ingest-lowercased), sorted-unique via `BTreeSet`.
fn distinct_source_types_over(rows: &[Value]) -> BTreeSet<String> {
    fn insert_normalized(raw: &str, set: &mut BTreeSet<String>) {
        let norm = raw.trim().to_lowercase();
        if !norm.is_empty() {
            set.insert(norm);
        }
    }
    let mut set = BTreeSet::new();
    for event in rows {
        // NAN-2155 (codex round 5): the per-event `source_type` is
        // ingest-controlled. Letting a forged reserved marker into a report's
        // manifest would make `report_artifact_download_allowed` deny EVERY
        // source-restricted requester — including the report's own owner — so a
        // single crafted event could take a scheduled report offline. Only the
        // engine's `_nano_source_types` stamp below may carry the sentinel,
        // where it legitimately means "provenance unresolved".
        if let Some(st) = event
            .get("source_type")
            .and_then(|v| v.as_str())
            .filter(|st| !crate::auth::is_reserved_source_type(st))
        {
            insert_normalized(st, &mut set);
        }
        if let Some(arr) = event.get("_nano_source_types").and_then(|v| v.as_array()) {
            for v in arr {
                if let Some(st) = v.as_str() {
                    insert_normalized(st, &mut set);
                }
            }
        }
    }
    set
}

/// NAN-2155: what a report companion result set proved about the window's
/// provenance — the report-side twin of
/// `detection::service::execution::classify_companion_rows`, kept pure so the
/// decision matrix is unit-testable.
///
/// Returns `(types, trustworthy)`:
///
/// * `trustworthy == false` — the companion returned nothing, or at least ONE
///   group had a blank / missing / non-string `source_type`, i.e. a slice of the
///   window whose source is unknown. **Partial attribution loses to nothing**
///   (codex round 7): a non-empty set of *other* groups must not certify the
///   result, or a restricted requester could download an artifact containing
///   unresolved-provenance data.
/// * `trustworthy == true` with an EMPTY set — every group was attributed and
///   every value was a reserved marker. The window is attributed to a name we
///   refuse to honour, which cannot be in the restricted registry, so nobody is
///   denied it (codex round 5). Failing closed here would let one crafted event
///   take a scheduled report offline for every restricted requester, including
///   its owner.
pub(crate) fn companion_provenance(rows: &[Value]) -> (BTreeSet<String>, bool) {
    let mut types: BTreeSet<String> = BTreeSet::new();
    let mut any_unattributed = false;
    for event in rows {
        match event
            .get("source_type")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
        {
            Some(source_type) => {
                // Reserved markers are dropped, never honoured — the companion
                // reads the ingest-controlled `source_type` column.
                if !crate::auth::is_reserved_source_type(&source_type) {
                    types.insert(source_type);
                }
            }
            None => any_unattributed = true,
        }
    }
    // Partial attribution loses to nothing: a non-empty set of OTHER groups must
    // not certify a result that also contains an unattributed slice.
    if any_unattributed || rows.is_empty() {
        return (types, false);
    }
    (types, true)
}

/// F-31: derive the companion query that lists the DISTINCT `source_type`
/// values feeding an nPL query's BASE search over a window — mirrors the
/// detection engine's `source_type_companion_query` (NAN-1800). Aggregate /
/// projection commands collapse or drop the per-row `source_type`, so the base
/// search is re-run piped into `stats count by source_type`. Dropping the
/// intermediate commands is deliberately OVER-inclusive (pre-aggregation filters
/// could only narrow the set) — over-stamping hides the artifact from MORE
/// scoped viewers, never fewer (the fail-closed direction). `None` when the
/// query cannot be parsed.
fn report_companion_query(query: &str) -> Option<String> {
    let parsed = parse_query(query).ok()?;
    let mut node: &Query = &parsed;
    loop {
        match node {
            Query::Piped { source, .. } => node = source,
            Query::Search(expr) => {
                return Some(format!("{} | stats count by source_type", expr.pretty_print()));
            }
        }
    }
}

/// Build a filesystem-safe artifact basename: `<slug>-<YYYYmmdd-HHMMSS>`.
fn artifact_basename(name: &str, at: DateTime<Utc>) -> String {
    let mut slug = String::with_capacity(name.len());
    let mut prev_dash = false;
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            slug.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            slug.push('-');
            prev_dash = true;
        }
    }
    let slug = slug.trim_matches('-');
    let slug = if slug.is_empty() { "report" } else { slug };
    let slug: String = slug.chars().take(60).collect();
    format!("{}-{}", slug, at.format("%Y%m%d-%H%M%S"))
}
