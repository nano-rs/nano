// SPDX-License-Identifier: AGPL-3.0-or-later

//! Cost-based admission for the unfiltered-search memory guards (NAN-5635).
//!
//! The decision rules live in
//! [`query_processing::oom_admission`](crate::search::query_processing::oom_admission);
//! this file runs the row estimate. The estimate is derived from the SAME
//! parsed query the search runs (after the viewer's source-scope deny-set was
//! injected into its text), so it counts only rows the caller may read.

use crate::query::{Query, QueryOptions, TimeRange};
use crate::search::query_processing::oom_admission::{
    admission_class, budget_override_from_env, decide, estimate_is_bounded, estimate_query,
    resolve_budget_bytes, row_budget, AdmissionClass,
};
use crate::search::query_processing::{oom_risk_sites, prevalence_scan_site, OomRiskSite};
use crate::search::TimeRangeInput;

use super::SearchService;

impl SearchService {
    /// Admit the query's structural OOM candidates, or return the refusal
    /// message. Spillable sites are admitted outright; each cost-gated site
    /// is admitted when its row estimate over `time_range` fits the budget.
    /// Anything that cannot be estimated (no ClickHouse executor, another
    /// dataset, a row-multiplying stage before the command, a failed count)
    /// is refused with the guard's message, as before NAN-5635.
    pub(super) async fn admit_oom_risks(
        &self,
        query: &Query,
        time_range: &TimeRangeInput,
        dataset: crate::query::Dataset,
        query_id: &str,
        scope: &crate::auth::ScopeSet,
    ) -> Result<(), String> {
        let sites = oom_risk_sites(query);
        self.admit_cost_gated_sites(&sites, time_range, dataset, query_id, scope)
            .await
    }

    /// NAN-5660: admit the prevalence pushdown's newest-1M full-width scan
    /// (the plan found no result window to push and no projection). Same
    /// budget, estimate and refusal as the other cost-gated sites. The
    /// estimate is every row the search feeds in, not the 1M the LIMIT keeps:
    /// peak memory grows with the input (measured ~8 KB per input row on wide
    /// OCSF rows whatever the LIMIT, 285k → 2.1 GiB, 571k → 4.2 GiB).
    pub(super) async fn admit_prevalence_scan(
        &self,
        query: &Query,
        time_range: &TimeRangeInput,
        query_id: &str,
        scope: &crate::auth::ScopeSet,
    ) -> Result<(), String> {
        let Some(site) = prevalence_scan_site(query) else {
            return Ok(());
        };
        self.admit_cost_gated_sites(
            std::slice::from_ref(&site),
            time_range,
            crate::query::Dataset::Logs,
            query_id,
            scope,
        )
        .await
    }

    /// Shared body of the admission checks: each cost-gated site in `sites`
    /// is admitted when its row estimate fits what the sites before it left
    /// of the budget.
    async fn admit_cost_gated_sites(
        &self,
        sites: &[OomRiskSite<'_>],
        time_range: &TimeRangeInput,
        dataset: crate::query::Dataset,
        query_id: &str,
        scope: &crate::auth::ScopeSet,
    ) -> Result<(), String> {
        let gated: Vec<_> = sites
            .iter()
            .filter_map(|site| match admission_class(site) {
                AdmissionClass::Spillable => None,
                AdmissionClass::CostGated { bytes_per_row } => Some((site, bytes_per_row)),
            })
            .collect();
        if gated.is_empty() {
            return Ok(());
        }

        let budget_bytes = resolve_budget_bytes(
            budget_override_from_env(),
            self.active_ch_settings
                .as_ref()
                .and_then(|s| s.max_memory_usage_bytes),
            self.query_memory_ceiling_bytes,
        );
        let executor = match self.ch_executor.as_ref() {
            Some(executor) if budget_bytes > 0 && dataset == crate::query::Dataset::Logs => {
                executor
            }
            _ => return Err(gated[0].0.risk.message()),
        };
        let range = TimeRange::new(time_range.start, time_range.end);

        // Every gated site runs inside the ONE query and its one memory
        // ceiling, so the sites share the budget: each is checked against what
        // the sites before it left. Sites with the same estimate share a count
        // (an admitted count is exact: a capped one was refused).
        let mut used_bytes: u64 = 0;
        let mut counts: Vec<(String, u64)> = Vec::new();
        for (site, bytes_per_row) in gated {
            let budget_rows = row_budget(bytes_per_row, budget_bytes.saturating_sub(used_bytes));
            let Some(estimate) = estimate_query(site) else {
                return Err(site.risk.message());
            };
            let bounded = estimate_is_bounded(&estimate);
            let key = format!("{estimate:?}");
            let counted = match counts.iter().find(|(k, _)| *k == key) {
                Some((_, counted)) => *counted,
                None => {
                    let counted = self
                        .count_estimate_rows(executor, &estimate, &range, bounded, budget_rows, query_id, scope)
                        .await
                        .map_err(|e| {
                            tracing::warn!(
                                error = %e,
                                "OOM guard row estimate failed; refusing the cost-gated command"
                            );
                            estimate_failure_message(&site.risk, &e)
                        })?;
                    counts.push((key, counted));
                    counted
                }
            };
            tracing::debug!(
                risk = ?site.risk,
                counted,
                bounded,
                budget_rows,
                budget_bytes,
                used_bytes,
                "OOM guard cost estimate"
            );
            decide(&site.risk, counted, bounded, budget_rows)?;
            used_bytes = used_bytes.saturating_add(counted.saturating_mul(bytes_per_row));
        }
        Ok(())
    }

    /// The estimate's base SQL. NAN-5793 review: the estimate EXECUTES the
    /// search's own subsearches (a `[dataset=risk …]` one reads findings), so
    /// it is generated under the caller's deny-set like the search itself.
    pub(super) fn estimate_sql(
        &self,
        estimate: &Query,
        range: &TimeRange,
        scope: &crate::auth::ScopeSet,
    ) -> Result<String, String> {
        let options = QueryOptions {
            use_cache: false,
            table_view: true,
            limit: None,
            unordered: true,
            omit_settings: false,
        };
        self.sql_generator(crate::query::GeneratorScope::viewer(scope))
            .generate_with_options(estimate, range, &options)
            .map_err(|e| e.to_string())
    }

    async fn count_estimate_rows(
        &self,
        executor: &crate::search::execution::ClickHouseExecutor,
        estimate: &Query,
        range: &TimeRange,
        bounded: bool,
        budget_rows: u64,
        query_id: &str,
        scope: &crate::auth::ScopeSet,
    ) -> Result<u64, String> {
        let sql = self.estimate_sql(estimate, range, scope)?;
        // Bounded: stop reading one past the budget (NAN-1635's SELECT 1
        // wrap); unbounded: a filter-free count served from part metadata.
        let count_sql = if bounded {
            let cap = usize::try_from(budget_rows.saturating_add(1)).unwrap_or(usize::MAX);
            format!(
                "SELECT count(*) AS cnt FROM (SELECT 1 FROM ({sql}) AS matched LIMIT {cap}) AS subquery"
            )
        } else {
            format!("SELECT count(*) AS cnt FROM ({sql}) AS subquery")
        };
        let escaped =
            crate::search::execution::clickhouse_executor::escape_question_marks_in_strings(
                &count_sql,
            );
        let guard_id = crate::search::companion_query_id::CompanionQuery::Guard.query_id(query_id);
        // The estimate must stay cheap next to the search it gates: cap its
        // run time (a selective `where` over a long window reads rows).
        let mut settings = self.active_ch_settings.clone();
        if let Some(s) = settings.as_mut() {
            s.max_execution_time = s.max_execution_time.min(ESTIMATE_MAX_EXECUTION_SECS);
        }
        let mut query = crate::search::execution::clickhouse_executor::with_query_options(
            executor.sized_query(&escaped),
            Some(&guard_id),
            settings.as_ref(),
        );
        if settings.is_none() {
            query = query.with_setting("max_execution_time", ESTIMATE_MAX_EXECUTION_SECS.to_string());
        }
        query.fetch_one::<u64>().await.map_err(|e| e.to_string())
    }
}

/// Run-time cap for the row estimate, in seconds.
const ESTIMATE_MAX_EXECUTION_SECS: u32 = 30;

/// The refusal when the estimate itself failed: the guard's message, plus
/// the reason when it is the estimate's own time cap.
fn estimate_failure_message(risk: &crate::search::query_processing::OomRisk, error: &str) -> String {
    if error.contains("TIMEOUT_EXCEEDED") || error.contains("Code: 159") {
        format!(
            "{} Counting the events this search would feed into it took longer than \
             {ESTIMATE_MAX_EXECUTION_SECS}s. Narrow the time range or add filters.",
            risk.message()
        )
    } else {
        risk.message()
    }
}
