// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule Execution
//!
//! Execute detection rules against log data and generate alerts/signals.

use chrono::{Duration, Utc};
use metrics::{counter, histogram};
use tracing::{debug, info, instrument, warn};

use crate::detection::query_enrichment::inject_timestamp_bounds;
use crate::models::{Alert, AlertMode, DetectionRule, RuleMode};
use crate::query::{parse_query, PrettyPrint, Query};
use crate::search::{SearchExecutionLimits, SearchRequest, TimeRangeInput};

use super::DetectionError;
use super::DetectionService;

/// How a rule's dataset relates to the `source_type` provenance dimension
/// (NAN-2024, refined by NAN-2227).
#[derive(Debug, PartialEq, Eq)]
pub(super) enum DatasetProvenance {
    /// `Logs` — carries a per-event `source_type`. Run the companion.
    SourceDerived,
    /// `Spans` / `Metrics` — `otel_spans` / `otel_metrics` have NO `source_type`
    /// column, and per-source RBAC does not scope those tables at all. Their
    /// provenance is not unknown, it is ABSENT: stamp an empty manifest.
    NotSourceDerived,
    /// `Risk` — a derived grain aggregated from the FINDINGS stream in the logs
    /// table, so a risk row can carry entity data whose origin was restricted.
    /// The companion cannot resolve it (the outer projection has no
    /// `source_type`), so this genuinely is unknown provenance: fail closed.
    Unknowable,
}

/// Classify a rule's dataset.
///
/// The logs-shaped companion (`… | stats count by source_type`) resolves to
/// UNKNOWN_IDENTIFIER (CH code 47) on every non-logs dataset, so it is skipped
/// for all three — but NAN-2227: skipping it is not the same fact for all three.
///
/// NAN-2024 lumped spans/metrics/risk together and failed closed for each. Once
/// NAN-2155 put [`UNRESOLVED_SOURCE_SENTINEL`](crate::auth::UNRESOLVED_SOURCE_SENTINEL)
/// into that fail-closed stamp, the consequence stopped being conservative and
/// became wrong for spans/metrics: their evidence is redacted from EVERY webhook
/// on EVERY deployment, and the sentinel — carried in every restricted
/// principal's deny bind — also hides those alerts from source-restricted
/// analysts in the UI. Neither table is source-scoped in the first place, so
/// both effects protect nothing.
///
/// "There is no source dimension here" is the `'{}'` manifest the read side
/// already treats as visible-to-everyone, and the value observability alerts
/// have always carried. Risk keeps failing closed because its rows really can
/// embed restricted-origin entities.
pub(super) fn dataset_provenance(dataset: Option<&str>) -> DatasetProvenance {
    match crate::query::Dataset::from_selector(dataset.unwrap_or("logs")) {
        crate::query::Dataset::Logs => DatasetProvenance::SourceDerived,
        crate::query::Dataset::Spans | crate::query::Dataset::Metrics => {
            DatasetProvenance::NotSourceDerived
        }
        crate::query::Dataset::Risk => DatasetProvenance::Unknowable,
    }
}

/// NAN-2155: what the `… | stats count by source_type` companion proved about a
/// window's provenance.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum CompanionProvenance {
    /// Every companion group carried a usable `source_type`. These are the
    /// window's real sources (normalized, sorted, deduped) — stamp them.
    Attributed(Vec<String>),
    /// Provenance was not fully established: the companion returned nothing, or
    /// at least one group had a blank / missing / non-string `source_type`, i.e.
    /// a slice of the window whose source is unknown. Fail closed.
    Unresolved { any_unattributed: bool },
    /// Every group was attributed, and every value was a reserved marker. The
    /// window IS attributed — to a name we refuse to honour. Not unresolved.
    ReservedOnly,
}

/// Classify a companion result set (NAN-2155, codex rounds 4-7).
///
/// Pure so the whole decision matrix is unit-testable without a search service —
/// and so the tests exercise the REAL branch rather than a re-implementation of
/// it, which is how the round 5/6/7 defects survived their own tests.
///
/// Precedence matters, and every ordering here was a codex finding:
///
/// 1. **Partial attribution loses to nothing.** If ANY group is unattributed the
///    window is `Unresolved`, even when other groups named real sources (round
///    7). Stamping just the known sources would let a viewer denied some OTHER
///    source see an aggregate that includes the unattributed slice — provenance
///    that was never established. This also matches the over-inclusive intent
///    `source_type_companion_query` already documents: over-stamping hides the
///    row from MORE scoped viewers, never fewer.
/// 2. **Reserved values are dropped, not honoured** (round 4). The companion
///    reads the ingest-controlled `logs.source_type` column, so it is the second
///    route by which a forged `X-Source-Type` could reach the trusted
///    `_nano_source_types` stamp; the per-event filter in
///    `distinct_source_types` never sees this path.
/// 3. **A fully attributed but reserved-only window is NOT unresolved**
///    (round 5). Failing closed there would let one forged header hide an
///    aggregate detection from every scoped analyst — the mirror image of the
///    bug this all fixes. The forged name cannot be in the restricted registry
///    (the registry write boundary rejects it), so nobody is denied it.
///
/// A window mixing a real source with a reserved one is `Attributed` on the real
/// source's strength, so a forged value can never mask a restricted source.
pub(super) fn classify_companion_rows(rows: &[serde_json::Value]) -> CompanionProvenance {
    let mut named: Vec<String> = Vec::new();
    let mut any_unattributed = false;
    for row in rows {
        match row
            .get("source_type")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty())
        {
            Some(source_type) => named.push(source_type),
            None => any_unattributed = true,
        }
    }

    // (1) Partial attribution — or no rows at all — is unresolved, regardless of
    // what the attributed groups said.
    if any_unattributed || named.is_empty() {
        return CompanionProvenance::Unresolved { any_unattributed };
    }

    // (2) Drop reserved markers; (3) an all-reserved window is still attributed.
    let mut types: Vec<String> = named
        .into_iter()
        .filter(|s| !crate::auth::is_reserved_source_type(s))
        .collect();
    types.sort();
    types.dedup();
    if types.is_empty() {
        CompanionProvenance::ReservedOnly
    } else {
        CompanionProvenance::Attributed(types)
    }
}

/// NAN-2155: THE fail-closed `_nano_source_types` stamp, used by every branch
/// of `annotate_source_types_for_scoping` that could not determine the window's
/// real source types.
///
/// One function rather than two so the "registry known" and "registry
/// unavailable" branches cannot drift: pass whatever restricted set is
/// available (possibly empty). Three ingredients, each doing a different job:
///
/// * `restricted` — the registry snapshot. Every restricted principal's deny
///   set is a SUBSET of the registry (`denied = restricted − granted`), so
///   stamping the whole registry overlaps all of them. This is the precise
///   part: it is what makes the row hidden from exactly the scoped viewers.
/// * [`UNRESOLVED_SOURCE_SENTINEL`](crate::auth::UNRESOLVED_SOURCE_SENTINEL) —
///   carried by EVERY restricted principal's deny bind
///   ([`crate::auth::deny_bind_values`]). This is the part that does NOT
///   depend on the snapshot being fresh or even present, so the stamp stays
///   fail-closed when the registry is stale (a just-restricted source the
///   snapshot has not picked up) or entirely unavailable.
/// * `audit` — an ALWAYS-restricted origin independent of the registry
///   (`FindingLogger::origin_restricted`, `WebhookService::origin_restricted`),
///   so the ClickHouse finding evidence and the webhook egress for this match
///   are redacted too, with no PostgreSQL access required. Without it, those
///   two write-time redactions would see a "known origin" they cannot prove
///   restricted and let the sample through.
///
/// Unrestricted principals bind no deny array at all, so none of this hides the
/// row from them — the detection stays triageable.
///
/// Returned sorted + deduped so the stamp is deterministic (it feeds no dedup
/// hash — `_nano_*` is stripped — but a stable value keeps tests/logs readable).
pub(super) fn fail_closed_stamp(
    restricted: &std::collections::BTreeSet<String>,
) -> serde_json::Value {
    let mut values: Vec<String> = restricted.iter().cloned().collect();
    values.push(crate::auth::UNRESOLVED_SOURCE_SENTINEL.to_string());
    values.push("audit".to_string());
    values.sort();
    values.dedup();
    serde_json::Value::Array(values.into_iter().map(serde_json::Value::String).collect())
}

impl DetectionService {
    // ========================================================================
    // Rule Execution
    // ========================================================================

    /// Run a query against a single time window and return the matched rows.
    ///
    /// This is the **pure per-window evaluator**. It performs no DB writes —
    /// no dedup, no live counter updates, no signal logging — so it's safe to
    /// call repeatedly during a backtest. Both production `execute_rule`
    /// (one window per cron tick) and the historical "Test Rule" feature
    /// (many windows in parallel) call this so they cannot diverge in
    /// query semantics.
    #[instrument(
        // NAN-2047: `scope` is authorization metadata (caller's denied-source
        // set) — never emit it into spans.
        skip(self, query, scope),
        fields(window_start = %time_range.start, window_end = %time_range.end)
    )]
    pub async fn evaluate_window(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        dataset: Option<String>,
        // NAN-2047: source scope for the window search (see
        // `evaluate_window_with_options`). Scheduled/real-time callers pass
        // `ScopeSet::unrestricted()`; the Test Rule path passes the caller scope.
        scope: &crate::auth::ScopeSet,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        self.evaluate_window_with_limit(
            query,
            time_range,
            dataset,
            crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT,
            scope,
        )
        .await
    }

    /// Evaluate one production-equivalent window with a caller-supplied result
    /// limit. Autonomous validation uses a deliberately small `cap + 1` limit
    /// so it can distinguish an exact result from a capped one without ever
    /// materializing the production 1M-row ceiling many times concurrently.
    pub(crate) async fn evaluate_window_with_limit(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        dataset: Option<String>,
        result_limit: usize,
        scope: &crate::auth::ScopeSet,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        self.evaluate_window_with_options(query, time_range, dataset, result_limit, None, None, scope)
            .await
    }

    /// Autonomous counterpart with an evaluator-owned query ID, no interactive
    /// count companion, and ClickHouse-enforced result row/byte ceilings.
    pub(crate) async fn evaluate_tuning_window(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        dataset: Option<String>,
        result_limit: usize,
        result_byte_limit: u64,
        query_id: String,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        let execution_limits = SearchExecutionLimits {
            max_result_rows: u64::try_from(result_limit).unwrap_or(u64::MAX),
            max_result_bytes: result_byte_limit,
        };
        self.evaluate_window_with_options(
            query,
            time_range,
            dataset,
            result_limit,
            Some(query_id),
            Some(execution_limits),
            // Autonomous tuning is a SYSTEM caller — unrestricted like scheduled
            // execution (NAN-2047).
            &crate::auth::ScopeSet::unrestricted(),
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn evaluate_window_with_options(
        &self,
        query: &str,
        time_range: TimeRangeInput,
        dataset: Option<String>,
        result_limit: usize,
        request_id: Option<String>,
        execution_limits: Option<SearchExecutionLimits>,
        // NAN-2047: the source-scope the window search runs under. Scheduled /
        // real-time / tuning execution is SYSTEM and passes
        // `ScopeSet::unrestricted()` (a rule must match across ALL sources,
        // including restricted + audit). The interactive "Test Rule" path passes
        // the CALLER's effective deny set so a source-restricted user cannot use
        // the tester as an unrestricted alternate search surface.
        scope: &crate::auth::ScopeSet,
    ) -> Result<Vec<serde_json::Value>, DetectionError> {
        // Enrich aggregation queries with timestamp bounds so results always carry
        // _first_seen/_last_seen for detection latency calculation.
        let enriched_query = match parse_query(query) {
            Ok(parsed) => inject_timestamp_bounds(&parsed).pretty_print(),
            Err(_) => query.to_string(),
        };

        let request = SearchRequest {
            query: enriched_query,
            time_range,
            // Production passes the standard 1M safety cap here (audit D19).
            // Autonomous validation passes a smaller cap+1 and treats reaching
            // it as non-exact, routing the proposal to review.
            limit: Some(result_limit),
            offset: None,
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id,
            async_mode: false,
            priority: None,
            dataset,
        };

        let search_service = execution_limits.map_or_else(
            || self.search_service.clone(),
            |limits| self.search_service.clone().with_execution_limits(limits),
        );
        search_service
            // NAN-2047: run under the caller-supplied scope. SYSTEM callers pass
            // `ScopeSet::unrestricted()` (match across ALL sources); the Test
            // Rule path passes the caller's effective deny set.
            .search(request, scope)
            .await
            .map(|r| r.results)
            .map_err(|e| DetectionError::SearchError(e.to_string()))
    }

    /// NAN-1800: derive the companion query that lists the DISTINCT
    /// `source_type` values feeding a rule's BASE search over a window.
    ///
    /// Aggregate commands (stats/timechart/top/rare) collapse the raw stream,
    /// so their output rows carry no per-event `source_type` and the alert
    /// `source_types` stamp would come out empty — which the read side treats
    /// as visible-to-everyone (fail-OPEN for scoped viewers). This companion
    /// re-runs only the rule's innermost search expression piped into
    /// `stats count by source_type`, yielding the window's distinct source
    /// types. Dropping the intermediate commands is deliberately
    /// OVER-inclusive (pre-aggregation filters could only narrow the set):
    /// over-stamping hides the alert from more scoped viewers, never fewer —
    /// the fail-closed direction.
    fn source_type_companion_query(rule_query: &str) -> Option<String> {
        let parsed = parse_query(rule_query).ok()?;
        let mut node: &Query = &parsed;
        loop {
            match node {
                Query::Piped { source, .. } => node = source,
                Query::Search(expr) => {
                    return Some(format!(
                        "{} | stats count by source_type",
                        expr.pretty_print()
                    ));
                }
            }
        }
    }

    /// NAN-1800: stamp aggregate result rows with the window's distinct
    /// `source_type` values (`_nano_source_types`) so
    /// `AlertRepository::create_alert` can derive a non-empty
    /// `alerts.source_types` for aggregate rules.
    ///
    /// No-op when every row already carries a per-event `source_type`
    /// (raw/grouped-raw and vendor pass-through rules — the common case, no
    /// extra query). The `_nano_` prefix keeps the stamp out of every dedup
    /// hash (both `compute_event_hash` and the matched-event overlap hash
    /// strip `_nano_*`).
    ///
    /// NAN-2155: NO path through this function may leave a row unstamped. The
    /// detection is never dropped (losing a detection is worse than losing its
    /// scoping stamp) but the stamp itself always fails CLOSED — every failure
    /// branch writes a value that hides the row from restricted viewers while
    /// keeping it visible to unrestricted ones:
    ///
    /// * registry known (fresh, or last-known after a PG error) → the full
    ///   restricted set, which by construction overlaps EVERY restricted
    ///   principal's deny set (`denied ⊆ restricted`);
    /// * registry never loaded → [`UNRESOLVED_SOURCE_SENTINEL`], which every
    ///   restricted principal's deny bind carries
    ///   ([`crate::auth::deny_bind_values`]).
    ///
    /// Leaving the stamp EMPTY is never an option here: `'{}'` is the read
    /// side's "known not to be source-derived" value and is visible to
    /// everyone, so an empty stamp on this path would publish a restricted
    /// match to every principal, permanently — the row is written once and its
    /// provenance can never be recovered.
    ///
    /// [`UNRESOLVED_SOURCE_SENTINEL`]: crate::auth::UNRESOLVED_SOURCE_SENTINEL
    async fn annotate_source_types_for_scoping(
        &self,
        rule: &DetectionRule,
        results: &mut [serde_json::Value],
        time_range: &TimeRangeInput,
    ) {
        let lacks_source_type = |event: &serde_json::Value| {
            event
                .get("source_type")
                .and_then(|v| v.as_str())
                .map_or(true, |s| s.trim().is_empty())
        };
        if !results.iter().any(lacks_source_type) {
            return;
        }
        let apply = |results: &mut [serde_json::Value], stamp: &serde_json::Value| {
            for event in results.iter_mut() {
                if lacks_source_type(event) {
                    if let Some(obj) = event.as_object_mut() {
                        obj.insert("_nano_source_types".to_string(), stamp.clone());
                    }
                }
            }
        };

        // Restricted registry = the fail-closed authority. If nothing is
        // restricted, any/empty stamp is harmless (scoping is a no-op).
        //
        // NAN-2155: read it through `SourceScopeResolver`, the same authority
        // the READ side resolves deny sets from, rather than a raw SELECT. The
        // resolver retains its last-known registry past a refresh failure, so a
        // transient PG error degrades to deny-all-restricted here exactly as it
        // does in `SourceScopeResolver::resolve` — previously the write path
        // returned early on that error and silently stamped `'{}'`, i.e. it
        // failed OPEN while the resolve path failed CLOSED.
        let mut restricted: std::collections::BTreeSet<String> =
            match self.source_scopes.restricted_snapshot().await {
                Ok(set) => set,
                Err(e) => {
                    // Registry has NEVER loaded in this process and PG is
                    // unreachable — there is no restricted set to stamp with.
                    // Stamp the unresolved-provenance marker: hidden from every
                    // restricted principal, still visible to unrestricted ones,
                    // and distinguishable from a legitimately sourceless row so
                    // it can be re-triaged later.
                    warn!(rule_id = %rule.id, error = %e,
                        "NAN-2155: restricted registry unavailable for aggregate stamping; \
                         stamping unresolved-provenance marker (fail closed)");
                    apply(
                        results,
                        &fail_closed_stamp(&std::collections::BTreeSet::new()),
                    );
                    return;
                }
            };
        // NAN-2001: 'audit' is an ALWAYS-restricted ORIGIN for finding redaction
        // (hard-wired sentinel, see `FindingLogger::origin_restricted`), so the
        // effective set is never empty. Seeding it here means the source_type
        // companion runs for aggregate rules on EVERY deployment — including
        // those with an empty per-source registry — so an aggregate AUDIT rule's
        // rows get stamped `_nano_source_types` and its finding becomes
        // known-origin (`origin_source_types_from` harvests the stamp). Without
        // this, an audit aggregate rule on an unscoped deployment would leave the
        // finding origin unknown and leak the audit actor via `risk_entity`.
        // This only affects the STAMP the companion writes (the window's real
        // matched source types); it does NOT enter any viewer's deny set — the
        // read side reads the PG registry directly — so alert/detection_match
        // visibility is unchanged (an empty registry denies nothing).
        restricted.insert("audit".to_string());
        // Fail-CLOSED stamp: the full restricted set, so an unresolved-origin
        // aggregate alert overlaps ANY scoped viewer's deny set and defaults to
        // HIDDEN — used whenever the companion can't produce a trustworthy
        // per-window source_type list (NAN-1800 review).
        //
        // NAN-2155 (codex round 4): the restricted set alone is NOT sufficient
        // here. This service builds its own `SourceScopeResolver`, which the
        // API's source-scope CRUD does not invalidate directly — it converges
        // via the cross-process version poll, so the snapshot can lag a
        // just-restricted source by up to `VERSION_CHECK_SECS`. The stamp is
        // IRREVERSIBLE, so even a few seconds of staleness would permanently
        // under-stamp a match: a caller denied the newly-restricted source but
        // holding `audit:view` would keep seeing that row forever, long after
        // every cache converged. `fail_closed_stamp` therefore also unions the
        // freshness-independent sentinel — see its doc for the full breakdown.
        let restricted_stamp = || fail_closed_stamp(&restricted);

        // NAN-2024: the companion is logs-shaped (`… | stats count by source_type`),
        // but non-Logs datasets are derived grains whose outer projection has no
        // `source_type` column — the query is UNKNOWN_IDENTIFIER (CH code 47) on
        // every cycle. Skip the doomed round-trip either way; NAN-2227 splits
        // WHAT the skip means (see `dataset_provenance`).
        match dataset_provenance(rule.dataset.as_deref()) {
            DatasetProvenance::NotSourceDerived => {
                // Spans/metrics: absent provenance, not unknown provenance.
                // An empty manifest is the read side's "known not source-derived"
                // value — visible to everyone, and egressable, exactly as these
                // alerts behaved before NAN-2155 put the sentinel in the stamp.
                debug!(rule_id = %rule.id, dataset = ?rule.dataset,
                    "NAN-2227: dataset has no source_type dimension; stamping an empty manifest (companion skipped)");
                apply(results, &serde_json::Value::Array(Vec::new()));
                return;
            }
            DatasetProvenance::Unknowable => {
                // Risk: aggregated from findings that DO have origins we cannot
                // recover here. Genuinely unknown ⇒ fail closed.
                debug!(rule_id = %rule.id, dataset = ?rule.dataset,
                    "NAN-2024: risk grain cannot resolve origin; failing closed (companion skipped)");
                apply(results, &restricted_stamp());
                return;
            }
            DatasetProvenance::SourceDerived => {}
        }

        let Some(companion) = Self::source_type_companion_query(&rule.query) else {
            warn!(rule_id = %rule.id,
                "NAN-1800: could not derive source_type companion query; failing closed with the full restricted set");
            apply(results, &restricted_stamp());
            return;
        };

        match self
            .evaluate_window(
                &companion,
                time_range.clone(),
                rule.dataset.clone(),
                // Scheduled/real-time SYSTEM execution — unrestricted (NAN-2047).
                &crate::auth::ScopeSet::unrestricted(),
            )
            .await
        {
            Ok(rows) => {
                let stamp = match classify_companion_rows(&rows) {
                    CompanionProvenance::Attributed(types) => serde_json::Value::Array(
                        types.into_iter().map(serde_json::Value::String).collect(),
                    ),
                    CompanionProvenance::Unresolved { any_unattributed } => {
                        warn!(rule_id = %rule.id, any_unattributed,
                            "NAN-1800: source_type companion did not fully attribute the window; failing closed with the full restricted set");
                        restricted_stamp()
                    }
                    CompanionProvenance::ReservedOnly => {
                        warn!(rule_id = %rule.id,
                            "NAN-2155: source_type companion attributed the window ONLY to reserved \
                             marker values (forged X-Source-Type?); treating it as \
                             attributed-but-unrestricted rather than failing closed, which would be a \
                             detection-suppression primitive");
                        serde_json::Value::Array(Vec::new())
                    }
                };
                apply(results, &stamp);
            }
            Err(e) => {
                warn!(rule_id = %rule.id, error = %e,
                    "NAN-1800: source_type companion query failed; failing closed with the full restricted set");
                apply(results, &restricted_stamp());
            }
        }
    }

    /// Execute a detection rule and generate alerts for matches (if in alerting mode)
    ///
    /// This method:
    /// - Queries logs using SearchService (ClickHouse when DualPool is configured) - Requirement 6.1
    /// - Evaluates prevalence conditions if present in the rule query - Requirements 6.1, 6.2
    /// - Stores matched events in alerts (PostgreSQL) - Requirement 6.4
    /// - Includes prevalence context in alerts - Requirement 6.5
    /// - Updates rule statistics (PostgreSQL)
    /// - Calculates risk scores using ScoreCalculator - Requirements 1.3, 8.2
    ///
    /// In live mode, matches are counted but no alerts are generated.
    /// In staging mode, the rule is not executed at all.
    #[instrument(
        skip_all,
        fields(rule_id = %rule.id, rule_name = %rule.name)
    )]
    pub async fn execute_rule(
        &self,
        rule: &DetectionRule,
        time_range: Option<TimeRangeInput>,
    ) -> Result<Option<Alert>, DetectionError> {
        // NAN-1791: auto retro-hunt rules ignore the scheduler's sliding window
        // and rule.query — they compute their own indicator delta and hunt it
        // over the configured lookback. Dispatch before any query parsing.
        if rule.is_retro_hunt() {
            return self.execute_retro_hunt_rule(rule).await;
        }

        // Don't execute paused rules
        if rule.mode == RuleMode::Paused {
            warn!("Attempted to execute paused rule: {}", rule.id);
            return Err(DetectionError::RulePaused(rule.id));
        }

        // Don't execute staging rules
        if rule.mode == RuleMode::Staging {
            debug!("Skipping execution of staging rule: {}", rule.name);
            return Ok(None);
        }

        // NAN-1805: execution-side feedback-loop guard for dataset=risk rules
        // (belt-and-suspenders — save-time validation already rejects these,
        // but a rule persisted through any other path must not run). A `| risk`
        // body would emit query-derived scores into the findings stream, which
        // is the risk dataset's own input. Refusing loudly every cycle keeps
        // the misconfiguration visible instead of silently neutralized.
        if Self::is_risk_dataset_rule(rule) {
            if let Ok(parsed) = parse_query(&rule.query) {
                if crate::query::contains_risk_command(&parsed) {
                    return Err(DetectionError::InvalidQuery(format!(
                        "rule '{}' targets dataset=risk but its query contains `| risk` — refusing to execute (feedback-loop guard); remove the `| risk` command",
                        rule.name
                    )));
                }
            }
            if rule.risk_score != Some(0) {
                // Scoring is zeroed at risk_result_for_group regardless; warn so
                // the drift from the save-time invariant is visible.
                warn!(
                    rule_id = %rule.id,
                    "Rule '{}' targets dataset=risk with risk_score {:?} — findings will be forced to score 0 (feedback-loop guard)",
                    rule.name,
                    rule.risk_score
                );
            }
        }

        // Determine time range
        let time_range = time_range.unwrap_or_else(|| {
            let end = Utc::now();
            let start = end - Duration::minutes(self.config.default_lookback_minutes);
            TimeRangeInput::new(start, end)
        });

        debug!(
            "Executing rule {} (mode: {:?}) with time range: {} to {}",
            rule.name, rule.mode, time_range.start, time_range.end
        );

        // Run the rule's query against this window. Shared with the historical
        // tester so test ≡ prod by construction. (`time_range` is kept for the
        // NAN-1800 source_type companion in the alerting branch below.)
        let mut results = self
            .evaluate_window(
                &rule.query,
                time_range.clone(),
                rule.dataset.clone(),
                // Scheduled/real-time SYSTEM execution — unrestricted (NAN-2047).
                &crate::auth::ScopeSet::unrestricted(),
            )
            .await?;

        // Audit D19: if a single window hit the 1M safety cap the rule is far too
        // broad — matches beyond 1M are still truncated, but now VISIBLY (a warn)
        // instead of silently at 100.
        if results.len() >= crate::query::ClickHouseSqlGenerator::DEFAULT_RESULT_LIMIT {
            warn!(
                rule_id = %rule.id,
                "Rule {} hit the 1M result cap in a single window — the query is too broad; some matches are truncated",
                rule.name
            );
        }

        // Dedup namespace: Live bake-in and Alerting record/filter separately so
        // a rule promoted Live→Alerting isn't suppressed by bake-in records (D17).
        let matched_kind = super::helpers::MatchedEventKind::for_mode(rule.mode);

        // Filter out events already matched by this rule in this namespace. This
        // is READ-only; the surviving events are RECORDED as matched *after* the
        // alert/finding is durably created (audit D5), in the mode branch below.
        //
        // Audit D29: dedup runs for EVERY scheduled rule, not only those with an
        // explicit `lookback_minutes`. A lookback-NULL rule still overlaps the
        // previous window by the 5s ingestion-lag buffer, so without this its
        // boundary events re-matched every cycle and inflated match_count /
        // detection_matches.
        {
            let original_count = results.len();
            results = self
                .filter_already_matched_events(rule.id, matched_kind, &results)
                .await?;
            let filtered_count = original_count - results.len();
            if filtered_count > 0 {
                debug!(
                    "Filtered out {} already-matched events for rule {} (overlap deduplication)",
                    filtered_count, rule.name
                );
            }
        }

        // Inject _nano_detected_at into all matched events for frontend latency calculation
        let detected_at = Utc::now();
        super::helpers::inject_detected_at(&mut results, detected_at);

        let match_count = results.len() as i64;
        let today = Utc::now().date_naive();

        // Record detection match metrics
        if match_count > 0 {
            let mode_str = format!("{:?}", rule.mode).to_lowercase();
            let severity_str = format!("{:?}", rule.severity).to_lowercase();

            counter!(
                "nanosiem_detection_matches_total",
                "mode" => mode_str,
                "severity" => severity_str.clone()
            )
            .increment(match_count as u64);

            // MTTD: find earliest event timestamp and measure time-to-detect.
            // Audit D23: use the shared event_field_time parser — the old inline
            // `parse_from_str(..., "%Y-%m-%d %H:%M:%S%.f")` targets DateTime<FixedOffset>
            // but the format carries no offset, so it ALWAYS errored (and the
            // RFC-3339 fallback can't parse the offset-less CH format either), so
            // MTTD never recorded for the normal CH timestamp format.
            let detection_time = Utc::now();
            let earliest_ts = results
                .iter()
                .filter_map(|e| Self::event_field_time(e, "timestamp"))
                .min();

            if let Some(earliest) = earliest_ts {
                let mttd = (detection_time - earliest.with_timezone(&Utc)).num_milliseconds()
                    as f64
                    / 1000.0;
                if mttd > 0.0 {
                    histogram!(
                        "nanosiem_detection_mttd_seconds",
                        "severity" => severity_str
                    )
                    .record(mttd);
                }
            }
        }

        // Load global risk weight for risk score calculation (Requirement 9.2)
        let global_weight = self.load_risk_weight().await;

        // Update stats based on mode
        match rule.mode {
            RuleMode::Staging => {
                // Staging rules should never be executed (caught earlier)
                unreachable!("Staging rules should not reach execution")
            }
            RuleMode::Live => {
                // In live mode, update live_match_count (for bake-in tracking)
                self.rule_repo
                    .update_live_match_count(rule.id, match_count)
                    .await?;

                // Record daily stats (no alerts in live mode)
                if match_count > 0 {
                    self.rule_repo
                        .record_daily_stats(rule.id, today, match_count, 0)
                        .await?;

                    // NAN-1808: detection_matches rows are scope-stamped from
                    // their events, so aggregate rows (no per-event
                    // source_type) must be annotated BEFORE the Live write —
                    // exactly like the alerting branch below. Without this, a
                    // Live-mode aggregate rule would store '{}' and its
                    // matched events would be visible to per-source-restricted
                    // viewers. No-op for raw/grouped-raw rules; fails CLOSED
                    // (full restricted set) when the window's source types
                    // can't be resolved. `_nano_source_types` is stripped from
                    // both dedup hashes, so match/matched-event dedup is
                    // unaffected.
                    self.annotate_source_types_for_scoping(rule, &mut results, &time_range)
                        .await;

                    // Store detection match for review
                    // Per-event rules store one match per event for consistent display
                    match rule.alert_mode {
                        AlertMode::PerEvent => {
                            for event in &results {
                                self.store_detection_match(rule, std::slice::from_ref(event))
                                    .await?;
                            }
                        }
                        AlertMode::Grouped => {
                            self.store_detection_match(rule, &results).await?;
                        }
                    }

                    // Log per-entity live findings, deduped per (rule, entity,
                    // window) and stamped with the source event window so
                    // overlapping re-evaluations don't re-emit / re-inflate risk
                    // (NAN-1305).
                    let emitted = self.log_live_findings(rule, &results, global_weight).await;

                    // Record matched events AFTER live processing (audit D5), in
                    // the 'live' namespace (audit D17). A crash before here leaves
                    // them un-recorded so the next run re-evaluates them.
                    // Unconditional (audit D29): the 5s overlap dedups even
                    // lookback-NULL rules.
                    self.record_matched_events(rule.id, matched_kind, &results)
                        .await?;

                    info!(
                        "Rule {} (LIVE mode) matched {} events, emitted {} new findings",
                        rule.name, match_count, emitted
                    );
                }

                // No alert in live mode
                Ok(None)
            }
            RuleMode::Alerting => {
                // In alerting mode, update match_count and generate alerts
                self.rule_repo
                    .update_execution_stats(rule.id, match_count)
                    .await?;

                // Generate alert if there are matches
                if !results.is_empty() {
                    // NAN-1800: aggregate rows carry no per-event source_type;
                    // stamp the window's distinct source types so the alert's
                    // `source_types` scope column is non-empty (else the alert
                    // would be visible to per-source-restricted viewers).
                    self.annotate_source_types_for_scoping(rule, &mut results, &time_range)
                        .await;

                    let alert = match rule.alert_mode {
                        AlertMode::Grouped => {
                            self.handle_grouped_alert(
                                rule,
                                &results,
                                match_count,
                                today,
                                global_weight,
                            )
                            .await?
                        }
                        AlertMode::PerEvent => {
                            self.handle_per_event_alerts(
                                rule,
                                &results,
                                match_count,
                                today,
                                global_weight,
                            )
                            .await?
                        }
                    };

                    // Record matched events only AFTER the alert path succeeds
                    // (audit D5), in the 'alert' namespace (audit D17). An error
                    // before here (propagated by `?`) leaves them un-recorded so
                    // the next run re-evaluates them instead of dropping the
                    // detection forever. Unconditional (audit D29): the 5s overlap
                    // dedups even lookback-NULL rules.
                    self.record_matched_events(rule.id, matched_kind, &results)
                        .await?;

                    Ok(alert)
                } else {
                    debug!("Rule {} had no matches", rule.name);
                    Ok(None)
                }
            }
            RuleMode::Paused => {
                // Paused rules should never reach here (caught earlier in execute_rule)
                warn!("Paused rule {} unexpectedly reached execution", rule.name);
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{dataset_provenance, DatasetProvenance};

    /// NAN-2024: only the logs dataset carries a per-event `source_type`, so the
    /// companion runs there and is skipped everywhere else.
    #[test]
    fn only_logs_dataset_runs_the_source_type_companion() {
        assert_eq!(dataset_provenance(None), DatasetProvenance::SourceDerived); // default => logs
        assert_eq!(
            dataset_provenance(Some("logs")),
            DatasetProvenance::SourceDerived
        );
        assert_eq!(
            dataset_provenance(Some("")),
            DatasetProvenance::SourceDerived
        ); // unknown/empty => logs
        assert_ne!(
            dataset_provenance(Some("risk")),
            DatasetProvenance::SourceDerived
        );
        assert_ne!(
            dataset_provenance(Some("spans")),
            DatasetProvenance::SourceDerived
        );
        assert_ne!(
            dataset_provenance(Some("metrics")),
            DatasetProvenance::SourceDerived
        );
    }

    /// NAN-2227: skipping the companion is not one fact. Spans/metrics have NO
    /// source dimension (their tables have no `source_type` column and per-source
    /// RBAC does not scope them), so their provenance is ABSENT and must stamp an
    /// empty manifest. Risk is aggregated from the findings stream, whose rows DO
    /// have origins this grain cannot recover — genuinely UNKNOWN, so it keeps
    /// failing closed.
    ///
    /// Collapsing these two back together is what made every spans/metrics alert
    /// lose its webhook evidence, and hid those alerts from restricted analysts.
    #[test]
    fn absent_provenance_is_distinguished_from_unknowable_provenance() {
        assert_eq!(
            dataset_provenance(Some("spans")),
            DatasetProvenance::NotSourceDerived
        );
        assert_eq!(
            dataset_provenance(Some("metrics")),
            DatasetProvenance::NotSourceDerived
        );
        assert_eq!(
            dataset_provenance(Some("risk")),
            DatasetProvenance::Unknowable,
            "risk aggregates findings that can carry restricted origins — must fail closed"
        );
    }
}
