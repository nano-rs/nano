// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC retro-hunt engine (NAN-1580).
//!
//! `ioc=<v> | retro [by asset|user]` runs an environment-wide retro-hunt over a
//! single indicator, a list/campaign, or a feed-sourced indicator set. The
//! `/api/search` request returns a lightweight MARKER row ([`build_retro_marker`])
//! so the frontend routes to the retro surface; the heavy rollup is computed by
//! the companion `/api/search/retro` endpoint via [`SearchService::build_retro_view`].
//!
//! ## Observable column → index mapping (NAN-1412 / migrations 119/132)
//!
//! The `ioc` term expands across the UDM observable columns (defined in
//! [`crate::query::clickhouse_sql_gen::search_expr`]):
//! * RAW equality (`col = '<lowered>'`) — `src_ip`, `dest_ip`, `dvc_ip` (ingest-
//!   lowercased, whole-value bloom prunes).
//! * `lower(col) = '<lowered>'` — `file_hash`, `process_hash`, `url`,
//!   `url_domain`, `query`, `user_id`, `sender`, `recipient`, `sender_domain`,
//!   `recipient_domain`, `cve`, `rule_id`, `signature_id` (mixed-case history;
//!   served by `idx_*_lower` expression blooms / text indexes).
//!
//! The retro SQL emits a single WHERE (`timestamp BETWEEN … AND (<ioc match>)`),
//! NO explicit PREWHERE — `optimize_move_to_prewhere` does placement.

use super::*;
use super::lateral::source_scope_sql_predicate;
use crate::auth::ScopeSet;
use crate::query::{IocFeed, IocLookup, RetroAxis, SearchExpr, Value};
use crate::query::clickhouse_sql_gen::search_expr::{
    classify_indicator, ioc_feed_indicator_subquery, resolve_ioc_observables, scope_observables,
    ResolvedObservable,
};
use crate::schema::SchemaProfile;

/// Full-retention floor for retro hunts. The `logs` table carries a 365-day TTL
/// (CLAUDE.md core architecture); the engine clamps the requested window's floor
/// to `now - RETRO_RETENTION_DAYS` so a retro hunt never scans beyond retained
/// history (a >365d request can't widen the window past what ClickHouse retains).
/// Capped (not unbounded) so the scan still prunes partitions.
const RETRO_RETENTION_DAYS: i64 = 365;

/// Window over which the active-host population (the rarity-verdict denominator,
/// `retro_total_hosts`) is measured. Decoupled from the user-selected match
/// window: an unfiltered distinct-host count over a wide match window is a
/// full-table scan that times out on a real tenant (see `retro_total_hosts`).
const RETRO_PREVALENCE_WINDOW_HOURS: i64 = 24;

/// Default page size for list/pivot rollups.
const RETRO_PAGE_SIZE: usize = 50;

/// Hard cap on indicators expanded from a feed/list before aggregation.
const RETRO_MAX_INDICATORS: usize = 1_000;

/// Sample cap on indicator values surfaced per pivot row.
const RETRO_PIVOT_INDICATOR_SAMPLE: usize = 8;

/// Retro submode, derived from the parsed `ioc` term + axis.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetroSubmode {
    /// Single literal indicator → environment-wide summary.
    Summary,
    /// Indicator list or feed-sourced set → rarest-first campaign list.
    List,
    /// `by asset|user` pivot over the matched indicators.
    Pivot,
}

impl RetroSubmode {
    fn as_str(&self) -> &'static str {
        match self {
            RetroSubmode::Summary => "summary",
            RetroSubmode::List => "list",
            RetroSubmode::Pivot => "pivot",
        }
    }
}

/// The parsed retro request recovered from the nPL `ioc … | retro …` query.
#[derive(Debug, Clone)]
pub(crate) struct RetroPlan {
    /// Literal indicator values (empty for a feed/lookup-sourced term).
    pub values: Vec<String>,
    /// Enrichment feed, if the term was `ioc in feed("arg")`.
    pub feed: Option<IocFeed>,
    /// Internal lookup-table source, if the term was `ioc in lookup("name")`
    /// (NAN-1581 Phase 6). Resolved to concrete `values` by the service layer
    /// before the rollup SQL runs.
    pub lookup: Option<IocLookup>,
    /// Pivot axis.
    pub axis: RetroAxis,
    /// Derived submode.
    pub submode: RetroSubmode,
}

impl RetroPlan {
    /// The single indicator value for the summary marker (`None` for list/feed).
    fn single_indicator(&self) -> Option<&str> {
        match (self.submode, self.values.first()) {
            (RetroSubmode::Summary, Some(v)) => Some(v.as_str()),
            _ => None,
        }
    }
}

/// Walk a parsed query and recover the `IocMatch` term + retro axis, deriving the
/// submode. Returns `None` if the query isn't a retro query (no `| retro`, or no
/// `ioc` term feeding it).
pub(crate) fn extract_retro_plan(query: &Query) -> Option<RetroPlan> {
    let axis = retro_axis(query)?;
    let (values, feed, lookup) = find_ioc_match(query)?;
    let literal_values: Vec<String> = values
        .iter()
        .map(|v| match v {
            Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .collect();

    let submode = match axis {
        RetroAxis::Asset | RetroAxis::User => RetroSubmode::Pivot,
        RetroAxis::Indicator => {
            // Feed/lookup-sourced or multi-value ⇒ list; single literal ⇒ summary.
            if feed.is_some() || lookup.is_some() || literal_values.len() > 1 {
                RetroSubmode::List
            } else {
                RetroSubmode::Summary
            }
        }
    };

    Some(RetroPlan {
        values: literal_values,
        feed,
        lookup,
        axis,
        submode,
    })
}

/// Find the terminal `retro` command and return its axis.
fn retro_axis(query: &Query) -> Option<RetroAxis> {
    match query {
        Query::Search(_) => None,
        Query::Piped { command, source } => match command {
            Command::Retro { axis } => Some(*axis),
            _ => retro_axis(source),
        },
    }
}

/// Find the `IocMatch` term anywhere in the query's search tree.
#[allow(clippy::type_complexity)]
fn find_ioc_match(query: &Query) -> Option<(Vec<Value>, Option<IocFeed>, Option<IocLookup>)> {
    fn walk(expr: &SearchExpr) -> Option<(Vec<Value>, Option<IocFeed>, Option<IocLookup>)> {
        match expr {
            SearchExpr::IocMatch { values, feed, lookup } => {
                Some((values.clone(), feed.clone(), lookup.clone()))
            }
            SearchExpr::And(l, r) | SearchExpr::Or(l, r) => walk(l).or_else(|| walk(r)),
            SearchExpr::Not(inner) | SearchExpr::Group(inner) => walk(inner),
            _ => None,
        }
    }
    match query {
        Query::Search(expr) => walk(expr),
        Query::Piped { source, .. } => find_ioc_match(source),
    }
}

/// Build the lightweight `/api/search` retro marker row (NAN-1580). Carries the
/// parsed retro request so the frontend knows what to fetch from the companion
/// endpoint — NO ClickHouse scan happens for this.
pub(crate) fn build_retro_marker(plan: &RetroPlan) -> serde_json::Value {
    serde_json::json!({
        "_display_type": "retro",
        "_retro_submode": plan.submode.as_str(),
        "_retro_axis": plan.axis.as_str(),
        "_retro_indicator": plan.single_indicator(),
        "_retro_feed": plan.feed.as_ref().map(|f| f.name.clone()),
        "_retro_feed_arg": plan.feed.as_ref().map(|f| f.arg.clone()),
        // NAN-1581 Phase 6: lookup-sourced retro term.
        "_retro_lookup": plan.lookup.as_ref().map(|l| l.table.clone()),
    })
}


/// The canonical host expression used to count distinct hosts touched and to
/// pivot by asset. First non-empty of the host/ip identity columns, RESOLVED to
/// the active profile's physical columns (NAN-1580 OCSF-awareness): UDM →
/// `src_host`/`dest_host`/`dvc`/`src_ip`/`dest_ip`; OCSF → the promoted
/// `src_host_unified`/`dst_endpoint.hostname`/\"src_endpoint.ip\"/… columns.
/// Identity columns the profile has no mapping for are skipped. The `lower()`
/// wrappers stay on the host-name legs (mixed-case history) and are dropped on
/// the ingest-lowercased ip legs to match each column's index form.
fn host_expr(profile: &dyn SchemaProfile) -> String {
    // Named hosts ONLY (NAN-1592). This is the host identity for the rarity
    // denominator (`retro_total_hosts`) and the matched `distinct_hosts`. We
    // deliberately DON'T fall back to raw `src_ip`/`dest_ip`: a remote endpoint
    // is not one of your assets, and that fallback counted every external
    // internet IP as a "host" — on Saturn it inflated the denominator ~280x
    // (1.78M, 99.8% public IPs, vs ~4.3K real hostnames). An RFC1918 filter was
    // rejected because cloud assets run on PUBLIC IPs (Saturn's hosts are
    // 104.130.x), so private-only would wrongly drop them. Host names are
    // mixed-case → each leg is lowered. No-hostname events yield '' and are
    // excluded from the host counts at the call sites.
    let legs: &[(&str, bool)] = &[("src_host", true), ("dest_host", true), ("dvc", true)];
    coalesce_identity_expr(profile, legs)
}

/// The canonical user expression for the user pivot, RESOLVED per the active
/// profile (NAN-1580): UDM → `user`/`user_id`/`src_user`; OCSF → `user_unified`/…
fn user_pivot_expr(profile: &dyn SchemaProfile) -> String {
    let legs: &[(&str, bool)] = &[("user", true), ("user_id", true), ("src_user", true)];
    coalesce_identity_expr(profile, legs)
}

/// Build a `coalesce(nullIf(<expr>, ''), …)` identity expression over the
/// profile-resolved physical columns for `legs`, skipping logical fields the
/// active schema has no column for. `wrap_lower` legs are wrapped in `lower()`
/// (mixed-case host/user names); the others compare raw (ingest-lowercased ips).
/// Under UDM every leg resolves to its own column and the emission is
/// byte-identical to the historical hardcoded expression. When NOTHING resolves
/// (degenerate profile) the result is `NULL` — the surrounding `id != ''` filters
/// and `uniqExact` treat it as no-host, exactly like an empty environment.
fn coalesce_identity_expr(profile: &dyn SchemaProfile, legs: &[(&str, bool)]) -> String {
    let parts: Vec<String> = legs
        .iter()
        .filter_map(|(logical, wrap_lower)| {
            profile.udm_column_sql(logical).map(|col| {
                if *wrap_lower {
                    format!("nullIf(lower({col}), '')")
                } else {
                    format!("nullIf({col}, '')")
                }
            })
        })
        .collect();
    // Terminate with a non-nullable '' so the entity expression is `String`,
    // not `Nullable(String)`: CH `coalesce` of all-nullable `nullIf(...)` legs
    // is Nullable, which the row structs (RetroPivotRowRaw.id / RetroTopEntity.id)
    // can't deserialize as `String` (fails at runtime, not in golden tests).
    // Empty identity is still filtered downstream by `entity != ''`.
    if parts.is_empty() {
        "''".to_string()
    } else {
        format!("coalesce({}, '')", parts.join(", "))
    }
}

impl SearchService {
    /// Resolve the literal indicator set for a retro plan, pulling feed-sourced
    /// indicators from `custom_enrichment_results` when the term is a feed. The
    /// returned list is lowercased + de-duplicated + capped.
    async fn resolve_retro_indicators(
        &self,
        plan: &RetroPlan,
    ) -> Result<Vec<String>, SearchError> {
        if !plan.values.is_empty() {
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();
            for v in &plan.values {
                let lv = v.to_lowercase();
                if seen.insert(lv.clone()) {
                    out.push(lv);
                }
                if out.len() >= RETRO_MAX_INDICATORS {
                    break;
                }
            }
            return Ok(out);
        }

        // Lookup-sourced (NAN-1581 Phase 6): pull indicator values from the named
        // internal lookup table via LookupService (backend-agnostic), lowercase +
        // dedup + cap. Mutually exclusive with `feed`.
        if let Some(lookup) = &plan.lookup {
            let resolved = super::ioc_lookup_resolve::resolve_ioc_lookup(
                lookup,
                self.lookup_service.as_ref(),
            )
            .await?;
            let mut seen = std::collections::HashSet::new();
            let mut out = Vec::new();
            for v in resolved {
                let lv = v.to_lowercase();
                if !lv.is_empty() && seen.insert(lv.clone()) {
                    out.push(lv);
                }
                if out.len() >= RETRO_MAX_INDICATORS {
                    break;
                }
            }
            return Ok(out);
        }

        // Feed-sourced: pull the indicator set from custom_enrichment_results.
        let feed = match &plan.feed {
            Some(f) => f,
            None => return Ok(Vec::new()),
        };
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };

        let sql = format!(
            "{} LIMIT {}",
            // Route the IOC feed subquery's source through the `_distributed`
            // wrapper on clusters (completeness across shards); single-node emits
            // the local name unchanged.
            ioc_feed_indicator_subquery(feed, self.table_names.is_clustered()),
            RETRO_MAX_INDICATORS
        );
        match clickhouse.query(&sql).fetch_all::<String>().await {
            Ok(rows) => {
                let mut seen = std::collections::HashSet::new();
                Ok(rows
                    .into_iter()
                    .filter(|v| !v.is_empty() && seen.insert(v.clone()))
                    .collect())
            }
            Err(e) => {
                tracing::warn!("Retro feed indicator resolution failed: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Active-host population — the rarity-verdict denominator.
    ///
    /// Measured with APPROXIMATE `uniq()` (fixed-memory HyperLogLog) over a
    /// bounded recent window (`RETRO_PREVALENCE_WINDOW_HOURS`), NOT the retro
    /// match range. The match range is user-controlled and can be wide; an
    /// unfiltered exact distinct-host count over a wide window is a full-table
    /// scan that OOMs/times out on a real tenant (`uniqExact` over retention hit
    /// the 300s ceiling on Saturn — 1.7B rows × a 5-column `lower()` host coalesce).
    /// A coarse rarity band only needs an approximate, recent "how big is the
    /// environment" figure, so a small fixed window keeps this cheap (~sub-4s).
    /// A numerator host outside this window can push the ratio >1 → `Common`,
    /// which [`RetroVerdict::from_ratio`] handles as a safe non-rare result.
    ///
    /// NAN-1801: the denominator is scoped too (`scope_predicate` is ANDed into
    /// the WHERE) so a scoped viewer's rarity ratio is measured against the
    /// population they can see — hosts that only appear in denied sources must
    /// not leak into the count. `None` (unrestricted) emits byte-identical SQL.
    async fn retro_total_hosts(&self, scope_predicate: Option<&str>) -> u64 {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return 0,
        };
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let now = chrono::Utc::now();
        let start = now - chrono::Duration::hours(RETRO_PREVALENCE_WINDOW_HOURS);
        let sql = format!(
            "SELECT uniq(nullIf({host}, '')) FROM {table} \
             WHERE timestamp BETWEEN '{start}' AND '{end}'{scope_and}",
            host = host_expr(self.active_profile.as_ref()),
            table = logs_table,
            start = crate::sql_hygiene::format_ch_bound(&start),
            end = crate::sql_hygiene::format_ch_bound(&now),
            scope_and = scope_and(scope_predicate),
        );
        clickhouse
            .query(&sql)
            .fetch_one::<u64>()
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("Retro total-hosts query failed: {}", e);
                0
            })
    }

    /// Clamp the requested window's floor to the retention floor so a retro hunt
    /// never scans beyond retained history (a >365d request would otherwise widen
    /// the window past what ClickHouse retains). The retention floor is the lower
    /// bound: requests older than retention are capped at the floor.
    fn retro_time_range(requested: &TimeRange) -> TimeRange {
        let floor = chrono::Utc::now() - chrono::Duration::days(RETRO_RETENTION_DAYS);
        let start = requested.start.max(floor);
        TimeRange::new(start, requested.end)
    }

    /// The active profile's resolved observable list (NAN-1580 OCSF-awareness).
    /// UDM → the UDM observable columns (identity resolution); OCSF → the promoted
    /// OCSF columns, with unmappable observables skipped.
    fn retro_observables(&self) -> Vec<ResolvedObservable> {
        resolve_ioc_observables(self.active_profile.as_ref())
    }

    /// Build the IOC observable match predicate for a concrete indicator set,
    /// reusing the sql-gen observable → physical-column resolution. Each indicator
    /// is matched RAW on the ingest-lowercased columns and via `lower(col)` on the
    /// mixed-case columns, resolved per the active schema profile (NAN-1580).
    fn retro_match_predicate(observables: &[ResolvedObservable], indicators: &[String]) -> String {
        if indicators.is_empty() || observables.is_empty() {
            return "0".to_string();
        }
        let mut clauses = Vec::new();
        for ind in indicators {
            let escaped = escape_sql_string(&ind.to_lowercase());
            for obs in observables {
                if obs.raw {
                    clauses.push(format!("{} = '{escaped}'", obs.col_sql));
                } else {
                    clauses.push(format!("lower({}) = '{escaped}'", obs.col_sql));
                }
            }
        }
        format!("({})", clauses.join(" OR "))
    }

    /// The full IOC retro-hunt rollup (companion `/api/search/retro`).
    ///
    /// Re-parses `req.query`, resolves the indicator set (feed pull included),
    /// generates + executes the submode rollup SQL, computes verdict bands
    /// against the environment host count, and paginates server-side.
    ///
    /// NAN-1801: the retro rollup is hand-built SQL over the logs table that
    /// bypasses the nPL search path (the P1 injector never sees it), so the
    /// caller's effective `ScopeSet` is threaded down here and its deny-set
    /// predicate is ANDed into EVERY logs scan — the host denominator, the
    /// summary/top-entities union legs, and the list/pivot rollups. An empty
    /// deny set renders `None` and every SQL string stays byte-identical to
    /// the pre-scoping form.
    pub async fn build_retro_view(
        &self,
        req: RetroRequest,
        scope: &ScopeSet,
    ) -> Result<RetroResponse, SearchError> {
        req.time_range.validate()?;

        let (cleaned_query, _earliest, _latest) = super::extract_time_modifiers(&req.query);
        let query = parse_query(&cleaned_query).map_err(super::convert_parse_error)?;

        let mut plan = extract_retro_plan(&query).ok_or_else(|| {
            SearchError::SqlValidationError(
                "Not a retro query — expected `ioc=… | retro [by asset|user]`.".to_string(),
            )
        })?;

        // The request axis overrides the parsed axis when explicitly provided
        // (the frontend can flip indicator ↔ pivot without rewriting the query).
        if let Some(req_axis) = RetroAxis::from_str(&req.axis) {
            plan.axis = req_axis;
            plan.submode = match req_axis {
                RetroAxis::Asset | RetroAxis::User => RetroSubmode::Pivot,
                RetroAxis::Indicator => {
                    // A feed/lookup source (or >1 literal) is a campaign list, not
                    // a single-indicator summary. Must mirror extract_retro_plan —
                    // omitting `lookup` here downgrades `ioc in lookup() | retro`
                    // to summary and resolves nothing.
                    if plan.feed.is_some() || plan.lookup.is_some() || plan.values.len() > 1 {
                        RetroSubmode::List
                    } else {
                        RetroSubmode::Summary
                    }
                }
            };
        }

        let range = Self::retro_time_range(&TimeRange::new(
            req.time_range.start,
            req.time_range.end,
        ));
        let indicators = self.resolve_retro_indicators(&plan).await?;

        // NAN-1801: render the deny-set ONCE; every logs scan below ANDs it.
        // The indicator-set resolution above is deliberately NOT scoped — it
        // reads `custom_enrichment_results` / lookup tables (threat intel, not
        // log events), which carry no `source_type`.
        let scope_predicate = source_scope_sql_predicate("source_type", scope.deny_set());
        let scope_predicate = scope_predicate.as_deref();

        let total_hosts = self.retro_total_hosts(scope_predicate).await;

        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(RETRO_PAGE_SIZE).clamp(1, 500);

        match plan.submode {
            RetroSubmode::Summary => {
                self.retro_summary(&plan, &indicators, &range, total_hosts, scope_predicate)
                    .await
            }
            RetroSubmode::List => {
                self.retro_list(
                    &plan,
                    &indicators,
                    &range,
                    total_hosts,
                    offset,
                    limit,
                    scope_predicate,
                )
                .await
            }
            RetroSubmode::Pivot => {
                self.retro_pivot(
                    &plan,
                    &indicators,
                    &range,
                    total_hosts,
                    offset,
                    limit,
                    scope_predicate,
                )
                .await
            }
        }
    }

    /// Summary submode: a single indicator's environment-wide footprint.
    async fn retro_summary(
        &self,
        plan: &RetroPlan,
        indicators: &[String],
        range: &TimeRange,
        total_hosts: u64,
        scope_predicate: Option<&str>,
    ) -> Result<RetroResponse, SearchError> {
        let value = plan
            .values
            .first()
            .cloned()
            .or_else(|| indicators.first().cloned())
            .unwrap_or_default();
        let observables = scope_observables(&self.retro_observables(), indicators);
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));

        let sql = build_summary_sql(
            self.active_profile.as_ref(),
            &observables,
            &logs_table,
            &value,
            range,
            scope_predicate,
        );

        // Aggregate row: hits, distinct_hosts, first_seen, last_seen, field_counts.
        let (hits, distinct_hosts, first_seen, last_seen, matched_fields) =
            self.retro_summary_agg(&sql).await?;

        let top_entities = self
            .retro_top_entities(&observables, &value, range, scope_predicate)
            .await
            .unwrap_or_default();

        let (source, campaign, confidence) =
            self.retro_indicator_intel(&value).await.unwrap_or_default();

        let verdict = if total_hosts == 0 {
            RetroVerdict::Rare
        } else {
            RetroVerdict::from_ratio(distinct_hosts as f64 / total_hosts as f64)
        };

        let indicator = RetroIndicatorSummary {
            value: value.clone(),
            indicator_type: classify_indicator(&value).to_string(),
            source,
            campaign,
            confidence,
            hits,
            first_seen,
            last_seen,
            matched_fields,
            distinct_hosts,
            total_hosts,
            verdict: verdict.as_str().to_string(),
            top_entities,
        };

        Ok(RetroResponse {
            submode: RetroSubmode::Summary.as_str().to_string(),
            axis: plan.axis.as_str().to_string(),
            total_hosts,
            generated_sql: Some(sql),
            indicator: Some(indicator),
            total_indicators: None,
            rows: None,
            no_hits: None,
            pivot_rows: None,
            offset: None,
            limit: None,
            has_more: None,
        })
    }

    /// Execute the summary aggregate, returning hits/hosts/seen + per-field counts.
    async fn retro_summary_agg(
        &self,
        sql: &str,
    ) -> Result<(u64, u64, Option<String>, Option<String>, Vec<(String, u64)>), SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok((0, 0, None, None, Vec::new())),
        };
        let rows = clickhouse
            .query(sql)
            .fetch_all::<RetroSummaryRow>()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;
        let row = match rows.into_iter().next() {
            Some(r) => r,
            None => return Ok((0, 0, None, None, Vec::new())),
        };
        // Keep only columns the indicator actually matched, preserving order.
        let matched_fields: Vec<(String, u64)> = row
            .field_counts
            .into_iter()
            .filter(|(_, c)| *c > 0)
            .collect();
        Ok((
            row.hits,
            row.distinct_hosts,
            normalize_ts(row.first_seen),
            normalize_ts(row.last_seen),
            matched_fields,
        ))
    }

    /// Top entities (hosts) for an indicator, by hit count. Uses the same
    /// per-column UNION ALL as the summary (NAN-1589) so each leg is
    /// index-pruned, then groups by host. `uniqExact(_rid)` gives exact per-host
    /// hit counts (a row matching the indicator in two columns counts once).
    async fn retro_top_entities(
        &self,
        observables: &[ResolvedObservable],
        value: &str,
        range: &TimeRange,
        scope_predicate: Option<&str>,
    ) -> Result<Vec<RetroTopEntity>, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let host = host_expr(self.active_profile.as_ref());
        let union = union_match_legs(observables, &logs_table, value, range, &host, scope_predicate);
        let sql = format!(
            "SELECT _host AS id, uniqExact(_rid) AS hits FROM ({union}) \
             WHERE _host != '' GROUP BY _host ORDER BY hits DESC LIMIT 10",
        );
        match clickhouse.query(&sql).fetch_all::<(String, u64)>().await {
            Ok(rows) => Ok(rows
                .into_iter()
                .filter(|(id, _)| !id.is_empty())
                .map(|(id, hits)| RetroTopEntity {
                    id,
                    hits,
                    kind: "asset".to_string(),
                })
                .collect()),
            Err(e) => {
                tracing::warn!("Retro top-entities query failed: {}", e);
                Ok(Vec::new())
            }
        }
    }

    /// Resolve threat-intel metadata (source feed, campaign tag, confidence) for
    /// a single indicator from `custom_enrichment_results`. Best-effort.
    async fn retro_indicator_intel(
        &self,
        value: &str,
    ) -> Result<(String, Option<String>, u32), SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(("query".to_string(), None, 0)),
        };
        let escaped = escape_sql_string(&value.to_lowercase());
        // Reads via the `_distributed` wrapper on clusters (custom_enrichment_results
        // is in DISTRIBUTED_TABLES — per-shard table + additive wrapper) so the
        // intel lookup sees all shards; `.read()` returns the local name on
        // single-node → byte-identical. `ORDER BY confidence DESC LIMIT 1` already
        // picks a single best row across shards (best-effort metadata).
        let intel_table = self.table_names.read("custom_enrichment_results");
        let sql = format!(
            "SELECT enrichment_name, arrayStringConcat(tags, ','), toUInt32(confidence) \
             FROM {intel_table} \
             WHERE is_ioc = 1 AND lower(key_value) = '{escaped}' \
             ORDER BY confidence DESC LIMIT 1"
        );
        match clickhouse
            .query(&sql)
            .fetch_optional::<(String, String, u32)>()
            .await
        {
            Ok(Some((name, tags, confidence))) => {
                let campaign = tags
                    .split(',')
                    .map(str::trim)
                    .find(|t| !t.is_empty())
                    .map(str::to_string);
                Ok((name, campaign, confidence))
            }
            // No intel row — a user-typed literal indicator.
            Ok(None) => Ok(("query".to_string(), None, 0)),
            Err(e) => {
                tracing::warn!("Retro indicator intel lookup failed: {}", e);
                Ok(("query".to_string(), None, 0))
            }
        }
    }

    /// List submode: rarest-first per-indicator rollup (campaign / multi-value).
    async fn retro_list(
        &self,
        plan: &RetroPlan,
        indicators: &[String],
        range: &TimeRange,
        total_hosts: u64,
        offset: usize,
        limit: usize,
        scope_predicate: Option<&str>,
    ) -> Result<RetroResponse, SearchError> {
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));

        let observables = scope_observables(&self.retro_observables(), indicators);
        let predicate = Self::retro_match_predicate(&observables, indicators);
        // The campaign rollup GROUPs by indicator value, so the FULL result is
        // bounded by indicators.len() (<= RETRO_MAX_INDICATORS) — small. Fetch
        // the complete grouped list ONCE unpaged so hit_values + no_hits reflect
        // the whole campaign (not just this page), then page in memory.
        // retro_pivot stays server-side paged (its result set is unbounded).
        let full_limit = indicators.len().max(1);
        let sql = build_list_sql(
            self.active_profile.as_ref(),
            &observables,
            &logs_table,
            &predicate,
            indicators,
            range,
            0,
            full_limit,
            scope_predicate,
        );

        let clickhouse = self
            .ch_client
            .as_ref()
            .ok_or_else(|| SearchError::SqlValidationError("ClickHouse unavailable".to_string()))?;
        let all = clickhouse
            .query(&sql)
            .fetch_all::<RetroListRowRaw>()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        // no_hits computed against the COMPLETE result set.
        let hit_values: std::collections::HashSet<String> =
            all.iter().map(|r| r.value.to_lowercase()).collect();
        let no_hits: Vec<String> = indicators
            .iter()
            .filter(|v| !hit_values.contains(&v.to_lowercase()))
            .cloned()
            .collect();

        // Page in memory.
        let has_more = all.len() > offset + limit;
        let rows: Vec<RetroListRow> = all
            .into_iter()
            .skip(offset)
            .take(limit)
            .map(|r| {
                let verdict = if total_hosts == 0 {
                    RetroVerdict::Rare
                } else {
                    RetroVerdict::from_ratio(r.hosts as f64 / total_hosts as f64)
                };
                RetroListRow {
                    indicator_type: classify_indicator(&r.value).to_string(),
                    value: r.value,
                    hits: r.hits,
                    hosts: r.hosts,
                    total_hosts,
                    first_seen: normalize_ts(r.first_seen),
                    last_seen: normalize_ts(r.last_seen),
                    field: r.field,
                    verdict: verdict.as_str().to_string(),
                }
            })
            .collect();

        Ok(RetroResponse {
            submode: RetroSubmode::List.as_str().to_string(),
            axis: plan.axis.as_str().to_string(),
            total_hosts,
            generated_sql: Some(sql),
            indicator: None,
            total_indicators: Some(indicators.len() as u64),
            rows: Some(rows),
            no_hits: Some(no_hits),
            pivot_rows: None,
            offset: Some(offset),
            limit: Some(limit),
            has_more: Some(has_more),
        })
    }

    /// Pivot submode: entities (asset|user) touched by the matched indicators.
    async fn retro_pivot(
        &self,
        plan: &RetroPlan,
        indicators: &[String],
        range: &TimeRange,
        total_hosts: u64,
        offset: usize,
        limit: usize,
        scope_predicate: Option<&str>,
    ) -> Result<RetroResponse, SearchError> {
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let observables = scope_observables(&self.retro_observables(), indicators);
        let predicate = Self::retro_match_predicate(&observables, indicators);

        let sql = build_pivot_sql(
            self.active_profile.as_ref(),
            &observables,
            &logs_table,
            plan.axis,
            &predicate,
            indicators,
            range,
            offset,
            limit + 1,
            scope_predicate,
        );

        let clickhouse = self
            .ch_client
            .as_ref()
            .ok_or_else(|| SearchError::SqlValidationError("ClickHouse unavailable".to_string()))?;
        let mut fetched = clickhouse
            .query(&sql)
            .fetch_all::<RetroPivotRowRaw>()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        let has_more = fetched.len() > limit;
        if has_more {
            fetched.truncate(limit);
        }

        let pivot_rows: Vec<RetroPivotRow> = fetched
            .into_iter()
            .map(|r| {
                let worst = if total_hosts == 0 {
                    RetroVerdict::Rare
                } else {
                    RetroVerdict::from_ratio(r.hosts as f64 / total_hosts as f64)
                };
                let mut inds = r.inds;
                inds.retain(|s| !s.is_empty());
                let iocs = inds.len() as u64;
                inds.truncate(RETRO_PIVOT_INDICATOR_SAMPLE);
                // USER axis resolves a real display name + department from
                // user_registry_dict in SQL; fall back to the raw id / None when
                // the dict has no row (or for the ASSET axis, which emits empty).
                let name = if r.ident_name.is_empty() {
                    r.id.clone()
                } else {
                    r.ident_name.clone()
                };
                let sub = if r.ident_dept.is_empty() {
                    None
                } else {
                    Some(r.ident_dept.clone())
                };
                RetroPivotRow {
                    id: r.id,
                    name,
                    sub,
                    iocs,
                    indicators: inds,
                    first_seen: normalize_ts(r.first_seen),
                    last_seen: normalize_ts(r.last_seen),
                    worst_verdict: worst.as_str().to_string(),
                }
            })
            .collect();

        Ok(RetroResponse {
            submode: RetroSubmode::Pivot.as_str().to_string(),
            axis: plan.axis.as_str().to_string(),
            total_hosts,
            generated_sql: Some(sql),
            indicator: None,
            total_indicators: None,
            rows: None,
            no_hits: None,
            pivot_rows: Some(pivot_rows),
            offset: Some(offset),
            limit: Some(limit),
            has_more: Some(has_more),
        })
    }

}

// =============================================================================
// Auto retro-hunt support (NAN-1791)
// =============================================================================
//
// A retro-hunt DETECTION rule pulls the delta of newly-landed feed indicators
// and hunts them over historical logs, emitting hits through the standard signal
// processor. These two methods are the ClickHouse half:
//   * `retro_hunt_feed_candidates` — the delta candidate set above a watermark.
//   * `retro_hunt_over_indicators` — the batched list-rollup hunt (ONE query for
//     the whole indicator set), reusing the same index-pruning machinery as the
//     interactive `| retro` list submode.

/// Row shape for the feed-candidate scan.
#[derive(clickhouse::Row, serde::Deserialize)]
struct RetroFeedCandidateRow {
    value: String,
    key_type: String,
    enrichment_name: String,
    confidence: u32,
    fetched_at_ms: i64,
}

impl SearchService {
    /// Build the SQL for the delta candidate scan over `custom_enrichment_results`
    /// (split out for unit testing).
    ///
    /// Live IOC rows only (`is_ioc = 1 AND expires_at > now()`), STRICTLY after
    /// the keyset cursor, optionally narrowed to selected feeds and artifact
    /// types. Grouped by lowercased value so a ReplacingMergeTree's duplicate
    /// versions collapse to one candidate carrying its newest `fetched_at`.
    ///
    /// ## Why the cursor is a keyset, not a bare timestamp
    ///
    /// A feed sync bulk-stamps thousands of indicators with the SAME
    /// `fetched_at`. With a timestamp-only cursor, a tie group larger than the
    /// per-run cap can never be drained: advancing past the timestamp skips the
    /// group's unprocessed tail, and NOT advancing means the capped, ordered
    /// query keeps returning the same already-hunted rows every run — so the tail
    /// is never hunted. Ordering by `(fetched_at, value)` and cursoring on the
    /// pair makes the cursor strictly monotonic, guaranteeing forward progress.
    ///
    /// The cursor predicate is applied at ROW level (both `fetched_at` and
    /// `lower(key_value)` are row expressions, not aggregates), which is sound
    /// under the `GROUP BY value`: a group's true newest row always satisfies the
    /// predicate whenever the group belongs above the cursor, so `max(fetched_at)`
    /// over the surviving rows equals the group's true `fetched_at`.
    fn retro_hunt_candidates_sql(
        table: &str,
        feeds: &[String],
        artifact_types: &[String],
        cursor: Option<(i64, &str)>,
        limit: usize,
    ) -> String {
        let mut filters = String::from("is_ioc = 1 AND expires_at > now()");
        if let Some((ms, value)) = cursor {
            // fromUnixTimestamp64Milli reconstructs the DateTime64(3) bound so the
            // comparison stays in the column's own type (no coercion surprises).
            let v = escape_sql_string(&value.to_lowercase());
            filters.push_str(&format!(
                " AND (fetched_at > fromUnixTimestamp64Milli({ms}) \
                 OR (fetched_at = fromUnixTimestamp64Milli({ms}) AND lower(key_value) > '{v}'))"
            ));
        }
        if !feeds.is_empty() {
            let list = feeds
                .iter()
                .map(|f| format!("'{}'", escape_sql_string(&f.to_lowercase())))
                .collect::<Vec<_>>()
                .join(", ");
            filters.push_str(&format!(" AND lower(enrichment_name) IN ({list})"));
        }
        if !artifact_types.is_empty() {
            let list = artifact_types
                .iter()
                .map(|t| format!("'{}'", escape_sql_string(&t.to_lowercase())))
                .collect::<Vec<_>>()
                .join(", ");
            filters.push_str(&format!(" AND key_type IN ({list})"));
        }
        format!(
            "SELECT lower(key_value) AS value, \
             any(key_type) AS key_type, \
             any(enrichment_name) AS enrichment_name, \
             toUInt32(max(confidence)) AS confidence, \
             toInt64(toUnixTimestamp64Milli(max(fetched_at))) AS fetched_at_ms \
             FROM {table} \
             WHERE {filters} \
             GROUP BY value \
             HAVING value != '' \
             ORDER BY fetched_at_ms ASC, value ASC \
             LIMIT {limit}"
        )
    }

    /// Pull the delta candidate set for a retro-hunt run (NAN-1791).
    ///
    /// Returns up to `limit` distinct candidate indicators strictly after the
    /// keyset `cursor`, ordered by `(fetched_at, value)`. The caller applies the
    /// per-rule hunted-set anti-join + per-run cap and advances the cursor.
    pub async fn retro_hunt_feed_candidates(
        &self,
        feeds: &[String],
        artifact_types: &[String],
        cursor: Option<(i64, &str)>,
        limit: usize,
    ) -> Result<Vec<RetroFeedCandidate>, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };
        // Reads via the `_distributed` wrapper on clusters (completeness across
        // shards); single-node emits the local name unchanged.
        let table = self.table_names.read("custom_enrichment_results");
        let sql = Self::retro_hunt_candidates_sql(&table, feeds, artifact_types, cursor, limit);
        let rows = clickhouse
            .query(&sql)
            .fetch_all::<RetroFeedCandidateRow>()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| RetroFeedCandidate {
                value: r.value,
                key_type: r.key_type,
                enrichment_name: r.enrichment_name,
                confidence: r.confidence,
                fetched_at_ms: r.fetched_at_ms,
            })
            .collect())
    }

    /// Count distinct candidate indicators still remaining after `cursor` — the
    /// honest overflow figure when a run truncates. Because the cursor is strict,
    /// this counts exactly the not-yet-covered candidates. Bounded by the feed
    /// table (which carries a short TTL), so it stays cheap.
    pub async fn retro_hunt_candidate_count(
        &self,
        feeds: &[String],
        artifact_types: &[String],
        cursor: Option<(i64, &str)>,
    ) -> Result<u64, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(0),
        };
        let table = self.table_names.read("custom_enrichment_results");
        // Reuse the candidate SQL as a subquery and count its rows (an unbounded
        // LIMIT via a large ceiling; the feed table is small).
        let inner =
            Self::retro_hunt_candidates_sql(&table, feeds, artifact_types, cursor, 1_000_000);
        let sql = format!("SELECT toUInt64(count()) FROM ({inner})");
        clickhouse
            .query(&sql)
            .fetch_one::<u64>()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))
    }

    /// Batched retro hunt over an explicit indicator set (NAN-1791).
    ///
    /// Reuses the list-submode rollup SQL: ONE index-pruned query over the
    /// lookback window that groups by indicator and returns per-indicator hits /
    /// hosts / first-seen / last-seen, with a rarity verdict. Only indicators
    /// that were actually found in logs (`hits > 0`) come back — those are the
    /// retro HITS the engine emits as signals.
    pub async fn retro_hunt_over_indicators(
        &self,
        indicators: &[String],
        lookback_days: i64,
    ) -> Result<Vec<RetroHuntHit>, SearchError> {
        if indicators.is_empty() {
            return Ok(Vec::new());
        }
        let end = chrono::Utc::now();
        let start = end - chrono::Duration::days(lookback_days.clamp(1, RETRO_RETENTION_DAYS));
        let range = Self::retro_time_range(&TimeRange::new(start, end));

        let observables = scope_observables(&self.retro_observables(), indicators);
        let predicate = Self::retro_match_predicate(&observables, indicators);
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));

        // Full grouped result (bounded by indicators.len() <= cap): unpaged.
        // NAN-1801: deliberately UNSCOPED (`None`). This is the detection-run
        // system path — the rule executes as the engine, not as a per-user
        // viewer, so per-source RBAC does not apply here (mirrors scheduled
        // detection execution; scoping applies at the read surfaces instead).
        let full_limit = indicators.len().max(1);
        let sql = build_list_sql(
            self.active_profile.as_ref(),
            &observables,
            &logs_table,
            &predicate,
            indicators,
            &range,
            0,
            full_limit,
            None,
        );

        let clickhouse = self
            .ch_client
            .as_ref()
            .ok_or_else(|| SearchError::SqlValidationError("ClickHouse unavailable".to_string()))?;
        let rows = clickhouse
            .query(&sql)
            .fetch_all::<RetroListRowRaw>()
            .await
            .map_err(|e| parse_clickhouse_error(&e.to_string()))?;

        // Unscoped denominator too (system path — see the build_list_sql note).
        let total_hosts = self.retro_total_hosts(None).await;

        Ok(rows
            .into_iter()
            .map(|r| {
                let verdict = if total_hosts == 0 {
                    RetroVerdict::Rare
                } else {
                    RetroVerdict::from_ratio(r.hosts as f64 / total_hosts as f64)
                };
                RetroHuntHit {
                    indicator_type: classify_indicator(&r.value).to_string(),
                    value: r.value,
                    field: r.field,
                    hits: r.hits,
                    hosts: r.hosts,
                    total_hosts,
                    first_seen: normalize_ts(r.first_seen),
                    last_seen: normalize_ts(r.last_seen),
                    verdict: verdict.as_str().to_string(),
                }
            })
            .collect())
    }

    /// List the distinct live IOC feed names (`enrichment_name`) available to a
    /// retro-hunt rule's feed picker (NAN-1791). Best-effort: an empty list on
    /// error or no ClickHouse.
    pub async fn list_ioc_feed_names(&self) -> Result<Vec<String>, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };
        let table = self.table_names.read("custom_enrichment_results");
        let sql = format!(
            "SELECT DISTINCT enrichment_name FROM {table} \
             WHERE is_ioc = 1 AND expires_at > now() AND enrichment_name != '' \
             ORDER BY enrichment_name ASC LIMIT 500"
        );
        match clickhouse.query(&sql).fetch_all::<String>().await {
            Ok(rows) => Ok(rows),
            Err(e) => {
                tracing::warn!("Retro-hunt feed list query failed: {}", e);
                Ok(Vec::new())
            }
        }
    }
}

/// Format a time-range bound for a ClickHouse `timestamp BETWEEN` clause.
fn ts(t: &chrono::DateTime<chrono::Utc>) -> String {
    crate::sql_hygiene::format_ch_bound(t)
}

/// Render a pre-built source-scope predicate as an ` AND <pred>` suffix for a
/// WHERE clause, or the empty string when the caller is unrestricted (NAN-1801).
/// The empty-string form keeps unrestricted SQL byte-identical to pre-scoping.
fn scope_and(scope_predicate: Option<&str>) -> String {
    scope_predicate
        .map(|p| format!(" AND {p}"))
        .unwrap_or_default()
}

/// Per-observable comparison expression (RAW vs `lower()`) over the
/// PROFILE-RESOLVED physical columns, used to attribute a row's hit back to the
/// indicator value it carried (NAN-1580). One entry per resolved observable, in
/// the same order as `observables`.
fn observable_value_exprs(observables: &[ResolvedObservable]) -> Vec<String> {
    observables
        .iter()
        .map(|obs| {
            if obs.raw {
                obs.col_sql.clone()
            } else {
                format!("lower({})", obs.col_sql)
            }
        })
        .collect()
}

/// Summary submode SQL: environment footprint for one indicator.
///
/// PER-COLUMN UNION ALL, not a single OR. ClickHouse does NOT combine *different
/// columns'* skip indexes across an `OR` — `src_ip='v' OR dest_ip='v' OR ...`
/// degrades to a near-full scan (measured 8.7s @7d / 20.8s @30d on Saturn, vs
/// each column alone pruning to <3% of granules). A `UNION ALL` of single-column
/// equality legs lets each leg use its own bloom (1.6s @7d / 2.7s @30d) —
/// NAN-1589. Each leg projects the row `id`, timestamp, the resolved host
/// expression, and a literal `_mf` = the LOGICAL observable name (stable UI
/// label across profiles). The outer aggregate dedups with `uniqExact(id)` so a
/// row carrying the indicator in two columns counts as ONE hit (exact parity
/// with the old `count()` over the OR); `_mf` field-counts intentionally count
/// per matching field. No PREWHERE — each leg's single WHERE lets
/// `optimize_move_to_prewhere` place the bound.
fn build_summary_sql(
    profile: &dyn SchemaProfile,
    observables: &[ResolvedObservable],
    table: &str,
    value: &str,
    range: &TimeRange,
    scope_predicate: Option<&str>,
) -> String {
    let host = host_expr(profile);
    let union = union_match_legs(observables, table, value, range, &host, scope_predicate);
    let count_tuples: Vec<String> = observables
        .iter()
        .map(|obs| format!("('{l}', toUInt64(countIf(_mf = '{l}')))", l = obs.logical))
        .collect();
    let counts = if count_tuples.is_empty() {
        "CAST([], 'Array(Tuple(String, UInt64))')".to_string()
    } else {
        format!("[{}]", count_tuples.join(", "))
    };
    format!(
        "SELECT uniqExact(_rid) AS hits, \
         uniqExact(nullIf(_host, '')) AS distinct_hosts, \
         formatDateTime(min(_ts), '%Y-%m-%dT%H:%i:%sZ') AS first_seen, \
         formatDateTime(max(_ts), '%Y-%m-%dT%H:%i:%sZ') AS last_seen, \
         {counts} AS field_counts \
         FROM ({union})",
    )
}

/// Build the per-observable `UNION ALL` body that the summary + top-entities
/// scans share. Each leg: `SELECT id AS _rid, timestamp AS _ts, <host> AS _host,
/// '<logical>' AS _mf FROM <table> WHERE timestamp BETWEEN … AND <col>=<v>`. The
/// single-column equality per leg is what makes each leg index-prunable
/// (NAN-1589). `value` is lowercased to match ingest-lowercased raw columns and
/// the `lower()` expression indexes. When no observable resolves (degenerate
/// profile / empty scope), emits a typed zero-row leg so the outer aggregate
/// returns hits=0 instead of an invalid empty UNION.
fn union_match_legs(
    observables: &[ResolvedObservable],
    table: &str,
    value: &str,
    range: &TimeRange,
    host: &str,
    scope_predicate: Option<&str>,
) -> String {
    let escaped_val = escape_sql_string(&value.to_lowercase());
    let start = ts(&range.start);
    let end = ts(&range.end);
    // NAN-1801: EVERY leg carries the caller's source-scope gate — the legs
    // are independent scans, so gating only some would leak denied-source rows
    // through the ungated legs. Empty (unrestricted) appends nothing.
    let gate = scope_and(scope_predicate);
    let legs: Vec<String> = observables
        .iter()
        .map(|obs| {
            let cmp = if obs.raw {
                format!("{} = '{escaped_val}'", obs.col_sql)
            } else {
                format!("lower({}) = '{escaped_val}'", obs.col_sql)
            };
            format!(
                "SELECT id AS _rid, timestamp AS _ts, {host} AS _host, '{l}' AS _mf \
                 FROM {table} WHERE timestamp BETWEEN '{start}' AND '{end}' AND {cmp}{gate}",
                l = obs.logical,
            )
        })
        .collect();
    if legs.is_empty() {
        format!(
            "SELECT generateUUIDv7() AS _rid, now() AS _ts, '' AS _host, '' AS _mf \
             FROM {table} WHERE 1 = 0"
        )
    } else {
        legs.join(" UNION ALL ")
    }
}

/// List submode SQL (NAN-1580): rarest-first per-indicator rollup. An
/// ARRAY JOIN over the profile-resolved observable columns attributes each hit to
/// a (field, value) pair, filtered to the indicator set; rarest-first = hosts
/// ASC, hits ASC. The attributed `field` is the stable LOGICAL UDM observable
/// name (consistent UI label across profiles); the matched value comes from the
/// resolved physical column.
fn build_list_sql(
    profile: &dyn SchemaProfile,
    observables: &[ResolvedObservable],
    table: &str,
    predicate: &str,
    indicators: &[String],
    range: &TimeRange,
    offset: usize,
    fetch: usize,
    scope_predicate: Option<&str>,
) -> String {
    let tuple_legs: Vec<String> = observables
        .iter()
        .zip(observable_value_exprs(observables))
        .map(|(obs, val)| format!("('{}', {val})", obs.logical))
        .collect();
    // No resolvable observable: emit a typed empty array so the ARRAY JOIN is
    // valid SQL (it yields zero rows, the correct "nothing matched" result).
    let tuples = if tuple_legs.is_empty() {
        "CAST([], 'Array(Tuple(String, String))')".to_string()
    } else {
        format!("[{}]", tuple_legs.join(", "))
    };
    format!(
        "SELECT obs.2 AS value, any(obs.1) AS field, count() AS hits, \
         uniqExact(nullIf({host}, '')) AS hosts, \
         formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS first_seen, \
         formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS last_seen \
         FROM {table} \
         ARRAY JOIN {tuples} AS obs \
         WHERE timestamp BETWEEN '{start}' AND '{end}' AND {pred}{gate} \
         AND obs.2 IN ({values}) \
         GROUP BY value \
         ORDER BY hosts ASC, hits ASC \
         LIMIT {fetch} OFFSET {offset}",
        host = host_expr(profile),
        start = ts(&range.start),
        end = ts(&range.end),
        pred = predicate,
        gate = scope_and(scope_predicate),
        values = sql_in_list(indicators),
    )
}

/// Pivot submode SQL (NAN-1580): entities (asset|user) touched by the matched
/// indicators. Distinct indicators per entity are collected via
/// `arrayDistinct(arrayFlatten(groupArray(arrayFilter(…))))` over the per-row
/// profile-resolved observable values. Stable order: first_seen ASC.
fn build_pivot_sql(
    profile: &dyn SchemaProfile,
    observables: &[ResolvedObservable],
    table: &str,
    axis: RetroAxis,
    predicate: &str,
    indicators: &[String],
    range: &TimeRange,
    offset: usize,
    fetch: usize,
    scope_predicate: Option<&str>,
) -> String {
    let entity_expr = match axis {
        RetroAxis::User => user_pivot_expr(profile),
        _ => host_expr(profile),
    };
    // Typed-empty fallback when nothing resolves (keeps the array literal valid).
    let obs_exprs = observable_value_exprs(observables);
    let obs = if obs_exprs.is_empty() {
        "CAST([], 'Array(String)')".to_string()
    } else {
        format!("[{}]", obs_exprs.join(", "))
    };
    let values = sql_in_list(indicators);
    // Identity columns. For the USER axis, resolve a real display name +
    // department synchronously via `user_registry_dict` (keyed on the lowercased
    // username — verified against clickhouse/124/125). For the ASSET axis emit
    // empty strings so the row shape is uniform; full asset-model
    // canonicalization (merging host-a ≡ host-a.corp ≡ ip via the identity
    // model) is a follow-up — out of scope for this pass.
    let (ident_name, ident_dept) = match axis {
        RetroAxis::User => (
            format!(
                "dictGetOrDefault('nanosiem.user_registry_dict', 'display_name', lower({entity}), '')",
                entity = entity_expr
            ),
            format!(
                "dictGetOrDefault('nanosiem.user_registry_dict', 'department', lower({entity}), '')",
                entity = entity_expr
            ),
        ),
        _ => ("''".to_string(), "''".to_string()),
    };
    format!(
        "SELECT {entity} AS id, \
         any({ident_name}) AS ident_name, any({ident_dept}) AS ident_dept, \
         arrayDistinct(arrayFlatten(groupArray(arrayFilter(x -> x IN ({values}), {obs})))) AS inds, \
         count() AS hits, uniqExact({host}) AS hosts, \
         formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS first_seen, \
         formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS last_seen \
         FROM {table} \
         WHERE timestamp BETWEEN '{start}' AND '{end}' AND {pred}{gate} \
         AND {entity} != '' \
         GROUP BY id \
         ORDER BY first_seen ASC \
         LIMIT {fetch} OFFSET {offset}",
        entity = entity_expr,
        host = host_expr(profile),
        start = ts(&range.start),
        end = ts(&range.end),
        pred = predicate,
        gate = scope_and(scope_predicate),
    )
}

/// Aggregate row for the summary scan: fixed leading columns plus an
/// `Array((field, count))` of per-observable-column match counts.
#[derive(clickhouse::Row, serde::Deserialize)]
struct RetroSummaryRow {
    hits: u64,
    distinct_hosts: u64,
    first_seen: String,
    last_seen: String,
    /// `[(field, count), …]` for each observable column that the indicator hit.
    field_counts: Vec<(String, u64)>,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct RetroListRowRaw {
    value: String,
    field: String,
    hits: u64,
    hosts: u64,
    first_seen: String,
    last_seen: String,
}

#[derive(clickhouse::Row, serde::Deserialize)]
struct RetroPivotRowRaw {
    id: String,
    /// Dict-resolved display name (USER axis); empty for the ASSET axis.
    ident_name: String,
    /// Dict-resolved department (USER axis); empty for the ASSET axis.
    ident_dept: String,
    inds: Vec<String>,
    #[allow(dead_code)]
    hits: u64,
    hosts: u64,
    first_seen: String,
    last_seen: String,
}

/// Build a `'a', 'b', …` SQL IN-list from lowercased indicators.
fn sql_in_list(indicators: &[String]) -> String {
    if indicators.is_empty() {
        return "''".to_string();
    }
    indicators
        .iter()
        .map(|v| format!("'{}'", escape_sql_string(&v.to_lowercase())))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Normalize a ClickHouse-formatted timestamp string to `Option`, dropping the
/// epoch sentinel ClickHouse emits for empty aggregates.
fn normalize_ts(s: String) -> Option<String> {
    if s.is_empty() || s == "1970-01-01T00:00:00Z" {
        None
    } else {
        Some(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::query::parse_query;
    use crate::schema::{OcsfProfile, UdmProfile};

    fn range() -> TimeRange {
        TimeRange::new(
            "2024-01-01T00:00:00Z".parse().unwrap(),
            "2024-01-02T00:00:00Z".parse().unwrap(),
        )
    }

    fn udm() -> UdmProfile {
        UdmProfile::new()
    }

    /// P2-e: a request older than retention is clamped UP to the retention floor
    /// (never widened past what ClickHouse retains); end is untouched.
    #[test]
    fn retro_time_range_clamps_start_to_retention_floor() {
        let now = chrono::Utc::now();
        let floor = now - chrono::Duration::days(RETRO_RETENTION_DAYS);

        // Request reaching back 2 years — older than the 365-day retention floor.
        let requested = TimeRange::new(now - chrono::Duration::days(730), now);
        let clamped = SearchService::retro_time_range(&requested);
        // Start is pulled UP to ~floor (within a second of the recomputed floor).
        assert!(
            (clamped.start - floor).num_seconds().abs() < 2,
            "start must clamp to the retention floor, got {} vs floor {}",
            clamped.start,
            floor
        );
        assert!(
            clamped.start > requested.start,
            "over-retention request must be capped, not widened"
        );
        // End is preserved.
        assert_eq!(clamped.end, requested.end);

        // A request already inside retention keeps its (later) start unchanged.
        let recent_start = now - chrono::Duration::days(10);
        let recent = TimeRange::new(recent_start, now);
        let kept = SearchService::retro_time_range(&recent);
        assert_eq!(kept.start, recent_start);
    }

    fn ocsf() -> OcsfProfile {
        OcsfProfile::new()
    }

    fn udm_obs() -> Vec<ResolvedObservable> {
        resolve_ioc_observables(&udm())
    }

    fn ocsf_obs() -> Vec<ResolvedObservable> {
        resolve_ioc_observables(&ocsf())
    }

    #[test]
    fn extract_plan_single_value_is_summary() {
        let q = parse_query("ioc=\"1.2.3.4\" | retro").unwrap();
        let plan = extract_retro_plan(&q).expect("retro plan");
        assert_eq!(plan.submode, RetroSubmode::Summary);
        assert_eq!(plan.axis, RetroAxis::Indicator);
        assert_eq!(plan.values, vec!["1.2.3.4".to_string()]);
        assert!(plan.feed.is_none());
    }

    #[test]
    fn extract_plan_list_and_pivot_axes() {
        let q = parse_query("ioc in [\"a.com\", \"b.com\"] | retro").unwrap();
        assert_eq!(extract_retro_plan(&q).unwrap().submode, RetroSubmode::List);

        let q = parse_query("ioc=\"1.2.3.4\" | retro by asset").unwrap();
        let p = extract_retro_plan(&q).unwrap();
        assert_eq!(p.submode, RetroSubmode::Pivot);
        assert_eq!(p.axis, RetroAxis::Asset);

        let q = parse_query("ioc=\"1.2.3.4\" | retro by user").unwrap();
        assert_eq!(extract_retro_plan(&q).unwrap().axis, RetroAxis::User);

        // `by host` normalizes to the asset axis.
        let q = parse_query("ioc=\"1.2.3.4\" | retro by host").unwrap();
        assert_eq!(extract_retro_plan(&q).unwrap().axis, RetroAxis::Asset);
    }

    #[test]
    fn extract_plan_feed_is_list() {
        let q = parse_query("ioc in threatfox(\"apt29\") | retro").unwrap();
        let p = extract_retro_plan(&q).unwrap();
        assert_eq!(p.submode, RetroSubmode::List);
        let feed = p.feed.expect("feed");
        assert_eq!(feed.name, "threatfox");
        assert_eq!(feed.arg, "apt29");
    }

    #[test]
    fn marker_carries_retro_fields() {
        let q = parse_query("ioc=\"1.2.3.4\" | retro").unwrap();
        let plan = extract_retro_plan(&q).unwrap();
        let m = build_retro_marker(&plan);
        assert_eq!(m["_display_type"], "retro");
        assert_eq!(m["_retro_submode"], "summary");
        assert_eq!(m["_retro_axis"], "indicator");
        assert_eq!(m["_retro_indicator"], "1.2.3.4");
        assert!(m["_retro_feed"].is_null());

        let q = parse_query("ioc in feodo(\"emotet\") | retro by asset").unwrap();
        let plan = extract_retro_plan(&q).unwrap();
        let m = build_retro_marker(&plan);
        assert_eq!(m["_retro_submode"], "pivot");
        assert_eq!(m["_retro_axis"], "asset");
        assert_eq!(m["_retro_feed"], "feodo");
        assert_eq!(m["_retro_feed_arg"], "emotet");
        // No single indicator for a feed-sourced term.
        assert!(m["_retro_indicator"].is_null());
    }

    #[test]
    fn match_predicate_uses_index_friendly_forms() {
        // UDM (default profile): observable names ARE the columns.
        let pred = SearchService::retro_match_predicate(&udm_obs(), &["1.2.3.4".to_string()]);
        // RAW for ingest-lowercased ip columns.
        assert!(pred.contains("src_ip = '1.2.3.4'"));
        assert!(pred.contains("dvc_ip = '1.2.3.4'"));
        // lower(col) for mixed-case observable columns.
        assert!(pred.contains("lower(file_hash) = '1.2.3.4'"));
        assert!(pred.contains("lower(url_domain) = '1.2.3.4'"));
        assert!(pred.contains(" OR "));
    }

    #[test]
    fn match_predicate_resolves_ocsf_columns() {
        // NAN-1580: under OCSF the logical observables resolve to the promoted
        // OCSF columns (dotted → backtick-quoted), never the raw UDM names.
        let pred = SearchService::retro_match_predicate(&ocsf_obs(), &["1.2.3.4".to_string()]);
        // src_ip → \"src_endpoint.ip\" (RAW, ingest-lowercased).
        assert!(pred.contains("\"src_endpoint.ip\" = '1.2.3.4'"), "got: {pred}");
        // dest_ip → \"dst_endpoint.ip\".
        assert!(pred.contains("\"dst_endpoint.ip\" = '1.2.3.4'"), "got: {pred}");
        // file_hash → \"file.hashes.sha256\" (lower()).
        assert!(
            pred.contains("lower(\"file.hashes.sha256\") = '1.2.3.4'"),
            "got: {pred}"
        );
        // No bare UDM column leaks through.
        assert!(!pred.contains("src_ip = "), "got: {pred}");
        assert!(!pred.contains("lower(file_hash)"), "got: {pred}");
        // dvc_ip has no OCSF mapping → skipped (not emitted).
        assert!(!pred.contains("dvc_ip"), "got: {pred}");
    }

    #[test]
    fn summary_sql_is_per_column_union_no_prewhere() {
        // NAN-1589: the summary is a per-column UNION ALL (each leg index-prunable),
        // not a single OR (which can't combine skip indexes across columns).
        let obs = udm_obs();
        let sql = build_summary_sql(&udm(), &obs, "logs", "1.2.3.4", &range(), None);
        assert!(sql.contains("UNION ALL"), "must be a per-column union: {sql}");
        assert!(sql.contains("WHERE timestamp BETWEEN"));
        assert!(!sql.contains("PREWHERE"));
        // exact hits via row-id dedup (parity with the old count() over the OR).
        assert!(sql.contains("uniqExact(_rid) AS hits"), "got: {sql}");
        assert!(sql.contains("uniqExact(nullIf(_host, '')) AS distinct_hosts"));
        assert!(sql.contains("min(_ts)") && sql.contains("max(_ts)"));
        assert!(sql.contains("AS field_counts"));
        // one single-column equality leg per observable...
        assert!(sql.contains("AND src_ip = '1.2.3.4'"), "got: {sql}");
        assert!(sql.contains("AND lower(file_hash) = '1.2.3.4'"), "got: {sql}");
        // ...NOT a single OR-ed predicate.
        assert!(!sql.contains(" OR "), "summary must not OR the columns: {sql}");
        // field counts attributed by the LOGICAL observable name via _mf.
        assert!(sql.contains("countIf(_mf = 'src_ip')"), "got: {sql}");
        assert!(sql.contains("countIf(_mf = 'file_hash')"), "got: {sql}");
    }

    #[test]
    fn summary_sql_resolves_ocsf_columns_keeps_logical_labels() {
        // NAN-1580/1589: each UNION leg matches the resolved OCSF physical column,
        // but the _mf field-count label stays the LOGICAL UDM name (stable UI label).
        let obs = ocsf_obs();
        let sql = build_summary_sql(&ocsf(), &obs, "ocsf_logs", "1.2.3.4", &range(), None);
        assert!(sql.contains("UNION ALL"), "got: {sql}");
        // leg matches the resolved OCSF column...
        assert!(
            sql.contains("AND \"src_endpoint.ip\" = '1.2.3.4'"),
            "got: {sql}"
        );
        assert!(
            sql.contains("AND lower(\"file.hashes.sha256\") = '1.2.3.4'"),
            "got: {sql}"
        );
        // ...labelled by the LOGICAL observable name for the UI.
        assert!(sql.contains("'src_ip' AS _mf"), "got: {sql}");
        assert!(sql.contains("'file_hash' AS _mf"), "got: {sql}");
        assert!(sql.contains("countIf(_mf = 'src_ip')"), "got: {sql}");
        // host_expr resolved to OCSF identity columns.
        assert!(sql.contains("\"src_endpoint.ip\"") && !sql.contains("nullIf(src_ip"));
    }

    #[test]
    fn list_sql_groups_and_orders_rarest_first() {
        let inds = vec!["a.com".to_string(), "b.com".to_string()];
        let obs = udm_obs();
        let pred = SearchService::retro_match_predicate(&obs, &inds);
        let sql = build_list_sql(&udm(), &obs, "logs", &pred, &inds, &range(), 0, 51, None);
        assert!(sql.contains("WHERE timestamp BETWEEN") && !sql.contains("PREWHERE"));
        assert!(sql.contains("GROUP BY value"));
        assert!(sql.contains("ORDER BY hosts ASC, hits ASC"));
        assert!(sql.contains("ARRAY JOIN"));
        assert!(sql.contains("LIMIT 51 OFFSET 0"));
        // UDM attribution tuple keys ARE the column names (identity resolution).
        assert!(sql.contains("('file_hash', lower(file_hash))"), "got: {sql}");
    }

    #[test]
    fn list_sql_resolves_ocsf_columns_keeps_logical_labels() {
        // NAN-1580: ARRAY JOIN legs target OCSF columns, attributed by logical name.
        let inds = vec!["a.com".to_string()];
        let obs = ocsf_obs();
        let pred = SearchService::retro_match_predicate(&obs, &inds);
        let sql = build_list_sql(&ocsf(), &obs, "ocsf_logs", &pred, &inds, &range(), 0, 51, None);
        assert!(sql.contains("ARRAY JOIN"));
        // logical label, OCSF physical value expr.
        assert!(
            sql.contains("('file_hash', lower(\"file.hashes.sha256\"))"),
            "got: {sql}"
        );
        assert!(sql.contains("('src_ip', \"src_endpoint.ip\")"), "got: {sql}");
        assert!(!sql.contains("lower(file_hash)"), "got: {sql}");
    }

    #[test]
    fn pivot_sql_groups_by_entity_full_retention_where() {
        let inds = vec!["1.2.3.4".to_string()];
        let obs = udm_obs();
        let pred = SearchService::retro_match_predicate(&obs, &inds);

        let asset_sql = build_pivot_sql(
            &udm(), &obs, "logs", RetroAxis::Asset, &pred, &inds, &range(), 0, 51, None,
        );
        assert!(asset_sql.contains("WHERE timestamp BETWEEN") && !asset_sql.contains("PREWHERE"));
        assert!(asset_sql.contains("GROUP BY id"));
        assert!(asset_sql.contains("ORDER BY first_seen ASC"));
        // Asset pivot keys on the host expression.
        assert!(asset_sql.contains("src_host"));

        // Asset pivot emits empty identity columns (uniform row shape).
        assert!(asset_sql.contains("any('') AS ident_name"));
        assert!(asset_sql.contains("any('') AS ident_dept"));

        let user_sql = build_pivot_sql(
            &udm(), &obs, "logs", RetroAxis::User, &pred, &inds, &range(), 0, 51, None,
        );
        // User pivot keys on the user expression.
        assert!(user_sql.contains("lower(\"user\")"));
        // User pivot resolves identity via the user_registry_dict (display_name +
        // department), keyed on the lowercased user expression.
        // dictGetOrDefault REQUIRES a 4th default-value arg (3-arg form is a CH
        // runtime error); assert the attribute prefix AND the trailing `), '')`
        // (the 4-arg close) so the missing-default regression can't slip back in.
        for attr in ["display_name", "department"] {
            let prefix =
                format!("dictGetOrDefault('nanosiem.user_registry_dict', '{attr}', lower(");
            assert!(user_sql.contains(&prefix), "got: {user_sql}");
        }
        // The 4th default arg (`, '')`) must appear on both identity legs — the
        // entity key expression is wrapped in `lower(...)`, then closed with `, ''`.
        assert!(
            user_sql.matches("), '')) AS ident_").count() >= 2,
            "both identity dictGetOrDefault calls must carry the 4th default arg, got: {user_sql}"
        );
        assert!(user_sql.contains("AS ident_name") && user_sql.contains("AS ident_dept"));
    }

    #[test]
    fn pivot_sql_resolves_ocsf_entity_columns() {
        // NAN-1580: the asset/user pivot entity expressions resolve to OCSF
        // identity columns, never the raw UDM names.
        let inds = vec!["1.2.3.4".to_string()];
        let obs = ocsf_obs();
        let pred = SearchService::retro_match_predicate(&obs, &inds);

        let asset_sql = build_pivot_sql(
            &ocsf(), &obs, "ocsf_logs", RetroAxis::Asset, &pred, &inds, &range(), 0, 51, None,
        );
        // src_ip identity leg → OCSF column; no bare UDM `nullIf(src_ip`.
        assert!(asset_sql.contains("\"src_endpoint.ip\""), "got: {asset_sql}");
        assert!(!asset_sql.contains("nullIf(src_ip"), "got: {asset_sql}");

        let user_sql = build_pivot_sql(
            &ocsf(), &obs, "ocsf_logs", RetroAxis::User, &pred, &inds, &range(), 0, 51, None,
        );
        // user → user_unified (OCSF class-split column), not bare `user`.
        assert!(user_sql.contains("user_unified"), "got: {user_sql}");
    }

    #[test]
    fn classify_indicator_buckets() {
        assert_eq!(classify_indicator("1.2.3.4"), "ip");
        assert_eq!(
            classify_indicator("44d88612fea8a8f36de82e1278abb02f"),
            "hash"
        );
        assert_eq!(classify_indicator("https://evil.test/x"), "url");
        assert_eq!(classify_indicator("CVE-2024-1234"), "cve");
        assert_eq!(classify_indicator("user@corp.test"), "user");
        assert_eq!(classify_indicator("evil.test"), "domain");
    }

    #[test]
    fn scope_observables_narrows_to_indicator_type() {
        let all = udm_obs();
        // An IP collapses to exactly the 3 raw IP columns — no lower(text) legs.
        let ip = scope_observables(&all, &["37.27.197.191".to_string()]);
        let cols: std::collections::HashSet<&str> = ip.iter().map(|o| o.logical).collect();
        assert_eq!(
            cols,
            ["src_ip", "dest_ip", "dvc_ip"].into_iter().collect()
        );
        assert!(ip.len() < all.len(), "IP scope must drop the irrelevant legs");

        // A hash collapses to the hash columns.
        let hash = scope_observables(&all, &["44d88612fea8a8f36de82e1278abb02f".to_string()]);
        let hcols: std::collections::HashSet<&str> = hash.iter().map(|o| o.logical).collect();
        assert_eq!(hcols, ["file_hash", "process_hash"].into_iter().collect());

        // The scoped predicate for an IP must NOT contain any text-column leg.
        let pred = SearchService::retro_match_predicate(&ip, &["37.27.197.191".to_string()]);
        assert!(pred.contains("src_ip = '37.27.197.191'"));
        assert!(!pred.contains("file_hash"), "got: {pred}");
        assert!(!pred.contains("lower("), "IP scope must emit no lower() legs: {pred}");
    }

    #[test]
    fn scope_observables_falls_back_to_all_for_unknown_or_mixed() {
        let all = udm_obs();
        // Unknown type ("other") → keep the full set (never narrow to nothing).
        let unknown = scope_observables(&all, &["some random thing".to_string()]);
        assert_eq!(unknown.len(), all.len());
        // A mix that includes an unknown also falls back to all.
        let mixed = scope_observables(
            &all,
            &["37.27.197.191".to_string(), "some random thing".to_string()],
        );
        assert_eq!(mixed.len(), all.len());
        // Empty indicator set → full set (defensive; never an empty predicate).
        assert_eq!(scope_observables(&all, &[]).len(), all.len());
    }

    // ------------------------------------------------------------------------
    // Source-scope gating of the retro logs scans (NAN-1801)
    // ------------------------------------------------------------------------

    fn deny(vals: &[&str]) -> std::collections::BTreeSet<String> {
        vals.iter().map(|s| s.to_string()).collect()
    }

    /// NAN-1801 multi-scan completeness: the rendered deny predicate must land
    /// in EVERY hand-built logs scan — each summary/top-entities UNION leg
    /// (they are independent scans; one ungated leg leaks denied rows), the
    /// list rollup, and the pivot rollup.
    #[test]
    fn retro_sql_scope_gate_lands_in_every_logs_scan() {
        let obs = udm_obs();
        let rendered = source_scope_sql_predicate("source_type", &deny(&["audit"]));
        let scope = rendered.as_deref();
        let gate = "lower(source_type) != 'audit'";

        // Summary: one gate per UNION leg (legs = observables).
        let sql = build_summary_sql(&udm(), &obs, "logs", "1.2.3.4", &range(), scope);
        let legs = sql.matches("UNION ALL").count() + 1;
        assert_eq!(legs, obs.len(), "one leg per observable: {sql}");
        assert_eq!(
            sql.matches(gate).count(),
            legs,
            "every summary union leg must carry the scope gate: {sql}"
        );

        // Raw union body (top-entities path) — same per-leg gating.
        let union = union_match_legs(&obs, "logs", "1.2.3.4", &range(), "host", scope);
        assert_eq!(union.matches(gate).count(), obs.len(), "got: {union}");

        // List rollup: single scan, gated once, inside the WHERE.
        let inds = vec!["1.2.3.4".to_string()];
        let pred = SearchService::retro_match_predicate(&obs, &inds);
        let list = build_list_sql(&udm(), &obs, "logs", &pred, &inds, &range(), 0, 51, scope);
        assert_eq!(list.matches(gate).count(), 1, "got: {list}");
        assert!(list.contains(&format!("AND {gate}")), "got: {list}");

        // Pivot rollup (both axes): single scan, gated once.
        for axis in [RetroAxis::Asset, RetroAxis::User] {
            let pivot = build_pivot_sql(
                &udm(), &obs, "logs", axis, &pred, &inds, &range(), 0, 51, scope,
            );
            assert_eq!(pivot.matches(gate).count(), 1, "axis {axis:?}: {pivot}");
        }

        // Multi-source deny renders the NOT IN form (lexicographic order).
        let multi = source_scope_sql_predicate("source_type", &deny(&["otel", "audit"]));
        let list_multi = build_list_sql(
            &udm(), &obs, "logs", &pred, &inds, &range(), 0, 51, multi.as_deref(),
        );
        assert!(
            list_multi.contains("lower(source_type) NOT IN ('audit', 'otel')"),
            "got: {list_multi}"
        );
    }

    /// NAN-1801 back-compat: an unrestricted caller (empty deny → `None`) must
    /// leave every retro SQL string byte-identical to the pre-scoping form —
    /// no `source_type` reference of any kind appears.
    #[test]
    fn retro_sql_unrestricted_scope_emits_no_gate() {
        let obs = udm_obs();
        // Empty deny set renders no predicate at all.
        assert_eq!(source_scope_sql_predicate("source_type", &deny(&[])), None);

        let inds = vec!["1.2.3.4".to_string()];
        let pred = SearchService::retro_match_predicate(&obs, &inds);
        let summary = build_summary_sql(&udm(), &obs, "logs", "1.2.3.4", &range(), None);
        let list = build_list_sql(&udm(), &obs, "logs", &pred, &inds, &range(), 0, 51, None);
        let pivot = build_pivot_sql(
            &udm(), &obs, "logs", RetroAxis::Asset, &pred, &inds, &range(), 0, 51, None,
        );
        for sql in [&summary, &list, &pivot] {
            assert!(!sql.contains("source_type"), "unscoped SQL must not gate: {sql}");
        }
    }

    // ------------------------------------------------------------------------
    // Retro-hunt candidate SQL (NAN-1791)
    // ------------------------------------------------------------------------

    #[test]
    fn retro_hunt_candidates_sql_live_ioc_grouped_oldest_first() {
        let sql = SearchService::retro_hunt_candidates_sql(
            "custom_enrichment_results",
            &[],
            &[],
            None,
            501,
        );
        // Live IOC rows only.
        assert!(sql.contains("is_ioc = 1 AND expires_at > now()"), "got: {sql}");
        // Grouped by lowercased value so ReplacingMergeTree dupes collapse.
        assert!(sql.contains("GROUP BY value"), "got: {sql}");
        assert!(sql.contains("lower(key_value) AS value"), "got: {sql}");
        // Oldest-first + value tiebreak = deterministic draining.
        assert!(sql.contains("ORDER BY fetched_at_ms ASC, value ASC"), "got: {sql}");
        assert!(sql.contains("LIMIT 501"), "got: {sql}");
        // No cursor / feed / type filters when unset.
        assert!(!sql.contains("fetched_at >"), "got: {sql}");
        assert!(!sql.contains("enrichment_name IN"), "got: {sql}");
        assert!(!sql.contains("key_type IN"), "got: {sql}");
    }

    #[test]
    fn retro_hunt_candidates_sql_applies_keyset_cursor_feed_and_type_filters() {
        let sql = SearchService::retro_hunt_candidates_sql(
            "custom_enrichment_results",
            &["ThreatFox".to_string(), "URLhaus".to_string()],
            &["ip".to_string(), "domain".to_string()],
            Some((1_700_000_000_000, "1.2.3.4")),
            51,
        );
        // STRICT keyset cursor: later timestamp, OR same timestamp + later value.
        assert!(
            sql.contains("fetched_at > fromUnixTimestamp64Milli(1700000000000)"),
            "got: {sql}"
        );
        assert!(
            sql.contains(
                "fetched_at = fromUnixTimestamp64Milli(1700000000000) AND lower(key_value) > '1.2.3.4'"
            ),
            "got: {sql}"
        );
        // Feed filter lowercased.
        assert!(
            sql.contains("lower(enrichment_name) IN ('threatfox', 'urlhaus')"),
            "got: {sql}"
        );
        // Artifact-type filter.
        assert!(sql.contains("key_type IN ('ip', 'domain')"), "got: {sql}");
    }

    #[test]
    fn retro_hunt_candidates_sql_cursor_value_is_escaped() {
        // A single quote in the cursor value must not break out of the literal.
        let sql = SearchService::retro_hunt_candidates_sql(
            "t",
            &[],
            &[],
            Some((1000, "o'brien")),
            10,
        );
        assert!(sql.contains("lower(key_value) > 'o''brien'"), "got: {sql}");
    }
}
