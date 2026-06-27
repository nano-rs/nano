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
use crate::query::{IocFeed, IocLookup, RetroAxis, SearchExpr, Value};
use crate::query::clickhouse_sql_gen::search_expr::{
    ioc_feed_indicator_subquery, resolve_ioc_observables, ResolvedObservable,
};
use crate::schema::SchemaProfile;

/// Full-retention floor for retro hunts. The `logs` table carries a 365-day TTL
/// (CLAUDE.md core architecture); the engine clamps the requested window's floor
/// to `now - RETRO_RETENTION_DAYS` so a retro hunt never scans beyond retained
/// history (a >365d request can't widen the window past what ClickHouse retains).
/// Capped (not unbounded) so the scan still prunes partitions.
const RETRO_RETENTION_DAYS: i64 = 365;

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

/// Classify an indicator value into a coarse type for display.
fn classify_indicator(value: &str) -> &'static str {
    let v = value.trim();
    if v.parse::<std::net::IpAddr>().is_ok() {
        return "ip";
    }
    let hexlen = v.len();
    if (hexlen == 32 || hexlen == 40 || hexlen == 64)
        && v.chars().all(|c| c.is_ascii_hexdigit())
    {
        return "hash";
    }
    if v.starts_with("http://") || v.starts_with("https://") {
        return "url";
    }
    if v.to_lowercase().starts_with("cve-") {
        return "cve";
    }
    if v.contains('@') {
        return "user";
    }
    if v.contains('.') && !v.contains(' ') {
        return "domain";
    }
    "other"
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
    // (logical UDM field, wrap_in_lower) — host names are mixed-case, ips are
    // ingest-lowercased (raw compare keeps the bloom).
    let legs: &[(&str, bool)] = &[
        ("src_host", true),
        ("dest_host", true),
        ("dvc", true),
        ("src_ip", false),
        ("dest_ip", false),
    ];
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
            ioc_feed_indicator_subquery(feed),
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

    /// Total distinct hosts in the environment over the retention window — the
    /// verdict denominator. Bounded by a row sample for cardinality safety.
    async fn retro_total_hosts(&self, range: &TimeRange) -> u64 {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return 0,
        };
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let sql = format!(
            "SELECT uniqExact({host}) FROM {table} \
             WHERE timestamp BETWEEN '{start}' AND '{end}'",
            host = host_expr(self.active_profile.as_ref()),
            table = logs_table,
            start = range.start.format("%Y-%m-%d %H:%M:%S"),
            end = range.end.format("%Y-%m-%d %H:%M:%S"),
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
    pub async fn build_retro_view(
        &self,
        req: RetroRequest,
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
        let total_hosts = self.retro_total_hosts(&range).await;

        let offset = req.offset.unwrap_or(0);
        let limit = req.limit.unwrap_or(RETRO_PAGE_SIZE).clamp(1, 500);

        match plan.submode {
            RetroSubmode::Summary => {
                self.retro_summary(&plan, &indicators, &range, total_hosts)
                    .await
            }
            RetroSubmode::List => {
                self.retro_list(&plan, &indicators, &range, total_hosts, offset, limit)
                    .await
            }
            RetroSubmode::Pivot => {
                self.retro_pivot(&plan, &indicators, &range, total_hosts, offset, limit)
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
    ) -> Result<RetroResponse, SearchError> {
        let value = plan
            .values
            .first()
            .cloned()
            .or_else(|| indicators.first().cloned())
            .unwrap_or_default();
        let observables = self.retro_observables();
        let predicate = Self::retro_match_predicate(&observables, indicators);
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));

        let sql = build_summary_sql(
            self.active_profile.as_ref(),
            &observables,
            &logs_table,
            &value,
            &predicate,
            range,
        );

        // Aggregate row: hits, distinct_hosts, first_seen, last_seen, field_counts.
        let (hits, distinct_hosts, first_seen, last_seen, matched_fields) =
            self.retro_summary_agg(&sql).await?;

        let top_entities = self
            .retro_top_entities(&predicate, range)
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

    /// Top entities (hosts) for an indicator predicate, by hit count.
    async fn retro_top_entities(
        &self,
        predicate: &str,
        range: &TimeRange,
    ) -> Result<Vec<RetroTopEntity>, SearchError> {
        let clickhouse = match &self.ch_client {
            Some(ch) => ch,
            None => return Ok(Vec::new()),
        };
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let sql = format!(
            "SELECT {host} AS id, count() AS hits FROM {table} \
             WHERE timestamp BETWEEN '{start}' AND '{end}' AND {pred} \
             AND id != '' GROUP BY id ORDER BY hits DESC LIMIT 10",
            host = host_expr(self.active_profile.as_ref()),
            table = logs_table,
            start = range.start.format("%Y-%m-%d %H:%M:%S"),
            end = range.end.format("%Y-%m-%d %H:%M:%S"),
            pred = predicate,
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
        let sql = format!(
            "SELECT enrichment_name, arrayStringConcat(tags, ','), toUInt32(confidence) \
             FROM nanosiem.custom_enrichment_results \
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
    ) -> Result<RetroResponse, SearchError> {
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));

        let observables = self.retro_observables();
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
    ) -> Result<RetroResponse, SearchError> {
        let logs_table = self
            .table_names
            .read(Self::logs_table_key(self.active_profile.as_ref()));
        let observables = self.retro_observables();
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

/// Format a time-range bound for a ClickHouse `timestamp BETWEEN` clause.
fn ts(t: &chrono::DateTime<chrono::Utc>) -> String {
    t.format("%Y-%m-%d %H:%M:%S").to_string()
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

/// Summary submode SQL (NAN-1580): single-scan environment footprint for one
/// indicator. Single WHERE (`timestamp BETWEEN … AND <ioc match>`), no PREWHERE.
/// Per-observable match counts surfaced as a fixed-shape `Array((field, count))`,
/// where `field` is the stable LOGICAL UDM observable name (so the UI shows a
/// consistent label regardless of profile) and the count is over the
/// profile-resolved physical column. `observables` is the active profile's
/// resolved observable set.
fn build_summary_sql(
    profile: &dyn SchemaProfile,
    observables: &[ResolvedObservable],
    table: &str,
    value: &str,
    predicate: &str,
    range: &TimeRange,
) -> String {
    let escaped_val = escape_sql_string(&value.to_lowercase());
    let count_tuples: Vec<String> = observables
        .iter()
        .map(|obs| {
            let leg = if obs.raw {
                format!("countIf({} = '{escaped_val}')", obs.col_sql)
            } else {
                format!("countIf(lower({}) = '{escaped_val}')", obs.col_sql)
            };
            // Attribute to the LOGICAL UDM observable name (stable UI label).
            format!("('{}', {leg})", obs.logical)
        })
        .collect();
    // A degenerate profile with no resolvable observable would emit an empty
    // `[]` array literal (CH can't infer its type); fall back to a typed empty.
    let counts = if count_tuples.is_empty() {
        "CAST([], 'Array(Tuple(String, UInt64))')".to_string()
    } else {
        format!("[{}]", count_tuples.join(", "))
    };
    format!(
        "SELECT count() AS hits, \
         uniqExact({host}) AS distinct_hosts, \
         formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS first_seen, \
         formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS last_seen, \
         {counts} AS field_counts \
         FROM {table} \
         WHERE timestamp BETWEEN '{start}' AND '{end}' AND {pred}",
        host = host_expr(profile),
        start = ts(&range.start),
        end = ts(&range.end),
        pred = predicate,
    )
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
         uniqExact({host}) AS hosts, \
         formatDateTime(min(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS first_seen, \
         formatDateTime(max(timestamp), '%Y-%m-%dT%H:%i:%sZ') AS last_seen \
         FROM {table} \
         ARRAY JOIN {tuples} AS obs \
         WHERE timestamp BETWEEN '{start}' AND '{end}' AND {pred} \
         AND obs.2 IN ({values}) \
         GROUP BY value \
         ORDER BY hosts ASC, hits ASC \
         LIMIT {fetch} OFFSET {offset}",
        host = host_expr(profile),
        start = ts(&range.start),
        end = ts(&range.end),
        pred = predicate,
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
         WHERE timestamp BETWEEN '{start}' AND '{end}' AND {pred} \
         AND {entity} != '' \
         GROUP BY id \
         ORDER BY first_seen ASC \
         LIMIT {fetch} OFFSET {offset}",
        entity = entity_expr,
        host = host_expr(profile),
        start = ts(&range.start),
        end = ts(&range.end),
        pred = predicate,
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
    fn summary_sql_is_single_where_no_prewhere() {
        let obs = udm_obs();
        let pred = SearchService::retro_match_predicate(&obs, &["1.2.3.4".to_string()]);
        let sql = build_summary_sql(&udm(), &obs, "logs", "1.2.3.4", &pred, &range());
        assert!(sql.contains("WHERE timestamp BETWEEN"));
        assert!(!sql.contains("PREWHERE"));
        assert!(sql.contains("count() AS hits"));
        assert!(sql.contains("uniqExact("));
        assert!(sql.contains("min(timestamp)") && sql.contains("max(timestamp)"));
        // Per-field counts surfaced as a fixed-shape array.
        assert!(sql.contains("AS field_counts"));
        assert!(sql.contains("countIf(src_ip = '1.2.3.4')"));
        assert!(sql.contains("countIf(lower(file_hash) = '1.2.3.4')"));
    }

    #[test]
    fn summary_sql_resolves_ocsf_columns_keeps_logical_labels() {
        // NAN-1580: counts target the OCSF physical columns, but the per-field
        // attribution tuple key stays the LOGICAL UDM name (stable UI label).
        let obs = ocsf_obs();
        let pred = SearchService::retro_match_predicate(&obs, &["1.2.3.4".to_string()]);
        let sql = build_summary_sql(&ocsf(), &obs, "ocsf_logs", "1.2.3.4", &pred, &range());
        // Count over the resolved OCSF column...
        assert!(
            sql.contains("countIf(\"src_endpoint.ip\" = '1.2.3.4')"),
            "got: {sql}"
        );
        assert!(
            sql.contains("countIf(lower(\"file.hashes.sha256\") = '1.2.3.4')"),
            "got: {sql}"
        );
        // ...labelled by the LOGICAL observable name for the UI.
        assert!(sql.contains("('src_ip', countIf("), "got: {sql}");
        assert!(sql.contains("('file_hash', countIf("), "got: {sql}");
        // host_expr resolved to OCSF identity columns.
        assert!(sql.contains("\"src_endpoint.ip\"") && !sql.contains("nullIf(src_ip"));
    }

    #[test]
    fn list_sql_groups_and_orders_rarest_first() {
        let inds = vec!["a.com".to_string(), "b.com".to_string()];
        let obs = udm_obs();
        let pred = SearchService::retro_match_predicate(&obs, &inds);
        let sql = build_list_sql(&udm(), &obs, "logs", &pred, &inds, &range(), 0, 51);
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
        let sql = build_list_sql(&ocsf(), &obs, "ocsf_logs", &pred, &inds, &range(), 0, 51);
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

        let asset_sql =
            build_pivot_sql(&udm(), &obs, "logs", RetroAxis::Asset, &pred, &inds, &range(), 0, 51);
        assert!(asset_sql.contains("WHERE timestamp BETWEEN") && !asset_sql.contains("PREWHERE"));
        assert!(asset_sql.contains("GROUP BY id"));
        assert!(asset_sql.contains("ORDER BY first_seen ASC"));
        // Asset pivot keys on the host expression.
        assert!(asset_sql.contains("src_host"));

        // Asset pivot emits empty identity columns (uniform row shape).
        assert!(asset_sql.contains("any('') AS ident_name"));
        assert!(asset_sql.contains("any('') AS ident_dept"));

        let user_sql =
            build_pivot_sql(&udm(), &obs, "logs", RetroAxis::User, &pred, &inds, &range(), 0, 51);
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
            &ocsf(), &obs, "ocsf_logs", RetroAxis::Asset, &pred, &inds, &range(), 0, 51,
        );
        // src_ip identity leg → OCSF column; no bare UDM `nullIf(src_ip`.
        assert!(asset_sql.contains("\"src_endpoint.ip\""), "got: {asset_sql}");
        assert!(!asset_sql.contains("nullIf(src_ip"), "got: {asset_sql}");

        let user_sql = build_pivot_sql(
            &ocsf(), &obs, "ocsf_logs", RetroAxis::User, &pred, &inds, &range(), 0, 51,
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
}
