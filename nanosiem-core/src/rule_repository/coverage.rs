// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coverage analysis for repository rules
//!
//! Analyzes which rules can run based on available log sources and UDM fields.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::info;

use crate::auth::ScopeSet;
use crate::db::DualPool;

use super::models::{
    normalize_coverage_severity, normalize_coverage_tactic, CoverageAnalysis, CoverageBySeverity,
    CoverageFilter, CoverageResult, MissingFieldCount, RepositoryRule, TacticCoverage,
};

/// Row for ClickHouse source type query
/// Paired (source_type, class_uid) row backing OCSF class coverage (NAN-2361).
#[derive(clickhouse::Row, Deserialize)]
struct SourceClassRow {
    source_type: String,
    class_uid: i64,
}

#[derive(clickhouse::Row, Deserialize)]
struct SourceTypeRow {
    source_type: String,
}

#[derive(Debug, Error)]
pub enum CoverageAnalyzerError {
    #[error("Query error: {0}")]
    Query(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// What a caller is allowed to learn from the live telemetry inventory
/// (NAN-2081).
///
/// The coverage analyzer reads an all-time `SELECT DISTINCT source_type` off the
/// ingested-events table. That inventory is exactly what `GET /api/source-types`
/// gates behind `search:view`, and individual sources are further hidden by
/// per-source RBAC — so a repository viewer must clear BOTH bars before any of
/// it reaches them.
#[derive(Debug, Clone, Copy)]
pub enum LiveInventoryAccess<'a> {
    /// The caller holds the live-data capability. Sources are still filtered by
    /// their per-source RBAC deny set (which carries the implicit `audit`
    /// denial unless the caller holds `audit:view`).
    Scoped(&'a ScopeSet),
    /// The caller has no live-data capability at all. The inventory is withheld
    /// entirely and the coverage decision degrades to `unknown` rather than
    /// leaking "these source types do / do not exist" through a status.
    Denied,
}

impl LiveInventoryAccess<'_> {
    /// True when the caller may consult live telemetry at all. Callers use this
    /// to skip the ClickHouse scan entirely for a denied principal.
    pub fn permits_live_data(&self) -> bool {
        self.scope().is_some()
    }

    fn scope(&self) -> Option<&ScopeSet> {
        match self {
            LiveInventoryAccess::Scoped(scope) => Some(scope),
            LiveInventoryAccess::Denied => None,
        }
    }
}

/// How far back the lake inventory looks.
///
/// The ClickHouse scan is all-time because a `DISTINCT source_type` over a
/// sorted column is nearly free there. On the lake the same question is a
/// `stats by` over every Parquet file ever written, so it is bounded instead.
/// 30 days is long enough that a weekly-batch source still registers, and the
/// practical effect of the divergence is that a source silent for over a month
/// stops being suggested — which is the more useful answer for "what can run
/// this rule today" anyway.
const LAKE_INVENTORY_LOOKBACK_DAYS: i64 = 30;

/// Group cap for the lake inventory read. Sources × classes, not events: a
/// tenant would need 1000 distinct (source, class) pairs to truncate, against
/// roughly 80 OCSF classes and a source count in the dozens.
const LAKE_INVENTORY_LIMIT: usize = 1_000;

/// Coverage status used when the caller may not consult live telemetry at all.
/// Deliberately distinct from `none`, which is a real "we looked and found
/// nothing" answer.
pub const COVERAGE_STATUS_UNKNOWN: &str = "unknown";

/// Analyzer for checking rule coverage against available log sources.
///
/// NAN-2081: the cached inventory is deliberately **raw and unscoped** — it is
/// shared process-wide across every caller, so baking one requester's per-source
/// RBAC scope into it would leak that scope to the next requester (or hide
/// sources from them). Every method that can surface a source type to a caller
/// therefore takes an explicit [`ScopeSet`] and filters against it at read time.
pub struct CoverageAnalyzer {
    /// `None` for an inventory-only analyzer (the shared lake's per-tenant
    /// coverage, fed from a tenant-scoped search through [`Self::load_lake_rows`]).
    dual_pool: Option<DualPool>,
    /// Raw, unscoped cache of available fields per source type. Never returned
    /// directly — always filtered through the calling principal's scope.
    available_fields: HashMap<String, HashSet<String>>,
    /// NAN-2361: which OCSF event classes each source type actually emits, read
    /// from the live inventory. This is what makes an OCSF rule's coverage
    /// answerable: the rule names a `class_uid`, and a source covers it if it has
    /// been observed emitting that class. Empty under UDM (no class concept) and
    /// whenever the inventory could not be read, in which case coverage falls
    /// back to the previous source-name behaviour rather than claiming nothing
    /// is covered.
    available_classes: HashMap<String, HashSet<i64>>,
}

impl CoverageAnalyzer {
    /// Create a new coverage analyzer with DualPool
    pub fn new(dual_pool: DualPool) -> Self {
        Self {
            dual_pool: Some(dual_pool),
            available_fields: HashMap::new(),
            available_classes: HashMap::new(),
        }
    }

    /// An analyzer that never queries a store: its inventory comes only from
    /// [`Self::load_lake_rows`]. Used by the enterprise-shared coverage port,
    /// where the inventory is read through the caller's tenant search runtime.
    pub fn inventory_only() -> Self {
        Self {
            dual_pool: None,
            available_fields: HashMap::new(),
            available_classes: HashMap::new(),
        }
    }

    /// The lake inventory query: `(metadata.log_source, class_uid)` pairs.
    pub const LAKE_INVENTORY_QUERY: &'static str =
        "* | stats count() as count by metadata.log_source, class_uid";
    /// Lookback for [`Self::LAKE_INVENTORY_QUERY`].
    pub const LAKE_INVENTORY_LOOKBACK_DAYS: i64 = LAKE_INVENTORY_LOOKBACK_DAYS;
    /// Group cap for [`Self::LAKE_INVENTORY_QUERY`].
    pub const LAKE_INVENTORY_LIMIT: usize = LAKE_INVENTORY_LIMIT;

    /// Replace the inventory with the rows of [`Self::LAKE_INVENTORY_QUERY`].
    pub fn load_lake_rows(&mut self, rows: &[serde_json::Value]) {
        self.available_fields.clear();
        self.available_classes.clear();
        for row in rows {
            let Some(source_type) = row
                .get("metadata.log_source")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            else {
                continue;
            };
            self.available_fields
                .entry(source_type.to_string())
                .or_default();
            // A row with no readable class still proves the source exists, so it
            // lands in `available_fields` either way — it just cannot contribute
            // to a class-derived suggestion.
            if let Some(class_uid) = row.get("class_uid").and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_u64().map(|c| c as i64))
                    .or_else(|| v.as_f64().map(|c| c as i64))
                    .or_else(|| v.as_str().and_then(|s| s.trim().parse::<i64>().ok()))
            }) {
                self.available_classes
                    .entry(source_type.to_string())
                    .or_default()
                    .insert(class_uid);
            }
        }
    }

    /// Get available source types from logs (all time).
    ///
    /// `search_service` is required only under the lake backend, where there is
    /// no ClickHouse logs table to scan (NAN-2361); pass `None` on ClickHouse
    /// deployments and in tests.
    pub async fn refresh_available_fields(
        &mut self,
        search_service: Option<&crate::search::SearchService>,
    ) -> Result<(), CoverageAnalyzerError> {
        // NAN-2361: under the lake backend there is no logs table to scan —
        // ClickHouse is either empty or absent — so the whole coverage feature
        // read as "no source has any data". Read the same inventory through
        // search, which is the lake's only query surface.
        if let Some(service) = search_service {
            if service.backend() == crate::SearchBackend::Lake {
                return self.refresh_from_lake(service).await;
            }
        }

        let Some(dual_pool) = self.dual_pool.as_ref() else {
            return Err(CoverageAnalyzerError::Query(
                "inventory-only analyzer has no store to refresh from".into(),
            ));
        };
        let ch_client = dual_pool.clickhouse();

        // Query all distinct source types (no time filter).
        // NAN-1241: read the active ingested-events table (ocsf_logs under OCSF)
        // so rule coverage sees the source types that actually exist. UDM-identical.
        // NAN-1728 (H5): route through the `_distributed` wrapper on a cluster so
        // DISTINCT source_type sees source types on ALL shards (otherwise rules
        // whose data landed on another shard are falsely reported as having no
        // matching data); bare local name on single-node (byte-identical).
        let logs_table = dual_pool
            .table_names()
            .read_bare(crate::schema::active_logs_table());
        // NAN-2361: under OCSF, pull the (source_type, class_uid) pairs so rule
        // coverage can be decided on the event CLASS a rule actually names.
        // `source_type` alone cannot answer that: one source emits many classes.
        let ocsf = matches!(
            crate::schema::active_profile_from_env().map(|p| p.id()),
            Ok(crate::schema::SchemaId::Ocsf)
        );

        self.available_fields.clear();
        self.available_classes.clear();

        if ocsf {
            let query = format!(
                r#"
                SELECT DISTINCT source_type, class_uid
                FROM {logs_table}
                WHERE source_type != ''
                ORDER BY source_type
            "#
            );
            let rows = ch_client
                .query(&query)
                .fetch_all::<SourceClassRow>()
                .await
                .map_err(|e| CoverageAnalyzerError::Query(e.to_string()))?;
            for row in rows {
                self.available_fields
                    .entry(row.source_type.clone())
                    .or_default();
                self.available_classes
                    .entry(row.source_type)
                    .or_default()
                    .insert(row.class_uid);
            }
        } else {
            let query = format!(
                r#"
                SELECT DISTINCT source_type
                FROM {logs_table}
                WHERE source_type != ''
                ORDER BY source_type
            "#
            );
            let result = ch_client
                .query(&query)
                .fetch_all::<SourceTypeRow>()
                .await
                .map_err(|e| CoverageAnalyzerError::Query(e.to_string()))?;
            for row in result {
                // Store source type with empty field set (fields not tracked for now)
                self.available_fields
                    .insert(row.source_type, HashSet::new());
            }
        }

        info!(
            "Refreshed available source types: {} found",
            self.available_fields.len()
        );
        Ok(())
    }

    /// Read the (source, class) inventory through search, for lake deployments.
    ///
    /// Scoped `unrestricted` on purpose: this populates the process-wide cache
    /// that every caller shares, exactly like the ClickHouse scan it replaces,
    /// and that cache is filtered against each caller's own scope at read time
    /// (see `visible_source_types`). Populating it from one caller's scope would
    /// hide their denied sources from everyone else.
    async fn refresh_from_lake(
        &mut self,
        search_service: &crate::search::SearchService,
    ) -> Result<(), CoverageAnalyzerError> {
        let response = search_service
            .search(
                crate::search::SearchRequest {
                    query: Self::LAKE_INVENTORY_QUERY.to_string(),
                    time_range: {
                        let end = chrono::Utc::now();
                        crate::search::TimeRangeInput::new(
                            end - chrono::Duration::days(LAKE_INVENTORY_LOOKBACK_DAYS),
                            end,
                        )
                    },
                    limit: Some(LAKE_INVENTORY_LIMIT),
                    offset: None,
                    include_sql: Some(false),
                    skip_histogram: true,
                    skip_field_stats: true,
                    use_cache: true,
                    table_view: false,
                    request_id: None,
                    async_mode: false,
                    priority: None,
                    dataset: Some("logs".to_string()),
                },
                &ScopeSet::unrestricted(),
            )
            .await
            .map_err(|e| CoverageAnalyzerError::Query(e.to_string()))?;

        self.load_lake_rows(&response.results);

        info!(
            source_types = self.available_fields.len(),
            "Refreshed available source types from the lake"
        );
        Ok(())
    }

    /// True when the raw inventory has never been populated.
    ///
    /// Callers use this to decide whether to trigger a refresh. It must be
    /// evaluated against the RAW cache, not a scoped view — otherwise a caller
    /// denied every cached source would re-scan ClickHouse on every request.
    pub fn is_inventory_empty(&self) -> bool {
        self.available_fields.is_empty()
    }

    /// Get list of source types that have logs, filtered to what `access` allows.
    ///
    /// NAN-2081: pass [`LiveInventoryAccess::Scoped`] with the requester's
    /// effective deny set (per-source RBAC ∪ implicit `audit` unless they hold
    /// `audit:view`) only once the live-data capability has been verified;
    /// otherwise pass [`LiveInventoryAccess::Denied`].
    pub fn get_available_source_types(&self, access: &LiveInventoryAccess<'_>) -> Vec<String> {
        let Some(scope) = access.scope() else {
            return Vec::new();
        };
        self.available_fields
            .keys()
            .filter(|source_type| Self::is_visible(source_type, scope))
            .cloned()
            .collect()
    }

    /// Per-source RBAC visibility for one cached source type.
    ///
    /// The deny set is normalized (`trim().to_lowercase()`) by
    /// `SourceScopeResolver`, and every SQL-side gate compares
    /// `lower(source_type)` (see `source_scope_sql_predicate`). The cached value
    /// comes straight out of ClickHouse and may be mixed-case — notably under
    /// the OCSF profile — so it must be normalized the same way before the
    /// membership test, or `Insider_Threat` would slip past a deny entry of
    /// `insider_threat`.
    fn is_visible(source_type: &str, scope: &ScopeSet) -> bool {
        !scope
            .deny_set()
            .contains(&source_type.trim().to_lowercase())
    }

    /// The entries of `inventory` a caller with `scope` is allowed to observe.
    ///
    /// Single source of truth for "which source types may this principal see",
    /// used by both the per-rule coverage decision and the aggregate analysis
    /// (NAN-2081). Internal/system source types are excluded for everyone; the
    /// per-source RBAC deny set (which already carries the implicit `audit`
    /// denial unless the caller holds `audit:view`) removes the rest.
    pub(crate) fn visible_source_types<'a, V>(
        inventory: &'a HashMap<String, V>,
        scope: &ScopeSet,
    ) -> Vec<(&'a String, &'a V)> {
        const EXCLUDED_TYPES: [&str; 3] = ["audit", "findings", "signal"];
        inventory
            .iter()
            .filter(|(source_type, _)| {
                let lowered = source_type.to_lowercase();
                !EXCLUDED_TYPES.contains(&lowered.as_str())
            })
            .filter(|(source_type, _)| Self::is_visible(source_type, scope))
            .collect()
    }

    /// Check coverage for a single rule against the sources `access` permits.
    pub fn check_rule_coverage(
        &self,
        rule: &RepositoryRule,
        access: &LiveInventoryAccess<'_>,
    ) -> CoverageResult {
        check_rule_coverage_in(
            &self.available_fields,
            &self.available_classes,
            rule,
            access,
        )
    }

    /// Analyze coverage for multiple rules against the sources `access` permits.
    pub fn analyze_coverage(
        &self,
        rules: &[RepositoryRule],
        filter: &CoverageFilter,
        access: &LiveInventoryAccess<'_>,
    ) -> CoverageAnalysis {
        // NAN-2081: with no live-data capability there is no analysis to report.
        // Returning per-rule `unknown` verdicts through the aggregator would
        // produce an incoherent shape (N total rules, zero in every bucket)
        // since `CoverageAnalysis` has no `unknown` bucket — so return the empty
        // analysis instead of a misleading one.
        let Some(scope) = access.scope() else {
            return CoverageAnalysis::default();
        };

        // `most_missing_fields[].source_types_with_field` is derived from the raw
        // inventory too, so hand the aggregator a scoped view rather than the
        // shared cache.
        let visible_fields: HashMap<String, HashSet<String>> =
            Self::visible_source_types(&self.available_fields, scope)
                .into_iter()
                .map(|(source_type, fields)| (source_type.clone(), fields.clone()))
                .collect();
        analyze_coverage_with(rules, filter, &visible_fields, |rule| {
            self.check_rule_coverage(rule, access)
        })
    }
}

/// The coverage decision for one rule against an explicit inventory.
///
/// Free-standing (rather than a method) so the authorization behavior can be
/// exercised over a synthetic inventory without a live `DualPool` — the shape
/// the NAN-2081 regressions need.
/// The OCSF event classes a rule needs, read from its own query.
///
/// NAN-2361: under OCSF a rule scopes itself by `class_uid`, not by source —
/// that is the point of normalising (a process launch is 1007 whether it came
/// from Sysmon, CrowdStrike or auditd). The coverage analyzer only ever read the
/// hand-maintained `requires_source_types` field, which no OCSF rule sets, so
/// the importer's SOURCE column was empty for 134 of 144 rules and every rule
/// looked uncovered. Deriving the classes from the query means the answer stays
/// correct as parsers are added, with nothing to hand-maintain.
///
/// Deliberately permissive: it matches `class_uid=1007`, `class_uid = 1007` and
/// `class_uid IN (1007, 1008)` — the three forms the shipped rules use — and
/// ignores anything else. An unrecognised query yields an empty set, which the
/// caller treats as "no class constraint" rather than "no coverage", so a rule
/// this cannot read is never falsely reported as unrunnable.
pub(crate) fn required_class_uids(query: &str) -> std::collections::BTreeSet<i64> {
    let mut out = std::collections::BTreeSet::new();
    let bytes = query.as_bytes();
    let mut idx = 0usize;
    while let Some(found) = query[idx..].find("class_uid") {
        let start = idx + found;
        let mut cursor = start + "class_uid".len();
        while cursor < bytes.len() && (bytes[cursor] as char).is_whitespace() {
            cursor += 1;
        }
        if cursor < bytes.len() && bytes[cursor] == b'=' {
            cursor += 1;
            while cursor < bytes.len() && (bytes[cursor] as char).is_whitespace() {
                cursor += 1;
            }
            let digits_start = cursor;
            while cursor < bytes.len() && (bytes[cursor] as char).is_ascii_digit() {
                cursor += 1;
            }
            if cursor > digits_start {
                if let Ok(v) = query[digits_start..cursor].parse::<i64>() {
                    out.insert(v);
                }
            }
        } else if query[cursor..].to_ascii_uppercase().starts_with("IN") {
            if let Some(open) = query[cursor..].find('(') {
                let list_start = cursor + open + 1;
                if let Some(close) = query[list_start..].find(')') {
                    for part in query[list_start..list_start + close].split(',') {
                        if let Ok(v) = part.trim().parse::<i64>() {
                            out.insert(v);
                        }
                    }
                    cursor = list_start + close;
                }
            }
        }
        idx = cursor.max(start + 1);
    }
    out
}

fn check_rule_coverage_in(
    inventory: &HashMap<String, HashSet<String>>,
    classes: &HashMap<String, HashSet<i64>>,
    rule: &RepositoryRule,
    access: &LiveInventoryAccess<'_>,
) -> CoverageResult {
    let required_fields: HashSet<String> = rule
        .requires_fields
        .as_ref()
        .map(|f| f.iter().cloned().collect())
        .unwrap_or_default();

    let mut suggested_source_types: Vec<String> = rule
        .requires_source_types
        .as_ref()
        .cloned()
        .unwrap_or_default();

    // NAN-2081: no live-data capability → the caller learns nothing about the
    // tenant's telemetry, not even a derived full/partial/none verdict.
    // `required_fields` / `suggested_source_types` come from the repository rule
    // itself (catalog content they may already read), so they stay.
    let Some(scope) = access.scope() else {
        return CoverageResult {
            status: COVERAGE_STATUS_UNKNOWN.to_string(),
            required_fields: required_fields.into_iter().collect(),
            available_fields: Vec::new(),
            missing_fields: Vec::new(),
            suggested_source_types,
            available_source_types: Vec::new(),
        };
    };

    // NAN-2361: an OCSF rule declares no source types — it names the event CLASS
    // it needs (a process launch is 1007 whether it came from Sysmon, CrowdStrike
    // or auditd). Derive the sources from the live class inventory so the
    // importer's SOURCE column shows what would actually run the rule instead of
    // a bare "-". This only fills a gap: a rule that declares its sources keeps
    // them, and a UDM tenant (empty `classes`) is untouched.
    //
    // Deliberately below the capability gate and filtered through the same
    // `visible_source_types` the field inventory uses: these are real
    // source-type names, so a caller denied live data — or denied this
    // source by per-source RBAC — must not learn them from a suggestion
    // (NAN-2081).
    if suggested_source_types.is_empty() && !classes.is_empty() {
        // The nPL lives in `converted_npl` once translated, and otherwise as the
        // body of `raw_content` after the YAML frontmatter. Scanning either is
        // safe: `class_uid` appears only in the query, never in the frontmatter.
        let needed =
            required_class_uids(rule.converted_npl.as_deref().unwrap_or(&rule.raw_content));
        if !needed.is_empty() {
            let mut derived: Vec<String> = CoverageAnalyzer::visible_source_types(classes, scope)
                .into_iter()
                .filter(|(_, emitted)| needed.iter().any(|c| emitted.contains(c)))
                .map(|(source_type, _)| source_type.clone())
                .collect();
            derived.sort();
            suggested_source_types = derived;
        }
    }

    // Find which source types have the required fields
    let mut available_fields = HashSet::new();
    let mut available_source_types = Vec::new();

    // Collect the source types this caller may observe. A source denied by
    // per-source RBAC must not appear in the inventory, the suggestions, or the
    // coverage decision — the preview would otherwise be an existence oracle for
    // telemetry that `GET /api/source-types` and search both hide.
    for (source_type, fields) in CoverageAnalyzer::visible_source_types(inventory, scope) {
        let st_lower = source_type.to_lowercase();

        available_source_types.push(source_type.clone());

        // Check if this source type might be relevant for field tracking
        let is_suggested = suggested_source_types.is_empty()
            || suggested_source_types.iter().any(|s| {
                st_lower.contains(&s.to_lowercase()) || s.to_lowercase().contains(&st_lower)
            });

        if is_suggested {
            // Add fields from this source type
            for field in fields {
                // Map common field names
                let normalized = normalize_field_name(field);
                if required_fields.contains(&normalized) || required_fields.contains(field) {
                    available_fields.insert(field.clone());
                }
            }
        }
    }

    // Sort source types alphabetically
    available_source_types.sort();

    // Calculate missing fields
    let missing_fields: Vec<String> = required_fields
        .iter()
        .filter(|f| {
            !available_fields.contains(*f) && !available_fields.contains(&normalize_field_name(f))
        })
        .cloned()
        .collect();

    // Determine coverage status
    let status = if required_fields.is_empty() || missing_fields.is_empty() {
        "full".to_string()
    } else if available_fields.is_empty() {
        "none".to_string()
    } else {
        "partial".to_string()
    };

    CoverageResult {
        status,
        required_fields: required_fields.into_iter().collect(),
        available_fields: available_fields.into_iter().collect(),
        missing_fields,
        suggested_source_types,
        available_source_types,
    }
}

fn analyze_coverage_with<F>(
    rules: &[RepositoryRule],
    filter: &CoverageFilter,
    available_fields: &HashMap<String, HashSet<String>>,
    check_rule_coverage: F,
) -> CoverageAnalysis
where
    F: Fn(&RepositoryRule) -> CoverageResult,
{
    let mut total = 0;
    let mut full = 0;
    let mut partial = 0;
    let mut none = 0;

    let mut by_severity = CoverageBySeverity::default();
    let mut tactic_counts: HashMap<String, (i32, i32, i32, i32)> = HashMap::new();
    let mut missing_field_counts: HashMap<String, i32> = HashMap::new();
    let mut all_suggested_source_types: HashSet<String> = HashSet::new();

    let filter = filter.normalized();
    for rule in rules.iter().filter(|rule| filter.matches_normalized(rule)) {
        let coverage = check_rule_coverage(rule);
        total += 1;

        // Update overall counts
        match coverage.status.as_str() {
            "full" => full += 1,
            "partial" => partial += 1,
            "none" => none += 1,
            _ => {}
        }

        // Update by severity
        let severity = rule
            .severity
            .as_deref()
            .map(normalize_coverage_severity)
            .unwrap_or_default();
        let severity_counts = match severity.as_str() {
            "critical" => &mut by_severity.critical,
            "high" => &mut by_severity.high,
            "medium" => &mut by_severity.medium,
            "low" => &mut by_severity.low,
            _ => &mut by_severity.informational,
        };
        severity_counts.total += 1;
        match coverage.status.as_str() {
            "full" => severity_counts.full += 1,
            "partial" => severity_counts.partial += 1,
            "none" => severity_counts.none += 1,
            _ => {}
        }

        // Update by tactic
        if let Some(tactics) = &rule.mitre_tactics {
            let canonical_tactics: HashSet<String> = tactics
                .iter()
                .map(|tactic| normalize_coverage_tactic(tactic))
                .collect();
            for tactic in canonical_tactics {
                let counts = tactic_counts.entry(tactic).or_insert((0, 0, 0, 0));
                counts.0 += 1; // total
                match coverage.status.as_str() {
                    "full" => counts.1 += 1,
                    "partial" => counts.2 += 1,
                    "none" => counts.3 += 1,
                    _ => {}
                }
            }
        }

        // Track missing fields
        for field in &coverage.missing_fields {
            *missing_field_counts.entry(field.clone()).or_insert(0) += 1;
        }

        // Track suggested source types
        for st in coverage.suggested_source_types {
            all_suggested_source_types.insert(st);
        }
    }

    // Build tactic coverage list
    let coverage_by_tactic: Vec<TacticCoverage> = tactic_counts
        .into_iter()
        .map(|(tactic, (total, full, partial, none))| TacticCoverage {
            tactic: tactic.clone(),
            tactic_name: tactic_to_name(&tactic),
            total,
            full,
            partial,
            none,
        })
        .collect();

    // Build missing fields list (sorted by count)
    let mut missing_fields: Vec<MissingFieldCount> = missing_field_counts
        .into_iter()
        .map(|(field, count)| {
            let source_types_with_field = available_fields
                .iter()
                .filter(|(_, fields)| fields.contains(&field))
                .map(|(st, _)| st.clone())
                .collect();
            MissingFieldCount {
                field,
                count,
                source_types_with_field,
            }
        })
        .collect();
    missing_fields.sort_by(|a, b| b.count.cmp(&a.count));
    missing_fields.truncate(20); // Top 20

    CoverageAnalysis {
        total_rules: total,
        full_coverage: full,
        partial_coverage: partial,
        no_coverage: none,
        coverage_by_severity: by_severity,
        coverage_by_tactic,
        most_missing_fields: missing_fields,
        suggested_source_types: all_suggested_source_types.into_iter().collect(),
    }
}

/// Normalize field names between Sigma and UDM conventions
fn normalize_field_name(field: &str) -> String {
    // Common mappings from Sigma field names to UDM
    match field.to_lowercase().as_str() {
        "commandline" | "command_line" | "process" => "command_line".to_string(),
        "image" | "process_path" | "processpath" => "process_path".to_string(),
        "parentimage" | "parent_process_path" | "parentprocesspath" => {
            "parent_process_path".to_string()
        }
        "parentcommandline" | "parent_command_line" | "parent_process" => {
            "parent_command_line".to_string()
        }
        "targetfilename" | "target_file_name" | "file_path" | "filepath" => "file_path".to_string(),
        "sourceip" | "src_ip" | "srcip" => "src_ip".to_string(),
        "destinationip" | "dest_ip" | "destip" | "dstip" => "dest_ip".to_string(),
        "sourceport" | "src_port" | "srcport" => "src_port".to_string(),
        "destinationport" | "dest_port" | "destport" | "dstport" => "dest_port".to_string(),
        "user" | "username" | "accountname" | "subjectusername" => "user".to_string(),
        "hashes" | "hash" | "file_hash" | "filehash" => "file_hash".to_string(),
        "originalfilename" | "original_file_name" => "process_original_name".to_string(),
        _ => field.to_lowercase(),
    }
}

/// Convert MITRE tactic ID to human-readable name
fn tactic_to_name(tactic: &str) -> String {
    match tactic.to_lowercase().as_str() {
        "reconnaissance" | "ta0043" => "Reconnaissance".to_string(),
        "resource_development" | "resource-development" | "ta0042" => {
            "Resource Development".to_string()
        }
        "initial_access" | "initial-access" | "ta0001" => "Initial Access".to_string(),
        "execution" | "ta0002" => "Execution".to_string(),
        "persistence" | "ta0003" => "Persistence".to_string(),
        "privilege_escalation" | "privilege-escalation" | "ta0004" => {
            "Privilege Escalation".to_string()
        }
        "defense_evasion" | "defense-evasion" | "ta0005" => "Defense Evasion".to_string(),
        "credential_access" | "credential-access" | "ta0006" => "Credential Access".to_string(),
        "discovery" | "ta0007" => "Discovery".to_string(),
        "lateral_movement" | "lateral-movement" | "ta0008" => "Lateral Movement".to_string(),
        "collection" | "ta0009" => "Collection".to_string(),
        "command_and_control" | "command-and-control" | "c2" | "ta0011" => {
            "Command and Control".to_string()
        }
        "exfiltration" | "ta0010" => "Exfiltration".to_string(),
        "impact" | "ta0040" => "Impact".to_string(),
        _ => tactic.replace('_', " ").replace('-', " "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repository_rule(
        repository_id: uuid::Uuid,
        severity: &str,
        tactics: &[&str],
        techniques: &[&str],
    ) -> RepositoryRule {
        let now = chrono::Utc::now();
        RepositoryRule {
            id: uuid::Uuid::now_v7(),
            repository_id,
            file_path: "rules/example.yml".to_string(),
            file_sha: None,
            raw_content: String::new(),
            title: Some("Example".to_string()),
            description: None,
            severity: Some(severity.to_string()),
            mitre_tactics: Some(tactics.iter().map(|value| (*value).to_string()).collect()),
            mitre_techniques: Some(
                techniques
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            ),
            tags: None,
            requires_fields: None,
            requires_source_types: None,
            conversion_status: "pending".to_string(),
            converted_npl: None,
            conversion_confidence: None,
            conversion_warnings: None,
            conversion_field_mappings: None,
            coverage_status: None,
            coverage_missing_fields: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn full_coverage() -> CoverageResult {
        CoverageResult {
            status: "full".to_string(),
            required_fields: Vec::new(),
            available_fields: Vec::new(),
            missing_fields: Vec::new(),
            suggested_source_types: Vec::new(),
            available_source_types: Vec::new(),
        }
    }

    #[test]
    fn test_normalize_field_name() {
        assert_eq!(normalize_field_name("CommandLine"), "command_line");
        assert_eq!(normalize_field_name("Image"), "process_path");
        assert_eq!(normalize_field_name("SourceIP"), "src_ip");
        assert_eq!(normalize_field_name("user"), "user");
    }

    #[test]
    fn test_tactic_to_name() {
        assert_eq!(tactic_to_name("credential_access"), "Credential Access");
        assert_eq!(tactic_to_name("initial-access"), "Initial Access");
        assert_eq!(tactic_to_name("execution"), "Execution");
    }

    /// NAN-2081: the raw inventory is shared process-wide; every read must be
    /// filtered against the *calling* principal's deny set. These exercise
    /// `CoverageAnalyzer::visible_source_types`, the single gate both
    /// `check_rule_coverage` and `analyze_coverage` route through.
    mod scope_filtering {
        use super::*;
        use std::collections::BTreeSet;

        fn inventory(source_types: &[&str]) -> HashMap<String, HashSet<String>> {
            source_types
                .iter()
                .map(|st| ((*st).to_string(), HashSet::new()))
                .collect()
        }

        fn scope(denied: &[&str]) -> ScopeSet {
            ScopeSet::from_denied(
                denied
                    .iter()
                    .map(|s| (*s).to_string())
                    .collect::<BTreeSet<String>>(),
            )
        }

        fn visible(inv: &HashMap<String, HashSet<String>>, scope: &ScopeSet) -> Vec<String> {
            let mut names: Vec<String> = CoverageAnalyzer::visible_source_types(inv, scope)
                .into_iter()
                .map(|(source_type, _)| source_type.clone())
                .collect();
            names.sort();
            names
        }

        #[test]
        fn denied_source_is_invisible_and_allowed_source_is_visible() {
            let s = scope(&["windows_sysmon", "audit"]);
            assert!(!CoverageAnalyzer::is_visible("windows_sysmon", &s));
            assert!(!CoverageAnalyzer::is_visible("audit", &s));
            assert!(CoverageAnalyzer::is_visible("apache_http_server", &s));
        }

        /// The deny set is normalized by `SourceScopeResolver`, and the SQL gates
        /// compare `lower(source_type)`. A mixed-case or padded value out of
        /// ClickHouse (common under OCSF) must not slip past.
        #[test]
        fn denial_is_case_and_whitespace_insensitive() {
            let s = scope(&["windows_sysmon"]);
            assert!(!CoverageAnalyzer::is_visible("Windows_Sysmon", &s));
            assert!(!CoverageAnalyzer::is_visible("WINDOWS_SYSMON", &s));
            assert!(!CoverageAnalyzer::is_visible("  windows_sysmon  ", &s));
        }

        #[test]
        fn mixed_case_denied_source_is_absent_from_the_visible_inventory() {
            let inv = inventory(&["Windows_Sysmon", "apache_http_server"]);
            assert_eq!(
                visible(&inv, &scope(&["windows_sysmon"])),
                vec!["apache_http_server".to_string()]
            );
        }

        /// NAN-2081: repository visibility is not a live-data capability. A
        /// caller without it must learn nothing about tenant telemetry — not the
        /// inventory, and not a derived coverage verdict.
        #[test]
        fn a_caller_without_live_data_capability_gets_no_inventory_and_no_verdict() {
            let rule = repository_rule(uuid::Uuid::now_v7(), "high", &[], &[]);
            let inv = inventory(&["windows_sysmon", "apache_http_server"]);

            let denied =
                check_rule_coverage_in(&inv, &HashMap::new(), &rule, &LiveInventoryAccess::Denied);
            assert!(denied.available_source_types.is_empty());
            assert!(denied.available_fields.is_empty());
            assert_eq!(denied.status, COVERAGE_STATUS_UNKNOWN);
            assert!(!LiveInventoryAccess::Denied.permits_live_data());

            // With the capability, the same inventory answers normally.
            let unrestricted = ScopeSet::unrestricted();
            let allowed = LiveInventoryAccess::Scoped(&unrestricted);
            let granted = check_rule_coverage_in(&inv, &HashMap::new(), &rule, &allowed);
            assert_eq!(granted.available_source_types.len(), 2);
            assert_ne!(granted.status, COVERAGE_STATUS_UNKNOWN);
            assert!(allowed.permits_live_data());
        }

        /// Both gates compose: the capability lets the inventory through, the
        /// per-source scope still removes the denied entries.
        #[test]
        fn the_capability_gate_and_the_source_scope_compose() {
            let rule = repository_rule(uuid::Uuid::now_v7(), "high", &[], &[]);
            let inv = inventory(&["windows_sysmon", "apache_http_server"]);
            let restricted = scope(&["windows_sysmon"]);

            let result = check_rule_coverage_in(
                &inv,
                &HashMap::new(),
                &rule,
                &LiveInventoryAccess::Scoped(&restricted),
            );
            assert_eq!(
                result.available_source_types,
                vec!["apache_http_server".to_string()]
            );
        }

        #[test]
        fn denied_source_is_absent_from_the_visible_inventory() {
            let inv = inventory(&["windows_sysmon", "apache_http_server", "aws_cloudtrail"]);
            assert_eq!(
                visible(&inv, &scope(&["windows_sysmon"])),
                vec![
                    "apache_http_server".to_string(),
                    "aws_cloudtrail".to_string()
                ]
            );
        }

        #[test]
        fn two_principals_do_not_contaminate_each_other_through_the_shared_cache() {
            let inv = inventory(&["windows_sysmon", "apache_http_server", "aws_cloudtrail"]);

            // Same cache, different grants — each caller sees only their own set,
            // and neither read mutates the inventory for the other.
            let restricted = visible(&inv, &scope(&["windows_sysmon"]));
            let unrestricted = visible(&inv, &ScopeSet::unrestricted());
            let restricted_again = visible(&inv, &scope(&["windows_sysmon"]));

            assert!(!restricted.contains(&"windows_sysmon".to_string()));
            assert!(unrestricted.contains(&"windows_sysmon".to_string()));
            assert_eq!(unrestricted.len(), 3);
            assert_eq!(restricted, restricted_again);
        }

        #[test]
        fn audit_is_denied_without_audit_view_and_internal_types_never_surface() {
            // `effective_source_deny_set()` injects "audit" unless the caller
            // holds `audit:view`; the internal types are excluded for everyone.
            let inv = inventory(&["audit", "findings", "signal", "apache_http_server"]);
            assert_eq!(
                visible(&inv, &scope(&["audit"])),
                vec!["apache_http_server".to_string()]
            );
            assert_eq!(
                visible(&inv, &ScopeSet::unrestricted()),
                vec!["apache_http_server".to_string()]
            );
        }
    }

    #[test]
    fn analyzer_applies_combined_filters_and_canonicalizes_buckets() {
        let repository_id = uuid::Uuid::now_v7();
        let rules = [
            repository_rule(
                repository_id,
                "HIGH",
                &["Credential Access", "TA0006"],
                &["t1059.001"],
            ),
            repository_rule(repository_id, "low", &["Execution"], &["T1059.001"]),
        ];
        let filter = CoverageFilter {
            repository_id: Some(repository_id),
            severity: Some(" high ".to_string()),
            mitre_tactic: Some("ta0006".to_string()),
            mitre_technique: Some("T1059.001".to_string()),
        };

        let analysis = analyze_coverage_with(&rules, &filter, &HashMap::new(), |_| full_coverage());

        assert_eq!(analysis.total_rules, 1);
        assert_eq!(analysis.full_coverage, 1);
        assert_eq!(analysis.coverage_by_severity.high.total, 1);
        assert_eq!(analysis.coverage_by_severity.informational.total, 0);
        assert_eq!(analysis.coverage_by_tactic.len(), 1);
        assert_eq!(analysis.coverage_by_tactic[0].tactic, "TA0006");
        assert_eq!(
            analysis.coverage_by_tactic[0].tactic_name,
            "Credential Access"
        );
        assert_eq!(analysis.coverage_by_tactic[0].total, 1);
    }

    /// The three forms the shipped OCSF rules actually use. Anchored on real
    /// rule bodies: `cobalt_strike_indicators` is the `IN (...)` case, most
    /// others are a bare equality.
    #[test]
    fn class_uids_are_read_from_every_shipped_query_form() {
        assert_eq!(
            required_class_uids("class_uid=1007 | stats count by process.name"),
            [1007].into_iter().collect()
        );
        assert_eq!(
            required_class_uids("class_uid = 1007"),
            [1007].into_iter().collect()
        );
        assert_eq!(
            required_class_uids("class_uid IN (1007, 1008)"),
            [1007, 1008].into_iter().collect()
        );
        assert_eq!(
            required_class_uids("class_uid in (4001,4002)"),
            [4001, 4002].into_iter().collect()
        );
        // Several rules constrain two classes in one query.
        assert_eq!(
            required_class_uids("class_uid=1007 and dst.port=445 or class_uid=4001"),
            [1007, 4001].into_iter().collect()
        );
    }

    /// The safety property: anything this cannot parse must read as "no class
    /// constraint", never as "needs a class nothing emits". A false empty set
    /// loses a suggestion; a false non-empty set marks a good rule unrunnable.
    #[test]
    fn unreadable_queries_yield_no_constraint_rather_than_a_wrong_one() {
        for query in [
            "",
            "search failed_login | stats count by user",
            "class_uid",
            "class_uid =",
            "class_uid = abc",
            "class_uid IN (",
            "eval x = class_uid_total + 1",
            "class_uid IN ()",
        ] {
            assert!(
                required_class_uids(query).is_empty(),
                "expected no constraint from {query:?}"
            );
        }
    }

    /// The bug this fixes: an OCSF rule sets no `requires_source_types`, so the
    /// importer's SOURCE column rendered "-" for 134 of 144 rules. The source is
    /// now derived from the class the rule names and the classes each source has
    /// actually been observed emitting.
    #[test]
    fn source_is_derived_from_the_class_an_ocsf_rule_names() {
        let mut rule = repository_rule(uuid::Uuid::now_v7(), "high", &[], &[]);
        rule.converted_npl = Some("class_uid=1007 | stats count by process.name".to_string());

        let inventory: HashMap<String, HashSet<String>> = [
            ("windows_sysmon".to_string(), HashSet::new()),
            ("aws_cloudtrail".to_string(), HashSet::new()),
            ("apache_access".to_string(), HashSet::new()),
        ]
        .into_iter()
        .collect();
        let classes: HashMap<String, HashSet<i64>> = [
            (
                "windows_sysmon".to_string(),
                [1007, 1005].into_iter().collect(),
            ),
            (
                "aws_cloudtrail".to_string(),
                [3002, 6003].into_iter().collect(),
            ),
            ("apache_access".to_string(), [4002].into_iter().collect()),
        ]
        .into_iter()
        .collect();

        let scope = ScopeSet::unrestricted();
        let result = check_rule_coverage_in(
            &inventory,
            &classes,
            &rule,
            &LiveInventoryAccess::Scoped(&scope),
        );
        assert_eq!(result.suggested_source_types, vec!["windows_sysmon"]);
    }

    /// A rule that declares its sources keeps them — the derivation only fills
    /// a gap, it never overrides curated content.
    #[test]
    fn a_declared_source_list_wins_over_the_derivation() {
        let mut rule = repository_rule(uuid::Uuid::now_v7(), "high", &[], &[]);
        rule.converted_npl = Some("class_uid=1007".to_string());
        rule.requires_source_types = Some(vec!["crowdstrike".to_string()]);

        let inventory: HashMap<String, HashSet<String>> =
            [("windows_sysmon".to_string(), HashSet::new())]
                .into_iter()
                .collect();
        let classes: HashMap<String, HashSet<i64>> =
            [("windows_sysmon".to_string(), [1007].into_iter().collect())]
                .into_iter()
                .collect();

        let scope = ScopeSet::unrestricted();
        let result = check_rule_coverage_in(
            &inventory,
            &classes,
            &rule,
            &LiveInventoryAccess::Scoped(&scope),
        );
        assert_eq!(result.suggested_source_types, vec!["crowdstrike"]);
    }

    /// NAN-2081 applied to the new field: a derived suggestion names REAL source
    /// types, so it must not become an existence oracle for telemetry the caller
    /// is denied — nor reach a caller with no live-data capability at all.
    #[test]
    fn a_derived_suggestion_never_names_a_source_the_caller_is_denied() {
        let mut rule = repository_rule(uuid::Uuid::now_v7(), "high", &[], &[]);
        rule.converted_npl = Some("class_uid=1007".to_string());

        let inventory: HashMap<String, HashSet<String>> = [
            ("windows_sysmon".to_string(), HashSet::new()),
            ("secret_edr".to_string(), HashSet::new()),
        ]
        .into_iter()
        .collect();
        let classes: HashMap<String, HashSet<i64>> = [
            ("windows_sysmon".to_string(), [1007].into_iter().collect()),
            ("secret_edr".to_string(), [1007].into_iter().collect()),
        ]
        .into_iter()
        .collect();

        let restricted = ScopeSet::from_denied(["secret_edr".to_string()].into_iter().collect());
        let scoped = check_rule_coverage_in(
            &inventory,
            &classes,
            &rule,
            &LiveInventoryAccess::Scoped(&restricted),
        );
        assert_eq!(
            scoped.suggested_source_types,
            vec!["windows_sysmon"],
            "a denied source must not surface through the class derivation"
        );

        let denied =
            check_rule_coverage_in(&inventory, &classes, &rule, &LiveInventoryAccess::Denied);
        assert!(
            denied.suggested_source_types.is_empty(),
            "no live-data capability must mean no derived source names"
        );
        assert_eq!(denied.status, COVERAGE_STATUS_UNKNOWN);
    }

    /// A UDM tenant has no class inventory; nothing about its behaviour changes.
    #[test]
    fn an_empty_class_inventory_leaves_udm_behaviour_untouched() {
        let mut rule = repository_rule(uuid::Uuid::now_v7(), "high", &[], &[]);
        rule.converted_npl = Some("class_uid=1007".to_string());

        let inventory: HashMap<String, HashSet<String>> =
            [("windows_sysmon".to_string(), HashSet::new())]
                .into_iter()
                .collect();
        let scope = ScopeSet::unrestricted();
        let result = check_rule_coverage_in(
            &inventory,
            &HashMap::new(),
            &rule,
            &LiveInventoryAccess::Scoped(&scope),
        );
        assert!(result.suggested_source_types.is_empty());
    }
}
