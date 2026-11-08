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
    dual_pool: DualPool,
    /// Raw, unscoped cache of available fields per source type. Never returned
    /// directly — always filtered through the calling principal's scope.
    available_fields: HashMap<String, HashSet<String>>,
}

impl CoverageAnalyzer {
    /// Create a new coverage analyzer with DualPool
    pub fn new(dual_pool: DualPool) -> Self {
        Self {
            dual_pool,
            available_fields: HashMap::new(),
        }
    }

    /// Get available source types from logs (all time)
    pub async fn refresh_available_fields(&mut self) -> Result<(), CoverageAnalyzerError> {
        let ch_client = self.dual_pool.clickhouse();

        // Query all distinct source types (no time filter).
        // NAN-1241: read the active ingested-events table (ocsf_logs under OCSF)
        // so rule coverage sees the source types that actually exist. UDM-identical.
        // NAN-1728 (H5): route through the `_distributed` wrapper on a cluster so
        // DISTINCT source_type sees source types on ALL shards (otherwise rules
        // whose data landed on another shard are falsely reported as having no
        // matching data); bare local name on single-node (byte-identical).
        let logs_table = self
            .dual_pool
            .table_names()
            .read_bare(crate::schema::active_logs_table());
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

        self.available_fields.clear();
        for row in result {
            // Store source type with empty field set (fields not tracked for now)
            self.available_fields
                .insert(row.source_type, HashSet::new());
        }

        info!(
            "Refreshed available source types: {} found",
            self.available_fields.len()
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
    pub(crate) fn visible_source_types<'a>(
        inventory: &'a HashMap<String, HashSet<String>>,
        scope: &ScopeSet,
    ) -> Vec<(&'a String, &'a HashSet<String>)> {
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
        check_rule_coverage_in(&self.available_fields, rule, access)
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
fn check_rule_coverage_in(
    inventory: &HashMap<String, HashSet<String>>,
    rule: &RepositoryRule,
    access: &LiveInventoryAccess<'_>,
) -> CoverageResult {
    let required_fields: HashSet<String> = rule
        .requires_fields
        .as_ref()
        .map(|f| f.iter().cloned().collect())
        .unwrap_or_default();

    let suggested_source_types: Vec<String> = rule
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

            let denied = check_rule_coverage_in(&inv, &rule, &LiveInventoryAccess::Denied);
            assert!(denied.available_source_types.is_empty());
            assert!(denied.available_fields.is_empty());
            assert_eq!(denied.status, COVERAGE_STATUS_UNKNOWN);
            assert!(!LiveInventoryAccess::Denied.permits_live_data());

            // With the capability, the same inventory answers normally.
            let unrestricted = ScopeSet::unrestricted();
            let allowed = LiveInventoryAccess::Scoped(&unrestricted);
            let granted = check_rule_coverage_in(&inv, &rule, &allowed);
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

            let result =
                check_rule_coverage_in(&inv, &rule, &LiveInventoryAccess::Scoped(&restricted));
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
}
