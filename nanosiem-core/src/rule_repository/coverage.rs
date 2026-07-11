// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coverage analysis for repository rules
//!
//! Analyzes which rules can run based on available log sources and UDM fields.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use tracing::info;

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

/// Analyzer for checking rule coverage against available log sources
pub struct CoverageAnalyzer {
    dual_pool: DualPool,
    /// Cache of available fields per source type
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

    /// Get list of source types that have logs
    pub fn get_available_source_types(&self) -> Vec<String> {
        self.available_fields.keys().cloned().collect()
    }

    /// Check coverage for a single rule
    pub fn check_rule_coverage(&self, rule: &RepositoryRule) -> CoverageResult {
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

        // Find which source types have the required fields
        let mut available_fields = HashSet::new();
        let mut available_source_types = Vec::new();

        // Collect all available source types (excluding internal types)
        let excluded_types = ["audit", "findings", "signal"];
        for (source_type, fields) in &self.available_fields {
            // Skip internal/system source types
            let st_lower = source_type.to_lowercase();
            if excluded_types.iter().any(|ex| st_lower == *ex) {
                continue;
            }

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
                !available_fields.contains(*f)
                    && !available_fields.contains(&normalize_field_name(f))
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

    /// Analyze coverage for multiple rules
    pub fn analyze_coverage(
        &self,
        rules: &[RepositoryRule],
        filter: &CoverageFilter,
    ) -> CoverageAnalysis {
        analyze_coverage_with(rules, filter, &self.available_fields, |rule| {
            self.check_rule_coverage(rule)
        })
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
