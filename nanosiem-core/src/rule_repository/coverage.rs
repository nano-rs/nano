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
    CoverageAnalysis, CoverageBySeverity, CoverageFilter, CoverageResult, MissingFieldCount,
    RepositoryRule, TacticCoverage,
};

/// Row for ClickHouse source type query
#[derive(clickhouse::Row, Deserialize)]
struct SourceTypeRow {
    source_type: String,
}

#[derive(Debug, Error)]
pub enum CoverageAnalyzerError {
    #[error("ClickHouse not available")]
    ClickHouseUnavailable,

    #[error("Query error: {0}")]
    Query(String),

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

/// Analyzer for checking rule coverage against available log sources
pub struct CoverageAnalyzer {
    dual_pool: Option<DualPool>,
    /// Cache of available fields per source type
    available_fields: HashMap<String, HashSet<String>>,
}

impl CoverageAnalyzer {
    /// Create a new coverage analyzer with DualPool
    pub fn new(dual_pool: DualPool) -> Self {
        Self {
            dual_pool: Some(dual_pool),
            available_fields: HashMap::new(),
        }
    }

    /// Create a coverage analyzer without ClickHouse (limited functionality)
    pub fn new_without_clickhouse() -> Self {
        Self {
            dual_pool: None,
            available_fields: HashMap::new(),
        }
    }

    /// Get available source types from logs (all time)
    pub async fn refresh_available_fields(&mut self) -> Result<(), CoverageAnalyzerError> {
        let dual_pool = self
            .dual_pool
            .as_ref()
            .ok_or(CoverageAnalyzerError::ClickHouseUnavailable)?;

        let ch_client = dual_pool.clickhouse();

        // Query all distinct source types (no time filter)
        let query = r#"
            SELECT DISTINCT source_type
            FROM logs
            WHERE source_type != ''
            ORDER BY source_type
        "#;

        let result = ch_client
            .query(query)
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
        _filter: &CoverageFilter,
    ) -> CoverageAnalysis {
        let mut total = 0;
        let mut full = 0;
        let mut partial = 0;
        let mut none = 0;

        let mut by_severity = CoverageBySeverity::default();
        let mut tactic_counts: HashMap<String, (i32, i32, i32, i32)> = HashMap::new();
        let mut missing_field_counts: HashMap<String, i32> = HashMap::new();
        let mut all_suggested_source_types: HashSet<String> = HashSet::new();

        for rule in rules {
            let coverage = self.check_rule_coverage(rule);
            total += 1;

            // Update overall counts
            match coverage.status.as_str() {
                "full" => full += 1,
                "partial" => partial += 1,
                "none" => none += 1,
                _ => {}
            }

            // Update by severity
            let severity_counts = match rule.severity.as_deref() {
                Some("critical") => &mut by_severity.critical,
                Some("high") => &mut by_severity.high,
                Some("medium") => &mut by_severity.medium,
                Some("low") => &mut by_severity.low,
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
                for tactic in tactics {
                    let counts = tactic_counts.entry(tactic.clone()).or_insert((0, 0, 0, 0));
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
                let source_types_with_field = self
                    .available_fields
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
        "reconnaissance" => "Reconnaissance".to_string(),
        "resource_development" | "resource-development" => "Resource Development".to_string(),
        "initial_access" | "initial-access" => "Initial Access".to_string(),
        "execution" => "Execution".to_string(),
        "persistence" => "Persistence".to_string(),
        "privilege_escalation" | "privilege-escalation" => "Privilege Escalation".to_string(),
        "defense_evasion" | "defense-evasion" => "Defense Evasion".to_string(),
        "credential_access" | "credential-access" => "Credential Access".to_string(),
        "discovery" => "Discovery".to_string(),
        "lateral_movement" | "lateral-movement" => "Lateral Movement".to_string(),
        "collection" => "Collection".to_string(),
        "command_and_control" | "command-and-control" | "c2" => "Command and Control".to_string(),
        "exfiltration" => "Exfiltration".to_string(),
        "impact" => "Impact".to_string(),
        _ => tactic.replace('_', " ").replace('-', " "),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
