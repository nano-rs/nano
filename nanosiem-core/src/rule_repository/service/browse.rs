// SPDX-License-Identifier: AGPL-3.0-or-later

//! Browse operations for repository rules.
//!
//! Handles listing, retrieving, and previewing rules from
//! synced repositories before import.

use tracing::warn;
use uuid::Uuid;

use super::super::error::RuleRepositoryError;
use super::super::models::{
    ImportPreview, RepositoryRule, RepositoryRuleFilter, RuleImport, SourceTypeSuggestion,
};
use super::super::npl_parser::{parse_npl, validate_source_types};
use super::RuleRepositoryService;

impl RuleRepositoryService {
    // =========================================================================
    // Browse Rules
    // =========================================================================

    /// List rules in a repository
    pub async fn list_rules(
        &self,
        repo_id: Uuid,
        filter: RepositoryRuleFilter,
    ) -> Result<Vec<RepositoryRule>, RuleRepositoryError> {
        // Verify repository exists
        let _ = self.get_repository(repo_id).await?;

        self.rules_repository
            .list(repo_id, &filter)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))
    }

    /// Get all imports for rules in a repository
    pub async fn get_imports_for_repository(
        &self,
        repo_id: Uuid,
    ) -> Result<Vec<RuleImport>, RuleRepositoryError> {
        self.imports_repository
            .list_for_repository(repo_id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))
    }

    /// Delete an import record by ID
    pub async fn delete_import(&self, import_id: Uuid) -> Result<(), RuleRepositoryError> {
        self.imports_repository
            .delete(import_id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))
    }

    /// Get a specific rule
    pub async fn get_rule(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<RepositoryRule, RuleRepositoryError> {
        self.rules_repository
            .find_by_path(repo_id, path)
            .await
            .map_err(|_| RuleRepositoryError::RuleNotFound {
                repo_id,
                path: path.to_string(),
            })
    }

    /// Preview importing a rule
    pub async fn preview_import(
        &self,
        repo_id: Uuid,
        path: &str,
    ) -> Result<ImportPreview, RuleRepositoryError> {
        let repo = self.get_repository(repo_id).await?;
        let repo_rule = self.get_rule(repo_id, path).await?;

        // Check if already imported
        let existing_import = self
            .imports_repository
            .find_by_repository_rule(repo_rule.id)
            .await
            .ok()
            .and_then(|imports| imports.into_iter().next());

        let (already_imported, existing_import_type, existing_detection_rule_id) =
            if let Some(import) = existing_import {
                (
                    true,
                    Some(import.import_type),
                    Some(import.detection_rule_id),
                )
            } else {
                (false, None, None)
            };

        // Build preview
        let proposed_name = repo_rule
            .title
            .clone()
            .unwrap_or_else(|| path.split('/').last().unwrap_or(path).to_string());

        let proposed_severity = repo_rule
            .severity
            .clone()
            .unwrap_or_else(|| "medium".to_string());

        // Auto-refresh coverage data if empty (first use)
        {
            let analyzer = self.coverage_analyzer.read().await;
            if analyzer.get_available_source_types().is_empty() {
                drop(analyzer); // Release read lock before acquiring write lock
                let mut analyzer = self.coverage_analyzer.write().await;
                if let Err(e) = analyzer.refresh_available_fields().await {
                    warn!("Failed to refresh coverage data: {}", e);
                }
            }
        }

        let coverage = {
            let analyzer = self.coverage_analyzer.read().await;
            analyzer.check_rule_coverage(&repo_rule)
        };

        // Validate source types
        let required_source_types = repo_rule.requires_source_types.clone().unwrap_or_default();
        let source_type_validation =
            validate_source_types(&required_source_types, &coverage.available_source_types);

        // Convert suggestions to model type
        let source_type_suggestions: Vec<SourceTypeSuggestion> = source_type_validation
            .suggestions
            .into_iter()
            .map(|s| SourceTypeSuggestion {
                missing_type: s.missing_type,
                suggested_type: s.suggested_type,
                reason: s.reason,
            })
            .collect();

        // Determine the proposed query - for nPL rules, extract just the query portion
        let proposed_query = if repo.rule_format == "nanosiem" {
            // Parse nPL rule to extract just the query
            parse_npl(&repo_rule.raw_content).ok().map(|npl| npl.query)
        } else {
            // For Sigma rules, use the converted nPL if available
            repo_rule.converted_npl.clone()
        };

        Ok(ImportPreview {
            repository_rule: repo_rule.clone(),
            proposed_name,
            proposed_description: repo_rule.description.clone(),
            proposed_severity,
            proposed_query,
            proposed_mitre_tactics: repo_rule.mitre_tactics.clone().unwrap_or_default(),
            proposed_mitre_techniques: repo_rule.mitre_techniques.clone().unwrap_or_default(),
            conversion_status: repo_rule.conversion_status,
            conversion_confidence: repo_rule.conversion_confidence,
            conversion_warnings: repo_rule.conversion_warnings.clone().unwrap_or_default(),
            field_mappings: repo_rule.conversion_field_mappings.clone(),
            coverage_status: Some(coverage.status),
            missing_fields: coverage.missing_fields,
            available_source_types: coverage.available_source_types,
            required_source_types,
            missing_source_types: source_type_validation.missing,
            source_type_suggestions,
            already_imported,
            existing_import_type,
            existing_detection_rule_id,
        })
    }
}
