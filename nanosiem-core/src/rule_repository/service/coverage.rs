// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coverage analysis operations.
//!
//! Handles refreshing coverage data from ClickHouse and analyzing
//! rule coverage across repositories.

use super::super::error::RuleRepositoryError;
use super::super::models::{CoverageAnalysis, CoverageFilter, RepositoryRuleFilter};
use super::RuleRepositoryService;

impl RuleRepositoryService {
    // =========================================================================
    // Coverage Analysis
    // =========================================================================

    /// Refresh available field data from ClickHouse
    pub async fn refresh_coverage_data(&self) -> Result<(), RuleRepositoryError> {
        let mut analyzer = self.coverage_analyzer.write().await;
        analyzer
            .refresh_available_fields()
            .await
            .map_err(|e| RuleRepositoryError::CoverageAnalysis(e.to_string()))
    }

    /// Get coverage analysis for a repository
    pub async fn get_coverage_analysis(
        &self,
        filter: CoverageFilter,
    ) -> Result<CoverageAnalysis, RuleRepositoryError> {
        // Get rules to analyze
        let rules = if let Some(repo_id) = filter.repository_id {
            self.list_rules(repo_id, RepositoryRuleFilter::default())
                .await?
        } else {
            // Get rules from all repositories
            let repos = self.list_repositories().await?;
            let mut all_rules = Vec::new();
            for repo in repos {
                if let Ok(rules) = self
                    .list_rules(repo.id, RepositoryRuleFilter::default())
                    .await
                {
                    all_rules.extend(rules);
                }
            }
            all_rules
        };

        let analyzer = self.coverage_analyzer.read().await;
        Ok(analyzer.analyze_coverage(&rules, &filter))
    }
}
