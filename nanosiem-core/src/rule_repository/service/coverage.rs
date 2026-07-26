// SPDX-License-Identifier: AGPL-3.0-or-later

//! Coverage analysis operations.
//!
//! Handles refreshing coverage data from ClickHouse and analyzing
//! rule coverage across repositories.

use super::super::coverage::LiveInventoryAccess;

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

    /// Get coverage analysis for a repository, scoped to the caller.
    ///
    /// NAN-2081: the shared coverage cache is raw live telemetry. `access`
    /// carries BOTH gates — the caller's live-data capability and, when present,
    /// their effective per-source deny set — so the analysis never reveals a
    /// source the caller could not enumerate directly.
    pub async fn get_coverage_analysis(
        &self,
        filter: CoverageFilter,
        access: &LiveInventoryAccess<'_>,
    ) -> Result<CoverageAnalysis, RuleRepositoryError> {
        let filter = filter.normalized();

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
        Ok(analyzer.analyze_coverage(&rules, &filter, access))
    }
}
