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
            .refresh_available_fields(self.search_service.as_deref())
            .await
            .map_err(|e| RuleRepositoryError::CoverageAnalysis(e.to_string()))
    }

    /// Per-rule source suggestions for a page of repository rules, in one pass.
    ///
    /// NAN-2361: the rule browser's SOURCE column reads the rule's own
    /// `requires_source_types`, which an OCSF rule never sets — it scopes itself
    /// by `class_uid` instead — so 60 of 144 shipped rules rendered a bare "-".
    /// This returns what each rule's class actually resolves to against live
    /// telemetry, for the browser to fall back on.
    ///
    /// Derived per request rather than stored: the answer changes as parsers are
    /// deployed, and it is a different claim from the curated
    /// `requires_source_types` — conflating the two would make a derived guess
    /// look like repository content.
    ///
    /// Returns an empty map for a caller with no live-data capability, and never
    /// names a source their per-source RBAC scope hides (both enforced inside
    /// `check_rule_coverage`).
    pub async fn suggested_source_types_for(
        &self,
        rules: &[super::super::models::RepositoryRule],
        access: &LiveInventoryAccess<'_>,
    ) -> std::collections::HashMap<uuid::Uuid, Vec<String>> {
        // A caller who may not observe live telemetry must not be able to
        // trigger a tenant-wide inventory scan either (NAN-2081).
        if !access.permits_live_data() || rules.is_empty() {
            return std::collections::HashMap::new();
        }

        // Refresh once for the whole page, and only on a cold cache — judged on
        // the RAW cache, not this caller's scoped view.
        {
            let analyzer = self.coverage_analyzer.read().await;
            if analyzer.is_inventory_empty() {
                drop(analyzer);
                let mut analyzer = self.coverage_analyzer.write().await;
                if let Err(e) = analyzer
                    .refresh_available_fields(self.search_service.as_deref())
                    .await
                {
                    tracing::warn!("Failed to refresh coverage data: {}", e);
                }
            }
        }

        let analyzer = self.coverage_analyzer.read().await;
        rules
            .iter()
            .filter_map(|rule| {
                let suggested = analyzer
                    .check_rule_coverage(rule, access)
                    .suggested_source_types;
                (!suggested.is_empty()).then(|| (rule.id, suggested))
            })
            .collect()
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
