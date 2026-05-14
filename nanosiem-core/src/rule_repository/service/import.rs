// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule import operations.
//!
//! Handles importing rules from external repositories into NanoSIEM's
//! detection engine, including format conversion and metadata mapping.

use tracing::info;
use uuid::Uuid;

use crate::models::{NewDetectionRule, RuleMode, Severity};

use super::super::error::RuleRepositoryError;
use super::super::models::{ImportOutcome, ImportRequest, ImportType, RuleImport};
use super::super::npl_parser::parse_npl;
use super::super::sigma_parser::parse_sigma;
use super::helpers::{convert_mitre_tactic_to_id, parse_lookback_to_minutes, to_snake_case};
use super::RuleRepositoryService;

impl RuleRepositoryService {
    // =========================================================================
    // Import Rules
    // =========================================================================

    /// Import a rule from a repository into detection rules.
    ///
    /// Returns the detection-rule ID alongside an [`ImportOutcome`] so the
    /// caller can distinguish a fresh import (`Created`) from re-importing an
    /// existing rule against newer upstream content (`Updated`). When an
    /// import already exists and `upstream_changed` is false, returns
    /// `AlreadyImported` so batch callers can count it as skipped (NAN-673).
    pub async fn import_rule(
        &self,
        repo_id: Uuid,
        path: &str,
        req: ImportRequest,
        user_id: Option<Uuid>,
        materialized_view_generator: &crate::detection::materialized_view::MaterializedViewGenerator,
    ) -> Result<(Uuid, ImportOutcome), RuleRepositoryError> {
        let detection_service = self.detection_service.as_ref().ok_or_else(|| {
            RuleRepositoryError::Internal("Detection service not configured".to_string())
        })?;

        let repo = self.get_repository(repo_id).await?;
        let repo_rule = self.get_rule(repo_id, path).await?;

        // Existing import bookkeeping: skip if already imported AND nothing
        // changed upstream; otherwise fall through to the update path so
        // re-imports refresh the linked detection rule with new content.
        let existing_imports = self
            .imports_repository
            .find_by_repository_rule(repo_rule.id)
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?;
        let existing_import: Option<RuleImport> = existing_imports.into_iter().next();

        if let Some(ref existing) = existing_import {
            if !existing.upstream_changed {
                return Err(RuleRepositoryError::AlreadyImported {
                    import_type: existing.import_type.clone(),
                });
            }
        }

        // Build detection rule based on format
        let reference_url = format!("{}/blob/{}/{}", repo.url, repo.branch, path);

        // Check if this is an nPL rule (native nano format)
        let is_npl_format = repo.rule_format == "nanosiem";

        // Parse source content based on format
        let (npl_parsed, npl_parse_error) = if is_npl_format {
            match parse_npl(&repo_rule.raw_content) {
                Ok(npl) => (Some(npl), None),
                Err(e) => (None, Some(e.to_string())),
            }
        } else {
            (None, None)
        };

        let sigma_parsed = if !is_npl_format {
            parse_sigma(&repo_rule.raw_content).ok()
        } else {
            None
        };

        // Determine the query to use
        let query = if let Some(custom) = req.custom_npl {
            custom
        } else if let Some(ref npl) = npl_parsed {
            // For nPL rules, use the query directly from the parsed rule
            npl.query.clone()
        } else if let Some(converted) = repo_rule.converted_npl.clone() {
            converted
        } else {
            let detail = if let Some(parse_err) = npl_parse_error {
                format!("Failed to parse nPL rule: {}", parse_err)
            } else {
                "No nPL query available. Please provide a custom query or convert the rule first."
                    .to_string()
            };
            return Err(RuleRepositoryError::ConversionFailed(detail));
        };

        // Build the detection rule
        // Convert name to snake_case
        let raw_name = req.name.unwrap_or_else(|| {
            repo_rule
                .title
                .clone()
                .unwrap_or_else(|| path.split('/').last().unwrap_or(path).to_string())
        });
        let name = to_snake_case(&raw_name);

        // Clean description - remove escaped quotes
        let description = repo_rule.description.as_ref().map(|d| {
            d.replace("\\\"", "\"")
                .replace("\\'", "'")
                .trim()
                .to_string()
        });

        // Extract author
        let author = if let Some(ref npl) = npl_parsed {
            npl.author.clone()
        } else {
            sigma_parsed.as_ref().and_then(|r| r.author.clone())
        };

        // Build AI triage hints based on format
        let ai_triage_hints = if let Some(ref npl) = npl_parsed {
            // For nPL rules, use ai_triage_hints directly from the rule
            npl.ai_triage_hints
                .as_ref()
                .map(|hints| crate::models::AiTriageHints {
                    ignore_when: hints.ignore_when.clone(),
                    suspicious_when: hints.suspicious_when.clone(),
                    context: hints.context.clone(),
                })
        } else {
            // For Sigma rules, build from false positives + AI hints
            let sigma_falsepositives: Vec<String> = sigma_parsed
                .as_ref()
                .map(|sigma_rule| sigma_rule.falsepositives.clone())
                .unwrap_or_default()
                .into_iter()
                .filter(|fp| {
                    let lower = fp.to_lowercase();
                    lower != "unknown" && lower != "none" && lower != "n/a" && !lower.is_empty()
                })
                .collect();

            if sigma_falsepositives.is_empty() && req.ai_triage_hints.is_none() {
                None
            } else {
                let ai_hints = req.ai_triage_hints.clone().unwrap_or_default();
                Some(crate::models::AiTriageHints {
                    ignore_when: sigma_falsepositives,
                    suspicious_when: ai_hints.suspicious_when,
                    context: ai_hints.context,
                })
            }
        };

        // Determine severity
        let severity_str = req
            .severity
            .clone()
            .or_else(|| npl_parsed.as_ref().and_then(|n| n.severity.clone()))
            .or(repo_rule.severity.clone())
            .unwrap_or_else(|| "medium".to_string());

        let severity = match severity_str.as_str() {
            "critical" => Severity::Critical,
            "high" => Severity::High,
            "medium" => Severity::Medium,
            "low" => Severity::Low,
            _ => Severity::Informational,
        };

        // Determine mode - for nPL rules, use the mode from the rule
        let mode = if let Some(mode_str) = req.mode.as_deref() {
            match mode_str {
                "live" => RuleMode::Live,
                "alerting" => RuleMode::Alerting,
                _ => RuleMode::Staging,
            }
        } else if let Some(ref npl) = npl_parsed {
            match npl.mode.as_deref() {
                Some("live") => RuleMode::Live,
                Some("alerting") => RuleMode::Alerting,
                _ => RuleMode::Staging,
            }
        } else {
            RuleMode::Staging
        };

        // Determine detection mode and schedule for nPL rules
        let (detection_mode, schedule_cron, lookback_minutes) = if let Some(ref npl) = npl_parsed {
            let det_mode = match npl.detection_mode.as_deref() {
                Some("realtime") => crate::models::DetectionMode::RealTime,
                _ => crate::models::DetectionMode::Scheduled,
            };
            let schedule = npl
                .schedule
                .clone()
                .or_else(|| Some("*/30 * * * *".to_string()));
            let lookback = npl
                .lookback
                .as_ref()
                .and_then(|l| parse_lookback_to_minutes(l));
            (det_mode, schedule, lookback)
        } else {
            (
                crate::models::DetectionMode::Scheduled,
                Some("*/30 * * * *".to_string()),
                None,
            )
        };

        // Convert MITRE tactics from names to IDs (e.g., "credential-access" -> "TA0006")
        let mitre_tactics = repo_rule.mitre_tactics.as_ref().map(|tactics| {
            tactics
                .iter()
                .map(|t| convert_mitre_tactic_to_id(t))
                .collect()
        });

        // Use tags from nPL rule if available, otherwise default to "sigma"
        let tags = if let Some(ref npl) = npl_parsed {
            if npl.tags.is_empty() {
                Some(vec!["nano".to_string()])
            } else {
                Some(npl.tags.clone())
            }
        } else {
            Some(vec!["sigma".to_string()])
        };

        let new_rule = NewDetectionRule {
            name,
            description,
            query,
            severity,
            mitre_tactics,
            mitre_techniques: repo_rule.mitre_techniques.clone(),
            schedule_cron,
            mode: Some(mode),
            narrative: None,
            reference_url: Some(reference_url),
            author,
            tags,
            ai_generated: Some(npl_parsed.is_none() && repo_rule.converted_npl.is_some()), // Only AI-generated for Sigma conversions
            realtime_enabled: Some(detection_mode == crate::models::DetectionMode::RealTime),
            risk_score: None,
            risk_entity_field: None,
            risk_modifiers: None,
            detection_mode: Some(detection_mode),
            lookback_minutes,
            auto_tuning_enabled: Some(true),
            auto_tuning_min_confidence: Some(0.8),
            auto_tuning_critical: Some(false),
            ai_triage_hints,
            folder: req
                .folder
                .clone()
                .or_else(|| npl_parsed.as_ref().and_then(|n| n.folder.clone()))
                .map(|f| f.to_lowercase()),
            case_visibility: None,
            case_group_ids: None,
            case_assigned_group: None,
            alert_mode: None,
            // Repository-imported rules default to no playbook. Analysts can
            // opt into specific/adaptive selection via the rule editor after
            // import; we don't plumb playbook_id through frontmatter today
            // because the repo playbooks UUIDs are local-only.
            playbook_selector_mode: None,
            playbook_id: None,
        };

        // Check if a detection rule with this name already exists from this repo.
        // This catches duplicates that slip past the rule_imports check (e.g., race
        // conditions from concurrent batch imports, or re-imports after DB cleanup).
        let existing_by_name: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM detection_rules WHERE name = $1 AND source_repository_id = $2 LIMIT 1",
        )
        .bind(&new_rule.name)
        .bind(repo_id)
        .fetch_optional(&self.pg_pool)
        .await
        .map_err(|e| RuleRepositoryError::Database(e))?;

        if let Some(existing_id) = existing_by_name {
            info!(
                "Rule '{}' already exists from this repo (id={}), updating instead of creating",
                new_rule.name, existing_id
            );

            // Update the existing rule's query, severity, and metadata
            sqlx::query(
                r#"
                UPDATE detection_rules
                SET query = $2, description = $3, severity = $4,
                    mitre_tactics = $5, mitre_techniques = $6,
                    schedule_cron = $7, lookback_minutes = $8,
                    tags = $9, source_rule_path = $10,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(existing_id)
            .bind(&new_rule.query)
            .bind(&new_rule.description)
            .bind(format!("{:?}", new_rule.severity).to_lowercase())
            .bind(new_rule.mitre_tactics.as_deref())
            .bind(new_rule.mitre_techniques.as_deref())
            .bind(&new_rule.schedule_cron)
            .bind(new_rule.lookback_minutes)
            .bind(new_rule.tags.as_deref())
            .bind(path)
            .execute(&self.pg_pool)
            .await
            .map_err(|e| RuleRepositoryError::Database(e))?;

            // Sync next_run_at in case mode/schedule changed
            if let Ok(rule) = detection_service.get_rule(existing_id).await {
                detection_service.sync_next_run_at(&rule).await;
            }

            // Mark the import record as synced so the row drops out of the
            // "updates available" view immediately — without this, the rule
            // stays UPDATED until the next repo sync rediscovers parity.
            if let (Some(ref existing), Some(commit)) =
                (&existing_import, repo.last_sync_commit.as_deref())
            {
                self.imports_repository
                    .update_sync(existing.id, commit)
                    .await
                    .map_err(|e| RuleRepositoryError::from_repo_error(e))?;
            }

            return Ok((existing_id, ImportOutcome::Updated));
        }

        // Create the detection rule
        let detection_rule = detection_service
            .create_rule_with_mode(new_rule, materialized_view_generator)
            .await
            .map_err(|e| RuleRepositoryError::DetectionService(e.to_string()))?;

        // Set next_run_at so the distributed scheduler picks up the rule immediately
        detection_service.sync_next_run_at(&detection_rule).await;

        // Update detection_rules with source info
        sqlx::query(
            r#"
            UPDATE detection_rules
            SET source_repository_id = $2, source_rule_path = $3, source_linked = $4, requires_fields = $5
            WHERE id = $1
            "#
        )
        .bind(detection_rule.id)
        .bind(repo_id)
        .bind(path)
        .bind(matches!(req.import_type, ImportType::Linked))
        .bind(&repo_rule.requires_fields)
        .execute(&self.pg_pool)
        .await
        .map_err(|e| RuleRepositoryError::Database(e))?;

        // Build customizations JSON to track source_type overrides for diff reapplication
        let customizations = {
            let mut cust = serde_json::Map::new();

            if let Some(ref mappings) = req.source_type_mappings {
                let filtered: std::collections::HashMap<&String, &String> = mappings
                    .iter()
                    .filter(|(_, v)| !v.is_empty() && *v != "__skip__")
                    .collect();
                if !filtered.is_empty() {
                    cust.insert(
                        "source_type_mappings".to_string(),
                        serde_json::to_value(&filtered).unwrap_or_default(),
                    );
                }
            }

            if let Some(ref merged) = req.merge_to_single_source_type {
                if !merged.is_empty() {
                    cust.insert(
                        "merge_to_single_source_type".to_string(),
                        serde_json::Value::String(merged.clone()),
                    );
                }
            }

            if let Some(ref sev) = req.severity {
                cust.insert(
                    "severity_override".to_string(),
                    serde_json::Value::String(sev.clone()),
                );
            }

            if cust.is_empty() {
                None
            } else {
                Some(serde_json::Value::Object(cust))
            }
        };

        // Create the import record
        self.imports_repository
            .create(
                repo_rule.id,
                detection_rule.id,
                &req.import_type.to_string(),
                user_id,
                repo.last_sync_commit.as_deref(),
                customizations,
            )
            .await
            .map_err(|e| RuleRepositoryError::from_repo_error(e))?;

        info!(
            "Imported rule {} from {}/{} as {:?}",
            detection_rule.id, repo.name, path, req.import_type
        );

        Ok((detection_rule.id, ImportOutcome::Created))
    }
}
