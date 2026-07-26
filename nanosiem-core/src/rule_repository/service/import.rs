// SPDX-License-Identifier: AGPL-3.0-or-later

//! Rule import operations.
//!
//! Handles importing rules from external repositories into NanoSIEM's
//! detection engine, including format conversion and metadata mapping.

use tracing::{info, warn};
use uuid::Uuid;

use crate::auth::{TargetEffect, TargetGrants};
use crate::models::{NewDetectionRule, RuleMode, Severity};

use super::super::error::RuleRepositoryError;
use super::super::models::{ImportOutcome, ImportRequest, ImportType, RuleImport};
use super::super::npl_parser::parse_npl;
use super::super::sigma_parser::parse_sigma;
use super::helpers::{convert_mitre_tactic_to_id, parse_lookback_to_minutes, to_snake_case};
use super::RuleRepositoryService;

/// What a repository import will do to the *detection* it targets.
///
/// Preflighted by [`RuleRepositoryService::plan_import`] so a handler can
/// enforce the complete capability policy (and reject a whole batch) before any
/// AI conversion, credit charge, materialized-view work, or database write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleImportAction {
    /// Mints a brand-new detection rule (`detections:create`).
    Create,
    /// Rewrites the linked/duplicate detection rule in place (`detections:edit`).
    Update,
    /// Already imported with no upstream change — `import_rule` will return
    /// `AlreadyImported` and write nothing, so no target capability is consumed.
    Skip,
}

/// Outcome-aware authorization plan for one rule import (NAN-2118).
#[derive(Debug, Clone)]
pub struct RuleImportPlan {
    pub action: RuleImportAction,
    /// True when the import would cross the `detections:promote` boundary:
    /// for a create, landing outside Staging or provisioning real-time
    /// execution (`requires_promote_for_create`); for an update, changing the
    /// schedule, downgrading severity, or shortening/introducing the lookback
    /// (`requires_promote_for_update`).
    pub requires_promote: bool,
    /// snake_case detection-rule name this import resolves to. Batch callers use
    /// it to detect two paths converging on the same target within one request.
    pub resolved_name: String,
}

impl RuleImportPlan {
    /// The target-resource capabilities this import will consume, in the order a
    /// handler should enforce them.
    pub fn required_effects(&self) -> Vec<TargetEffect> {
        let mut effects = match self.action {
            RuleImportAction::Create => vec![TargetEffect::DetectionCreate],
            RuleImportAction::Update => vec![TargetEffect::DetectionEdit],
            RuleImportAction::Skip => Vec::new(),
        };
        // A skipped import writes nothing, so it never crosses the promotion
        // boundary either.
        if self.requires_promote && !matches!(self.action, RuleImportAction::Skip) {
            effects.push(TargetEffect::DetectionPromote);
        }
        effects
    }
}

/// Resolve the detection-rule name an import will land on.
///
/// Shared by [`RuleRepositoryService::plan_import`] and
/// [`RuleRepositoryService::import_rule`] so the preflight's create-vs-update
/// decision keys off the byte-identical name the write path uses.
pub(crate) fn resolve_import_name(
    requested: Option<&str>,
    repo_rule_title: Option<&str>,
    path: &str,
) -> String {
    let raw = requested
        .map(str::to_string)
        .or_else(|| repo_rule_title.map(str::to_string))
        .unwrap_or_else(|| path.split('/').next_back().unwrap_or(path).to_string());
    to_snake_case(&raw)
}

/// Every lifecycle-bearing field the resulting detection will carry.
///
/// Derived ONCE from `(req, repo_rule, npl)` and consumed by both
/// [`RuleRepositoryService::plan_import`] and
/// [`RuleRepositoryService::import_rule`], so the authorization preflight and
/// the write path can never disagree about what the import produces.
pub(crate) struct ImportLifecycle {
    pub(crate) mode: RuleMode,
    pub(crate) realtime: bool,
    pub(crate) severity: Severity,
    pub(crate) detection_mode: crate::models::DetectionMode,
    pub(crate) schedule_cron: Option<String>,
    pub(crate) lookback_minutes: Option<i32>,
}

impl ImportLifecycle {
    pub(crate) fn resolve(
        req: &ImportRequest,
        repo_rule_severity: Option<&str>,
        npl: Option<&crate::rule_repository::NplRule>,
    ) -> Self {
        let mode = if let Some(mode_str) = req.mode.as_deref() {
            match mode_str {
                "live" => RuleMode::Live,
                "alerting" => RuleMode::Alerting,
                _ => RuleMode::Staging,
            }
        } else {
            match npl.and_then(|n| n.mode.as_deref()) {
                Some("live") => RuleMode::Live,
                Some("alerting") => RuleMode::Alerting,
                _ => RuleMode::Staging,
            }
        };

        let severity_str = req
            .severity
            .clone()
            .or_else(|| npl.and_then(|n| n.severity.clone()))
            .or_else(|| repo_rule_severity.map(str::to_string))
            .unwrap_or_else(|| "medium".to_string());
        let severity = parse_severity(&severity_str);

        let (detection_mode, schedule_cron, lookback_minutes) = if let Some(npl) = npl {
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

        Self {
            mode,
            realtime: detection_mode == crate::models::DetectionMode::RealTime,
            severity,
            detection_mode,
            schedule_cron,
            lookback_minutes,
        }
    }

    /// The `detections:promote` predicate for the CREATE branch, mirroring
    /// `nanosiem-api::handlers::detections::crud::requires_promote_for_create`:
    /// creating outside Staging, or provisioning a real-time materialized view,
    /// skips the Staging → Live → Alerting boundary.
    pub(crate) fn requires_promote_for_create(&self) -> bool {
        self.mode != RuleMode::Staging || self.realtime
    }

    /// The `detections:promote` predicate for the UPDATE branch, mirroring the
    /// reachable arms of
    /// `nanosiem-api::handlers::detections::crud::requires_promote_for_update`.
    ///
    /// The repository update rewrites `severity`, `schedule_cron` and
    /// `lookback_minutes` on a possibly-live detection, and the canonical
    /// `PUT /api/rules/{id}` gates a schedule change, a severity DOWNGRADE, and a
    /// shortened/newly-introduced lookback behind `detections:promote`. Without
    /// this, `rule_repositories:import` + `detections:edit` would be a cheaper
    /// route to those production changes.
    ///
    /// The create-branch predicate deliberately does NOT apply here: the update
    /// SQL writes neither `mode` nor `detection_mode` nor `realtime_enabled`, so
    /// re-importing an nPL rule whose frontmatter says `mode: live` promotes
    /// nothing — the target keeps whatever lifecycle state it already had. Gating
    /// it on the requested mode would make a plain content refresh cost more than
    /// the equivalent `PUT /api/rules/{id}`, which requires only `detections:edit`
    /// when no protected field actually changes.
    pub(crate) fn requires_promote_for_update(&self, existing: &ExistingImportTarget) -> bool {
        // Unparseable stored severity → assume the worst and demand promote.
        let Some(old_severity) = existing.severity.as_deref().and_then(try_parse_severity) else {
            return true;
        };
        if severity_rank(self.severity) < severity_rank(old_severity) {
            return true;
        }
        if self.schedule_cron.as_deref() != existing.schedule_cron.as_deref() {
            return true;
        }
        match (self.lookback_minutes, existing.lookback_minutes) {
            (Some(new_lookback), Some(old_lookback)) if new_lookback < old_lookback => true,
            (Some(_), None) => true,
            _ => false,
        }
    }
}

/// The columns of an existing repository-imported detection that the update
/// branch overwrites and that the promotion policy compares against.
pub(crate) struct ExistingImportTarget {
    pub(crate) id: Uuid,
    pub(crate) dataset: Option<String>,
    pub(crate) risk_score: Option<i32>,
    pub(crate) severity: Option<String>,
    pub(crate) schedule_cron: Option<String>,
    pub(crate) lookback_minutes: Option<i32>,
}

/// Severity ordering, mirroring
/// `nanosiem-api::handlers::detections::crud::severity_rank`.
pub(crate) fn severity_rank(severity: Severity) -> u8 {
    match severity {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::Informational => 0,
    }
}

/// Parse a severity string, defaulting unknown values to `Informational` (the
/// pre-existing import behavior).
pub(crate) fn parse_severity(value: &str) -> Severity {
    try_parse_severity(value).unwrap_or(Severity::Informational)
}

/// Strict severity parse — `None` for a value this code does not recognize, so
/// authorization decisions can fail closed rather than assume the lowest rank.
pub(crate) fn try_parse_severity(value: &str) -> Option<Severity> {
    match value {
        "critical" => Some(Severity::Critical),
        "high" => Some(Severity::High),
        "medium" => Some(Severity::Medium),
        "low" => Some(Severity::Low),
        "informational" | "info" => Some(Severity::Informational),
        _ => None,
    }
}

impl RuleRepositoryService {
    // =========================================================================
    // Import Rules
    // =========================================================================

    /// Preflight what [`Self::import_rule`] would do to the target detection,
    /// **without writing anything** (NAN-2118).
    ///
    /// Performs a strict subset of `import_rule`'s reads (repository, catalog
    /// rule, existing import, existing same-name rule from this repo) so a
    /// handler can enforce the composite capability policy — and reject an
    /// entire batch — before the first mutation. Errors raised here are raised
    /// identically by `import_rule` at the same point, before any write, so a
    /// batch caller may safely defer them to the execution loop.
    pub async fn plan_import(
        &self,
        repo_id: Uuid,
        path: &str,
        req: &ImportRequest,
    ) -> Result<RuleImportPlan, RuleRepositoryError> {
        let repo = self.get_repository(repo_id).await?;
        let repo_rule = self.get_rule(repo_id, path).await?;

        let existing_import: Option<RuleImport> = self
            .imports_repository
            .find_by_repository_rule(repo_rule.id)
            .await
            .map_err(RuleRepositoryError::from_repo_error)?
            .into_iter()
            .next();

        let name = resolve_import_name(req.name.as_deref(), repo_rule.title.as_deref(), path);

        // Same short-circuit `import_rule` takes: already imported and upstream
        // unchanged writes nothing at all.
        if let Some(ref existing) = existing_import {
            if !existing.upstream_changed {
                return Ok(RuleImportPlan {
                    action: RuleImportAction::Skip,
                    requires_promote: false,
                    resolved_name: name,
                });
            }
        }

        let npl_parsed = if repo.rule_format == "nanosiem" {
            parse_npl(&repo_rule.raw_content).ok()
        } else {
            None
        };
        let lifecycle =
            ImportLifecycle::resolve(req, repo_rule.severity.as_deref(), npl_parsed.as_ref());

        let existing_by_name = self.find_existing_import_target(&name, repo_id).await?;

        let (action, requires_promote) = match existing_by_name {
            Some(existing) => (
                RuleImportAction::Update,
                lifecycle.requires_promote_for_update(&existing),
            ),
            None => (
                RuleImportAction::Create,
                lifecycle.requires_promote_for_create(),
            ),
        };

        Ok(RuleImportPlan {
            action,
            requires_promote,
            resolved_name: name,
        })
    }

    /// Load the detection an import would overwrite, if one already exists from
    /// this repository under the same name. Shared by the preflight and the
    /// write path so both evaluate the promotion policy against the same row.
    async fn find_existing_import_target(
        &self,
        name: &str,
        repo_id: Uuid,
    ) -> Result<Option<ExistingImportTarget>, RuleRepositoryError> {
        /// `(id, dataset, risk_score, severity, schedule_cron, lookback_minutes)`
        type ExistingImportTargetRow = (
            Uuid,
            Option<String>,
            Option<i32>,
            Option<String>,
            Option<String>,
            Option<i32>,
        );

        let row: Option<ExistingImportTargetRow> =
            sqlx::query_as(
                "SELECT id, dataset, risk_score, severity, schedule_cron, lookback_minutes \
                 FROM detection_rules WHERE name = $1 AND source_repository_id = $2 LIMIT 1",
            )
            .bind(name)
            .bind(repo_id)
            .fetch_optional(&self.pg_pool)
            .await
            .map_err(RuleRepositoryError::Database)?;

        Ok(row.map(
            |(id, dataset, risk_score, severity, schedule_cron, lookback_minutes)| {
                ExistingImportTarget {
                    id,
                    dataset,
                    risk_score,
                    severity,
                    schedule_cron,
                    lookback_minutes,
                }
            },
        ))
    }

    /// Import a rule from a repository into detection rules.
    ///
    /// Returns the detection-rule ID alongside an [`ImportOutcome`] so the
    /// caller can distinguish a fresh import (`Created`) from re-importing an
    /// existing rule against newer upstream content (`Updated`). When an
    /// import already exists and `upstream_changed` is false, returns
    /// `AlreadyImported` so batch callers can count it as skipped (NAN-673).
    ///
    /// `grants` carries the target-resource capabilities the caller was verified
    /// to hold (NAN-2118). It is re-checked at the exact create/update branch,
    /// so a concurrent import that flips the outcome from create to update
    /// cannot launder a missing `detections:edit`. Internal SYSTEM callers pass
    /// [`TargetGrants::system`]; anything else must pass a principal-derived set.
    pub async fn import_rule(
        &self,
        repo_id: Uuid,
        path: &str,
        req: ImportRequest,
        user_id: Option<Uuid>,
        grants: &TargetGrants,
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

        // Determine the query to use. `req` stays intact (cloned, not moved out
        // of) so the lifecycle derivation below can borrow it whole — the same
        // one `plan_import` authorized against.
        let query = if let Some(custom) = req.custom_npl.clone() {
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

        // Build the detection rule. Name derivation is shared with
        // `plan_import` so the preflight's create-vs-update decision keys off
        // the exact name written here.
        let name = resolve_import_name(req.name.as_deref(), repo_rule.title.as_deref(), path);

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

        // Severity, mode, real-time flag, detection mode, schedule and lookback
        // all come from the ONE derivation `plan_import` preflighted against, so
        // the promotion gate below cannot drift from the authorization decision.
        let lifecycle =
            ImportLifecycle::resolve(&req, repo_rule.severity.as_deref(), npl_parsed.as_ref());
        let mode = lifecycle.mode;
        let severity = lifecycle.severity;
        let detection_mode = lifecycle.detection_mode;
        let schedule_cron = lifecycle.schedule_cron.clone();
        let lookback_minutes = lifecycle.lookback_minutes;

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
            // Repository-imported rules default to the logs dataset (NAN-1561);
            // spans/metrics rules are authored via the editor today.
            dataset: None,
            // Curated pull-feed rules carry NO DaC provenance (NAN-1764): this is
            // nano's outbound curated repo, not the customer's inbound DaC push
            // target, so a tuning PR must not be steered at a curated-feed path.
            source_path: None,
            source_repo_url: None,
            alert_cooldown_minutes: None,
        };

        // Check if a detection rule with this name already exists from this repo.
        // This catches duplicates that slip past the rule_imports check (e.g., race
        // conditions from concurrent batch imports, or re-imports after DB cleanup).
        // The existing rule's dataset/risk_score ride along for the NAN-1805
        // feedback-loop guard below.
        let existing_by_name = self
            .find_existing_import_target(&new_rule.name, repo_id)
            .await?;

        if let Some(existing) = existing_by_name {
            let ExistingImportTarget {
                id: existing_id,
                dataset: existing_dataset,
                risk_score: existing_risk_score,
                ..
            } = &existing;
            let (existing_id, existing_dataset, existing_risk_score) =
                (*existing_id, existing_dataset.clone(), *existing_risk_score);

            // NAN-2118: this branch rewrites a live detection in place, so it
            // consumes `detections:edit` — not `detections:create`. Checked HERE
            // rather than only in the handler preflight so a concurrent import
            // that flips the outcome from create to update cannot slip past a
            // caller who only holds create.
            grants
                .ensure(TargetEffect::DetectionEdit)
                .map_err(|effect| RuleRepositoryError::Forbidden(effect.permission().to_string()))?;

            // ...and the update branch rewrites severity / schedule_cron /
            // lookback_minutes on a possibly-live rule, which the canonical
            // `PUT /api/rules/{id}` gates behind `detections:promote` for a
            // schedule change, a severity downgrade, or a shortened lookback.
            // Same predicate `plan_import` preflighted, re-evaluated against the
            // row we actually found.
            if lifecycle.requires_promote_for_update(&existing) {
                grants.ensure(TargetEffect::DetectionPromote).map_err(|effect| {
                    RuleRepositoryError::Forbidden(effect.permission().to_string())
                })?;
            }

            info!(
                "Rule '{}' already exists from this repo (id={}), updating instead of creating",
                new_rule.name, existing_id
            );

            // NAN-1805 feedback-loop guard: this UPDATE writes the query
            // directly (bypassing DetectionService::update_rule), so enforce
            // the dataset=risk invariants here too — a re-import must not
            // persist `| risk` (or ride a nonzero score) onto a rule the user
            // has since moved to the risk dataset. (Execution refuses such
            // rules as belt-and-suspenders, but save paths should never
            // manufacture a permanently-failing rule.)
            crate::detection::DetectionService::validate_risk_dataset_rule(
                existing_dataset.as_deref(),
                &new_rule.query,
                existing_risk_score,
                true, // imported updates never write risk_modifiers
            )
            .map_err(|e| RuleRepositoryError::ConversionFailed(e.to_string()))?;

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
            .map_err(map_rule_mitre_write_error)?;

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

        // NAN-2118: minting a first-class detection consumes `detections:create`,
        // exactly like `POST /api/rules`. `rule_repositories:import` authorizes
        // the catalog read, never the target creation.
        grants
            .ensure(TargetEffect::DetectionCreate)
            .map_err(|effect| RuleRepositoryError::Forbidden(effect.permission().to_string()))?;

        // ...and creating outside Staging or provisioning a real-time
        // materialized view additionally consumes `detections:promote`, exactly
        // as `requires_promote_for_create` enforces on `POST /api/rules`.
        if lifecycle.requires_promote_for_create() {
            grants
                .ensure(TargetEffect::DetectionPromote)
                .map_err(|effect| RuleRepositoryError::Forbidden(effect.permission().to_string()))?;
        }

        // Create the detection rule
        let detection_rule = detection_service
            .create_rule_with_mode(new_rule, materialized_view_generator)
            .await
            .map_err(|error| match error {
                crate::detection::DetectionError::InvalidMitreMapping(message) => {
                    RuleRepositoryError::ConversionFailed(message)
                }
                error => RuleRepositoryError::DetectionService(error.to_string()),
            })?;

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

    /// Sync a signed, air-gapped rule bundle into the synthetic air-gap rule
    /// repository's catalog (NAN-1226).
    ///
    /// The bundle has already been verified upstream (Ed25519 signature +
    /// per-file SHA-256 checksums via `nanosiem_core::airgap::verify_bundle`);
    /// this method takes the already-verified `(file_path, raw_content)` pairs
    /// and upserts each into `repository_rules` — the *exact same* catalog
    /// upsert performed by the nPL branch of `run_sync` for GitHub-synced
    /// repos. This is the offline equivalent of a repo *sync*: the rules land
    /// as available-to-import (a `repository_rules` row with no
    /// `rule_imports` row), and the operator selectively imports them from the
    /// repositories page afterward.
    ///
    /// Nothing is imported or activated here — no detection rule is created.
    /// The bundle's rules are upserted into a synthetic, always-present air-gap
    /// rule repository (created on first use via `AIRGAP_RULE_REPOSITORY_SLUG`,
    /// `rule_format = "nanosiem"`). Returns the number of rules synced
    /// (successfully upserted) into the catalog.
    pub async fn sync_rule_bundle(
        &self,
        content_version: &str,
        rules: &[(String, String)],
        user_id: Option<Uuid>,
    ) -> Result<crate::rule_repository::models::RuleBundleImportResult, RuleRepositoryError> {
        use crate::rule_repository::npl_parser::parse_npl;

        let repo = self.find_or_create_airgap_rule_repository(user_id).await?;

        let mut synced = 0usize;

        for (path, raw_content) in rules {
            // Parse the nano-native nPL rule for metadata and upsert it into
            // repository_rules so the rule shows up as available-to-import on
            // the repositories page. Mirrors the nPL branch of `run_sync`.
            let (
                title,
                description,
                severity,
                mitre_tactics,
                mitre_techniques,
                tags,
                requires_fields,
                requires_source_types,
                conversion_status,
            ) = match parse_npl(raw_content) {
                Ok(npl) => (
                    Some(npl.title),
                    npl.description,
                    npl.severity,
                    (!npl.mitre_tactics.is_empty()).then_some(npl.mitre_tactics),
                    (!npl.mitre_techniques.is_empty()).then_some(npl.mitre_techniques),
                    (!npl.tags.is_empty()).then_some(npl.tags),
                    (!npl.required_fields.is_empty()).then_some(npl.required_fields),
                    (!npl.source_types.is_empty()).then_some(npl.source_types),
                    Some("success"),
                ),
                // Store unparseable rules with minimal metadata + a failed
                // conversion status, exactly as `run_sync` does, so they remain
                // visible in the catalog rather than silently dropped.
                Err(e) => {
                    warn!(repo_id = %repo.id, path = %path, error = %e, "Failed to parse nPL rule in air-gap bundle");
                    (None, None, None, None, None, None, None, None, Some("failed"))
                }
            };

            if let Err(e) = self
                .rules_repository
                .upsert(
                    repo.id,
                    path,
                    None,
                    raw_content,
                    title.as_deref(),
                    description.as_deref(),
                    severity.as_deref(),
                    mitre_tactics.as_deref(),
                    mitre_techniques.as_deref(),
                    tags.as_deref(),
                    requires_fields.as_deref(),
                    requires_source_types.as_deref(),
                    conversion_status,
                )
                .await
            {
                warn!(repo_id = %repo.id, path = %path, error = %e, "Failed to upsert air-gap rule into catalog");
                continue;
            }

            synced += 1;
        }

        info!(
            repo_id = %repo.id,
            content_version = %content_version,
            synced,
            "Air-gapped rule bundle synced into catalog"
        );

        Ok(crate::rule_repository::models::RuleBundleImportResult {
            repository_id: repo.id,
            content_version: content_version.to_string(),
            synced,
        })
    }

    /// Find (or lazily create) the synthetic repository that air-gapped rule
    /// bundles are imported into. A normal `rule_repositories` row (so it shows
    /// up in the rule-repo browser) with auto-sync disabled, a non-GitHub
    /// sentinel URL, and `rule_format = "nanosiem"` — air-gap rule bundles ship
    /// the native nPL format.
    async fn find_or_create_airgap_rule_repository(
        &self,
        user_id: Option<Uuid>,
    ) -> Result<crate::rule_repository::models::RuleRepository, RuleRepositoryError> {
        use crate::rule_repository::models::NewRuleRepository;

        const AIRGAP_RULE_REPOSITORY_SLUG: &str = "airgap-rules";
        const AIRGAP_RULE_REPOSITORY_NAME: &str = "Air-gapped Rule Bundles";

        if let Ok(existing) = self
            .repo_repository
            .find_by_slug(AIRGAP_RULE_REPOSITORY_SLUG)
            .await
        {
            return Ok(existing);
        }

        let new_repo = NewRuleRepository {
            name: AIRGAP_RULE_REPOSITORY_NAME.to_string(),
            slug: Some(AIRGAP_RULE_REPOSITORY_SLUG.to_string()),
            description: Some(
                "Rules imported from offline air-gapped bundles (NAN-1220).".to_string(),
            ),
            // Sentinel, never-fetched URL — air-gap bundles are uploaded, not synced.
            url: "airgap://rules".to_string(),
            branch: None,
            rules_path: None,
            rule_format: Some("nanosiem".to_string()),
            auto_sync_enabled: Some(false),
            sync_interval_hours: None,
        };

        match self.repo_repository.create(&new_repo, user_id).await {
            Ok(repo) => Ok(repo),
            // Lost a create race with a concurrent bundle upload — re-fetch.
            Err(crate::rule_repository::repository::RuleRepositoryRepositoryError::AlreadyExists(_)) => {
                self.repo_repository
                    .find_by_slug(AIRGAP_RULE_REPOSITORY_SLUG)
                    .await
                    .map_err(|e| RuleRepositoryError::Internal(e.to_string()))
            }
            Err(e) => Err(RuleRepositoryError::Internal(e.to_string())),
        }
    }
}

fn map_rule_mitre_write_error(error: sqlx::Error) -> RuleRepositoryError {
    match crate::mitre::mapping::database_mapping_violation(&error) {
        Some(message) => RuleRepositoryError::ConversionFailed(message),
        None => RuleRepositoryError::Database(error),
    }
}
