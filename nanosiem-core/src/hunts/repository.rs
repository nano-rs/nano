// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2238 — the hunt runtime's Postgres repository.
//!
//! # Two rules this file exists to keep
//!
//! **1. Every read of a derived artifact carries the provenance predicate.**
//! `hunt_leads`, `hunt_suppressions`, `hunt_profiles` and `hunt_rule_ideas` all
//! carry entity values an agent lifted out of matched events. The CHECK
//! constraints in migration 9000054 make an unstamped WRITE fail closed, but a
//! CHECK cannot filter a SELECT: that is [`ArtifactScope::sql_predicate`]'s job,
//! and [`ARTIFACT_READ_SITES`] plus the test module is the guard against a new
//! query being added without it. Filtering in SQL rather than after the fetch is
//! deliberate — a post-filter still pages over denied rows, which makes the page
//! size an oracle for how many exist.
//!
//! **2. Only analyst triage writes a suppression.** There is exactly one
//! insert into `hunt_suppressions` in this file and it lives inside
//! [`HuntRepository::dismiss_lead`], which is reachable only from the
//! `hunts:triage` handler. An agent that could suppress could blind its own
//! successors, so this is asserted by a test rather than left to review.
//!
//! # The fence
//!
//! [`HuntRepository::commit_sweep_report`] reasserts
//! `(sweep_id, runner_id, runner_fence, unexpired lease, active status)` in a
//! `SELECT … FOR UPDATE` **before it writes anything**. Under `READ COMMITTED`
//! Postgres re-evaluates the qualifier after acquiring the row lock, so a
//! concurrent reassignment that commits first makes the reassertion find no row
//! — which is exactly the case a stale runner waking after failover produces.
//! Recording the fence without reasserting it, as the schema alone does, is a
//! comment rather than a control.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use sqlx::{PgPool, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::auth::{ArtifactScope, SourceProvenance};
use crate::hunts::spec::HuntSpecDraft;
use serde_json::Value;
use crate::playbooks::models::{CreatePlaybookRequest, Playbook, PlaybookScope, PlaybookStatus};
use crate::hunts::error::HuntError;
use crate::hunts::evidence::ResolvedEvent;
use crate::hunts::fingerprint::{derive as derive_fingerprint, CanonicalEntity, FingerprintInput};
use crate::hunts::knowledge::{record_prepared_in_tx, PreparedKnowledge, RecordOutcome};
use crate::hunts::models::*;
use crate::hunts::report::{reconcile_outcome, BudgetLimits, BudgetUsage, TrailStep};
use crate::hunts::scoring::{score, Contribution, ScoreInputs};

/// Column pairs the artifact-provenance predicate must be applied to, keyed by
/// the table whose rows carry them.
///
/// Referenced by `every_artifact_table_read_is_scoped` so that adding a table to
/// migration 9000054 without teaching this file about it fails a test rather
/// than silently shipping an unfiltered read.
pub const ARTIFACT_READ_SITES: &[(&str, &str, &str)] = &[
    ("hunt_leads", "l.source_types", "l.source_types_complete"),
    (
        "hunt_suppressions",
        "s.source_types",
        "s.source_types_complete",
    ),
    ("hunt_profiles", "p.source_types", "p.source_types_complete"),
    ("hunt_rule_ideas", "i.source_types", "i.source_types_complete"),
];

/// Longest lease a runner may hold. A runner that asked for a month would make
/// failover impossible: the reclaim path only reassigns a sweep whose lease has
/// EXPIRED, so an unbounded lease is an unbounded outage for that hunt.
pub const MAX_LEASE_SECONDS: i64 = 3600;
/// Default when a runner does not ask. Comfortably above `budget_max_wall_seconds`'s
/// 900s default so a normal sweep never has to renew.
pub const DEFAULT_LEASE_SECONDS: i64 = 1800;

/// Cap on the trail we persist, mirroring `hunt_sweeps_trail_bounded`. Trimmed
/// where the value is produced so the CHECK is never what rejects a report —
/// a 400 on the last step of a 15-minute sweep loses the whole sweep.
const MAX_TRAIL_STEPS: usize = 500;

/// Cap on stored narrative / outcome detail, mirroring the CHECKs. Same reason.
const MAX_NARRATIVE_CHARS: usize = 16_384;
const MAX_OUTCOME_DETAIL_CHARS: usize = 4_000;

#[derive(Clone)]
pub struct HuntRepository {
    pool: PgPool,
}

/// One candidate the service has already resolved, corroborated and measured.
///
/// The repository receives THIS, never a `LeadCandidate`. Everything an agent
/// could influence has already been through a server-side resolver by the time
/// it reaches a SQL statement, and there is no field on this type to carry a
/// score, a fingerprint or a manifest — those are computed inside the commit
/// transaction from facts the database itself supplies.
pub struct PreparedLead {
    pub entity: CanonicalEntity,
    /// Validated against the server's known-signal set. Unrecognised signals
    /// were already dropped, which is what stops an agent minting a fresh
    /// fingerprint by appending a nonce to a suppressed finding.
    pub signals: Vec<crate::hunts::fingerprint::ValidatedSignal>,
    /// What the agent believes it found. Free to differ from the hunt's own
    /// technique — recorded as an attribute, never fed to the fingerprint.
    pub mitre_technique: Option<String>,
    pub narrative: Option<String>,
    pub evidence: Vec<ResolvedEvent>,
    pub provenance: SourceProvenance,
    /// Measured by the server from the log store. `None` = unmeasured, which
    /// the scorer treats as "not evidence of rarity" rather than as rare.
    pub prevalence: Option<f64>,
    pub first_seen_in_window: bool,
}

/// The runner-measured half of a report, plus the agent's own claim about why
/// it stopped. The claim loses to the measurement — see [`reconcile_outcome`].
pub struct CommitInputs {
    pub sweep_id: Uuid,
    pub runner_id: Uuid,
    pub runner_fence: i64,
    pub usage: BudgetUsage,
    pub trail: Vec<TrailStep>,
    pub claimed_outcome: Option<String>,
    pub note: Option<String>,
    pub leads: Vec<PreparedLead>,
    /// Candidates the service refused before this point (uncorroborated entity,
    /// unknown entity type, nothing readable behind them). Reported rather than
    /// dropped: a sweep whose candidates are all being rejected is broken, and
    /// a silent zero looks identical to a clean run.
    pub rejected: usize,
    /// Durable facts already normalized and provenance-stamped by the service.
    /// They commit under the same fence transaction as the report.
    pub knowledge: Vec<PreparedKnowledge>,
    /// Malformed or over-limit facts refused before the transaction.
    pub knowledge_rejected: usize,
}

impl HuntRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // =========================================================================
    // Hunt definitions
    // =========================================================================

    /// The projection every hunt read shares. `kind = 'hunt'` is not optional:
    /// `playbooks` is a shared definition table and a response playbook joined
    /// to nothing would render as a malformed hunt.
    const HUNT_SELECT: &'static str = r#"
        SELECT p.id AS playbook_id, p.title, p.subtitle, p.category, p.status, p.tags,
               h.sweep_query, h.schedule_cron, h.schedule_timezone, h.required_source_types,
               h.mitre_tactic, h.mitre_technique, h.enabled,
               h.budget_max_turns, h.budget_max_tool_calls, h.budget_max_rows,
               h.budget_max_wall_seconds, h.lookback_window, h.max_catchup_lookback,
               h.next_due_slot, h.coalesced_through_slot, h.last_attempt_at, h.last_success_at,
               h.auto_promote_threshold::float8 AS auto_promote_threshold,
               h.auto_promote, h.generated_from_profile, h.generated_at,
               h.created_at, h.updated_at
          FROM hunt_specs h
          JOIN playbooks p ON p.id = h.playbook_id AND p.kind = 'hunt'
    "#;

    pub async fn list_hunts(
        &self,
        enabled_only: bool,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Hunt>, HuntError> {
        let mut sql = String::from(Self::HUNT_SELECT);
        sql.push_str(" WHERE p.status <> 'archived'");
        if enabled_only {
            sql.push_str(" AND h.enabled");
        }
        sql.push_str(" ORDER BY p.title ASC LIMIT $1 OFFSET $2");
        let rows = sqlx::query(&sql)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(hunt_from_row).collect()
    }

    /// The detail projection: [`Self::HUNT_SELECT`] plus the hunt's own body.
    ///
    /// Separate from the list projection deliberately. `doc` is markdown of
    /// unbounded length and `parsed_steps` is a JSON tree; a library listing
    /// every hunt has no business carrying either, which is exactly why they
    /// were left out — and then never added back anywhere, so the detail view
    /// never received them.
    const HUNT_DETAIL_SELECT: &'static str = r#"
        SELECT p.id AS playbook_id, p.title, p.subtitle, p.category, p.status, p.tags,
               p.doc, p.parsed_steps AS steps,
               h.sweep_query, h.schedule_cron, h.schedule_timezone, h.required_source_types,
               h.mitre_tactic, h.mitre_technique, h.enabled,
               h.budget_max_turns, h.budget_max_tool_calls, h.budget_max_rows,
               h.budget_max_wall_seconds, h.lookback_window, h.max_catchup_lookback,
               h.next_due_slot, h.coalesced_through_slot, h.last_attempt_at, h.last_success_at,
               h.auto_promote_threshold::float8 AS auto_promote_threshold,
               h.auto_promote, h.generated_from_profile, h.generated_at,
               h.created_at, h.updated_at
          FROM hunt_specs h
          JOIN playbooks p ON p.id = h.playbook_id AND p.kind = 'hunt'
    "#;

    /// Set or CLEAR a hunt's cadence (NAN-2252).
    ///
    /// # Why this is not `update_hunt`
    ///
    /// `update_hunt` is `COALESCE($n, column)` on every field, so a NULL means
    /// "leave it alone" and no field on that endpoint can ever be cleared. That
    /// is right for a partial update and wrong for a cadence, where "manual
    /// only" is a REAL value an analyst chooses — clearing was silently a no-op,
    /// so a hunt could be given a schedule and never taken off one.
    ///
    /// Here the SET is direct. `None` writes NULL and means manual-only.
    ///
    /// `next_due_slot` is cleared alongside it. A slot computed from the OLD
    /// cadence is a scheduled run the new cadence never asked for — leaving it
    /// would fire one more sweep on a hunt the analyst just set to manual.
    pub async fn set_hunt_schedule(
        &self,
        playbook_id: Uuid,
        schedule_cron: Option<&str>,
        schedule_timezone: Option<&str>,
    ) -> Result<Hunt, HuntError> {
        sqlx::query(
            "UPDATE hunt_specs \
                SET schedule_cron = $2, \
                    schedule_timezone = COALESCE($3, schedule_timezone), \
                    next_due_slot = NULL, \
                    updated_at = NOW() \
              WHERE playbook_id = $1",
        )
        .bind(playbook_id)
        .bind(schedule_cron)
        .bind(schedule_timezone)
        .execute(&self.pool)
        .await?;
        self.get_hunt(playbook_id).await
    }

    pub async fn get_hunt(&self, playbook_id: Uuid) -> Result<Hunt, HuntError> {
        let sql = format!("{} WHERE p.id = $1", Self::HUNT_DETAIL_SELECT);
        let row = sqlx::query(&sql)
            .bind(playbook_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(HuntError::NotFound(playbook_id))?;
        hunt_from_row(&row)
    }

    pub async fn create_hunt(
        &self,
        req: &CreateHuntRequest,
        created_by: Option<Uuid>,
    ) -> Result<Hunt, HuntError> {
        validate_hunt_text(&req.title, &req.category, &req.sweep_query)?;
        // Frontmatter's nested `budget` block wins over the flat fields, so a
        // hunt imported from a repository gets the ceilings its author wrote.
        let budget = req.budget_values();
        let mut tx = self.pool.begin().await?;

        // `kind = 'hunt'` on the definition row is what every constant-kind
        // composite FK below anchors to. Writing it here — rather than relying
        // on a default — keeps the intent visible at the one place a hunt comes
        // into existence.
        let playbook_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO playbooks (title, subtitle, category, doc, tags, kind, status, created_by)
            VALUES ($1, $2, $3, $4, $5, 'hunt', 'draft', $6)
            RETURNING id
            "#,
        )
        .bind(req.title.trim())
        .bind(req.subtitle.as_deref())
        .bind(req.category.trim().to_lowercase())
        .bind(&req.doc)
        .bind(req.tags.clone())
        .bind(created_by)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            INSERT INTO hunt_specs (
                playbook_id, sweep_query, schedule_cron, schedule_timezone,
                required_source_types, mitre_tactic, mitre_technique,
                budget_max_turns, budget_max_tool_calls, budget_max_rows,
                budget_max_wall_seconds, lookback_window, max_catchup_lookback
            )
            VALUES (
                $1, $2, $3, COALESCE($4, 'UTC'),
                $5, $6, $7,
                COALESCE($8, 40), COALESCE($9, 120), COALESCE($10, 5000),
                COALESCE($11, 900), COALESCE($12, '24h'), COALESCE($13, '72h')
            )
            "#,
        )
        .bind(playbook_id)
        .bind(req.sweep_query.trim())
        .bind(req.schedule_cron.as_deref())
        .bind(req.schedule_timezone.as_deref())
        .bind(normalize_sources(&req.required_source_types))
        .bind(req.mitre_tactic.as_deref())
        .bind(req.mitre_technique.as_deref())
        .bind(budget.max_turns)
        .bind(budget.max_tool_calls)
        .bind(budget.max_rows)
        .bind(budget.max_wall_seconds)
        .bind(req.lookback_window.as_deref())
        .bind(req.max_catchup_lookback.as_deref())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.get_hunt(playbook_id).await
    }

    pub async fn update_hunt(
        &self,
        playbook_id: Uuid,
        req: &UpdateHuntRequest,
    ) -> Result<Hunt, HuntError> {
        if let Some(query) = &req.sweep_query {
            if query.trim().is_empty() {
                return Err(HuntError::Validation("sweep_query must not be empty".into()));
            }
        }
        let budget = req.budget_values();
        let mut tx = self.pool.begin().await?;

        // COALESCE-per-column rather than a dynamically assembled SET list: the
        // parameter positions are fixed, so a future field cannot be added in a
        // way that shifts an existing bind onto the wrong column.
        let updated: Option<Uuid> = sqlx::query_scalar(
            r#"
            UPDATE playbooks
               SET title = COALESCE($2, title),
                   subtitle = COALESCE($3, subtitle),
                   doc = COALESCE($4, doc),
                   tags = COALESCE($5, tags),
                   updated_at = NOW()
             WHERE id = $1 AND kind = 'hunt'
            RETURNING id
            "#,
        )
        .bind(playbook_id)
        .bind(req.title.as_deref())
        .bind(req.subtitle.as_deref())
        .bind(req.doc.as_deref())
        .bind(req.tags.clone())
        .fetch_optional(&mut *tx)
        .await?;
        if updated.is_none() {
            tx.rollback().await?;
            return Err(HuntError::NotFound(playbook_id));
        }

        sqlx::query(
            r#"
            UPDATE hunt_specs
               SET sweep_query = COALESCE($2, sweep_query),
                   schedule_cron = COALESCE($3, schedule_cron),
                   schedule_timezone = COALESCE($4, schedule_timezone),
                   required_source_types = COALESCE($5, required_source_types),
                   mitre_tactic = COALESCE($6, mitre_tactic),
                   mitre_technique = COALESCE($7, mitre_technique),
                   enabled = COALESCE($8, enabled),
                   budget_max_turns = COALESCE($9, budget_max_turns),
                   budget_max_tool_calls = COALESCE($10, budget_max_tool_calls),
                   budget_max_rows = COALESCE($11, budget_max_rows),
                   budget_max_wall_seconds = COALESCE($12, budget_max_wall_seconds),
                   lookback_window = COALESCE($13, lookback_window),
                   max_catchup_lookback = COALESCE($14, max_catchup_lookback),
                   updated_at = NOW()
             WHERE playbook_id = $1
            "#,
        )
        .bind(playbook_id)
        .bind(req.sweep_query.as_deref().map(str::trim))
        .bind(req.schedule_cron.as_deref())
        .bind(req.schedule_timezone.as_deref())
        .bind(req.required_source_types.as_ref().map(|s| normalize_sources(s)))
        .bind(req.mitre_tactic.as_deref())
        .bind(req.mitre_technique.as_deref())
        .bind(req.enabled)
        .bind(budget.max_turns)
        .bind(budget.max_tool_calls)
        .bind(budget.max_rows)
        .bind(budget.max_wall_seconds)
        .bind(req.lookback_window.as_deref())
        .bind(req.max_catchup_lookback.as_deref())
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        self.get_hunt(playbook_id).await
    }

    /// Archive a hunt. Also disables it: an archived hunt that kept sweeping
    /// would be invisible in the library and still burning a runner.
    pub async fn archive_hunt(&self, playbook_id: Uuid) -> Result<(), HuntError> {
        let mut tx = self.pool.begin().await?;
        let archived = sqlx::query(
            "UPDATE playbooks SET status = 'archived', updated_at = NOW() \
             WHERE id = $1 AND kind = 'hunt'",
        )
        .bind(playbook_id)
        .execute(&mut *tx)
        .await?;
        if archived.rows_affected() == 0 {
            tx.rollback().await?;
            return Err(HuntError::NotFound(playbook_id));
        }
        sqlx::query(
            "UPDATE hunt_specs SET enabled = FALSE, next_due_slot = NULL, updated_at = NOW() \
             WHERE playbook_id = $1",
        )
        .bind(playbook_id)
        .execute(&mut *tx)
        .await?;

        // Disabling the schedule stops FUTURE sweeps; it does nothing about the
        // one already sitting in the queue or held by a runner. Without this an
        // archived hunt — invisible in the library — keeps burning a runner and
        // filing leads against a definition nobody can see. Abandoning also
        // frees `uq_hunt_sweeps_in_flight`, so the hunt can be un-archived and
        // run again without a stuck row blocking it.
        sqlx::query(
            "UPDATE hunt_sweeps \
                SET status = 'abandoned', outcome = 'cancelled', \
                    outcome_detail = 'hunt archived', finished_at = NOW(), \
                    lease_expires_at = NULL \
              WHERE playbook_id = $1 AND status IN ('queued', 'leased', 'running')",
        )
        .bind(playbook_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    // =========================================================================
    // Runners
    // =========================================================================

    pub async fn list_runners(&self) -> Result<Vec<HuntRunner>, HuntError> {
        let rows = sqlx::query(
            "SELECT * FROM hunt_runners ORDER BY enabled DESC, last_heartbeat_at DESC NULLS LAST",
        )
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(runner_from_row).collect()
    }

    /// Register (or re-register) a runner, BUMPING its fence.
    ///
    /// Re-registration is the event that invalidates in-flight leases. A runner
    /// that crashed mid-sweep, was reassigned, and then came back must not be
    /// able to report for the work it lost — so the fence moves and
    /// [`Self::commit_sweep_report`]'s reassertion stops matching.
    pub async fn register_runner(
        &self,
        req: &RegisterRunnerRequest,
        registered_by: Option<Uuid>,
    ) -> Result<HuntRunner, HuntError> {
        let label = req.label.trim();
        if label.is_empty() {
            return Err(HuntError::Validation("label must not be empty".into()));
        }
        let row = sqlx::query(
            r#"
            INSERT INTO hunt_runners (label, hostname, agent_tool, agent_model, registered_by,
                                      last_heartbeat_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            RETURNING *
            "#,
        )
        .bind(label)
        .bind(req.hostname.as_deref())
        .bind(req.agent_tool.as_deref())
        .bind(req.agent_model.as_deref())
        .bind(registered_by)
        .fetch_one(&self.pool)
        .await?;
        runner_from_row(&row)
    }

    /// Bump an existing runner's fence — the explicit "I am starting fresh"
    /// signal, used when a runner restarts under the same identity.
    pub async fn rotate_runner_fence(&self, runner_id: Uuid) -> Result<HuntRunner, HuntError> {
        let row = sqlx::query(
            "UPDATE hunt_runners \
                SET fence_token = fence_token + 1, last_heartbeat_at = NOW(), updated_at = NOW() \
              WHERE id = $1 RETURNING *",
        )
        .bind(runner_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(HuntError::RunnerNotFound(runner_id))?;
        runner_from_row(&row)
    }

    /// A heartbeat deliberately does NOT extend a lease.
    ///
    /// If it did, a runner that had wedged mid-sweep but whose heartbeat thread
    /// was still alive would hold its sweep forever — the exact failure the
    /// lease exists to bound. Renewal is a separate, explicit act.
    pub async fn heartbeat_runner(&self, runner_id: Uuid) -> Result<HuntRunner, HuntError> {
        let row = sqlx::query(
            "UPDATE hunt_runners SET last_heartbeat_at = NOW(), updated_at = NOW() \
              WHERE id = $1 AND enabled RETURNING *",
        )
        .bind(runner_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(HuntError::RunnerNotFound(runner_id))?;
        runner_from_row(&row)
    }

    /// Grant or withdraw this machine's Antigravity sweep waiver (NAN-2264).
    ///
    /// Both directions stamp their own instant and actor and leave the other
    /// pair alone, so the row keeps the full shape of the decision: a re-grant
    /// after a withdrawal still shows that it was once withdrawn, and
    /// [`crate::hunts::models::agy_waiver_in_force`] resolves which is current
    /// from the two timestamps.
    ///
    /// Deliberately NOT filtered on `enabled`: a disabled runner must still be
    /// revocable. Making revocation depend on the machine being switched on
    /// would mean the one state you most want to be able to withdraw a standing
    /// authorisation from — a runner someone turned off and forgot — is the one
    /// state where you cannot.
    pub async fn set_runner_agy_waiver(
        &self,
        runner_id: Uuid,
        granted: bool,
        actor: Option<Uuid>,
    ) -> Result<HuntRunner, HuntError> {
        let sql = if granted {
            "UPDATE hunt_runners \
                SET agy_waiver_granted_at = NOW(), agy_waiver_granted_by = $2, updated_at = NOW() \
              WHERE id = $1 RETURNING *"
        } else {
            "UPDATE hunt_runners \
                SET agy_waiver_revoked_at = NOW(), agy_waiver_revoked_by = $2, updated_at = NOW() \
              WHERE id = $1 RETURNING *"
        };
        let row = sqlx::query(sql)
            .bind(runner_id)
            .bind(actor)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(HuntError::RunnerNotFound(runner_id))?;
        runner_from_row(&row)
    }

    /// One runner by id, for the handler that needs to know what it changed.
    pub async fn get_runner(&self, runner_id: Uuid) -> Result<HuntRunner, HuntError> {
        let row = sqlx::query("SELECT * FROM hunt_runners WHERE id = $1")
            .bind(runner_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(HuntError::RunnerNotFound(runner_id))?;
        runner_from_row(&row)
    }

    // =========================================================================
    // Sweeps
    // =========================================================================

    /// Queue a manual sweep.
    ///
    /// `schedule_slot` stays NULL, which `hunt_sweeps_slot_matches_trigger`
    /// REQUIRES for `trigger = 'manual'`: without that CHECK a manual run could
    /// squat a scheduled slot and the unique index that makes catch-up coalesce
    /// would silently enforce nothing.
    pub async fn enqueue_manual_sweep(
        &self,
        playbook_id: Uuid,
        window_start: DateTime<Utc>,
        window_end: DateTime<Utc>,
    ) -> Result<HuntSweep, HuntError> {
        let version: Option<i32> =
            sqlx::query_scalar("SELECT current_version FROM playbooks WHERE id = $1 AND kind = 'hunt'")
                .bind(playbook_id)
                .fetch_optional(&self.pool)
                .await?;
        let version = version.ok_or(HuntError::NotFound(playbook_id))?;

        let row = sqlx::query(
            r#"
            INSERT INTO hunt_sweeps (playbook_id, playbook_version, trigger, status,
                                     window_start, window_end)
            VALUES ($1, $2, 'manual', 'queued', $3, $4)
            RETURNING *, (SELECT COUNT(*) FROM hunt_leads l
                           WHERE l.sweep_id = hunt_sweeps.id) AS leads_produced
            "#,
        )
        .bind(playbook_id)
        .bind(version)
        .bind(window_start)
        .bind(window_end)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| match &e {
            // `uq_hunt_sweeps_in_flight` — at most one sweep in flight per
            // hunt. A 409 here is correct and actionable; a 500 would read as
            // a bug in the trigger button.
            sqlx::Error::Database(db) if db.constraint() == Some("uq_hunt_sweeps_in_flight") => {
                HuntError::Conflict("a sweep is already in flight for this hunt".into())
            }
            _ => HuntError::Database(e),
        })?;
        sweep_from_row(&row)
    }

    /// Claim the oldest queued sweep for `runner_id`, or reclaim one whose
    /// lease expired.
    ///
    /// The `FOR UPDATE SKIP LOCKED` is what lets several runners poll
    /// concurrently without serializing on the same head-of-queue row: a
    /// contending claimer skips the row being taken rather than waiting for it
    /// and then finding it gone.
    pub async fn claim_next_sweep(
        &self,
        runner_id: Uuid,
        lease_seconds: Option<i64>,
    ) -> Result<Option<ClaimedSweep>, HuntError> {
        let lease = lease_seconds
            .unwrap_or(DEFAULT_LEASE_SECONDS)
            .clamp(60, MAX_LEASE_SECONDS);

        let mut tx = self.pool.begin().await?;

        let fence: Option<i64> =
            sqlx::query_scalar("SELECT fence_token FROM hunt_runners WHERE id = $1 AND enabled")
                .bind(runner_id)
                .fetch_optional(&mut *tx)
                .await?;
        let Some(fence) = fence else {
            tx.rollback().await?;
            return Err(HuntError::RunnerNotFound(runner_id));
        };

        let candidate: Option<Uuid> = sqlx::query_scalar(
            r#"
            SELECT id FROM hunt_sweeps
             WHERE status = 'queued'
                OR (status IN ('leased', 'running') AND lease_expires_at <= NOW())
             ORDER BY created_at ASC
             LIMIT 1
             FOR UPDATE SKIP LOCKED
            "#,
        )
        .fetch_optional(&mut *tx)
        .await?;

        let Some(sweep_id) = candidate else {
            tx.rollback().await?;
            return Ok(None);
        };

        let row = sqlx::query(
            r#"
            UPDATE hunt_sweeps
               SET runner_id = $2,
                   runner_fence = $3,
                   lease_expires_at = NOW() + ($4 * INTERVAL '1 second'),
                   status = 'leased',
                   started_at = COALESCE(started_at, NOW())
             WHERE id = $1
            RETURNING *, (SELECT COUNT(*) FROM hunt_leads l
                           WHERE l.sweep_id = hunt_sweeps.id) AS leads_produced
            "#,
        )
        .bind(sweep_id)
        .bind(runner_id)
        .bind(fence)
        .bind(lease as f64)
        .fetch_one(&mut *tx)
        .await?;
        let sweep = sweep_from_row(&row)?;

        let hunt_sql = format!("{} WHERE p.id = $1", Self::HUNT_SELECT);
        let hunt_row = sqlx::query(&hunt_sql)
            .bind(sweep.playbook_id)
            .fetch_one(&mut *tx)
            .await?;
        let hunt = hunt_from_row(&hunt_row)?;

        tx.commit().await?;

        let lease_expires_at = sweep
            .lease_expires_at
            .ok_or_else(|| HuntError::Internal("leased sweep has no expiry".into()))?;
        Ok(Some(ClaimedSweep {
            sweep,
            hunt,
            runner_fence: fence,
            lease_expires_at,
        }))
    }

    /// Analyst-facing sweep list.
    ///
    /// NOT row-filtered by provenance — see [`HuntSweep::redact_unattributed`].
    /// A sweep row is scheduler state; its agent-authored prose is the derived
    /// artifact, and that is what gets blanked.
    pub async fn list_sweeps(
        &self,
        query: &ListSweepsQuery,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntSweep>, HuntError> {
        let mut sql = String::from(
            "SELECT s.*, (SELECT COUNT(*) FROM hunt_leads l WHERE l.sweep_id = s.id) \
             AS leads_produced FROM hunt_sweeps s WHERE 1 = 1",
        );
        let mut param = 1usize;
        if query.playbook_id.is_some() {
            sql.push_str(&format!(" AND s.playbook_id = ${param}"));
            param += 1;
        }
        if query.status.is_some() {
            sql.push_str(&format!(" AND s.status = ${param}"));
            param += 1;
        }
        sql.push_str(&format!(
            " ORDER BY s.created_at DESC LIMIT ${} OFFSET ${}",
            param,
            param + 1
        ));

        let mut q = sqlx::query(&sql);
        if let Some(id) = query.playbook_id {
            q = q.bind(id);
        }
        if let Some(status) = &query.status {
            q = q.bind(status.clone());
        }
        let rows = q
            .bind(query.limit)
            .bind(query.offset)
            .fetch_all(&self.pool)
            .await?;
        let mut sweeps = rows
            .iter()
            .map(sweep_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        for sweep in &mut sweeps {
            sweep.redact_unattributed(scope);
        }
        Ok(sweeps)
    }

    pub async fn get_sweep(
        &self,
        sweep_id: Uuid,
        scope: &ArtifactScope,
    ) -> Result<HuntSweep, HuntError> {
        let row = sqlx::query(
            "SELECT s.*, (SELECT COUNT(*) FROM hunt_leads l WHERE l.sweep_id = s.id) \
             AS leads_produced FROM hunt_sweeps s WHERE s.id = $1",
        )
        .bind(sweep_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(HuntError::SweepNotFound(sweep_id))?;
        let mut sweep = sweep_from_row(&row)?;
        sweep.redact_unattributed(scope);
        Ok(sweep)
    }

    /// Everything the service needs to prepare a report, read WITHOUT taking a
    /// lock.
    ///
    /// Deliberately a separate, non-authoritative read: preparing a report means
    /// talking to ClickHouse, and holding a Postgres row lock across a network
    /// round trip to another database would let one slow evidence lookup block
    /// every reclaim. The authoritative check is the reassertion inside
    /// [`Self::commit_sweep_report`]; this one only decides whether it is worth
    /// doing the work at all.
    pub async fn sweep_report_context(
        &self,
        sweep_id: Uuid,
        runner_id: Uuid,
        runner_fence: i64,
    ) -> Result<SweepReportContext, HuntError> {
        let row = sqlx::query(
            r#"
            SELECT s.playbook_id, s.window_start, s.window_end,
                   h.budget_max_turns, h.budget_max_tool_calls,
                   h.budget_max_rows, h.budget_max_wall_seconds,
                   h.sweep_query
              FROM hunt_sweeps s
              JOIN hunt_specs h ON h.playbook_id = s.playbook_id
              JOIN hunt_runners r ON r.id = s.runner_id
             WHERE s.id = $1
               AND s.runner_id = $2
               AND s.runner_fence = $3
               AND r.fence_token = $3
               AND s.lease_expires_at > NOW()
               AND s.status IN ('leased', 'running')
            "#,
        )
        .bind(sweep_id)
        .bind(runner_id)
        .bind(runner_fence)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| {
            HuntError::LeaseLost(format!(
                "sweep {sweep_id} is not leased to this runner at fence {runner_fence}"
            ))
        })?;

        Ok(SweepReportContext {
            playbook_id: row.try_get("playbook_id")?,
            window_start: row.try_get("window_start")?,
            window_end: row.try_get("window_end")?,
            sweep_query: row.try_get("sweep_query")?,
            limits: BudgetLimits {
                max_turns: row.try_get::<i32, _>("budget_max_turns")?.max(0) as u32,
                max_tool_calls: row.try_get::<i32, _>("budget_max_tool_calls")?.max(0) as u32,
                max_rows: row.try_get::<i32, _>("budget_max_rows")?.max(0) as u64,
                max_wall_seconds: row.try_get::<i32, _>("budget_max_wall_seconds")?.max(0) as u64,
            },
        })
    }

    /// Persist a sweep's result. **The fence is reasserted under lock here.**
    ///
    /// Order matters and is not incidental:
    ///
    /// 1. `SELECT … FOR UPDATE OF s` reasserting runner, fence, lease and
    ///    status. Nothing is written before this succeeds, so a stale runner
    ///    that woke after reassignment cannot append a single row.
    /// 2. Fingerprints are derived from the LOCKED row's `playbook_id`, never
    ///    from the preflight read — the two cannot disagree, but deriving from
    ///    the locked value is what makes that a fact rather than an assumption.
    /// 3. Suppression and recurrence are measured inside the same transaction,
    ///    so a suppression written a millisecond ago is honoured.
    /// 4. The sweep's own status/outcome update lands last, which is what makes
    ///    a crashed commit leave a still-leased sweep for the reclaim path
    ///    rather than a half-finished one.
    pub async fn commit_sweep_report(
        &self,
        inputs: CommitInputs,
    ) -> Result<SweepReportAccepted, HuntError> {
        let mut tx = self.pool.begin().await?;

        // ---- 1. The fence ---------------------------------------------------
        //
        // `FOR UPDATE OF s` locks only `hunt_sweeps`: locking the joined spec or
        // runner rows too would serialize every concurrent sweep of the same
        // hunt behind one commit for no correctness benefit.
        //
        // Under READ COMMITTED, Postgres re-evaluates this qualifier after
        // acquiring the row lock. A reassignment that commits while we wait
        // therefore makes the row stop matching, and we get zero rows — which
        // is precisely the stale-runner case.
        let locked = sqlx::query(
            r#"
            SELECT s.playbook_id, s.window_start, s.window_end,
                   h.budget_max_turns, h.budget_max_tool_calls,
                   h.budget_max_rows, h.budget_max_wall_seconds, h.sweep_query
              FROM hunt_sweeps s
              JOIN hunt_specs h ON h.playbook_id = s.playbook_id
              JOIN hunt_runners r ON r.id = s.runner_id
             WHERE s.id = $1
               AND s.runner_id = $2
               AND s.runner_fence = $3
               AND r.fence_token = $3
               AND s.lease_expires_at > NOW()
               AND s.status IN ('leased', 'running')
             -- Lock the RUNNER as well as the sweep. Checking `r.fence_token`
             -- while holding no lock on `r` leaves a window: an operator
             -- rotating the fence (revoking a machine, re-registering it after
             -- it was lost) commits between this check and the writes below,
             -- and the revoked runner's report lands anyway. Locking both makes
             -- the rotation wait, so a runner invalidated at any point before
             -- the commit is invalidated for this report too.
             FOR UPDATE OF s, r
            "#,
        )
        .bind(inputs.sweep_id)
        .bind(inputs.runner_id)
        .bind(inputs.runner_fence)
        .fetch_optional(&mut *tx)
        .await?;

        let Some(locked) = locked else {
            tx.rollback().await?;
            return Err(HuntError::LeaseLost(format!(
                "sweep {} was reassigned, expired or already finished; \
                 this runner's results belong to a generation of work that no longer exists",
                inputs.sweep_id
            )));
        };

        let playbook_id: Uuid = locked.try_get("playbook_id")?;
        let sweep_window_start: Option<DateTime<Utc>> = locked.try_get("window_start")?;
        let sweep_window_end: Option<DateTime<Utc>> = locked.try_get("window_end")?;
        let limits = BudgetLimits {
            max_turns: locked.try_get::<i32, _>("budget_max_turns")?.max(0) as u32,
            max_tool_calls: locked.try_get::<i32, _>("budget_max_tool_calls")?.max(0) as u32,
            max_rows: locked.try_get::<i32, _>("budget_max_rows")?.max(0) as u64,
            max_wall_seconds: locked.try_get::<i32, _>("budget_max_wall_seconds")?.max(0) as u64,
        };
        let sweep_query: String = locked.try_get("sweep_query")?;

        let window_start = sweep_window_start.unwrap_or_else(|| Utc::now() - Duration::days(1));
        let window_end = sweep_window_end.unwrap_or_else(Utc::now);

        // ---- 2/3. Score and persist each lead -------------------------------
        let mut leads_created = 0usize;
        let mut evidence_attached = 0usize;
        // The sweep manifest is the union of every lead's. Seeded INCOMPLETE on
        // purpose — see the update below.
        let mut sweep_sources: BTreeSet<String> = BTreeSet::new();

        for prepared in &inputs.leads {
            let fingerprint = derive_fingerprint(&FingerprintInput {
                hunt_id: playbook_id,
                entity: &prepared.entity,
                signals: &prepared.signals,
            });

            // GLOBAL, with no scope predicate, and that is the decision rather
            // than an omission: a suppression the sweep's principal cannot see
            // must still suppress. Scoping this check would make an analyst's
            // dismissal stop working for every sweep whose scope differs from
            // theirs, and dismissal memory is the feature that decides whether
            // the bench is trusted at all.
            //
            // The disclosure that creates — a stored line telling a later reader
            // that an artifact they cannot see EXISTS — is handled where it
            // belongs, at render: the matching suppressions' merged manifest
            // rides along with the contribution and `redact_contributions`
            // re-evaluates it per reader.
            let suppression_row = sqlx::query(
                r#"
                SELECT COUNT(DISTINCT s.id) AS matches,
                       COALESCE(
                           array_agg(DISTINCT st.source_type)
                               FILTER (WHERE st.source_type IS NOT NULL),
                           '{}'::text[]
                       ) AS source_types,
                       COALESCE(bool_and(s.source_types_complete), FALSE) AS source_types_complete
                  FROM hunt_suppressions s
                  LEFT JOIN LATERAL unnest(s.source_types) AS st(source_type) ON TRUE
                 WHERE s.fingerprint = $1
                   AND s.revoked_at IS NULL
                   AND (s.expires_at IS NULL OR s.expires_at > NOW())
                   AND (s.playbook_id IS NULL OR s.playbook_id = $2)
                "#,
            )
            .bind(&fingerprint)
            .bind(playbook_id)
            .fetch_one(&mut *tx)
            .await?;
            let suppressed = suppression_row.try_get::<i64, _>("matches")? > 0;
            let suppression_basis = if suppressed {
                ContributionBasis::from_artifacts(
                    suppression_row.try_get("source_types")?,
                    suppression_row.try_get("source_types_complete")?,
                )
            } else {
                ContributionBasis::references_nothing()
            };

            // DISTINCT sweeps, not distinct leads: a sweep that reported the
            // same shape twice must not read as two occurrences and decay a
            // fresh finding on its first outing.
            //
            // Also global, for the same reason and with the same treatment: the
            // COUNT must be the real one or the score changes with the reader,
            // and a count is not an existence claim — a reader admitted to only
            // SOME of the prior leads would be told a number they cannot
            // account for, so the merged basis withholds unless they are
            // admitted to all of them.
            let recurrence_row = sqlx::query(
                r#"
                SELECT COUNT(DISTINCT l.sweep_id) AS prior_sweeps,
                       COALESCE(
                           array_agg(DISTINCT st.source_type)
                               FILTER (WHERE st.source_type IS NOT NULL),
                           '{}'::text[]
                       ) AS source_types,
                       COALESCE(bool_and(l.source_types_complete), FALSE) AS source_types_complete
                  FROM hunt_leads l
                  LEFT JOIN LATERAL unnest(l.source_types) AS st(source_type) ON TRUE
                 WHERE l.fingerprint = $1 AND l.sweep_id <> $2
                "#,
            )
            .bind(&fingerprint)
            .bind(inputs.sweep_id)
            .fetch_one(&mut *tx)
            .await?;
            let prior_occurrences: i64 = recurrence_row.try_get("prior_sweeps")?;
            let recurrence_basis = if prior_occurrences > 0 {
                ContributionBasis::from_artifacts(
                    recurrence_row.try_get("source_types")?,
                    recurrence_row.try_get("source_types_complete")?,
                )
            } else {
                ContributionBasis::references_nothing()
            };

            let distinct_sources: BTreeSet<String> = prepared
                .evidence
                .iter()
                .map(|e| e.source_type.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();

            let computed = score(&ScoreInputs {
                evidence_count: prepared.evidence.len(),
                distinct_source_types: distinct_sources.len(),
                prevalence: prepared.prevalence,
                first_seen_in_window: prepared.first_seen_in_window,
                suppressed,
                prior_occurrences: prior_occurrences.clamp(0, u32::MAX as i64) as u32,
            });

            let (manifest, complete) = prepared.provenance.clone().into_parts();
            sweep_sources.extend(manifest.iter().cloned());

            let narrative = prepared.narrative.as_deref().map(truncate_chars_fn(MAX_NARRATIVE_CHARS));
            // Stored WITH the provenance of what each referential factor looked
            // at, so a later reader's scope can be applied to the explanation
            // without re-running a check whose answer must not vary by reader.
            let contributions = serde_json::to_value(stamp_contribution_bases(
                computed.contributions,
                &suppression_basis,
                &recurrence_basis,
            ))
            .map_err(|e| HuntError::Internal(format!("contributions not serializable: {e}")))?;

            // Idempotent within a sweep: a retry inside the same lease updates
            // the existing lead rather than stacking a second copy of it. There
            // is no unique index to lean on because a lead's identity is
            // (sweep, fingerprint) only for THIS purpose — across sweeps the
            // same fingerprint recurring is the signal, not a duplicate.
            let existing: Option<Uuid> =
                sqlx::query_scalar("SELECT id FROM hunt_leads WHERE sweep_id = $1 AND fingerprint = $2")
                    .bind(inputs.sweep_id)
                    .bind(&fingerprint)
                    .fetch_optional(&mut *tx)
                    .await?;

            let lead_id: Uuid = match existing {
                Some(id) => {
                    sqlx::query(
                        r#"
                        UPDATE hunt_leads
                           SET entity_type = $2, entity_value = $3, mitre_technique = $4,
                               window_start = $5, window_end = $6, narrative = $7,
                               score = $8::float8::numeric, score_contributions = $9,
                               source_types = $10, source_types_complete = $11,
                               updated_at = NOW()
                         WHERE id = $1
                        "#,
                    )
                    .bind(id)
                    .bind(prepared.entity.entity_type())
                    .bind(prepared.entity.value())
                    .bind(prepared.mitre_technique.as_deref())
                    .bind(window_start)
                    .bind(window_end)
                    .bind(narrative.as_deref())
                    .bind(computed.value)
                    .bind(&contributions)
                    .bind(manifest.clone())
                    .bind(complete)
                    .execute(&mut *tx)
                    .await?;
                    id
                }
                None => {
                    let id: Uuid = sqlx::query_scalar(
                        r#"
                        INSERT INTO hunt_leads (
                            sweep_id, playbook_id, playbook_version,
                            entity_type, entity_value, mitre_technique,
                            window_start, window_end, narrative,
                            score, score_contributions, fingerprint,
                            source_types, source_types_complete
                        )
                        SELECT $1, s.playbook_id, s.playbook_version,
                               $2, $3, $4, $5, $6, $7,
                               $8::float8::numeric, $9, $10, $11, $12
                          FROM hunt_sweeps s WHERE s.id = $1
                        RETURNING id
                        "#,
                    )
                    .bind(inputs.sweep_id)
                    .bind(prepared.entity.entity_type())
                    .bind(prepared.entity.value())
                    .bind(prepared.mitre_technique.as_deref())
                    .bind(window_start)
                    .bind(window_end)
                    .bind(narrative.as_deref())
                    .bind(computed.value)
                    .bind(&contributions)
                    .bind(&fingerprint)
                    .bind(manifest.clone())
                    .bind(complete)
                    .fetch_one(&mut *tx)
                    .await?;
                    leads_created += 1;
                    id
                }
            };

            for (position, event) in prepared.evidence.iter().enumerate() {
                // `uq_hunt_lead_evidence_canonical` makes this idempotent AND
                // stops the same event being stacked to inflate an evidence
                // count — which, because volume feeds the score, would be a way
                // to inflate a score with one event.
                let inserted = sqlx::query(
                    r#"
                    INSERT INTO hunt_lead_evidence (
                        lead_id, event_timestamp, source_type, event_ref,
                        canonical_event_id, summary, position
                    )
                    VALUES ($1, $2, $3, $4, $5, $6, $7)
                    ON CONFLICT (lead_id, canonical_event_id) DO NOTHING
                    "#,
                )
                .bind(lead_id)
                .bind(event.timestamp)
                .bind(&event.source_type)
                .bind(serde_json::json!({
                    "table": "logs",
                    "id": event.canonical_event_id,
                    "timestamp": event.timestamp,
                }))
                .bind(&event.canonical_event_id)
                .bind(truncate_chars(&event.summary, 4096))
                .bind(position as i32)
                .execute(&mut *tx)
                .await?;
                evidence_attached += inserted.rows_affected() as usize;
            }

            self.accrue_rule_idea_basis(
                &mut tx,
                playbook_id,
                inputs.sweep_id,
                lead_id,
                &fingerprint,
                prepared,
                &sweep_query,
                &manifest,
                complete,
            )
            .await?;
        }

        // Knowledge is an OUTPUT of the sweep, never an INPUT to scoring. It
        // lands only after every lead has been scored and persisted, but before
        // the sweep is marked finished, under the same fence transaction.
        let mut knowledge_recorded = 0usize;
        let mut knowledge_rejected = inputs.knowledge_rejected;
        for fact in &inputs.knowledge {
            let (outcome, _) = record_prepared_in_tx(&mut tx, inputs.sweep_id, fact).await?;
            if outcome == RecordOutcome::RefusedRevoked {
                knowledge_rejected += 1;
            } else {
                knowledge_recorded += 1;
            }
        }

        // ---- 4. The sweep row ----------------------------------------------
        let outcome = reconcile_outcome(
            inputs.claimed_outcome.as_deref(),
            &inputs.usage,
            &limits,
            inputs.leads.len(),
        );
        let trail: Vec<&TrailStep> = inputs.trail.iter().take(MAX_TRAIL_STEPS).collect();
        let rows_truncated = inputs.trail.iter().any(TrailStep::was_truncated);
        let trail_json = serde_json::to_value(&trail)
            .map_err(|e| HuntError::Internal(format!("trail not serializable: {e}")))?;

        sqlx::query(
            r#"
            UPDATE hunt_sweeps
               SET status = 'finished',
                   outcome = $2,
                   outcome_detail = $3,
                   turns_used = $4,
                   tool_calls_used = $5,
                   rows_read = $6,
                   rows_truncated = $7,
                   trail = $8,
                   source_types = $9,
                   -- Deliberately never TRUE. A sweep reads more than it cites:
                   -- a manifest derived from the evidence that made it into a
                   -- lead under-reports every source the agent looked at and
                   -- discarded. An under-reporting manifest that claims
                   -- completeness is exactly the leak the contract exists to
                   -- prevent, so a scoped reader sees no sweeps at all — while
                   -- the LEADS, whose evidence IS the whole input, stay
                   -- readable.
                   source_types_complete = FALSE,
                   finished_at = NOW(),
                   lease_expires_at = NULL
             WHERE id = $1
            "#,
        )
        .bind(inputs.sweep_id)
        .bind(outcome)
        .bind(inputs.note.as_deref().map(truncate_chars_fn(MAX_OUTCOME_DETAIL_CHARS)))
        .bind(clamp_i32(inputs.usage.turns as i64))
        .bind(clamp_i32(inputs.usage.tool_calls as i64))
        .bind(clamp_i32(inputs.usage.rows_read.min(i32::MAX as u64) as i64))
        .bind(rows_truncated)
        .bind(&trail_json)
        .bind(sweep_sources.into_iter().collect::<Vec<String>>())
        .execute(&mut *tx)
        .await?;

        // `held` means a required source was unhealthy and we refused to run
        // partial — that is not a success, and recording it as one would make
        // "last successful sweep" a lie on exactly the hunts an operator needs
        // to look at.
        let succeeded = matches!(outcome, "completed" | "no_leads");
        sqlx::query(
            "UPDATE hunt_specs \
                SET last_attempt_at = NOW(), \
                    last_success_at = CASE WHEN $2 THEN NOW() ELSE last_success_at END, \
                    updated_at = NOW() \
              WHERE playbook_id = $1",
        )
        .bind(playbook_id)
        .bind(succeeded)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;

        Ok(SweepReportAccepted {
            sweep_id: inputs.sweep_id,
            outcome: outcome.to_string(),
            leads_created,
            candidates_rejected: inputs.rejected,
            evidence_attached,
            knowledge_recorded,
            knowledge_rejected,
        })
    }

    /// Record that this lead contributes to a rule idea, creating the INERT
    /// idea row if this shape has not been seen before.
    ///
    /// What a sweep may create here is deliberately minimal: `proposed_npl` is
    /// the hunt's OWN `sweep_query`, read from `hunt_specs` inside the commit
    /// transaction, and the name is composed from the hunt title plus the
    /// corroborated entity type. No agent prose reaches this table, because a
    /// rule idea is one human click away from a detection rule and
    /// attacker-influenced text must not have a path into one.
    ///
    /// The counters stay at zero. They are a cache; the gate is computed from
    /// `hunt_rule_idea_basis` in [`Self::reevaluate_rule_idea`].
    #[allow(clippy::too_many_arguments)]
    async fn accrue_rule_idea_basis(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        playbook_id: Uuid,
        sweep_id: Uuid,
        lead_id: Uuid,
        fingerprint: &str,
        prepared: &PreparedLead,
        sweep_query: &str,
        manifest: &[String],
        complete: bool,
    ) -> Result<(), HuntError> {
        // Named from the CORROBORATED entity, not from the narrative. The value
        // is the same one already stored on `hunt_leads.entity_value` and shown
        // on the bench, so this adds no new exposure — but it does make the
        // name unique per shape, which "Recurring host shape" alone was not.
        let name = format!(
            "Recurring {} shape: {}",
            prepared.entity.entity_type(),
            prepared.entity.value()
        );

        // `uq_hunt_rule_ideas_fingerprint` makes this idempotent across sweeps.
        // On conflict the manifest is UNIONED and completeness is ANDed: an
        // idea derived from several leads is only as attributed as its least
        // attributed contributor.
        let idea_id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO hunt_rule_ideas (
                playbook_id, fingerprint, name, proposed_npl, mitre_technique,
                state, source_types, source_types_complete
            )
            VALUES ($1, $2, $3, $4, $5, 'keep_hunting', $6, $7)
            ON CONFLICT (playbook_id, fingerprint) DO UPDATE
               SET source_types = (
                       SELECT COALESCE(array_agg(DISTINCT st ORDER BY st), '{}'::text[])
                         FROM unnest(hunt_rule_ideas.source_types || EXCLUDED.source_types) AS st
                   ),
                   source_types_complete =
                       hunt_rule_ideas.source_types_complete AND EXCLUDED.source_types_complete,
                   updated_at = NOW()
            RETURNING id
            "#,
        )
        .bind(playbook_id)
        .bind(fingerprint)
        .bind(truncate_chars(&name, 200))
        .bind(truncate_chars(sweep_query, 16_384))
        .bind(prepared.mitre_technique.as_deref())
        .bind(manifest.to_vec())
        .bind(complete)
        .fetch_one(&mut **tx)
        .await?;

        // `promoted` is snapshotted FALSE here and only ever set by triage, so
        // the gate is stable if a lead is later re-triaged.
        sqlx::query(
            "INSERT INTO hunt_rule_idea_basis (idea_id, lead_id, sweep_id, promoted) \
             VALUES ($1, $2, $3, FALSE) ON CONFLICT (idea_id, lead_id) DO NOTHING",
        )
        .bind(idea_id)
        .bind(lead_id)
        .bind(sweep_id)
        .execute(&mut **tx)
        .await?;

        // Refresh the cached counters and the derived state from the rows we
        // just added, so `ready` is truthful without an operator poking a
        // button to make it so.
        //
        // Unscoped: this is the sweep's own bookkeeping over an idea it just
        // wrote to. A sweep key's scope gates what EVIDENCE it could read (see
        // `evidence.rs`); applying it to the counter refresh would make a
        // source-scoped sweep unable to recount an idea it had just accrued
        // into, and abort the whole report.
        Self::recompute_rule_idea_gate(tx, idea_id, &ArtifactScope::system()).await?;

        Ok(())
    }

    // =========================================================================
    // Leads
    // =========================================================================

    pub async fn list_leads(
        &self,
        query: &ListLeadsQuery,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntLead>, HuntError> {
        let (sql, scoped) = build_leads_sql(query, scope);
        let mut q = sqlx::query(&sql);
        if let Some(id) = query.playbook_id {
            q = q.bind(id);
        }
        if let Some(id) = query.sweep_id {
            q = q.bind(id);
        }
        if !query.states.is_empty() {
            q = q.bind(query.states.clone());
        }
        if let Some(reviewer) = query.reviewed_by {
            q = q.bind(reviewer);
        }
        if let Some(min) = query.min_score {
            q = q.bind(min);
        }
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let rows = q
            .bind(query.limit)
            .bind(query.offset)
            .fetch_all(&self.pool)
            .await?;
        let mut leads = rows
            .iter()
            .map(lead_from_row)
            .collect::<Result<Vec<_>, _>>()?;
        // The rows that got here already cleared their OWN manifest in SQL.
        // This is the second gate: two of the stored score factors describe
        // artifacts the lead's manifest says nothing about.
        for lead in &mut leads {
            redact_contributions(lead, scope);
        }
        Ok(leads)
    }

    /// How many leads match the filter, past the page window — the header's
    /// "N leads in this queue". Shares [`push_leads_filter`] with
    /// [`Self::list_leads`], so the count is over exactly the rows the page
    /// reads and the artifact-scope predicate cannot be present in one
    /// statement and missing from the other.
    pub async fn count_leads(
        &self,
        query: &ListLeadsQuery,
        scope: &ArtifactScope,
    ) -> Result<i64, HuntError> {
        let (sql, scoped) = build_leads_count_sql(query, scope);
        let mut q = sqlx::query_scalar::<_, i64>(&sql);
        if let Some(id) = query.playbook_id {
            q = q.bind(id);
        }
        if let Some(id) = query.sweep_id {
            q = q.bind(id);
        }
        if !query.states.is_empty() {
            q = q.bind(query.states.clone());
        }
        if let Some(reviewer) = query.reviewed_by {
            q = q.bind(reviewer);
        }
        if let Some(min) = query.min_score {
            q = q.bind(min);
        }
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        Ok(q.fetch_one(&self.pool).await?)
    }

    pub async fn get_lead(
        &self,
        lead_id: Uuid,
        scope: &ArtifactScope,
    ) -> Result<HuntLeadDetail, HuntError> {
        let mut sql = format!("{LEAD_SELECT} WHERE l.id = $1");
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&ArtifactScope::sql_predicate(
                "l.source_types",
                "l.source_types_complete",
                2,
            ));
        }
        let mut q = sqlx::query(&sql).bind(lead_id);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let row = q
            .fetch_optional(&self.pool)
            .await?
            .ok_or(HuntError::LeadNotFound(lead_id))?;
        let mut lead = lead_from_row(&row)?;
        redact_contributions(&mut lead, scope);

        // No second scope predicate here: the evidence rows are children of a
        // lead the caller has already been cleared for by the query above, and
        // they carry no manifest of their own to filter on.
        let evidence_rows = sqlx::query(
            "SELECT * FROM hunt_lead_evidence WHERE lead_id = $1 ORDER BY position ASC, event_timestamp ASC",
        )
        .bind(lead_id)
        .fetch_all(&self.pool)
        .await?;
        let evidence = evidence_rows
            .iter()
            .map(evidence_from_row)
            .collect::<Result<Vec<_>, _>>()?;

        // The sweep that filed this lead, for the provenance block. The FK is
        // `ON DELETE CASCADE`, so a missing sweep can only mean the lead is
        // mid-delete — reported as not-found rather than as a lead with
        // fabricated provenance.
        let sweep_row = sqlx::query(
            "SELECT finished_at, query_sha, source_types, source_types_complete \
               FROM hunt_sweeps WHERE id = $1",
        )
        .bind(lead.sweep_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(HuntError::LeadNotFound(lead_id))?;

        // `query_sha` follows the sweep ledger's redaction rule
        // (`HuntSweep::redact_unattributed`): the SWEEP's manifest can be
        // broader than the lead's, and clearing the lead's gate must not leak
        // the sweep's agent-authored half. `swept_at` is scheduler state — the
        // fact that a sweep ran, and when — and is never redacted.
        let sweep_sources: Vec<String> = sweep_row.try_get("source_types")?;
        let sweep_complete: bool = sweep_row.try_get("source_types_complete")?;
        let query_sha = if scope.allows(&sweep_sources, sweep_complete) {
            sweep_row.try_get("query_sha")?
        } else {
            None
        };
        let provenance = HuntLeadProvenance {
            sweep_id: lead.sweep_id,
            swept_at: sweep_row.try_get("finished_at")?,
            query_sha,
            playbook_version: lead.playbook_version,
            scored_by: LEAD_SCORED_BY.to_string(),
        };

        let contributions = wire_contributions(&lead.score_contributions);
        Ok(HuntLeadDetail {
            lead,
            evidence,
            contributions,
            provenance,
        })
    }

    /// Promote a lead into a case. Idempotent, one transaction.
    ///
    /// The `FOR UPDATE` on the lead is what makes idempotency real rather than
    /// probable: two analysts clicking Promote at the same moment serialize on
    /// the lead row, and the second one finds `promoted_case_id` already set
    /// and returns the SAME case instead of opening a duplicate.
    ///
    /// The derived case title names the hunt and the entity and deliberately
    /// does NOT embed the narrative. The narrative is attacker-influenceable
    /// prose that belongs behind the lead's provenance gate; a case carries no
    /// manifest, so anything copied into one is copied past that gate.
    pub async fn promote_lead(
        &self,
        lead_id: Uuid,
        req: &PromoteLeadRequest,
        actor: Uuid,
        scope: &ArtifactScope,
    ) -> Result<PromoteLeadResponse, HuntError> {
        let mut tx = self.pool.begin().await?;

        let mut sql = String::from(
            "SELECT l.id, l.entity_type, l.entity_value, l.mitre_technique, l.score::float8 AS score, \
                    l.promoted_case_id, l.window_start, l.window_end, p.title AS hunt_title \
               FROM hunt_leads l \
               JOIN playbooks p ON p.id = l.playbook_id \
              WHERE l.id = $1",
        );
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&ArtifactScope::sql_predicate(
                "l.source_types",
                "l.source_types_complete",
                2,
            ));
        }
        sql.push_str(" FOR UPDATE OF l");

        let mut q = sqlx::query(&sql).bind(lead_id);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let Some(row) = q.fetch_optional(&mut *tx).await? else {
            tx.rollback().await?;
            return Err(HuntError::LeadNotFound(lead_id));
        };

        if let Some(case_id) = row.try_get::<Option<Uuid>, _>("promoted_case_id")? {
            let case_number: i32 = sqlx::query_scalar("SELECT case_number FROM cases WHERE id = $1")
                .bind(case_id)
                .fetch_one(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(PromoteLeadResponse {
                lead_id,
                case_id,
                case_number,
                already_promoted: true,
            });
        }

        let entity_type: String = row.try_get("entity_type")?;
        let entity_value: String = row.try_get("entity_value")?;
        let hunt_title: String = row.try_get("hunt_title")?;
        let technique: Option<String> = row.try_get("mitre_technique")?;
        let lead_score: f64 = row.try_get("score")?;
        let window_start: DateTime<Utc> = row.try_get("window_start")?;
        let window_end: DateTime<Utc> = row.try_get("window_end")?;

        let title = req
            .title
            .as_deref()
            .map(str::trim)
            .filter(|t| !t.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| format!("{hunt_title}: {entity_type} {entity_value}"));
        let severity = normalize_case_severity(req.severity.as_deref(), lead_score);

        let case_row = sqlx::query(
            r#"
            INSERT INTO cases (title, description, severity, status, created_by,
                               first_activity_at, last_activity_at, mitre_techniques)
            VALUES ($1, $2, $3, 'open', $4, $5, $6, $7)
            RETURNING id, case_number
            "#,
        )
        .bind(truncate_chars(&title, 500))
        .bind(format!(
            "Promoted from hunt lead {}. Hunt: {hunt_title}. \
             The lead's evidence, score breakdown and narrative stay on the lead, \
             which is the artifact that carries source provenance.",
            crate::typeid::encode("lead", &lead_id)
        ))
        .bind(severity)
        .bind(actor)
        .bind(window_start)
        .bind(window_end)
        .bind(
            technique
                .as_deref()
                .map(|t| vec![t.to_string()])
                .unwrap_or_default(),
        )
        .fetch_one(&mut *tx)
        .await?;
        let case_id: Uuid = case_row.try_get("id")?;
        let case_number: i32 = case_row.try_get("case_number")?;

        // `provenance_recorded = FALSE` is CORRECT here and not an oversight: a
        // hunt lead's entity is not alert-derived, so there is no
        // `case_entity_alerts` row to point at, and NAN-2079's read path treats
        // an unrecorded entity as fail-closed for a source-restricted viewer.
        sqlx::query(
            "INSERT INTO case_entities (case_id, entity_type, entity_value, is_primary, provenance_recorded) \
             VALUES ($1, $2, $3, TRUE, FALSE) \
             ON CONFLICT (case_id, entity_type, entity_value) DO NOTHING",
        )
        .bind(case_id)
        .bind(&entity_type)
        .bind(&entity_value)
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE hunt_leads \
                SET state = 'promoted', promoted_case_id = $2, reviewed_by = $3, \
                    reviewed_at = NOW(), updated_at = NOW() \
              WHERE id = $1",
        )
        .bind(lead_id)
        .bind(case_id)
        .bind(actor)
        .execute(&mut *tx)
        .await?;

        // The gate is "3 sweeps, 2 promotions". Snapshotting the promotion onto
        // every basis row this lead contributed to is what makes the second
        // half of that gate derivable rather than asserted.
        let touched: Vec<Uuid> = sqlx::query_scalar(
            "UPDATE hunt_rule_idea_basis SET promoted = TRUE WHERE lead_id = $1 RETURNING idea_id",
        )
        .bind(lead_id)
        .fetch_all(&mut *tx)
        .await?;
        // The promotion just changed the second half of the gate for every idea
        // this lead contributed to, so recount them here rather than waiting for
        // the next sweep to notice.
        //
        // Unscoped, and NOT the promoting analyst's scope: an idea's basis spans
        // every lead that ever matched its shape, so a scoped recount here would
        // either fail the promotion or — worse — leave a `ready` idea claiming a
        // count it no longer has, because of a sibling lead from a source this
        // analyst cannot see. Whether they may DECIDE the idea is a different
        // question, asked (under the same lock) in `decide_rule_idea`.
        for idea_id in touched {
            Self::recompute_rule_idea_gate(&mut tx, idea_id, &ArtifactScope::system()).await?;
        }

        tx.commit().await?;
        Ok(PromoteLeadResponse {
            lead_id,
            case_id,
            case_number,
            already_promoted: false,
        })
    }

    /// Dismiss a lead. **Always writes a suppression.**
    ///
    /// **This is the only writer of `hunt_suppressions` in the codebase.** It is
    /// reachable only from the `hunts:triage` handler, so an agent — which
    /// carries `hunts:report` and nothing else — has no path to author one. An
    /// agent able to suppress could blind its own successors, which is the one
    /// failure this feature could not recover from silently.
    ///
    /// There is no "dismiss without remembering": per-machine dismissal memory
    /// is worthless, and a bench that re-serves yesterday's rejects is abandoned
    /// in week three. The analyst chooses WIDTH and EXPIRY, never whether.
    pub async fn dismiss_lead(
        &self,
        lead_id: Uuid,
        req: &DismissLeadRequest,
        actor: Uuid,
        scope: &ArtifactScope,
    ) -> Result<DismissLeadResponse, HuntError> {
        let reason = req.reason.trim();
        if reason.is_empty() {
            return Err(HuntError::Validation(
                "a dismissal needs a reason — it is what a future analyst reads when \
                 deciding whether the suppression still applies"
                    .into(),
            ));
        }

        let mut tx = self.pool.begin().await?;

        let mut sql = format!("{LEAD_SELECT} WHERE l.id = $1");
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&ArtifactScope::sql_predicate(
                "l.source_types",
                "l.source_types_complete",
                2,
            ));
        }
        sql.push_str(" FOR UPDATE OF l");
        let mut q = sqlx::query(&sql).bind(lead_id);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let Some(row) = q.fetch_optional(&mut *tx).await? else {
            tx.rollback().await?;
            return Err(HuntError::LeadNotFound(lead_id));
        };
        let lead = lead_from_row(&row)?;

        if lead.state == "promoted" {
            tx.rollback().await?;
            return Err(HuntError::Conflict(
                "a promoted lead cannot be dismissed; close its case instead".into(),
            ));
        }

        sqlx::query(
            "UPDATE hunt_leads SET state = 'dismissed', reviewed_by = $2, reviewed_at = NOW(), \
                    updated_at = NOW() WHERE id = $1",
        )
        .bind(lead_id)
        .bind(actor)
        .execute(&mut *tx)
        .await?;

        let expires_at = req
            .expires_in_days
            .filter(|d| *d > 0)
            .map(|d| Utc::now() + Duration::days(d));
        // `Hunt` width pins the suppression to this hunt; `Tenant` leaves
        // `playbook_id` NULL, which is what makes the fingerprint match across
        // every hunt. That nullable column IS the width dial.
        let scoped_playbook = match req.width {
            SuppressionWidth::Hunt => Some(lead.playbook_id),
            SuppressionWidth::Tenant => None,
        };

        // The suppression INHERITS the lead's manifest: a reader who cannot see
        // the source cannot safely be shown the rule that hides it, nor infer
        // its contents from the entity value it carries.
        let suppression_row = sqlx::query(
            r#"
            INSERT INTO hunt_suppressions (
                fingerprint, playbook_id, entity_type, entity_value, reason,
                created_by, origin_lead_id, expires_at,
                source_types, source_types_complete
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            RETURNING *
            "#,
        )
        .bind(&lead.fingerprint)
        .bind(scoped_playbook)
        .bind(&lead.entity_type)
        .bind(&lead.entity_value)
        .bind(truncate_chars(reason, 2000))
        .bind(actor)
        .bind(lead_id)
        .bind(expires_at)
        .bind(lead.source_types.clone())
        .bind(lead.source_types_complete)
        .fetch_one(&mut *tx)
        .await?;
        let suppression = suppression_from_row(&suppression_row)?;

        tx.commit().await?;

        let mut dismissed = lead;
        dismissed.state = "dismissed".to_string();
        dismissed.reviewed_by = Some(actor);
        // The dismissal response carries the whole lead back, breakdown
        // included. Redacting on the read path but not here would make
        // "dismiss it" a way to fetch the unredacted explanation.
        redact_contributions(&mut dismissed, scope);
        Ok(DismissLeadResponse {
            lead: dismissed,
            suppression,
        })
    }

    // =========================================================================
    // Suppressions
    // =========================================================================

    pub async fn list_suppressions(
        &self,
        include_revoked: bool,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntSuppression>, HuntError> {
        let mut sql = String::from("SELECT s.* FROM hunt_suppressions s WHERE 1 = 1");
        if !include_revoked {
            sql.push_str(" AND s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > NOW())");
        }
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&ArtifactScope::sql_predicate(
                "s.source_types",
                "s.source_types_complete",
                1,
            ));
        }
        sql.push_str(" ORDER BY s.created_at DESC LIMIT 500");
        let mut q = sqlx::query(&sql);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(suppression_from_row).collect()
    }

    /// Author a suppression from a SWEEP (NAN-2240).
    ///
    /// # Every bound is enforced here, not asked of the caller
    ///
    /// This is the most dangerous write in the hunt system: it is the one an
    /// attacker who has got text into a log line would most like to reach. So
    /// the constraints are structural rather than parameters:
    ///
    /// * `origin` is written as the literal `'agent'` — not passed in. A caller
    ///   cannot use this method to forge an analyst-authored row.
    /// * `expires_at` is computed from a CLAMPED ttl. A permanent agent
    ///   suppression is the exact failure 9000054 warned about, and the schema
    ///   CHECK refuses one, but this makes the clamp the only reachable path
    ///   rather than relying on the CHECK to catch a bug.
    /// * `playbook_id`, `entity_type` and `entity_value` are never WRITTEN, so
    ///   the broad forms are unreachable: the row carries one exact fingerprint
    ///   and nothing wider. (The entity is read to FIND the lead; it is not
    ///   stored as a suppression target.)
    /// * The suppression must attach to a lead THIS SWEEP actually filed, named
    ///   by the ENTITY the agent recorded it for. An agent free to name an
    ///   arbitrary target could suppress a finding it never saw, including one
    ///   from a different hunt. The fingerprint is taken FROM that lead, and so
    ///   is the provenance — neither is ever declared by a caller.
    ///
    /// # Why the entity, and not the fingerprint
    ///
    /// The obvious signature takes a fingerprint. It is also unusable: a
    /// fingerprint is DERIVED SERVER-SIDE from the hunt id plus entities the
    /// server resolved from evidence (`hunts::fingerprint`), and the sweep agent
    /// has no way to obtain one. The hunt MCP server it records leads through is
    /// deliberately network-less and knows no hunt id, `record_lead` does not
    /// return a fingerprint, and the environment brief carries knowledge rather
    /// than leads. Asking the agent to echo one back would have been a contract
    /// nothing could satisfy — an unreachable path that looked implemented.
    ///
    /// The entity is what the agent actually holds: it is exactly what it just
    /// passed to `record_lead`. Resolving entity → lead → fingerprint here is
    /// also strictly safer, because it removes the last server-derived value a
    /// caller could have supplied.
    ///
    /// Returns `Ok(None)` when this sweep filed no lead for that entity, which
    /// is a refusal rather than an error: the sweep is told, the run continues,
    /// and nothing is written.
    pub async fn record_agent_suppression(
        &self,
        sweep_id: Uuid,
        entity_type: &str,
        entity_value: &str,
        reason: &str,
        ttl_days: i64,
    ) -> Result<Option<HuntSuppression>, HuntError> {
        let ttl = ttl_days.clamp(MIN_AGENT_SUPPRESSION_TTL_DAYS, MAX_AGENT_SUPPRESSION_TTL_DAYS);
        let row = sqlx::query(
            "INSERT INTO hunt_suppressions \
                 (fingerprint, reason, origin, created_by_sweep_id, origin_lead_id, \
                  expires_at, source_types, source_types_complete) \
             SELECT l.fingerprint, $2, 'agent', $1, l.id, \
                    NOW() + ($5 || ' days')::INTERVAL, l.source_types, l.source_types_complete \
               FROM hunt_leads l \
              WHERE l.sweep_id = $1 AND l.entity_type = $3 AND lower(l.entity_value) = lower($4) \
              ORDER BY l.created_at DESC \
              LIMIT 1 \
             RETURNING *",
        )
        .bind(sweep_id)
        .bind(reason)
        .bind(entity_type)
        .bind(entity_value)
        .bind(ttl.to_string())
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(suppression_from_row).transpose()
    }

    /// Revoke a suppression so its shape can reach the bench again.
    ///
    /// Scoped in the UPDATE itself, not merely in a preflight read: a preflight
    /// cannot be trusted across a concurrent provenance re-stamp, and the same
    /// reasoning is why `tuning`'s state transitions carry the predicate into
    /// the mutation.
    pub async fn revoke_suppression(
        &self,
        suppression_id: Uuid,
        actor: Uuid,
        scope: &ArtifactScope,
    ) -> Result<bool, HuntError> {
        let mut sql = String::from(
            "UPDATE hunt_suppressions s SET revoked_at = NOW(), revoked_by = $2 \
              WHERE s.id = $1 AND s.revoked_at IS NULL",
        );
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&ArtifactScope::sql_predicate(
                "s.source_types",
                "s.source_types_complete",
                3,
            ));
        }
        let mut q = sqlx::query(&sql).bind(suppression_id).bind(actor);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        Ok(q.execute(&self.pool).await?.rows_affected() > 0)
    }

    // =========================================================================
    // Profiles
    // =========================================================================

    pub async fn latest_profile(
        &self,
        scope: &ArtifactScope,
    ) -> Result<Option<HuntProfile>, HuntError> {
        let mut sql = String::from("SELECT p.* FROM hunt_profiles p WHERE 1 = 1");
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&ArtifactScope::sql_predicate(
                "p.source_types",
                "p.source_types_complete",
                1,
            ));
        }
        sql.push_str(" ORDER BY p.created_at DESC LIMIT 1");
        let mut q = sqlx::query(&sql);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let row = q.fetch_optional(&self.pool).await?;
        row.as_ref().map(profile_from_row).transpose()
    }

    // =========================================================================
    // Rule ideas
    // =========================================================================

    pub async fn list_rule_ideas(
        &self,
        playbook_id: Option<Uuid>,
        scope: &ArtifactScope,
    ) -> Result<Vec<HuntRuleIdea>, HuntError> {
        let mut sql = String::from(
            "SELECT i.id, i.playbook_id, i.fingerprint, i.name, i.rationale, i.proposed_npl, \
                    i.proposed_severity, i.proposed_mode, i.mitre_technique, \
                    i.basis_sweep_count, i.basis_promoted_count, \
                    i.precision_estimate::float8 AS precision_estimate, i.backtest, i.state, \
                    i.dac_reference, i.source_types, i.source_types_complete, \
                    i.created_at, i.updated_at \
               FROM hunt_rule_ideas i WHERE 1 = 1",
        );
        let mut param = 1usize;
        if playbook_id.is_some() {
            sql.push_str(&format!(" AND i.playbook_id = ${param}"));
            param += 1;
        }
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&ArtifactScope::sql_predicate(
                "i.source_types",
                "i.source_types_complete",
                param,
            ));
        }
        sql.push_str(" ORDER BY i.updated_at DESC LIMIT 500");
        let mut q = sqlx::query(&sql);
        if let Some(id) = playbook_id {
            q = q.bind(id);
        }
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let rows = q.fetch_all(&self.pool).await?;
        rows.iter().map(rule_idea_from_row).collect()
    }

    /// Recompute a rule idea's basis FROM `hunt_rule_idea_basis` and refresh
    /// both the cached counters and the derived state.
    ///
    /// The cached counters on `hunt_rule_ideas` are never an INPUT here. They
    /// are a denormalized convenience for listing, and the
    /// `hunt_rule_ideas_counter_guard` CHECK over them is trivially satisfied by
    /// writing 3 and 2 — it proves nothing about distinct sweeps or real
    /// promotions. The evidence is the basis rows.
    ///
    /// Called from the sweep commit (which just added basis rows) and from
    /// promotion (which just flipped one to `promoted`), so `state` is truthful
    /// without an operator having to poke a button to make it so.
    ///
    /// # Why the scope predicate rides on the LOCKING read
    ///
    /// `scope` gates the `FOR UPDATE` select itself rather than a preflight
    /// before it. A preflight that cleared the caller and then locked the row
    /// unconditionally leaves a window: `hunt_rule_ideas.source_types` is
    /// re-stamped whenever another sweep's lead accrues into the same idea
    /// ([`Self::accrue_rule_idea_basis`] UNIONs the manifest), so a concurrent
    /// accrual can add a denied source between the check and the lock — and the
    /// decision then lands on an artifact the caller may no longer see. Carrying
    /// the predicate into the locked read makes the authorization and the lock
    /// the same event: under READ COMMITTED, Postgres re-evaluates the qualifier
    /// after acquiring the lock, so a re-stamp that commits first makes this
    /// find no row.
    ///
    /// The two INTERNAL callers pass [`ArtifactScope::system`] deliberately.
    /// Recomputing a counter is server bookkeeping, not a read on anyone's
    /// behalf: a source-scoped analyst promoting a lead must not fail — or, far
    /// worse, leave a stale `ready` — because some OTHER lead in the same idea's
    /// basis came from a source they cannot see. The authorization decision
    /// lives at the caller that has a caller, which is [`Self::decide_rule_idea`].
    async fn recompute_rule_idea_gate(
        tx: &mut Transaction<'_, Postgres>,
        idea_id: Uuid,
        scope: &ArtifactScope,
    ) -> Result<(HuntRuleIdeaBasisCounts, String, String), HuntError> {
        let (sql, scoped) = build_rule_idea_lock_sql(scope);
        let mut q = sqlx::query(&sql).bind(idea_id);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let current = q
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(HuntError::RuleIdeaNotFound(idea_id))?;
        let previous_state: String = current.try_get("state")?;

        // Terminal and human-owned states are NOT recounted, and this is a
        // correctness requirement rather than an optimization.
        //
        // `hunt_rule_ideas_counter_guard` demands `basis_sweep_count >= 3 AND
        // basis_promoted_count >= 2` for any state outside
        // `keep_hunting`/`rejected`. Basis rows cascade away with their lead or
        // sweep, so a `sent` idea whose sweeps have aged out would recompute to
        // counters BELOW the guard — and writing them would violate the CHECK
        // and abort whatever transaction asked for the recount, which during a
        // sweep commit means losing an entire sweep's leads to an unrelated
        // idea's history. A shipped decision's basis snapshot is history; leave
        // it alone.
        if !matches!(previous_state.as_str(), "keep_hunting" | "ready") {
            return Ok((
                HuntRuleIdeaBasisCounts {
                    distinct_sweeps: current.try_get::<i32, _>("basis_sweep_count")? as i64,
                    promoted_leads: current.try_get::<i32, _>("basis_promoted_count")? as i64,
                },
                previous_state.clone(),
                previous_state,
            ));
        }

        let counts_row = sqlx::query(
            "SELECT COUNT(DISTINCT sweep_id) AS distinct_sweeps, \
                    COUNT(*) FILTER (WHERE promoted) AS promoted_leads \
               FROM hunt_rule_idea_basis WHERE idea_id = $1",
        )
        .bind(idea_id)
        .fetch_one(&mut **tx)
        .await?;
        let counts = HuntRuleIdeaBasisCounts {
            distinct_sweeps: counts_row.try_get("distinct_sweeps")?,
            promoted_leads: counts_row.try_get("promoted_leads")?,
        };

        // Only reachable for `keep_hunting` / `ready` — everything else returned
        // above. `sent` and `rejected` are human decisions a recount must not
        // undo, and `needs_lookup` records a missing enrichment that recounting
        // cannot resolve.
        let next_state = if counts.clears_gate() {
            "ready"
        } else {
            "keep_hunting"
        }
        .to_string();

        sqlx::query(
            "UPDATE hunt_rule_ideas \
                SET basis_sweep_count = $2, basis_promoted_count = $3, state = $4, \
                    updated_at = NOW() \
              WHERE id = $1",
        )
        .bind(idea_id)
        .bind(clamp_i32(counts.distinct_sweeps))
        .bind(clamp_i32(counts.promoted_leads))
        .bind(&next_state)
        .execute(&mut **tx)
        .await?;

        Ok((counts, previous_state, next_state))
    }

    /// Ship or reject a rule idea.
    ///
    /// The gate is re-derived from the basis rows inside this transaction
    /// before `send` is allowed, so a stale cached counter can never be what
    /// authorizes shipping. Sending records the human's own reference and
    /// nothing else: the record stays INERT — no repo mount, no git
    /// credentials, no write-capable nanodac tools — because attacker-influenced
    /// lead content must not have a path into a detection rule.
    pub async fn decide_rule_idea(
        &self,
        idea_id: Uuid,
        decision: RuleIdeaVerdict,
        note: Option<&str>,
        scope: &ArtifactScope,
    ) -> Result<RuleIdeaDecision, HuntError> {
        let mut tx = self.pool.begin().await?;

        // Scope and lock in ONE statement. This used to be a separate unlocked
        // preflight followed by an unscoped `FOR UPDATE`, which authorized
        // against a row nobody was holding: `hunt_rule_ideas.source_types` is
        // re-stamped by any concurrent sweep whose lead accrues into this idea,
        // so a manifest that gained a denied source between the two reads was
        // decided on anyway. `recompute_rule_idea_gate` now carries the
        // predicate into its own locking read, so the caller's authorization and
        // the lock are the same event and a losing re-stamp yields no row.
        let (counts, previous_state, _recomputed_state) =
            match Self::recompute_rule_idea_gate(&mut tx, idea_id, scope).await {
                Ok(gate) => gate,
                Err(e) => {
                    tx.rollback().await?;
                    // A scope miss is indistinguishable from a missing idea, on
                    // purpose: telling a caller "it exists but is not yours"
                    // answers the question the predicate is there to refuse.
                    return Err(e);
                }
            };

        let final_state = match decision {
            RuleIdeaVerdict::Reject => "rejected".to_string(),
            RuleIdeaVerdict::Send => {
                if !counts.clears_gate() {
                    tx.rollback().await?;
                    return Err(HuntError::Conflict(format!(
                        "this shape has not earned a rule yet: {} of {} sweeps, {} of {} promotions",
                        counts.distinct_sweeps,
                        RULE_IDEA_MIN_SWEEPS,
                        counts.promoted_leads,
                        RULE_IDEA_MIN_PROMOTIONS
                    )));
                }
                "sent".to_string()
            }
        };

        sqlx::query(
            "UPDATE hunt_rule_ideas \
                SET state = $2, \
                    dac_reference = COALESCE($3, dac_reference), \
                    updated_at = NOW() \
              WHERE id = $1",
        )
        .bind(idea_id)
        .bind(&final_state)
        .bind(note.map(str::trim).filter(|n| !n.is_empty()).map(truncate_chars_fn(500)))
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(RuleIdeaDecision {
            id: idea_id,
            counts,
            state_changed: final_state != previous_state,
            state: final_state,
        })
    }

    // =========================================================================
    // Rail summary
    // =========================================================================

    /// The counts the Hunting rail needs before it can draw anything.
    ///
    /// One statement of scalar subqueries rather than six round trips: they are
    /// all cheap indexed counts, and issuing them together is what stops the
    /// rail rendering four numbers measured at four different instants.
    ///
    /// The scope split is deliberate and documented on [`HuntSummary`]: derived
    /// artifacts are counted under the predicate, scheduler activity is not.
    pub async fn summary_counts(&self, scope: &ArtifactScope) -> Result<SummaryCounts, HuntError> {
        let scoped = !scope.is_unrestricted();
        // $1 is bound once and referenced by both artifact subqueries.
        let lead_scope = if scoped {
            ArtifactScope::sql_predicate("l.source_types", "l.source_types_complete", 1)
        } else {
            String::new()
        };
        let idea_scope = if scoped {
            ArtifactScope::sql_predicate("i.source_types", "i.source_types_complete", 1)
        } else {
            String::new()
        };

        let sql = format!(
            r#"
            SELECT
              (SELECT COUNT(*) FROM hunt_leads l
                WHERE l.state = 'unreviewed'{lead_scope}) AS open_leads,
              (SELECT COUNT(*) FROM hunt_specs h
                 JOIN playbooks p ON p.id = h.playbook_id AND p.kind = 'hunt'
                WHERE p.status <> 'archived') AS hunts_total,
              (SELECT COUNT(*) FROM hunt_specs h
                 JOIN playbooks p ON p.id = h.playbook_id AND p.kind = 'hunt'
                WHERE p.status <> 'archived' AND h.enabled) AS hunts_enabled,
              (SELECT COUNT(*) FROM hunt_sweeps s
                WHERE s.created_at >= NOW() - INTERVAL '24 hours') AS sweeps_24h,
              (SELECT COUNT(*) FROM hunt_specs h
                 JOIN playbooks p ON p.id = h.playbook_id AND p.kind = 'hunt'
                WHERE p.status <> 'archived' AND h.last_attempt_at IS NULL) AS never_swept,
              (SELECT COUNT(*) FROM hunt_rule_ideas i
                WHERE i.state = 'ready'{idea_scope}) AS rule_idea_candidates
            "#
        );

        let mut q = sqlx::query(&sql);
        if scoped {
            q = q.bind(scope.deny_bind_values().to_vec());
        }
        let row = q.fetch_one(&self.pool).await?;
        Ok(SummaryCounts {
            open_leads: row.try_get("open_leads")?,
            hunts_total: row.try_get("hunts_total")?,
            hunts_enabled: row.try_get("hunts_enabled")?,
            sweeps_24h: row.try_get("sweeps_24h")?,
            never_swept: row.try_get("never_swept")?,
            rule_idea_candidates: row.try_get("rule_idea_candidates")?,
        })
    }

    /// Source types required by at least one ENABLED, non-archived hunt.
    ///
    /// The health check runs against THIS set rather than every configured
    /// source: an unhealthy source nothing hunts is a log-sources problem, and
    /// surfacing it on the Hunting rail would be noise the analyst cannot act on
    /// from there.
    pub async fn required_source_types(&self) -> Result<Vec<String>, HuntError> {
        let rows = sqlx::query(
            "SELECT DISTINCT unnest(h.required_source_types) AS source_type \
               FROM hunt_specs h \
               JOIN playbooks p ON p.id = h.playbook_id AND p.kind = 'hunt' \
              WHERE h.enabled AND p.status <> 'archived'",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = Vec::new();
        for row in rows {
            let value: String = row.try_get("source_type")?;
            let value = value.trim().to_lowercase();
            if !value.is_empty() {
                out.push(value);
            }
        }
        out.sort();
        out.dedup();
        Ok(out)
    }

    // =========================================================================
    // Signals
    // =========================================================================

    /// The server's known-signal set: the MITRE technique catalogue plus this
    /// tenant's rule ids, both lowercased.
    ///
    /// This is what `ValidatedSignal::validate` checks against, and it is the
    /// whole defence against fingerprint nonce-ing: an agent that appends a
    /// junk signal to a suppressed finding gets it DROPPED rather than hashed,
    /// so the fingerprint — and therefore the suppression — still matches.
    pub async fn known_signals(&self) -> Result<BTreeSet<String>, HuntError> {
        let rows = sqlx::query(
            "SELECT lower(id) AS signal FROM mitre_techniques \
             UNION SELECT lower(id::text) AS signal FROM detection_rules",
        )
        .fetch_all(&self.pool)
        .await?;
        let mut out = BTreeSet::new();
        for row in rows {
            let signal: String = row.try_get("signal")?;
            if !signal.is_empty() {
                out.insert(signal);
            }
        }
        Ok(out)
    }

    /// Create a `playbooks` row of `kind = 'hunt'` plus its `hunt_specs`
    /// extension, in one transaction.
    ///
    /// `req` carries the shared definition metadata the importer already
    /// assembled (title, category, doc, tags, source linkage); `draft` carries
    /// everything the hunt file was allowed to decide. Two fields of `req` are
    /// deliberately not honoured:
    ///
    /// * `status` — forced to `draft`. The library lifecycle is a separate axis
    ///   from the enable switch, and an import has no standing to publish.
    /// * `danger_policy` / `adaptive` — a hunt has no `/action` steps for a
    ///   danger policy to govern, and is never agent-composed for a case.
    pub async fn create_from_import(
        &self,
        req: &CreatePlaybookRequest,
        parsed_steps: Option<&Value>,
        draft: &HuntSpecDraft,
        user_id: Option<Uuid>,
    ) -> Result<Playbook, HuntError> {
        let scope = req.scope.unwrap_or(PlaybookScope::Tenant);

        let mut tx = self.pool.begin().await?;

        // `kind` is a SQL literal, not a bind. Nothing a caller passes decides
        // it, and `hunt_specs`' composite FK to `playbooks (id, kind)` refuses
        // the row below if it is ever anything else.
        let hunt = sqlx::query_as::<_, Playbook>(
            r#"
            INSERT INTO playbooks (
                title, subtitle, category, doc, parsed_steps,
                match_signals, review_cadence, scope, tags,
                owner_team, status, kind,
                source_repository_id, source_playbook_path, source_linked,
                created_by, maintainer_user_id
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9,
                $10, $11, 'hunt',
                $12, $13, $14,
                $15, $15
            )
            RETURNING *
            "#,
        )
        .bind(&req.title)
        .bind(&req.subtitle)
        .bind(req.category.as_str())
        .bind(&req.doc)
        .bind(parsed_steps)
        .bind(&req.match_signals)
        .bind(req.review_cadence.as_deref().unwrap_or("90d"))
        .bind(scope.as_str())
        .bind(&req.tags)
        .bind(&req.owner_team)
        .bind(PlaybookStatus::Draft.as_str())
        .bind(req.source_repository_id)
        .bind(&req.source_playbook_path)
        .bind(req.source_linked.unwrap_or(false))
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        Self::insert_spec(&mut tx, hunt.id, draft).await?;

        tx.commit().await?;
        Ok(hunt)
    }

    /// Write the `hunt_specs` row for a freshly created hunt.
    ///
    /// THE ONE RULE: this statement does not name the enable switch, and no
    /// future statement in this module may either. The column's `DEFAULT FALSE`
    /// is what decides it, and a human turns it on in the product — where the
    /// act is visibly a privilege decision rather than a markdown diff.
    ///
    /// Any future re-sync / refresh path belongs here too, as an `ON CONFLICT
    /// (playbook_id) DO UPDATE` over this same column list, so that it inherits
    /// the same omission rather than reasoning about it again.
    async fn insert_spec(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        playbook_id: Uuid,
        draft: &HuntSpecDraft,
    ) -> Result<(), HuntError> {
        sqlx::query(
            r#"
            INSERT INTO hunt_specs (
                playbook_id, sweep_query,
                schedule_cron, schedule_timezone, lookback_window,
                required_source_types, mitre_tactic, mitre_technique,
                budget_max_turns, budget_max_tool_calls,
                budget_max_rows, budget_max_wall_seconds
            ) VALUES (
                $1, $2,
                $3, $4, $5,
                $6, $7, $8,
                $9, $10,
                $11, $12
            )
            "#,
        )
        .bind(playbook_id)
        .bind(&draft.sweep_query)
        .bind(&draft.schedule_cron)
        .bind(&draft.schedule_timezone)
        .bind(&draft.lookback_window)
        .bind(&draft.required_source_types)
        .bind(&draft.mitre_tactic)
        .bind(&draft.mitre_technique)
        .bind(draft.budget.max_turns as i32)
        .bind(draft.budget.max_tool_calls as i32)
        .bind(draft.budget.max_rows as i32)
        .bind(draft.budget.max_wall_seconds as i32)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

// =============================================================================
// Score contributions — stored with the provenance of what they REFER to
// =============================================================================
//
// Two of the scorer's factors are not statements about the lead in front of the
// reader. They are statements about OTHER stored artifacts:
//
//   * `suppression` — "an active suppression matches this fingerprint", which
//     is an assertion that a `hunt_suppressions` row exists;
//   * `recurrence`  — "seen in N prior sweeps", which counts `hunt_leads` rows
//     from other sweeps.
//
// Both checks are measured GLOBALLY at commit time and that is deliberate: a
// suppression the sweep principal cannot see must still suppress, or an
// analyst's "never show me this again" quietly stops working for anyone whose
// scope differs from the runner's, and the bench refills with dismissed leads.
// Scoping the CHECK would trade a disclosure for a broken feature.
//
// So the check stays global and the EXPLANATION is re-evaluated per reader. Each
// referential contribution is stored with the provenance of what it referred to,
// and a reader whose scope does not admit that provenance gets a withheld line
// instead of the detail — same factor, same signed value, honest sentence.
//
// What redaction does NOT buy, stated plainly: the signed value stays, because
// the breakdown has to reconcile with the score the reader can already see, and
// a residual is derivable by subtraction whatever we do. A `-0.10 recurrence`
// line still bounds the count at three or more. What is withheld is the exact
// number and the affirmative sentence — and, in the suppression case, the shape
// of the artifact behind it. Blanking the LINE would be worse than either: an
// absent factor is indistinguishable from a check that never ran, which is the
// ambiguity `scoring`'s "−0.00 no suppression matched" exists to prevent.

/// The provenance of the artifact(s) a stored contribution refers to.
///
/// Serialized inside `hunt_leads.score_contributions`, alongside the factor it
/// belongs to, because that is the only place a later reader can re-evaluate it
/// from: the referenced suppression may since have been revoked and the prior
/// leads may since have aged out, and neither absence should be able to turn a
/// withheld line into a disclosed one.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ContributionBasis {
    /// Union of every referenced artifact's manifest.
    #[serde(default)]
    pub source_types: Vec<String>,
    /// AND of every referenced artifact's completeness. Union + AND is exactly
    /// [`SourceProvenance::merge`]'s semantics, which makes
    /// `scope.allows(union, all_complete)` equivalent to "the reader is admitted
    /// to EVERY referenced artifact" — the right test for a claim derived from
    /// all of them.
    #[serde(default)]
    pub complete: bool,
}

impl ContributionBasis {
    /// The check ran and referred to no stored artifact at all — no suppression
    /// matched, no prior sweep produced this shape.
    ///
    /// A complete EMPTY manifest, which [`ArtifactScope::allows`] admits for
    /// every reader. That is the documented meaning of the state (a producer
    /// proving its output contains nothing source-derived), and it is the right
    /// one here: "no suppression matched" reveals no artifact, so withholding it
    /// would cost the analyst a line that says the check ran and bought nothing.
    ///
    /// Constructed directly rather than through [`SourceProvenance`], whose
    /// producer rule refuses to mark an empty manifest complete precisely
    /// because a DERIVED ARTIFACT with no recorded inputs is usually an
    /// unstamped one. This is not an artifact; it is the record of a check.
    pub fn references_nothing() -> Self {
        Self {
            source_types: Vec::new(),
            complete: true,
        }
    }

    /// The merged provenance of the artifacts a check actually found.
    pub fn from_artifacts(source_types: Vec<String>, complete: bool) -> Self {
        let source_types = normalize_sources(&source_types);
        Self {
            // Emptiness is judged AFTER normalization, which is the whole
            // point: a stored `{''}` satisfies the migration's
            // `cardinality(source_types) > 0` CHECK, normalizes to nothing, and
            // would otherwise land as the complete-empty manifest that every
            // reader is admitted to — turning an unattributed suppression into
            // a visible one.
            complete: complete && !source_types.is_empty(),
            source_types,
        }
    }

    fn allows(&self, scope: &ArtifactScope) -> bool {
        scope.allows(&self.source_types, self.complete)
    }
}

/// One contribution as it is persisted: the scorer's own signed factor, plus
/// the basis for the factors that refer to another artifact.
///
/// `#[serde(flatten)]` keeps the stored shape a flat `{factor, value, detail}`
/// object with one extra key, so every existing reader of
/// `score_contributions` — including the bench, which renders `factor`, `value`
/// and `detail` and ignores the rest — is unaffected.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct StoredContribution {
    #[serde(flatten)]
    pub contribution: Contribution,
    /// `None` on rows written before this contract existed. Treated as
    /// unprovable, and therefore withheld, for a restricted reader — the same
    /// direction every other provenance gate in this feature fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub basis: Option<ContributionBasis>,
}

/// Factors whose detail describes another stored artifact, with the sentence a
/// reader gets instead when their scope does not cover it.
///
/// A factor absent from this table needs no basis: `base`, `evidence_volume`,
/// `corroboration`, `rarity` and `first_seen` are all measured from THIS lead's
/// own evidence, which the lead's own manifest already gates.
const REFERENTIAL_FACTORS: &[(&str, &str)] = &[
    ("suppression", "suppression state withheld"),
    ("recurrence", "prior occurrences withheld"),
];

/// What a reader gets when the stored breakdown cannot be parsed at all.
///
/// Fail-closed rather than pass-through: an unreadable breakdown is one this
/// code cannot classify, and handing it over unclassified is the one outcome
/// the gate exists to prevent. It is still a LINE rather than an empty list,
/// for the reason in the module comment above.
const UNREADABLE_BREAKDOWN_DETAIL: &str = "score breakdown withheld";

/// What a factor OUTSIDE [`REFERENTIAL_FACTORS`] gets if it ever carries a
/// basis the reader is not admitted to. Nothing emits one today; the branch
/// exists so a future factor that starts referencing another artifact is
/// redacted by default rather than by remembering to add a sentence here.
const WITHHELD_DETAIL_FALLBACK: &str = "detail withheld";

/// Attach each factor's basis on the way to storage.
///
/// Every referential factor gets one — including the negative case, which gets
/// [`ContributionBasis::references_nothing`]. That is what makes a MISSING
/// basis unambiguous: it can only mean a row written before this contract, and
/// those fail closed.
fn stamp_contribution_bases(
    contributions: Vec<Contribution>,
    suppression: &ContributionBasis,
    recurrence: &ContributionBasis,
) -> Vec<StoredContribution> {
    contributions
        .into_iter()
        .map(|contribution| {
            let basis = match contribution.factor.as_str() {
                "suppression" => Some(suppression.clone()),
                "recurrence" => Some(recurrence.clone()),
                _ => None,
            };
            StoredContribution {
                contribution,
                basis,
            }
        })
        .collect()
}

/// Replace the details a reader's source scope does not cover.
///
/// The lead itself has already passed its own provenance gate by the time this
/// runs — this is only about the factors that speak for OTHER artifacts.
fn redact_contributions(lead: &mut HuntLead, scope: &ArtifactScope) {
    if scope.is_unrestricted() {
        return;
    }
    // Taken rather than cloned: the bench redacts every row it returns, and the
    // only paths out of here either replace the value or put the redacted list
    // back.
    let raw = std::mem::take(&mut lead.score_contributions);
    let Ok(stored) = serde_json::from_value::<Vec<StoredContribution>>(raw) else {
        lead.score_contributions = serde_json::json!([{
            "factor": "redacted",
            "value": 0.0,
            "detail": UNREADABLE_BREAKDOWN_DETAIL,
        }]);
        return;
    };

    let redacted: Vec<StoredContribution> = stored
        .into_iter()
        .map(|mut entry| {
            let Some((_, withheld)) = REFERENTIAL_FACTORS
                .iter()
                .find(|(factor, _)| *factor == entry.contribution.factor)
            else {
                // Not referential. It may still carry a basis if a future
                // factor grows one, in which case that basis decides.
                if entry.basis.as_ref().is_some_and(|b| !b.allows(scope)) {
                    entry.contribution.detail = WITHHELD_DETAIL_FALLBACK.to_string();
                    entry.basis = None;
                }
                return entry;
            };
            let admitted = entry.basis.as_ref().is_some_and(|b| b.allows(scope));
            if !admitted {
                entry.contribution.detail = (*withheld).to_string();
                // The basis itself is a manifest of artifacts this reader
                // cannot see. Returning it would leak by name what the detail
                // just refused to state.
                entry.basis = None;
            }
            entry
        })
        .collect();

    match serde_json::to_value(&redacted) {
        Ok(value) => lead.score_contributions = value,
        // Unreachable in practice — this round-trips a value that just
        // deserialized — but the fallback must not be "ship the unredacted
        // one".
        Err(_) => {
            lead.score_contributions = serde_json::json!([{
                "factor": "redacted",
                "value": 0.0,
                "detail": UNREADABLE_BREAKDOWN_DETAIL,
            }])
        }
    }
}

/// The flat `{factor, value, detail}` list the bench's "why this score" block
/// renders, from the stored (and by now redacted) breakdown.
///
/// The stored shape ([`StoredContribution`]) carries each factor's provenance
/// basis; the bench does not read it, so it is dropped rather than serialized
/// — serving it would put a manifest of artifact source types on a wire field
/// nothing consumes. A breakdown that cannot be parsed lands as the same
/// single withheld line `redact_contributions` uses, never as an empty list:
/// an empty "why" block is indistinguishable from "no factors ran".
fn wire_contributions(stored: &Value) -> Vec<Contribution> {
    match serde_json::from_value::<Vec<StoredContribution>>(stored.clone()) {
        Ok(entries) => entries.into_iter().map(|e| e.contribution).collect(),
        Err(_) => vec![Contribution {
            factor: "redacted".to_string(),
            value: 0.0,
            detail: UNREADABLE_BREAKDOWN_DETAIL.to_string(),
        }],
    }
}

/// Which way a rule-idea decision goes. Two compile-time literals — nothing
/// here is caller-influenced, so no decision string can reach the `state`
/// column from a request body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleIdeaVerdict {
    Send,
    Reject,
}

/// The scalar half of the rail summary — everything answerable from Postgres.
/// The recon profile and source health are composed on top in the service.
#[derive(Debug, Clone, Copy)]
pub struct SummaryCounts {
    pub open_leads: i64,
    pub hunts_total: i64,
    pub hunts_enabled: i64,
    pub sweeps_24h: i64,
    pub never_swept: i64,
    pub rule_idea_candidates: i64,
}

/// Preflight facts about a leased sweep. See
/// [`HuntRepository::sweep_report_context`] for why this read is deliberately
/// unlocked.
pub struct SweepReportContext {
    pub playbook_id: Uuid,
    pub window_start: Option<DateTime<Utc>>,
    pub window_end: Option<DateTime<Utc>>,
    pub sweep_query: String,
    pub limits: BudgetLimits,
}

// =============================================================================
// SQL builders (pure — the scope predicate is testable without a database)
// =============================================================================

/// Shared lead projection. `score` is cast to `float8` because the column is
/// `NUMERIC(4,3)`; reading it as a Rust `f64` without the cast is a decode
/// error at runtime, not a compile error.
const LEAD_SELECT: &str = r#"
    SELECT l.id, l.sweep_id, l.playbook_id, l.playbook_version, p.title AS hunt_title,
           l.entity_type, l.entity_value, l.mitre_technique,
           l.window_start, l.window_end, l.narrative,
           l.score::float8 AS score, l.score_contributions, l.fingerprint,
           l.state, l.reviewed_by, l.reviewed_at, l.promoted_case_id,
           l.source_types, l.source_types_complete, l.created_at, l.updated_at
      FROM hunt_leads l
      JOIN playbooks p ON p.id = l.playbook_id
"#;

/// Build the rule-idea locking read. Returns the SQL and whether a deny array
/// must be bound as `$2`.
///
/// Pure for the same reason [`build_leads_sql`] is: the property that matters —
/// the scope predicate is part of the LOCKING statement rather than a preflight
/// before it — is a property of one string, and a test that needs a database to
/// prove an authorization filter exists is a test that does not run in CI.
///
/// The projection stays unqualified. The cached counters it reads feed only the
/// terminal-state early return, never the gate, and
/// `the_gate_is_recomputed_from_basis_rows_not_from_the_cached_counters` treats
/// a qualified reference to them as the tell that someone started branching on
/// them.
fn build_rule_idea_lock_sql(scope: &ArtifactScope) -> (String, bool) {
    let mut sql = String::from(
        "SELECT state, basis_sweep_count, basis_promoted_count \
           FROM hunt_rule_ideas i WHERE i.id = $1",
    );
    let scoped = !scope.is_unrestricted();
    if scoped {
        sql.push_str(&ArtifactScope::sql_predicate(
            "i.source_types",
            "i.source_types_complete",
            2,
        ));
    }
    // Last, and after the predicate: `FOR UPDATE` closes the statement, so a
    // predicate appended behind it is a syntax error rather than a weaker gate.
    sql.push_str(" FOR UPDATE");
    (sql, scoped)
}

/// Append the bench filters shared by the page read and its companion count.
/// Returns the next free `$n` and whether a deny array must be bound.
///
/// ONE builder for both statements, deliberately: a count that assembled its
/// own WHERE could disagree with the rows it claims to describe — and, worse,
/// could drop the artifact-scope predicate and turn the header count into an
/// oracle for how many denied leads exist.
fn push_leads_filter(sql: &mut String, query: &ListLeadsQuery, scope: &ArtifactScope) -> (usize, bool) {
    sql.push_str(" WHERE 1 = 1");
    let mut param = 1usize;
    if query.playbook_id.is_some() {
        sql.push_str(&format!(" AND l.playbook_id = ${param}"));
        param += 1;
    }
    if query.sweep_id.is_some() {
        sql.push_str(&format!(" AND l.sweep_id = ${param}"));
        param += 1;
    }
    if !query.states.is_empty() {
        // `= ANY` against a bound text[], because the bench's segments are
        // MULTI-state (`state=unreviewed,in_review`). The old form emitted an
        // equality and bound the whole comma-joined string, which matched no
        // row ever — the Unreviewed tab read 0 while unreviewed leads sat in
        // the table. States are validated against `LEAD_STATES` in the handler
        // and bound, never interpolated.
        sql.push_str(&format!(" AND l.state = ANY(${param})"));
        param += 1;
    }
    if query.reviewed_by.is_some() {
        // `mine=true`: leads whose verdict the caller recorded. `reviewed_by`
        // is stamped by promote and dismiss only, so this is "leads I
        // triaged" — there is no assignment concept to filter on.
        sql.push_str(&format!(" AND l.reviewed_by = ${param}"));
        param += 1;
    }
    if query.min_score.is_some() {
        sql.push_str(&format!(" AND l.score >= ${param}::float8::numeric"));
        param += 1;
    }
    let scoped = !scope.is_unrestricted();
    if scoped {
        // In the WHERE clause, so denied rows are excluded BEFORE LIMIT/OFFSET.
        // A post-fetch filter would still page over them and make the page size
        // an oracle for how many exist.
        sql.push_str(&ArtifactScope::sql_predicate(
            "l.source_types",
            "l.source_types_complete",
            param,
        ));
        param += 1;
    }
    (param, scoped)
}

/// Build the bench query. Returns the SQL and whether a deny array must be
/// bound.
///
/// Split out as a pure function so `list_leads_is_always_scoped` can assert the
/// predicate is present without a database — a test that needs Postgres to
/// prove an authorization filter exists is a test that does not run in CI.
fn build_leads_sql(query: &ListLeadsQuery, scope: &ArtifactScope) -> (String, bool) {
    let mut sql = LEAD_SELECT.to_string();
    let (param, scoped) = push_leads_filter(&mut sql, query, scope);
    sql.push_str(&format!(
        " ORDER BY l.score DESC, l.created_at DESC LIMIT ${} OFFSET ${}",
        param,
        param + 1
    ));
    (sql, scoped)
}

/// Build the bench count — the same filters, no page window. This is what the
/// header's "N leads in this queue" reads; without it the desktop fell back to
/// zero and the queue claimed to be empty above the very rows it listed.
fn build_leads_count_sql(query: &ListLeadsQuery, scope: &ArtifactScope) -> (String, bool) {
    // The JOIN is kept identical to `LEAD_SELECT` (playbook_id is a NOT NULL
    // FK, so it never changes the row count) so the two statements stay
    // textually parallel and a future filter on `p.*` cannot break only one.
    let mut sql = String::from(
        "SELECT COUNT(*) FROM hunt_leads l JOIN playbooks p ON p.id = l.playbook_id",
    );
    let (_, scoped) = push_leads_filter(&mut sql, query, scope);
    (sql, scoped)
}

// =============================================================================
// Row mapping
// =============================================================================

fn hunt_from_row(row: &sqlx::postgres::PgRow) -> Result<Hunt, HuntError> {
    Ok(Hunt {
        playbook_id: row.try_get("playbook_id")?,
        title: row.try_get("title")?,
        subtitle: row.try_get("subtitle")?,
        // `try_get` errors when the COLUMN is absent, which is the normal case
        // for the list projection — so a miss is mapped to `None` rather than
        // failing the whole row.
        doc: row.try_get("doc").ok().flatten(),
        steps: row.try_get("steps").ok().flatten(),
        category: row.try_get("category")?,
        status: row.try_get("status")?,
        tags: row.try_get("tags")?,
        sweep_query: row.try_get("sweep_query")?,
        schedule_cron: row.try_get("schedule_cron")?,
        schedule_timezone: row.try_get("schedule_timezone")?,
        required_source_types: row.try_get("required_source_types")?,
        mitre_tactic: row.try_get("mitre_tactic")?,
        mitre_technique: row.try_get("mitre_technique")?,
        enabled: row.try_get("enabled")?,
        budget_max_turns: row.try_get("budget_max_turns")?,
        budget_max_tool_calls: row.try_get("budget_max_tool_calls")?,
        budget_max_rows: row.try_get("budget_max_rows")?,
        budget_max_wall_seconds: row.try_get("budget_max_wall_seconds")?,
        lookback_window: row.try_get("lookback_window")?,
        max_catchup_lookback: row.try_get("max_catchup_lookback")?,
        next_due_slot: row.try_get("next_due_slot")?,
        coalesced_through_slot: row.try_get("coalesced_through_slot")?,
        last_attempt_at: row.try_get("last_attempt_at")?,
        last_success_at: row.try_get("last_success_at")?,
        auto_promote_threshold: row.try_get("auto_promote_threshold")?,
        auto_promote: row.try_get("auto_promote")?,
        generated_from_profile: row.try_get("generated_from_profile")?,
        generated_at: row.try_get("generated_at")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn runner_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntRunner, HuntError> {
    let agy_waiver_granted_at: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("agy_waiver_granted_at")?;
    let agy_waiver_revoked_at: Option<chrono::DateTime<chrono::Utc>> =
        row.try_get("agy_waiver_revoked_at")?;
    Ok(HuntRunner {
        id: row.try_get("id")?,
        label: row.try_get("label")?,
        hostname: row.try_get("hostname")?,
        agent_tool: row.try_get("agent_tool")?,
        agent_model: row.try_get("agent_model")?,
        registered_by: row.try_get("registered_by")?,
        fence_token: row.try_get("fence_token")?,
        last_heartbeat_at: row.try_get("last_heartbeat_at")?,
        enabled: row.try_get("enabled")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
        // Derived here rather than stored, so the flag and the timestamps can
        // never disagree (NAN-2264).
        agy_waiver_granted: crate::hunts::models::agy_waiver_in_force(
            agy_waiver_granted_at,
            agy_waiver_revoked_at,
        ),
        agy_waiver_granted_at,
        agy_waiver_granted_by: row.try_get("agy_waiver_granted_by")?,
        agy_waiver_revoked_at,
    })
}

/// Every query that feeds this MUST select `leads_produced` alongside the
/// row (`(SELECT COUNT(*) FROM hunt_leads l WHERE l.sweep_id = …) AS
/// leads_produced`) — the `try_get` below fails loudly on a query that
/// forgot, rather than defaulting to a fabricated zero the ledger would
/// present as a measurement (NAN-2243).
fn sweep_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntSweep, HuntError> {
    Ok(HuntSweep {
        id: row.try_get("id")?,
        playbook_id: row.try_get("playbook_id")?,
        playbook_version: row.try_get("playbook_version")?,
        schedule_slot: row.try_get("schedule_slot")?,
        runner_id: row.try_get("runner_id")?,
        runner_fence: row.try_get("runner_fence")?,
        lease_expires_at: row.try_get("lease_expires_at")?,
        trigger: row.try_get("trigger")?,
        status: row.try_get("status")?,
        outcome: row.try_get("outcome")?,
        outcome_detail: row.try_get("outcome_detail")?,
        window_start: row.try_get("window_start")?,
        window_end: row.try_get("window_end")?,
        started_at: row.try_get("started_at")?,
        finished_at: row.try_get("finished_at")?,
        turns_used: row.try_get("turns_used")?,
        tool_calls_used: row.try_get("tool_calls_used")?,
        rows_read: row.try_get("rows_read")?,
        rows_truncated: row.try_get("rows_truncated")?,
        leads_produced: row.try_get("leads_produced")?,
        trail: row.try_get("trail")?,
        query_sha: row.try_get("query_sha")?,
        source_types: row.try_get("source_types")?,
        source_types_complete: row.try_get("source_types_complete")?,
        created_at: row.try_get("created_at")?,
        redacted: false,
    })
}

fn lead_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntLead, HuntError> {
    Ok(HuntLead {
        id: row.try_get("id")?,
        sweep_id: row.try_get("sweep_id")?,
        playbook_id: row.try_get("playbook_id")?,
        playbook_version: row.try_get("playbook_version")?,
        hunt_title: row.try_get::<Option<String>, _>("hunt_title").unwrap_or(None),
        entity_type: row.try_get("entity_type")?,
        entity_value: row.try_get("entity_value")?,
        mitre_technique: row.try_get("mitre_technique")?,
        window_start: row.try_get("window_start")?,
        window_end: row.try_get("window_end")?,
        narrative: row.try_get("narrative")?,
        score: row.try_get("score")?,
        score_contributions: row.try_get("score_contributions")?,
        fingerprint: row.try_get("fingerprint")?,
        state: row.try_get("state")?,
        reviewed_by: row.try_get("reviewed_by")?,
        reviewed_at: row.try_get("reviewed_at")?,
        promoted_case_id: row.try_get("promoted_case_id")?,
        source_types: row.try_get("source_types")?,
        source_types_complete: row.try_get("source_types_complete")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

fn evidence_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntLeadEvidence, HuntError> {
    Ok(HuntLeadEvidence {
        id: row.try_get("id")?,
        lead_id: row.try_get("lead_id")?,
        event_timestamp: row.try_get("event_timestamp")?,
        source_type: row.try_get("source_type")?,
        event_ref: row.try_get("event_ref")?,
        canonical_event_id: row.try_get("canonical_event_id")?,
        summary: row.try_get("summary")?,
        position: row.try_get("position")?,
        created_at: row.try_get("created_at")?,
    })
}

fn suppression_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntSuppression, HuntError> {
    Ok(HuntSuppression {
        id: row.try_get("id")?,
        fingerprint: row.try_get("fingerprint")?,
        playbook_id: row.try_get("playbook_id")?,
        entity_type: row.try_get("entity_type")?,
        entity_value: row.try_get("entity_value")?,
        reason: row.try_get("reason")?,
        origin: row.try_get("origin")?,
        created_by: row.try_get("created_by")?,
        created_by_sweep_id: row.try_get("created_by_sweep_id")?,
        origin_lead_id: row.try_get("origin_lead_id")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        revoked_at: row.try_get("revoked_at")?,
        revoked_by: row.try_get("revoked_by")?,
        source_types: row.try_get("source_types")?,
        source_types_complete: row.try_get("source_types_complete")?,
    })
}

fn profile_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntProfile, HuntError> {
    Ok(HuntProfile {
        id: row.try_get("id")?,
        census: row.try_get("census")?,
        fingerprint: row.try_get("fingerprint")?,
        huntable_surface: row.try_get("huntable_surface")?,
        actor_weighting: row.try_get("actor_weighting")?,
        degraded: row.try_get("degraded")?,
        degraded_detail: row.try_get("degraded_detail")?,
        source_types: row.try_get("source_types")?,
        source_types_complete: row.try_get("source_types_complete")?,
        generated_by: row.try_get("generated_by")?,
        runner_id: row.try_get("runner_id")?,
        created_at: row.try_get("created_at")?,
    })
}

fn rule_idea_from_row(row: &sqlx::postgres::PgRow) -> Result<HuntRuleIdea, HuntError> {
    Ok(HuntRuleIdea {
        id: row.try_get("id")?,
        playbook_id: row.try_get("playbook_id")?,
        fingerprint: row.try_get("fingerprint")?,
        name: row.try_get("name")?,
        rationale: row.try_get("rationale")?,
        proposed_npl: row.try_get("proposed_npl")?,
        proposed_severity: row.try_get("proposed_severity")?,
        proposed_mode: row.try_get("proposed_mode")?,
        mitre_technique: row.try_get("mitre_technique")?,
        basis_sweep_count: row.try_get("basis_sweep_count")?,
        basis_promoted_count: row.try_get("basis_promoted_count")?,
        precision_estimate: row.try_get("precision_estimate")?,
        backtest: row.try_get("backtest")?,
        state: row.try_get("state")?,
        dac_reference: row.try_get("dac_reference")?,
        source_types: row.try_get("source_types")?,
        source_types_complete: row.try_get("source_types_complete")?,
        created_at: row.try_get("created_at")?,
        updated_at: row.try_get("updated_at")?,
    })
}

// =============================================================================
// Small helpers
// =============================================================================

fn normalize_sources(values: &[String]) -> Vec<String> {
    crate::auth::normalize_source_manifest(values)
}

fn validate_hunt_text(title: &str, category: &str, sweep_query: &str) -> Result<(), HuntError> {
    if title.trim().is_empty() {
        return Err(HuntError::Validation("title must not be empty".into()));
    }
    if sweep_query.trim().is_empty() {
        return Err(HuntError::Validation("sweep_query must not be empty".into()));
    }
    // Mirrors `playbooks_category_check`. Rejecting here turns a 500 from a
    // constraint violation into an actionable 400.
    const CATEGORIES: &[&str] = &["identity", "endpoint", "cloud", "data", "network", "email"];
    if !CATEGORIES.contains(&category.trim().to_lowercase().as_str()) {
        return Err(HuntError::Validation(format!(
            "category must be one of {CATEGORIES:?}"
        )));
    }
    Ok(())
}

/// Map a server-computed score onto a case severity when the analyst does not
/// override it.
///
/// Only ever the DERIVED score decides — an agent has no field to propose a
/// severity, and mapping one from its narrative would reintroduce the same
/// self-assessment the scorer exists to replace.
fn normalize_case_severity(requested: Option<&str>, score: f64) -> String {
    const ALLOWED: &[&str] = &["critical", "high", "medium", "low", "informational"];
    if let Some(requested) = requested.map(str::trim).map(str::to_lowercase) {
        if ALLOWED.contains(&requested.as_str()) {
            return requested;
        }
    }
    match score {
        s if s >= 0.85 => "critical",
        s if s >= 0.65 => "high",
        s if s >= 0.40 => "medium",
        _ => "low",
    }
    .to_string()
}

/// Truncate by CHARACTERS, not bytes. The Postgres CHECKs are `length()`, which
/// counts characters; truncating by bytes would both mis-measure and be able to
/// split a UTF-8 sequence.
fn truncate_chars(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        value.chars().take(max).collect()
    }
}

fn truncate_chars_fn(max: usize) -> impl Fn(&str) -> String {
    move |value: &str| truncate_chars(value, max)
}

/// Saturate rather than wrap. A runner reporting an absurd count should skew a
/// dashboard, not overflow into a negative and trip
/// `hunt_rule_ideas_counters_nonneg`.
fn clamp_i32(value: i64) -> i32 {
    value.clamp(0, i32::MAX as i64) as i32
}

#[cfg(test)]
mod enable_switch_tests {
    /// This module's own source, read at compile time.
    ///
    /// Self-referential on purpose: a path-relative `include_str!` travels with
    /// the file, so if the open-core mirror ever strips this module the test is
    /// stripped with it. An absolute `CARGO_MANIFEST_DIR` path would survive
    /// the strip and break the mirror build (NAN-2169).
    const SOURCE: &str = include_str!("repository.rs");

    /// No statement in this module may write `hunt_specs.enabled`.
    ///
    /// The rule this enforces is not a preference about defaults. A hunt is an
    /// autonomous process that reads production telemetry on a cron. If an
    /// import path could switch one on, merge access to a content repository
    /// would silently become equivalent to holding `hunts:run` — an enormous
    /// privilege, granted by approving a markdown file, with the reviewer
    /// reading prose rather than a permission grant.
    ///
    /// The grep is crude on purpose. A future change that adds `enabled` to the
    /// column list, binds a variable named `enabled`, or writes `SET enabled =`
    /// in a refresh path trips it, and the person who wrote it has to come read
    /// this comment and say out loud what they are doing. That is the whole
    /// mechanism: not prevention, but forced acknowledgement at the one place
    /// where the mistake is invisible in review.
    #[test]
    fn hunt_specs_never_writes_the_enable_switch() {
        let production = SOURCE
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(SOURCE);

        // Scope the scan to the IMPORT path.
        //
        // `toggle_hunt` writes `enabled` and must — it is the human-operated
        // switch this whole rule exists to protect. The invariant was never
        // "nothing in this file touches the column"; it is "nothing an IMPORT
        // reaches can". Scanning the whole module conflated the two the moment
        // the operator surface landed beside the importer, and a guard that
        // fires on the legitimate case is one somebody deletes.
        let import_fn = production
            .split_once("pub async fn create_from_import")
            .map(|(_, after)| after)
            .expect("create_from_import is the import path this guard protects");
        // Bound by brace depth, not by "the next fn": create_from_import is the
        // last method in the impl, so a naive forward search runs on into the
        // row mappers below — which read `enabled` perfectly legitimately.
        // Both halves of the import write path. After the merge the hunt_specs
        // INSERT sits in `insert_spec`, called from `create_from_import` — and
        // THAT is the statement that could name the switch, so a scan covering
        // only the caller would miss the thing this guard exists for.
        let bounded = |src: &str, marker: &str| -> String {
            let Some((_, after)) = src.split_once(marker) else {
                return String::new();
            };
            let start = match after.find('{') {
                Some(i) => i,
                None => return String::new(),
            };
            let mut depth = 0usize;
            let mut end = after.len();
            for (i, c) in after.char_indices().skip(start) {
                match c {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            end = i + 1;
                            break;
                        }
                    }
                    _ => {}
                }
            }
            after[start..end].to_string()
        };
        let import_fn = format!(
            "{}\n{}",
            bounded(production, "pub async fn create_from_import"),
            bounded(production, "async fn insert_spec"),
        );
        let import_fn = import_fn.as_str();


        let offenders: Vec<String> = import_fn
            .lines()
            .enumerate()
            // Prose is where this rule is EXPLAINED, so comment lines are
            // exempt — otherwise the guard would fail on its own rationale.
            .filter(|(_, line)| !line.trim_start().starts_with("//"))
            .filter(|(_, line)| line.contains("enabled"))
            .map(|(idx, line)| format!("line {}: {}", idx + 1, line.trim()))
            .collect();

        assert!(
            offenders.is_empty(),
            "a synced hunt must land DISABLED — `hunt_specs.enabled` is written nowhere in \
             this module, so the column takes its DEFAULT FALSE. Something here now mentions \
             it outside a comment, which means a merged markdown file may be one step from \
             starting an unattended sweep against production telemetry. See the test's \
             doc comment:\n{}",
            offenders.join("\n")
        );

        // A scanner that matches nothing is indistinguishable from a clean
        // file. Pin the write sites so a refactor that moves them somewhere
        // this guard cannot see has to be acknowledged too.
        let write_sites = import_fn.matches("INSERT INTO ").count();
        assert!(
            write_sites >= 2,
            "expected the playbooks + hunt_specs inserts in this module, found {write_sites} \
             — either they moved somewhere the enable-switch guard cannot see, or the \
             matcher stopped working"
        );
    }

    /// The `playbooks` row is created with a literal kind, so no caller-supplied
    /// value can produce a response playbook through the hunt path (or a hunt
    /// through a response path, which the composite FK would then accept).
    #[test]
    fn the_playbooks_insert_pins_kind_as_a_literal() {
        assert!(
            SOURCE.contains("'hunt',"),
            "the playbooks INSERT must write kind as the literal 'hunt', not a bind"
        );
    }
}

#[cfg(test)]
#[path = "repository_tests.rs"]
mod repository_tests;
