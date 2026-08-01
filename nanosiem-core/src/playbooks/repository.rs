// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database repository for playbooks.
//!
//! Handles CRUD for `playbooks`, `playbook_versions`, `playbook_runs`,
//! `playbook_permissions`, and `playbook_approvals`.

use serde_json::Value;
use sqlx::{PgPool, QueryBuilder};
use uuid::Uuid;

use super::acl::{
    acl_sql, is_synthetic_role, push_acl, PlaybookAction, PlaybookPrincipal, SYNTHETIC_ROLES,
};
use super::error::PlaybookError;
use super::models::{
    CreatePlaybookRequest, ForkPlaybookRequest, ListPlaybooksQuery, Playbook, PlaybookApproval,
    PlaybookPermission, PlaybookRun, PlaybookScope, PlaybookStatus, PlaybookVersion,
    UpdatePlaybookRequest,
};

/// Restricts every query in this repository to RESPONSE playbooks.
///
/// NAN-2238 made `playbooks` a SHARED definition table: a hunt is a `playbooks`
/// row of `kind = 'hunt'`, extended by `hunt_specs`. The two kinds deliberately
/// do not share a runtime, an audience, or a permission set — `playbooks:*`
/// grants authority over case-response procedure, `hunts:*` over what runs
/// unattended against the whole log estate on a schedule.
///
/// Without this predicate on every read, a `playbooks:view` holder would fetch
/// hunt definitions through the playbook API and bypass `hunts:view` outright,
/// a `playbooks:run` holder could attach a hunt to a case, and hunts would
/// render in the Playbooks library as malformed response playbooks. The
/// database enforces the other direction — `playbooks_id_kind_key` plus the
/// constant-kind composite FKs stop a hunt spec, sweep or rule idea attaching
/// to a response playbook — but it cannot infer which kind a *reader* meant.
///
/// Hunts are reached only through the hunts facade, which enforces `hunts:*`.
/// A new query in this file that omits this predicate is an authorization bug;
/// `response_repository_queries_are_kind_scoped` is the regression guard.
const RESPONSE_KIND: &str = "playbooks.kind = 'response'";

/// NAN-469 — bundle of inputs required to build a manual-attach
/// `run_context` snapshot. Returned by
/// [`PlaybookRepository::fetch_case_snapshot_inputs`] and consumed by
/// [`super::runtime::build_snapshot_from_case`].
#[derive(Debug, Clone)]
pub struct CaseSnapshotInputs {
    pub title: String,
    pub severity: String,
    pub entities: Vec<crate::entity_extraction::ExtractedEntity>,
}

/// Which way an approval is being answered (NAN-2098).
///
/// Approve and reject share one authorization rule and one conditional-UPDATE
/// implementation; only the terminal status and the follow-on playbook status
/// differ. Both are compile-time literals — nothing here is caller-influenced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ApprovalOutcome {
    Approved,
    Rejected,
}

/// Row-lock strength used to serialize ACL-predicated mutations with ACL
/// writes. Run attachment only needs a shared lock, allowing independent cases
/// to attach the same popular playbook concurrently.
#[derive(Debug, Clone, Copy)]
enum PlaybookRowLock {
    Exclusive,
    Shared,
}

/// SQL predicate for whether a named human reviewer can currently publish a
/// playbook.
///
/// Assignment is intentionally narrower than request-time principal
/// resolution: an approval names a user, so eligibility must come from that
/// active user's persisted group roles. API-key and ephemeral demo principals
/// cannot be assigned as a human reviewer.
fn approval_assignee_eligible_sql(user_id: &str, playbook_id: &str) -> String {
    format!(
        r#"EXISTS (
             SELECT 1
               FROM users approval_user
              WHERE approval_user.id = {user_id}
                AND approval_user.status = 'active'
                AND EXISTS (
                    SELECT 1
                      FROM user_groups approval_ug
                      JOIN group_roles approval_gr
                        ON approval_gr.group_id = approval_ug.group_id
                      JOIN role_permissions approval_rp
                        ON approval_rp.role_id = approval_gr.role_id
                     WHERE approval_ug.user_id = approval_user.id
                       AND approval_rp.permission_id = 'playbooks:publish'
                )
                AND (
                    NOT EXISTS (
                        SELECT 1
                          FROM playbook_permissions approval_any_acl
                         WHERE approval_any_acl.playbook_id = {playbook_id}
                    )
                    OR EXISTS (
                        SELECT 1
                          FROM user_groups approval_acl_ug
                          JOIN group_roles approval_acl_gr
                            ON approval_acl_gr.group_id = approval_acl_ug.group_id
                          JOIN playbook_permissions approval_acl
                            ON approval_acl.role_id = approval_acl_gr.role_id
                         WHERE approval_acl_ug.user_id = approval_user.id
                           AND approval_acl.playbook_id = {playbook_id}
                           AND approval_acl.can_view
                           AND approval_acl.can_publish
                    )
                )
         )"#
    )
}

impl ApprovalOutcome {
    /// The `playbook_approvals.status` the row transitions to.
    const fn terminal_status(self) -> &'static str {
        match self {
            ApprovalOutcome::Approved => "approved",
            ApprovalOutcome::Rejected => "rejected",
        }
    }

    /// The follow-on `playbooks.status` transition. Rejection only reverts a
    /// playbook that is still `pending_review` — a previously-approved playbook
    /// stays `live`.
    const fn playbook_status_sql(self) -> &'static str {
        match self {
            ApprovalOutcome::Approved => {
                "UPDATE playbooks SET status = 'live', updated_at = NOW() \
                  WHERE id = $1 AND kind = 'response'"
            }
            ApprovalOutcome::Rejected => {
                "UPDATE playbooks SET status = 'draft', updated_at = NOW() \
                  WHERE id = $1 AND kind = 'response' AND status = 'pending_review'"
            }
        }
    }
}

/// Repository for the `playbooks` table and its children.
#[derive(Clone)]
pub struct PlaybookRepository {
    pool: PgPool,
}

impl PlaybookRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    // =========================================================================
    // List / Get
    // =========================================================================

    /// List playbooks the caller may VIEW (NAN-2097).
    ///
    /// The ACL predicate is part of the WHERE clause, so denied rows are excluded
    /// **before** `LIMIT`/`OFFSET` — pagination cannot reveal a hidden playbook,
    /// and [`count`](Self::count) applies the identical predicate so the reported
    /// total matches what the caller can actually page through.
    pub async fn list(
        &self,
        query: &ListPlaybooksQuery,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<Playbook>, PlaybookError> {
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT * FROM playbooks WHERE ");
        qb.push(RESPONSE_KIND).push(" AND ");
        push_acl(&mut qb, "playbooks.id", PlaybookAction::View, principal);

        if let Some(cat) = query.category {
            qb.push(" AND category = ").push_bind(cat.as_str().to_string());
        }
        if let Some(status) = query.status {
            qb.push(" AND status = ").push_bind(status.as_str().to_string());
        }
        if let Some(ref signal) = query.signal {
            qb.push(" AND ").push_bind(signal.clone()).push(" = ANY(match_signals)");
        }
        if let Some(ref search) = query.search {
            let pattern = format!("%{}%", search);
            qb.push(" AND (title ILIKE ").push_bind(pattern.clone());
            qb.push(" OR COALESCE(subtitle, '') ILIKE ").push_bind(pattern);
            qb.push(")");
        }
        if let Some(adaptive) = query.adaptive {
            qb.push(" AND adaptive = ").push_bind(adaptive);
        }

        // Sort. NAN-454: wire the four library tabs (`usage`, `recent`, `skip`,
        // `az`) that the frontend already sends but the backend was silently
        // falling through for. Legacy values (`title`, `attached`) still work
        // as aliases so older clients don't regress.
        match query.sort.as_deref() {
            // Most-used — attach count desc, tie-break newest-first so fresh
            // playbooks don't get buried behind untouched ones.
            Some("usage") | Some("attached") => qb.push(
                " ORDER BY (SELECT COUNT(*) FROM playbook_runs WHERE playbook_id = playbooks.id) DESC, updated_at DESC",
            ),
            // Recently edited — last touched (author edit or sync).
            Some("recent") => qb.push(" ORDER BY updated_at DESC"),
            // High-skip — compute from step_completion JSONB: sum of steps
            // marked skipped across all runs divided by total steps touched.
            // Higher ratio = noisier playbook ⇒ tuning candidate.
            Some("skip") => qb.push(
                r#" ORDER BY COALESCE((
                    SELECT COUNT(*) FILTER (WHERE (step_value -> 'skipped')::boolean IS TRUE)::float
                         / NULLIF(COUNT(*)::float, 0)
                    FROM playbook_runs pr,
                         jsonb_each(COALESCE(pr.step_completion, '{}'::jsonb)) AS step(step_key, step_value)
                    WHERE pr.playbook_id = playbooks.id
                ), 0) DESC, updated_at DESC"#,
            ),
            // Alphabetical.
            Some("az") | Some("title") => qb.push(" ORDER BY title ASC"),
            _ => qb.push(" ORDER BY updated_at DESC"),
        };

        let limit = query.limit.unwrap_or(100).clamp(1, 1000);
        let offset = query.offset.unwrap_or(0).max(0);
        qb.push(" LIMIT ").push_bind(limit);
        qb.push(" OFFSET ").push_bind(offset);

        let rows: Vec<Playbook> = qb.build_query_as().fetch_all(&self.pool).await?;
        Ok(rows)
    }

    /// Count playbooks the caller may VIEW. Must stay in lock-step with
    /// [`list`](Self::list) — a total larger than the visible set would itself
    /// disclose that hidden playbooks exist.
    pub async fn count(
        &self,
        query: &ListPlaybooksQuery,
        principal: &PlaybookPrincipal,
    ) -> Result<i64, PlaybookError> {
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT COUNT(*) FROM playbooks WHERE ");
        qb.push(RESPONSE_KIND).push(" AND ");
        push_acl(&mut qb, "playbooks.id", PlaybookAction::View, principal);
        if let Some(cat) = query.category {
            qb.push(" AND category = ").push_bind(cat.as_str().to_string());
        }
        if let Some(status) = query.status {
            qb.push(" AND status = ").push_bind(status.as_str().to_string());
        }
        if let Some(ref signal) = query.signal {
            qb.push(" AND ").push_bind(signal.clone()).push(" = ANY(match_signals)");
        }
        if let Some(ref search) = query.search {
            let pattern = format!("%{}%", search);
            qb.push(" AND (title ILIKE ").push_bind(pattern.clone());
            qb.push(" OR COALESCE(subtitle, '') ILIKE ").push_bind(pattern);
            qb.push(")");
        }
        if let Some(adaptive) = query.adaptive {
            qb.push(" AND adaptive = ").push_bind(adaptive);
        }

        let count: (i64,) = qb.build_query_as().fetch_one(&self.pool).await?;
        Ok(count.0)
    }

    /// Fetch one playbook the caller may VIEW (NAN-2097).
    ///
    /// A playbook that does not exist and one the ACL hides are indistinguishable
    /// — both yield `NotFound`, so this is not a playbook-existence oracle.
    /// Every `{id}`-scoped child read (`versions`, `runs`, `permissions`,
    /// `approvals`, `analytics`) funnels through this in the service layer.
    pub async fn get(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        let sql = format!(
            "SELECT * FROM playbooks WHERE id = $1 AND {RESPONSE_KIND} AND {}",
            acl_sql("playbooks.id", PlaybookAction::View, "$2", "$3", "$4")
        );
        let pb = sqlx::query_as::<_, Playbook>(&sql)
            .bind(id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(PlaybookError::NotFound(id))?;
        Ok(pb)
    }

    /// Live playbooks whose `match_signals` overlap `signals`, filtered to those
    /// the caller may VIEW.
    pub async fn list_by_signal(
        &self,
        signals: &[String],
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<Playbook>, PlaybookError> {
        if signals.is_empty() {
            return Ok(Vec::new());
        }
        let sql = format!(
            "SELECT * FROM playbooks \
              WHERE status = 'live' AND {RESPONSE_KIND} AND match_signals && $1 AND {} \
              ORDER BY updated_at DESC",
            acl_sql("playbooks.id", PlaybookAction::View, "$2", "$3", "$4")
        );
        let rows = sqlx::query_as::<_, Playbook>(&sql)
            .bind(signals)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    // =========================================================================
    // Create
    // =========================================================================

    pub async fn create(
        &self,
        req: &CreatePlaybookRequest,
        parsed_steps: Option<&Value>,
        user_id: Option<Uuid>,
    ) -> Result<Playbook, PlaybookError> {
        let danger_policy = req
            .danger_policy
            .as_ref()
            .map(|m| serde_json::to_value(m).unwrap_or(Value::Object(Default::default())))
            .unwrap_or(Value::Object(Default::default()));
        let adaptive_source = req
            .adaptive_source
            .as_ref()
            .and_then(|s| serde_json::to_value(s).ok());
        let status = req.status.unwrap_or(PlaybookStatus::Draft);
        let scope = req.scope.unwrap_or(PlaybookScope::Tenant);

        let mut tx = self.pool.begin().await?;

        let pb = sqlx::query_as::<_, Playbook>(
            r#"
            INSERT INTO playbooks (
                title, subtitle, category, doc, parsed_steps,
                match_signals, danger_policy, review_cadence, scope, tags,
                owner_team, status, adaptive, adaptive_source,
                source_repository_id, source_playbook_path, source_linked,
                created_by, maintainer_user_id
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9, $10,
                $11, $12, $13, $14,
                $15, $16, $17,
                $18, $18
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
        .bind(&danger_policy)
        .bind(req.review_cadence.as_deref().unwrap_or("90d"))
        .bind(scope.as_str())
        .bind(&req.tags)
        .bind(&req.owner_team)
        .bind(status.as_str())
        .bind(req.adaptive.unwrap_or(false))
        .bind(&adaptive_source)
        .bind(req.source_repository_id)
        .bind(&req.source_playbook_path)
        .bind(req.source_linked.unwrap_or(false))
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        // Initial version = 1
        let metadata = build_metadata_snapshot(&pb);
        sqlx::query(
            r#"
            INSERT INTO playbook_versions (
                playbook_id, version, doc, metadata, note, author_id, author_name
            ) VALUES ($1, 1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(pb.id)
        .bind(&pb.doc)
        .bind(&metadata)
        .bind(Option::<String>::None)
        .bind(user_id)
        .bind(Option::<String>::None)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(pb)
    }

    // =========================================================================
    // Hard delete (NAN-456) — removes the row. FKs cascade versions/runs/
    // approvals/permissions. `detection_rules.playbook_id` FK is RESTRICT,
    // so a playbook referenced by any rule will fail to delete — the admin
    // must retarget those rules first. Archive is the soft-delete path.
    // =========================================================================

    /// Hard-delete a playbook the caller may EDIT (NAN-2097). The parent is
    /// locked before the ACL check so a revocation that started first wins;
    /// missing and denied both return `NotFound`.
    pub async fn delete(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_playbook_for_action(&mut tx, id, PlaybookAction::Edit, principal).await?;
        sqlx::query("DELETE FROM playbooks WHERE id = $1 AND kind = 'response'")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    // =========================================================================
    // Update
    // =========================================================================

    /// Update a playbook the caller may EDIT (NAN-2097).
    ///
    /// A request that explicitly sets `status = live` additionally requires the
    /// PUBLISH grant. If an edit changes an already-live playbook without
    /// explicitly republishing it, the new version returns to `draft`; it must
    /// travel through review before becoming live again. The same applies to a
    /// version currently under review: changing its contents supersedes the
    /// pending approval instead of letting that older approval publish the new
    /// version.
    ///
    /// The transaction locks the playbook row first, then evaluates the ACL in a
    /// fresh statement snapshot. ACL writes take the same lock
    /// ([`upsert_permission`](Self::upsert_permission)), so a concurrent grant
    /// revocation is visible before the decision and cannot interleave with the
    /// subsequent UPDATE.
    pub async fn update(
        &self,
        id: Uuid,
        req: &UpdatePlaybookRequest,
        parsed_steps: Option<&Value>,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        let current =
            Self::lock_playbook_for_action(&mut tx, id, PlaybookAction::Edit, principal).await?;
        if matches!(req.status, Some(PlaybookStatus::Live)) {
            Self::lock_playbook_for_action(&mut tx, id, PlaybookAction::Publish, principal).await?;
        }

        // Did the doc or meta actually change? If so, bump version. Compare
        // values rather than mere field presence so a retry carrying the
        // already-current value does not demote a live playbook or mint a
        // spurious version.
        let doc_changed = req.doc.as_deref().map(|d| d != current.doc).unwrap_or(false);
        let danger_policy_changed = req
            .danger_policy
            .as_ref()
            .map(|policy| {
                serde_json::to_value(policy).unwrap_or(Value::Object(Default::default()))
                    != current.danger_policy
            })
            .unwrap_or(false);
        let content_or_metadata_changed = doc_changed
            || req.title.as_ref().is_some_and(|value| value != &current.title)
            || req
                .subtitle
                .as_ref()
                .is_some_and(|value| Some(value) != current.subtitle.as_ref())
            || req
                .category
                .is_some_and(|value| value.as_str() != current.category)
            || req
                .match_signals
                .as_ref()
                .is_some_and(|value| value != &current.match_signals)
            || danger_policy_changed
            || req
                .review_cadence
                .as_ref()
                .is_some_and(|value| value != &current.review_cadence)
            || req
                .scope
                .is_some_and(|value| value.as_str() != current.scope)
            || req.tags.as_ref().is_some_and(|value| value != &current.tags)
            || req
                .owner_team
                .as_ref()
                .is_some_and(|value| Some(value) != current.owner_team.as_ref());
        let requested_status = req.status.map(|status| status.as_str());
        let status_changed = requested_status.is_some_and(|value| value != current.status);
        let version_changed = content_or_metadata_changed || status_changed;

        let next_version = if version_changed {
            current.current_version + 1
        } else {
            current.current_version
        };

        let title = req.title.clone().unwrap_or_else(|| current.title.clone());
        let subtitle = req
            .subtitle
            .clone()
            .or_else(|| current.subtitle.clone());
        let category = req
            .category
            .map(|c| c.as_str().to_string())
            .unwrap_or_else(|| current.category.clone());
        let doc = req.doc.clone().unwrap_or_else(|| current.doc.clone());
        let match_signals = req
            .match_signals
            .clone()
            .unwrap_or_else(|| current.match_signals.clone());
        let danger_policy = req
            .danger_policy
            .as_ref()
            .map(|m| serde_json::to_value(m).unwrap_or(Value::Object(Default::default())))
            .unwrap_or_else(|| current.danger_policy.clone());
        let review_cadence = req
            .review_cadence
            .clone()
            .unwrap_or_else(|| current.review_cadence.clone());
        let scope = req
            .scope
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| current.scope.clone());
        let tags = req.tags.clone().unwrap_or_else(|| current.tags.clone());
        let owner_team = req
            .owner_team
            .clone()
            .or_else(|| current.owner_team.clone());
        let status = match requested_status {
            Some("pending_review")
                if current.status == "pending_review" && content_or_metadata_changed =>
            {
                "draft".to_string()
            }
            Some(status) => status.to_string(),
            None if matches!(current.status.as_str(), "live" | "pending_review")
                && content_or_metadata_changed =>
            {
                "draft".to_string()
            }
            None => current.status.clone(),
        };

        let pb = sqlx::query_as::<_, Playbook>(
            r#"
            UPDATE playbooks SET
                title = $2,
                subtitle = $3,
                category = $4,
                doc = $5,
                parsed_steps = COALESCE($6, parsed_steps),
                match_signals = $7,
                danger_policy = $8,
                review_cadence = $9,
                scope = $10,
                tags = $11,
                owner_team = $12,
                status = $13,
                current_version = $14,
                updated_at = NOW()
            WHERE id = $1 AND kind = 'response'
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&title)
        .bind(&subtitle)
        .bind(&category)
        .bind(&doc)
        .bind(parsed_steps)
        .bind(&match_signals)
        .bind(&danger_policy)
        .bind(&review_cadence)
        .bind(&scope)
        .bind(&tags)
        .bind(&owner_team)
        .bind(&status)
        .bind(next_version)
        .fetch_one(&mut *tx)
        .await?;

        if next_version > current.current_version {
            // A review is pinned to the version submitted. Terminalize every
            // older pending row in the same transaction that advances the
            // playbook, before inserting the new snapshot. Without this, an
            // approval for v1 could publish newly-written v2 content.
            sqlx::query(
                r#"UPDATE playbook_approvals
                      SET status = 'withdrawn',
                          response = COALESCE(
                              response,
                              'Superseded by a newer playbook version'
                          ),
                          responded_at = NOW()
                    WHERE playbook_id = $1
                      AND version < $2
                      AND status = 'pending'"#,
            )
            .bind(id)
            .bind(next_version)
            .execute(&mut *tx)
            .await?;

            let metadata = build_metadata_snapshot(&pb);
            sqlx::query(
                r#"
                INSERT INTO playbook_versions (
                    playbook_id, version, doc, metadata, note, author_id, author_name
                ) VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (playbook_id, version) DO NOTHING
                "#,
            )
            .bind(pb.id)
            .bind(next_version)
            .bind(&pb.doc)
            .bind(&metadata)
            .bind(req.note.clone())
            .bind(user_id)
            .bind(Option::<String>::None)
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;
        Ok(pb)
    }

    // =========================================================================
    // Archive
    // =========================================================================

    /// Archive (soft-delete) a playbook the caller may EDIT (NAN-2097).
    /// The parent is locked before the ACL check; missing and denied both yield
    /// `NotFound`.
    pub async fn archive(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        let mut tx = self.pool.begin().await?;
        Self::lock_playbook_for_action(&mut tx, id, PlaybookAction::Edit, principal).await?;
        sqlx::query(
            "UPDATE playbooks SET status = 'archived', updated_at = NOW() \
              WHERE id = $1 AND kind = 'response'",
        )
            .bind(id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    // =========================================================================
    // Fork
    // =========================================================================

    /// Fork a playbook the caller may EDIT (NAN-2097).
    ///
    /// Fork *copies the source doc verbatim* into a new row the caller then owns,
    /// so a fork the ACL didn't authorize would launder the whole document past
    /// `can_view`. The `can_view` floor baked into the Edit predicate is what
    /// prevents that.
    pub async fn fork(
        &self,
        id: Uuid,
        req: &ForkPlaybookRequest,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        let source =
            Self::lock_playbook_for_action(&mut tx, id, PlaybookAction::Edit, principal).await?;

        let new_title = req
            .title
            .clone()
            .unwrap_or_else(|| format!("{} (fork)", source.title));
        let new_owner = req
            .owner_team
            .clone()
            .or_else(|| source.owner_team.clone());

        // New playbook: same content, draft, source_linked=FALSE, no adaptive_source
        let pb = sqlx::query_as::<_, Playbook>(
            r#"
            INSERT INTO playbooks (
                title, subtitle, category, doc, parsed_steps,
                match_signals, danger_policy, review_cadence, scope, tags,
                owner_team, status, adaptive, adaptive_source,
                source_repository_id, source_playbook_path, source_linked,
                created_by, maintainer_user_id
            ) VALUES (
                $1, $2, $3, $4, $5,
                $6, $7, $8, $9, $10,
                $11, 'draft', FALSE, NULL,
                NULL, NULL, FALSE,
                $12, $12
            )
            RETURNING *
            "#,
        )
        .bind(&new_title)
        .bind(&source.subtitle)
        .bind(&source.category)
        .bind(&source.doc)
        .bind(&source.parsed_steps)
        .bind(&source.match_signals)
        .bind(&source.danger_policy)
        .bind(&source.review_cadence)
        .bind(&source.scope)
        .bind(&source.tags)
        .bind(&new_owner)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await?;

        // Initial version for the fork
        let metadata = build_metadata_snapshot(&pb);
        sqlx::query(
            r#"
            INSERT INTO playbook_versions (
                playbook_id, version, doc, metadata, note, author_id, author_name
            ) VALUES ($1, 1, $2, $3, $4, $5, $6)
            "#,
        )
        .bind(pb.id)
        .bind(&pb.doc)
        .bind(&metadata)
        .bind(Some(format!("Forked from {}", source.id)))
        .bind(user_id)
        .bind(Option::<String>::None)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(pb)
    }

    // =========================================================================
    // Versions
    // =========================================================================

    /// NAN-2097: carries the VIEW predicate itself rather than relying on the
    /// service having called [`get`](Self::get) first. Every child read below
    /// does the same — `PlaybookRepository` is `pub`, so a gate that lives only
    /// in the service layer is an escape hatch, and the ordered pair of queries
    /// would be check-then-act besides.
    pub async fn list_versions(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookVersion>, PlaybookError> {
        let sql = format!(
            "SELECT pv.* FROM playbook_versions pv \
              WHERE pv.playbook_id = $1 AND {} \
              ORDER BY pv.version DESC",
            acl_sql("pv.playbook_id", PlaybookAction::View, "$2", "$3", "$4")
        );
        let rows = sqlx::query_as::<_, PlaybookVersion>(&sql)
            .bind(id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// Fetch the `doc` text for a specific `(playbook_id, version)` pair —
    /// used by [`crate::playbooks::service::PlaybookService::resolve_run`]
    /// to parse + resolve a run against its frozen version.
    /// NAN-2097: gated on the caller's VIEW grant for the OWNING playbook — a
    /// frozen version doc is the same content as the playbook itself, so it must
    /// not be readable through the run-resolve side door when the live row isn't.
    pub async fn get_version_doc(
        &self,
        playbook_id: Uuid,
        version: i32,
        principal: &PlaybookPrincipal,
    ) -> Result<String, PlaybookError> {
        let sql = format!(
            "SELECT pv.doc FROM playbook_versions pv \
              WHERE pv.playbook_id = $1 AND pv.version = $2 AND {}",
            acl_sql("pv.playbook_id", PlaybookAction::View, "$3", "$4", "$5")
        );
        let doc: Option<String> = sqlx::query_scalar(&sql)
            .bind(playbook_id)
            .bind(version)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_optional(&self.pool)
            .await?;
        doc.ok_or(PlaybookError::NotFound(playbook_id))
    }

    // =========================================================================
    // Runs
    // =========================================================================

    /// List a playbook's runs VISIBLE to `user_id` (NAN-2044).
    ///
    /// Each run is attached to a case (`playbook_runs.case_id`) and carries a
    /// frozen `run_context` snapshot of that case's data. The playbook
    /// capability is not permission over the case, so the runs are filtered to
    /// those whose case the caller can see, using the SAME predicate as
    /// `CaseRepository::check_user_access` / `find_by_id_for_user` (public, or
    /// creator/assignee, or a `group`-visibility case the caller shares a group
    /// with) — copied verbatim so it cannot drift. `user_id` is mandatory.
    pub async fn list_runs(
        &self,
        id: Uuid,
        user_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookRun>, PlaybookError> {
        let sql = format!(
            r#"
            SELECT pr.*
              FROM playbook_runs pr
             WHERE pr.playbook_id = $1
               AND {acl}
               AND EXISTS (
                   SELECT 1
                     FROM cases c
                    WHERE c.id = pr.case_id
                      AND (
                          c.visibility = 'public'
                          OR c.created_by = $2
                          OR c.assigned_to = $2
                          OR (c.visibility = 'group' AND EXISTS (
                              SELECT 1 FROM case_groups cg
                              JOIN user_groups ug ON ug.group_id = cg.group_id
                              WHERE cg.case_id = c.id AND ug.user_id = $2
                          ))
                      )
               )
             ORDER BY pr.started_at DESC
            "#,
            acl = acl_sql("pr.playbook_id", PlaybookAction::View, "$3", "$4", "$5"),
        );
        let rows = sqlx::query_as::<_, PlaybookRun>(&sql)
            .bind(id)
            .bind(user_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    /// Whether `user_id` can see case `case_id` (NAN-2044).
    ///
    /// Uses the canonical case-visibility predicate — the SAME one as
    /// `CaseRepository::check_user_access` (public, or creator/assignee, or a
    /// `group`-visibility case the caller shares a group with) — evaluated here
    /// in the playbook repo's own SQL. That is deliberate: the shared
    /// (open-core) playbook handlers cannot depend on the enterprise-gated
    /// `CaseRepository` type, and this repo already reads case tables directly
    /// (`fetch_case_snapshot_inputs`, `list_runs_for_case`, …).
    pub async fn case_visible_to(
        &self,
        case_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, PlaybookError> {
        let visible: Option<(bool,)> = sqlx::query_as(
            r#"
            SELECT TRUE
              FROM cases c
             WHERE c.id = $1
               AND (
                   c.visibility = 'public'
                   OR c.created_by = $2
                   OR c.assigned_to = $2
                   OR (c.visibility = 'group' AND EXISTS (
                       SELECT 1 FROM case_groups cg
                       JOIN user_groups ug ON ug.group_id = cg.group_id
                       WHERE cg.case_id = c.id AND ug.user_id = $2
                   ))
               )
             LIMIT 1
            "#,
        )
        .bind(case_id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(visible.is_some())
    }

    // =========================================================================
    // Permissions
    // =========================================================================

    /// NAN-2097: reading WHO may see a playbook is itself part of the playbook,
    /// so the ACL gates its own disclosure.
    pub async fn list_permissions(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookPermission>, PlaybookError> {
        let sql = format!(
            "SELECT pp2.playbook_id, COALESCE(r.name, pp2.role) AS role, \
                    pp2.role_id, pp2.can_view, pp2.can_run, pp2.can_edit, \
                    pp2.can_publish, pp2.member_count, pp2.created_at, pp2.updated_at \
               FROM playbook_permissions pp2 \
               LEFT JOIN roles r ON r.id = pp2.role_id \
              WHERE pp2.playbook_id = $1 AND {} \
              ORDER BY COALESCE(r.name, pp2.role) ASC",
            acl_sql("pp2.playbook_id", PlaybookAction::View, "$2", "$3", "$4")
        );
        let rows = sqlx::query_as::<_, PlaybookPermission>(&sql)
            .bind(id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    // =========================================================================
    // Approvals
    // =========================================================================

    pub async fn list_approvals(
        &self,
        id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookApproval>, PlaybookError> {
        let sql = format!(
            "SELECT a.* FROM playbook_approvals a \
              WHERE a.playbook_id = $1 AND {} \
              ORDER BY a.requested_at DESC",
            acl_sql("a.playbook_id", PlaybookAction::View, "$2", "$3", "$4")
        );
        let rows = sqlx::query_as::<_, PlaybookApproval>(&sql)
            .bind(id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }
}

fn build_metadata_snapshot(pb: &Playbook) -> Value {
    serde_json::json!({
        "title": pb.title,
        "subtitle": pb.subtitle,
        "category": pb.category,
        "match_signals": pb.match_signals,
        "danger_policy": pb.danger_policy,
        "review_cadence": pb.review_cadence,
        "scope": pb.scope,
        "tags": pb.tags,
        "owner_team": pb.owner_team,
        "status": pb.status,
    })
}

// ============================================================================
// NAN-445 — suggest + run mutations
// ============================================================================

/// Lightweight view of a detection rule, used by the suggest algorithm.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct RuleSignalContext {
    pub id: Uuid,
    pub name: String,
    pub folder: Option<String>,
    pub mitre_tactics: Vec<String>,
    pub mitre_techniques: Vec<String>,
}

impl PlaybookRepository {
    /// Fetch the minimum fields needed to score a rule against the playbook
    /// library. Returns `NotFound` if the rule has been deleted.
    pub async fn get_rule_signal_context(
        &self,
        rule_id: Uuid,
    ) -> Result<RuleSignalContext, PlaybookError> {
        let row: Option<RuleSignalContext> = sqlx::query_as(
            r#"SELECT
                 id,
                 name,
                 folder,
                 COALESCE(mitre_tactics, '{}') AS mitre_tactics,
                 COALESCE(mitre_techniques, '{}') AS mitre_techniques
               FROM detection_rules
               WHERE id = $1"#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?;
        row.ok_or(PlaybookError::NotFound(rule_id))
    }

    /// Suggest live playbooks that match the given signal set + optional
    /// category hint. Returns (playbook, score, matched_signals) tuples in
    /// descending score order, capped at 20 rows.
    /// NAN-2097: the suggestion feed returns whole `Playbook` rows — including
    /// `doc` — so it is a full library read path and carries the same VIEW
    /// predicate as `list`/`get`. Filtering happens in SQL, before the 200-row
    /// candidate cap, so a denied playbook can never displace a permitted one.
    pub async fn suggest_by_signals(
        &self,
        signals: &[String],
        category: Option<&str>,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<(Playbook, i32, Vec<String>)>, PlaybookError> {
        use sqlx::Row;

        // Fetch candidate rows in two columns: the Playbook (FromRow) payload,
        // plus the matched-signals array for scoring. Use plain `query` + manual
        // row mapping so the tuple doesn't need to implement Decode.
        let sql = format!(
            r#"SELECT p.*,
                      COALESCE(ARRAY(
                          SELECT UNNEST(p.match_signals)
                          INTERSECT
                          SELECT UNNEST($1::text[])
                      ), '{{}}') AS matched_signals_out
               FROM playbooks p
               WHERE p.status = 'live'
                 AND p.kind = 'response'
                 AND (
                      p.match_signals && $1::text[]
                      OR ($2::text IS NOT NULL AND p.category = $2::text)
                 )
                 AND {acl}
               LIMIT 200"#,
            acl = acl_sql("p.id", PlaybookAction::View, "$3", "$4", "$5"),
        );
        let rows = sqlx::query(&sql)
            .bind(signals)
            .bind(category)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;

        let mut scored: Vec<(Playbook, i32, Vec<String>)> = Vec::with_capacity(rows.len());
        for row in rows {
            let pb = <Playbook as sqlx::FromRow<_>>::from_row(&row)?;
            let matched: Vec<String> = row.try_get("matched_signals_out").unwrap_or_default();
            let cat_match = category.map(|c| pb.category == c).unwrap_or(false);
            let score = (matched.len() as i32) * 10 + cat_match as i32;
            scored.push((pb, score, matched));
        }

        scored.sort_by(|a, b| b.1.cmp(&a.1));
        scored.truncate(20);
        Ok(scored)
    }

    /// Create a new `playbook_runs` row (attach the playbook to a case).
    ///
    /// NAN-462: `run_context` is a JSON snapshot of the triggering alert +
    /// entities + rule + case captured by the caller. Stored verbatim on
    /// the row and consumed by [`crate::playbooks::runtime`] at render time
    /// to resolve `{{...}}` tokens. Passing `None` is the manual-attach
    /// path — tokens still render, just mostly as empty strings.
    pub async fn create_run(
        &self,
        playbook_id: Uuid,
        version: Option<i32>,
        case_id: Uuid,
        operator_user_id: Option<Uuid>,
        operator_label: Option<String>,
        run_context: Option<serde_json::Value>,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        // Serialize against ACL writes before checking RUN. If a revocation
        // already owns the parent lock, this waits and then evaluates
        // authorization in a fresh statement snapshot. A shared lock still
        // conflicts with ACL writers while allowing concurrent attachments.
        let mut tx = self.pool.begin().await?;
        let playbook = Self::lock_playbook_for_action_with_lock(
            &mut tx,
            playbook_id,
            PlaybookAction::Run,
            principal,
            PlaybookRowLock::Shared,
        )
        .await?;
        let resolved_version = version.unwrap_or(playbook.current_version);

        // NAN-2044: the run may only be attached to a case $7 can actually see —
        // enforced atomically as a conditional INSERT (INSERT … SELECT … WHERE
        // EXISTS(<case visible>)) so a concurrent revocation cannot slip an
        // attach through. 0 rows inserted → NotFound(case_id).
        //
        // NAN-2097: RUN was checked after acquiring the parent lock above. That
        // lock remains held through commit, so an ACL writer cannot interleave
        // between the fresh check and this insert.
        let insert_sql = r#"INSERT INTO playbook_runs
                 (playbook_id, playbook_version, case_id, status,
                  operator_user_id, operator_label, run_context)
               SELECT $1, $2, $3, 'active', $4, $5, $6
                WHERE ($7::uuid IS NULL OR EXISTS (
                    SELECT 1 FROM cases c
                     WHERE c.id = $3
                       AND (
                           c.visibility = 'public'
                           OR c.created_by = $7
                           OR c.assigned_to = $7
                           OR (c.visibility = 'group' AND EXISTS (
                               SELECT 1 FROM case_groups cg
                               JOIN user_groups ug ON ug.group_id = cg.group_id
                               WHERE cg.case_id = c.id AND ug.user_id = $7
                           ))
                       )
                ))
                  AND EXISTS (
                      SELECT 1 FROM playbooks
                       WHERE playbooks.id = $1
                         AND playbooks.kind = 'response'
                  )
               RETURNING *"#;
        let run: Option<PlaybookRun> = sqlx::query_as(&insert_sql)
            .bind(playbook_id)
            .bind(resolved_version)
            .bind(case_id)
            .bind(operator_user_id)
            .bind(operator_label)
            .bind(run_context)
            .bind(user_id)
            .fetch_optional(&mut *tx)
            .await?;
        let run = run.ok_or(PlaybookError::NotFound(case_id))?;
        tx.commit().await?;
        Ok(run)
    }

    /// Get a single run by id, gated on the caller's VIEW grant for the run's
    /// playbook (NAN-2097).
    ///
    /// This does NOT check case visibility — callers that surface `run_context`
    /// must additionally apply [`case_visible_to`](Self::case_visible_to)
    /// (NAN-2044); `PlaybookService::resolve_run` does exactly that.
    pub async fn get_run(
        &self,
        run_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        let sql = format!(
            "SELECT pr.* FROM playbook_runs pr WHERE pr.id = $1 AND {}",
            acl_sql("pr.playbook_id", PlaybookAction::View, "$2", "$3", "$4")
        );
        let row: Option<PlaybookRun> = sqlx::query_as(&sql)
            .bind(run_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_optional(&self.pool)
            .await?;
        row.ok_or(PlaybookError::NotFound(run_id))
    }

    /// NAN-469 — fetch the inputs needed to build a manual-attach
    /// `run_context` snapshot: the case's user-facing fields plus its live
    /// `case_entities` rows (already deduped by the table's unique
    /// constraint on `(case_id, entity_type, entity_value)`).
    ///
    /// Entities are returned ordered `is_primary DESC, occurrence_count DESC,
    /// entity_value` so the runtime's `{{entity.user}}` (= index 0) renders
    /// the case's primary value for that type.
    ///
    /// Returns `PlaybookError::NotFound(case_id)` when the case row is
    /// missing — the manual-attach handler can map that to a 404.
    pub async fn fetch_case_snapshot_inputs(
        &self,
        case_id: Uuid,
    ) -> Result<CaseSnapshotInputs, PlaybookError> {
        let case_row: Option<(String, String)> =
            sqlx::query_as("SELECT title, severity FROM cases WHERE id = $1")
                .bind(case_id)
                .fetch_optional(&self.pool)
                .await?;
        let (title, severity) = case_row.ok_or(PlaybookError::NotFound(case_id))?;

        let entity_rows: Vec<(String, String)> = sqlx::query_as(
            r#"SELECT entity_type, entity_value
                 FROM case_entities
                WHERE case_id = $1
                ORDER BY is_primary DESC, occurrence_count DESC, entity_value"#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(CaseSnapshotInputs {
            title,
            severity,
            entities: entity_rows
                .into_iter()
                .map(|(entity_type, value)| {
                    crate::entity_extraction::ExtractedEntity { entity_type, value }
                })
                .collect(),
        })
    }

    /// NAN-463 — upsert a single step's entry inside `step_completion`.
    ///
    /// The JSONB map is keyed by `step_id` → `{completed_at, operator_user_id,
    /// skipped, note}`. Only fields present in the patch overwrite their
    /// counterparts on the existing entry; unspecified fields are preserved
    /// (`completed=true` stamps `completed_at` + `operator_user_id`, `false`
    /// clears both; `skipped` / `note` update only when provided). Safe to
    /// call repeatedly — idempotent per patch.
    pub async fn update_step_completion(
        &self,
        run_id: Uuid,
        step_id: &str,
        completed: Option<bool>,
        skipped: Option<bool>,
        note: Option<String>,
        operator_user_id: Option<Uuid>,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        let mut patch = serde_json::Map::new();
        match completed {
            Some(true) => {
                patch.insert(
                    "completed_at".into(),
                    serde_json::Value::String(chrono::Utc::now().to_rfc3339()),
                );
                if let Some(uid) = operator_user_id {
                    patch.insert(
                        "operator_user_id".into(),
                        serde_json::Value::String(crate::typeid::encode("user", &uid)),
                    );
                }
            }
            Some(false) => {
                patch.insert("completed_at".into(), serde_json::Value::Null);
                patch.insert("operator_user_id".into(), serde_json::Value::Null);
            }
            None => {}
        }
        if let Some(s) = skipped {
            patch.insert("skipped".into(), serde_json::Value::Bool(s));
        }
        if let Some(n) = note {
            patch.insert("note".into(), serde_json::Value::String(n));
        }
        let patch_json = serde_json::Value::Object(patch);

        // Serialize with ACL writes before evaluating RUN. Looking up the
        // immutable parent id does not lock the run, so independent run
        // mutations remain concurrent; the shared parent lock only conflicts
        // with an ACL writer's exclusive lock.
        let mut tx = self.pool.begin().await?;
        Self::lock_run_playbook_for_action(
            &mut tx,
            run_id,
            PlaybookAction::Run,
            principal,
        )
        .await?;

        // jsonb_set with `create_missing=true`: target path is
        // `step_completion -> $step_id`; value is the prior entry (or `{}`)
        // concatenated with the patch, so only specified fields overwrite.
        // NAN-2044: same atomic case-visibility conjunction as finish_run — the
        // write only fires while $4 can still see the run's case.
        // NAN-2097: plus the per-playbook RUN grant, as a further conjunct of the
        // same UPDATE. Missing run, invisible case and denied playbook are all
        // 0-rows → NotFound, so none of the three is distinguishable.
        let sql = format!(
            r#"UPDATE playbook_runs
                 SET step_completion = jsonb_set(
                     COALESCE(step_completion, '{{}}'::jsonb),
                     ARRAY[$2::text],
                     COALESCE(step_completion -> $2, '{{}}'::jsonb) || $3::jsonb,
                     true
                 )
               WHERE id = $1
                 AND ($4::uuid IS NULL OR EXISTS (
                     SELECT 1 FROM cases c
                      WHERE c.id = playbook_runs.case_id
                        AND (
                            c.visibility = 'public'
                            OR c.created_by = $4
                            OR c.assigned_to = $4
                            OR (c.visibility = 'group' AND EXISTS (
                                SELECT 1 FROM case_groups cg
                                JOIN user_groups ug ON ug.group_id = cg.group_id
                                WHERE cg.case_id = c.id AND ug.user_id = $4
                            ))
                        )
                 ))
                 AND {acl}
               RETURNING *"#,
            acl = acl_sql("playbook_runs.playbook_id", PlaybookAction::Run, "$5", "$6", "$7"),
        );
        let run: Option<PlaybookRun> = sqlx::query_as(&sql)
            .bind(run_id)
            .bind(step_id)
            .bind(patch_json)
            .bind(user_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_optional(&mut *tx)
            .await?;
        let run = run.ok_or(PlaybookError::NotFound(run_id))?;
        tx.commit().await?;
        Ok(run)
    }

    /// Mark a run finished and compute TTR. Idempotent — re-finishing a
    /// resolved run re-sets `finished_at` and `ttr_minutes`.
    pub async fn finish_run(
        &self,
        run_id: Uuid,
        outcome: Option<String>,
        step_completion: Option<serde_json::Value>,
        user_id: Option<Uuid>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookRun, PlaybookError> {
        // Match create_run and step updates: take the owning playbook's shared
        // lock before the fresh RUN check, and hold it through the mutation.
        // Otherwise an UPDATE can snapshot a grant, block behind a revoker, and
        // resume after commit without re-evaluating the ACL.
        let mut tx = self.pool.begin().await?;
        Self::lock_run_playbook_for_action(
            &mut tx,
            run_id,
            PlaybookAction::Run,
            principal,
        )
        .await?;

        // NAN-2044: case visibility is enforced ATOMICALLY, as a conjunction of
        // the UPDATE itself (not a separate check-then-act probe), so a
        // concurrent access revocation between check and mutation cannot slip a
        // write through (codex TOCTOU). If the run is missing OR its case is no
        // longer visible to $4, 0 rows update → NotFound — identical for both,
        // so the response is not a run-existence oracle. `user_id = NULL` means a
        // SYSTEM caller (no interactive user) and bypasses the gate.
        // NAN-2097: the per-playbook RUN grant joins the same conjunction.
        let sql = format!(
            r#"UPDATE playbook_runs
                 SET finished_at  = NOW(),
                     status       = 'resolved',
                     outcome      = COALESCE($2, outcome),
                     step_completion = COALESCE($3, step_completion),
                     ttr_minutes  = CAST(
                         EXTRACT(EPOCH FROM (NOW() - started_at)) / 60 AS INTEGER
                     )
               WHERE id = $1
                 AND ($4::uuid IS NULL OR EXISTS (
                     SELECT 1 FROM cases c
                      WHERE c.id = playbook_runs.case_id
                        AND (
                            c.visibility = 'public'
                            OR c.created_by = $4
                            OR c.assigned_to = $4
                            OR (c.visibility = 'group' AND EXISTS (
                                SELECT 1 FROM case_groups cg
                                JOIN user_groups ug ON ug.group_id = cg.group_id
                                WHERE cg.case_id = c.id AND ug.user_id = $4
                            ))
                        )
                 ))
                 AND {acl}
               RETURNING *"#,
            acl = acl_sql("playbook_runs.playbook_id", PlaybookAction::Run, "$5", "$6", "$7"),
        );
        let run: Option<PlaybookRun> = sqlx::query_as(&sql)
            .bind(run_id)
            .bind(outcome)
            .bind(step_completion)
            .bind(user_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_optional(&mut *tx)
            .await?;
        let run = run.ok_or(PlaybookError::NotFound(run_id))?;
        tx.commit().await?;
        Ok(run)
    }

    /// List the runs attached to a case that belong to playbooks the caller may
    /// VIEW (NAN-2097).
    ///
    /// Case visibility is checked by the caller (`PlaybookService::list_runs_for_case`,
    /// NAN-2044); this adds the per-playbook filter so a case the caller *can*
    /// see does not become a side door onto a playbook they cannot.
    pub async fn list_runs_for_case(
        &self,
        case_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<Vec<PlaybookRun>, PlaybookError> {
        let sql = format!(
            "SELECT pr.* FROM playbook_runs pr \
              WHERE pr.case_id = $1 AND {} \
              ORDER BY pr.started_at DESC",
            acl_sql("pr.playbook_id", PlaybookAction::View, "$2", "$3", "$4")
        );
        let rows: Vec<PlaybookRun> = sqlx::query_as(&sql)
            .bind(case_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;
        Ok(rows)
    }

    // =========================================================================
    // NAN-449 — Phase 5b: adaptive composition from a case
    // =========================================================================

    /// Fetch the raw notebook entries that Shadow Investigator wrote for a
    /// given case. Used by `compose_adaptive_from_case` to build the doc.
    ///
    /// Returns an empty vec if the case has no notebook yet — the caller
    /// treats that as "nothing to compose."
    pub async fn fetch_case_notebook_entries(
        &self,
        case_id: Uuid,
        user_id: Option<Uuid>,
    ) -> Result<Vec<crate::models::notebook::NotebookEntryWithCreator>, PlaybookError> {
        // NAN-2044: these entries are the private case's investigation notes,
        // read into a composed playbook. Gate the read on case visibility as a
        // conjunction of the query itself (atomic, no separate probe), so a
        // caller who cannot see case $2 gets no entries — and compose then 404s
        // the same as an empty case.
        let rows = sqlx::query_as::<_, crate::models::notebook::NotebookEntryWithCreator>(
            r#"SELECT e.id,
                      e.notebook_id,
                      e.entry_type,
                      e.content,
                      NULL::text AS source_url,
                      e.created_by,
                      e.created_at,
                      NULL::text AS creator_name,
                      NULL::uuid AS merged_from_notebook_id,
                      NULL::text AS merged_from_notebook_title,
                      NULL::timestamptz AS original_created_at,
                      e.source
                 FROM notebook_entries e
                 JOIN notebooks n ON n.id = e.notebook_id
                WHERE n.case_id = $1
                  AND ($2::uuid IS NULL OR EXISTS (
                      SELECT 1 FROM cases c
                       WHERE c.id = $1
                         AND (
                             c.visibility = 'public'
                             OR c.created_by = $2
                             OR c.assigned_to = $2
                             OR (c.visibility = 'group' AND EXISTS (
                                 SELECT 1 FROM case_groups cg
                                 JOIN user_groups ug ON ug.group_id = cg.group_id
                                 WHERE cg.case_id = c.id AND ug.user_id = $2
                             ))
                         )
                  ))
                ORDER BY e.created_at ASC"#,
        )
        .bind(case_id)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch a minimal rule name for a case so the adaptive playbook title can
    /// include it. Returns None if the case has no source rule or the rule
    /// has been archived.
    pub async fn fetch_case_rule_name(
        &self,
        case_id: Uuid,
    ) -> Result<Option<String>, PlaybookError> {
        // Cases link to detection rules indirectly through alerts/case_alerts.
        // Pull the most recent alert's rule name as the best proxy.
        let row: Option<(Option<String>, Option<String>)> = sqlx::query_as(
            r#"SELECT r.name, r.folder
                 FROM cases c
                 JOIN case_alerts ca ON ca.case_id = c.id
                 JOIN alerts a       ON a.id = ca.alert_id
                 LEFT JOIN detection_rules r ON r.id = a.rule_id
                WHERE c.id = $1
                ORDER BY a.created_at DESC
                LIMIT 1"#,
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(name, _folder)| name))
    }

    /// Fetch `rule.folder` for a case — maps to `PlaybookCategory`. Returns
    /// None if the join fails (case has no rule-bearing alert).
    pub async fn fetch_case_category(
        &self,
        case_id: Uuid,
    ) -> Result<Option<String>, PlaybookError> {
        let row: Option<(Option<String>,)> = sqlx::query_as(
            r#"SELECT r.folder
                 FROM cases c
                 JOIN case_alerts ca ON ca.case_id = c.id
                 JOIN alerts a       ON a.id = ca.alert_id
                 LEFT JOIN detection_rules r ON r.id = a.rule_id
                WHERE c.id = $1
                ORDER BY a.created_at DESC
                LIMIT 1"#,
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.and_then(|(folder,)| folder))
    }

    /// Insert an adaptive playbook composed from a case. `parsed_steps` is
    /// the cached step tree (pre-serialized by the service layer).
    pub async fn insert_adaptive_from_case(
        &self,
        case_id: Uuid,
        composed_by_user_id: Option<Uuid>,
        title: &str,
        subtitle: Option<&str>,
        category: &str,
        doc: &str,
        parsed_steps: Option<serde_json::Value>,
        composed_by_label: &str,
    ) -> Result<Playbook, PlaybookError> {
        let adaptive_source = serde_json::json!({
            "case_id": case_id.to_string(),
            "composed_at": chrono::Utc::now().to_rfc3339(),
            "composed_by": composed_by_label,
            "based_on": [],
        });

        let pb: Playbook = sqlx::query_as(
            r#"INSERT INTO playbooks
                 (title, subtitle, category, doc, parsed_steps,
                  match_signals, danger_policy, status,
                  adaptive, adaptive_source, promoted,
                  source_linked, created_by)
               VALUES ($1, $2, $3, $4, $5,
                       '{}'::text[], '{}'::jsonb, 'draft',
                       TRUE, $6, FALSE,
                       FALSE, $7)
               RETURNING *"#,
        )
        .bind(title)
        .bind(subtitle)
        .bind(category)
        .bind(doc)
        .bind(parsed_steps)
        .bind(adaptive_source)
        .bind(composed_by_user_id)
        .fetch_one(&self.pool)
        .await?;
        Ok(pb)
    }

    // =========================================================================
    // NAN-448 — Phase 7: analytics
    // =========================================================================

    /// Aggregate analytics for a playbook from `playbook_runs`.
    ///
    /// NAN-2097: run counts, median TTR and the 30-day sparkline are operational
    /// facts about a playbook, so a caller the ACL hides the playbook from must
    /// not be able to infer that it exists or is being used.
    ///
    /// The predicate is a conjunct of the `r` CTE in the totals query and of the
    /// `LEFT JOIN` condition in the sparkline query, NOT a preceding probe. A
    /// probe alone would be check-then-act: an ACL revocation committing between
    /// the probe and either aggregate would still hand back real numbers. A
    /// denied caller now gets the all-zero shape of a playbook with no runs.
    pub async fn compute_analytics(
        &self,
        playbook_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<super::models::PlaybookAnalytics, PlaybookError> {
        use sqlx::Row;

        // Existence + visibility, for the clean 404. The aggregates below do NOT
        // depend on this having passed — each carries the predicate itself.
        let _ = self.get(playbook_id, principal).await?;

        // Totals: attached/finished in the last 30 days + median TTR (90d) +
        // hours since last run. One round-trip to keep it cheap.
        let totals_sql = format!(
            r#"WITH r AS (
                 SELECT * FROM playbook_runs
                  WHERE playbook_id = $1 AND {acl}
               )
               SELECT
                 (SELECT COUNT(*) FROM r WHERE started_at >= NOW() - INTERVAL '30 days')
                   AS attached_30d,
                 (SELECT COUNT(*) FROM r
                   WHERE status = 'resolved' AND finished_at >= NOW() - INTERVAL '30 days')
                   AS finished_30d,
                 (SELECT PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY ttr_minutes)
                    FROM r WHERE status = 'resolved' AND ttr_minutes IS NOT NULL
                           AND finished_at >= NOW() - INTERVAL '90 days')
                   AS ttr_median_min,
                 (SELECT EXTRACT(EPOCH FROM (NOW() - MAX(started_at))) / 3600.0
                    FROM r)
                   AS hours_since_last_run"#,
            acl = acl_sql("playbook_runs.playbook_id", PlaybookAction::View, "$2", "$3", "$4"),
        );
        let totals = sqlx::query(&totals_sql)
            .bind(playbook_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_one(&self.pool)
            .await?;

        let attached: i64 = totals.try_get("attached_30d").unwrap_or(0);
        let finished: i64 = totals.try_get("finished_30d").unwrap_or(0);
        let ttr_median_min: Option<f64> = totals.try_get("ttr_median_min").ok().flatten();
        let hours_since_last_run: Option<f64> =
            totals.try_get("hours_since_last_run").ok().flatten();

        // 30-day daily sparkline of attach counts (oldest → newest).
        let spark_sql = format!(
            r#"WITH days AS (
                 SELECT generate_series(
                   date_trunc('day', NOW() - INTERVAL '29 days'),
                   date_trunc('day', NOW()),
                   INTERVAL '1 day'
                 ) AS day
               )
               SELECT days.day,
                      COALESCE(COUNT(r.id), 0) AS attaches
                 FROM days
                 LEFT JOIN playbook_runs r
                   ON r.playbook_id = $1
                  AND date_trunc('day', r.started_at) = days.day
                  AND {acl}
               GROUP BY days.day
               ORDER BY days.day"#,
            acl = acl_sql("r.playbook_id", PlaybookAction::View, "$2", "$3", "$4"),
        );
        let spark_rows = sqlx::query(&spark_sql)
            .bind(playbook_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_all(&self.pool)
            .await?;

        let spark_30d: Vec<i64> = spark_rows
            .into_iter()
            .map(|row| row.try_get("attaches").unwrap_or(0))
            .collect();

        Ok(super::models::PlaybookAnalytics {
            attached,
            started: attached, // == attached until a "start" event is distinct
            finished,
            evd: 0, // placeholder — evidence-promoted tracking lands later
            ttr_median_min,
            hours_since_last_run,
            spark_30d,
        })
    }

    // =========================================================================
    // NAN-447 — Phase 6: approval workflow + permissions
    // =========================================================================

    /// Create an approval row + flip the playbook status to `pending_review`.
    /// No-op (returns the existing pending approval) if one is already open
    /// for the playbook's current version.
    ///
    /// A named reviewer must currently be an active user with both the coarse
    /// `playbooks:publish` capability and this playbook's Publish ACL grant.
    /// Response-time authorization re-evaluates the same condition: if the
    /// assignee later loses eligibility, another eligible publisher may recover
    /// the otherwise-stranded review.
    pub async fn submit_for_review(
        &self,
        playbook_id: Uuid,
        requester_id: Option<Uuid>,
        approver_id: Option<Uuid>,
        message: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookApproval, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        // NAN-2097: submitting for review mutates the playbook's status, so it is
        // an EDIT. Lock first, then evaluate the ACL in a fresh statement
        // snapshot; see `lock_playbook_for_action`.
        let current = Self::lock_playbook_for_action(
            &mut tx,
            playbook_id,
            PlaybookAction::Edit,
            principal,
        )
        .await?;

        if let Some(approver_id) = approver_id {
            let eligible_sql = format!("SELECT {}", approval_assignee_eligible_sql("$1", "$2"));
            let eligible: bool = sqlx::query_scalar(&eligible_sql)
                .bind(approver_id)
                .bind(playbook_id)
                .fetch_one(&mut *tx)
                .await?;
            if !eligible {
                tx.rollback().await?;
                return Err(PlaybookError::Validation(
                    "Assigned reviewer must be an active user with playbooks:publish and this \
                     playbook's publish ACL grant"
                        .to_string(),
                ));
            }
        }

        if let Some(existing) = sqlx::query_as::<_, PlaybookApproval>(
            "SELECT * FROM playbook_approvals
              WHERE playbook_id = $1 AND version = $2 AND status = 'pending'
              LIMIT 1",
        )
        .bind(playbook_id)
        .bind(current.current_version)
        .fetch_optional(&mut *tx)
        .await?
        {
            tx.rollback().await?;
            return Ok(existing);
        }

        if current.status != "pending_review" && current.status != "live" {
            sqlx::query(
                "UPDATE playbooks SET status = 'pending_review', updated_at = NOW() \
              WHERE id = $1 AND kind = 'response'",
            )
            .bind(playbook_id)
            .execute(&mut *tx)
            .await?;
        }

        let approval: PlaybookApproval = sqlx::query_as(
            r#"INSERT INTO playbook_approvals
                 (playbook_id, version, requester_id, approver_id, status, message)
               VALUES ($1, $2, $3, $4, 'pending', $5)
               RETURNING *"#,
        )
        .bind(playbook_id)
        .bind(current.current_version)
        .bind(requester_id)
        .bind(approver_id)
        .bind(message)
        .fetch_one(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(approval)
    }

    /// Approve a pending approval. Flips playbook to `live`. Idempotent.
    ///
    /// NAN-2098 — the transition is a SINGLE conditional UPDATE carrying every
    /// authorization predicate, replacing a load-then-update sequence that
    /// checked neither the assignee nor the playbook ACL:
    ///
    /// * `status = 'pending'` moved INTO the statement, so two concurrent
    ///   responders produce exactly one terminal transition.
    /// * an approval assigned to a specific reviewer may only be answered by
    ///   that reviewer while they remain eligible. If they become inactive,
    ///   lose `playbooks:publish`, or lose this playbook's Publish ACL grant,
    ///   any otherwise-authorized publisher may recover the stranded review.
    ///   Passing `assignee_claim = None` (see `PlaybookService::approve`) still
    ///   prevents an API key from impersonating an eligible named reviewer.
    /// * an open approval records the responder in `approver_id`; an assigned
    ///   approval preserves its assignee unless an interactive human is using
    ///   the orphan-recovery path, in which case it records that actual responder
    ///   instead of falsely attributing the terminal action to the former
    ///   assignee.
    /// * the per-playbook PUBLISH grant (NAN-2097).
    ///
    /// A mismatch is non-disclosing: an approval assigned to somebody else is
    /// reported exactly like one that does not exist (`NotFound`). An
    /// already-terminal approval is still returned unchanged (idempotent), which
    /// is no more than the caller can already read from
    /// `GET /api/playbooks/{id}/approvals` with the same capability.
    pub async fn approve_approval(
        &self,
        approval_id: Uuid,
        responder_id: Option<Uuid>,
        assignee_claim: Option<Uuid>,
        response: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookApproval, PlaybookError> {
        self.respond_to_approval(
            ApprovalOutcome::Approved,
            approval_id,
            responder_id,
            assignee_claim,
            response,
            principal,
        )
        .await
    }

    /// Reject a pending approval. Reverts playbook to `draft` (only if still
    /// in pending_review — previously-approved rows stay live). Idempotent.
    ///
    /// Same authorization rule as [`approve_approval`](Self::approve_approval):
    /// rejecting somebody else's assigned review is as much a separation-of-duties
    /// break as approving it.
    pub async fn reject_approval(
        &self,
        approval_id: Uuid,
        responder_id: Option<Uuid>,
        assignee_claim: Option<Uuid>,
        response: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookApproval, PlaybookError> {
        self.respond_to_approval(
            ApprovalOutcome::Rejected,
            approval_id,
            responder_id,
            assignee_claim,
            response,
            principal,
        )
        .await
    }

    /// The one implementation behind approve/reject — identical authorization,
    /// differing only in the terminal status and the playbook status it drives.
    async fn respond_to_approval(
        &self,
        outcome: ApprovalOutcome,
        approval_id: Uuid,
        responder_id: Option<Uuid>,
        assignee_claim: Option<Uuid>,
        response: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookApproval, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        // codex round 6 (P2): take the OWNING playbook's row lock for the whole
        // transaction. The conditional UPDATE below carries the Publish predicate,
        // but the follow-on `playbooks` status write does not — so without this
        // lock a concurrent ACL writer could revoke publish and commit between the
        // two, and the now-denied publish would still land. ACL writes take the
        // same lock (`lock_playbook_for_acl_write`), so they serialise. Resolving
        // the playbook id from the approval also 404s a missing approval before
        // any work.
        let owning: Option<(Uuid,)> = sqlx::query_as(
            "SELECT p.id FROM playbooks p \
              JOIN playbook_approvals a ON a.playbook_id = p.id \
             WHERE a.id = $1 AND p.kind = 'response' FOR UPDATE OF p",
        )
        .bind(approval_id)
        .fetch_optional(&mut *tx)
        .await?;
        if owning.is_none() {
            tx.rollback().await?;
            return Err(PlaybookError::NotFound(approval_id));
        }

        let assignee_eligible = approval_assignee_eligible_sql("a.approver_id", "a.playbook_id");
        let responder_eligible = approval_assignee_eligible_sql("$4", "a.playbook_id");
        // Re-read the interactive responder's authority from PostgreSQL at the
        // transition itself. Request-time permission resolution is cached, so it
        // cannot be the final word after a publisher's role was just revoked.
        // API keys deliberately have no assignee claim and remain limited to open
        // approvals by the predicate below.
        let interactive_responder =
            format!("$4 IS NOT NULL AND $2 = $4 AND ({responder_eligible})");
        // Recovery is human-only: API keys deliberately pass a NULL
        // `assignee_claim`, and the repository also requires the authorization
        // identity to match the responder attribution before it can override an
        // ineligible assignment.
        let can_recover = format!(
            "a.approver_id IS NOT NULL AND ({interactive_responder}) AND NOT ({assignee_eligible})"
        );
        let update_sql = format!(
            r#"UPDATE playbook_approvals a
                 SET status       = '{terminal}',
                     approver_id  = CASE
                         WHEN a.approver_id IS NULL OR ({can_recover}) THEN $2
                         ELSE a.approver_id
                     END,
                     response     = $3,
                     responded_at = NOW()
               WHERE a.id = $1
                 AND a.status = 'pending'
                 AND EXISTS (
                     SELECT 1
                       FROM playbooks approval_playbook
                      WHERE approval_playbook.id = a.playbook_id
                        AND approval_playbook.kind = 'response'
                        AND approval_playbook.current_version = a.version
                 )
                 AND (
                     (
                         a.approver_id IS NULL
                         AND ($4 IS NULL OR ({interactive_responder}))
                     )
                     OR (
                         a.approver_id = $4
                         AND ({interactive_responder})
                     )
                     OR ({can_recover})
                 )
                 AND {acl}
               RETURNING a.*"#,
            terminal = outcome.terminal_status(),
            interactive_responder = interactive_responder,
            can_recover = can_recover,
            acl = acl_sql("a.playbook_id", PlaybookAction::Publish, "$5", "$6", "$7"),
        );

        let updated: Option<PlaybookApproval> = sqlx::query_as(&update_sql)
            .bind(approval_id)
            .bind(responder_id)
            .bind(response)
            .bind(assignee_claim)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_optional(&mut *tx)
            .await?;

        let Some(updated) = updated else {
            // Nothing transitioned. Only ONE case is distinguishable — an approval
            // that is already terminal, which the caller may re-read idempotently.
            // Every authorization failure collapses into `NotFound` so the
            // response cannot be used to probe assignment or ACL state.
            //
            // This read-back carries the SAME Publish predicate as the UPDATE.
            // Without it the fallback would be an ACL bypass in its own right: a
            // caller denied `can_view` cannot read this approval through
            // `GET /api/playbooks/{id}/approvals`, but could POST to the approve
            // route against a terminal approval and receive the full row back —
            // requester, assignee, message and response included.
            let existing_sql = format!(
                "SELECT a.* FROM playbook_approvals a WHERE a.id = $1 AND {}",
                acl_sql("a.playbook_id", PlaybookAction::Publish, "$2", "$3", "$4")
            );
            let existing: Option<PlaybookApproval> = sqlx::query_as(&existing_sql)
                .bind(approval_id)
                .bind(principal.is_system())
                .bind(principal.role_ids())
                .bind(principal.synthetic_roles())
                .fetch_optional(&mut *tx)
                .await?;
            tx.rollback().await?;
            return match existing {
                Some(row) if row.status != "pending" => Ok(row),
                _ => Err(PlaybookError::NotFound(approval_id)),
            };
        };

        sqlx::query(outcome.playbook_status_sql())
            .bind(updated.playbook_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(updated)
    }

    /// Upsert a per-role permission row for a playbook (NAN-2097).
    ///
    /// Administering a playbook's ACL is an EDIT of that playbook: if it were
    /// gated on the coarse `playbooks:manage` alone, a caller denied `can_edit`
    /// could simply delete the row denying them and then edit — the ACL would be
    /// advisory. The whole operation runs under a `FOR UPDATE` lock on the
    /// playbook row, which serialises it against every other ACL write and
    /// against the ACL-predicated mutations (`update`, `fork`, `submit_for_review`,
    /// `promote`).
    ///
    /// Three write-time invariants keep the ACL from becoming un-administrable
    /// or locking out the caller:
    ///
    /// 1. `role` must name an existing role, or one of the reserved synthetic
    ///    principals in [`SYNTHETIC_ROLES`]. Without this,
    ///    `PUT …/permissions/soc-leads` (the example the API docs used to give!)
    ///    would create a row matching nobody and instantly hide the playbook from
    ///    every principal. A real role is stored by `role_id`, so the entry
    ///    survives a rename and cannot be captured by a later role reusing the
    ///    name.
    /// 2. The resulting ACL must leave at least one role holding `can_view AND
    ///    can_edit` **and** the coarse `playbooks:manage` capability. `can_edit`
    ///    alone is not enough: the ACL endpoints also require `playbooks:manage`
    ///    at the handler, and the seeded `Editor` role is granted only
    ///    `playbooks:view` + `playbooks:run` — so an ACL naming Editor as its
    ///    sole editor satisfies `can_edit` while leaving no principal able to
    ///    call the endpoints (codex round 5). Removing the LAST row is still
    ///    allowed — that returns the playbook to the un-ACL'd,
    ///    coarse-capability-only state.
    /// 3. A request principal must retain `can_view AND can_edit` after the
    ///    mutation. Invariant 2 only proves that *some* administrator exists; a
    ///    first row for a different managing role otherwise returns success and
    ///    immediately makes the playbook and its ACL return 404 to the caller
    ///    (NAN-2167). An implicit owner row is unsafe in this role-keyed schema:
    ///    the caller may hold several roles, and auto-granting any one of them
    ///    widens access to every member of that role. Reject the ambiguous
    ///    handoff instead. SYSTEM operations remain exempt, and removing the
    ///    final row remains valid because an empty ACL uses coarse RBAC.
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_permission(
        &self,
        playbook_id: Uuid,
        role: &str,
        can_view: bool,
        can_run: bool,
        can_edit: bool,
        can_publish: bool,
        member_count: Option<i32>,
        principal: &PlaybookPrincipal,
    ) -> Result<PlaybookPermission, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        // Invariant 1: resolve the label to a STABLE role id, or accept it as one
        // of the reserved synthetic principals (which have no `roles` row).
        // Lock a real role BEFORE the playbook. Permission changes take the
        // conflicting role lock and then every referenced playbook in the same
        // order, so neither side can validate against a stale permission set or
        // race a brand-new ACL reference into existence.
        let role_id: Option<Uuid> = if is_synthetic_role(role) {
            None
        } else {
            let resolved: Option<(Uuid,)> =
                sqlx::query_as("SELECT id FROM roles WHERE name = $1 FOR SHARE")
                    .bind(role)
                    .fetch_optional(&mut *tx)
                    .await?;
            match resolved {
                Some((id,)) => Some(id),
                None => {
                    // Keep the ACL authorization boundary opaque: a caller the
                    // current ACL denies still receives NotFound, not a role
                    // namespace oracle.
                    Self::lock_playbook_for_acl_write(&mut tx, playbook_id, principal).await?;
                    tx.rollback().await?;
                    return Err(PlaybookError::Validation(format!(
                        "Unknown role '{role}': a playbook ACL entry must name an existing role, \
                         or one of the reserved principals {SYNTHETIC_ROLES:?}"
                    )));
                }
            }
        };
        Self::lock_playbook_for_acl_write(&mut tx, playbook_id, principal).await?;

        // Migration 267/9000040 deliberately retains a full unique
        // `(playbook_id, role)` key until every pre-role_id binary has drained:
        // those binaries name that key in `ON CONFLICT`. Refresh every real
        // display label before inserting so the compatibility key cannot let a
        // stale label block a different role that legitimately reused the old
        // name. Normal role renames are kept in sync by the migration trigger;
        // this also repairs rows changed out-of-band.
        sqlx::query(
            r#"UPDATE playbook_permissions pp
                  SET role = roles.name,
                      updated_at = NOW()
                 FROM roles
                WHERE pp.playbook_id = $1
                  AND pp.role_id = roles.id
                  AND pp.role IS DISTINCT FROM roles.name"#,
        )
        .bind(playbook_id)
        .execute(&mut *tx)
        .await?;

        // codex round 6 (P1): conflict on the STABLE key, not the label. A role
        // rename leaves the stored `role` text behind, so conflicting on
        // `(playbook_id, role)` would miss the existing entry and INSERT a second
        // row for the same role_id — and union semantics would then preserve the
        // stale grants the caller was trying to revoke. Real roles therefore
        // conflict on `(playbook_id, role_id)` (partial unique index) and re-sync
        // the display label; synthetic principals, whose `role` IS the key,
        // conflict on `(playbook_id, role)`.
        let row: PlaybookPermission = if role_id.is_some() {
            sqlx::query_as(
                r#"INSERT INTO playbook_permissions
                     (playbook_id, role, role_id, can_view, can_run, can_edit, can_publish, member_count)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   ON CONFLICT (playbook_id, role_id) WHERE role_id IS NOT NULL DO UPDATE SET
                     role         = EXCLUDED.role,
                     can_view     = EXCLUDED.can_view,
                     can_run      = EXCLUDED.can_run,
                     can_edit     = EXCLUDED.can_edit,
                     can_publish  = EXCLUDED.can_publish,
                     member_count = EXCLUDED.member_count,
                     updated_at   = NOW()
                   RETURNING *"#,
            )
        } else {
            sqlx::query_as(
                r#"INSERT INTO playbook_permissions
                     (playbook_id, role, role_id, can_view, can_run, can_edit, can_publish, member_count)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                   ON CONFLICT (playbook_id, role) WHERE role_id IS NULL DO UPDATE SET
                     role_id      = EXCLUDED.role_id,
                     can_view     = EXCLUDED.can_view,
                     can_run      = EXCLUDED.can_run,
                     can_edit     = EXCLUDED.can_edit,
                     can_publish  = EXCLUDED.can_publish,
                     member_count = EXCLUDED.member_count,
                     updated_at   = NOW()
                   RETURNING *"#,
            )
        }
        .bind(playbook_id)
        .bind(role)
        .bind(role_id)
        .bind(can_view)
        .bind(can_run)
        .bind(can_edit)
        .bind(can_publish)
        .bind(member_count)
        .fetch_one(&mut *tx)
        .await?;

        Self::assert_acl_still_administrable(&mut tx, playbook_id).await?;
        Self::assert_acl_still_allows_principal(&mut tx, playbook_id, principal)
            .await?;
        tx.commit().await?;
        Ok(row)
    }

    /// Delete a per-role permission row. No error if the row doesn't exist.
    /// Same EDIT gate and same administrability invariant as
    /// [`upsert_permission`](Self::upsert_permission).
    pub async fn delete_permission(
        &self,
        playbook_id: Uuid,
        role: &str,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        let mut tx = self.pool.begin().await?;

        // Resolve and lock a real role before the playbook, matching permission
        // edits' lock order. A concurrent rename cannot make the subsequent
        // stable-id delete miss, and a concurrent permission removal cannot
        // invalidate the post-delete administrability check.
        let role_id: Option<Uuid> = if is_synthetic_role(role) {
            None
        } else {
            sqlx::query_scalar("SELECT id FROM roles WHERE name = $1 FOR SHARE")
                .bind(role)
                .fetch_optional(&mut *tx)
                .await?
        };
        Self::lock_playbook_for_acl_write(&mut tx, playbook_id, principal).await?;

        // Delete by the STABLE key for a real role. `list_permissions` joins the
        // current role name, so the label accepted here remains usable after a
        // rename even if the denormalized ACL label is stale.
        if is_synthetic_role(role) {
            sqlx::query(
                "DELETE FROM playbook_permissions \
                  WHERE playbook_id = $1 AND role_id IS NULL AND role = $2",
            )
            .bind(playbook_id)
            .bind(role)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "DELETE FROM playbook_permissions \
                  WHERE playbook_id = $1 \
                    AND role_id = $2",
            )
            .bind(playbook_id)
            .bind(role_id)
            .execute(&mut *tx)
            .await?;
        }

        Self::assert_acl_still_administrable(&mut tx, playbook_id).await?;
        Self::assert_acl_still_allows_principal(&mut tx, playbook_id, principal)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Take the playbook row lock, then enforce the EDIT grant from a fresh
    /// statement snapshot. Every ACL write starts here, so ACL writes serialise
    /// against each other and against ACL-predicated mutations.
    async fn lock_playbook_for_acl_write(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        playbook_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        Self::lock_playbook_for_action(tx, playbook_id, PlaybookAction::Edit, principal)
            .await
            .map(|_| ())
    }

    /// Serialize a mutation against ACL writes without evaluating authorization
    /// from a stale PostgreSQL READ COMMITTED statement snapshot.
    ///
    /// A single `SELECT ... WHERE <acl> FOR UPDATE` is subtly unsafe: it can
    /// evaluate the ACL, block behind a concurrent ACL writer that already owns
    /// the playbook lock, then continue after the revocation commits using the
    /// old statement snapshot. Locking the parent in an ACL-free statement and
    /// checking the ACL in the next statement guarantees the check observes the
    /// revocation. The parent remains locked until commit, so no later ACL write
    /// can interleave with the authorized mutation.
    async fn lock_playbook_for_action(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        playbook_id: Uuid,
        action: PlaybookAction,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        Self::lock_playbook_for_action_with_lock(
            tx,
            playbook_id,
            action,
            principal,
            PlaybookRowLock::Exclusive,
        )
        .await
    }

    /// Lock the immutable parent of an existing run, then evaluate its ACL in a
    /// fresh statement snapshot. ACL writers take the conflicting exclusive
    /// parent lock, so a revocation that started first must commit before this
    /// check runs. Denials stay indistinguishable from a missing run.
    async fn lock_run_playbook_for_action(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        run_id: Uuid,
        action: PlaybookAction,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        let playbook_id: Option<Uuid> =
            sqlx::query_scalar("SELECT playbook_id FROM playbook_runs WHERE id = $1")
                .bind(run_id)
                .fetch_optional(&mut **tx)
                .await?;
        let playbook_id = playbook_id.ok_or(PlaybookError::NotFound(run_id))?;

        match Self::lock_playbook_for_action_with_lock(
            tx,
            playbook_id,
            action,
            principal,
            PlaybookRowLock::Shared,
        )
        .await
        {
            Ok(_) => Ok(()),
            Err(PlaybookError::NotFound(_)) => Err(PlaybookError::NotFound(run_id)),
            Err(error) => Err(error),
        }
    }

    async fn lock_playbook_for_action_with_lock(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        playbook_id: Uuid,
        action: PlaybookAction,
        principal: &PlaybookPrincipal,
        row_lock: PlaybookRowLock,
    ) -> Result<Playbook, PlaybookError> {
        let lock_clause = match row_lock {
            PlaybookRowLock::Exclusive => "FOR UPDATE",
            PlaybookRowLock::Shared => "FOR SHARE",
        };
        let lock_sql =
            format!("SELECT * FROM playbooks WHERE id = $1 AND {RESPONSE_KIND} {lock_clause}");
        let current: Option<Playbook> = sqlx::query_as(&lock_sql)
            .bind(playbook_id)
            .fetch_optional(&mut **tx)
            .await?;
        let current = current.ok_or(PlaybookError::NotFound(playbook_id))?;

        let sql = format!(
            "SELECT EXISTS (SELECT 1 FROM playbooks WHERE id = $1 AND {RESPONSE_KIND} AND {})",
            acl_sql("playbooks.id", action, "$2", "$3", "$4")
        );
        let authorized: bool = sqlx::query_scalar(&sql)
            .bind(playbook_id)
            .bind(principal.is_system())
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_one(&mut **tx)
            .await?;
        if !authorized {
            return Err(PlaybookError::NotFound(playbook_id));
        }
        Ok(current)
    }

    /// Reject an ACL state that no principal could ever administer. An EMPTY ACL
    /// is fine (that is the un-restricted default); a NON-empty one must grant
    /// `can_view AND can_edit` to a role that ALSO holds `playbooks:manage`.
    ///
    /// The coarse-capability half is what codex round 5 caught: the ACL endpoints
    /// require `playbooks:manage` at the handler, and the seeded `Editor` role
    /// holds only `playbooks:view` + `playbooks:run` (157 / 9000004). An ACL
    /// naming Editor as its sole editor therefore satisfied `can_edit` while
    /// leaving nobody able to call the endpoints — including Admin, whose own
    /// `can_edit` the ACL denies.
    ///
    /// Synthetic principals cannot satisfy this: an API key's capabilities live on
    /// the key, not on a role, so there is no `role_permissions` row to check.
    /// Requiring a real role is the conservative reading — a human must remain
    /// able to repair the ACL.
    async fn assert_acl_still_administrable(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        playbook_id: Uuid,
    ) -> Result<(), PlaybookError> {
        let state: (bool, bool) = sqlx::query_as(
            r#"SELECT
                 EXISTS (SELECT 1 FROM playbook_permissions WHERE playbook_id = $1),
                 EXISTS (
                     SELECT 1
                       FROM playbook_permissions pp
                       JOIN role_permissions rp ON rp.role_id = pp.role_id
                      WHERE pp.playbook_id = $1
                        AND pp.can_view
                        AND pp.can_edit
                        AND rp.permission_id = 'playbooks:manage'
                 )"#,
        )
        .bind(playbook_id)
        .fetch_one(&mut **tx)
        .await?;

        if state.0 && !state.1 {
            return Err(PlaybookError::Validation(
                "Refusing to leave this playbook with an ACL nobody could administer: at \
                 least one entry must grant can_view AND can_edit to a role that also holds \
                 the playbooks:manage capability (or remove every entry to return the \
                 playbook to tenant-wide capability control)"
                    .to_string(),
            ));
        }
        Ok(())
    }

    /// Reject an ACL mutation that would make the caller unable to administer
    /// the same playbook through the API.
    ///
    /// [`Self::assert_acl_still_administrable`] proves only that at least one
    /// globally-capable role retains access. That can be a role the caller does
    /// not hold, which made a successful first ACL write an irreversible
    /// self-lockout (NAN-2167). Re-evaluate the canonical EDIT predicate against
    /// the transaction's resulting rows before commit. The playbook row is still
    /// exclusively locked, so no concurrent ACL writer can change the answer
    /// between this check and commit.
    async fn assert_acl_still_allows_principal(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        playbook_id: Uuid,
        principal: &PlaybookPrincipal,
    ) -> Result<(), PlaybookError> {
        if principal.is_system() {
            return Ok(());
        }

        let sql = format!(
            "SELECT EXISTS (SELECT 1 FROM playbooks WHERE id = $1 AND {RESPONSE_KIND} AND {})",
            acl_sql("playbooks.id", PlaybookAction::Edit, "$2", "$3", "$4")
        );
        let still_allowed: bool = sqlx::query_scalar(&sql)
            .bind(playbook_id)
            .bind(false)
            .bind(principal.role_ids())
            .bind(principal.synthetic_roles())
            .fetch_one(&mut **tx)
            .await?;

        if !still_allowed {
            return Err(PlaybookError::Validation(
                "Refusing to apply an ACL change that would remove your own can_view AND \
                 can_edit access. Grant one of your current roles (or synthetic principals) \
                 can_view AND can_edit before delegating access, or remove every ACL entry \
                 to return the playbook to tenant-wide capability control"
                    .to_string(),
            ));
        }
        Ok(())
    }

    // =========================================================================
    // NAN-446 — Phase 5: adaptive → library promote
    // =========================================================================

    /// Promote an adaptive (agent-composed) playbook into the library.
    ///
    /// Clears the `adaptive` flag, sets `promoted=TRUE`, and flips status to
    /// `pending_review` so the approval workflow (Phase 6) takes over.
    /// Snapshots the current doc/meta into a new `playbook_versions` row with
    /// `promoted_from_case_id` set — gives the library versions UI a record
    /// of where the playbook originated.
    ///
    /// Idempotent: if the playbook is already promoted (adaptive=false,
    /// promoted=true), this returns the existing row without modification.
    pub async fn promote(
        &self,
        playbook_id: Uuid,
        promoted_by_user_id: Option<Uuid>,
        promoted_by_name: Option<String>,
        principal: &PlaybookPrincipal,
    ) -> Result<Playbook, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        // NAN-2097: promotion moves an adaptive playbook into the reviewed
        // library, so it is a PUBLISH. Lock first, then evaluate the ACL in a
        // fresh statement snapshot; see `lock_playbook_for_action`.
        let current = Self::lock_playbook_for_action(
            &mut tx,
            playbook_id,
            PlaybookAction::Publish,
            principal,
        )
        .await?;

        // Idempotency: already promoted → no-op return.
        if !current.adaptive && current.promoted {
            tx.rollback().await?;
            return Ok(current);
        }

        // Extract the adaptive_source.case_id (if any) for version provenance.
        let promoted_from_case_id: Option<Uuid> = current
            .adaptive_source
            .as_ref()
            .and_then(|v| v.get("case_id"))
            .and_then(|v| v.as_str())
            .and_then(|s| crate::typeid::decode("case", s).ok().or_else(|| Uuid::parse_str(s).ok()));

        // Flip the flags + bump version.
        let new_version = current.current_version + 1;
        let promoted: Playbook = sqlx::query_as(
            r#"UPDATE playbooks
                 SET adaptive        = FALSE,
                     promoted        = TRUE,
                     status          = 'pending_review',
                     current_version = $2,
                     updated_at      = NOW()
               WHERE id = $1 AND kind = 'response'
               RETURNING *"#,
        )
        .bind(playbook_id)
        .bind(new_version)
        .fetch_one(&mut *tx)
        .await?;

        // Promotion advances the version outside the generic update path.
        // Supersede any review pinned to the adaptive version just as update()
        // does, so list_approvals does not retain an apparently-actionable
        // pending row that can never satisfy the response-time version guard.
        sqlx::query(
            r#"UPDATE playbook_approvals
                  SET status = 'withdrawn',
                      response = COALESCE(
                          response,
                          'Superseded by a newer playbook version'
                      ),
                      responded_at = NOW()
                WHERE playbook_id = $1
                  AND version < $2
                  AND status = 'pending'"#,
        )
        .bind(playbook_id)
        .bind(new_version)
        .execute(&mut *tx)
        .await?;

        // Snapshot into playbook_versions.
        let metadata = serde_json::json!({
            "title": promoted.title,
            "subtitle": promoted.subtitle,
            "category": promoted.category,
            "match_signals": promoted.match_signals,
            "danger_policy": promoted.danger_policy,
            "review_cadence": promoted.review_cadence,
            "scope": promoted.scope,
            "owner_team": promoted.owner_team,
            "tags": promoted.tags,
        });

        sqlx::query(
            r#"INSERT INTO playbook_versions
                 (playbook_id, version, doc, metadata, note,
                  author_id, author_name, promoted_from_case_id)
               VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"#,
        )
        .bind(playbook_id)
        .bind(new_version)
        .bind(&promoted.doc)
        .bind(metadata)
        .bind("Promoted from adaptive (agent-composed) to library")
        .bind(promoted_by_user_id)
        .bind(promoted_by_name.unwrap_or_else(|| "system".to_string()))
        .bind(promoted_from_case_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(promoted)
    }
}

#[cfg(test)]
mod kind_scope_tests {
    /// This module's own source, read at compile time.
    ///
    /// Self-referential on purpose: a path-relative `include_str!` travels with
    /// the file, so if the open-core mirror strips this module the test is
    /// stripped with it. An absolute `CARGO_MANIFEST_DIR` path would survive
    /// the strip and break the mirror build (NAN-2169).
    const SOURCE: &str = include_str!("repository.rs");

    /// Every query against the shared `playbooks` table must restrict itself to
    /// `kind = 'response'`.
    ///
    /// NAN-2238 made `playbooks` hold two kinds of row. A query here that omits
    /// the predicate lets a `playbooks:*` holder read, attach, or delete a HUNT
    /// through the response-playbook API, bypassing `hunts:*` entirely. That is
    /// an authorization bug rather than a cosmetic one, and it is invisible in
    /// review because the query looks exactly like it always did.
    ///
    /// Matching is deliberately crude — the predicate must appear within a few
    /// lines of the table reference. A guard that is easy to satisfy correctly
    /// and hard to satisfy accidentally beats a parser.
    #[test]
    fn response_repository_queries_are_kind_scoped() {
        // Scan PRODUCTION source only. An earlier revision scanned the whole
        // file, so the guard matched its own `line.contains("FROM playbooks")`
        // and found `kind = 'response'` in the assertion text a few lines
        // below — passing on its own body regardless of the code above it.
        let production = SOURCE
            .split_once("#[cfg(test)]")
            .map(|(before, _)| before)
            .unwrap_or(SOURCE);
        let lines: Vec<&str> = production.lines().collect();
        let mut unscoped = Vec::new();
        let mut sites = 0usize;

        for (idx, line) in lines.iter().enumerate() {
            // Every DML form, not just SELECT: an unscoped UPDATE or DELETE
            // mutates a hunt through the response API just as effectively as a
            // SELECT reads one.
            // INSERT is deliberately excluded. An insert cannot REACH an
            // existing hunt — the risk it carries is creating one through the
            // response API, and `playbooks.kind` defaults to 'response' so a
            // repository that never names the column cannot produce a hunt.
            // Including inserts here would flag three sites that are correct
            // and train the next reader to silence the guard.
            let touches_playbooks =
                line.contains("FROM playbooks") || line.contains("UPDATE playbooks");
            if !touches_playbooks || line.trim_start().starts_with("//") {
                continue;
            }
            sites += 1;
            // Follow the STATEMENT rather than a fixed line count. A fixed
            // window is wrong in both directions: too small and it misses the
            // predicate on a long multi-line UPDATE (the 14-column update in
            // `update` is 15 lines from `UPDATE playbooks` to its WHERE); too
            // large and it starts accepting an unrelated predicate from the
            // next query along. Stopping at the end of the SQL literal is the
            // boundary that actually matters.
            //
            // The floor of 7 lines covers the other shape in this file: a
            // `QueryBuilder` whose literal ends on its own line and whose
            // predicate arrives on the next `qb.push(...)`. Statement-end alone
            // would close the window before reaching it.
            let statement_end = lines[idx..]
                .iter()
                .position(|l| l.contains("\"#,") || l.contains("\");") || l.contains("\","))
                .map(|offset| idx + offset + 1)
                .unwrap_or(idx + 20);
            let window_end = statement_end.max(idx + 7).min(lines.len());
            let window = lines[idx..window_end].join("\n");
            let scoped = window.contains("kind = 'response'")
                || window.contains("RESPONSE_KIND")
                || window.contains("{RESPONSE_KIND}");
            if !scoped {
                unscoped.push(format!("line {}: {}", idx + 1, line.trim()));
            }
        }

        assert!(
            unscoped.is_empty(),
            "these `playbooks` queries are not restricted to kind = 'response', so a \
             playbooks:* holder could reach a HUNT through the response-playbook API \
             (NAN-2238). Add the predicate, or move the query to the hunts repository:\n{}",
            unscoped.join("\n")
        );

        // A scanner that silently matches nothing is indistinguishable from a
        // clean file. Pin the count so both a new unscoped query AND a refactor
        // that moves queries out of this file's reach have to be acknowledged.
        assert!(
            sites >= 12,
            "expected at least 12 `playbooks` query sites, found {sites} — either queries \
             moved somewhere this guard cannot see, or the matcher stopped working"
        );
    }

    /// The predicate names the column explicitly rather than relying on a join
    /// alias, so it keeps working if a query gains a second table.
    #[test]
    fn response_kind_predicate_is_column_qualified() {
        assert_eq!(super::RESPONSE_KIND, "playbooks.kind = 'response'");
    }

    /// The child tables are NOT this guard's job.
    ///
    /// `playbook_versions`, `playbook_runs`, `playbook_approvals` and
    /// `playbook_permissions` are keyed on `playbook_id` alone and are read by
    /// roughly eighteen queries that never mention `playbooks`. Rather than
    /// scope each one — and re-scope the nineteenth somebody adds — migration
    /// 9000055 pins all four to `kind = 'response'` with constant-kind
    /// composite FKs, so a hunt cannot have a row in them at all and those
    /// queries have nothing of a hunt's to leak however they are written.
    ///
    /// This test documents the division of responsibility so a future reader
    /// does not "fix" the child tables here and conclude the migration is
    /// redundant.
    ///
    /// Read at RUNTIME, not via `include_str!`.
    ///
    /// `tools/sync-to-nano-mirror.sh` strips `migrations/postgres-enterprise/`
    /// but keeps this file, so a compile-time include of that path makes the
    /// public mirror fail to build — the NAN-2169 shape. The script's existing
    /// answer is to delete whole test FILES that read stripped paths, which is
    /// not available here because this module lives inside core source. A
    /// runtime read compiles everywhere and simply skips where the migration is
    /// absent, keeping the coverage in the private repo without breaking the
    /// public one. Its own guidance applies: prefer keeping a test compilable
    /// over stripping it.
    #[test]
    fn child_tables_are_pinned_in_schema_not_scoped_in_sql() {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(
            "../migrations/postgres-enterprise/9000055_pin_playbook_children_to_response.sql",
        );
        let Ok(migration) = std::fs::read_to_string(&path) else {
            // Stripped mirror. The invariant this guards is enterprise-only, so
            // there is nothing to assert where the schema does not ship.
            return;
        };
        for child in [
            "playbook_versions",
            "playbook_runs",
            "playbook_approvals",
            "playbook_permissions",
        ] {
            assert!(
                migration.contains(&format!("ALTER TABLE {child}")),
                "{child} is not pinned to kind='response' by 9000055; its queries would then \
                 need explicit scoping in this file"
            );
        }
    }
}
