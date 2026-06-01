// SPDX-License-Identifier: AGPL-3.0-or-later

//! Database repository for playbooks.
//!
//! Handles CRUD for `playbooks`, `playbook_versions`, `playbook_runs`,
//! `playbook_permissions`, and `playbook_approvals`.

use serde_json::Value;
use sqlx::{PgPool, QueryBuilder};
use uuid::Uuid;

use super::error::PlaybookError;
use super::models::{
    CreatePlaybookRequest, ForkPlaybookRequest, ListPlaybooksQuery, Playbook, PlaybookApproval,
    PlaybookPermission, PlaybookRun, PlaybookScope, PlaybookStatus, PlaybookVersion,
    UpdatePlaybookRequest,
};

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

    pub async fn list(&self, query: &ListPlaybooksQuery) -> Result<Vec<Playbook>, PlaybookError> {
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT * FROM playbooks WHERE 1=1");

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

    pub async fn count(&self, query: &ListPlaybooksQuery) -> Result<i64, PlaybookError> {
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT COUNT(*) FROM playbooks WHERE 1=1");
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

    pub async fn get(&self, id: Uuid) -> Result<Playbook, PlaybookError> {
        let pb = sqlx::query_as::<_, Playbook>("SELECT * FROM playbooks WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(PlaybookError::NotFound(id))?;
        Ok(pb)
    }

    pub async fn list_by_signal(&self, signals: &[String]) -> Result<Vec<Playbook>, PlaybookError> {
        if signals.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, Playbook>(
            "SELECT * FROM playbooks WHERE status = 'live' AND match_signals && $1 ORDER BY updated_at DESC",
        )
        .bind(signals)
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

    pub async fn delete(&self, id: Uuid) -> Result<(), PlaybookError> {
        let result = sqlx::query("DELETE FROM playbooks WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        if result.rows_affected() == 0 {
            return Err(PlaybookError::NotFound(id));
        }
        Ok(())
    }

    // =========================================================================
    // Update
    // =========================================================================

    pub async fn update(
        &self,
        id: Uuid,
        req: &UpdatePlaybookRequest,
        parsed_steps: Option<&Value>,
        user_id: Option<Uuid>,
    ) -> Result<Playbook, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        let current = sqlx::query_as::<_, Playbook>("SELECT * FROM playbooks WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(PlaybookError::NotFound(id))?;

        // Did the doc or meta actually change? If so, bump version.
        let doc_changed = req.doc.as_deref().map(|d| d != current.doc).unwrap_or(false);
        let meta_changed = req.title.is_some()
            || req.subtitle.is_some()
            || req.category.is_some()
            || req.match_signals.is_some()
            || req.danger_policy.is_some()
            || req.review_cadence.is_some()
            || req.scope.is_some()
            || req.tags.is_some()
            || req.owner_team.is_some()
            || req.status.is_some();

        let next_version = if doc_changed || meta_changed {
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
        let status = req
            .status
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| current.status.clone());

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
            WHERE id = $1
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

    pub async fn archive(&self, id: Uuid) -> Result<(), PlaybookError> {
        let result = sqlx::query(
            "UPDATE playbooks SET status = 'archived', updated_at = NOW() WHERE id = $1",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        if result.rows_affected() == 0 {
            return Err(PlaybookError::NotFound(id));
        }
        Ok(())
    }

    // =========================================================================
    // Fork
    // =========================================================================

    pub async fn fork(
        &self,
        id: Uuid,
        req: &ForkPlaybookRequest,
        user_id: Option<Uuid>,
    ) -> Result<Playbook, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        let source = sqlx::query_as::<_, Playbook>("SELECT * FROM playbooks WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(PlaybookError::NotFound(id))?;

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

    pub async fn list_versions(&self, id: Uuid) -> Result<Vec<PlaybookVersion>, PlaybookError> {
        let rows = sqlx::query_as::<_, PlaybookVersion>(
            "SELECT * FROM playbook_versions WHERE playbook_id = $1 ORDER BY version DESC",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// Fetch the `doc` text for a specific `(playbook_id, version)` pair —
    /// used by [`crate::playbooks::service::PlaybookService::resolve_run`]
    /// to parse + resolve a run against its frozen version.
    pub async fn get_version_doc(
        &self,
        playbook_id: Uuid,
        version: i32,
    ) -> Result<String, PlaybookError> {
        let doc: Option<String> = sqlx::query_scalar(
            "SELECT doc FROM playbook_versions WHERE playbook_id = $1 AND version = $2",
        )
        .bind(playbook_id)
        .bind(version)
        .fetch_optional(&self.pool)
        .await?;
        doc.ok_or(PlaybookError::NotFound(playbook_id))
    }

    // =========================================================================
    // Runs
    // =========================================================================

    pub async fn list_runs(&self, id: Uuid) -> Result<Vec<PlaybookRun>, PlaybookError> {
        let rows = sqlx::query_as::<_, PlaybookRun>(
            "SELECT * FROM playbook_runs WHERE playbook_id = $1 ORDER BY started_at DESC",
        )
        .bind(id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    // =========================================================================
    // Permissions
    // =========================================================================

    pub async fn list_permissions(
        &self,
        id: Uuid,
    ) -> Result<Vec<PlaybookPermission>, PlaybookError> {
        let rows = sqlx::query_as::<_, PlaybookPermission>(
            "SELECT * FROM playbook_permissions WHERE playbook_id = $1 ORDER BY role ASC",
        )
        .bind(id)
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
    ) -> Result<Vec<PlaybookApproval>, PlaybookError> {
        let rows = sqlx::query_as::<_, PlaybookApproval>(
            "SELECT * FROM playbook_approvals WHERE playbook_id = $1 ORDER BY requested_at DESC",
        )
        .bind(id)
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
    pub async fn suggest_by_signals(
        &self,
        signals: &[String],
        category: Option<&str>,
    ) -> Result<Vec<(Playbook, i32, Vec<String>)>, PlaybookError> {
        use sqlx::Row;

        // Fetch candidate rows in two columns: the Playbook (FromRow) payload,
        // plus the matched-signals array for scoring. Use plain `query` + manual
        // row mapping so the tuple doesn't need to implement Decode.
        let rows = sqlx::query(
            r#"SELECT p.*,
                      COALESCE(ARRAY(
                          SELECT UNNEST(p.match_signals)
                          INTERSECT
                          SELECT UNNEST($1::text[])
                      ), '{}') AS matched_signals_out
               FROM playbooks p
               WHERE p.status = 'live'
                 AND (
                      p.match_signals && $1::text[]
                      OR ($2::text IS NOT NULL AND p.category = $2::text)
                 )
               LIMIT 200"#,
        )
        .bind(signals)
        .bind(category)
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
    ) -> Result<PlaybookRun, PlaybookError> {
        // Resolve version: either caller-supplied or the playbook's current.
        let resolved_version: i32 = if let Some(v) = version {
            v
        } else {
            sqlx::query_scalar::<_, i32>(
                "SELECT current_version FROM playbooks WHERE id = $1",
            )
            .bind(playbook_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(PlaybookError::NotFound(playbook_id))?
        };

        let run: PlaybookRun = sqlx::query_as(
            r#"INSERT INTO playbook_runs
                 (playbook_id, playbook_version, case_id, status,
                  operator_user_id, operator_label, run_context)
               VALUES ($1, $2, $3, 'active', $4, $5, $6)
               RETURNING *"#,
        )
        .bind(playbook_id)
        .bind(resolved_version)
        .bind(case_id)
        .bind(operator_user_id)
        .bind(operator_label)
        .bind(run_context)
        .fetch_one(&self.pool)
        .await?;
        Ok(run)
    }

    /// Get a single run by id.
    pub async fn get_run(&self, run_id: Uuid) -> Result<PlaybookRun, PlaybookError> {
        let row: Option<PlaybookRun> =
            sqlx::query_as("SELECT * FROM playbook_runs WHERE id = $1")
                .bind(run_id)
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

        // jsonb_set with `create_missing=true`: target path is
        // `step_completion -> $step_id`; value is the prior entry (or `{}`)
        // concatenated with the patch, so only specified fields overwrite.
        let run: Option<PlaybookRun> = sqlx::query_as(
            r#"UPDATE playbook_runs
                 SET step_completion = jsonb_set(
                     COALESCE(step_completion, '{}'::jsonb),
                     ARRAY[$2::text],
                     COALESCE(step_completion -> $2, '{}'::jsonb) || $3::jsonb,
                     true
                 )
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(run_id)
        .bind(step_id)
        .bind(patch_json)
        .fetch_optional(&self.pool)
        .await?;
        run.ok_or(PlaybookError::NotFound(run_id))
    }

    /// Mark a run finished and compute TTR. Idempotent — re-finishing a
    /// resolved run re-sets `finished_at` and `ttr_minutes`.
    pub async fn finish_run(
        &self,
        run_id: Uuid,
        outcome: Option<String>,
        step_completion: Option<serde_json::Value>,
    ) -> Result<PlaybookRun, PlaybookError> {
        let run: Option<PlaybookRun> = sqlx::query_as(
            r#"UPDATE playbook_runs
                 SET finished_at  = NOW(),
                     status       = 'resolved',
                     outcome      = COALESCE($2, outcome),
                     step_completion = COALESCE($3, step_completion),
                     ttr_minutes  = CAST(
                         EXTRACT(EPOCH FROM (NOW() - started_at)) / 60 AS INTEGER
                     )
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(run_id)
        .bind(outcome)
        .bind(step_completion)
        .fetch_optional(&self.pool)
        .await?;
        run.ok_or(PlaybookError::NotFound(run_id))
    }

    /// List all runs attached to a given case, newest first.
    pub async fn list_runs_for_case(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<PlaybookRun>, PlaybookError> {
        let rows: Vec<PlaybookRun> = sqlx::query_as(
            "SELECT * FROM playbook_runs WHERE case_id = $1 ORDER BY started_at DESC",
        )
        .bind(case_id)
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
    ) -> Result<Vec<crate::models::notebook::NotebookEntryWithCreator>, PlaybookError> {
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
                ORDER BY e.created_at ASC"#,
        )
        .bind(case_id)
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
    pub async fn compute_analytics(
        &self,
        playbook_id: Uuid,
    ) -> Result<super::models::PlaybookAnalytics, PlaybookError> {
        use sqlx::Row;

        // Totals: attached/finished in the last 30 days + median TTR (90d) +
        // hours since last run. One round-trip to keep it cheap.
        let totals = sqlx::query(
            r#"WITH r AS (
                 SELECT * FROM playbook_runs WHERE playbook_id = $1
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
        )
        .bind(playbook_id)
        .fetch_one(&self.pool)
        .await?;

        let attached: i64 = totals.try_get("attached_30d").unwrap_or(0);
        let finished: i64 = totals.try_get("finished_30d").unwrap_or(0);
        let ttr_median_min: Option<f64> = totals.try_get("ttr_median_min").ok().flatten();
        let hours_since_last_run: Option<f64> =
            totals.try_get("hours_since_last_run").ok().flatten();

        // 30-day daily sparkline of attach counts (oldest → newest).
        let spark_rows = sqlx::query(
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
               GROUP BY days.day
               ORDER BY days.day"#,
        )
        .bind(playbook_id)
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
    pub async fn submit_for_review(
        &self,
        playbook_id: Uuid,
        requester_id: Option<Uuid>,
        approver_id: Option<Uuid>,
        message: Option<String>,
    ) -> Result<PlaybookApproval, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        let current: Playbook = sqlx::query_as("SELECT * FROM playbooks WHERE id = $1")
            .bind(playbook_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(PlaybookError::NotFound(playbook_id))?;

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
                "UPDATE playbooks SET status = 'pending_review', updated_at = NOW() WHERE id = $1",
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
    pub async fn approve_approval(
        &self,
        approval_id: Uuid,
        approver_id: Option<Uuid>,
        response: Option<String>,
    ) -> Result<PlaybookApproval, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        let approval: PlaybookApproval =
            sqlx::query_as("SELECT * FROM playbook_approvals WHERE id = $1")
                .bind(approval_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(PlaybookError::NotFound(approval_id))?;

        if approval.status != "pending" {
            tx.rollback().await?;
            return Ok(approval);
        }

        let updated: PlaybookApproval = sqlx::query_as(
            r#"UPDATE playbook_approvals
                 SET status       = 'approved',
                     approver_id  = COALESCE($2, approver_id),
                     response     = $3,
                     responded_at = NOW()
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(approval_id)
        .bind(approver_id)
        .bind(response)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query("UPDATE playbooks SET status = 'live', updated_at = NOW() WHERE id = $1")
            .bind(approval.playbook_id)
            .execute(&mut *tx)
            .await?;

        tx.commit().await?;
        Ok(updated)
    }

    /// Reject a pending approval. Reverts playbook to `draft` (only if still
    /// in pending_review — previously-approved rows stay live). Idempotent.
    pub async fn reject_approval(
        &self,
        approval_id: Uuid,
        approver_id: Option<Uuid>,
        response: Option<String>,
    ) -> Result<PlaybookApproval, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        let approval: PlaybookApproval =
            sqlx::query_as("SELECT * FROM playbook_approvals WHERE id = $1")
                .bind(approval_id)
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(PlaybookError::NotFound(approval_id))?;

        if approval.status != "pending" {
            tx.rollback().await?;
            return Ok(approval);
        }

        let updated: PlaybookApproval = sqlx::query_as(
            r#"UPDATE playbook_approvals
                 SET status       = 'rejected',
                     approver_id  = COALESCE($2, approver_id),
                     response     = $3,
                     responded_at = NOW()
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(approval_id)
        .bind(approver_id)
        .bind(response)
        .fetch_one(&mut *tx)
        .await?;

        sqlx::query(
            "UPDATE playbooks
               SET status = 'draft', updated_at = NOW()
             WHERE id = $1 AND status = 'pending_review'",
        )
        .bind(approval.playbook_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(updated)
    }

    /// Upsert a per-role permission row for a playbook.
    pub async fn upsert_permission(
        &self,
        playbook_id: Uuid,
        role: &str,
        can_view: bool,
        can_run: bool,
        can_edit: bool,
        can_publish: bool,
        member_count: Option<i32>,
    ) -> Result<PlaybookPermission, PlaybookError> {
        let row: PlaybookPermission = sqlx::query_as(
            r#"INSERT INTO playbook_permissions
                 (playbook_id, role, can_view, can_run, can_edit, can_publish, member_count)
               VALUES ($1, $2, $3, $4, $5, $6, $7)
               ON CONFLICT (playbook_id, role) DO UPDATE SET
                 can_view     = EXCLUDED.can_view,
                 can_run      = EXCLUDED.can_run,
                 can_edit     = EXCLUDED.can_edit,
                 can_publish  = EXCLUDED.can_publish,
                 member_count = EXCLUDED.member_count,
                 updated_at   = NOW()
               RETURNING *"#,
        )
        .bind(playbook_id)
        .bind(role)
        .bind(can_view)
        .bind(can_run)
        .bind(can_edit)
        .bind(can_publish)
        .bind(member_count)
        .fetch_one(&self.pool)
        .await?;
        Ok(row)
    }

    /// Delete a per-role permission row. No error if the row doesn't exist.
    pub async fn delete_permission(
        &self,
        playbook_id: Uuid,
        role: &str,
    ) -> Result<(), PlaybookError> {
        sqlx::query("DELETE FROM playbook_permissions WHERE playbook_id = $1 AND role = $2")
            .bind(playbook_id)
            .bind(role)
            .execute(&self.pool)
            .await?;
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
    ) -> Result<Playbook, PlaybookError> {
        let mut tx = self.pool.begin().await?;

        // Fetch current state inside the tx for consistency.
        let current: Playbook = sqlx::query_as("SELECT * FROM playbooks WHERE id = $1")
            .bind(playbook_id)
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(PlaybookError::NotFound(playbook_id))?;

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
               WHERE id = $1
               RETURNING *"#,
        )
        .bind(playbook_id)
        .bind(new_version)
        .fetch_one(&mut *tx)
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
