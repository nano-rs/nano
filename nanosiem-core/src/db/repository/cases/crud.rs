// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case CRUD operations: create, read, update, delete, list, stats

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::{
    AssignCase, Case, CaseDisposition, CaseFilter, CaseFullResponse, CaseRepository,
    CaseRepositoryError, CaseResponseStats, CaseSort, CaseStats, CaseSummary, CaseWithDetails,
    CaseWithDetailsRow, ChangeCaseStatus, NewCase, SlaTargets, UpdateCase,
};

/// NAN-1093: assemble the ORDER BY clause for `CaseRepository::list`. Kept
/// out of the format!() macro to keep the SQL string readable. `$9` is the
/// bound `user_id` parameter — referenced inline by the `MineFirst` variant
/// so we don't add a redundant bind.
///
/// NAN-1095: `Sla` is the only variant that needs runtime input — the
/// per-severity target minutes. Those are inlined as numeric literals
/// (safe — every value is an `i32` from a closed settings table, never
/// user input) so the rest of the bind list stays the same.
fn build_order_by(sort: CaseSort, sla_targets: Option<&SlaTargets>) -> String {
    match sort {
        // NAN-1057: recency first so new cases surface immediately; severity
        // is the tiebreaker. last_activity_at is nullable for legacy rows,
        // COALESCE so they still rank by created_at.
        CaseSort::Newest => "ORDER BY \
                COALESCE(c.last_activity_at, c.created_at) DESC, \
                CASE c.severity \
                    WHEN 'critical' THEN 1 \
                    WHEN 'high' THEN 2 \
                    WHEN 'medium' THEN 3 \
                    WHEN 'low' THEN 4 \
                    ELSE 5 \
                END, \
                c.priority DESC"
            .to_string(),
        CaseSort::Oldest => "ORDER BY \
                COALESCE(c.last_activity_at, c.created_at) ASC, \
                c.priority DESC"
            .to_string(),
        CaseSort::Severity => "ORDER BY \
                CASE c.severity \
                    WHEN 'critical' THEN 1 \
                    WHEN 'high' THEN 2 \
                    WHEN 'medium' THEN 3 \
                    WHEN 'low' THEN 4 \
                    ELSE 5 \
                END, \
                COALESCE(c.last_activity_at, c.created_at) DESC"
            .to_string(),
        CaseSort::MineFirst => {
            // $9 is user_id (already bound for the visibility predicate). Cases
            // assigned to the caller come first, then by recency.
            "ORDER BY \
                CASE WHEN c.assigned_to = $9 THEN 0 ELSE 1 END, \
                COALESCE(c.last_activity_at, c.created_at) DESC"
                .to_string()
        }
        CaseSort::Sla => {
            // NAN-1095: server-side SLA-urgency sort. For each of the three
            // tracked clocks (TTA / TTR / TTClose) compute `target - elapsed`
            // when the clock is still running; NULL otherwise. `LEAST()` in
            // Postgres ignores NULLs, so a case with all clocks stopped
            // becomes NULL and sorts last via `NULLS LAST`. Breached cases
            // (negative remaining) sort first.
            //
            // Clock stop conditions mirror `buildSlaSnapshot` in
            // `nanosiem-web/src/enterprise/components/case-investigate/sla/helpers.ts`:
            //   - TTA stops when `triage_completed_at` OR `first_response_at`
            //   - TTR stops when `first_response_at`
            //   - TTClose stops when `resolved_at` OR `closed_at`
            //
            // If `sla_targets` is None we shouldn't be here — defensive
            // fallback uses the same defaults as `CaseConfig::default()` so
            // a misconfigured caller still gets sensible ordering instead
            // of an SQL error.
            let t = sla_targets.copied().unwrap_or(SlaTargets::FALLBACK_DEFAULTS);
            let elapsed = "EXTRACT(EPOCH FROM (now() - COALESCE(c.first_activity_at, c.created_at)))";

            // Per-clock CASE expressions. Each yields the per-severity target
            // in seconds when the relevant stop fields are NULL (clock
            // running), else NULL (clock stopped → drop out of the LEAST).
            //
            // NAN-1097: `ELSE NULL` on the inner severity CASE is explicit
            // so the "unknown severity → drop out of LEAST → sort last via
            // NULLS LAST" path is visible to the next reader. Postgres would
            // return NULL implicitly without it, but the contract is now
            // documented in the SQL itself.
            let tta = format!(
                "CASE WHEN c.triage_completed_at IS NULL AND c.first_response_at IS NULL THEN \
                    CASE c.severity \
                        WHEN 'critical' THEN {ct} * 60 - {elapsed} \
                        WHEN 'high' THEN {ht} * 60 - {elapsed} \
                        WHEN 'medium' THEN {mt} * 60 - {elapsed} \
                        WHEN 'low' THEN {lt} * 60 - {elapsed} \
                        WHEN 'informational' THEN {it} * 60 - {elapsed} \
                        ELSE NULL \
                    END \
                 END",
                ct = t.critical_triage_minutes,
                ht = t.high_triage_minutes,
                mt = t.medium_triage_minutes,
                lt = t.low_triage_minutes,
                it = t.informational_triage_minutes,
                elapsed = elapsed,
            );
            let ttr = format!(
                "CASE WHEN c.first_response_at IS NULL THEN \
                    CASE c.severity \
                        WHEN 'critical' THEN {ct} * 60 - {elapsed} \
                        WHEN 'high' THEN {ht} * 60 - {elapsed} \
                        WHEN 'medium' THEN {mt} * 60 - {elapsed} \
                        WHEN 'low' THEN {lt} * 60 - {elapsed} \
                        WHEN 'informational' THEN {it} * 60 - {elapsed} \
                        ELSE NULL \
                    END \
                 END",
                ct = t.critical_response_minutes,
                ht = t.high_response_minutes,
                mt = t.medium_response_minutes,
                lt = t.low_response_minutes,
                it = t.informational_response_minutes,
                elapsed = elapsed,
            );
            let tt_close = format!(
                "CASE WHEN c.resolved_at IS NULL AND c.closed_at IS NULL THEN \
                    CASE c.severity \
                        WHEN 'critical' THEN {ct} * 60 - {elapsed} \
                        WHEN 'high' THEN {ht} * 60 - {elapsed} \
                        WHEN 'medium' THEN {mt} * 60 - {elapsed} \
                        WHEN 'low' THEN {lt} * 60 - {elapsed} \
                        WHEN 'informational' THEN {it} * 60 - {elapsed} \
                        ELSE NULL \
                    END \
                 END",
                ct = t.critical_resolution_minutes,
                ht = t.high_resolution_minutes,
                mt = t.medium_resolution_minutes,
                lt = t.low_resolution_minutes,
                it = t.informational_resolution_minutes,
                elapsed = elapsed,
            );
            format!(
                "ORDER BY LEAST({tta}, {ttr}, {tt_close}) ASC NULLS LAST, \
                 COALESCE(c.last_activity_at, c.created_at) DESC"
            )
        }
    }
}

impl SlaTargets {
    /// NAN-1095: defensive defaults that match
    /// `nanosiem_enterprise::cases::settings::CaseConfig::default()`. Used
    /// when `build_order_by` is asked for `Sla` ordering without an explicit
    /// target set — keeps the SQL valid instead of producing a runtime error.
    pub const FALLBACK_DEFAULTS: SlaTargets = SlaTargets {
        critical_triage_minutes: 60,
        critical_response_minutes: 15,
        critical_resolution_minutes: 240,
        high_triage_minutes: 120,
        high_response_minutes: 30,
        high_resolution_minutes: 480,
        medium_triage_minutes: 480,
        medium_response_minutes: 120,
        medium_resolution_minutes: 1440,
        low_triage_minutes: 1440,
        low_response_minutes: 480,
        low_resolution_minutes: 4320,
        informational_triage_minutes: 2880,
        informational_response_minutes: 1440,
        informational_resolution_minutes: 10080,
    };
}

impl CaseRepository {
    // ==================== CASE CRUD ====================

    /// Create a new case
    ///
    /// All operations (case insert + group associations) are wrapped in a transaction.
    pub async fn create(&self, case: &NewCase) -> Result<Case, CaseRepositoryError> {
        let severity_str = format!("{:?}", case.severity).to_lowercase();
        let grouping_type_str = case.grouping_type.as_ref().map(|g| g.to_string());
        let visibility = case.visibility.as_deref().unwrap_or("public");

        // Start transaction to ensure case + group associations are atomic
        let mut tx = self.pool.begin().await?;

        let result = sqlx::query_as::<_, Case>(
            r#"
            INSERT INTO cases (
                title, description, severity, priority, assigned_to,
                grouping_key, grouping_type, visibility, created_by,
                assigned_group, assigned_group_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                    $10, CASE WHEN $10 IS NOT NULL THEN NOW() ELSE NULL END)
            RETURNING *
            "#,
        )
        .bind(&case.title)
        .bind(&case.description)
        .bind(&severity_str)
        .bind(case.priority)
        .bind(case.assigned_to)
        .bind(&case.grouping_key)
        .bind(&grouping_type_str)
        .bind(visibility)
        .bind(case.created_by)
        .bind(case.assigned_group)
        .fetch_one(&mut *tx)
        .await?;

        // If visibility is 'group', add the group associations (batch insert)
        if visibility == "group" {
            if let Some(ref group_ids) = case.group_ids {
                if !group_ids.is_empty() {
                    sqlx::query(
                        r#"
                        INSERT INTO case_groups (case_id, group_id)
                        SELECT $1, unnest($2::uuid[])
                        ON CONFLICT DO NOTHING
                        "#,
                    )
                    .bind(result.id)
                    .bind(group_ids)
                    .execute(&mut *tx)
                    .await?;
                }
            }
        }

        // Commit transaction
        tx.commit().await?;

        Ok(result)
    }

    /// Find a case by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<Case, CaseRepositoryError> {
        let result = sqlx::query_as::<_, Case>(r#"SELECT * FROM cases WHERE id = $1"#)
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(CaseRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Find a case by case number
    pub async fn find_by_case_number(&self, case_number: i32) -> Result<Case, CaseRepositoryError> {
        let result = sqlx::query_as::<_, Case>(r#"SELECT * FROM cases WHERE case_number = $1"#)
            .bind(case_number)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(CaseRepositoryError::NotFound(Uuid::nil()))?;

        Ok(result)
    }

    /// Find case by grouping key (for auto-grouping)
    pub async fn find_by_grouping_key(
        &self,
        grouping_key: &str,
    ) -> Result<Option<Case>, CaseRepositoryError> {
        let result = sqlx::query_as::<_, Case>(
            r#"
            SELECT * FROM cases
            WHERE grouping_key = $1
              AND status NOT IN ('resolved', 'closed')
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(grouping_key)
        .fetch_optional(&self.pool)
        .await?;

        Ok(result)
    }

    /// Get case with full details including alerts, entities, wall entries
    pub async fn get_full(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<CaseFullResponse, CaseRepositoryError> {
        let case = self.find_by_id_for_user(id, user_id).await?;
        let alerts = self.get_case_alerts(id).await?;
        let entities = self.get_entities_grouped(id).await?;
        let wall = self.get_wall_entries(id, None, None).await?;
        let related = self.get_related_cases(id).await?;
        let stats = self.get_case_stats_single(id).await?;

        Ok(CaseFullResponse {
            case,
            alerts,
            entities,
            wall,
            related_cases: related,
            stats,
            playbook: None,
            close_note: None,
            pending_state: None,
            escalations: Vec::new(),
            handoffs: Vec::new(),
            workflow_events: Vec::new(),
            linked_cases_index: std::collections::HashMap::new(),
        })
    }

    /// Batch-fetch compact case references by id, filtered to cases the
    /// viewer can see. Used by `get_case_full` to resolve `case_*` typeid
    /// mentions in wall metadata / workflow events into display-friendly
    /// chips. Returns at most `ids.len()` rows — any missing IDs (deleted,
    /// not-visible-to-this-user, wrong tenant) are silently dropped and
    /// surface as a "lookup miss" fallback in the UI.
    ///
    /// The visibility clause mirrors `list` / `count`: public cases, cases
    /// the user created or is assigned to, or group-shared cases where the
    /// user is in the sharing group.
    pub async fn list_linked_case_refs(
        &self,
        ids: &[Uuid],
        user_id: Uuid,
    ) -> Result<Vec<crate::models::case::LinkedCaseRef>, CaseRepositoryError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let rows = sqlx::query_as::<_, crate::models::case::LinkedCaseRef>(
            r#"
            SELECT c.id, c.case_number, c.title, c.status, c.severity
              FROM cases c
             WHERE c.id = ANY($1)
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
            "#,
        )
        .bind(ids)
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows)
    }

    /// List cases with filters (with visibility filtering for user)
    pub async fn list(
        &self,
        filter: &CaseFilter,
        user_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<CaseWithDetails>, CaseRepositoryError> {
        let status_filter: Option<Vec<String>> = filter
            .status
            .as_ref()
            .map(|statuses| statuses.iter().map(|s| s.to_string()).collect());

        let severity_filter: Option<Vec<String>> = filter.severity.as_ref().map(|severities| {
            severities
                .iter()
                .map(|s| format!("{:?}", s).to_lowercase())
                .collect()
        });

        let visibility_filter = filter.visibility.clone();
        let assigned_groups_filter = filter.assigned_groups.clone();

        // NAN-1093: ORDER BY varies by sort variant — assembled in Rust so
        // each variant gets a static, planner-friendly clause (no big CASE
        // tree that the planner can't index). `user_id` is bound as $9 and
        // referenced inline in the `mine_first` ordering.
        let order_by = build_order_by(filter.sort, filter.sla_targets.as_ref());

        // Query with visibility filtering using EXISTS for group membership check
        // This avoids DISTINCT which has issues with ORDER BY expressions.
        //
        // NAN-420: a LEFT JOIN LATERAL on `case_handoffs` pulls the most
        // recent pending handoff per case in a single query (no N+1 fan-out
        // across the list). The nested LEFT JOIN on `users` resolves the
        // recipient's display name so the list row can render "handoff to
        // Riley Chen" without a second lookup.
        let sql = format!(
            r#"
            SELECT
                c.id, c.case_number, c.title, c.description, c.severity, c.status,
                c.disposition, c.priority, c.assigned_to, c.assigned_at,
                c.assigned_group, c.assigned_group_at,
                c.ai_summary, c.grouping_type, c.mitre_tactics, c.mitre_techniques,
                c.created_at, c.updated_at, c.first_activity_at, c.last_activity_at,
                c.visibility, c.created_by,
                c.first_response_at, c.triage_completed_at,
                c.close_reason, c.pending_kind, c.pending_target, c.pending_since,
                c.incident_id,
                inc.incident_number as incident_number,
                inc.title as incident_title,
                inc.severity as incident_severity,
                inc.status as incident_status,
                inc.source as incident_source,
                creator.name as creator_name,
                COALESCE(ac.alert_count, 0) as alert_count,
                COALESCE(ec.entity_count, 0) as entity_count,
                assignee.name as assignee_name,
                assigned_grp.name as assigned_group_name,
                ah.id as active_handoff_id,
                ah.target_user_id as active_handoff_target_user_id,
                ah_to_user.name as active_handoff_target_user_name,
                ah.target_label as active_handoff_target_label,
                ah.state as active_handoff_state,
                ah.created_at as active_handoff_created_at
            FROM cases c
            LEFT JOIN users assignee ON c.assigned_to = assignee.id
            LEFT JOIN users creator ON c.created_by = creator.id
            LEFT JOIN groups assigned_grp ON c.assigned_group = assigned_grp.id
            LEFT JOIN incidents inc ON inc.id = c.incident_id
            LEFT JOIN (
                SELECT case_id, COUNT(*) as alert_count
                FROM case_alerts
                GROUP BY case_id
            ) ac ON ac.case_id = c.id
            LEFT JOIN (
                SELECT case_id, COUNT(*) as entity_count
                FROM case_entities
                GROUP BY case_id
            ) ec ON ec.case_id = c.id
            LEFT JOIN LATERAL (
                SELECT h.id, h.target_user_id, h.target_label, h.state, h.created_at
                FROM case_handoffs h
                WHERE h.case_id = c.id
                  AND h.state = 'pending'
                ORDER BY h.created_at DESC
                LIMIT 1
            ) ah ON true
            LEFT JOIN users ah_to_user ON ah.target_user_id = ah_to_user.id
            WHERE ($1::text[] IS NULL OR c.status = ANY($1))
              AND ($2::text[] IS NULL OR c.severity = ANY($2))
              AND ($3::uuid IS NULL OR c.assigned_to = $3)
              AND ($4::text IS NULL OR c.title ILIKE '%' || $4 || '%' OR c.description ILIKE '%' || $4 || '%')
              AND ($5::timestamptz IS NULL OR c.created_at >= $5)
              AND ($6::timestamptz IS NULL OR c.created_at <= $6)
              AND ($10::text[] IS NULL OR c.visibility = ANY($10))
              AND ($11::uuid IS NULL OR c.assigned_group = $11)
              -- NAN-1093: multi-group filter for the Escalations tab.
              -- `NULL` means "filter disabled". An empty array means
              -- "match nothing" — keeps semantics in lock-step with the
              -- `inbox-counts` aggregation, which treats `= ANY('{{}}')`
              -- as FALSE. An analyst with zero groups gets an empty
              -- Escalations tab from both endpoints.
              AND ($13::uuid[] IS NULL OR c.assigned_group = ANY($13))
              -- NAN-1093: incident_id NULL / NOT NULL gate. Used to keep
              -- the inbox's loose list and incident summary in sync.
              AND ($14::bool IS NULL
                   OR ($14 = TRUE AND c.incident_id IS NULL)
                   OR ($14 = FALSE AND c.incident_id IS NOT NULL))
              -- NAN-1074: Free-text mode. EXISTS subquery keeps the row set
              -- de-duplicated without DISTINCT (and avoids the join-induced
              -- row blowup for cases with many alerts). Cast matched_events
              -- to text for an ILIKE against the serialised JSON — good
              -- enough for hunting; full FTS lands in a follow-up.
              AND ($12::text IS NULL OR (
                  c.title ILIKE '%' || $12 || '%'
                  OR c.description ILIKE '%' || $12 || '%'
                  OR EXISTS (
                      -- NAN-1075: time-bound the alerts side too — `$5` is
                      -- the same created_after filtering the case rows.
                      -- NAN-1076: rule name lives on detection_rules.name,
                      -- not on alerts. LEFT JOIN so an alert with a missing
                      -- rule (rare orphan) still matches via matched_events.
                      SELECT 1 FROM case_alerts ca
                      JOIN alerts a ON a.id = ca.alert_id
                      LEFT JOIN detection_rules r ON r.id = a.rule_id
                      WHERE ca.case_id = c.id
                        AND ($5::timestamptz IS NULL OR a.created_at >= $5)
                        AND (
                            (r.name IS NOT NULL AND r.name ILIKE '%' || $12 || '%')
                            OR a.matched_events::text ILIKE '%' || $12 || '%'
                        )
                  )
              ))
              AND (
                  c.visibility = 'public'
                  OR c.created_by = $9
                  OR c.assigned_to = $9
                  OR (c.visibility = 'group' AND EXISTS (
                      SELECT 1 FROM case_groups cg
                      JOIN user_groups ug ON ug.group_id = cg.group_id
                      WHERE cg.case_id = c.id AND ug.user_id = $9
                  ))
              )
            -- NAN-1093: ORDER BY is built in Rust per `CaseFilter::sort`.
            -- Default (`Newest`) preserves the NAN-1057 recency-first ordering.
            {order_by}
            LIMIT $7 OFFSET $8
            "#,
            order_by = order_by,
        );

        let rows = sqlx::query_as::<_, CaseWithDetailsRow>(&sql)
            .bind(&status_filter)
            .bind(&severity_filter)
            .bind(filter.assigned_to)
            .bind(&filter.search)
            .bind(filter.created_after)
            .bind(filter.created_before)
            .bind(limit)
            .bind(offset)
            .bind(user_id)
            .bind(&visibility_filter)
            .bind(filter.assigned_group)
            .bind(&filter.free_text)
            .bind(&assigned_groups_filter)
            .bind(filter.incident_id_is_null)
            .fetch_all(&self.pool)
            .await?;

        // Convert rows to CaseWithDetails with shared_groups
        let mut results = Vec::with_capacity(rows.len());
        for row in rows {
            let shared_groups = self.get_shared_groups(row.id).await?;
            let incident = build_incident_summary(&row);
            let pending_state = build_pending_state(&row);
            let active_handoff = build_active_handoff(&row);
            results.push(CaseWithDetails {
                id: row.id,
                case_number: row.case_number,
                title: row.title,
                description: row.description,
                severity: row.severity,
                status: row.status,
                disposition: row.disposition,
                priority: row.priority,
                assigned_to: row.assigned_to,
                assigned_at: row.assigned_at,
                assigned_group: row.assigned_group,
                assigned_group_at: row.assigned_group_at,
                ai_summary: row.ai_summary,
                grouping_type: row.grouping_type,
                mitre_tactics: row.mitre_tactics,
                mitre_techniques: row.mitre_techniques,
                created_at: row.created_at,
                updated_at: row.updated_at,
                first_activity_at: row.first_activity_at,
                last_activity_at: row.last_activity_at,
                visibility: row.visibility,
                created_by: row.created_by,
                creator_name: row.creator_name,
                shared_groups,
                is_creator: row.created_by == Some(user_id),
                first_response_at: row.first_response_at,
                triage_completed_at: row.triage_completed_at,
                alert_count: row.alert_count,
                entity_count: row.entity_count,
                assignee_name: row.assignee_name,
                assigned_group_name: row.assigned_group_name,
                close_reason: row.close_reason,
                pending_kind: row.pending_kind,
                pending_target: row.pending_target,
                pending_since: row.pending_since,
                incident_id: row.incident_id,
                incident,
                pending_state,
                active_handoff,
                // Collab-presence is NOT persisted — it's stamped onto the
                // response by the service layer from the in-memory presence
                // tracker. Default to zero here.
                collab_presence: crate::models::case::CollabPresenceSummary::default(),
            });
        }

        Ok(results)
    }

    /// Count cases matching filters (with visibility filtering for user)
    pub async fn count(
        &self,
        filter: &CaseFilter,
        user_id: Uuid,
    ) -> Result<i64, CaseRepositoryError> {
        let status_filter: Option<Vec<String>> = filter
            .status
            .as_ref()
            .map(|statuses| statuses.iter().map(|s| s.to_string()).collect());

        let severity_filter: Option<Vec<String>> = filter.severity.as_ref().map(|severities| {
            severities
                .iter()
                .map(|s| format!("{:?}", s).to_lowercase())
                .collect()
        });

        let visibility_filter = filter.visibility.clone();
        let assigned_groups_filter = filter.assigned_groups.clone();

        let count: (i64,) = sqlx::query_as(
            r#"
            SELECT COUNT(DISTINCT c.id)
            FROM cases c
            WHERE ($1::text[] IS NULL OR c.status = ANY($1))
              AND ($2::text[] IS NULL OR c.severity = ANY($2))
              AND ($3::uuid IS NULL OR c.assigned_to = $3)
              AND ($4::text IS NULL OR c.title ILIKE '%' || $4 || '%' OR c.description ILIKE '%' || $4 || '%')
              AND ($5::timestamptz IS NULL OR c.created_at >= $5)
              AND ($6::timestamptz IS NULL OR c.created_at <= $6)
              AND ($8::text[] IS NULL OR c.visibility = ANY($8))
              AND ($9::uuid IS NULL OR c.assigned_group = $9)
              -- NAN-1093: multi-group filter (Escalations tab). See
              -- `list()` for the empty-array semantics.
              AND ($11::uuid[] IS NULL OR c.assigned_group = ANY($11))
              -- NAN-1093: incident_id NULL / NOT NULL gate.
              AND ($12::bool IS NULL
                   OR ($12 = TRUE AND c.incident_id IS NULL)
                   OR ($12 = FALSE AND c.incident_id IS NOT NULL))
              -- NAN-1074: free-text mode — same predicate as list().
              AND ($10::text IS NULL OR (
                  c.title ILIKE '%' || $10 || '%'
                  OR c.description ILIKE '%' || $10 || '%'
                  OR EXISTS (
                      -- NAN-1075 / NAN-1076 — see list() for context.
                      SELECT 1 FROM case_alerts ca
                      JOIN alerts a ON a.id = ca.alert_id
                      LEFT JOIN detection_rules r ON r.id = a.rule_id
                      WHERE ca.case_id = c.id
                        AND ($5::timestamptz IS NULL OR a.created_at >= $5)
                        AND (
                            (r.name IS NOT NULL AND r.name ILIKE '%' || $10 || '%')
                            OR a.matched_events::text ILIKE '%' || $10 || '%'
                        )
                  )
              ))
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
            "#,
        )
        .bind(&status_filter)
        .bind(&severity_filter)
        .bind(filter.assigned_to)
        .bind(&filter.search)
        .bind(filter.created_after)
        .bind(filter.created_before)
        .bind(user_id)
        .bind(&visibility_filter)
        .bind(filter.assigned_group)
        .bind(&filter.free_text)
        .bind(&assigned_groups_filter)
        .bind(filter.incident_id_is_null)
        .fetch_one(&self.pool)
        .await?;

        Ok(count.0)
    }

    /// List cases assigned to or mentioning a specific user (for My Cases)
    pub async fn list_my_cases(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<CaseSummary>, CaseRepositoryError> {
        // Convert UUID to string for JSONB comparison
        let user_id_str = user_id.to_string();

        let results = sqlx::query_as::<_, CaseSummary>(
            r#"
            SELECT
                c.id, c.case_number, c.title, c.severity, c.status,
                COALESCE(ac.alert_count, 0) as alert_count,
                c.created_at, c.last_activity_at
            FROM cases c
            LEFT JOIN (
                SELECT case_id, COUNT(*) as alert_count
                FROM case_alerts
                GROUP BY case_id
            ) ac ON ac.case_id = c.id
            WHERE (
                c.assigned_to = $1
                OR c.id IN (
                    SELECT DISTINCT case_id
                    FROM case_wall
                    WHERE entry_type = 'comment'
                      AND metadata->'mentioned_user_ids' @> to_jsonb($2::text)
                )
            )
              AND c.status NOT IN ('resolved', 'closed')
            ORDER BY
                CASE c.severity
                    WHEN 'critical' THEN 1
                    WHEN 'high' THEN 2
                    WHEN 'medium' THEN 3
                    WHEN 'low' THEN 4
                    ELSE 5
                END,
                c.priority DESC,
                c.created_at DESC
            LIMIT $3
            "#,
        )
        .bind(user_id)
        .bind(&user_id_str)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Update a case
    pub async fn update(&self, id: Uuid, update: &UpdateCase) -> Result<Case, CaseRepositoryError> {
        let severity_str = update
            .severity
            .as_ref()
            .map(|s| format!("{:?}", s).to_lowercase());
        let status_str = update.status.as_ref().map(|s| s.to_string());
        let disposition_str = update
            .disposition
            .as_ref()
            .map(|d| format!("{:?}", d).to_lowercase());

        let result = sqlx::query_as::<_, Case>(
            r#"
            UPDATE cases SET
                title = COALESCE($2, title),
                description = COALESCE($3, description),
                severity = COALESCE($4, severity),
                status = COALESCE($5, status),
                disposition = COALESCE($6, disposition),
                priority = COALESCE($7, priority),
                ai_summary = COALESCE($8, ai_summary),
                ai_recommendations = COALESCE($9, ai_recommendations),
                ai_summary_generated_at = CASE WHEN $8 IS NOT NULL THEN NOW() ELSE ai_summary_generated_at END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&update.title)
        .bind(&update.description)
        .bind(&severity_str)
        .bind(&status_str)
        .bind(&disposition_str)
        .bind(update.priority)
        .bind(&update.ai_summary)
        .bind(&update.ai_recommendations)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Assign a case to a user and/or group.
    ///
    /// NAN-1069: wall-entry emission lives at the caller (`assign_case` in the
    /// lifecycle service) so it can be enriched with resolved names and
    /// suppressed entirely from contexts like `escalate_case`, which write
    /// their own richer `action_taken` row. Mirrors the convention already
    /// documented on `bulk_assign`.
    pub async fn assign(&self, id: Uuid, assign: &AssignCase) -> Result<Case, CaseRepositoryError> {
        let result = sqlx::query_as::<_, Case>(
            r#"
            UPDATE cases SET
                assigned_to = $2,
                assigned_at = CASE WHEN $2 IS NOT NULL THEN NOW() ELSE NULL END,
                assigned_group = $3,
                assigned_group_at = CASE WHEN $3 IS NOT NULL THEN NOW() ELSE NULL END,
                first_response_at = CASE WHEN first_response_at IS NULL AND ($2 IS NOT NULL OR $3 IS NOT NULL) THEN NOW() ELSE first_response_at END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(assign.assigned_to)
        .bind(assign.assigned_group)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Bulk-assign cases in a single transaction (NAN-421).
    ///
    /// Atomically updates `assigned_to` / `assigned_group` on every case whose
    /// id appears in `ids`. Returns the ids that matched. Cases that don't
    /// match (already deleted, typo'd typeid, visibility-gated away) are
    /// simply missing from the returned vec — the caller surfaces those as
    /// per-case failures.
    ///
    /// Wall entries + audit events are NOT written here. The caller iterates
    /// the returned ids and writes those side-effects — mirroring the single-
    /// case `assign()` path but keeping the bulk UPDATE atomic.
    pub async fn bulk_assign(
        &self,
        ids: &[Uuid],
        assigned_to: Option<Uuid>,
        assigned_group: Option<Uuid>,
    ) -> Result<Vec<Case>, CaseRepositoryError> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }

        // One atomic UPDATE. `assigned_at` / `assigned_group_at` only set when
        // the respective fk becomes non-null (matches single-case `assign()`).
        // `first_response_at` only flips the first time an assignee lands on
        // the case (again, matches single-case `assign()`).
        let updated = sqlx::query_as::<_, Case>(
            r#"
            UPDATE cases SET
                assigned_to = $1,
                assigned_at = CASE WHEN $1 IS NOT NULL THEN NOW() ELSE NULL END,
                assigned_group = $2,
                assigned_group_at = CASE WHEN $2 IS NOT NULL THEN NOW() ELSE NULL END,
                first_response_at = CASE WHEN first_response_at IS NULL AND ($1 IS NOT NULL OR $2 IS NOT NULL) THEN NOW() ELSE first_response_at END,
                updated_at = NOW()
            WHERE id = ANY($3)
            RETURNING *
            "#,
        )
        .bind(assigned_to)
        .bind(assigned_group)
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;

        Ok(updated)
    }

    /// Change case status
    pub async fn change_status(
        &self,
        id: Uuid,
        change: &ChangeCaseStatus,
    ) -> Result<Case, CaseRepositoryError> {
        let status_str = change.status.to_string();
        let disposition_str = change.disposition.as_ref().map(|d| {
            match d {
                CaseDisposition::TruePositive => "true_positive",
                CaseDisposition::FalsePositive => "false_positive",
                CaseDisposition::Benign => "benign",
                CaseDisposition::Inconclusive => "inconclusive",
                CaseDisposition::Merged => "merged",
            }
            .to_string()
        });

        let result = sqlx::query_as::<_, Case>(
            r#"
            UPDATE cases SET
                status = $2,
                disposition = COALESCE($3, disposition),
                resolved_at = CASE WHEN $2 = 'resolved' THEN NOW() ELSE resolved_at END,
                resolved_by = CASE WHEN $2 = 'resolved' THEN $4 ELSE resolved_by END,
                closed_at = CASE WHEN $2 = 'closed' THEN NOW() ELSE closed_at END,
                closed_by = CASE WHEN $2 = 'closed' THEN $4 ELSE closed_by END,
                first_response_at = CASE WHEN first_response_at IS NULL AND status = 'open' AND $2 != 'open' THEN NOW() ELSE first_response_at END,
                triage_completed_at = CASE WHEN triage_completed_at IS NULL AND $2 = 'in_progress' THEN NOW() ELSE triage_completed_at END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(&status_str)
        .bind(&disposition_str)
        .bind(change.changed_by)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::NotFound(id))?;

        // Add wall entry for status change
        let metadata = serde_json::json!({
            "status": status_str,
            "disposition": disposition_str,
            "changed_by": change.changed_by,
        });
        self.add_wall_entry_internal(id, "status_change", None, metadata, Some(change.changed_by))
            .await?;

        Ok(result)
    }

    // ==================== WORKFLOW COLUMN SETTERS (NAN-415) ====================

    /// Set pending state on a case (kind + optional target).
    pub async fn set_pending(
        &self,
        id: Uuid,
        kind: &str,
        target: Option<&str>,
    ) -> Result<(), CaseRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE cases SET
                pending_kind = $2,
                pending_target = $3,
                pending_since = NOW(),
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(kind)
        .bind(target)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(CaseRepositoryError::NotFound(id));
        }
        Ok(())
    }

    /// Clear pending state on a case.
    pub async fn clear_pending(&self, id: Uuid) -> Result<(), CaseRepositoryError> {
        let result = sqlx::query(
            r#"
            UPDATE cases SET
                pending_kind = NULL,
                pending_target = NULL,
                pending_since = NULL,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(CaseRepositoryError::NotFound(id));
        }
        Ok(())
    }

    /// Set the close_reason column (workflow resolution key: fp/tp/btp/dup/etc).
    pub async fn set_close_reason(
        &self,
        id: Uuid,
        reason: &str,
    ) -> Result<(), CaseRepositoryError> {
        let result = sqlx::query(
            r#"UPDATE cases SET close_reason = $2, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(id)
        .bind(reason)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(CaseRepositoryError::NotFound(id));
        }
        Ok(())
    }

    /// Clear the close_reason column (used on reopen).
    pub async fn clear_close_reason(&self, id: Uuid) -> Result<(), CaseRepositoryError> {
        let result = sqlx::query(
            r#"UPDATE cases SET close_reason = NULL, updated_at = NOW() WHERE id = $1"#,
        )
        .bind(id)
        .execute(&self.pool)
        .await?;

        if result.rows_affected() == 0 {
            return Err(CaseRepositoryError::NotFound(id));
        }
        Ok(())
    }

    /// Delete a case
    pub async fn delete(&self, id: Uuid) -> Result<(), CaseRepositoryError> {
        let result = sqlx::query(r#"DELETE FROM cases WHERE id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(CaseRepositoryError::NotFound(id));
        }

        Ok(())
    }

    /// Get case statistics filtered by visibility for the requesting user.
    ///
    /// Aggregates are computed only over cases the user is permitted to view —
    /// public, owned, assigned, or shared via group membership. Mirrors the
    /// predicate used by `list` / `count` so the stats surface cannot leak
    /// existence or shape of cases the caller cannot read (NAN-684).
    ///
    /// `exclude_ids` lets the handler layer subtract resources tracked for
    /// `demo_analyst` session isolation. Pass an empty slice for normal users.
    pub async fn get_stats(
        &self,
        user_id: Uuid,
        exclude_ids: &[Uuid],
    ) -> Result<CaseStats, CaseRepositoryError> {
        // Visibility predicate uses $1 = user_id, $2 = exclude_ids[].
        // sqlx encodes an empty slice as a non-NULL empty Postgres array,
        // so `NOT (c.id = ANY($2))` evaluates TRUE when the exclude is empty.
        let predicate = r#"
            (
                c.visibility = 'public'
                OR c.created_by = $1
                OR c.assigned_to = $1
                OR (c.visibility = 'group' AND EXISTS (
                    SELECT 1 FROM case_groups cg
                    JOIN user_groups ug ON ug.group_id = cg.group_id
                    WHERE cg.case_id = c.id AND ug.user_id = $1
                ))
            )
            AND NOT (c.id = ANY($2))
        "#;

        let counts_sql = format!(
            r#"SELECT c.status, COUNT(*) FROM cases c WHERE {predicate} GROUP BY c.status"#
        );
        let counts: Vec<(String, i64)> = sqlx::query_as(&counts_sql)
            .bind(user_id)
            .bind(exclude_ids)
            .fetch_all(&self.pool)
            .await?;

        let severity_sql = format!(
            r#"
            SELECT c.severity, COUNT(*)
            FROM cases c
            WHERE c.status NOT IN ('resolved', 'closed')
              AND {predicate}
            GROUP BY c.severity
            "#
        );
        let severity_counts: Vec<(String, i64)> = sqlx::query_as(&severity_sql)
            .bind(user_id)
            .bind(exclude_ids)
            .fetch_all(&self.pool)
            .await?;

        let avg_sql = format!(
            r#"
            SELECT AVG(EXTRACT(EPOCH FROM (c.resolved_at - c.created_at)) / 3600)::float
            FROM cases c
            WHERE c.resolved_at IS NOT NULL
              AND c.created_at > NOW() - INTERVAL '30 days'
              AND {predicate}
            "#
        );
        let avg_resolution: Option<f64> = sqlx::query_scalar(&avg_sql)
            .bind(user_id)
            .bind(exclude_ids)
            .fetch_one(&self.pool)
            .await?;

        let mut stats = CaseStats {
            total: 0,
            open: 0,
            in_progress: 0,
            pending: 0,
            resolved: 0,
            closed: 0,
            by_severity: std::collections::HashMap::new(),
            avg_resolution_time_hours: avg_resolution,
        };

        for (status, count) in counts {
            stats.total += count;
            match status.as_str() {
                "open" => stats.open = count,
                "in_progress" => stats.in_progress = count,
                "pending" => stats.pending = count,
                "resolved" => stats.resolved = count,
                "closed" => stats.closed = count,
                _ => {}
            }
        }

        for (severity, count) in severity_counts {
            stats.by_severity.insert(severity, count);
        }

        Ok(stats)
    }

    /// Get stats for a single case
    pub(super) async fn get_case_stats_single(
        &self,
        case_id: Uuid,
    ) -> Result<CaseResponseStats, CaseRepositoryError> {
        let counts: (i64, i64, i64, Option<DateTime<Utc>>) = sqlx::query_as(
            r#"
            SELECT
                (SELECT COUNT(*) FROM case_alerts WHERE case_id = $1),
                (SELECT COUNT(*) FROM case_entities WHERE case_id = $1),
                (SELECT COUNT(*) FROM case_wall WHERE case_id = $1 AND entry_type = 'comment'),
                (SELECT created_at FROM cases WHERE id = $1)
            "#,
        )
        .bind(case_id)
        .fetch_one(&self.pool)
        .await?;

        let time_open_hours = counts
            .3
            .map(|created| (Utc::now() - created).num_hours() as f64);

        Ok(CaseResponseStats {
            alert_count: counts.0,
            entity_count: counts.1,
            comment_count: counts.2,
            time_open_hours,
        })
    }
}

/// Reconstruct an `IncidentSummary` from the denormalized columns pulled by
/// the LEFT JOIN on `incidents`. Returns `None` when the case has no parent
/// incident (all `incident_*` columns will be NULL in that case).
pub(super) fn build_incident_summary(
    row: &CaseWithDetailsRow,
) -> Option<crate::models::incident::IncidentSummary> {
    let id = row.incident_id?;
    Some(crate::models::incident::IncidentSummary {
        id,
        incident_number: row.incident_number.unwrap_or_default(),
        title: row.incident_title.clone().unwrap_or_default(),
        severity: row.incident_severity.clone().unwrap_or_default(),
        status: row.incident_status.clone().unwrap_or_default(),
        source: row.incident_source.clone().unwrap_or_default(),
    })
}

/// Build a [`CasePendingState`] from the `cases.pending_*` columns already
/// on the row. Kept next to `build_incident_summary` so both list-row
/// hydration helpers live together (NAN-420).
fn build_pending_state(
    row: &CaseWithDetailsRow,
) -> Option<crate::models::case::CasePendingState> {
    let kind = row.pending_kind.clone()?;
    let since = row.pending_since?;
    Some(crate::models::case::CasePendingState {
        kind,
        target: row.pending_target.clone(),
        since,
    })
}

/// Build an [`ActiveHandoffSummary`] from the lateral-subquery columns.
/// Returns `None` when the case has no open handoff (`active_handoff_id`
/// is NULL).
fn build_active_handoff(
    row: &CaseWithDetailsRow,
) -> Option<crate::models::case::ActiveHandoffSummary> {
    let id = row.active_handoff_id?;
    Some(crate::models::case::ActiveHandoffSummary {
        id,
        to_user_id: row.active_handoff_target_user_id,
        to_user_name: row.active_handoff_target_user_name.clone(),
        target_label: row.active_handoff_target_label.clone().unwrap_or_default(),
        initiated_at: row.active_handoff_created_at.unwrap_or_else(Utc::now),
        state: row
            .active_handoff_state
            .clone()
            .unwrap_or_else(|| "pending".to_string()),
    })
}
