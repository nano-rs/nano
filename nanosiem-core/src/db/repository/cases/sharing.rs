// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case sharing, access control, merging, and entity-based lookups

use uuid::Uuid;

use super::{
    Case, CaseAffectedUser, CaseAlertDetail, CaseRepository, CaseRepositoryError, CaseShareResult,
    CaseSummary, CaseWithDetails, CaseWithDetailsRow, ShareCaseRequest, SharedGroup,
};

impl CaseRepository {
    // ==================== SHARING ====================

    /// Lightweight visibility probe — answers "can this user see this case?"
    /// without loading the full row, handoffs, alert/entity counts, etc.
    /// Used on hot paths like the presence heartbeat where we only need the
    /// yes/no gate, not the payload.
    pub async fn can_view_case(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<bool, CaseRepositoryError> {
        let exists: Option<(bool,)> = sqlx::query_as(
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
        .bind(id)
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(exists.is_some())
    }

    /// Find a case by ID with access check
    pub async fn find_by_id_for_user(
        &self,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<CaseWithDetails, CaseRepositoryError> {
        // Get the case with creator info
        // NAN-420: mirrors the list query's handoff lateral subquery so both
        // paths populate the same CaseWithDetailsRow shape.
        let row = sqlx::query_as::<_, CaseWithDetailsRow>(
            r#"
            SELECT
                c.id, c.case_number, c.title, c.description, c.severity, c.status,
                c.disposition, c.priority, c.assigned_to, c.assigned_at,
                c.assigned_group, c.assigned_group_at,
                c.ai_summary,
                c.ai_disposition, c.ai_confidence, c.ai_recommended_action,
                c.ai_key_evidence, c.ai_triaged_at,
                c.needs_review, c.needs_review_reason, c.needs_review_at,
                c.ai_closed,
                c.grouping_type, c.mitre_tactics, c.mitre_techniques,
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
            WHERE c.id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::NotFound(id))?;

        // Convert to Case for access check
        let case = Case {
            id: row.id,
            case_number: row.case_number,
            title: row.title.clone(),
            description: row.description.clone(),
            severity: row.severity.clone(),
            status: row.status.clone(),
            disposition: row.disposition.clone(),
            priority: row.priority,
            assigned_to: row.assigned_to,
            assigned_at: row.assigned_at,
            assigned_group: row.assigned_group,
            assigned_group_at: row.assigned_group_at,
            ai_summary: row.ai_summary.clone(),
            ai_recommendations: None,
            ai_summary_generated_at: None,
            // ai_* verdict columns aren't needed for the access-check synthetic
            // Case (NAN-1251); this row shape doesn't select them.
            ai_disposition: None,
            ai_confidence: None,
            ai_recommended_action: None,
            ai_key_evidence: None,
            ai_triaged_at: None,
            needs_review: false,
            needs_review_reason: None,
            needs_review_at: None,
            ai_closed: false,
            grouping_key: None,
            grouping_type: row.grouping_type.clone(),
            mitre_tactics: row.mitre_tactics.clone(),
            mitre_techniques: row.mitre_techniques.clone(),
            created_at: row.created_at,
            updated_at: row.updated_at,
            first_activity_at: row.first_activity_at,
            last_activity_at: row.last_activity_at,
            resolved_at: None,
            resolved_by: None,
            closed_at: None,
            closed_by: None,
            first_response_at: row.first_response_at,
            triage_completed_at: row.triage_completed_at,
            visibility: row.visibility.clone(),
            created_by: row.created_by,
            close_reason: row.close_reason.clone(),
            pending_kind: row.pending_kind.clone(),
            pending_target: row.pending_target.clone(),
            pending_since: row.pending_since,
        };

        // Check access
        let has_access = self.check_user_access(&case, user_id).await?;
        if !has_access {
            return Err(CaseRepositoryError::AccessDenied);
        }

        // Get shared groups
        let shared_groups = self.get_shared_groups(id).await?;
        let incident = super::crud::build_incident_summary(&row);
        // Rebuild pending-state + active-handoff summaries from the same
        // row shape the list path uses. Keeps list + detail in lockstep.
        let pending_state = row.pending_kind.clone().and_then(|kind| {
            row.pending_since.map(|since| crate::models::case::CasePendingState {
                kind,
                target: row.pending_target.clone(),
                since,
            })
        });
        let active_handoff = row.active_handoff_id.map(|hid| {
            crate::models::case::ActiveHandoffSummary {
                id: hid,
                to_user_id: row.active_handoff_target_user_id,
                to_user_name: row.active_handoff_target_user_name.clone(),
                target_label: row.active_handoff_target_label.clone().unwrap_or_default(),
                initiated_at: row.active_handoff_created_at.unwrap_or_else(chrono::Utc::now),
                state: row
                    .active_handoff_state
                    .clone()
                    .unwrap_or_else(|| "pending".to_string()),
            }
        });

        Ok(CaseWithDetails {
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
            ai_disposition: row.ai_disposition,
            ai_confidence: row.ai_confidence,
            ai_recommended_action: row.ai_recommended_action,
            ai_key_evidence: row.ai_key_evidence,
            ai_triaged_at: row.ai_triaged_at,
            needs_review: row.needs_review,
            needs_review_reason: row.needs_review_reason,
            needs_review_at: row.needs_review_at,
            ai_closed: row.ai_closed,
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
            collab_presence: crate::models::case::CollabPresenceSummary::default(),
        })
    }

    /// Check if a user has access to a case
    pub async fn check_user_access(
        &self,
        case: &Case,
        user_id: Uuid,
    ) -> Result<bool, CaseRepositoryError> {
        // Creator always has access
        if case.created_by == Some(user_id) {
            return Ok(true);
        }

        // Assigned user always has access
        if case.assigned_to == Some(user_id) {
            return Ok(true);
        }

        // Public cases are visible to all
        if case.visibility == "public" {
            return Ok(true);
        }

        // For group visibility, check if user is in any shared group
        if case.visibility == "group" {
            let count: (i64,) = sqlx::query_as(
                r#"
                SELECT COUNT(*)
                FROM case_groups cg
                JOIN user_groups ug ON ug.group_id = cg.group_id
                WHERE cg.case_id = $1 AND ug.user_id = $2
                "#,
            )
            .bind(case.id)
            .bind(user_id)
            .fetch_one(&self.pool)
            .await?;

            return Ok(count.0 > 0);
        }

        // Private cases - only creator or assigned user has access
        Ok(false)
    }

    /// Get shared groups for a case
    pub async fn get_shared_groups(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<SharedGroup>, CaseRepositoryError> {
        let groups = sqlx::query_as::<_, (Uuid, String)>(
            r#"
            SELECT g.id, g.name
            FROM groups g
            JOIN case_groups cg ON cg.group_id = g.id
            WHERE cg.case_id = $1
            "#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(groups
            .into_iter()
            .map(|(id, name)| SharedGroup { id, name })
            .collect())
    }

    /// Get users in the specified groups (excluding a specific user, e.g., the creator)
    async fn get_users_in_groups(
        &self,
        group_ids: &[Uuid],
        exclude_user_id: Uuid,
    ) -> Result<Vec<CaseAffectedUser>, CaseRepositoryError> {
        if group_ids.is_empty() {
            return Ok(Vec::new());
        }

        let users = sqlx::query_as::<_, (Uuid, String, String)>(
            r#"
            SELECT DISTINCT u.id, u.name, u.email
            FROM users u
            JOIN user_groups ug ON ug.user_id = u.id
            WHERE ug.group_id = ANY($1) AND u.id != $2
            "#,
        )
        .bind(group_ids)
        .bind(exclude_user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(users
            .into_iter()
            .map(|(user_id, user_name, user_email)| CaseAffectedUser {
                user_id,
                user_name,
                user_email,
            })
            .collect())
    }

    /// Share a case (change visibility and groups)
    /// Returns the updated case and a list of users who lost access
    pub async fn share(
        &self,
        id: Uuid,
        request: &ShareCaseRequest,
        user_id: Uuid,
    ) -> Result<CaseShareResult, CaseRepositoryError> {
        // Get existing case to check ownership
        let existing = self.find_by_id(id).await?;

        // Only creator can share (admin check is done in service layer)
        if existing.created_by != Some(user_id) {
            return Err(CaseRepositoryError::AccessDenied);
        }

        // Get current groups BEFORE the change (to track who loses access)
        let old_groups = self.get_shared_groups(id).await?;
        let old_group_ids: std::collections::HashSet<Uuid> =
            old_groups.iter().map(|g| g.id).collect();

        // Determine new group IDs
        let new_group_ids: std::collections::HashSet<Uuid> = if request.visibility == "group" {
            request
                .group_ids
                .as_ref()
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

        // Find groups that are being REMOVED (were shared, now aren't)
        let removed_group_ids: Vec<Uuid> =
            old_group_ids.difference(&new_group_ids).copied().collect();

        // Get users in removed groups who will lose access (excluding the creator)
        let users_who_lost_access = if !removed_group_ids.is_empty() {
            self.get_users_in_groups(&removed_group_ids, user_id)
                .await?
        } else {
            Vec::new()
        };

        // Update visibility
        sqlx::query(
            r#"
            UPDATE cases
            SET visibility = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&request.visibility)
        .execute(&self.pool)
        .await?;

        // Clear existing group associations
        sqlx::query(r#"DELETE FROM case_groups WHERE case_id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        // Add new group associations if visibility is 'group'
        if request.visibility == "group" {
            if let Some(ref group_ids) = request.group_ids {
                for group_id in group_ids {
                    sqlx::query(
                        r#"
                        INSERT INTO case_groups (case_id, group_id)
                        VALUES ($1, $2)
                        ON CONFLICT DO NOTHING
                        "#,
                    )
                    .bind(id)
                    .bind(group_id)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }

        // Return updated case with context and affected users
        let case = self.find_by_id_for_user(id, user_id).await?;
        Ok(CaseShareResult {
            case,
            users_who_lost_access,
        })
    }

    // ==================== CASE MERGING ====================

    /// Merge source cases into a target case
    ///
    /// This operation:
    /// 1. Moves all alerts from source cases to target case
    /// 2. Moves all entities from source cases to target case
    /// 3. Adds wall entries to both source and target noting the merge
    /// 4. Closes the source cases with a "merged" note
    ///
    /// Returns the number of alerts moved and the number of entities moved.
    pub async fn merge_cases(
        &self,
        target_case_id: Uuid,
        source_case_ids: &[Uuid],
        merged_by: Uuid,
    ) -> Result<(i64, i64), CaseRepositoryError> {
        if source_case_ids.is_empty() {
            return Ok((0, 0));
        }

        // Verify target case exists
        let target = self.find_by_id(target_case_id).await?;

        let mut total_alerts_moved = 0i64;
        let mut total_entities_moved = 0i64;

        for source_id in source_case_ids {
            // Skip if trying to merge a case into itself
            if *source_id == target_case_id {
                continue;
            }

            // Verify source case exists
            let source = self.find_by_id(*source_id).await?;

            // Move alerts from source to target
            let alerts_moved = sqlx::query_scalar::<_, i64>(
                r#"
                WITH moved AS (
                    UPDATE case_alerts
                    SET case_id = $1
                    WHERE case_id = $2
                    RETURNING 1
                )
                SELECT COUNT(*) FROM moved
                "#,
            )
            .bind(target_case_id)
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;

            total_alerts_moved += alerts_moved;

            // Update alerts table to point to target case
            sqlx::query(
                r#"
                UPDATE alerts
                SET case_id = $1
                WHERE case_id = $2
                "#,
            )
            .bind(target_case_id)
            .bind(source_id)
            .execute(&self.pool)
            .await?;

            // Move entities from source to target (upsert to handle duplicates)
            let entities_moved = sqlx::query_scalar::<_, i64>(
                r#"
                WITH source_entities AS (
                    SELECT entity_type, entity_value, is_primary, occurrence_count, first_seen_at, last_seen_at
                    FROM case_entities
                    WHERE case_id = $2
                ),
                upserted AS (
                    INSERT INTO case_entities (case_id, entity_type, entity_value, is_primary, occurrence_count, first_seen_at, last_seen_at)
                    SELECT $1, entity_type, entity_value, is_primary, occurrence_count, first_seen_at, last_seen_at
                    FROM source_entities
                    ON CONFLICT (case_id, entity_type, entity_value) DO UPDATE SET
                        occurrence_count = case_entities.occurrence_count + EXCLUDED.occurrence_count,
                        first_seen_at = LEAST(case_entities.first_seen_at, EXCLUDED.first_seen_at),
                        last_seen_at = GREATEST(case_entities.last_seen_at, EXCLUDED.last_seen_at)
                    RETURNING 1
                )
                SELECT COUNT(*) FROM upserted
                "#,
            )
            .bind(target_case_id)
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;

            total_entities_moved += entities_moved;

            // Delete original entities from source case
            sqlx::query(r#"DELETE FROM case_entities WHERE case_id = $1"#)
                .bind(source_id)
                .execute(&self.pool)
                .await?;

            // Add wall entry to source case noting the merge
            let source_metadata = serde_json::json!({
                "event_type": "case_merged",
                "merged_into_case_id": target_case_id.to_string(),
                "merged_into_case_number": target.case_number,
                "merged_by": merged_by.to_string(),
                "alerts_moved": alerts_moved,
                "entities_moved": entities_moved,
            });
            self.add_wall_entry_internal(
                *source_id,
                "system",
                Some(format!("Case merged into CASE-{}", target.case_number)),
                source_metadata,
                Some(merged_by),
            )
            .await?;

            // Add wall entry to target case noting the merge
            let target_metadata = serde_json::json!({
                "event_type": "case_merged",
                "merged_from_case_id": source_id.to_string(),
                "merged_from_case_number": source.case_number,
                "merged_by": merged_by.to_string(),
                "alerts_moved": alerts_moved,
                "entities_moved": entities_moved,
            });
            self.add_wall_entry_internal(
                target_case_id,
                "system",
                Some(format!(
                    "Merged CASE-{} into this case ({} alerts, {} entities)",
                    source.case_number, alerts_moved, entities_moved
                )),
                target_metadata,
                Some(merged_by),
            )
            .await?;

            // Close the source case
            sqlx::query(
                r#"
                UPDATE cases SET
                    status = 'closed',
                    disposition = 'merged',
                    closed_at = NOW(),
                    closed_by = $2,
                    updated_at = NOW()
                WHERE id = $1
                "#,
            )
            .bind(source_id)
            .bind(merged_by)
            .execute(&self.pool)
            .await?;
        }

        // Update target case timestamps
        sqlx::query(
            r#"
            UPDATE cases SET
                updated_at = NOW(),
                last_activity_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(target_case_id)
        .execute(&self.pool)
        .await?;

        Ok((total_alerts_moved, total_entities_moved))
    }

    /// Share a case as admin (bypasses ownership check)
    pub async fn share_as_admin(
        &self,
        id: Uuid,
        request: &ShareCaseRequest,
        admin_user_id: Uuid,
    ) -> Result<CaseShareResult, CaseRepositoryError> {
        // Get existing case
        let existing = self.find_by_id(id).await?;

        // Get the creator ID (or use admin_user_id for notifications)
        let creator_id = existing.created_by.unwrap_or(admin_user_id);

        // Get current groups BEFORE the change (to track who loses access)
        let old_groups = self.get_shared_groups(id).await?;
        let old_group_ids: std::collections::HashSet<Uuid> =
            old_groups.iter().map(|g| g.id).collect();

        // Determine new group IDs
        let new_group_ids: std::collections::HashSet<Uuid> = if request.visibility == "group" {
            request
                .group_ids
                .as_ref()
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default()
        } else {
            std::collections::HashSet::new()
        };

        // Find groups that are being REMOVED (were shared, now aren't)
        let removed_group_ids: Vec<Uuid> =
            old_group_ids.difference(&new_group_ids).copied().collect();

        // Get users in removed groups who will lose access (excluding the creator)
        let users_who_lost_access = if !removed_group_ids.is_empty() {
            self.get_users_in_groups(&removed_group_ids, creator_id)
                .await?
        } else {
            Vec::new()
        };

        // Update visibility
        sqlx::query(
            r#"
            UPDATE cases
            SET visibility = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(&request.visibility)
        .execute(&self.pool)
        .await?;

        // Clear existing group associations
        sqlx::query(r#"DELETE FROM case_groups WHERE case_id = $1"#)
            .bind(id)
            .execute(&self.pool)
            .await?;

        // Add new group associations if visibility is 'group'
        if request.visibility == "group" {
            if let Some(ref group_ids) = request.group_ids {
                for group_id in group_ids {
                    sqlx::query(
                        r#"
                        INSERT INTO case_groups (case_id, group_id)
                        VALUES ($1, $2)
                        ON CONFLICT DO NOTHING
                        "#,
                    )
                    .bind(id)
                    .bind(group_id)
                    .execute(&self.pool)
                    .await?;
                }
            }
        }

        // Return updated case with context and affected users
        let case = self.find_by_id_for_user(id, admin_user_id).await?;
        Ok(CaseShareResult {
            case,
            users_who_lost_access,
        })
    }

    /// Get recent alerts associated with an entity (via case_entities -> case_alerts -> alerts)
    pub async fn get_alerts_for_entity(
        &self,
        entity_values: &[String],
        days: i64,
    ) -> Result<Vec<CaseAlertDetail>, CaseRepositoryError> {
        if entity_values.is_empty() {
            return Ok(Vec::new());
        }

        let results = sqlx::query_as::<_, CaseAlertDetail>(
            r#"
            SELECT DISTINCT ON (a.id)
                ca.id, ca.alert_id, a.rule_id, r.name as rule_name, a.severity, a.status,
                a.disposition, a.matched_event_count, a.created_at, ca.added_at,
                ca.is_primary, t.verdict_type as triage_verdict, t.confidence as triage_confidence,
                r.risk_score as score_contribution,
                COALESCE(r.mitre_tactics, ARRAY[]::text[]) as mitre_tactics
            FROM case_entities ce
            JOIN case_alerts ca ON ca.case_id = ce.case_id
            JOIN alerts a ON ca.alert_id = a.id
            LEFT JOIN detection_rules r ON a.rule_id = r.id
            LEFT JOIN LATERAL (
                SELECT verdict_type, confidence
                FROM alert_triage_results
                WHERE alert_id = a.id AND status = 'completed'
                ORDER BY created_at DESC
                LIMIT 1
            ) t ON true
            WHERE ce.entity_value = ANY($1)
              AND a.created_at >= NOW() - make_interval(days => $2)
            ORDER BY a.id, a.created_at DESC
            LIMIT 50
            "#,
        )
        .bind(entity_values)
        .bind(days as i32)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get recent cases associated with an entity (via case_entities)
    pub async fn get_cases_for_entity(
        &self,
        entity_values: &[String],
        days: i64,
    ) -> Result<Vec<CaseSummary>, CaseRepositoryError> {
        if entity_values.is_empty() {
            return Ok(Vec::new());
        }

        let results = sqlx::query_as::<_, CaseSummary>(
            r#"
            SELECT DISTINCT ON (c.id)
                c.id, c.case_number, c.title, c.severity, c.status,
                (SELECT count(*) FROM case_alerts WHERE case_id = c.id) as alert_count,
                c.created_at, c.last_activity_at
            FROM case_entities ce
            JOIN cases c ON c.id = ce.case_id
            WHERE ce.entity_value = ANY($1)
              AND c.created_at >= NOW() - make_interval(days => $2)
            ORDER BY c.id, c.created_at DESC
            LIMIT 20
            "#,
        )
        .bind(entity_values)
        .bind(days as i32)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
