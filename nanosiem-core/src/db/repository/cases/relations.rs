// SPDX-License-Identifier: AGPL-3.0-or-later

//! Case relation operations: add relations, get related cases, find shared entities

use uuid::Uuid;

use super::{
    CaseRelation, CaseRepository, CaseRepositoryError, DuplicateCandidate, NewCaseRelation,
    RelatedCaseSummary,
};

impl CaseRepository {
    // ==================== CASE RELATIONS ====================

    /// Add a case relation
    pub async fn add_relation(
        &self,
        relation: &NewCaseRelation,
    ) -> Result<CaseRelation, CaseRepositoryError> {
        let relation_type_str = format!("{:?}", relation.relation_type).to_lowercase();

        let result = sqlx::query_as::<_, CaseRelation>(
            r#"
            INSERT INTO case_relations (
                source_case_id, target_case_id, relation_type, confidence, reason, shared_entities, created_by
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            ON CONFLICT (source_case_id, target_case_id) DO NOTHING
            RETURNING *
            "#,
        )
        .bind(relation.source_case_id)
        .bind(relation.target_case_id)
        .bind(&relation_type_str)
        .bind(relation.confidence)
        .bind(&relation.reason)
        .bind(&relation.shared_entities)
        .bind(relation.created_by)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(CaseRepositoryError::RelationAlreadyExists)?;

        Ok(result)
    }

    /// Get related cases
    pub async fn get_related_cases(
        &self,
        case_id: Uuid,
    ) -> Result<Vec<RelatedCaseSummary>, CaseRepositoryError> {
        // NAN-431: also project `cr.created_by` + `cr.reason` so the UI can
        // distinguish manual links (created_by IS NOT NULL) from
        // auto-detected ones and show the analyst-written rationale on hover.
        let results = sqlx::query_as::<_, RelatedCaseSummary>(
            r#"
            SELECT
                c.id, c.case_number, c.title, c.severity, c.status,
                cr.relation_type, cr.confidence,
                COALESCE(jsonb_array_length(cr.shared_entities), 0)::bigint as shared_entity_count,
                cr.created_by, cr.reason
            FROM case_relations cr
            JOIN cases c ON c.id = cr.target_case_id
            WHERE cr.source_case_id = $1
            UNION
            SELECT
                c.id, c.case_number, c.title, c.severity, c.status,
                cr.relation_type, cr.confidence,
                COALESCE(jsonb_array_length(cr.shared_entities), 0)::bigint as shared_entity_count,
                cr.created_by, cr.reason
            FROM case_relations cr
            JOIN cases c ON c.id = cr.source_case_id
            WHERE cr.target_case_id = $1
            ORDER BY confidence DESC NULLS LAST
            "#,
        )
        .bind(case_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Delete a manual case relation by (source, target) — NAN-431.
    ///
    /// Matches either direction since the relation is stored as a directed
    /// edge but analysts think of it as symmetric. Only rows where
    /// `created_by IS NOT NULL` are deletable: we never want analysts to
    /// remove auto-detected relations via this path (those rebuild on the
    /// next detection pass, so the UX would be flappy).
    ///
    /// Returns the number of rows deleted (0 = not found or was auto).
    pub async fn delete_manual_relation(
        &self,
        case_a: Uuid,
        case_b: Uuid,
    ) -> Result<u64, CaseRepositoryError> {
        let result = sqlx::query(
            r#"
            DELETE FROM case_relations
            WHERE ((source_case_id = $1 AND target_case_id = $2)
                OR (source_case_id = $2 AND target_case_id = $1))
              AND created_by IS NOT NULL
            "#,
        )
        .bind(case_a)
        .bind(case_b)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    /// Find duplicate-candidate cases for a subject case (NAN-421).
    ///
    /// v1 rule-based detector. Replaces the NAN-414 `grouping_key`-within-the-
    /// visible-set heuristic with a signal that persists across page limits.
    ///
    /// Algorithm (one query, three signal sources combined):
    ///
    /// 1. **Same grouping_key** (strongest — auto-grouper already thinks these
    ///    should collapse). Confidence starts at 0.80, boosted by shared
    ///    entities.
    /// 2. **Shared entities** via `case_entities` intersection. Confidence =
    ///    `shared / max(source_entity_count, 1)` capped at 0.75.
    /// 3. **Same rule + within 24h** of subject's creation. Confidence 0.45
    ///    (weak — same detection firing twice isn't necessarily a dupe).
    ///
    /// Closed + resolved cases are excluded (merging a case into a closed
    /// one is weird; analysts want live candidates).
    ///
    /// Returns up to `limit` candidates sorted by confidence desc. Typical
    /// callers pass 3 (the row hint) or 20 (the merge dialog).
    pub async fn find_duplicate_candidates(
        &self,
        case_id: Uuid,
        limit: i64,
    ) -> Result<Vec<DuplicateCandidate>, CaseRepositoryError> {
        // Subject case metadata we need for the scoring CTEs. If the case
        // doesn't exist the detector returns an empty list rather than
        // erroring — this endpoint is a best-effort enrichment, not a
        // hard-contract resource read.
        let subject: Option<(Option<String>, chrono::DateTime<chrono::Utc>, i64)> = sqlx::query_as(
            r#"
            SELECT c.grouping_key, c.created_at,
                   COALESCE((SELECT COUNT(*) FROM case_entities WHERE case_id = c.id), 0)::bigint
              FROM cases c
             WHERE c.id = $1
            "#,
        )
        .bind(case_id)
        .fetch_optional(&self.pool)
        .await?;

        let Some((grouping_key, created_at, source_entity_count)) = subject else {
            return Ok(Vec::new());
        };

        // Normalize entity count for the denominator. A case with 0 entities
        // can still have a grouping-key or same-rule match; the entity bonus
        // just becomes 0.
        let denom = source_entity_count.max(1) as f32;

        // The query pulls candidate case ids from each signal, scores each,
        // and keeps the max score per candidate. `rule_ids` for same-rule
        // detection is derived from the subject's `case_alerts` → `alerts`.
        //
        // Why not a `case_relations` join? Because relations is a separate
        // concept (already-detected related cases); we want the raw signal
        // at query time so analysts can see candidates before the auto-
        // relation job has run.
        let rows: Vec<(Uuid, i32, String, String, String, i64, f32, String)> = sqlx::query_as(
            r#"
            WITH subject_entities AS (
                SELECT entity_type, entity_value
                  FROM case_entities
                 WHERE case_id = $1
                 LIMIT 100
            ),
            subject_rules AS (
                SELECT DISTINCT a.rule_id
                  FROM case_alerts ca
                  JOIN alerts a ON a.id = ca.alert_id
                 WHERE ca.case_id = $1
                   AND a.rule_id IS NOT NULL
            ),
            -- Signal 1: shared grouping_key (strongest)
            group_matches AS (
                SELECT c.id,
                       0.80::real AS base_conf,
                       'Same grouping key'::text AS base_reason
                  FROM cases c
                 WHERE $2::text IS NOT NULL
                   AND c.grouping_key = $2
                   AND c.id <> $1
                   AND c.status NOT IN ('resolved', 'closed')
            ),
            -- Signal 2: shared entities (count-based)
            entity_matches AS (
                SELECT ce.case_id AS id,
                       COUNT(*)::bigint AS shared_count,
                       LEAST(0.75, (COUNT(*)::real / $3::real))::real AS base_conf,
                       (COUNT(*)::text || ' shared entities') AS base_reason
                  FROM subject_entities se
                  JOIN case_entities ce ON se.entity_type = ce.entity_type
                                       AND se.entity_value = ce.entity_value
                                       AND ce.case_id <> $1
                  JOIN cases c ON c.id = ce.case_id
                 WHERE c.status NOT IN ('resolved', 'closed')
                 GROUP BY ce.case_id
                HAVING COUNT(*) >= 1
            ),
            -- Signal 3: same rule within 24h
            rule_matches AS (
                SELECT DISTINCT c.id,
                       0.45::real AS base_conf,
                       'Same rule within 24h'::text AS base_reason
                  FROM cases c
                  JOIN case_alerts ca ON ca.case_id = c.id
                  JOIN alerts a ON a.id = ca.alert_id
                 WHERE a.rule_id IN (SELECT rule_id FROM subject_rules)
                   AND c.id <> $1
                   AND c.status NOT IN ('resolved', 'closed')
                   AND c.created_at BETWEEN $4 - INTERVAL '24 hours'
                                        AND $4 + INTERVAL '24 hours'
            ),
            -- Union all signals then pick the single best per candidate.
            all_signals AS (
                SELECT id, base_conf, base_reason, 0::bigint AS shared_count FROM group_matches
                UNION ALL
                SELECT id, base_conf, base_reason, shared_count FROM entity_matches
                UNION ALL
                SELECT id, base_conf, base_reason, 0::bigint AS shared_count FROM rule_matches
            ),
            ranked AS (
                SELECT id,
                       base_conf,
                       base_reason,
                       shared_count,
                       ROW_NUMBER() OVER (PARTITION BY id ORDER BY base_conf DESC, shared_count DESC) AS rk
                  FROM all_signals
            )
            SELECT c.id,
                   c.case_number,
                   c.title,
                   c.severity,
                   c.status,
                   r.shared_count,
                   r.base_conf AS confidence,
                   r.base_reason AS reason
              FROM ranked r
              JOIN cases c ON c.id = r.id
             WHERE r.rk = 1
             ORDER BY r.base_conf DESC, c.created_at DESC
             LIMIT $5
            "#,
        )
        .bind(case_id)
        .bind(grouping_key)
        .bind(denom)
        .bind(created_at)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for (id, case_number, title, severity, status, shared_count, confidence, reason) in rows {
            // v1 detector: whichever CTE signal wins ROW_NUMBER dictates the
            // confidence; we only reshape the reason string for display. A
            // future pass can combine signals (e.g. boost grouping_key match
            // when entity overlap is also present) once we have a dataset to
            // tune against — kept simple here to avoid premature weighting.
            let mut final_conf = confidence;
            let mut final_reason = reason;
            if shared_count > 0 {
                final_reason = format!("{} shared entities", shared_count);
            } else if final_conf >= 0.79 {
                // grouping_key signal path — no entity overlap computed yet.
                final_reason = "Same grouping key".to_string();
            }
            final_conf = final_conf.clamp(0.0, 1.0);

            out.push(DuplicateCandidate {
                case_id: id,
                case_number,
                title,
                severity,
                status,
                confidence: final_conf,
                reason: final_reason,
            });
        }

        Ok(out)
    }

    /// Find cases with overlapping entities (for auto-detection of related cases)
    /// Limited to 100 entities from source case to prevent join explosion
    pub async fn find_cases_with_shared_entities(
        &self,
        case_id: Uuid,
        min_shared: i32,
    ) -> Result<Vec<(Uuid, i64)>, CaseRepositoryError> {
        let results: Vec<(Uuid, i64)> = sqlx::query_as(
            r#"
            WITH source_entities AS (
                SELECT entity_type, entity_value
                FROM case_entities
                WHERE case_id = $1
                LIMIT 100
            )
            SELECT ce2.case_id, COUNT(*) as shared_count
            FROM source_entities se
            JOIN case_entities ce2 ON se.entity_type = ce2.entity_type
                AND se.entity_value = ce2.entity_value
                AND ce2.case_id != $1
            GROUP BY ce2.case_id
            HAVING COUNT(*) >= $2
            ORDER BY shared_count DESC
            LIMIT 10
            "#,
        )
        .bind(case_id)
        .bind(min_shared)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }
}
