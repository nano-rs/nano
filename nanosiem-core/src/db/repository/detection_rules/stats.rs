// SPDX-License-Identifier: AGPL-3.0-or-later

//! Execution stats and daily statistics for detection rules

use chrono::NaiveDate;
use uuid::Uuid;

use super::types::{DailyStat, DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Increment `match_count` (and `last_match_at` when there were matches).
    ///
    /// Does **not** touch `last_run_at` — that column is owned solely by
    /// `release_claim`, which advances it to the executed window end on success
    /// only (audit D1+D2, NAN-1703). This function runs mid-execution, *before*
    /// alert creation; writing `last_run_at` here re-opened the window-drop bug
    /// whenever the alert path failed afterward.
    pub async fn update_execution_stats(
        &self,
        id: Uuid,
        matches: i64,
    ) -> Result<(), DetectionRuleRepositoryError> {
        // No matches → nothing to record here: match_count wouldn't change and
        // last_run_at is owned by release_claim (audit D1). Skip the no-op write.
        if matches <= 0 {
            return Ok(());
        }

        sqlx::query(
            r#"
            UPDATE detection_rules SET
                last_match_at = NOW(),
                match_count = match_count + $2
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(matches)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update live match count (for bake-in mode).
    /// Also updates `last_match_at` if there were matches.
    ///
    /// Like `update_execution_stats`, this does **not** touch `last_run_at`
    /// (owned by `release_claim`; audit D1+D2, NAN-1703).
    ///
    /// NAN-869: `match_count` is the true lifetime counter (always incremented
    /// in both modes); `live_match_count` is the current bake-in phase counter
    /// (reset on Alerting→Live demotion). The two columns are disjoint — no
    /// code path folds one into the other — so incrementing both here is
    /// exact, not a double-count.
    pub async fn update_live_match_count(
        &self,
        id: Uuid,
        matches: i64,
    ) -> Result<(), DetectionRuleRepositoryError> {
        // No matches → nothing to record (counters unchanged; last_run_at owned
        // by release_claim, audit D1). Skip the no-op write.
        if matches <= 0 {
            return Ok(());
        }

        sqlx::query(
            r#"
            UPDATE detection_rules SET
                last_match_at = NOW(),
                live_match_count = live_match_count + $2,
                match_count = match_count + $2
            WHERE id = $1
            "#,
        )
        .bind(id)
        .bind(matches)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Record daily stats for a rule (upserts - adds to existing count for the day)
    pub async fn record_daily_stats(
        &self,
        rule_id: Uuid,
        date: NaiveDate,
        match_count: i64,
        alert_count: i64,
    ) -> Result<(), DetectionRuleRepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO detection_daily_stats (rule_id, date, match_count, alert_count)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (rule_id, date)
            DO UPDATE SET
                match_count = detection_daily_stats.match_count + EXCLUDED.match_count,
                alert_count = detection_daily_stats.alert_count + EXCLUDED.alert_count,
                updated_at = NOW()
            "#,
        )
        .bind(rule_id)
        .bind(date)
        .bind(match_count)
        .bind(alert_count)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get daily stats for a rule over a date range
    pub async fn get_daily_stats(
        &self,
        rule_id: Uuid,
        days: i32,
    ) -> Result<Vec<DailyStat>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, DailyStat>(
            r#"
            SELECT date, match_count, alert_count
            FROM detection_daily_stats
            WHERE rule_id = $1 AND date >= (now() AT TIME ZONE 'UTC')::date - $2::integer
            ORDER BY date ASC
            "#,
        )
        .bind(rule_id)
        .bind(days)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get daily stats for all rules (for the detections list page sparkline).
    ///
    /// `match_count` is the per-day count of detection firings (rows in
    /// `detection_matches`), matching what the rules list "today" badge and
    /// rule-detail hour-by-hour strip show. `alert_count` continues to come
    /// from `detection_daily_stats` (NAN-812).
    pub async fn get_all_daily_stats(
        &self,
        days: i32,
    ) -> Result<Vec<(Uuid, DailyStat)>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, (Uuid, NaiveDate, i64, i64)>(
            r#"
            SELECT
                COALESCE(m.rule_id, d.rule_id) AS rule_id,
                COALESCE(m.date, d.date) AS date,
                COALESCE(m.match_count, 0)::bigint AS match_count,
                COALESCE(d.alert_count, 0)::bigint AS alert_count
            FROM (
                SELECT
                    rule_id,
                    (detected_at AT TIME ZONE 'UTC')::date AS date,
                    COUNT(*)::bigint AS match_count
                FROM detection_matches
                WHERE detected_at >= (((now() AT TIME ZONE 'UTC')::date - $1::integer)::timestamp AT TIME ZONE 'UTC')
                GROUP BY rule_id, (detected_at AT TIME ZONE 'UTC')::date
            ) m
            FULL OUTER JOIN (
                SELECT rule_id, date, alert_count
                FROM detection_daily_stats
                WHERE date >= (now() AT TIME ZONE 'UTC')::date - $1::integer
            ) d ON m.rule_id = d.rule_id AND m.date = d.date
            ORDER BY rule_id, date ASC
            "#,
        )
        .bind(days)
        .fetch_all(&self.pool)
        .await?;

        Ok(results
            .into_iter()
            .map(|(rule_id, date, match_count, alert_count)| {
                (
                    rule_id,
                    DailyStat {
                        date,
                        match_count,
                        alert_count,
                    },
                )
            })
            .collect())
    }
}
