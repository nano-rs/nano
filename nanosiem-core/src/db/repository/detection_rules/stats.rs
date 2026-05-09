// SPDX-License-Identifier: AGPL-3.0-or-later

//! Execution stats and daily statistics for detection rules

use chrono::NaiveDate;
use uuid::Uuid;

use super::types::{DailyStat, DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Update last run timestamp and match count
    /// Also updates last_match_at if there were matches
    pub async fn update_execution_stats(
        &self,
        id: Uuid,
        matches: i64,
    ) -> Result<(), DetectionRuleRepositoryError> {
        if matches > 0 {
            // Update both last_run_at and last_match_at when there are matches
            sqlx::query(
                r#"
                UPDATE detection_rules SET
                    last_run_at = NOW(),
                    last_match_at = NOW(),
                    match_count = match_count + $2
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(matches)
            .execute(&self.pool)
            .await?;
        } else {
            // Only update last_run_at when there are no matches
            sqlx::query(
                r#"
                UPDATE detection_rules SET
                    last_run_at = NOW(),
                    match_count = match_count + $2
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(matches)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    /// Update live match count (for bake-in mode)
    /// Also updates last_match_at if there were matches
    pub async fn update_live_match_count(
        &self,
        id: Uuid,
        matches: i64,
    ) -> Result<(), DetectionRuleRepositoryError> {
        if matches > 0 {
            // Update both last_run_at and last_match_at when there are matches
            sqlx::query(
                r#"
                UPDATE detection_rules SET
                    last_run_at = NOW(),
                    last_match_at = NOW(),
                    live_match_count = live_match_count + $2
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(matches)
            .execute(&self.pool)
            .await?;
        } else {
            // Only update last_run_at when there are no matches
            sqlx::query(
                r#"
                UPDATE detection_rules SET
                    last_run_at = NOW(),
                    live_match_count = live_match_count + $2
                WHERE id = $1
                "#,
            )
            .bind(id)
            .bind(matches)
            .execute(&self.pool)
            .await?;
        }

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
            WHERE rule_id = $1 AND date >= CURRENT_DATE - $2::integer
            ORDER BY date ASC
            "#,
        )
        .bind(rule_id)
        .bind(days)
        .fetch_all(&self.pool)
        .await?;

        Ok(results)
    }

    /// Get daily stats for all rules (for the detections list page)
    pub async fn get_all_daily_stats(
        &self,
        days: i32,
    ) -> Result<Vec<(Uuid, DailyStat)>, DetectionRuleRepositoryError> {
        let results = sqlx::query_as::<_, (Uuid, NaiveDate, i64, i64)>(
            r#"
            SELECT rule_id, date, match_count, alert_count
            FROM detection_daily_stats
            WHERE date >= CURRENT_DATE - $1::integer
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
