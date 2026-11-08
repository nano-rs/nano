// SPDX-License-Identifier: AGPL-3.0-or-later

//! Retro-hunt rule persistence (NAN-1791).
//!
//! Config (`retro_hunt_rule_config`), delta state (`retro_hunt_rule_state` +
//! `retro_hunt_hunted_indicators`), and run history (`retro_hunt_runs`) for auto
//! retro-hunt rules. The rule row itself lives in `detection_rules`
//! (`kind = 'retro_hunt'`) and is managed by [`DetectionRuleRepository`].

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::models::retro_hunt::{
    RetroHuntConfig, RetroHuntRun, RetroHuntState, UpdateRetroHuntConfigRequest,
};

/// Errors from the retro-hunt repository.
#[derive(Debug, thiserror::Error)]
pub enum RetroHuntRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("retro-hunt config not found for rule {0}")]
    ConfigNotFound(Uuid),
}

/// Repository for retro-hunt config, delta state, and run history.
#[derive(Clone)]
pub struct RetroHuntRepository {
    pool: PgPool,
}

impl RetroHuntRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    // ------------------------------------------------------------------
    // Config
    // ------------------------------------------------------------------

    /// Insert or replace a rule's retro-hunt config.
    pub async fn upsert_config(
        &self,
        rule_id: Uuid,
        feeds: &[String],
        artifact_types: &[String],
        lookback_days: i32,
        max_indicators_per_run: i32,
    ) -> Result<RetroHuntConfig, RetroHuntRepositoryError> {
        let config = sqlx::query_as::<_, RetroHuntConfig>(
            r#"
            INSERT INTO retro_hunt_rule_config
                (rule_id, feeds, artifact_types, lookback_days, max_indicators_per_run)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (rule_id) DO UPDATE SET
                feeds = EXCLUDED.feeds,
                artifact_types = EXCLUDED.artifact_types,
                lookback_days = EXCLUDED.lookback_days,
                max_indicators_per_run = EXCLUDED.max_indicators_per_run,
                updated_at = now()
            RETURNING *
            "#,
        )
        .bind(rule_id)
        .bind(feeds)
        .bind(artifact_types)
        .bind(lookback_days)
        .bind(max_indicators_per_run)
        .fetch_one(&self.pool)
        .await?;
        Ok(config)
    }

    /// Apply a partial config update (COALESCE — omitted fields unchanged).
    pub async fn update_config(
        &self,
        rule_id: Uuid,
        update: &UpdateRetroHuntConfigRequest,
    ) -> Result<RetroHuntConfig, RetroHuntRepositoryError> {
        let config = sqlx::query_as::<_, RetroHuntConfig>(
            r#"
            UPDATE retro_hunt_rule_config SET
                feeds = COALESCE($2, feeds),
                artifact_types = COALESCE($3, artifact_types),
                lookback_days = COALESCE($4, lookback_days),
                max_indicators_per_run = COALESCE($5, max_indicators_per_run),
                updated_at = now()
            WHERE rule_id = $1
            RETURNING *
            "#,
        )
        .bind(rule_id)
        .bind(update.feeds.as_deref())
        .bind(update.artifact_types.as_deref())
        .bind(update.lookback_days)
        .bind(update.max_indicators_per_run)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(RetroHuntRepositoryError::ConfigNotFound(rule_id))?;
        Ok(config)
    }

    /// Fetch a rule's retro-hunt config, if any.
    pub async fn get_config(
        &self,
        rule_id: Uuid,
    ) -> Result<Option<RetroHuntConfig>, RetroHuntRepositoryError> {
        let config = sqlx::query_as::<_, RetroHuntConfig>(
            r#"SELECT * FROM retro_hunt_rule_config WHERE rule_id = $1"#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(config)
    }

    // ------------------------------------------------------------------
    // Delta state (watermark)
    // ------------------------------------------------------------------

    /// Fetch a rule's delta state (watermark), if it has run before.
    pub async fn get_state(
        &self,
        rule_id: Uuid,
    ) -> Result<Option<RetroHuntState>, RetroHuntRepositoryError> {
        let state = sqlx::query_as::<_, RetroHuntState>(
            r#"SELECT * FROM retro_hunt_rule_state WHERE rule_id = $1"#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(state)
    }

    /// Advance the keyset cursor `(watermark, watermark_value)` + stamp
    /// last_run_at for a rule.
    pub async fn upsert_state(
        &self,
        rule_id: Uuid,
        watermark: Option<DateTime<Utc>>,
        watermark_value: Option<&str>,
        last_run_at: DateTime<Utc>,
    ) -> Result<(), RetroHuntRepositoryError> {
        sqlx::query(
            r#"
            INSERT INTO retro_hunt_rule_state
                (rule_id, watermark, watermark_value, last_run_at, updated_at)
            VALUES ($1, $2, $3, $4, now())
            ON CONFLICT (rule_id) DO UPDATE SET
                watermark = EXCLUDED.watermark,
                watermark_value = EXCLUDED.watermark_value,
                last_run_at = EXCLUDED.last_run_at,
                updated_at = now()
            "#,
        )
        .bind(rule_id)
        .bind(watermark)
        .bind(watermark_value)
        .bind(last_run_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Hunted-indicator dedup set
    // ------------------------------------------------------------------

    /// Return the subset of `values` this rule has ALREADY hunted. Batched
    /// `= ANY($values)`. The caller hunts the complement.
    pub async fn already_hunted(
        &self,
        rule_id: Uuid,
        values: &[String],
    ) -> Result<HashSet<String>, RetroHuntRepositoryError> {
        if values.is_empty() {
            return Ok(HashSet::new());
        }
        let rows: Vec<String> = sqlx::query_scalar(
            r#"
            SELECT indicator_value
            FROM retro_hunt_hunted_indicators
            WHERE rule_id = $1 AND indicator_value = ANY($2)
            "#,
        )
        .bind(rule_id)
        .bind(values)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.into_iter().collect())
    }

    /// Record `(value, type)` pairs as hunted (idempotent). Call AFTER the hunt's
    /// hits are emitted so a crash mid-run re-hunts rather than silently skips.
    pub async fn record_hunted(
        &self,
        rule_id: Uuid,
        indicators: &[(String, String)],
    ) -> Result<(), RetroHuntRepositoryError> {
        if indicators.is_empty() {
            return Ok(());
        }
        let mut qb = sqlx::QueryBuilder::new(
            "INSERT INTO retro_hunt_hunted_indicators (rule_id, indicator_value, indicator_type) ",
        );
        qb.push_values(indicators, |mut b, (value, ty)| {
            b.push_bind(rule_id).push_bind(value).push_bind(ty);
        });
        qb.push(" ON CONFLICT (rule_id, indicator_value) DO NOTHING");
        qb.build().execute(&self.pool).await?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Run history
    // ------------------------------------------------------------------

    /// Open a run-history row (`status = 'running'`). Returns its id.
    pub async fn start_run(
        &self,
        rule_id: Uuid,
        watermark_before: Option<DateTime<Utc>>,
    ) -> Result<i64, RetroHuntRepositoryError> {
        let id: i64 = sqlx::query_scalar(
            r#"
            INSERT INTO retro_hunt_runs (rule_id, watermark_before, status)
            VALUES ($1, $2, 'running')
            RETURNING id
            "#,
        )
        .bind(rule_id)
        .bind(watermark_before)
        .fetch_one(&self.pool)
        .await?;
        Ok(id)
    }

    /// Finalize a run-history row.
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_run(
        &self,
        run_id: i64,
        status: &str,
        candidates_considered: i32,
        indicators_hunted: i32,
        hits: i32,
        truncated: bool,
        overflow_remaining: i32,
        watermark_after: Option<DateTime<Utc>>,
        error: Option<&str>,
    ) -> Result<(), RetroHuntRepositoryError> {
        sqlx::query(
            r#"
            UPDATE retro_hunt_runs SET
                finished_at = now(),
                status = $2,
                candidates_considered = $3,
                indicators_hunted = $4,
                hits = $5,
                truncated = $6,
                overflow_remaining = $7,
                watermark_after = $8,
                error = $9
            WHERE id = $1
            "#,
        )
        .bind(run_id)
        .bind(status)
        .bind(candidates_considered)
        .bind(indicators_hunted)
        .bind(hits)
        .bind(truncated)
        .bind(overflow_remaining)
        .bind(watermark_after)
        .bind(error)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// List a rule's recent runs, newest first.
    pub async fn list_runs(
        &self,
        rule_id: Uuid,
        limit: i64,
    ) -> Result<Vec<RetroHuntRun>, RetroHuntRepositoryError> {
        let runs = sqlx::query_as::<_, RetroHuntRun>(
            r#"
            SELECT * FROM retro_hunt_runs
            WHERE rule_id = $1
            ORDER BY started_at DESC
            LIMIT $2
            "#,
        )
        .bind(rule_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        Ok(runs)
    }
}
