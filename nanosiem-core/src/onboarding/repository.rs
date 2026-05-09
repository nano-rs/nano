// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL-backed onboarding progress storage.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use super::types::{OnboardingProgress, OnboardingStep};

/// Internal row type for sqlx deserialization.
#[derive(sqlx::FromRow)]
struct OnboardingRow {
    user_id: Uuid,
    current_step: String,
    completed_steps: serde_json::Value,
    skipped_steps: serde_json::Value,
    step_data: serde_json::Value,
    dismissed: bool,
    completed_at: Option<DateTime<Utc>>,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
}

impl TryFrom<OnboardingRow> for OnboardingProgress {
    type Error = serde_json::Error;

    fn try_from(row: OnboardingRow) -> Result<Self, Self::Error> {
        Ok(Self {
            user_id: row.user_id,
            current_step: OnboardingStep::from_str(&row.current_step)
                .unwrap_or(OnboardingStep::AiSetup),
            completed_steps: serde_json::from_value(row.completed_steps)?,
            skipped_steps: serde_json::from_value(row.skipped_steps)?,
            step_data: row.step_data,
            dismissed: row.dismissed,
            completed_at: row.completed_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
        })
    }
}

/// PostgreSQL-backed repository for onboarding progress.
#[derive(Debug, Clone)]
pub struct OnboardingRepository {
    pool: PgPool,
}

impl OnboardingRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get progress for a user, returns None if no record exists.
    pub async fn get_progress(
        &self,
        user_id: Uuid,
    ) -> Result<Option<OnboardingProgress>, sqlx::Error> {
        let row: Option<OnboardingRow> = sqlx::query_as(
            "SELECT user_id, current_step, completed_steps, skipped_steps,
                    step_data, dismissed, completed_at, created_at, updated_at
             FROM onboarding_progress
             WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some(r) => r
                .try_into()
                .map(Some)
                .map_err(|e: serde_json::Error| sqlx::Error::Decode(Box::new(e))),
            None => Ok(None),
        }
    }

    /// Create or update progress (upsert).
    pub async fn upsert_progress(&self, progress: &OnboardingProgress) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO onboarding_progress
                (user_id, current_step, completed_steps, skipped_steps,
                 step_data, dismissed, completed_at, created_at, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
             ON CONFLICT (user_id) DO UPDATE SET
                current_step = EXCLUDED.current_step,
                completed_steps = EXCLUDED.completed_steps,
                skipped_steps = EXCLUDED.skipped_steps,
                step_data = EXCLUDED.step_data,
                dismissed = EXCLUDED.dismissed,
                completed_at = EXCLUDED.completed_at,
                updated_at = NOW()",
        )
        .bind(progress.user_id)
        .bind(progress.current_step.as_str())
        .bind(serde_json::to_value(&progress.completed_steps).unwrap_or_default())
        .bind(serde_json::to_value(&progress.skipped_steps).unwrap_or_default())
        .bind(&progress.step_data)
        .bind(progress.dismissed)
        .bind(progress.completed_at)
        .bind(progress.created_at)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Mark a step as completed for a user.
    pub async fn complete_step(
        &self,
        user_id: Uuid,
        step: OnboardingStep,
        data: Option<serde_json::Value>,
    ) -> Result<OnboardingProgress, sqlx::Error> {
        let mut progress = self
            .get_progress(user_id)
            .await?
            .unwrap_or_else(|| new_progress(user_id));

        if !progress.completed_steps.contains(&step) {
            progress.completed_steps.push(step);
        }
        // Remove from skipped if it was previously skipped
        progress.skipped_steps.retain(|s| s != &step);

        // Store step data if provided
        if let Some(d) = data {
            if let Some(obj) = progress.step_data.as_object_mut() {
                obj.insert(step.as_str().to_string(), d);
            }
        }

        // Advance to next step if completing the current one
        if progress.current_step == step {
            if let Some(next) = step.next() {
                progress.current_step = next;
            }
        }

        // Check if all steps are completed or skipped
        let all_done = OnboardingStep::all()
            .iter()
            .all(|s| progress.completed_steps.contains(s) || progress.skipped_steps.contains(s));
        if all_done {
            progress.completed_at = Some(Utc::now());
        }

        self.upsert_progress(&progress).await?;
        Ok(progress)
    }

    /// Mark a step as skipped for a user.
    pub async fn skip_step(
        &self,
        user_id: Uuid,
        step: OnboardingStep,
    ) -> Result<OnboardingProgress, sqlx::Error> {
        let mut progress = self
            .get_progress(user_id)
            .await?
            .unwrap_or_else(|| new_progress(user_id));

        if !progress.skipped_steps.contains(&step) {
            progress.skipped_steps.push(step);
        }

        // Advance to next step if skipping the current one
        if progress.current_step == step {
            if let Some(next) = step.next() {
                progress.current_step = next;
            }
        }

        // Check if all steps are completed or skipped
        let all_done = OnboardingStep::all()
            .iter()
            .all(|s| progress.completed_steps.contains(s) || progress.skipped_steps.contains(s));
        if all_done {
            progress.completed_at = Some(Utc::now());
        }

        self.upsert_progress(&progress).await?;
        Ok(progress)
    }

    /// Dismiss the wizard entirely.
    pub async fn dismiss(&self, user_id: Uuid) -> Result<OnboardingProgress, sqlx::Error> {
        let mut progress = self
            .get_progress(user_id)
            .await?
            .unwrap_or_else(|| new_progress(user_id));

        progress.dismissed = true;
        self.upsert_progress(&progress).await?;
        Ok(progress)
    }

    /// Reset onboarding progress (re-run wizard).
    pub async fn reset(&self, user_id: Uuid) -> Result<OnboardingProgress, sqlx::Error> {
        let progress = new_progress(user_id);
        self.upsert_progress(&progress).await?;
        Ok(progress)
    }
}

fn new_progress(user_id: Uuid) -> OnboardingProgress {
    OnboardingProgress {
        user_id,
        current_step: OnboardingStep::AiSetup,
        completed_steps: vec![],
        skipped_steps: vec![],
        step_data: serde_json::json!({}),
        dismissed: false,
        completed_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}
