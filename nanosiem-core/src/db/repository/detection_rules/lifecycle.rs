// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mode transition methods for detection rules (promote, demote, pause, resume)

use uuid::Uuid;

use crate::models::{DetectionRule, RuleMode};

use super::types::{DetectionRuleRepository, DetectionRuleRepositoryError};

impl DetectionRuleRepository {
    /// Compatibility window for legacy lifecycle POSTs without an
    /// `expected_mode` guard. A second unguarded transition for the same rule
    /// inside this window returns the current row without mutating it.
    pub const LEGACY_LIFECYCLE_DWELL_SECONDS: i64 = 30;

    /// Promote a rule from staging to live mode (ready for testing)
    pub async fn promote_to_live(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        // Audit D28: entering Live starts a fresh bake-in phase, so reset the
        // live_match_count — otherwise it carries over a previous bake-in's count
        // and misleads the tuning signal.
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'live',
                live_match_count = 0,
                updated_at = NOW()
            WHERE id = $1 AND mode = 'staging'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Promote a rule from live to alerting mode
    pub async fn promote_to_alerting(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'alerting',
                updated_at = NOW()
            WHERE id = $1 AND mode = 'live'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                // Distinguish "not found" from "wrong mode"
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Demote a rule from alerting to live mode (for tuning)
    pub async fn demote_to_live(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'live',
                live_match_count = 0,
                updated_at = NOW()
            WHERE id = $1 AND mode = 'alerting'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                // Distinguish "not found" from "wrong mode"
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Demote a rule from live to staging mode (back to development)
    pub async fn demote_to_staging(
        &self,
        id: Uuid,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = 'staging',
                updated_at = NOW()
            WHERE id = $1 AND mode = 'live'
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                // Distinguish "not found" from "wrong mode"
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Pause a detection rule while recording the exact mode to restore.
    pub async fn pause(
        &self,
        id: Uuid,
        expected_mode: RuleMode,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                paused_from_mode = mode,
                mode = 'paused',
                updated_at = NOW()
            WHERE id = $1
              AND mode = $2
              AND mode IN ('alerting', 'live')
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(expected_mode.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Set a rule's mode directly (used by bulk operations)
    ///
    /// Unlike the transition methods (promote, demote, pause, resume), this does
    /// not enforce mode transition rules — it sets the mode unconditionally.
    pub async fn set_mode(
        &self,
        id: Uuid,
        mode: &str,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = $2,
                paused_from_mode = CASE
                    WHEN $2 = 'paused' AND mode IN ('staging', 'live', 'alerting') THEN mode
                    WHEN $2 <> 'paused' THEN NULL
                    ELSE paused_from_mode
                END,
                -- Audit D28: bulk transitions into Live must reset the bake-in
                -- counter too (single-rule demote_to_live already does).
                live_match_count = CASE WHEN $2 = 'live' THEN 0 ELSE live_match_count END,
                updated_at = NOW()
            WHERE id = $1
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(mode)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(DetectionRuleRepositoryError::NotFound(id))?;

        Ok(result)
    }

    /// Resume a paused detection rule to the mode captured when it was paused.
    pub async fn resume(
        &self,
        id: Uuid,
        expected_mode: RuleMode,
    ) -> Result<DetectionRule, DetectionRuleRepositoryError> {
        let result = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = paused_from_mode,
                paused_from_mode = NULL,
                updated_at = NOW()
            WHERE id = $1
              AND mode = $2
              AND mode = 'paused'
              AND paused_from_mode IN ('staging', 'live', 'alerting')
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(expected_mode.to_string())
        .fetch_optional(&self.pool)
        .await?;

        match result {
            Some(rule) => Ok(rule),
            None => {
                let current_mode: Option<(String,)> =
                    sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1")
                        .bind(id)
                        .fetch_optional(&self.pool)
                        .await?;
                match current_mode {
                    Some((mode,)) => Err(DetectionRuleRepositoryError::InvalidModeTransition(
                        id, mode,
                    )),
                    None => Err(DetectionRuleRepositoryError::NotFound(id)),
                }
            }
        }
    }

    /// Pause one active rule for a legacy bodyless caller under a row lock.
    ///
    /// Unlike promote/demote, pause has a fixed terminal state. A concurrent
    /// request or retry that observes the already-paused row is therefore an
    /// idempotent no-op and receives the current rule.
    pub async fn pause_legacy(
        &self,
        id: Uuid,
    ) -> Result<(Option<RuleMode>, DetectionRule), DetectionRuleRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let source_mode: Option<(String,)> =
            sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some((source_mode,)) = source_mode else {
            return Err(DetectionRuleRepositoryError::NotFound(id));
        };
        let source_mode = parse_rule_mode(id, &source_mode)?;
        if source_mode == RuleMode::Paused {
            let rule =
                sqlx::query_as::<_, DetectionRule>("SELECT * FROM detection_rules WHERE id = $1")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?;
            tx.commit().await?;
            return Ok((None, rule));
        }
        if !matches!(source_mode, RuleMode::Live | RuleMode::Alerting) {
            return Err(DetectionRuleRepositoryError::InvalidModeTransition(
                id,
                source_mode.to_string(),
            ));
        }

        let rule = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                paused_from_mode = mode,
                mode = 'paused',
                updated_at = NOW()
            WHERE id = $1 AND mode = $2
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(source_mode.to_string())
        .fetch_one(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok((Some(source_mode), rule))
    }

    /// Resume one legacy bodyless request to its persisted pre-pause mode.
    ///
    /// A request that observes any non-paused mode is an idempotent no-op. The
    /// row lock makes a concurrent retry observe the result of the first
    /// resume rather than applying another lifecycle transition.
    pub async fn resume_legacy(
        &self,
        id: Uuid,
    ) -> Result<(Option<RuleMode>, DetectionRule), DetectionRuleRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let source_mode: Option<(String,)> =
            sqlx::query_as("SELECT mode::text FROM detection_rules WHERE id = $1 FOR UPDATE")
                .bind(id)
                .fetch_optional(&mut *tx)
                .await?;

        let Some((source_mode,)) = source_mode else {
            return Err(DetectionRuleRepositoryError::NotFound(id));
        };
        let source_mode = parse_rule_mode(id, &source_mode)?;
        if source_mode != RuleMode::Paused {
            let rule =
                sqlx::query_as::<_, DetectionRule>("SELECT * FROM detection_rules WHERE id = $1")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?;
            tx.commit().await?;
            return Ok((None, rule));
        }

        let rule = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = paused_from_mode,
                paused_from_mode = NULL,
                updated_at = NOW()
            WHERE id = $1
              AND mode = 'paused'
              AND paused_from_mode IN ('staging', 'live', 'alerting')
            RETURNING *
            "#,
        )
        .bind(id)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            DetectionRuleRepositoryError::InvalidModeTransition(id, source_mode.to_string())
        })?;
        tx.commit().await?;

        Ok((Some(source_mode), rule))
    }

    /// Apply one legacy bodyless promotion under a row lock.
    ///
    /// The timestamp check and transition are in the same transaction. Two
    /// overlapping requests therefore cannot both infer a source state and
    /// advance the rule: the loser observes the first transition's dwell and
    /// receives the current row unchanged.
    pub async fn promote_legacy(
        &self,
        id: Uuid,
    ) -> Result<(Option<RuleMode>, DetectionRule), DetectionRuleRepositoryError> {
        self.transition_legacy(id, LegacyLifecycleDirection::Promote)
            .await
    }

    /// Apply one legacy bodyless demotion with the same retry-safe semantics
    /// as [`Self::promote_legacy`].
    pub async fn demote_legacy(
        &self,
        id: Uuid,
    ) -> Result<(Option<RuleMode>, DetectionRule), DetectionRuleRepositoryError> {
        self.transition_legacy(id, LegacyLifecycleDirection::Demote)
            .await
    }

    async fn transition_legacy(
        &self,
        id: Uuid,
        direction: LegacyLifecycleDirection,
    ) -> Result<(Option<RuleMode>, DetectionRule), DetectionRuleRepositoryError> {
        let mut tx = self.pool.begin().await?;
        let state: Option<(String, bool)> = sqlx::query_as(
            r#"
            SELECT mode::text,
                   COALESCE(
                       legacy_lifecycle_transition_at >
                           NOW() - make_interval(secs => $2::double precision),
                       FALSE
                   )
            FROM detection_rules
            WHERE id = $1
            FOR UPDATE
            "#,
        )
        .bind(id)
        .bind(Self::LEGACY_LIFECYCLE_DWELL_SECONDS as f64)
        .fetch_optional(&mut *tx)
        .await?;

        let Some((source_mode, within_dwell)) = state else {
            return Err(DetectionRuleRepositoryError::NotFound(id));
        };

        if within_dwell {
            let rule =
                sqlx::query_as::<_, DetectionRule>("SELECT * FROM detection_rules WHERE id = $1")
                    .bind(id)
                    .fetch_one(&mut *tx)
                    .await?;
            tx.commit().await?;
            return Ok((None, rule));
        }

        let source_mode = parse_rule_mode(id, &source_mode)?;
        let target_mode = match (direction, source_mode) {
            (LegacyLifecycleDirection::Promote, RuleMode::Staging) => RuleMode::Live,
            (LegacyLifecycleDirection::Promote, RuleMode::Live) => RuleMode::Alerting,
            (LegacyLifecycleDirection::Demote, RuleMode::Alerting) => RuleMode::Live,
            (LegacyLifecycleDirection::Demote, RuleMode::Live) => RuleMode::Staging,
            _ => {
                return Err(DetectionRuleRepositoryError::InvalidModeTransition(
                    id,
                    source_mode.to_string(),
                ))
            }
        };

        let rule = sqlx::query_as::<_, DetectionRule>(
            r#"
            UPDATE detection_rules SET
                mode = $2,
                live_match_count = CASE
                    WHEN $2 = 'live' THEN 0
                    ELSE live_match_count
                END,
                legacy_lifecycle_transition_at = NOW(),
                updated_at = NOW()
            WHERE id = $1 AND mode = $3
            RETURNING *
            "#,
        )
        .bind(id)
        .bind(target_mode.to_string())
        .bind(source_mode.to_string())
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| {
            DetectionRuleRepositoryError::InvalidModeTransition(id, source_mode.to_string())
        })?;
        tx.commit().await?;

        Ok((Some(source_mode), rule))
    }
}

#[derive(Clone, Copy)]
enum LegacyLifecycleDirection {
    Promote,
    Demote,
}

fn parse_rule_mode(id: Uuid, mode: &str) -> Result<RuleMode, DetectionRuleRepositoryError> {
    match mode {
        "staging" => Ok(RuleMode::Staging),
        "live" => Ok(RuleMode::Live),
        "alerting" => Ok(RuleMode::Alerting),
        "paused" => Ok(RuleMode::Paused),
        _ => Err(DetectionRuleRepositoryError::InvalidModeTransition(
            id,
            mode.to_owned(),
        )),
    }
}
