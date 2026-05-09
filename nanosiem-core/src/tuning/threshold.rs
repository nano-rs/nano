// SPDX-License-Identifier: AGPL-3.0-or-later

//! Threshold Detector for AI Detection Auto-Tuning
//!
//! Monitors baselines and detects anomalous behavior:
//! - Detects when alert volumes exceed baseline thresholds (mean + 2*std_dev)
//! - Tracks consecutive breach periods (requires 3 consecutive periods)
//! - Prioritizes breaches by severity and deviation magnitude
//! - Persists breach history for audit and analysis

use chrono::{DateTime, Duration, Utc};
use sqlx::PgPool;
use std::sync::Arc;
use thiserror::Error;
use uuid::Uuid;

use super::{BaselineMonitor, BaselineStatus, RuleMetrics, ThresholdBreach};

/// Number of consecutive periods required to trigger auto-tuning
const CONSECUTIVE_PERIODS_THRESHOLD: i32 = 3;

/// Evaluation period duration (in minutes)
const EVALUATION_PERIOD_MINUTES: i64 = 15;

/// Errors that can occur during threshold detection
#[derive(Error, Debug)]
pub enum ThresholdDetectorError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Baseline error: {0}")]
    BaselineError(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(Uuid),

    #[error("No baseline established for rule: {0}")]
    NoBaseline(Uuid),

    #[error("Invalid metrics: {0}")]
    InvalidMetrics(String),
}

impl From<sqlx::Error> for ThresholdDetectorError {
    fn from(err: sqlx::Error) -> Self {
        ThresholdDetectorError::DatabaseError(err.to_string())
    }
}

/// Threshold detector service
pub struct ThresholdDetector {
    pg_pool: PgPool,
    baseline_monitor: Arc<BaselineMonitor>,
}

impl ThresholdDetector {
    /// Create a new threshold detector
    pub fn new(pg_pool: PgPool, baseline_monitor: Arc<BaselineMonitor>) -> Self {
        Self {
            pg_pool,
            baseline_monitor,
        }
    }

    /// Check thresholds for all rules with established baselines
    ///
    /// This method scans all detection rules that have baselines,
    /// evaluates their current metrics against thresholds, and
    /// returns any breaches detected.
    ///
    /// # Returns
    /// * `Vec<ThresholdBreach>` - List of threshold breaches detected
    pub async fn check_thresholds(&self) -> Result<Vec<ThresholdBreach>, ThresholdDetectorError> {
        // Get all rules with established baselines
        let rule_ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT rule_id 
            FROM detection_rule_baselines
            WHERE established_at IS NOT NULL
            "#,
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let mut breaches = Vec::new();

        // Evaluate each rule
        for rule_id in rule_ids {
            // Get the most recent metrics for this rule
            if let Some(metrics) = self.get_latest_metrics(rule_id).await? {
                // Evaluate the rule and check for breaches
                if let Some(breach) = self.evaluate_rule(rule_id, metrics).await? {
                    breaches.push(breach);
                }
            }
        }

        // Sort breaches by deviation magnitude (highest first)
        breaches.sort_by(|a, b| {
            b.deviation_magnitude
                .partial_cmp(&a.deviation_magnitude)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        Ok(breaches)
    }

    /// Evaluate a specific rule against its baseline
    ///
    /// This method checks if the current metrics exceed the baseline threshold
    /// and tracks consecutive breach periods.
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    /// * `metrics` - Current metrics for the rule
    ///
    /// # Returns
    /// * `Option<ThresholdBreach>` - Breach information if threshold is exceeded
    pub async fn evaluate_rule(
        &self,
        rule_id: Uuid,
        metrics: RuleMetrics,
    ) -> Result<Option<ThresholdBreach>, ThresholdDetectorError> {
        // Get baseline for this rule
        let baseline = self
            .baseline_monitor
            .get_baseline(rule_id)
            .await
            .map_err(|e| ThresholdDetectorError::BaselineError(e.to_string()))?;

        let baseline = match baseline {
            Some(b) => b,
            None => return Err(ThresholdDetectorError::NoBaseline(rule_id)),
        };

        // Calculate current alert rate (alerts per hour)
        let current_value = metrics.alert_count_1h as f64;

        // Compute effective threshold based on baseline status:
        // - Provisional baselines use wider threshold (mean + 3σ) to reduce noise
        // - Established baselines use the stored threshold (mean + 2σ)
        let effective_threshold = match baseline.status {
            BaselineStatus::Provisional => {
                baseline.mean_alerts_per_hour + (3.0 * baseline.std_dev_alerts_per_hour)
            }
            BaselineStatus::Established => baseline.threshold_breach_level,
        };

        let is_breach = current_value > effective_threshold;

        if !is_breach {
            // No breach - clear any consecutive period tracking
            self.clear_consecutive_periods(rule_id).await?;
            return Ok(None);
        }

        // Calculate deviation magnitude in standard deviations
        let deviation_magnitude = if baseline.std_dev_alerts_per_hour > 0.0 {
            (current_value - baseline.mean_alerts_per_hour) / baseline.std_dev_alerts_per_hour
        } else {
            // If std_dev is 0, use a simple ratio
            if baseline.mean_alerts_per_hour > 0.0 {
                current_value / baseline.mean_alerts_per_hour
            } else {
                current_value
            }
        };

        // Get or increment consecutive periods
        let consecutive_periods = self.increment_consecutive_periods(rule_id).await?;

        // Determine if this breach should trigger auto-tuning
        let should_trigger_tuning = consecutive_periods >= CONSECUTIVE_PERIODS_THRESHOLD;

        // Create breach record
        let breach = ThresholdBreach {
            rule_id,
            detected_at: Utc::now(),
            current_value,
            baseline_mean: baseline.mean_alerts_per_hour,
            baseline_threshold: effective_threshold,
            deviation_magnitude,
            consecutive_periods,
            should_trigger_tuning,
        };

        // Persist breach to database
        self.persist_breach(&breach).await?;

        Ok(Some(breach))
    }

    /// Get breach history for a specific rule
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `Vec<ThresholdBreach>` - Historical breaches for the rule
    pub async fn get_breach_history(
        &self,
        rule_id: Uuid,
    ) -> Result<Vec<ThresholdBreach>, ThresholdDetectorError> {
        let breaches: Vec<BreachRow> = sqlx::query_as(
            r#"
            SELECT 
                id,
                rule_id,
                detected_at,
                current_value,
                baseline_mean,
                baseline_threshold,
                deviation_magnitude,
                consecutive_periods,
                tuning_triggered,
                tuning_proposal_id
            FROM detection_threshold_breaches
            WHERE rule_id = $1
            ORDER BY detected_at DESC
            LIMIT 100
            "#,
        )
        .bind(rule_id)
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(breaches
            .into_iter()
            .map(|row| ThresholdBreach {
                rule_id: row.rule_id,
                detected_at: row.detected_at,
                current_value: row.current_value,
                baseline_mean: row.baseline_mean,
                baseline_threshold: row.baseline_threshold,
                deviation_magnitude: row.deviation_magnitude,
                consecutive_periods: row.consecutive_periods,
                should_trigger_tuning: row.tuning_triggered,
            })
            .collect())
    }

    /// Get the latest metrics for a rule
    async fn get_latest_metrics(
        &self,
        rule_id: Uuid,
    ) -> Result<Option<RuleMetrics>, ThresholdDetectorError> {
        let metrics: Option<MetricsRow> = sqlx::query_as(
            r#"
            SELECT 
                rule_id,
                timestamp,
                alert_count_1h,
                alert_count_24h,
                alert_count_7d,
                unique_users,
                unique_hosts,
                unique_ips,
                avg_severity,
                execution_time_ms
            FROM detection_rule_metrics
            WHERE rule_id = $1
            ORDER BY timestamp DESC
            LIMIT 1
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        Ok(metrics.map(|row| RuleMetrics {
            rule_id: row.rule_id,
            timestamp: row.timestamp,
            alert_count_1h: row.alert_count_1h,
            alert_count_24h: row.alert_count_24h,
            alert_count_7d: row.alert_count_7d,
            unique_users: row.unique_users,
            unique_hosts: row.unique_hosts,
            unique_ips: row.unique_ips,
            avg_severity: row.avg_severity,
            execution_time_ms: row.execution_time_ms,
        }))
    }

    /// Increment consecutive breach periods for a rule
    ///
    /// This method tracks how many consecutive evaluation periods
    /// a rule has been in breach state.
    async fn increment_consecutive_periods(
        &self,
        rule_id: Uuid,
    ) -> Result<i32, ThresholdDetectorError> {
        let now = Utc::now();
        let period_start = now - Duration::minutes(EVALUATION_PERIOD_MINUTES);

        // Check if there was a recent breach (within the last evaluation period)
        let recent_breach: Option<(i32,)> = sqlx::query_as(
            r#"
            SELECT consecutive_periods
            FROM detection_threshold_breaches
            WHERE rule_id = $1 AND detected_at >= $2
            ORDER BY detected_at DESC
            LIMIT 1
            "#,
        )
        .bind(rule_id)
        .bind(period_start)
        .fetch_optional(&self.pg_pool)
        .await?;

        // If there was a recent breach, increment the count
        // Otherwise, start at 1
        Ok(recent_breach.map(|(count,)| count + 1).unwrap_or(1))
    }

    /// Clear consecutive breach period tracking for a rule
    ///
    /// Called when a rule is no longer in breach state
    async fn clear_consecutive_periods(
        &self,
        _rule_id: Uuid,
    ) -> Result<(), ThresholdDetectorError> {
        // Consecutive periods are tracked implicitly by the timestamp
        // of the most recent breach. If no recent breach exists within
        // the evaluation period, the count resets to 1 automatically.
        // No explicit clearing is needed.
        Ok(())
    }

    /// Persist a breach record to the database
    async fn persist_breach(&self, breach: &ThresholdBreach) -> Result<(), ThresholdDetectorError> {
        sqlx::query(
            r#"
            INSERT INTO detection_threshold_breaches (
                rule_id,
                detected_at,
                current_value,
                baseline_mean,
                baseline_threshold,
                deviation_magnitude,
                consecutive_periods,
                tuning_triggered
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            "#,
        )
        .bind(breach.rule_id)
        .bind(breach.detected_at)
        .bind(breach.current_value)
        .bind(breach.baseline_mean)
        .bind(breach.baseline_threshold)
        .bind(breach.deviation_magnitude)
        .bind(breach.consecutive_periods)
        .bind(breach.should_trigger_tuning)
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    /// Check thresholds for all rules (alias for check_thresholds)
    ///
    /// This method is called by the scheduler to check all thresholds.
    /// It's an alias for check_thresholds() to match the scheduler's expected interface.
    ///
    /// # Returns
    /// * `Vec<ThresholdBreach>` - List of threshold breaches detected
    pub async fn check_all_thresholds(
        &self,
    ) -> Result<Vec<ThresholdBreach>, ThresholdDetectorError> {
        self.check_thresholds().await
    }
}

/// Database row for breach queries
#[derive(sqlx::FromRow)]
struct BreachRow {
    #[allow(dead_code)]
    id: Uuid,
    rule_id: Uuid,
    detected_at: DateTime<Utc>,
    current_value: f64,
    baseline_mean: f64,
    baseline_threshold: f64,
    deviation_magnitude: f64,
    consecutive_periods: i32,
    tuning_triggered: bool,
    #[allow(dead_code)]
    tuning_proposal_id: Option<Uuid>,
}

/// Database row for metrics queries
#[derive(sqlx::FromRow)]
struct MetricsRow {
    rule_id: Uuid,
    timestamp: DateTime<Utc>,
    alert_count_1h: i64,
    alert_count_24h: i64,
    alert_count_7d: i64,
    unique_users: i64,
    unique_hosts: i64,
    unique_ips: i64,
    avg_severity: f64,
    execution_time_ms: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deviation_magnitude_calculation() {
        // Test normal case with non-zero std_dev
        let current_value = 100.0;
        let mean = 50.0;
        let std_dev = 10.0;

        let deviation = (current_value - mean) / std_dev;
        assert_eq!(deviation, 5.0); // 5 standard deviations above mean

        // Test with zero std_dev (use ratio instead)
        let std_dev_zero = 0.0;
        let deviation_ratio = if std_dev_zero > 0.0 {
            (current_value - mean) / std_dev_zero
        } else if mean > 0.0 {
            current_value / mean
        } else {
            current_value
        };
        assert_eq!(deviation_ratio, 2.0); // 2x the mean
    }

    #[test]
    fn test_breach_detection_logic() {
        // Test breach detection
        let mean = 50.0;
        let std_dev = 10.0;
        let threshold = mean + (2.0 * std_dev); // 70.0

        // Above threshold - should breach
        let current_value_high = 75.0;
        assert!(current_value_high > threshold);

        // Below threshold - should not breach
        let current_value_low = 65.0;
        assert!(current_value_low < threshold);

        // Exactly at threshold - should not breach
        let current_value_exact = 70.0;
        assert!(!(current_value_exact > threshold));
    }

    #[test]
    fn test_consecutive_periods_logic() {
        // Test consecutive period increment logic
        let recent_breach_count = Some(2);
        let new_count = recent_breach_count.map(|count| count + 1).unwrap_or(1);
        assert_eq!(new_count, 3);

        // Test first breach (no recent breach)
        let no_recent_breach: Option<i32> = None;
        let first_count = no_recent_breach.map(|count| count + 1).unwrap_or(1);
        assert_eq!(first_count, 1);
    }

    #[test]
    fn test_should_trigger_tuning() {
        // Test that tuning is triggered after 3 consecutive periods
        let consecutive_periods = 3;
        let should_trigger = consecutive_periods >= CONSECUTIVE_PERIODS_THRESHOLD;
        assert!(should_trigger);

        // Test that tuning is not triggered before 3 periods
        let consecutive_periods_low = 2;
        let should_not_trigger = consecutive_periods_low >= CONSECUTIVE_PERIODS_THRESHOLD;
        assert!(!should_not_trigger);
    }

    #[test]
    fn test_breach_prioritization() {
        // Create multiple breaches with different deviation magnitudes
        let mut breaches = vec![
            ThresholdBreach {
                rule_id: Uuid::now_v7(),
                detected_at: Utc::now(),
                current_value: 100.0,
                baseline_mean: 50.0,
                baseline_threshold: 70.0,
                deviation_magnitude: 5.0,
                consecutive_periods: 3,
                should_trigger_tuning: true,
            },
            ThresholdBreach {
                rule_id: Uuid::now_v7(),
                detected_at: Utc::now(),
                current_value: 80.0,
                baseline_mean: 50.0,
                baseline_threshold: 70.0,
                deviation_magnitude: 3.0,
                consecutive_periods: 3,
                should_trigger_tuning: true,
            },
            ThresholdBreach {
                rule_id: Uuid::now_v7(),
                detected_at: Utc::now(),
                current_value: 120.0,
                baseline_mean: 50.0,
                baseline_threshold: 70.0,
                deviation_magnitude: 7.0,
                consecutive_periods: 3,
                should_trigger_tuning: true,
            },
        ];

        // Sort by deviation magnitude (highest first)
        breaches.sort_by(|a, b| {
            b.deviation_magnitude
                .partial_cmp(&a.deviation_magnitude)
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        // Verify sorting
        assert_eq!(breaches[0].deviation_magnitude, 7.0);
        assert_eq!(breaches[1].deviation_magnitude, 5.0);
        assert_eq!(breaches[2].deviation_magnitude, 3.0);
    }

    #[test]
    fn test_zero_mean_edge_case() {
        // Test deviation calculation when mean is zero
        let current_value = 10.0;
        let mean = 0.0;
        let std_dev = 0.0;

        let deviation = if std_dev > 0.0 {
            (current_value - mean) / std_dev
        } else if mean > 0.0 {
            current_value / mean
        } else {
            current_value
        };

        assert_eq!(deviation, 10.0); // Falls back to current_value
    }
}
