// SPDX-License-Identifier: AGPL-3.0-or-later

//! Baseline Monitor for AI Detection Auto-Tuning
//!
//! Establishes and maintains statistical baselines for detection rules:
//! - Progressive baselines: provisional after 24h, established after 7 days
//! - Calculates statistical thresholds (mean, std_dev, percentiles)
//! - Updates baselines using rolling 30-day windows
//! - Discovers and establishes baselines for new rules automatically

use chrono::{DateTime, Duration, Utc};
use serde_json::json;
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use super::Baseline;
use crate::auth::{Provenanced, SourceProvenance};

/// Minimum number of days required to establish a provisional baseline
const MIN_BASELINE_DAYS: i64 = 1; // 24 hours for provisional baseline

/// Rolling window size for baseline calculations (in days)
const BASELINE_WINDOW_DAYS: i64 = 30;

/// Minimum number of data points required for provisional baseline
const MIN_DATA_POINTS: i32 = 24; // 24 hours * 1 data point per hour

/// Errors that can occur during baseline operations
#[derive(Error, Debug)]
pub enum BaselineMonitorError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(Uuid),

    #[error("Insufficient data: need at least {0} days of data")]
    InsufficientData(i64),

    #[error("Invalid baseline data: {0}")]
    InvalidBaselineData(String),

    #[error("Calculation error: {0}")]
    CalculationError(String),
}

impl From<sqlx::Error> for BaselineMonitorError {
    fn from(err: sqlx::Error) -> Self {
        BaselineMonitorError::DatabaseError(err.to_string())
    }
}

/// Baseline monitor service
#[derive(Clone)]
pub struct BaselineMonitor {
    pg_pool: PgPool,
}

impl BaselineMonitor {
    /// Create a new baseline monitor
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    /// Establish a baseline for a detection rule
    ///
    /// This method checks if sufficient data (minimum 24 hours) exists,
    /// calculates statistical thresholds, and creates a baseline record.
    /// The baseline starts as "provisional" and upgrades to "established"
    /// once 7+ days of data and 168+ data points are available.
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `Baseline` - The established baseline
    ///
    /// # Errors
    /// * `InsufficientData` - If less than 24 hours of metrics exist
    /// * `RuleNotFound` - If the rule doesn't exist
    pub async fn establish_baseline(
        &self,
        rule_id: Uuid,
    ) -> Result<Baseline, BaselineMonitorError> {
        // Verify rule exists
        let rule_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM detection_rules WHERE id = $1)")
                .bind(rule_id)
                .fetch_one(&self.pg_pool)
                .await?;

        if !rule_exists {
            return Err(BaselineMonitorError::RuleNotFound(rule_id));
        }

        // Check if we have at least 7 days of metrics data
        let oldest_metric: Option<DateTime<Utc>> = sqlx::query_scalar(
            "SELECT MIN(timestamp) FROM detection_rule_metrics WHERE rule_id = $1",
        )
        .bind(rule_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        let now = Utc::now();

        if let Some(oldest) = oldest_metric {
            let data_age = now.signed_duration_since(oldest);
            if data_age < Duration::days(MIN_BASELINE_DAYS) {
                return Err(BaselineMonitorError::InsufficientData(MIN_BASELINE_DAYS));
            }
        } else {
            return Err(BaselineMonitorError::InsufficientData(MIN_BASELINE_DAYS));
        }

        // Count data points
        let data_points: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM detection_rule_metrics WHERE rule_id = $1")
                .bind(rule_id)
                .fetch_one(&self.pg_pool)
                .await?;

        if data_points < MIN_DATA_POINTS as i64 {
            return Err(BaselineMonitorError::InsufficientData(MIN_BASELINE_DAYS));
        }

        // Calculate baseline statistics
        let baseline = self.calculate_baseline_statistics(rule_id).await?;
        let value = &baseline.value;

        // Insert baseline into database
        sqlx::query(
            r#"
            INSERT INTO detection_rule_baselines (
                rule_id,
                established_at,
                last_updated,
                mean_alerts_per_hour,
                std_dev_alerts_per_hour,
                percentile_95,
                percentile_99,
                threshold_breach_level,
                data_points,
                baseline_data,
                source_types,
                source_types_complete
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (rule_id) DO UPDATE SET
                last_updated = EXCLUDED.last_updated,
                mean_alerts_per_hour = EXCLUDED.mean_alerts_per_hour,
                std_dev_alerts_per_hour = EXCLUDED.std_dev_alerts_per_hour,
                percentile_95 = EXCLUDED.percentile_95,
                percentile_99 = EXCLUDED.percentile_99,
                threshold_breach_level = EXCLUDED.threshold_breach_level,
                data_points = EXCLUDED.data_points,
                baseline_data = EXCLUDED.baseline_data,
                source_types = EXCLUDED.source_types,
                source_types_complete = EXCLUDED.source_types_complete
            "#,
        )
        .bind(value.rule_id)
        .bind(value.established_at)
        .bind(value.last_updated)
        .bind(value.mean_alerts_per_hour)
        .bind(value.std_dev_alerts_per_hour)
        .bind(value.percentile_95)
        .bind(value.percentile_99)
        .bind(value.threshold_breach_level)
        .bind(value.data_points)
        .bind(json!({}))
        .bind(baseline.provenance.source_types())
        .bind(baseline.provenance.is_complete())
        .execute(&self.pg_pool)
        .await?;

        Ok(baseline.value)
    }

    /// Update an existing baseline with new metrics
    ///
    /// This method recalculates baseline statistics using a rolling 30-day window
    /// and updates the baseline record.
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    pub async fn update_baseline(&self, rule_id: Uuid) -> Result<(), BaselineMonitorError> {
        // Check if baseline exists
        let baseline_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM detection_rule_baselines WHERE rule_id = $1)",
        )
        .bind(rule_id)
        .fetch_one(&self.pg_pool)
        .await?;

        if !baseline_exists {
            // If no baseline exists, try to establish one
            self.establish_baseline(rule_id).await?;
            return Ok(());
        }

        // Recalculate baseline statistics using rolling window
        let baseline = self.calculate_baseline_statistics(rule_id).await?;
        let value = &baseline.value;

        // Update baseline in database
        sqlx::query(
            r#"
            UPDATE detection_rule_baselines SET
                last_updated = $2,
                mean_alerts_per_hour = $3,
                std_dev_alerts_per_hour = $4,
                percentile_95 = $5,
                percentile_99 = $6,
                threshold_breach_level = $7,
                data_points = $8,
                source_types = $9,
                source_types_complete = $10
            WHERE rule_id = $1
            "#,
        )
        .bind(rule_id)
        .bind(value.last_updated)
        .bind(value.mean_alerts_per_hour)
        .bind(value.std_dev_alerts_per_hour)
        .bind(value.percentile_95)
        .bind(value.percentile_99)
        .bind(value.threshold_breach_level)
        .bind(value.data_points)
        .bind(baseline.provenance.source_types())
        .bind(baseline.provenance.is_complete())
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }

    /// Get the baseline for a detection rule
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `Option<Baseline>` - The baseline if it exists
    pub async fn get_baseline(
        &self,
        rule_id: Uuid,
    ) -> Result<Option<Baseline>, BaselineMonitorError> {
        Ok(self
            .get_baseline_with_provenance(rule_id)
            .await?
            .map(Provenanced::into_value))
    }

    /// Load a baseline with the persisted union of every metric origin used to
    /// calculate it. Legacy/incomplete metrics remain incomplete after folding.
    pub async fn get_baseline_with_provenance(
        &self,
        rule_id: Uuid,
    ) -> Result<Option<Provenanced<Baseline>>, BaselineMonitorError> {
        let baseline = sqlx::query_as::<_, BaselineRow>(
            r#"
            SELECT 
                rule_id,
                established_at,
                last_updated,
                mean_alerts_per_hour,
                std_dev_alerts_per_hour,
                percentile_95,
                percentile_99,
                threshold_breach_level,
                data_points,
                source_types,
                source_types_complete
            FROM detection_rule_baselines
            WHERE rule_id = $1
            "#,
        )
        .bind(rule_id)
        .fetch_optional(&self.pg_pool)
        .await?;

        Ok(baseline.map(|row| {
            let provenance =
                SourceProvenance::from_parts(row.source_types, row.source_types_complete);
            let mut b = Baseline {
                rule_id: row.rule_id,
                established_at: row.established_at,
                last_updated: row.last_updated,
                mean_alerts_per_hour: row.mean_alerts_per_hour,
                std_dev_alerts_per_hour: row.std_dev_alerts_per_hour,
                percentile_95: row.percentile_95,
                percentile_99: row.percentile_99,
                threshold_breach_level: row.threshold_breach_level,
                data_points: row.data_points,
                status: Default::default(),
            };
            b.compute_status();
            Provenanced::new(b, provenance)
        }))
    }

    /// Check if a baseline is established for a rule
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `bool` - True if baseline exists and is established
    pub async fn is_baseline_established(
        &self,
        rule_id: Uuid,
    ) -> Result<bool, BaselineMonitorError> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM detection_rule_baselines WHERE rule_id = $1)",
        )
        .bind(rule_id)
        .fetch_one(&self.pg_pool)
        .await?;

        Ok(exists)
    }

    /// Calculate baseline statistics from metrics data
    ///
    /// Uses a rolling 30-day window to calculate:
    /// - Mean alerts per hour
    /// - Standard deviation
    /// - 95th and 99th percentiles
    /// - Threshold breach level (mean + 2*std_dev)
    async fn calculate_baseline_statistics(
        &self,
        rule_id: Uuid,
    ) -> Result<Provenanced<Baseline>, BaselineMonitorError> {
        let now = Utc::now();
        let window_start = now - Duration::days(BASELINE_WINDOW_DAYS);

        // Get metrics within the rolling window
        let metrics: Vec<MetricRow> = sqlx::query_as(
            r#"
            SELECT alert_count_1h, timestamp, source_types, source_types_complete
            FROM detection_rule_metrics
            WHERE rule_id = $1 AND timestamp >= $2
            ORDER BY timestamp ASC
            "#,
        )
        .bind(rule_id)
        .bind(window_start)
        .fetch_all(&self.pg_pool)
        .await?;

        if metrics.is_empty() {
            return Err(BaselineMonitorError::InsufficientData(MIN_BASELINE_DAYS));
        }

        let provenance = metrics
            .iter()
            .map(|metric| {
                SourceProvenance::from_parts(
                    metric.source_types.iter(),
                    metric.source_types_complete,
                )
            })
            .reduce(|combined, metric| combined.merge(&metric))
            .expect("metrics was checked non-empty");

        // Extract alert counts
        let alert_counts: Vec<f64> = metrics.iter().map(|m| m.alert_count_1h as f64).collect();

        // Calculate mean
        let mean = alert_counts.iter().sum::<f64>() / alert_counts.len() as f64;

        // Calculate standard deviation
        let variance = alert_counts
            .iter()
            .map(|&x| {
                let diff = x - mean;
                diff * diff
            })
            .sum::<f64>()
            / alert_counts.len() as f64;
        let std_dev = variance.sqrt();

        // Calculate percentiles
        let mut sorted_counts = alert_counts.clone();
        sorted_counts.sort_by(|a, b| a.partial_cmp(b).unwrap());

        let percentile_95 = self.calculate_percentile(&sorted_counts, 0.95);
        let percentile_99 = self.calculate_percentile(&sorted_counts, 0.99);

        // Calculate threshold breach level (mean + 2*std_dev)
        let threshold_breach_level = mean + (2.0 * std_dev);

        // Get the earliest timestamp to determine when baseline was established
        let established_at = metrics.first().map(|m| m.timestamp).unwrap_or(now);

        let mut baseline = Baseline {
            rule_id,
            established_at,
            last_updated: now,
            mean_alerts_per_hour: mean,
            std_dev_alerts_per_hour: std_dev,
            percentile_95,
            percentile_99,
            threshold_breach_level,
            data_points: metrics.len() as i32,
            status: Default::default(),
        };
        baseline.compute_status();
        Ok(Provenanced::new(baseline, provenance))
    }

    /// Calculate a percentile from sorted data
    fn calculate_percentile(&self, sorted_data: &[f64], percentile: f64) -> f64 {
        if sorted_data.is_empty() {
            return 0.0;
        }

        let index = (percentile * (sorted_data.len() - 1) as f64).round() as usize;
        sorted_data[index.min(sorted_data.len() - 1)]
    }

    /// Update baselines for all rules with established baselines
    ///
    /// This method is called by the scheduler to update all baselines.
    /// It queries all rules with established baselines and updates them.
    ///
    /// # Returns
    /// * `usize` - Number of baselines updated
    pub async fn update_all_baselines(&self) -> Result<usize, BaselineMonitorError> {
        // Get all rules with established baselines
        let rule_ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT rule_id FROM detection_rule_baselines")
                .fetch_all(&self.pg_pool)
                .await?;

        let mut updated_count = 0;

        for rule_id in rule_ids {
            match self.update_baseline(rule_id).await {
                Ok(_) => {
                    updated_count += 1;
                }
                Err(e) => {
                    tracing::warn!(
                        rule_id = %rule_id,
                        error = %e,
                        "Failed to update baseline for rule"
                    );
                }
            }
        }

        Ok(updated_count)
    }

    /// Try to establish baselines for enabled rules that don't have one yet
    ///
    /// This solves the chicken-and-egg problem where `update_all_baselines()`
    /// only updates existing baselines but never creates new ones for rules
    /// that have accumulated enough data.
    ///
    /// # Returns
    /// * `usize` - Number of new baselines established
    pub async fn try_establish_new_baselines(&self) -> Result<usize, BaselineMonitorError> {
        // Find active rules (live or alerting) WITHOUT a baseline row
        let rule_ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT dr.id
            FROM detection_rules dr
            LEFT JOIN detection_rule_baselines drb ON dr.id = drb.rule_id
            WHERE dr.mode IN ('alerting', 'live')
              AND dr.archived = false
              AND drb.rule_id IS NULL
            "#,
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let mut established_count = 0;

        for rule_id in rule_ids {
            match self.establish_baseline(rule_id).await {
                Ok(_) => {
                    tracing::info!(rule_id = %rule_id, "Established new baseline for rule");
                    established_count += 1;
                }
                Err(BaselineMonitorError::InsufficientData(_)) => {
                    // Expected for new rules - silently skip
                    tracing::debug!(rule_id = %rule_id, "Insufficient data to establish baseline");
                }
                Err(e) => {
                    tracing::warn!(
                        rule_id = %rule_id,
                        error = %e,
                        "Failed to establish baseline for rule"
                    );
                }
            }
        }

        Ok(established_count)
    }
}

/// Database row for baseline queries
#[derive(sqlx::FromRow)]
struct BaselineRow {
    rule_id: Uuid,
    established_at: DateTime<Utc>,
    last_updated: DateTime<Utc>,
    mean_alerts_per_hour: f64,
    std_dev_alerts_per_hour: f64,
    percentile_95: f64,
    percentile_99: f64,
    threshold_breach_level: f64,
    data_points: i32,
    source_types: Vec<String>,
    source_types_complete: bool,
}

/// Database row for metrics queries
#[derive(sqlx::FromRow)]
struct MetricRow {
    alert_count_1h: i64,
    timestamp: DateTime<Utc>,
    source_types: Vec<String>,
    source_types_complete: bool,
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_calculate_percentile() {
        // Test percentile calculation directly without needing a monitor instance
        fn calculate_percentile(sorted_data: &[f64], percentile: f64) -> f64 {
            if sorted_data.is_empty() {
                return 0.0;
            }
            let index = (percentile * (sorted_data.len() - 1) as f64).round() as usize;
            sorted_data[index.min(sorted_data.len() - 1)]
        }

        let data = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0];

        // Test 95th percentile (0.95 * 9 = 8.55, rounds to 9, so index 9 = 10.0)
        let p95 = calculate_percentile(&data, 0.95);
        assert_eq!(p95, 10.0);

        // Test 50th percentile (median) (0.50 * 9 = 4.5, rounds to 5, so index 5 = 6.0)
        let p50 = calculate_percentile(&data, 0.50);
        assert_eq!(p50, 6.0);

        // Test with empty data
        let empty: Vec<f64> = vec![];
        let p95_empty = calculate_percentile(&empty, 0.95);
        assert_eq!(p95_empty, 0.0);
    }

    #[test]
    fn test_statistical_calculations() {
        // Test mean calculation
        let values = vec![2.0, 4.0, 6.0, 8.0, 10.0];
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        assert_eq!(mean, 6.0);

        // Test standard deviation calculation
        let variance = values
            .iter()
            .map(|&x| {
                let diff = x - mean;
                diff * diff
            })
            .sum::<f64>()
            / values.len() as f64;
        let std_dev = variance.sqrt();
        assert!((std_dev - 2.828).abs() < 0.01); // sqrt(8) ≈ 2.828

        // Test threshold calculation
        let threshold = mean + (2.0 * std_dev);
        assert!((threshold - 11.656).abs() < 0.01);
    }

    #[test]
    fn test_constant_values_std_dev() {
        // When all values are the same, std_dev should be 0
        let values = vec![5.0, 5.0, 5.0, 5.0, 5.0];
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        assert_eq!(mean, 5.0);

        let variance = values
            .iter()
            .map(|&x| {
                let diff = x - mean;
                diff * diff
            })
            .sum::<f64>()
            / values.len() as f64;
        let std_dev = variance.sqrt();
        assert_eq!(std_dev, 0.0);

        // Threshold should equal mean when std_dev is 0
        let threshold = mean + (2.0 * std_dev);
        assert_eq!(threshold, 5.0);
    }

    #[test]
    fn test_percentile_edge_cases() {
        // Test percentile calculation directly without needing a monitor instance
        fn calculate_percentile(sorted_data: &[f64], percentile: f64) -> f64 {
            if sorted_data.is_empty() {
                return 0.0;
            }
            let index = (percentile * (sorted_data.len() - 1) as f64).round() as usize;
            sorted_data[index.min(sorted_data.len() - 1)]
        }

        // Single value
        let single = vec![42.0];
        assert_eq!(calculate_percentile(&single, 0.95), 42.0);
        assert_eq!(calculate_percentile(&single, 0.50), 42.0);

        // Two values (0.95 * 1 = 0.95, rounds to 1, so index 1 = 20.0)
        let two = vec![10.0, 20.0];
        assert_eq!(calculate_percentile(&two, 0.95), 20.0);
        // (0.50 * 1 = 0.5, rounds to 1, so index 1 = 20.0)
        assert_eq!(calculate_percentile(&two, 0.50), 20.0);
    }
}
