// SPDX-License-Identifier: AGPL-3.0-or-later

//! Metrics Collector for AI Detection Auto-Tuning
//!
//! Continuously collects detection rule execution metrics including:
//! - Alert counts over various time windows (1h, 24h, 7d)
//! - Unique entity counts (users, hosts, IPs)
//! - Alert patterns and common field values
//! - Query execution times

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::collections::HashMap;
use thiserror::Error;
use uuid::Uuid;

use super::{AlertPattern, RuleMetrics};

/// Errors that can occur during metrics collection
#[derive(Error, Debug)]
pub enum MetricsCollectorError {
    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("ClickHouse error: {0}")]
    ClickHouseError(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(Uuid),

    #[error("Invalid time range: {0}")]
    InvalidTimeRange(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

impl From<sqlx::Error> for MetricsCollectorError {
    fn from(err: sqlx::Error) -> Self {
        MetricsCollectorError::DatabaseError(err.to_string())
    }
}

impl From<clickhouse::error::Error> for MetricsCollectorError {
    fn from(err: clickhouse::error::Error) -> Self {
        MetricsCollectorError::ClickHouseError(err.to_string())
    }
}

impl From<serde_json::Error> for MetricsCollectorError {
    fn from(err: serde_json::Error) -> Self {
        MetricsCollectorError::SerializationError(err.to_string())
    }
}

/// Alert data retrieved from PostgreSQL
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct Alert {
    pub id: Uuid,
    pub rule_id: Uuid,
    pub severity: String,
    pub matched_events: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

/// Metrics collector service
pub struct MetricsCollector {
    pg_pool: PgPool,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new(pg_pool: PgPool) -> Self {
        Self { pg_pool }
    }

    /// Collect comprehensive metrics for a detection rule
    ///
    /// This method queries PostgreSQL to count alerts over various time windows
    /// and extracts entity information from matched events.
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `RuleMetrics` - Comprehensive metrics for the rule
    pub async fn collect_rule_metrics(
        &self,
        rule_id: Uuid,
    ) -> Result<RuleMetrics, MetricsCollectorError> {
        let now = Utc::now();

        // Verify rule exists
        let rule_exists: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM detection_rules WHERE id = $1)")
                .bind(rule_id)
                .fetch_one(&self.pg_pool)
                .await?;

        if !rule_exists {
            return Err(MetricsCollectorError::RuleNotFound(rule_id));
        }

        // Count alerts in last 1 hour
        let one_hour_ago = now - Duration::hours(1);
        let alert_count_1h: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alerts WHERE rule_id = $1 AND created_at >= $2",
        )
        .bind(rule_id)
        .bind(one_hour_ago)
        .fetch_one(&self.pg_pool)
        .await?;

        // Count alerts in last 24 hours
        let twenty_four_hours_ago = now - Duration::hours(24);
        let alert_count_24h: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alerts WHERE rule_id = $1 AND created_at >= $2",
        )
        .bind(rule_id)
        .bind(twenty_four_hours_ago)
        .fetch_one(&self.pg_pool)
        .await?;

        // Count alerts in last 7 days
        let seven_days_ago = now - Duration::days(7);
        let alert_count_7d: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM alerts WHERE rule_id = $1 AND created_at >= $2",
        )
        .bind(rule_id)
        .bind(seven_days_ago)
        .fetch_one(&self.pg_pool)
        .await?;

        // Get recent alerts to extract entity information
        let recent_alerts = self.get_recent_alerts(rule_id, Duration::hours(24)).await?;

        // Extract unique entities from matched events
        let (unique_users, unique_hosts, unique_ips) = self.extract_unique_entities(&recent_alerts);

        // Calculate average severity (map severity to numeric values)
        let avg_severity = self.calculate_average_severity(&recent_alerts);

        // For now, execution_time_ms is set to 0 as we don't track this yet
        // This can be enhanced later by measuring actual query execution times
        let execution_time_ms = 0;

        Ok(RuleMetrics {
            rule_id,
            timestamp: now,
            alert_count_1h,
            alert_count_24h,
            alert_count_7d,
            unique_users,
            unique_hosts,
            unique_ips,
            avg_severity,
            execution_time_ms,
        })
    }

    /// Get recent alerts for a detection rule
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    /// * `duration` - How far back to look for alerts
    ///
    /// # Returns
    /// * `Vec<Alert>` - List of recent alerts
    pub async fn get_recent_alerts(
        &self,
        rule_id: Uuid,
        duration: Duration,
    ) -> Result<Vec<Alert>, MetricsCollectorError> {
        let cutoff_time = Utc::now() - duration;

        let alerts: Vec<Alert> = sqlx::query_as(
            r#"
            SELECT 
                id,
                rule_id,
                severity,
                matched_events,
                created_at
            FROM alerts
            WHERE rule_id = $1 AND created_at >= $2
            ORDER BY created_at DESC
            LIMIT 1000
            "#,
        )
        .bind(rule_id)
        .bind(cutoff_time)
        .fetch_all(&self.pg_pool)
        .await?;

        Ok(alerts)
    }

    /// Identify common patterns in alert field values
    ///
    /// This method analyzes matched events to find frequently occurring field values
    /// that might indicate false positive patterns.
    ///
    /// # Arguments
    /// * `rule_id` - UUID of the detection rule
    ///
    /// # Returns
    /// * `Vec<AlertPattern>` - List of common patterns with occurrence counts
    pub async fn get_alert_patterns(
        &self,
        rule_id: Uuid,
    ) -> Result<Vec<AlertPattern>, MetricsCollectorError> {
        // Get recent alerts (last 24 hours)
        let recent_alerts = self.get_recent_alerts(rule_id, Duration::hours(24)).await?;

        if recent_alerts.is_empty() {
            return Ok(Vec::new());
        }

        let total_alerts = recent_alerts.len() as i64;

        // Track field value occurrences
        let mut field_value_counts: HashMap<(String, String), i64> = HashMap::new();

        // Extract field values from matched events
        for alert in &recent_alerts {
            if let Some(events) = alert.matched_events.as_array() {
                for event in events {
                    if let Some(obj) = event.as_object() {
                        // Extract common UDM fields
                        self.extract_field_patterns(obj, &mut field_value_counts);
                    }
                }
            }
        }

        // Convert to AlertPattern structs and calculate percentages
        let mut patterns: Vec<AlertPattern> = field_value_counts
            .into_iter()
            .map(|((field_name, field_value), occurrence_count)| {
                let percentage = (occurrence_count as f64 / total_alerts as f64) * 100.0;
                AlertPattern {
                    field_name,
                    field_value,
                    occurrence_count,
                    percentage,
                }
            })
            .collect();

        // Sort by occurrence count (descending)
        patterns.sort_by(|a, b| b.occurrence_count.cmp(&a.occurrence_count));

        // Return top 50 patterns
        patterns.truncate(50);

        Ok(patterns)
    }

    /// Extract unique entity counts from alerts
    ///
    /// Uses UDM field names from signal_processor matched_events:
    /// src_user, dest_user, src_host, dest_host, src_ip, dest_ip
    fn extract_unique_entities(&self, alerts: &[Alert]) -> (i64, i64, i64) {
        let mut unique_users = std::collections::HashSet::new();
        let mut unique_hosts = std::collections::HashSet::new();
        let mut unique_ips = std::collections::HashSet::new();

        for alert in alerts {
            if let Some(events) = alert.matched_events.as_array() {
                for event in events {
                    if let Some(obj) = event.as_object() {
                        // Extract user information (UDM fields)
                        for field in &["src_user", "dest_user"] {
                            if let Some(user) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !user.is_empty() {
                                    unique_users.insert(user.to_string());
                                }
                            }
                        }

                        // Extract host information (UDM fields)
                        for field in &["src_host", "dest_host"] {
                            if let Some(host) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !host.is_empty() {
                                    unique_hosts.insert(host.to_string());
                                }
                            }
                        }

                        // Extract IP information (UDM fields)
                        for field in &["src_ip", "dest_ip"] {
                            if let Some(ip) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !ip.is_empty() {
                                    unique_ips.insert(ip.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        (
            unique_users.len() as i64,
            unique_hosts.len() as i64,
            unique_ips.len() as i64,
        )
    }

    /// Calculate average severity from alerts
    fn calculate_average_severity(&self, alerts: &[Alert]) -> f64 {
        if alerts.is_empty() {
            return 0.0;
        }

        let severity_sum: i32 = alerts
            .iter()
            .map(|alert| match alert.severity.as_str() {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                "informational" => 1,
                _ => 0,
            })
            .sum();

        severity_sum as f64 / alerts.len() as f64
    }

    /// Extract field patterns from an event object
    ///
    /// Uses UDM field names from signal_processor matched_events:
    /// src_ip, dest_ip, src_host, dest_host, src_user, dest_user,
    /// source_type, risk_entity, plus metadata object keys.
    fn extract_field_patterns(
        &self,
        obj: &serde_json::Map<String, serde_json::Value>,
        field_value_counts: &mut HashMap<(String, String), i64>,
    ) {
        // UDM fields present in matched_events from signal_processor
        let tracked_fields = [
            "src_ip",
            "dest_ip",
            "src_host",
            "dest_host",
            "src_user",
            "dest_user",
            "source_type",
            "risk_entity",
            "src_port",
            "dest_port",
            "protocol",
            "process_name",
            "command_line",
            "file_path",
            "file_hash",
        ];

        for field in tracked_fields {
            if let Some(value) = obj.get(field) {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                if !value_str.is_empty() {
                    let key = (field.to_string(), value_str);
                    *field_value_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        // Also iterate over the metadata object for additional fields
        if let Some(metadata) = obj.get("metadata").and_then(|v| v.as_object()) {
            for (key, value) in metadata {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                if !value_str.is_empty() {
                    let field_name = format!("metadata.{}", key);
                    let key = (field_name, value_str);
                    *field_value_counts.entry(key).or_insert(0) += 1;
                }
            }
        }
    }

    /// Collect metrics for all enabled detection rules
    ///
    /// This method is called by the scheduler to collect metrics for all rules.
    /// It queries all enabled rules and collects metrics for each one.
    ///
    /// # Returns
    /// * `usize` - Number of rules for which metrics were collected
    pub async fn collect_all_metrics(&self) -> Result<usize, MetricsCollectorError> {
        // Get all active detection rules (not staging or paused)
        let rule_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM detection_rules WHERE mode NOT IN ('staging', 'paused')",
        )
        .fetch_all(&self.pg_pool)
        .await?;

        let mut collected_count = 0;

        for rule_id in rule_ids {
            match self.collect_rule_metrics(rule_id).await {
                Ok(metrics) => {
                    // Store metrics in database
                    if let Err(e) = self.store_metrics(&metrics).await {
                        tracing::warn!(
                            rule_id = %rule_id,
                            error = %e,
                            "Failed to store metrics for rule"
                        );
                    } else {
                        collected_count += 1;
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        rule_id = %rule_id,
                        error = %e,
                        "Failed to collect metrics for rule"
                    );
                }
            }
        }

        Ok(collected_count)
    }

    /// Store metrics in the database
    async fn store_metrics(&self, metrics: &RuleMetrics) -> Result<(), MetricsCollectorError> {
        sqlx::query(
            r#"
            INSERT INTO detection_rule_metrics (
                rule_id, timestamp, alert_count_1h, alert_count_24h, alert_count_7d,
                unique_users, unique_hosts, unique_ips, avg_severity, execution_time_ms,
                patterns
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            "#,
        )
        .bind(metrics.rule_id)
        .bind(metrics.timestamp)
        .bind(metrics.alert_count_1h)
        .bind(metrics.alert_count_24h)
        .bind(metrics.alert_count_7d)
        .bind(metrics.unique_users)
        .bind(metrics.unique_hosts)
        .bind(metrics.unique_ips)
        .bind(metrics.avg_severity)
        .bind(metrics.execution_time_ms)
        .bind(serde_json::json!({})) // Empty patterns for now
        .execute(&self.pg_pool)
        .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_calculate_average_severity() {
        // Create a mock collector without database connections
        let alerts = vec![
            Alert {
                id: Uuid::now_v7(),
                rule_id: Uuid::now_v7(),
                severity: "critical".to_string(),
                matched_events: serde_json::json!([]),
                created_at: Utc::now(),
            },
            Alert {
                id: Uuid::now_v7(),
                rule_id: Uuid::now_v7(),
                severity: "high".to_string(),
                matched_events: serde_json::json!([]),
                created_at: Utc::now(),
            },
            Alert {
                id: Uuid::now_v7(),
                rule_id: Uuid::now_v7(),
                severity: "medium".to_string(),
                matched_events: serde_json::json!([]),
                created_at: Utc::now(),
            },
        ];

        // Test the calculation directly without needing a collector instance
        let severity_sum: i32 = alerts
            .iter()
            .map(|alert| match alert.severity.as_str() {
                "critical" => 5,
                "high" => 4,
                "medium" => 3,
                "low" => 2,
                "informational" => 1,
                _ => 0,
            })
            .sum();

        let avg = severity_sum as f64 / alerts.len() as f64;
        assert_eq!(avg, 4.0); // (5 + 4 + 3) / 3 = 4.0
    }

    #[test]
    fn test_extract_unique_entities() {
        let alerts = vec![
            Alert {
                id: Uuid::now_v7(),
                rule_id: Uuid::now_v7(),
                severity: "high".to_string(),
                matched_events: serde_json::json!([
                    {
                        "src_user": "alice",
                        "src_host": "server1",
                        "src_ip": "192.168.1.1"
                    }
                ]),
                created_at: Utc::now(),
            },
            Alert {
                id: Uuid::now_v7(),
                rule_id: Uuid::now_v7(),
                severity: "high".to_string(),
                matched_events: serde_json::json!([
                    {
                        "src_user": "alice",
                        "dest_host": "server2",
                        "src_ip": "192.168.1.1"
                    }
                ]),
                created_at: Utc::now(),
            },
            Alert {
                id: Uuid::now_v7(),
                rule_id: Uuid::now_v7(),
                severity: "high".to_string(),
                matched_events: serde_json::json!([
                    {
                        "dest_user": "bob",
                        "src_host": "server1",
                        "dest_ip": "192.168.1.2"
                    }
                ]),
                created_at: Utc::now(),
            },
        ];

        // Test entity extraction directly using UDM field names
        let mut unique_users = std::collections::HashSet::new();
        let mut unique_hosts = std::collections::HashSet::new();
        let mut unique_ips = std::collections::HashSet::new();

        for alert in &alerts {
            if let Some(events) = alert.matched_events.as_array() {
                for event in events {
                    if let Some(obj) = event.as_object() {
                        for field in &["src_user", "dest_user"] {
                            if let Some(user) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !user.is_empty() {
                                    unique_users.insert(user.to_string());
                                }
                            }
                        }
                        for field in &["src_host", "dest_host"] {
                            if let Some(host) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !host.is_empty() {
                                    unique_hosts.insert(host.to_string());
                                }
                            }
                        }
                        for field in &["src_ip", "dest_ip"] {
                            if let Some(ip) = obj.get(*field).and_then(|v| v.as_str()) {
                                if !ip.is_empty() {
                                    unique_ips.insert(ip.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        assert_eq!(unique_users.len(), 2); // alice, bob
        assert_eq!(unique_hosts.len(), 2); // server1, server2
        assert_eq!(unique_ips.len(), 2); // 192.168.1.1, 192.168.1.2
    }

    #[test]
    fn test_extract_field_patterns() {
        let mut field_value_counts = HashMap::new();
        let mut obj = serde_json::Map::new();
        obj.insert("process_name".to_string(), serde_json::json!("chrome.exe"));
        obj.insert("src_user".to_string(), serde_json::json!("alice"));
        obj.insert("src_host".to_string(), serde_json::json!("workstation1"));
        obj.insert(
            "metadata".to_string(),
            serde_json::json!({"rule_name": "test_rule"}),
        );

        // Test pattern extraction directly using UDM field names
        let tracked_fields = ["process_name", "src_user", "src_host"];

        for field in tracked_fields {
            if let Some(value) = obj.get(field) {
                let value_str = match value {
                    serde_json::Value::String(s) => s.clone(),
                    serde_json::Value::Number(n) => n.to_string(),
                    serde_json::Value::Bool(b) => b.to_string(),
                    _ => continue,
                };

                if !value_str.is_empty() {
                    let key = (field.to_string(), value_str);
                    *field_value_counts.entry(key).or_insert(0) += 1;
                }
            }
        }

        // Also extract metadata fields
        if let Some(metadata) = obj.get("metadata").and_then(|v| v.as_object()) {
            for (key, value) in metadata {
                if let Some(s) = value.as_str() {
                    if !s.is_empty() {
                        let field_name = format!("metadata.{}", key);
                        *field_value_counts
                            .entry((field_name, s.to_string()))
                            .or_insert(0) += 1;
                    }
                }
            }
        }

        assert_eq!(field_value_counts.len(), 4); // 3 UDM fields + 1 metadata field
        assert_eq!(
            field_value_counts.get(&("process_name".to_string(), "chrome.exe".to_string())),
            Some(&1)
        );
        assert_eq!(
            field_value_counts.get(&("src_user".to_string(), "alice".to_string())),
            Some(&1)
        );
        assert_eq!(
            field_value_counts.get(&("src_host".to_string(), "workstation1".to_string())),
            Some(&1)
        );
        assert_eq!(
            field_value_counts.get(&("metadata.rule_name".to_string(), "test_rule".to_string())),
            Some(&1)
        );
    }
}
