// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source-scoped reads for persisted tuning analytics (NAN-2086).
//!
//! Metrics, baselines, and threshold breaches are frozen aggregates. Their
//! producers stamp the immutable union of every contributing origin plus a
//! completeness bit. These reads re-evaluate that stamp against the current
//! viewer scope on every request, so restricting a source after collection
//! revokes the derived artifacts immediately.

use super::TuningRepository;
use crate::tuning::scope::TuningScope;
use crate::tuning::types::{Baseline, RuleMetrics, ThresholdBreach};
use anyhow::Result;
use uuid::Uuid;

impl TuningRepository {
    /// Load one baseline if its complete origin manifest is visible to `scope`.
    ///
    /// A restricted reader receives `None` for denied, mixed-source, and
    /// legacy/incomplete rows, identical to a rule with no baseline.
    /// Background/system callers pass [`TuningScope::system`].
    pub async fn get_baseline_for_scope(
        &self,
        rule_id: Uuid,
        scope: &TuningScope,
    ) -> Result<Option<Baseline>> {
        let mut sql = String::from(
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
                data_points
            FROM detection_rule_baselines
            WHERE rule_id = $1
            "#,
        );
        let scoped = !scope.is_unrestricted();
        if scoped {
            sql.push_str(&TuningScope::sql_predicate(
                "source_types",
                "source_types_complete",
                2,
            ));
        }

        let mut query = sqlx::query_as::<_, Baseline>(&sql).bind(rule_id);
        if scoped {
            query = query.bind(scope.deny_bind_values().to_vec());
        }

        let mut baseline = query.fetch_optional(&self.pool).await?;
        if let Some(value) = baseline.as_mut() {
            value.compute_status();
        }
        Ok(baseline)
    }

    /// List metrics visible under the reader's current source scope.
    ///
    /// The provenance predicate is applied before ordering and limiting. This
    /// prevents denied rows from consuming page slots or turning page length
    /// into an activity oracle.
    pub async fn list_metrics_for_scope(
        &self,
        rule_id: Uuid,
        limit: i64,
        scope: &TuningScope,
    ) -> Result<Vec<RuleMetrics>> {
        let mut sql = String::from(
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
            "#,
        );
        let scoped = !scope.is_unrestricted();
        let limit_param = if scoped {
            sql.push_str(&TuningScope::sql_predicate(
                "source_types",
                "source_types_complete",
                2,
            ));
            3
        } else {
            2
        };
        sql.push_str(&format!(" ORDER BY timestamp DESC LIMIT ${limit_param}"));

        let mut query = sqlx::query_as::<_, RuleMetrics>(&sql).bind(rule_id);
        if scoped {
            query = query.bind(scope.deny_bind_values().to_vec());
        }
        query = query.bind(limit);

        Ok(query.fetch_all(&self.pool).await?)
    }

    /// List threshold breaches visible under the reader's current source scope.
    ///
    /// Mixed-source decisions fail closed if any metric or baseline contributor
    /// is denied. Legacy rows have `source_types_complete = FALSE` and are
    /// hidden from every restricted reader.
    pub async fn list_breaches_for_scope(
        &self,
        rule_id: Uuid,
        limit: i64,
        scope: &TuningScope,
    ) -> Result<Vec<ThresholdBreach>> {
        let mut sql = String::from(
            r#"
            SELECT
                rule_id,
                detected_at,
                current_value,
                baseline_mean,
                baseline_threshold,
                deviation_magnitude,
                consecutive_periods,
                tuning_triggered
            FROM detection_threshold_breaches
            WHERE rule_id = $1
            "#,
        );
        let scoped = !scope.is_unrestricted();
        let limit_param = if scoped {
            sql.push_str(&TuningScope::sql_predicate(
                "source_types",
                "source_types_complete",
                2,
            ));
            3
        } else {
            2
        };
        sql.push_str(&format!(" ORDER BY detected_at DESC LIMIT ${limit_param}"));

        let mut query = sqlx::query_as::<_, ThresholdBreach>(&sql).bind(rule_id);
        if scoped {
            query = query.bind(scope.deny_bind_values().to_vec());
        }
        query = query.bind(limit);

        Ok(query.fetch_all(&self.pool).await?)
    }
}
