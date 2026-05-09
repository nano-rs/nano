// SPDX-License-Identifier: AGPL-3.0-or-later

//! Data collector for SIEM health metrics
//!
//! Queries ClickHouse for ingestion/parsing metrics and PostgreSQL for detection metrics.

use chrono::Utc;
use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use tracing::{info, warn};

use super::types::*;
use crate::db::TableNames;

/// Collect all health metrics from ClickHouse and PostgreSQL
pub async fn collect_metrics(
    pool: &PgPool,
    ch_client: Option<&ClickHouseClient>,
    is_clustered: bool,
) -> CollectedMetrics {
    let ingestion = collect_ingestion_metrics(ch_client, is_clustered).await;
    let parsing = collect_parsing_metrics(ch_client, is_clustered).await;
    let enrichment = collect_enrichment_metrics(ch_client, is_clustered).await;
    let detection = collect_detection_metrics(pool).await;
    let alerting = collect_alerting_metrics(pool).await;

    CollectedMetrics {
        ingestion,
        parsing,
        enrichment,
        detection,
        alerting,
        collected_at: Utc::now(),
    }
}

/// Collect ingestion health metrics from ClickHouse
async fn collect_ingestion_metrics(
    ch_client: Option<&ClickHouseClient>,
    is_clustered: bool,
) -> IngestionMetrics {
    let ch = match ch_client {
        Some(ch) => ch,
        None => {
            warn!("ClickHouse unavailable, returning empty ingestion metrics");
            return IngestionMetrics {
                source_volumes: vec![],
                total_events_24h: 0,
                total_events_prior_24h: 0,
                silent_sources: vec![],
            };
        }
    };

    // Get per-source-type volumes for last 24h and prior 24h
    let logs_table = TableNames::new(is_clustered).read("logs");
    let sql = format!(
        r#"
        SELECT
            source_type,
            countIf(timestamp >= now() - INTERVAL 24 HOUR) AS count_24h,
            countIf(timestamp >= now() - INTERVAL 48 HOUR AND timestamp < now() - INTERVAL 24 HOUR) AS count_prior_24h
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 48 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        ORDER BY count_24h DESC
    "#
    );

    let mut source_volumes: Vec<SourceVolumeMetric> = Vec::new();
    let mut total_24h: u64 = 0;
    let mut total_prior_24h: u64 = 0;
    let mut silent_sources: Vec<String> = Vec::new();

    match ch.query(&sql).fetch_all::<(String, u64, u64)>().await {
        Ok(rows) => {
            for (source_type, count_24h, count_prior_24h) in rows {
                total_24h += count_24h;
                total_prior_24h += count_prior_24h;

                let change_pct = if count_prior_24h > 0 {
                    ((count_24h as f64 - count_prior_24h as f64) / count_prior_24h as f64) * 100.0
                } else if count_24h > 0 {
                    100.0 // New source
                } else {
                    0.0
                };

                if count_24h == 0 && count_prior_24h > 0 {
                    silent_sources.push(source_type.clone());
                }

                source_volumes.push(SourceVolumeMetric {
                    source_type,
                    count_24h,
                    count_prior_24h,
                    change_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect ingestion metrics: {}", e);
        }
    }

    info!(
        "Collected ingestion metrics: {} source types, {} events (24h), {} silent sources",
        source_volumes.len(),
        total_24h,
        silent_sources.len()
    );

    IngestionMetrics {
        source_volumes,
        total_events_24h: total_24h,
        total_events_prior_24h: total_prior_24h,
        silent_sources,
    }
}

/// Collect parsing health metrics from ClickHouse
async fn collect_parsing_metrics(
    ch_client: Option<&ClickHouseClient>,
    is_clustered: bool,
) -> ParsingMetrics {
    let ch = match ch_client {
        Some(ch) => ch,
        None => {
            warn!("ClickHouse unavailable, returning empty parsing metrics");
            return ParsingMetrics {
                field_coverage: vec![],
                high_ext_sources: vec![],
            };
        }
    };

    // Field coverage: percentage of events where key fields are populated
    let logs_table = TableNames::new(is_clustered).read("logs");
    let coverage_sql = build_field_coverage_sql(&logs_table);

    let mut field_coverage: Vec<FieldCoverageMetric> = Vec::new();
    match ch
        .query(&coverage_sql)
        .fetch_all::<(String, u64, f64, f64, f64, f64)>()
        .await
    {
        Ok(rows) => {
            for (source_type, total_events, src_ip_pct, user_pct, event_type_pct, message_pct) in
                rows
            {
                field_coverage.push(FieldCoverageMetric {
                    source_type,
                    total_events,
                    src_ip_filled_pct: src_ip_pct,
                    user_filled_pct: user_pct,
                    event_type_filled_pct: event_type_pct,
                    message_filled_pct: message_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect field coverage metrics: {}", e);
        }
    }

    let ext_sql = build_ext_usage_sql(&logs_table);

    let mut high_ext_sources: Vec<ExtUsageMetric> = Vec::new();
    match ch.query(&ext_sql).fetch_all::<(String, u64, f64)>().await {
        Ok(rows) => {
            for (source_type, total_events, ext_pct) in rows {
                high_ext_sources.push(ExtUsageMetric {
                    source_type,
                    total_events,
                    ext_usage_pct: ext_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect ext usage metrics: {}", e);
        }
    }

    info!(
        "Collected parsing metrics: {} source types with coverage, {} with high ext usage",
        field_coverage.len(),
        high_ext_sources.len()
    );

    ParsingMetrics {
        field_coverage,
        high_ext_sources,
    }
}

/// Collect enrichment health metrics from ClickHouse.
///
/// Computes fleet-wide fill rates for GeoIP / ASN / IOC / user-identity
/// columns over the last 24h, plus a per-source coverage breakdown for the
/// top sources by event volume.
async fn collect_enrichment_metrics(
    ch_client: Option<&ClickHouseClient>,
    is_clustered: bool,
) -> EnrichmentMetrics {
    let empty = EnrichmentMetrics {
        total_events_24h: 0,
        geoip_fill_pct: 0.0,
        asn_fill_pct: 0.0,
        ioc_hit_pct: 0.0,
        identity_fill_pct: 0.0,
        per_source_coverage: vec![],
    };
    let ch = match ch_client {
        Some(ch) => ch,
        None => {
            warn!("ClickHouse unavailable, returning empty enrichment metrics");
            return empty;
        }
    };

    let logs_table = TableNames::new(is_clustered).read("logs");

    // Fleet-wide rollup
    let rollup_sql = format!(
        r#"
        SELECT
            count() AS total_events,
            countIf(enriched_src_country != '') * 100.0 / count() AS geoip_pct,
            countIf(enriched_src_asn != '') * 100.0 / count() AS asn_pct,
            countIf(ioc_confidence > 0) * 100.0 / count() AS ioc_pct,
            countIf(user_identity_department != '') * 100.0 / count() AS identity_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        "#
    );

    let mut rollup = empty.clone();
    match ch
        .query(&rollup_sql)
        .fetch_one::<(u64, f64, f64, f64, f64)>()
        .await
    {
        Ok((total, geoip, asn, ioc, identity)) => {
            rollup.total_events_24h = total;
            // Guard against NaN: ClickHouse `countIf * 100.0 / count()` returns
            // NaN when no rows match. Short-circuit to zeros so the API never
            // emits NaN, which doesn't survive JSON serialization cleanly.
            if total == 0 {
                return empty;
            }
            rollup.geoip_fill_pct = geoip;
            rollup.asn_fill_pct = asn;
            rollup.ioc_hit_pct = ioc;
            rollup.identity_fill_pct = identity;
        }
        Err(e) => {
            warn!("Failed to collect enrichment rollup: {}", e);
            return empty;
        }
    }

    // Per-source coverage (top 20 by volume, min 100 events to avoid noise)
    let per_source_sql = format!(
        r#"
        SELECT
            source_type,
            count() AS total_events,
            countIf(enriched_src_country != '') * 100.0 / count() AS geoip_pct,
            countIf(ioc_confidence > 0) * 100.0 / count() AS ioc_pct,
            countIf(user_identity_department != '') * 100.0 / count() AS identity_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100
        ORDER BY total_events DESC
        LIMIT 20
        "#
    );

    let mut per_source: Vec<EnrichmentCoverageMetric> = Vec::new();
    match ch
        .query(&per_source_sql)
        .fetch_all::<(String, u64, f64, f64, f64)>()
        .await
    {
        Ok(rows) => {
            for (source_type, total_events, geoip_pct, ioc_pct, identity_pct) in rows {
                per_source.push(EnrichmentCoverageMetric {
                    source_type,
                    total_events,
                    geoip_pct,
                    ioc_pct,
                    identity_pct,
                });
            }
        }
        Err(e) => {
            warn!("Failed to collect per-source enrichment coverage: {}", e);
        }
    }
    rollup.per_source_coverage = per_source;

    info!(
        "Collected enrichment metrics: {} events, geoip={:.1}%, ioc={:.1}%, identity={:.1}%",
        rollup.total_events_24h,
        rollup.geoip_fill_pct,
        rollup.ioc_hit_pct,
        rollup.identity_fill_pct
    );

    rollup
}

/// Collect detection health metrics from PostgreSQL
async fn collect_detection_metrics(pool: &PgPool) -> DetectionMetrics {
    // Total enabled rules
    let total_enabled: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM detection_rules WHERE mode != 'paused'")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    // Rules by mode
    let rules_by_mode: Vec<RulesByMode> = match sqlx::query_as::<_, (String, i64)>(
        "SELECT mode, COUNT(*) FROM detection_rules WHERE mode != 'paused' GROUP BY mode",
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(mode, count)| RulesByMode { mode, count })
            .collect(),
        Err(e) => {
            warn!("Failed to collect rules by mode: {}", e);
            vec![]
        }
    };

    // Stale rules: enabled rules that haven't matched in 30+ days (or never)
    let stale_rules: Vec<StaleRule> =
        match sqlx::query_as::<_, (String, Option<chrono::DateTime<Utc>>)>(
            r#"
        SELECT name, last_match_at
        FROM detection_rules
        WHERE mode = 'alerting'
          AND (last_match_at IS NULL OR last_match_at < NOW() - INTERVAL '30 days')
        ORDER BY last_match_at ASC NULLS FIRST
        LIMIT 50
        "#,
        )
        .fetch_all(pool)
        .await
        {
            Ok(rows) => rows
                .into_iter()
                .map(|(name, last_match)| {
                    let days = match last_match {
                        Some(dt) => (Utc::now() - dt).num_days(),
                        None => 999,
                    };
                    StaleRule {
                        rule_name: name,
                        last_matched: last_match,
                        days_since_match: days,
                    }
                })
                .collect(),
            Err(e) => {
                warn!("Failed to collect stale rules: {}", e);
                vec![]
            }
        };

    // Noisy rules: rules with high match counts in last 24h
    let noisy_rules: Vec<NoisyRule> = match sqlx::query_as::<_, (String, i64, String)>(
        r#"
        SELECT dr.name, COALESCE(ds.match_count, 0) AS matches, dr.severity
        FROM detection_rules dr
        LEFT JOIN detection_daily_stats ds ON dr.id = ds.rule_id AND ds.date = CURRENT_DATE
        WHERE dr.mode != 'paused'
          AND COALESCE(ds.match_count, 0) > 1000
        ORDER BY matches DESC
        LIMIT 20
        "#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(name, count, severity)| NoisyRule {
                rule_name: name,
                matches_24h: count,
                severity,
            })
            .collect(),
        Err(e) => {
            warn!("Failed to collect noisy rules: {}", e);
            vec![]
        }
    };

    // Alerts by severity in last 24h
    let alerts_24h: Vec<AlertsBySeverity> = match sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT severity, COUNT(*)
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY severity
        "#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(severity, count)| AlertsBySeverity { severity, count })
            .collect(),
        Err(e) => {
            warn!("Failed to collect alerts by severity: {}", e);
            vec![]
        }
    };

    info!(
        "Collected detection metrics: {} enabled rules, {} stale, {} noisy",
        total_enabled,
        stale_rules.len(),
        noisy_rules.len()
    );

    DetectionMetrics {
        total_enabled_rules: total_enabled,
        rules_by_mode,
        stale_rules,
        noisy_rules,
        alerts_24h_by_severity: alerts_24h,
    }
}

/// Collect alerting health metrics from PostgreSQL.
///
/// Volume + status counts come from the `alerts` table; routing health from
/// `webhooks` + `webhook_delivery_log` + `queue_routing_rules`. MTTA is
/// computed inline against `alerts.acknowledged_at - alerts.created_at`
/// because no pre-built helper exists.
async fn collect_alerting_metrics(pool: &PgPool) -> AlertingMetrics {
    let total_alerts_24h: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '24 hours'",
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let total_alerts_prior_24h: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*) FROM alerts
        WHERE created_at >= NOW() - INTERVAL '48 hours'
          AND created_at <  NOW() - INTERVAL '24 hours'
        "#,
    )
    .fetch_one(pool)
    .await
    .unwrap_or(0);

    let by_status: Vec<AlertStatusCount> = match sqlx::query_as::<_, (String, i64)>(
        r#"
        SELECT status, COUNT(*)
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
        GROUP BY status
        "#,
    )
    .fetch_all(pool)
    .await
    {
        Ok(rows) => rows
            .into_iter()
            .map(|(status, count)| AlertStatusCount { status, count })
            .collect(),
        Err(e) => {
            warn!("Failed to collect alerts by status: {}", e);
            vec![]
        }
    };

    // MTTA: average minutes between created_at and acknowledged_at, only over
    // alerts that were acknowledged in the window.
    let mean_mtta_minutes: Option<f64> = sqlx::query_scalar(
        r#"
        SELECT AVG(EXTRACT(EPOCH FROM (acknowledged_at - created_at)) / 60.0)::float8
        FROM alerts
        WHERE created_at >= NOW() - INTERVAL '24 hours'
          AND acknowledged_at IS NOT NULL
        "#,
    )
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    let active_webhooks: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM webhooks WHERE enabled = true")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    // Webhook delivery success rate over the last 24h. Both columns are
    // SELECTed with explicit casts so sqlx can infer the row type.
    let (webhook_deliveries_24h, webhook_success_pct): (i64, Option<f64>) =
        match sqlx::query_as::<_, (i64, i64)>(
            r#"
        SELECT
            COUNT(*)::bigint AS total,
            COUNT(*) FILTER (WHERE success = true)::bigint AS succeeded
        FROM webhook_delivery_log
        WHERE delivered_at >= NOW() - INTERVAL '24 hours'
        "#,
        )
        .fetch_one(pool)
        .await
        {
            Ok((total, succeeded)) => {
                let pct = if total > 0 {
                    Some((succeeded as f64 / total as f64) * 100.0)
                } else {
                    None
                };
                (total, pct)
            }
            Err(e) => {
                warn!("Failed to collect webhook delivery stats: {}", e);
                (0, None)
            }
        };

    let active_routing_rules: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM queue_routing_rules WHERE enabled = true")
            .fetch_one(pool)
            .await
            .unwrap_or(0);

    info!(
        "Collected alerting metrics: {} alerts (24h, prior {}), MTTA {:?}m, {} webhooks, {} routing rules",
        total_alerts_24h, total_alerts_prior_24h, mean_mtta_minutes, active_webhooks, active_routing_rules
    );

    AlertingMetrics {
        total_alerts_24h,
        total_alerts_prior_24h,
        by_status,
        mean_mtta_minutes,
        active_webhooks,
        webhook_deliveries_24h,
        webhook_success_pct,
        active_routing_rules,
    }
}

/// Build the per-source field-coverage SQL. Extracted as a pure function so
/// regression tests can pin its shape — the inline version previously had a
/// JSON-vs-String comparison bug (NAN-614) that is hard to catch by reading.
fn build_field_coverage_sql(logs_table: &str) -> String {
    format!(
        r#"
        SELECT
            source_type,
            count() AS total_events,
            countIf(src_ip != '') * 100.0 / count() AS src_ip_pct,
            countIf(user != '') * 100.0 / count() AS user_pct,
            countIf(event_type != '') * 100.0 / count() AS event_type_pct,
            countIf(message != '') * 100.0 / count() AS message_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100
        ORDER BY total_events DESC
    "#
    )
}

/// Build the ext-column usage SQL.
///
/// `ext` is a JSON column (init.sql:508). The previous implementation used
/// `length(toString(ext)) > 2`, which is broken: ClickHouse's JSON `toString`
/// serializes the full dynamic schema and almost always returns more than 2
/// chars even when the row's payload is effectively empty, so the query
/// reported ~100% ext usage for every source. Counting top-level keys via
/// `JSONExtractKeys` is the correct emptiness check and matches the pattern
/// used in `field_stats.rs`.
fn build_ext_usage_sql(logs_table: &str) -> String {
    format!(
        r#"
        SELECT
            source_type,
            count() AS total_events,
            countIf(length(JSONExtractKeys(ext)) > 0) * 100.0 / count() AS ext_pct
        FROM {logs_table}
        WHERE timestamp >= now() - INTERVAL 24 HOUR
          AND source_type != 'audit'
          AND source_type != ''
        GROUP BY source_type
        HAVING total_events >= 100 AND ext_pct > 50
        ORDER BY ext_pct DESC
    "#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ext_usage_sql_uses_json_aware_emptiness_check() {
        // Regression: NAN-614. The bug was `length(toString(ext)) > 2`, which
        // hits the JSON column's serialized schema rather than its payload and
        // reports ~100% ext usage for every source. The correct check counts
        // top-level keys via JSONExtractKeys.
        let sql = build_ext_usage_sql("logs");
        assert!(
            sql.contains("length(JSONExtractKeys(ext)) > 0"),
            "ext_pct must use JSONExtractKeys-based emptiness check, got:\n{sql}"
        );
        assert!(
            !sql.contains("length(toString(ext))"),
            "ext_pct must not regress to length(toString(ext)) — that returns ~100% on JSON columns. got:\n{sql}"
        );
    }

    #[test]
    fn field_coverage_sql_filters_audit_and_unknown_sources() {
        let sql = build_field_coverage_sql("logs");
        assert!(sql.contains("source_type != 'audit'"));
        assert!(sql.contains("source_type != ''"));
        assert!(sql.contains("HAVING total_events >= 100"));
    }
}
