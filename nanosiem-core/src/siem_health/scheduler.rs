// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduled SIEM health check (leader-only, every 12 hours)

use std::sync::Arc;
use std::time::Duration;

use clickhouse::Client as ClickHouseClient;
use sqlx::PgPool;
use tokio::time;
use tracing::{error, info, warn};

use super::analyzer;
use super::analyzer::SuppressedFinding;
use super::collector;
use super::repository::SiemHealthRepository;
use super::suppressions_repository::SuppressionRepository;
use super::types::HealthStatus;
use crate::extensions::SiemHealthAiAnalyzer;

/// Default interval: 12 hours
const DEFAULT_INTERVAL_SECS: u64 = 12 * 60 * 60;

/// Initial delay before first run (5 minutes — let other services stabilize)
const INITIAL_DELAY_SECS: u64 = 5 * 60;

pub fn start(
    pool: PgPool,
    ch_client: Option<ClickHouseClient>,
    is_clustered: bool,
    ai_analyzer: Arc<dyn SiemHealthAiAnalyzer>,
) -> tokio::task::JoinHandle<()> {
    let interval_secs: u64 = std::env::var("SIEM_HEALTH_CHECK_INTERVAL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_INTERVAL_SECS);

    tokio::spawn(async move {
        // Initial delay
        time::sleep(Duration::from_secs(INITIAL_DELAY_SECS)).await;
        info!(
            "SIEM health check scheduler started (interval: {}s)",
            interval_secs
        );

        let repo = SiemHealthRepository::new(pool.clone());

        loop {
            run_health_check(
                &pool,
                ch_client.as_ref(),
                is_clustered,
                ai_analyzer.as_ref(),
                &repo,
            )
            .await;
            time::sleep(Duration::from_secs(interval_secs)).await;
        }
    })
}

/// Run a single health check: collect metrics, analyze with AI, store report.
/// Also used by the manual trigger endpoint.
///
/// `ai_analyzer` is non-optional: open-core wires `NoopSiemHealthAiAnalyzer`,
/// whose `analyze_with_ai` returns `Err(ExtensionError::Unavailable)`, and
/// this function falls through to the rules-based `analyzer::fallback_report`
/// in that case.
pub async fn run_health_check(
    pool: &PgPool,
    ch_client: Option<&ClickHouseClient>,
    is_clustered: bool,
    ai_analyzer: &dyn SiemHealthAiAnalyzer,
    repo: &SiemHealthRepository,
) -> Option<uuid::Uuid> {
    run_health_check_with_trigger(pool, ch_client, is_clustered, ai_analyzer, repo, None).await
}

/// Run a health check, optionally recording who triggered it.
pub async fn run_health_check_with_trigger(
    pool: &PgPool,
    ch_client: Option<&ClickHouseClient>,
    is_clustered: bool,
    ai_analyzer: &dyn SiemHealthAiAnalyzer,
    repo: &SiemHealthRepository,
    triggered_by: Option<uuid::Uuid>,
) -> Option<uuid::Uuid> {
    let start = std::time::Instant::now();
    info!("Starting SIEM health check...");

    // Step 1: Collect metrics
    let metrics = collector::collect_metrics(pool, ch_client, is_clustered).await;
    let metrics_json = serde_json::to_value(&metrics).unwrap_or_default();

    // Step 1b: Load active suppressions so the AI can omit classes the tenant
    // has already marked as not-an-issue (NAN-615).
    let suppressions = match SuppressionRepository::new(pool.clone()).list_active().await {
        Ok(rows) => rows
            .into_iter()
            .map(|s| SuppressedFinding {
                title: s.title,
                reason: s.reason,
            })
            .collect::<Vec<_>>(),
        Err(e) => {
            warn!(
                "Failed to load suppressions; continuing without prompt context: {}",
                e
            );
            Vec::new()
        }
    };

    // Step 2: Analyze with AI (or fallback). On open-core builds the
    // `NoopSiemHealthAiAnalyzer` returns `Err(Unavailable)`, and any real AI
    // failure (network / parse / rate limit) lands here too — we treat both
    // identically by falling through to the rules-based heuristic.
    let analysis = match ai_analyzer.analyze_with_ai(&metrics, &suppressions).await {
        Ok(result) => {
            info!(
                "SIEM health analysis complete (score: {}, {} active suppressions)",
                result.overall_score,
                suppressions.len()
            );
            result
        }
        Err(e) => {
            warn!("AI analysis unavailable or failed, using fallback: {}", e);
            analyzer::fallback_report(&metrics)
        }
    };

    let duration_ms = start.elapsed().as_millis() as i32;
    let status = HealthStatus::from_score(analysis.overall_score);

    // Step 3: Store report
    let recommendations_json = serde_json::to_value(&analysis.recommendations).unwrap_or_default();
    let details_json = serde_json::to_value(&analysis.dimension_details).unwrap_or_default();

    match repo
        .insert(
            analysis.overall_score,
            status.as_str(),
            analysis.ingestion_score,
            analysis.parsing_score,
            analysis.enrichment_score,
            analysis.detection_score,
            analysis.alerting_score,
            &analysis.summary,
            &metrics_json,
            &recommendations_json,
            &details_json,
            triggered_by,
            Some(duration_ms),
        )
        .await
    {
        Ok(report) => {
            info!(
                "SIEM health report saved: id={}, score={} ({}), took {}ms",
                report.id, report.overall_score, status, duration_ms
            );
            Some(report.id)
        }
        Err(e) => {
            error!("Failed to save health report: {}", e);
            None
        }
    }
}
