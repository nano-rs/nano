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
use crate::auth::ScopeSet;
use crate::extensions::SiemHealthAiAnalyzer;

/// Default interval: 12 hours
const DEFAULT_INTERVAL_SECS: u64 = 12 * 60 * 60;

/// Initial delay before first run (5 minutes — let other services stabilize)
const INITIAL_DELAY_SECS: u64 = 5 * 60;

pub fn start(
    pool: PgPool,
    ch_client: ClickHouseClient,
    system_probe_client: ClickHouseClient,
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
                &ch_client,
                &system_probe_client,
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
    ch_client: &ClickHouseClient,
    system_probe_client: &ClickHouseClient,
    is_clustered: bool,
    ai_analyzer: &dyn SiemHealthAiAnalyzer,
    repo: &SiemHealthRepository,
) -> Option<uuid::Uuid> {
    let system_scope = ScopeSet::unrestricted();
    run_health_check_with_trigger(
        pool,
        ch_client,
        system_probe_client,
        is_clustered,
        ai_analyzer,
        repo,
        &system_scope,
        None,
    )
    .await
}

/// Run a health check under an explicit collection scope, optionally recording
/// who triggered it.
///
/// The scheduled path passes [`ScopeSet::unrestricted`]. HTTP callers pass
/// their current effective viewer scope so denied log rows never enter metrics,
/// the AI prompt, fallback analysis, or the durable report.
pub async fn run_health_check_with_trigger(
    pool: &PgPool,
    ch_client: &ClickHouseClient,
    system_probe_client: &ClickHouseClient,
    is_clustered: bool,
    ai_analyzer: &dyn SiemHealthAiAnalyzer,
    repo: &SiemHealthRepository,
    scope: &ScopeSet,
    triggered_by: Option<uuid::Uuid>,
) -> Option<uuid::Uuid> {
    let start = std::time::Instant::now();
    info!("Starting SIEM health check...");

    // Step 1: Collect metrics
    let metrics =
        collector::collect_metrics(pool, ch_client, system_probe_client, is_clustered, scope).await;
    let provenance = metrics.source_provenance();
    let metrics_json = serde_json::to_value(&metrics).unwrap_or_default();

    // Step 1b: Load active suppressions so the AI can omit classes the tenant
    // has already marked as not-an-issue (NAN-615).
    //
    // NAN-2222: this list is deliberately SYSTEM-scoped, not viewer-scoped.
    // Suppressions are tenant-wide operator configuration keyed by finding
    // signature — not source-derived rows — and they decide what the generator
    // omits. Deriving them from the triggering principal's scope meant any
    // restricted trigger produced a report with ZERO suppressions applied, so
    // findings the tenant had already dismissed reappeared in a durable
    // artifact that every reader consumes. Generation is a system operation
    // regardless of who pressed the button; who may READ suppression prose is a
    // separate decision that `list_active_for_scope` still makes on the API
    // path (`handlers/siem_health_suppressions.rs`), unchanged.
    //
    // NAN-2219 reached the same defect from the scope side and narrowed it to
    // triggers with a REAL per-source boundary. NAN-2222 supersedes that:
    // there is no viewer scope here to narrow, because generation is not a
    // viewer operation. `scope` below still governs metric COLLECTION, which
    // is per-source log data and stays on the row-filter half.
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
    let mut analysis = match ai_analyzer.analyze_with_ai(&metrics, &suppressions).await {
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
    // NAN-4954: audit-trail holes surface on every path (AI, fallback, Fresh).
    analyzer::ensure_audit_durability_findings(&mut analysis, &metrics);
    // NAN-5032: sources stored under a platform-owned source type.
    analyzer::ensure_reserved_source_name_findings(&mut analysis, &metrics);
    // NAN-5342: one shard taking more writes / parts / merges than the rest.
    analyzer::ensure_shard_skew_findings(&mut analysis, &metrics);
    // Security review 2026-11-08: insecure-but-accepted deployment settings.
    analyzer::ensure_deployment_posture_findings(
        &mut analysis,
        &crate::deployment_posture::PostureInputs::from_env(),
    );
    // NAN-5367: nano ClickHouse users that still accept any address (Helm
    // with clickhouse.allowedNetworks unset, or SQL users an older release
    // created without HOST).
    match analyzer::open_clickhouse_users(system_probe_client).await {
        Ok(users) => analyzer::ensure_clickhouse_network_findings(&mut analysis, &users),
        Err(e) => warn!("Failed to read ClickHouse user networks: {}", e),
    }
    // NAN-5390: ClickHouse refusing nano's logins or writes (wrong user
    // networks, password or grants). A refused probe login is itself evidence.
    let refusals = match super::clickhouse_refusals::clickhouse_refusals(system_probe_client).await {
        Ok(lines) => lines,
        Err(e) => {
            let msg = e.to_string();
            warn!("Failed to read ClickHouse refusals: {}", msg);
            super::clickhouse_refusals::refusal_from_error(&msg).into_iter().collect()
        }
    };
    super::clickhouse_refusals::ensure_clickhouse_refusal_findings(&mut analysis, &refusals);
    // NAN-5204: automatic backups enabled but none succeeded in 36 hours.
    match crate::backup_status::BackupStatusRepository::new(pool.clone()).get().await {
        Ok(status) => {
            analyzer::ensure_backup_findings(&mut analysis, status.as_ref(), chrono::Utc::now())
        }
        Err(e) => warn!("Failed to read backup status: {}", e),
    }
    // NAN-5077: IP allowlist rule loads that failed (fail-closed enforcement),
    // as published to the system-health bus by nanosiem-api / nanosiem-search.
    #[cfg(feature = "enterprise")]
    let mut service_events: Vec<crate::system_health::SystemHealthEvent> = Vec::new();
    match crate::system_health::SystemHealthRepository::new(pool.clone())
        .list(None, Some(crate::system_health::HealthCategory::Service.as_str()), None, 200, 0)
        .await
    {
        Ok((events, _)) => {
            analyzer::ensure_ip_allowlist_findings(&mut analysis, &events);
            // NAN-5149: repeated failed sign-ins for one email.
            analyzer::ensure_login_guessing_findings(&mut analysis, &events);
            #[cfg(feature = "enterprise")]
            {
                service_events = events;
            }
        }
        Err(e) => warn!("Failed to read service health events: {}", e),
    }
    // NAN-5194: the license server refused this deployment's token.
    // Enterprise only (the license module is not in the open edition).
    #[cfg(feature = "enterprise")]
    match crate::license::LicenseRepository::new(pool.clone())
        .get_token_rejected_notice()
        .await
    {
        Ok(notice) => crate::license::token_rejection::ensure_token_rejected_finding(
            &mut analysis,
            notice.as_ref(),
        ),
        Err(e) => warn!("Failed to read license token rejection: {}", e),
    }

    // NAN-5097: custom enrichments that cannot move to the wasm sandbox yet.
    #[cfg(feature = "enterprise")]
    match super::enrichment_wasm_findings::load_needs_attention(pool).await {
        Ok(names) => {
            super::enrichment_wasm_findings::ensure_enrichment_wasm_findings(&mut analysis, &names)
        }
        Err(e) => warn!("Failed to read custom enrichment wasm status: {}", e),
    }
    #[cfg(feature = "enterprise")]
    match super::enrichment_wasm_findings::load_collectors_needing_attention(pool).await {
        Ok(names) => {
            if let Some(rec) = super::enrichment_wasm_findings::collector_recommendation(&names) {
                if !analysis.recommendations.iter().any(|r| r.title == rec.title) {
                    analysis.recommendations.push(rec);
                }
            }
        }
        Err(e) => warn!("Failed to read collector wasm failures: {}", e),
    }

    // NAN-5360 + NAN-5362: Agent Lane over its active-token cap or blind to
    // its budgets; query audit lag, refusal spikes, failed logins from
    // unknown addresses. One registration for both.
    #[cfg(feature = "enterprise")]
    super::agentlane_findings::ensure_all(pool, &mut analysis, &service_events).await;

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
            &provenance,
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
