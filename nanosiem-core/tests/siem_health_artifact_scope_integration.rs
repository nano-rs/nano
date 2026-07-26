// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2089 database-backed regression coverage for SIEM-health persistent
//! artifact visibility.
//!
//! The suite exercises the production repositories against migrated
//! PostgreSQL. It is ignored in ordinary unit runs and executed by the
//! pg-integration lane.

mod common;

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

use async_trait::async_trait;
use clickhouse::Client;
use nanosiem_core::auth::{ArtifactScope, SourceProvenance};
use nanosiem_core::extensions::{ExtensionError, SiemHealthAiAnalyzer};
use nanosiem_core::siem_health::analyzer::SuppressedFinding;
use nanosiem_core::siem_health::scheduler::run_health_check_with_trigger;
use nanosiem_core::siem_health::types::{
    AnalysisResult, CollectedMetrics, DimensionDetails, Recommendation,
};
use nanosiem_core::siem_health::{
    SiemHealthReport, SiemHealthRepository, SiemHealthRepositoryError, SuppressionRepository,
};
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

fn restricted(denied: &[String]) -> ArtifactScope {
    ArtifactScope::from_denied(&denied.iter().cloned().collect::<BTreeSet<_>>())
}

fn ch_client() -> Client {
    Client::default()
        .with_url(
            std::env::var("CLICKHOUSE_TEST_URL")
                .unwrap_or_else(|_| "http://localhost:8123".to_string()),
        )
        .with_user("nanosiem")
        .with_password("nanosiem")
        .with_database("nanosiem")
}

#[derive(Clone, Copy)]
enum AnalyzerMode {
    AiSuccess,
    Fallback,
}

struct RecordingAnalyzer {
    mode: AnalyzerMode,
    received_empty_suppressions: AtomicBool,
}

impl RecordingAnalyzer {
    fn new(mode: AnalyzerMode) -> Self {
        Self {
            mode,
            received_empty_suppressions: AtomicBool::new(false),
        }
    }

    fn received_empty_suppressions(&self) -> bool {
        self.received_empty_suppressions.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl SiemHealthAiAnalyzer for RecordingAnalyzer {
    async fn analyze_with_ai(
        &self,
        _metrics: &CollectedMetrics,
        suppressions: &[SuppressedFinding],
    ) -> Result<AnalysisResult, ExtensionError> {
        self.received_empty_suppressions
            .store(suppressions.is_empty(), Ordering::SeqCst);
        match self.mode {
            AnalyzerMode::AiSuccess => Ok(AnalysisResult {
                overall_score: 21,
                ingestion_score: 22,
                parsing_score: 23,
                enrichment_score: 24,
                detection_score: 25,
                alerting_score: 26,
                summary: "NAN-2089 AI narrative".to_string(),
                recommendations: vec![Recommendation {
                    title: "NAN-2089 AI recommendation".to_string(),
                    description: "persistent AI prose".to_string(),
                    priority: "high".to_string(),
                }],
                dimension_details: DimensionDetails {
                    ingestion: "AI ingestion detail".to_string(),
                    parsing: "AI parsing detail".to_string(),
                    enrichment: "AI enrichment detail".to_string(),
                    detection: "AI detection detail".to_string(),
                    alerting: "AI alerting detail".to_string(),
                },
            }),
            AnalyzerMode::Fallback => Err(ExtensionError::Unavailable(
                "NAN-2089 forced fallback analyzer",
            )),
        }
    }
}

async fn insert_report(
    repo: &SiemHealthRepository,
    marker: &str,
    provenance: &SourceProvenance,
) -> SiemHealthReport {
    repo.insert(
        13,
        "critical",
        14,
        15,
        16,
        17,
        18,
        &format!("{marker} narrative"),
        &json!({
            "marker": marker,
            "global_total": 991,
        }),
        &json!([{
            "title": format!("{marker} recommendation"),
        }]),
        &json!({
            "ingestion": format!("{marker} dimension"),
        }),
        provenance,
        None,
        Some(19),
    )
    .await
    .expect("insert SIEM-health report")
}

async fn set_future_order(pool: &PgPool, report_id: Uuid, minutes: i32) {
    sqlx::query(
        r#"
        UPDATE siem_health_reports
        SET created_at = NOW() + INTERVAL '100 years' + ($2 * INTERVAL '1 minute')
        WHERE id = $1
        "#,
    )
    .bind(report_id)
    .bind(minutes)
    .execute(pool)
    .await
    .expect("order fixture reports");
}

async fn cleanup_reports(pool: &PgPool, ids: &[Uuid]) {
    let _ = sqlx::query("DELETE FROM siem_health_reports WHERE id = ANY($1::uuid[])")
        .bind(ids)
        .execute(pool)
        .await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn report_scope_filters_whole_artifacts_before_latest_and_pagination() {
    let pool = common::migrated_pool().await;
    let repo = SiemHealthRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let allowed_source = format!("allowed_{suffix}");
    let denied_source = format!("denied_{suffix}");

    let allowed = insert_report(
        &repo,
        "NAN-2089 allowed",
        &SourceProvenance::complete([allowed_source.as_str()]),
    )
    .await;
    let legacy = insert_report(
        &repo,
        "NAN-2089 legacy secret",
        &SourceProvenance::incomplete([allowed_source.as_str()]),
    )
    .await;
    let mixed = insert_report(
        &repo,
        "NAN-2089 mixed secret",
        &SourceProvenance::complete([allowed_source.as_str(), denied_source.as_str()]),
    )
    .await;
    let denied = insert_report(
        &repo,
        "NAN-2089 denied secret",
        &SourceProvenance::complete([denied_source.as_str()]),
    )
    .await;
    let ids = [allowed.id, legacy.id, mixed.id, denied.id];

    // Unsafe rows are newer than the allowed row. SQL-scoping after LIMIT
    // would therefore return an empty first page/latest result.
    set_future_order(&pool, allowed.id, 1).await;
    set_future_order(&pool, legacy.id, 2).await;
    set_future_order(&pool, mixed.id, 3).await;
    set_future_order(&pool, denied.id, 4).await;

    let deny_denied = restricted(std::slice::from_ref(&denied_source));

    let unrestricted_latest = repo
        .get_latest()
        .await
        .expect("read unrestricted latest")
        .expect("unrestricted report");
    assert_eq!(unrestricted_latest.id, denied.id);
    assert_eq!(
        unrestricted_latest.summary, "NAN-2089 denied secret narrative",
        "system behavior must preserve every stored field"
    );
    let (unrestricted_page, _) = repo
        .list_summaries(1, 0)
        .await
        .expect("list unrestricted summaries");
    assert_eq!(unrestricted_page[0].id, denied.id);
    assert_eq!(
        repo.get_latest_for_scope(&ArtifactScope::system())
            .await
            .expect("scoped API preserves SYSTEM behavior")
            .expect("SYSTEM latest report")
            .id,
        denied.id
    );

    let scoped_latest = repo
        .get_latest_for_scope(&deny_denied)
        .await
        .expect("read scoped latest")
        .expect("visible report");
    assert_eq!(scoped_latest.id, allowed.id);
    assert_eq!(scoped_latest.overall_score, 13);
    assert_eq!(scoped_latest.overall_status, "critical");
    assert_eq!(scoped_latest.metrics["global_total"], 991);
    assert_eq!(
        scoped_latest.recommendations[0]["title"],
        "NAN-2089 allowed recommendation"
    );
    assert_eq!(
        scoped_latest.dimension_details["ingestion"],
        "NAN-2089 allowed dimension"
    );

    for hidden in [&legacy, &mixed, &denied] {
        assert!(matches!(
            repo.get_by_id_for_scope(hidden.id, &deny_denied).await,
            Err(SiemHealthRepositoryError::NotFound(_))
        ));
    }

    let (first_page, total) = repo
        .list_summaries_for_scope(1, 0, &deny_denied)
        .await
        .expect("list scoped summaries");
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page[0].id, allowed.id);
    assert_eq!(first_page[0].summary, "NAN-2089 allowed narrative");

    let expected_total: i64 = sqlx::query_scalar(
        r#"
        SELECT COUNT(*)
        FROM siem_health_reports
        WHERE source_types_complete
          AND NOT (source_types && $1::text[])
        "#,
    )
    .bind(deny_denied.deny_bind_values())
    .fetch_one(&pool)
    .await
    .expect("count directly scoped reports");
    assert_eq!(total, expected_total);

    cleanup_reports(&pool, &ids).await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn current_scope_revokes_and_restores_detail_without_regeneration() {
    let pool = common::migrated_pool().await;
    let repo = SiemHealthRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let source = format!("revoked_{suffix}");
    let unrelated = format!("unrelated_{suffix}");
    let report = insert_report(
        &repo,
        "NAN-2089 grant revoke",
        &SourceProvenance::complete([source.as_str()]),
    )
    .await;

    let pre_revoke = restricted(std::slice::from_ref(&unrelated));
    assert_eq!(
        repo.get_by_id_for_scope(report.id, &pre_revoke)
            .await
            .expect("report visible before revoke")
            .id,
        report.id
    );

    let revoked = restricted(std::slice::from_ref(&source));
    assert!(matches!(
        repo.get_by_id_for_scope(report.id, &revoked).await,
        Err(SiemHealthRepositoryError::NotFound(_))
    ));

    assert_eq!(
        repo.get_by_id_for_scope(report.id, &pre_revoke)
            .await
            .expect("report visible after grant restoration")
            .id,
        report.id
    );

    cleanup_reports(&pool, &[report.id]).await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn legacy_suppressions_never_enter_a_restricted_read_or_analyzer_context() {
    let pool = common::migrated_pool().await;
    let user_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
        VALUES ($1, $2, 'NAN-2089', 'x', 'active', NOW(), NOW())
        "#,
    )
    .bind(user_id)
    .bind(format!("nan-2089-{user_id}@example.invalid"))
    .execute(&pool)
    .await
    .expect("create suppression owner");

    let repo = SuppressionRepository::new(pool.clone());
    let signature = format!("nan-2089-{}", Uuid::now_v7());
    let suppression = repo
        .create(
            &signature,
            "denied source finding",
            "operator reason names denied source",
            user_id,
        )
        .await
        .expect("create legacy suppression");

    let system_rows = repo
        .list_active_for_scope(&ArtifactScope::system())
        .await
        .expect("system suppression list");
    assert!(system_rows.iter().any(|row| row.id == suppression.id));

    let denied_scope = restricted(&[format!("denied_{}", Uuid::now_v7().simple())]);
    assert!(
        repo.list_active_for_scope(&denied_scope)
            .await
            .expect("restricted active suppressions")
            .is_empty(),
        "the scheduler uses this exact path before both AI and fallback analysis"
    );
    assert!(repo
        .list_all_for_scope(&denied_scope)
        .await
        .expect("restricted suppression history")
        .is_empty());

    let _ = sqlx::query("DELETE FROM siem_health_finding_suppressions WHERE id = $1")
        .bind(suppression.id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;
}

#[tokio::test]
#[ignore = "dual-db-backed; runs with local PostgreSQL + ClickHouse validation"]
async fn restricted_ai_and_fallback_generation_persist_only_fail_closed_reports() {
    let pool = common::migrated_pool().await;
    let repo = SiemHealthRepository::new(pool.clone());
    let denied_source = format!("denied_{}", Uuid::now_v7().simple());
    let collection_scope =
        nanosiem_core::auth::ScopeSet::from_denied(BTreeSet::from([denied_source.clone()]));
    let artifact_scope = ArtifactScope::from_scope(&collection_scope);

    let ai = RecordingAnalyzer::new(AnalyzerMode::AiSuccess);
    let ai_id = run_health_check_with_trigger(
        &pool,
        &ch_client(),
        false,
        &ai,
        &repo,
        &collection_scope,
        None,
    )
    .await
    .expect("AI report persisted");
    assert!(
        ai.received_empty_suppressions(),
        "unattributed suppression prose must not enter the AI prompt"
    );

    let fallback = RecordingAnalyzer::new(AnalyzerMode::Fallback);
    let fallback_id = run_health_check_with_trigger(
        &pool,
        &ch_client(),
        false,
        &fallback,
        &repo,
        &collection_scope,
        None,
    )
    .await
    .expect("fallback report persisted");
    assert!(
        fallback.received_empty_suppressions(),
        "both analyzer selections must begin from the same scoped context"
    );

    let ai_report = repo.get_by_id(ai_id).await.expect("system reads AI report");
    assert_eq!(ai_report.summary, "NAN-2089 AI narrative");
    assert!(!ai_report.source_types_complete);

    let fallback_report = repo
        .get_by_id(fallback_id)
        .await
        .expect("system reads fallback report");
    assert_ne!(fallback_report.summary, "NAN-2089 AI narrative");
    assert!(!fallback_report.source_types_complete);

    for report_id in [ai_id, fallback_id] {
        assert!(matches!(
            repo.get_by_id_for_scope(report_id, &artifact_scope).await,
            Err(SiemHealthRepositoryError::NotFound(_))
        ));
    }

    cleanup_reports(&pool, &[ai_id, fallback_id]).await;
}
