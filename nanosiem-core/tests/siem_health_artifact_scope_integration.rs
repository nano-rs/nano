// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-2089 / NAN-2222 database-backed regression coverage for SIEM-health
//! persistent artifact visibility.
//!
//! The suite exercises the production repositories against migrated
//! PostgreSQL. It is ignored in ordinary unit runs and executed by the
//! pg-integration lane.
//!
//! NAN-2222 moved the policy from "hide the whole row" to "reduce the row":
//! reports are always returned, denied `source_type` partitions are pruned, and
//! the unattributable narrative is withheld unless the stored provenance proves
//! the report disjoint from the reader's deny set. The assertions below were
//! rewritten accordingly — the old ones pinned a gate that no row could ever
//! satisfy, so they passed against a permanently empty result set.

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

/// A stored metrics payload that really is the typed `CollectedMetrics`
/// contract, with one ingestion partition per `sources` entry.
///
/// The old fixture stored an arbitrary `{"marker": …}` blob. That was fine while
/// the policy was "admit or hide the row", but it cannot exercise partition
/// pruning — and a restricted reader now fails closed to `{}` on any payload
/// that does not deserialize, so an untyped blob would hide the very behaviour
/// under test.
fn metrics_for(sources: &[&str]) -> serde_json::Value {
    let source_volumes: Vec<serde_json::Value> = sources
        .iter()
        .map(|source_type| {
            json!({
                "source_type": source_type,
                "count_24h": 10,
                "count_prior_24h": 5,
                "change_pct": 100.0
            })
        })
        .collect();
    json!({
        "ingestion": {
            "source_volumes": source_volumes,
            "total_events_24h": 10 * sources.len(),
            "total_events_prior_24h": 5 * sources.len(),
            "silent_sources": [],
            "insert_integrity": {
                "probes_available": false,
                "logs_inserts_1h": 0,
                "new_parts_1h": 0,
                "new_parts_probe_ok": false,
                "memory_limit_errors": 0,
                "cache_dictionary_update_fails": 0,
                "failed_logs_dictionaries": [],
                "async_insert_failures_1h": null,
                "last_async_insert_error": null,
                "stale_dict_refreshes": []
            }
        },
        "parsing": {
            "field_coverage": [],
            "high_ext_sources": [],
            "lowercase_invariant_violations": []
        },
        "enrichment": {
            "total_events_24h": 991,
            "geoip_fill_pct": 0.0,
            "asn_fill_pct": 0.0,
            "ioc_hit_pct": 0.0,
            "identity_fill_pct": 0.0,
            "identity_fill_prior_pct": 0.0,
            "per_source_coverage": [],
            "providers": []
        },
        "detection": {
            "total_enabled_rules": 1,
            "total_matches_24h": 0,
            "rules_by_mode": [],
            "stale_rules": [],
            "noisy_rules": [],
            "alerts_24h_by_severity": []
        },
        "alerting": {
            "total_alerts_24h": 0,
            "total_alerts_prior_24h": 0,
            "by_status": [],
            "mean_mtta_minutes": null,
            "active_webhooks": 0,
            "webhook_deliveries_24h": 0,
            "webhook_success_pct": null,
            "active_routing_rules": 0
        },
        "collected_at": chrono::Utc::now()
    })
}

async fn insert_report(
    repo: &SiemHealthRepository,
    marker: &str,
    provenance: &SourceProvenance,
    metric_sources: &[&str],
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
        &metrics_for(metric_sources),
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
async fn report_scope_reduces_rows_instead_of_hiding_them_from_latest_and_pagination() {
    let pool = common::migrated_pool().await;
    let repo = SiemHealthRepository::new(pool.clone());
    let suffix = Uuid::now_v7().simple().to_string();
    let allowed_source = format!("allowed_{suffix}");
    let denied_source = format!("denied_{suffix}");

    let allowed = insert_report(
        &repo,
        "NAN-2089 allowed",
        &SourceProvenance::complete([allowed_source.as_str()]),
        &[allowed_source.as_str()],
    )
    .await;
    let legacy = insert_report(
        &repo,
        "NAN-2089 legacy secret",
        &SourceProvenance::incomplete([allowed_source.as_str()]),
        &[allowed_source.as_str(), denied_source.as_str()],
    )
    .await;
    let mixed = insert_report(
        &repo,
        "NAN-2089 mixed secret",
        &SourceProvenance::complete([allowed_source.as_str(), denied_source.as_str()]),
        &[allowed_source.as_str(), denied_source.as_str()],
    )
    .await;
    let denied = insert_report(
        &repo,
        "NAN-2089 denied secret",
        &SourceProvenance::complete([denied_source.as_str()]),
        &[denied_source.as_str()],
    )
    .await;
    let ids = [allowed.id, legacy.id, mixed.id, denied.id];

    set_future_order(&pool, allowed.id, 1).await;
    set_future_order(&pool, legacy.id, 2).await;
    set_future_order(&pool, mixed.id, 3).await;
    set_future_order(&pool, denied.id, 4).await;

    let deny_denied = restricted(std::slice::from_ref(&denied_source));

    // SYSTEM behavior is untouched: every stored field, verbatim.
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

    // NAN-2222: "latest" is the real latest for a restricted reader too. It
    // used to be `allowed` — or, with no complete row anywhere, nothing at all
    // and a 404 asserting no report existed.
    let scoped_latest = repo
        .get_latest_for_scope(&deny_denied)
        .await
        .expect("read scoped latest")
        .expect("restricted readers still get the current health of the SIEM");
    assert_eq!(scoped_latest.id, denied.id);
    assert_eq!(scoped_latest.overall_score, 13);
    assert_eq!(scoped_latest.overall_status, "critical");
    assert_eq!(
        scoped_latest.summary,
        nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE,
        "prose over a denied source is withheld, not delivered"
    );
    assert_eq!(scoped_latest.recommendations, json!([]));
    assert_eq!(scoped_latest.dimension_details, json!({}));
    assert!(
        scoped_latest.metrics["ingestion"]["source_volumes"]
            .as_array()
            .expect("typed source volumes")
            .is_empty(),
        "the denied partition must not survive"
    );
    assert_eq!(scoped_latest.metrics["ingestion"]["total_events_24h"], 0);

    // The provably complete + disjoint report keeps everything.
    let scoped_allowed = repo
        .get_by_id_for_scope(allowed.id, &deny_denied)
        .await
        .expect("complete disjoint report stays fully readable");
    assert_eq!(scoped_allowed.summary, "NAN-2089 allowed narrative");
    assert_eq!(
        scoped_allowed.recommendations[0]["title"],
        "NAN-2089 allowed recommendation"
    );
    assert_eq!(
        scoped_allowed.dimension_details["ingestion"],
        "NAN-2089 allowed dimension"
    );
    assert_eq!(
        scoped_allowed.metrics["ingestion"]["source_volumes"][0]["source_type"],
        json!(allowed_source)
    );

    // Legacy (incomplete stamp) and mixed-origin reports are readable but
    // narrative-withheld, and never carry the denied partition.
    for hidden in [&legacy, &mixed, &denied] {
        let reduced = repo
            .get_by_id_for_scope(hidden.id, &deny_denied)
            .await
            .expect("reports are reduced, not hidden");
        assert_eq!(
            reduced.summary,
            nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE
        );
        let volumes = reduced.metrics["ingestion"]["source_volumes"]
            .as_array()
            .expect("typed source volumes")
            .iter()
            .map(|row| row["source_type"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        assert!(
            !volumes.contains(&denied_source),
            "denied partition leaked from report {}",
            hidden.id
        );
    }

    // Pagination is no longer an oracle in either direction: a restricted
    // reader sees the same page and the same total a SYSTEM reader sees.
    let (first_page, total) = repo
        .list_summaries_for_scope(1, 0, &deny_denied)
        .await
        .expect("list scoped summaries");
    assert_eq!(first_page.len(), 1);
    assert_eq!(first_page[0].id, denied.id);
    assert_eq!(
        first_page[0].summary,
        nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE
    );

    let expected_total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM siem_health_reports")
        .fetch_one(&pool)
        .await
        .expect("count all reports");
    assert_eq!(total, expected_total);

    let (allowed_page, _) = repo
        .list_summaries_for_scope(1, 3, &deny_denied)
        .await
        .expect("page to the complete disjoint report");
    assert_eq!(allowed_page[0].id, allowed.id);
    assert_eq!(allowed_page[0].summary, "NAN-2089 allowed narrative");

    // `NotFound` recovers its literal meaning: the row does not exist. It used
    // to be returned for every id a restricted principal asked for, which is
    // what made the trigger endpoint a create-then-vanish loop.
    assert!(
        matches!(
            repo.get_by_id_for_scope(Uuid::now_v7(), &deny_denied).await,
            Err(SiemHealthRepositoryError::NotFound(_))
        ),
        "an absent id must still be NotFound"
    );

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
        &[source.as_str()],
    )
    .await;

    let pre_revoke = restricted(std::slice::from_ref(&unrelated));
    let before = repo
        .get_by_id_for_scope(report.id, &pre_revoke)
        .await
        .expect("report visible before revoke");
    assert_eq!(before.id, report.id);
    assert_eq!(before.summary, "NAN-2089 grant revoke narrative");
    assert_eq!(
        before.metrics["ingestion"]["source_volumes"][0]["source_type"],
        json!(source)
    );

    // Revoking the grant takes away the detail derived from that source — the
    // narrative and the source's own partition — without regenerating the
    // report and without pretending the report never existed.
    let revoked = restricted(std::slice::from_ref(&source));
    let during = repo
        .get_by_id_for_scope(report.id, &revoked)
        .await
        .expect("a revoked grant reduces the report, it does not delete it");
    assert_eq!(during.id, report.id);
    assert_eq!(during.overall_score, 13);
    assert_eq!(
        during.summary,
        nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE
    );
    assert!(during.metrics["ingestion"]["source_volumes"]
        .as_array()
        .expect("typed source volumes")
        .is_empty());

    let after = repo
        .get_by_id_for_scope(report.id, &pre_revoke)
        .await
        .expect("report visible after grant restoration");
    assert_eq!(after.id, report.id);
    assert_eq!(after.summary, "NAN-2089 grant revoke narrative");
    assert_eq!(
        after.metrics["ingestion"]["source_volumes"][0]["source_type"],
        json!(source)
    );

    cleanup_reports(&pool, &[report.id]).await;
}

#[tokio::test]
#[ignore = "db-backed; runs with local PostgreSQL integration validation"]
async fn unattributed_suppressions_stay_out_of_a_restricted_read() {
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

    // The READ policy is unchanged by NAN-2222: suppression rows carry no
    // provenance at all, so a restricted principal gets none of their prose.
    // What changed is that the report GENERATOR no longer routes through this
    // path — see `restricted_trigger_still_applies_tenant_suppressions`.
    let denied_scope = restricted(&[format!("denied_{}", Uuid::now_v7().simple())]);
    assert!(
        repo.list_active_for_scope(&denied_scope)
            .await
            .expect("restricted active suppressions")
            .is_empty(),
        "unattributed operator prose must not reach a source-restricted reader"
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

/// NAN-2222, second half: a restricted manual trigger must still apply the
/// tenant's suppressions, and must be able to read the report it just created.
///
/// The previous version of this test asserted the opposite of both — that the
/// generator received ZERO suppressions and that the caller could not fetch its
/// own `report_id`. The first silently resurrects every finding the tenant has
/// dismissed into a durable artifact all readers consume; the second is the
/// create-then-vanish loop.
#[tokio::test]
#[ignore = "dual-db-backed; runs with local PostgreSQL + ClickHouse validation"]
async fn restricted_trigger_still_applies_tenant_suppressions() {
    let pool = common::migrated_pool().await;
    let repo = SiemHealthRepository::new(pool.clone());
    let denied_source = format!("denied_{}", Uuid::now_v7().simple());
    let collection_scope =
        nanosiem_core::auth::ScopeSet::from_denied(BTreeSet::from([denied_source.clone()]));
    let artifact_scope = ArtifactScope::from_scope(&collection_scope);

    // An operator has already dismissed a finding class. Every subsequent run
    // must keep omitting it, whoever triggers it.
    let user_id = Uuid::now_v7();
    sqlx::query(
        r#"
        INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
        VALUES ($1, $2, 'NAN-2222', 'x', 'active', NOW(), NOW())
        "#,
    )
    .bind(user_id)
    .bind(format!("nan-2222-{user_id}@example.invalid"))
    .execute(&pool)
    .await
    .expect("create suppression owner");
    let suppressions = SuppressionRepository::new(pool.clone());
    let signature = format!("nan-2222-{}", Uuid::now_v7());
    let suppression = suppressions
        .create(
            &signature,
            "Known-good finding",
            "accepted risk, reviewed quarterly",
            user_id,
        )
        .await
        .expect("create active suppression");

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
        !ai.received_empty_suppressions(),
        "a restricted trigger must not silently un-dismiss the tenant's findings"
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
        !fallback.received_empty_suppressions(),
        "both analyzer selections must begin from the same tenant-wide context"
    );

    let ai_report = repo.get_by_id(ai_id).await.expect("system reads AI report");
    assert_eq!(ai_report.summary, "NAN-2089 AI narrative");
    // The stamp stays honest: global scores and prose are still not attributed.
    assert!(!ai_report.source_types_complete);

    let fallback_report = repo
        .get_by_id(fallback_id)
        .await
        .expect("system reads fallback report");
    assert_ne!(fallback_report.summary, "NAN-2089 AI narrative");
    assert!(!fallback_report.source_types_complete);

    // Create-then-vanish is fixed: the triggering principal can fetch the id it
    // was handed, reduced to what it may see.
    for report_id in [ai_id, fallback_id] {
        let reduced = repo
            .get_by_id_for_scope(report_id, &artifact_scope)
            .await
            .expect("the triggering principal can read the report it just created");
        assert_eq!(reduced.id, report_id);
        assert_eq!(
            reduced.summary,
            nanosiem_core::siem_health::types::WITHHELD_NARRATIVE_NOTICE,
            "an incompletely attributed report still withholds its prose"
        );
        let volumes = reduced.metrics["ingestion"]["source_volumes"]
            .as_array()
            .expect("typed source volumes")
            .iter()
            .map(|row| row["source_type"].as_str().unwrap_or_default().to_string())
            .collect::<Vec<_>>();
        assert!(!volumes.contains(&denied_source));
    }

    cleanup_reports(&pool, &[ai_id, fallback_id]).await;
    let _ = sqlx::query("DELETE FROM siem_health_finding_suppressions WHERE id = $1")
        .bind(suppression.id)
        .execute(&pool)
        .await;
    let _ = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await;
}
