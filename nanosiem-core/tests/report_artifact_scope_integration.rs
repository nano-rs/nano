// SPDX-License-Identifier: AGPL-3.0-or-later

//! F-31: stored report artifacts must honour a source-access revocation applied
//! AFTER the run was stored.
//!
//! Rendered artifacts are frozen byte blobs with no per-row source attribution,
//! so a source-scoped viewer cannot be row-filtered at download time. The fix
//! stamps each run with the DISTINCT `source_type` manifest of its artifacts
//! (migration 252) and gates downloads on it — OWNERSHIP IS NOT AN EXEMPTION.
//!
//! These `#[ignore]`d DB-backed tests (pg-integration CI:
//! `cargo test -- --ignored`) exercise the persistence + predicate against a
//! real migrated Postgres. They are also the only guard against schema drift for
//! the new `report_runs.source_types` / `source_types_complete` columns and the
//! runtime `sqlx` in `get_artifact_content` / `store_run_success`.

mod common;

use std::collections::BTreeSet;

use nanosiem_core::db::repository::SourceScopeRepository;
use nanosiem_core::reports::{
    report_artifact_download_allowed, NewReportDefinition, RenderedArtifact, ReportRepository,
    ReportSourceType,
};
use sqlx::PgPool;
use uuid::Uuid;

fn suffix() -> String {
    Uuid::now_v7().simple().to_string()[..16].to_string()
}

async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Report Scope Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("rpt-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn create_definition(repo: &ReportRepository, owner: Uuid, sfx: &str) -> Uuid {
    repo.create_definition(
        &NewReportDefinition {
            name: format!("report-{sfx}"),
            description: None,
            source_type: ReportSourceType::Search,
            source_query: Some("error".to_string()),
            saved_query_id: None,
            source_dashboard_id: None,
            time_range_seconds: 3600,
            cron_expression: "0 * * * *".to_string(),
            owner_id: owner,
            enabled: false,
            retention_runs: 10,
        },
        None,
    )
    .await
    .expect("create definition")
    .id
}

fn csv_artifact() -> Vec<RenderedArtifact> {
    vec![RenderedArtifact {
        kind: "csv".to_string(),
        filename: "report.csv".to_string(),
        content_type: "text/csv; charset=utf-8".to_string(),
        content: b"src_ip,count\n10.0.0.1,5\n".to_vec(),
    }]
}

fn deny_set(items: &[String]) -> BTreeSet<String> {
    items.iter().cloned().collect()
}

/// A run whose COMPLETE manifest lists source `X`; restricting `X` afterwards
/// (with the OWNER not granted it) must refuse the owner's own download.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn owner_download_refused_after_later_restriction() {
    let pool = common::migrated_pool().await;
    let repo = ReportRepository::new(pool.clone());
    let scope_repo = SourceScopeRepository::new(pool.clone());

    let sfx = suffix();
    let source = format!("insider_{sfx}");
    let owner = create_user(&pool).await;
    let def_id = create_definition(&repo, owner, &sfx).await;

    // Store a successful run whose artifacts drew on `source` (complete manifest).
    let run_id = Uuid::now_v7();
    repo.upsert_run_running(run_id, def_id, "manual")
        .await
        .expect("run running");
    let stored = repo
        .store_run_success(
            run_id,
            def_id,
            None,
            5,
            Some(1),
            false,
            false,
            &csv_artifact(),
            &[source.clone()],
            true,
        )
        .await
        .expect("store success");
    assert!(stored, "store_run_success under no fence must persist");

    // Fetch the artifact scope (round-trips migration 252 columns).
    let arts = repo.list_artifacts_meta(run_id).await.expect("meta");
    let artifact_id = arts[0].id;
    let (_content, art_scope) = repo
        .get_artifact_content(artifact_id)
        .await
        .expect("artifact content");
    assert_eq!(art_scope.definition_id, def_id);
    assert!(art_scope.source_types.contains(&source));
    assert!(art_scope.source_types_complete);

    // Before restriction: the owner's deny set does not contain `source`, so the
    // (complete, disjoint) manifest is downloadable.
    let owner_deny = deny_set(&scope_repo.denied_for_user(owner).await.expect("deny pre"));
    assert!(
        report_artifact_download_allowed(
            &owner_deny,
            &art_scope.source_types,
            art_scope.source_types_complete
        ),
        "owner must be able to download before any restriction"
    );

    // Restrict `source`; the OWNER holds no grant for it.
    scope_repo
        .add_restricted(&source, Some("insider feed"), None)
        .await
        .expect("restrict source");
    let owner_deny = deny_set(&scope_repo.denied_for_user(owner).await.expect("deny post"));
    assert!(
        owner_deny.contains(&source),
        "owner must now be denied the newly restricted source"
    );
    // OWNERSHIP IS NOT AN EXEMPTION: the frozen artifact is now refused.
    assert!(
        !report_artifact_download_allowed(
            &owner_deny,
            &art_scope.source_types,
            art_scope.source_types_complete
        ),
        "owner download of a pre-existing artifact drawing on a now-restricted source must be refused"
    );

    let _ = scope_repo.remove_restricted(&source).await;
}

/// A run whose COMPLETE manifest is DISJOINT from a restricted viewer's deny set
/// still serves that viewer.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn disjoint_manifest_still_serves_restricted_requester() {
    let pool = common::migrated_pool().await;
    let repo = ReportRepository::new(pool.clone());
    let scope_repo = SourceScopeRepository::new(pool.clone());

    let sfx = suffix();
    let restricted = format!("secret_{sfx}");
    let owner = create_user(&pool).await;
    let def_id = create_definition(&repo, owner, &sfx).await;

    // The run's artifacts drew ONLY on an unrestricted source.
    let run_id = Uuid::now_v7();
    repo.upsert_run_running(run_id, def_id, "manual")
        .await
        .expect("run running");
    repo.store_run_success(
        run_id,
        def_id,
        None,
        5,
        Some(1),
        false,
        false,
        &csv_artifact(),
        &[format!("syslog_{sfx}")],
        true,
    )
    .await
    .expect("store");

    let arts = repo.list_artifacts_meta(run_id).await.expect("meta");
    let (_c, art_scope) = repo
        .get_artifact_content(arts[0].id)
        .await
        .expect("content");

    // A viewer denied `restricted` (which the manifest does not contain) may
    // still download.
    scope_repo
        .add_restricted(&restricted, None, None)
        .await
        .expect("restrict");
    let requester = create_user(&pool).await; // no grants → denied `restricted`
    let requester_deny =
        deny_set(&scope_repo.denied_for_user(requester).await.expect("deny"));
    assert!(
        requester_deny.contains(&restricted),
        "requester must be denied the restricted source"
    );
    assert!(
        report_artifact_download_allowed(
            &requester_deny,
            &art_scope.source_types,
            art_scope.source_types_complete
        ),
        "a complete manifest disjoint from the requester's deny set must still serve"
    );

    let _ = scope_repo.remove_restricted(&restricted).await;
}

/// A PRE-FEATURE run (no manifest: default `'{}'` + `complete=false`, simulated
/// by a hand-inserted row that omits the new columns) denies any restricted
/// requester but still serves an unrestricted one.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn pre_feature_run_denies_restricted_requester() {
    let pool = common::migrated_pool().await;
    let repo = ReportRepository::new(pool.clone());

    let sfx = suffix();
    let owner = create_user(&pool).await;
    let def_id = create_definition(&repo, owner, &sfx).await;

    // Insert a 'success' run WITHOUT touching source_types → column defaults
    // ('{}' + FALSE), exactly what an already-stored run carries post-migration.
    let run_id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO report_runs
             (id, definition_id, status, triggered_by, started_at, finished_at, duration_ms, row_count)
           VALUES ($1, $2, 'success', 'manual', NOW(), NOW(), 5, 1)"#,
    )
    .bind(run_id)
    .bind(def_id)
    .execute(&pool)
    .await
    .expect("insert legacy run");
    sqlx::query(
        r#"INSERT INTO report_run_artifacts
             (id, run_id, kind, filename, content_type, size_bytes, content)
           VALUES ($1, $2, 'csv', 'legacy.csv', 'text/csv', 4, $3)"#,
    )
    .bind(Uuid::now_v7())
    .bind(run_id)
    .bind(b"data".to_vec())
    .execute(&pool)
    .await
    .expect("insert legacy artifact");

    let arts = repo.list_artifacts_meta(run_id).await.expect("meta");
    let (_c, art_scope) = repo
        .get_artifact_content(arts[0].id)
        .await
        .expect("content");
    assert!(
        art_scope.source_types.is_empty() && !art_scope.source_types_complete,
        "a pre-feature run must default to an empty, incomplete manifest"
    );

    // Restricted requester → denied (bytes may contain anything).
    let restricted_deny = deny_set(&[format!("anything_{sfx}")]);
    assert!(
        !report_artifact_download_allowed(
            &restricted_deny,
            &art_scope.source_types,
            art_scope.source_types_complete
        ),
        "an incomplete (pre-feature) manifest must deny a restricted requester"
    );
    // Unrestricted requester → still allowed (back-compat).
    assert!(
        report_artifact_download_allowed(
            &BTreeSet::new(),
            &art_scope.source_types,
            art_scope.source_types_complete
        ),
        "an unrestricted requester is never blocked"
    );
}

/// Metadata parity: `get_run` carries the same manifest the download gate uses,
/// so `get_report_run` / `list_report_runs` redact consistently with download.
#[tokio::test]
#[ignore = "db-backed; runs in pg-integration CI (cargo test -- --ignored)"]
async fn get_run_carries_manifest_for_metadata_gate() {
    let pool = common::migrated_pool().await;
    let repo = ReportRepository::new(pool.clone());

    let sfx = suffix();
    let source = format!("insider_{sfx}");
    let owner = create_user(&pool).await;
    let def_id = create_definition(&repo, owner, &sfx).await;

    let run_id = Uuid::now_v7();
    repo.upsert_run_running(run_id, def_id, "manual")
        .await
        .expect("running");
    repo.store_run_success(
        run_id,
        def_id,
        None,
        5,
        Some(1),
        false,
        false,
        &csv_artifact(),
        &[source.clone()],
        true,
    )
    .await
    .expect("store");

    // get_run surfaces the manifest fields (internal; not serialized).
    let run = repo.get_run(run_id).await.expect("get_run");
    assert!(run.source_types.contains(&source));
    assert!(run.source_types_complete);
    assert_eq!(run.artifacts.len(), 1, "get_run populates artifact metadata");

    // The metadata gate uses the SAME predicate as download.
    let deny = deny_set(&[source.clone()]);
    assert!(
        !report_artifact_download_allowed(&deny, &run.source_types, run.source_types_complete),
        "a denied requester must be redacted at the metadata layer too"
    );

    // list_runs surfaces the manifest as well (used by list_report_runs redaction).
    let runs = repo.list_runs(def_id, 10).await.expect("list_runs");
    let listed = runs.iter().find(|r| r.id == run_id).expect("run in list");
    assert!(listed.source_types.contains(&source));
    assert!(listed.source_types_complete);
}
