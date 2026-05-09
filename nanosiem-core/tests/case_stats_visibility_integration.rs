//! Regression tests for NAN-684: `/api/cases/stats` must not leak aggregates
//! over cases the caller cannot see.
//!
//! Gated like the other DB-backed integration suites: requires a live Postgres
//! at `DATABASE_URL`. Drop the `cfg(any())` gate to run locally.

#![cfg(any())]

use nanosiem_core::db::repository::cases::CaseRepository;
use nanosiem_core::models::case::NewCase;
use nanosiem_core::models::detection_rule::Severity;
use sqlx::PgPool;
use uuid::Uuid;

async fn pool() -> PgPool {
    let url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://nanosiem:nanosiem@localhost:5432/nanosiem".to_string());
    PgPool::connect(&url).await.expect("connect test db")
}

async fn create_user(pool: &PgPool) -> Uuid {
    let id = Uuid::now_v7();
    sqlx::query(
        r#"INSERT INTO users (id, email, name, password_hash, status, created_at, updated_at)
           VALUES ($1, $2, 'Stats Test', 'x', 'active', NOW(), NOW())"#,
    )
    .bind(id)
    .bind(format!("stats-{id}@example.com"))
    .execute(pool)
    .await
    .expect("create user");
    id
}

async fn make_case(repo: &CaseRepository, owner: Uuid, visibility: &str, severity: Severity) {
    repo.create(&NewCase {
        title: format!("c-{}", Uuid::now_v7()),
        description: Some("regression fixture".to_string()),
        severity,
        priority: 0,
        assigned_to: None,
        assigned_group: None,
        grouping_key: None,
        grouping_type: None,
        visibility: Some(visibility.to_string()),
        created_by: Some(owner),
        group_ids: None,
    })
    .await
    .expect("create case");
}

#[tokio::test]
async fn stats_excludes_private_cases_owned_by_others() {
    let pool = pool().await;
    let repo = CaseRepository::new(pool.clone());

    let admin = create_user(&pool).await;
    let viewer = create_user(&pool).await;

    // Public case both can see.
    make_case(&repo, admin, "public", Severity::Medium).await;
    // Private case admin owns; viewer must not see it in aggregates.
    make_case(&repo, admin, "private", Severity::High).await;

    let admin_stats = repo.get_stats(admin, &[]).await.expect("admin stats");
    let viewer_stats = repo.get_stats(viewer, &[]).await.expect("viewer stats");

    assert!(
        viewer_stats.total < admin_stats.total,
        "viewer total {} should be < admin total {} when admin owns a private case",
        viewer_stats.total,
        admin_stats.total
    );
    let admin_high = admin_stats.by_severity.get("high").copied().unwrap_or(0);
    let viewer_high = viewer_stats.by_severity.get("high").copied().unwrap_or(0);
    assert!(
        viewer_high < admin_high,
        "viewer high-sev {} should be < admin high-sev {}",
        viewer_high,
        admin_high
    );
}

#[tokio::test]
async fn stats_total_does_not_exceed_visible_count() {
    let pool = pool().await;
    let repo = CaseRepository::new(pool.clone());

    let viewer = create_user(&pool).await;
    let other = create_user(&pool).await;

    make_case(&repo, viewer, "public", Severity::Low).await;
    make_case(&repo, other, "private", Severity::Critical).await;
    make_case(&repo, other, "private", Severity::Critical).await;

    let stats = repo.get_stats(viewer, &[]).await.expect("stats");
    let visible_count = repo
        .count(
            &nanosiem_core::CaseFilter {
                status: None,
                severity: None,
                assigned_to: None,
                assigned_group: None,
                mentioned_by: None,
                search: None,
                created_after: None,
                created_before: None,
                visibility: None,
            },
            viewer,
        )
        .await
        .expect("count");

    assert!(
        stats.total <= visible_count,
        "stats.total {} must not exceed list-visible count {}",
        stats.total,
        visible_count
    );
    let stats_crit = stats.by_severity.get("critical").copied().unwrap_or(0);
    assert!(
        stats_crit <= visible_count,
        "severity bucket critical={} must not exceed visible count {}",
        stats_crit,
        visible_count
    );
}

#[tokio::test]
async fn stats_exclude_ids_subtracts_demo_peer_cases() {
    let pool = pool().await;
    let repo = CaseRepository::new(pool.clone());

    let demo_user = create_user(&pool).await;

    // Two public cases owned by the same demo user (both visible).
    make_case(&repo, demo_user, "public", Severity::Medium).await;
    make_case(&repo, demo_user, "public", Severity::Medium).await;

    let baseline = repo.get_stats(demo_user, &[]).await.expect("baseline");
    // Pull one of them out via the exclude list — typeids aren't exposed by
    // the test helper, so use the most recent two public cases as a proxy.
    let ids: Vec<Uuid> = sqlx::query_scalar(
        "SELECT id FROM cases WHERE created_by = $1 AND visibility = 'public' LIMIT 1",
    )
    .bind(demo_user)
    .fetch_all(&pool)
    .await
    .expect("fetch ids");

    let excluded = repo.get_stats(demo_user, &ids).await.expect("excluded");
    assert_eq!(
        excluded.total,
        baseline.total - ids.len() as i64,
        "exclude_ids should reduce total by the excluded count",
    );
}
