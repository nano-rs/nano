// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4779: the Getting Started checklist on a dedicated deployment (open
//! core, sovereign single-host) against the production schema.
//!
//! Runs every migration through the boot runner, so the seeded rows a fresh
//! install carries (the `system-ai` service account, the OpenTelemetry log
//! source from migration 315) are present. Then it performs each step through
//! the repository the matching page or wizard calls, and checks that exactly
//! that step clears:
//!
//! - fresh install: nothing is checked (the seeded rows do not count);
//! - Add data wizard auto-persists a draft: Log Source clears, Log Parser does not;
//! - the wizard's Save draft (persisted VRL, still a draft): Log Parser clears;
//! - a saved / deployed source with VRL: Log Parser stays clear;
//! - AI Guidance saved with no organization name: AI Guidance clears;
//! - a second human user: Team clears;
//! - a search recorded to history: First Search clears.
//!
//! One test function, so the steps run in order in a single binary. Needs a
//! disposable, freshly created database:
//!
//!   NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1 DATABASE_URL=postgres://… \
//!     cargo test -p nanosiem-core --test onboarding_status_integration -- --ignored

mod common;

use common::migrated_pool;
use nanosiem_core::db::repository::{NewSearchHistoryEntry, SearchHistoryRepository};
use nanosiem_core::log_sources::{LogSourceRepository, NewLogSource, UpdateLogSource};
use nanosiem_core::onboarding::{
    probe_dedicated_onboarding_status, DedicatedProbeInputs, OnboardingStatus,
    PLATFORM_SEEDED_LOG_SOURCES,
};
use nanosiem_core::settings::{OrganizationalContextService, UpdateOrganizationalContextRequest};
use sqlx::PgPool;
use uuid::Uuid;

const OPEN_CORE: DedicatedProbeInputs = DedicatedProbeInputs {
    ai_available: false,
    ai_service_loaded: false,
    sso_available: false,
};

async fn status(pool: &PgPool) -> OnboardingStatus {
    probe_dedicated_onboarding_status(pool, OPEN_CORE).await
}

async fn human_user(pool: &PgPool, email: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO users (email, name, password_hash, status) VALUES ($1, $1, '', 'active') RETURNING id",
    )
    .bind(email)
    .fetch_one(pool)
    .await
    .expect("insert user")
}

fn wizard_feed(name: &str, vrl: &str, lifecycle: Option<&str>) -> NewLogSource {
    // Mirrors the payload AddFeed sends (`source_type: 'routed'`, one match value).
    NewLogSource {
        name: name.to_string(),
        description: None,
        namespace: "default".to_string(),
        timezone: "UTC".to_string(),
        source_type: "routed".to_string(),
        parser_vrl: vrl.to_string(),
        output_fields: None,
        dispatch_source_config_id: None,
        category: None,
        vendor: None,
        product: None,
        icon: None,
        color: None,
        match_field: None,
        match_pattern: None,
        match_values: Some(vec![format!("nan4779_{}", Uuid::new_v4().simple())]),
        sampling_ratio: None,
        sampling_exclude_condition: None,
        lifecycle_status: lifecycle.map(str::to_string),
        extension_vrl: None,
        extension_enabled: None,
    }
}

#[tokio::test]
#[ignore = "requires a disposable, freshly migrated Postgres (DATABASE_URL + NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1)"]
async fn each_getting_started_step_clears_from_the_row_its_page_writes() {
    let pool = migrated_pool().await;

    // The seeded rows a fresh install carries are present...
    let seeded: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_sources WHERE name = ANY($1)")
        .bind(PLATFORM_SEEDED_LOG_SOURCES)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(
        seeded, 1,
        "migration 315 seeds the OpenTelemetry log source"
    );
    let system_users: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM users WHERE status = 'system'")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(system_users >= 1, "the system-ai service account is seeded");

    // ...and none of them checks a step. The first-boot admin is one human.
    human_user(&pool, "nan4779-admin@example.test").await;
    let fresh = status(&pool).await;
    assert!(
        !fresh.has_users,
        "seeded system accounts must not clear Team: {fresh:?}"
    );
    assert!(
        !fresh.has_log_sources,
        "the seeded OTLP source must not clear Log Source: {fresh:?}"
    );
    assert!(
        !fresh.has_parsers,
        "the seeded OTLP parser must not clear Log Parser: {fresh:?}"
    );
    assert!(!fresh.has_org_context, "{fresh:?}");
    assert!(!fresh.has_search_history, "{fresh:?}");
    assert!(
        !fresh.has_ai_provider && !fresh.has_sso,
        "open core has no AI / SSO step: {fresh:?}"
    );

    // Add data wizard, step 1: the feed auto-persists as a draft with no VRL yet.
    let repo = LogSourceRepository::new(pool.clone());
    let draft = repo
        .create(&wizard_feed("nan4779 firewall", "", Some("draft")))
        .await
        .expect("auto-persisted draft");
    let after_draft = status(&pool).await;
    assert!(
        after_draft.has_log_sources,
        "a connected (draft) feed clears Log Source"
    );
    assert!(
        !after_draft.has_parsers,
        "an empty draft is not a parser yet"
    );

    // Save draft writes VRL through update without promoting the lifecycle.
    // Browser-only edits have no database signal; a persisted parser is saved.
    let saved = repo
        .update(
            draft.id,
            &UpdateLogSource {
                parser_vrl: Some(". = parse_json!(.message)".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(saved.lifecycle_status, "draft");
    assert!(
        status(&pool).await.has_parsers,
        "Save draft clears Log Parser before deployment"
    );

    // Save / Deploy in the wizard (no parser-repository import involved): before
    // NAN-4779 this never cleared Log Parser because only parser_imports was read.
    repo.create(&wizard_feed(
        "nan4779 proxy",
        ". = parse_json!(.message)",
        None,
    ))
    .await
    .expect("saved feed");
    assert!(
        status(&pool).await.has_parsers,
        "a saved wizard parser clears Log Parser"
    );

    // AI Guidance saved without an organization name.
    OrganizationalContextService::new(pool.clone())
        .update_context(UpdateOrganizationalContextRequest {
            organization_name: None,
            industry: Some("Healthcare".to_string()),
            environment: None,
            attack_vectors: None,
            compliance_frameworks: None,
            custom_context: None,
            enable_for_chat: None,
            enable_for_query: None,
            enable_for_detection: None,
            enable_for_parser: None,
            enable_for_dashboard: None,
        })
        .await
        .expect("save guidance");
    assert!(
        status(&pool).await.has_org_context,
        "any saved guidance field clears AI Guidance"
    );

    // Team: a second human.
    let analyst = human_user(&pool, "nan4779-analyst@example.test").await;
    assert!(
        status(&pool).await.has_users,
        "a second human user clears Team"
    );

    // First Search: the Search page records the run to history.
    SearchHistoryRepository::new(pool.clone())
        .add(
            analyst,
            &NewSearchHistoryEntry {
                query: "src_ip=10.0.0.1".to_string(),
                query_mode: "piped".to_string(),
                time_range_type: "preset".to_string(),
                time_range_preset: Some("24h".to_string()),
                time_range_start: None,
                time_range_end: None,
            },
        )
        .await
        .expect("record search");
    assert!(
        status(&pool).await.has_search_history,
        "a recorded search clears First Search"
    );
}
