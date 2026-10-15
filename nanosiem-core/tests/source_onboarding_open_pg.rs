// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3769: the dedicated (open core) source onboarding storage path.
//!
//! Open core's `detection_rules` has no `tenant_id` column; only the enterprise
//! schema adds it. The dedicated adapter used to read rule references with
//! `WHERE tenant_id=$1`, so every open-core `GET /api/source-onboarding` failed
//! with "Source onboarding storage unavailable". This suite runs the exact
//! dedicated read/mutate/export sequence against the open-core table shapes
//! plus the real onboarding migration.
//!
//! Run: `TEST_DATABASE_URL=postgres://... cargo test -p nanosiem-core \
//!   --test source_onboarding_open_pg -- --ignored`

use nanosiem_core::source_onboarding::{
    repository::SourceOnboardingRepository as Repo,
    service::{self, Action, PlanningFields, SourceOnboardingService as Service},
};
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;

const TENANT: Uuid = Uuid::from_u128(0x100);

/// Open-core shapes of the tables the onboarding path touches. Deliberately
/// no `tenant_id` on `detection_rules`, matching `migrations/postgres`.
const OPEN_TABLES: &str = r#"
CREATE TABLE tenants (id UUID PRIMARY KEY);
CREATE TABLE detection_rules (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    query TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'staging',
    archived BOOLEAN NOT NULL DEFAULT FALSE
);
"#;

async fn isolated_pool() -> (PgPool, PgPool, String) {
    let url = std::env::var("TEST_DATABASE_URL")
        .expect("TEST_DATABASE_URL must reference a disposable PostgreSQL database");
    let admin = PgPool::connect(&url)
        .await
        .expect("connect test PostgreSQL");
    let schema = format!("source_onboarding_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .expect("create isolated schema");
    let search_path = schema.clone();
    let pool = PgPoolOptions::new()
        .max_connections(2)
        .after_connect(move |connection, _| {
            let statement = format!("SET search_path TO {search_path}");
            Box::pin(async move {
                sqlx::query(&statement).execute(connection).await?;
                Ok(())
            })
        })
        .connect(&url)
        .await
        .expect("connect isolated pool");
    sqlx::raw_sql(OPEN_TABLES)
        .execute(&pool)
        .await
        .expect("create open-core tables");
    // The core migration schema-qualifies `public.`; retarget it at the
    // isolated schema so parallel runs never share state.
    let migration = include_str!("../../migrations/postgres/353_source_onboarding.sql")
        .replace("public.", &format!("{schema}."));
    let mut tx = pool.begin().await.expect("begin migration");
    sqlx::raw_sql(&migration)
        .execute(&mut *tx)
        .await
        .expect("apply core source onboarding migration");
    tx.commit().await.expect("commit migration");
    sqlx::query("INSERT INTO tenants(id) VALUES ($1)")
        .bind(TENANT)
        .execute(&pool)
        .await
        .expect("seed dedicated tenant");
    (admin, pool, schema)
}

async fn drop_schema(admin: &PgPool, pool: PgPool, schema: &str) {
    pool.close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(admin)
        .await
        .expect("drop isolated schema");
}

fn fields(name: &str, wave_id: Option<Uuid>) -> PlanningFields {
    PlanningFields {
        name: name.into(),
        vendor: "Okta".into(),
        expected_type: Some("okta".into()),
        wave_id,
        priority: 1,
        owner: "soc".into(),
        target: None,
        notes: String::new(),
    }
}

#[tokio::test]
#[ignore = "requires TEST_DATABASE_URL; uses a disposable per-test schema"]
async fn dedicated_plan_reads_mutates_and_exports_on_open_core_schema() {
    let (admin, pool, schema) = isolated_pool().await;
    sqlx::query(
        "INSERT INTO detection_rules(id,name,query,mode) VALUES ($1,'okta live','source_type=\"okta\" | stats count by user','live'),($2,'okta staging','source_type=\"okta\"','staging')",
    )
    .bind(Uuid::new_v4())
    .bind(Uuid::new_v4())
    .execute(&pool)
    .await
    .expect("seed rules");

    // Root cause pin: the pre-fix tenant-filtered read is invalid on this schema.
    let error = sqlx::query("SELECT id FROM detection_rules WHERE tenant_id=$1")
        .bind(TENANT)
        .fetch_all(&pool)
        .await
        .expect_err("open-core detection_rules has no tenant_id");
    assert_eq!(
        error.as_database_error().and_then(|e| e.code()).as_deref(),
        Some("42703"),
        "undefined_column"
    );

    // GET: empty plan + rule references, no tenant_id column required.
    let mut tx = pool.begin().await.expect("begin read");
    let plan = Repo::read(&mut tx, TENANT).await.expect("read empty plan");
    assert!(plan.waves.is_empty() && plan.sources.is_empty());
    let rules = service::read_dedicated_rules(&mut tx)
        .await
        .expect("dedicated rule read must not need detection_rules.tenant_id");
    assert_eq!(
        rules.len(),
        1,
        "only the live rule is a reference: {rules:?}"
    );
    assert_eq!(rules[0].sources, vec!["okta".to_string()]);
    tx.rollback().await.expect("rollback read");

    // POST actions: create a wave, then a source in it.
    let mut tx = pool.begin().await.expect("begin wave");
    let action = Action::CreateWave {
        name: "Wave 1".into(),
        target: None,
    };
    Service::apply(&mut tx, TENANT, Uuid::nil(), &action, &[], &rules)
        .await
        .expect("create wave");
    tx.commit().await.expect("commit wave");
    let mut tx = pool.begin().await.expect("begin source");
    let wave = Repo::read(&mut tx, TENANT).await.expect("read wave").waves[0].id;
    let action = Action::CreateSource {
        fields: fields("Okta system log", Some(wave)),
    };
    Service::apply(&mut tx, TENANT, Uuid::nil(), &action, &[], &rules)
        .await
        .expect("create source");
    tx.commit().await.expect("commit source");

    // GET + export.
    let mut tx = pool.begin().await.expect("begin export");
    let plan = Repo::read(&mut tx, TENANT).await.expect("read plan");
    let rules = service::read_dedicated_rules(&mut tx).await.expect("rules");
    tx.rollback().await.expect("rollback export");
    assert_eq!(plan.waves.len(), 1);
    assert_eq!(plan.sources.len(), 1);
    assert_eq!(plan.sources[0].wave_id, Some(wave));
    let joined = Service::join(plan, vec![], &rules);
    let csv = service::export(&joined).expect("export csv");
    let mut lines = csv.lines();
    assert!(lines
        .next()
        .expect("header")
        .starts_with("name,vendor,wave"));
    let row = lines.next().expect("one planned source row");
    assert!(
        row.starts_with("Okta system log,Okta,Wave 1,1,soc,"),
        "unexpected CSV row: {row}"
    );

    drop_schema(&admin, pool, &schema).await;
}
