// SPDX-License-Identifier: AGPL-3.0-or-later
// Private, disposable PG18 fixture shared by C11's core and composition-root
// regressions. It never accepts a caller/database environment URL.
include!("disposable_postgres.rs");

struct JobsPgFixture {
    _postgres: DisposablePostgres,
    admin: sqlx::PgPool,
    runtime: sqlx::PgPool,
    provisioner: sqlx::PgPool,
    context: std::sync::Arc<nanosiem_core::tenant_db::TenantDbContextSigner>,
}
impl JobsPgFixture {
    async fn new() -> Self {
        Self::new_with_activation_order(true).await
    }
    async fn new_with_activation_order(upgrade: bool) -> Self {
        use sqlx::{PgPool, postgres::PgConnectOptions};
        use std::str::FromStr;
        let postgres = DisposablePostgres::start("pscale_admin");
        let admin = PgPool::connect(&postgres.url("postgres")).await.unwrap();
        sqlx::query("CREATE DATABASE sovereign_jobs_fixture")
            .execute(&admin)
            .await
            .unwrap();
        admin.close().await;
        let options = PgConnectOptions::from_str(&postgres.url("sovereign_jobs_fixture")).unwrap();
        let admin = PgPool::connect_with(options.clone()).await.unwrap();
        sqlx::raw_sql("CREATE ROLE postgres LOGIN CREATEROLE CREATEDB BYPASSRLS INHERIT NOSUPERUSER PASSWORD 'fixture-only';
            ALTER DATABASE sovereign_jobs_fixture OWNER TO postgres;
            CREATE ROLE nano_shared_provisioner LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD 'fixture-only';
            DO $$ BEGIN EXECUTE format('COMMENT ON DATABASE sovereign_jobs_fixture IS %L',
                'nano.managed_bootstrap_admin=pscale-v1:' || (SELECT oid FROM pg_database WHERE datname=current_database()) || ':' ||
                ('postgres'::regrole)::oid || ':' || ('pscale_admin'::regrole)::oid); END $$;")
            .execute(&admin).await.unwrap();
        let migrator = PgPool::connect_with(
            options
                .clone()
                .username("postgres")
                .password("fixture-only"),
        )
        .await
        .unwrap();
        nanosiem_core::db::run_postgres_migrations(&migrator)
            .await
            .unwrap();
        let mut prior = sqlx::migrate!("../migrations/postgres-enterprise");
        prior.migrations = prior
            .migrations
            .iter()
            .filter(|m| !upgrade || m.version < 9015250)
            .cloned()
            .collect::<Vec<_>>()
            .into();
        prior.set_ignore_missing(true);
        prior.run(&migrator).await.unwrap();
        sqlx::query("GRANT USAGE ON SCHEMA nano_shared TO nano_shared_provisioner")
            .execute(&migrator)
            .await
            .unwrap();
        sqlx::raw_sql(
            "CREATE ROLE nano_shared_app_owner NOLOGIN NOINHERIT NOBYPASSRLS;
            CREATE ROLE nano_shared_app_runtime LOGIN NOINHERIT NOBYPASSRLS PASSWORD 'fixture-only';
            GRANT nano_shared_app_owner TO postgres WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
            GRANT nano_shared_app_runtime TO postgres WITH ADMIN TRUE, INHERIT FALSE, SET FALSE;
            GRANT USAGE ON SCHEMA public TO nano_shared_app_runtime;",
        )
        .execute(&admin)
        .await
        .unwrap();
        let key_id = uuid::Uuid::from_u128(2);
        let key = vec![0x41; 32];
        // Fresh full-chain activation and an already-active upgrade are both
        // real non-superuser paths. Generic activation is repeated after C11.
        for _ in 0..2 {
            sqlx::query("SELECT nano_shared.activate_rls_contract('nano_shared_app_runtime','nano_shared_app_owner',$1,$2,now()+interval '2 hours')")
                .bind(key_id).bind(&key).execute(&migrator).await.unwrap();
        }
        let mut chain = sqlx::migrate!("../migrations/postgres-enterprise");
        chain.set_ignore_missing(true);
        chain.run(&migrator).await.unwrap();
        chain.run(&migrator).await.unwrap();
        for _ in 0..2 {
            sqlx::query("SELECT nano_shared.activate_rls_contract('nano_shared_app_runtime','nano_shared_app_owner',$1,$2,now()+interval '2 hours')")
                .bind(key_id).bind(&key).execute(&migrator).await.unwrap();
        }
        // Generic RLS deliberately does not enable the existing detection read
        // surfaces. Use their production activation before the full audit.
        sqlx::query("SELECT nano_shared.activate_detection_runtime_read()")
            .execute(&migrator)
            .await
            .unwrap();
        let dormant: bool = sqlx::query_scalar("SELECT NOT has_table_privilege('nano_shared_app_runtime','nano_shared.sovereign_jobs','SELECT')")
            .fetch_one(&admin).await.unwrap();
        assert!(dormant, "hosted activation cannot enable sovereign jobs");
        for _ in 0..2 {
            sqlx::query("SELECT nano_shared.activate_sovereign_jobs_runtime()")
                .execute(&migrator)
                .await
                .unwrap();
        }
        for _ in 0..2 {
            sqlx::query("SELECT nano_shared.activate_rls_contract('nano_shared_app_runtime','nano_shared_app_owner',$1,$2,now()+interval '2 hours')")
                .bind(key_id).bind(&key).execute(&migrator).await.unwrap();
        }
        let audit: serde_json::Value = sqlx::query_scalar("SELECT COALESCE(jsonb_agg(to_jsonb(a)),'[]'::jsonb) FROM nano_shared.audit_rls_catalog('nano_shared_app_runtime','nano_shared_app_owner') a")
            .fetch_one(&admin).await.unwrap();
        assert_eq!(
            audit,
            serde_json::json!([]),
            "actual audit catalog findings"
        );
        let create: bool = sqlx::query_scalar(
            "SELECT has_schema_privilege('nano_shared_app_owner','nano_shared','CREATE')",
        )
        .fetch_one(&admin)
        .await
        .unwrap();
        assert!(!create, "private DDL privilege cannot persist");
        for n in [1_u128, 11] {
            let tenant = uuid::Uuid::from_u128(n);
            let actor = uuid::Uuid::from_u128(n + 2);
            sqlx::query("INSERT INTO public.tenants(id,slug,display_name,status) VALUES($1,$2,'Sovereign jobs fixture','active')").bind(tenant).bind(format!("jobs-{n}")).execute(&admin).await.unwrap();
            sqlx::query("INSERT INTO public.users(id,email,name,password_hash,status) VALUES($1,$2,'Jobs fixture','x','active')").bind(actor).bind(format!("jobs-{n}@example.invalid")).execute(&admin).await.unwrap();
            sqlx::query("INSERT INTO public.tenant_members(tenant_id,user_id) VALUES($1,$2)")
                .bind(tenant)
                .bind(actor)
                .execute(&admin)
                .await
                .unwrap();
        }
        let provisioner = PgPool::connect_with(
            options
                .clone()
                .username("nano_shared_provisioner")
                .password("fixture-only"),
        )
        .await
        .unwrap();
        let runtime = sqlx::postgres::PgPoolOptions::new()
            .max_connections(8)
            .connect_with(
                options
                    .username("nano_shared_app_runtime")
                    .password("fixture-only"),
            )
            .await
            .unwrap();
        let context = std::sync::Arc::new(
            nanosiem_core::tenant_db::TenantDbContextSigner::new(
                "sovereign_jobs_fixture",
                "nano_shared_app_runtime",
                key_id,
                key,
                30,
            )
            .unwrap(),
        );
        assert!(
            sqlx::query("SELECT nano_shared.activate_sovereign_jobs_runtime()")
                .execute(&runtime)
                .await
                .is_err()
        );
        assert!(
            sqlx::query("SELECT nano_shared.activate_sovereign_jobs_runtime()")
                .execute(&provisioner)
                .await
                .is_err()
        );
        migrator.close().await;
        Self {
            _postgres: postgres,
            admin,
            runtime,
            provisioner,
            context,
        }
    }
}
