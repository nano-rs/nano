// SPDX-License-Identifier: AGPL-3.0-or-later

//! Transaction-pool transport and the explicit bounded session exception.
//! Unknown roles fail closed; ownership consumers require a separate direct URL.
use sqlx::postgres::PgConnectOptions;

pub fn safe_role(login: &str) -> bool {
    let role = login.split('.').next().unwrap_or(login);
    data_path_role(role) || matches!(
        role,
        "nano_shared_app_control"
            | "nano_shared_reclaim_maint"
            | "nano_shared_app_runtime"
            | "nano_shared_erasure_runner"
            | "nano_shared_readiness_attestor"
            | "nano_shared_provisioner"
            | "nano_shared_retention_plan_operator"
            | "nano_shared_tenant_access_operator"
            | "nano_shared_uid_capability_issuer"
            | "nano_shared_r2_owner_observer"
            | "nano_shared_r2_writer_authority"
            | "nano_shared_r2_writer_verifier"
            | "nano_shared_r2_delete_authority"
            | "nano_shared_iceberg_catalog_authority"
            | "nano_shared_iceberg_catalog_verifier"
            | "nano_shared_r2_copy_registrar"
            | "nano_shared_worker_release_owner"
            | "nano_shared_convergence_worker"
            | "nano_shared_provider_adapter"
            | "nano_shared_r2_credential_rotation_worker"
    )
}

/// Only the capability suffixes emitted by the runtime principal renderer.
fn data_path_role(role: &str) -> bool {
    let bundle = role.strip_prefix("nano_lake_bundle_").is_some_and(|tail| {
        ["builder", "consumer"].iter().any(|suffix| tail.strip_suffix(&format!("_{suffix}")).is_some_and(|id|
            id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))))
    });
    bundle || role.strip_prefix("nano_lake_dp_").is_some_and(|tail| {
        ["event_publish", "publish", "activate", "retention", "job"]
            .iter().any(|suffix| tail.strip_suffix(&format!("_{suffix}")).is_some_and(|id|
                !id.is_empty() && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')))
    })
}

/// Explicit escape hatch for operations that fence external writes across
/// commits. All such app consumers share at most two direct connections.
/// Closing on drop is mandatory: a session lock must never return to the pool.
pub async fn session_connection(pool: &sqlx::PgPool) -> Result<sqlx::pool::PoolConnection<sqlx::Postgres>, sqlx::Error> {
    let direct = session_pool(pool)?;
    let mut connection = direct.acquire().await?;
    connection.close_on_drop();
    Ok(connection)
}

pub fn session_pool(pool: &sqlx::PgPool) -> Result<sqlx::PgPool, sqlx::Error> {
    if pool.connect_options().get_port() != 6432 {
        return Ok(pool.clone());
    }
    static DIRECT: std::sync::OnceLock<sqlx::PgPool> = std::sync::OnceLock::new();
    let url = std::env::var("NANOSIEM_SESSION_DATABASE_URL").map_err(|_| sqlx::Error::Configuration(
        "NANOSIEM_SESSION_DATABASE_URL is required for cross-transaction ownership".into()))?;
    let options: PgConnectOptions = url.parse()?;
    let pooled = pool.connect_options();
    if options.get_port() == 6432 || options.get_host() != pooled.get_host()
        || options.get_database() != pooled.get_database() || options.get_username() != pooled.get_username()
        || std::mem::discriminant(&options.get_ssl_mode()) != std::mem::discriminant(&pooled.get_ssl_mode())
    {
        return Err(sqlx::Error::Configuration("session URL must use the same endpoint, database, login and TLS mode on a direct port".into()));
    }
    let direct_port = options.get_port();
    let direct = DIRECT.get_or_init(|| super::connection_budget::pool_options(2)
        .idle_timeout(std::time::Duration::from_secs(15))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .acquire_timeout(pool.options().get_acquire_timeout())
        .connect_lazy_with(options));
    let existing = direct.connect_options();
    if existing.get_host() != pooled.get_host() || existing.get_database() != pooled.get_database()
        || existing.get_username() != pooled.get_username() || existing.get_port() != direct_port
        || std::mem::discriminant(&existing.get_ssl_mode()) != std::mem::discriminant(&pooled.get_ssl_mode()) {
        return Err(sqlx::Error::Configuration("a process may only have one direct session identity".into()));
    }
    Ok(direct.clone())
}

pub fn connect_lazy(
    pool: sqlx::postgres::PgPoolOptions,
    url: &str,
) -> Result<sqlx::PgPool, sqlx::Error> {
    Ok(pool.min_connections(0).connect_lazy_with(options(url)?))
}

pub fn options(url: &str) -> Result<PgConnectOptions, sqlx::Error> {
    configure(url.parse()?)
}

pub fn configure(options: PgConnectOptions) -> Result<PgConnectOptions, sqlx::Error> {
    if options.get_port() == 6432 && !safe_role(options.get_username()) {
        return Err(sqlx::Error::Configuration(
            "role is not qualified for transaction pooling".into(),
        ));
    }
    // No reliance on PgBouncer's version or protocol prepared-statement support.
    let capacity = std::env::var("NANOSIEM_PG_STATEMENT_CACHE_CAPACITY")
        .ok().map(|value| value.parse::<usize>().map_err(|_| sqlx::Error::Configuration(
            "NANOSIEM_PG_STATEMENT_CACHE_CAPACITY must be a nonnegative integer".into())))
        .transpose()?;
    Ok(match capacity {
        Some(capacity) => options.statement_cache_capacity(capacity),
        None if options.get_port() == 6432 => options.statement_cache_capacity(0),
        None => options,
    })
}

/// Pooled control/convergence sessions cannot SET session timeouts. The rollout
/// installs these as login-role defaults first; refuse boot if that step is absent.
pub async fn attest_timeouts(
    connection: &mut sqlx::PgConnection,
    statement: &str,
    lock: &str,
    idle: &str,
) -> Result<(), sqlx::Error> {
    let valid: bool = sqlx::query_scalar(
        "SELECT current_setting('statement_timeout')::interval = $1::text::interval \
         AND current_setting('lock_timeout')::interval = $2::text::interval \
         AND current_setting('idle_in_transaction_session_timeout')::interval = $3::text::interval",
    )
    .bind(statement)
    .bind(lock)
    .bind(idle)
    .fetch_one(connection)
    .await?;
    if !valid {
        return Err(sqlx::Error::Protocol(
            "pooled role timeout defaults differ; apply the reviewed role-defaults SQL first"
                .into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn classification_keeps_session_consumers_direct() {
        for role in [
            "nano_shared_writer_owner",
            "nano_r2_normal_owner_iad1",
            "postgres",
            "unknown",
        ] {
            assert!(!safe_role(role));
            assert!(options(&format!("postgres://{role}@localhost:6432/db")).is_err());
            assert!(options(&format!("postgres://{role}@localhost:5432/db")).is_ok());
        }
        for role in ["nano_shared_reclaim_maint", "nano_shared_app_control", "nano_lake_dp_fixture_publish", "nano_lake_dp_fixture_event_publish", "nano_lake_dp_fixture_activate", "nano_lake_bundle_0123456789abcdef0123456789abcdef_builder"] {
            assert!(safe_role(role));
            assert!(options(&format!("postgres://{role}@localhost:6432/db")).is_ok());
        }
        for role in ["nano_lake_dp__publish", "nano_lake_dp_x_owner", "nano_lake_dp_x_publish_extra"] { assert!(!safe_role(role)); }
        assert!(safe_role("nano_shared_app_runtime.5khjlxokjx7z"));
        let options =
            options("postgres://nano_shared_app_runtime.branch@localhost:6432/db").unwrap();
        assert_eq!(options.get_port(), 6432);
    }
}

#[cfg(all(test, feature = "enterprise"))]
mod integration {
    use super::*;
    use sqlx::Connection;

    /// Run against an isolated migrated product DB through transaction PgBouncer.
    /// No writes and no production credential fallback. RLS may return no rows;
    /// this qualifies protocol/query shapes, not authorization or capacity.
    #[tokio::test]
    #[ignore = "requires PGBOUNCER_TEST_DATABASE_URL on an isolated migrated product database"]
    async fn pooled_api_hot_query_shapes_under_contention() {
        let url = std::env::var("PGBOUNCER_TEST_DATABASE_URL").unwrap();
        let options = options(&url).unwrap();
        assert_eq!(options.get_port(), 6432);
        let tenant = std::env::var("PGBOUNCER_TEST_TENANT_ID")
            .unwrap()
            .parse::<uuid::Uuid>()
            .unwrap();
        let actor = std::env::var("PGBOUNCER_TEST_ACTOR_ID")
            .unwrap()
            .parse::<uuid::Uuid>()
            .unwrap();
        let signer = std::sync::Arc::new(
            crate::tenant_db::TenantDbContextSigner::new(
                options.get_database().unwrap(),
                options.get_username().split('.').next().unwrap(),
                std::env::var("PGBOUNCER_TEST_KEY_ID")
                    .unwrap()
                    .parse()
                    .unwrap(),
                hex::decode(std::env::var("PGBOUNCER_TEST_CONTEXT_KEY_HEX").unwrap()).unwrap(),
                30,
            )
            .unwrap(),
        );
        let pool = sqlx::postgres::PgPoolOptions::new()
            .min_connections(0)
            .max_connections(12)
            .connect_with(options)
            .await
            .unwrap();
        // Execute the API's actual alert list SELECT (UUID, nullable filters,
        // array predicates, JSON, lateral join, sort and bound pagination).
        let source = include_str!("../enterprise_shared_alert_reads.rs");
        let query = source
            .split("        SELECT a.*,")
            .nth(1)
            .unwrap()
            .split("\"#)")
            .next()
            .unwrap();
        let query = format!("SELECT a.*,{query}");
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..24 {
            let pool = pool.clone();
            let query = query.clone();
            let signer = signer.clone();
            tasks.spawn(async move {
                for _ in 0..8 {
                    let mut tx = signer
                        .begin_transaction(&pool, tenant, actor)
                        .await
                        .unwrap();
                    sqlx::query(&query)
                        .bind(tenant)
                        .bind(None::<uuid::Uuid>)
                        .bind(None::<&str>)
                        .bind(None::<&str>)
                        .bind(None::<uuid::Uuid>)
                        .bind(None::<Vec<String>>)
                        .bind(Vec::<String>::new())
                        .bind(25_i64)
                        .bind(0_i64)
                        .fetch_all(&mut *tx)
                        .await
                        .unwrap();
                    let _: i64 =
                        sqlx::query_scalar("SELECT count(*) FROM alerts WHERE tenant_id=$1")
                            .bind(tenant)
                            .fetch_one(&mut *tx)
                            .await
                            .unwrap();
                    assert_eq!((&mut *tx).cached_statements_size(), 0);
                    tx.commit().await.unwrap();
                }
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        pool.close().await;
    }
}
