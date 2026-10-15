// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{
    error::MarketplaceError, repository::MarketplaceRepository,
    sync_service::{run_sync, SYNC_SCHEMA_VERSION},
    types::RepoSyncResult,
};
use sqlx::PgPool;
use std::{path::PathBuf, time::Duration};
use uuid::Uuid;

#[derive(Debug, serde::Serialize, utoipa::ToSchema)]
pub struct SyncNowAccepted {
    pub request_id: Uuid,
    pub repository_id: Uuid,
    pub managed_by_platform: bool,
    pub status: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    #[error("Repository not found or disabled")]
    Unavailable,
    #[error("Platform sync request rate limit exceeded")]
    RateLimited(i64),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

pub async fn request_sync(
    pool: &PgPool,
    id: Uuid,
    tenant_id: Uuid,
    actor_id: Uuid,
    api_key_id: Option<Uuid>,
) -> Result<SyncNowAccepted, RequestError> {
    let mut tx = pool.begin().await?;
    let active = sqlx::query_scalar::<_, Option<Uuid>>(
        "SELECT CASE WHEN last_sync_status='syncing' AND sync_lease_expires_at > clock_timestamp()
         THEN sync_lease_token END FROM enrichment_marketplace_repos WHERE id=$1 AND enabled FOR UPDATE",
    ).bind(id).fetch_optional(&mut *tx).await?.ok_or(RequestError::Unavailable)?;
    let retry = sqlx::query_scalar::<_, i64>(
        "SELECT CEIL(EXTRACT(EPOCH FROM (created_at + INTERVAL '10 minutes' - clock_timestamp())))::bigint
         FROM platform_repository_sync_request_audit WHERE tenant_id=$1 AND repository_id=$2
         AND created_at > clock_timestamp()-INTERVAL '10 minutes' ORDER BY created_at DESC LIMIT 1",
    ).bind(tenant_id).bind(id).fetch_optional(&mut *tx).await?;
    if let Some(seconds) = retry {
        return Err(RequestError::RateLimited(seconds.max(1)));
    }
    let request_id = sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO platform_repository_sync_requests (repository_id, lease_token) VALUES ($1,$2)
         ON CONFLICT (repository_id) WHERE completed_at IS NULL
         DO UPDATE SET repository_id=EXCLUDED.repository_id RETURNING id",
    ).bind(id).bind(active).fetch_one(&mut *tx).await?;
    sqlx::query("INSERT INTO platform_repository_sync_request_audit
        (request_id, repository_id, tenant_id, actor_id, api_key_id) VALUES ($1,$2,$3,$4,$5)")
        .bind(request_id).bind(id).bind(tenant_id).bind(actor_id).bind(api_key_id)
        .execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(SyncNowAccepted { request_id, repository_id: id, managed_by_platform: true, status: "accepted".into() })
}

pub async fn pending_repositories(pool: &PgPool) -> Result<Vec<Uuid>, sqlx::Error> {
    sqlx::query_scalar("SELECT repository_id FROM platform_repository_sync_requests WHERE completed_at IS NULL")
        .fetch_all(pool).await
}

pub(super) async fn sync(
    pool: &PgPool,
    repository: &MarketplaceRepository,
    data_dir: &PathBuf,
    id: Uuid,
) -> Result<RepoSyncResult, MarketplaceError> {
    let repo = repository.get_repo(id).await?;
    let token = claim(pool, id).await?;
    let repository = repository.with_platform_lease(id, token);
    let result = run_with_heartbeat(pool, id, token, run_sync(&repo, &repository, data_dir)).await;
    finish(pool, id, token, &result).await?;
    result
}

async fn claim(pool: &PgPool, id: Uuid) -> Result<Uuid, MarketplaceError> {
    let token = Uuid::new_v4();
    let mut tx = pool.begin().await?;
    let locked = sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM enrichment_marketplace_repos WHERE id=$1 AND enabled FOR UPDATE",
    ).bind(id).fetch_optional(&mut *tx).await?;
    if locked.is_none() {
        return Err(MarketplaceError::SyncInProgress(id));
    }
    // Recheck requests after locking: a previous worker may have completed while we waited.
    let available = sqlx::query_scalar::<_, Uuid>("SELECT id FROM enrichment_marketplace_repos
        WHERE id=$1 AND enabled
          AND (EXISTS (SELECT 1 FROM platform_repository_sync_requests WHERE repository_id=$1 AND completed_at IS NULL)
               OR (auto_sync_enabled AND (last_synced_at IS NULL
                   OR last_synced_at + sync_interval_hours * INTERVAL '1 hour' < clock_timestamp())))
          AND (last_sync_status IS DISTINCT FROM 'syncing'
            OR sync_lease_expires_at IS NULL OR sync_lease_expires_at <= clock_timestamp())")
        .bind(id).fetch_optional(&mut *tx).await?;
    if available.is_none() {
        return Err(MarketplaceError::SyncInProgress(id));
    }
    sqlx::query("INSERT INTO platform_repository_sync_audit (repository_id, lease_token, phase, error)
        SELECT id, sync_lease_token, 'failed', 'Previous platform sync worker stopped'
        FROM enrichment_marketplace_repos WHERE id=$1 AND last_sync_status='syncing' AND sync_lease_token IS NOT NULL")
        .bind(id).execute(&mut *tx).await?;
    sqlx::query("UPDATE enrichment_marketplace_repos SET last_sync_status='syncing', last_sync_error=NULL,
        sync_started_at=clock_timestamp(), sync_lease_expires_at=clock_timestamp()+INTERVAL '15 minutes', sync_lease_token=$2 WHERE id=$1")
        .bind(id).bind(token).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO platform_repository_sync_audit (repository_id, lease_token, phase) VALUES ($1,$2,'started')")
        .bind(id).bind(token).execute(&mut *tx).await?;
    sqlx::query("UPDATE platform_repository_sync_requests SET lease_token=$2 WHERE repository_id=$1 AND completed_at IS NULL")
        .bind(id).bind(token).execute(&mut *tx).await?;
    tx.commit().await?;

    Ok(token)
}

async fn finish(
    pool: &PgPool,
    id: Uuid,
    token: Uuid,
    result: &Result<RepoSyncResult, MarketplaceError>,
) -> Result<(), MarketplaceError> {
    let mut tx = pool.begin().await?;
    let (phase, commit, count, error) = match &result {
        Ok(value) => (
            "success",
            value.commit.as_deref(),
            Some(value.enrichment_count),
            None,
        ),
        Err(error) => ("failed", None, None, Some(error.to_string())),
    };
    let changed = sqlx::query("UPDATE enrichment_marketplace_repos SET last_sync_status=$3, last_sync_error=$4,
        last_synced_at=CASE WHEN $3='success' THEN NOW() ELSE last_synced_at END,
        last_sync_commit=COALESCE($5,last_sync_commit), enrichment_count=COALESCE($6,enrichment_count),
        last_sync_schema_version=CASE WHEN $3='success' THEN $7 ELSE last_sync_schema_version END, updated_at=NOW()
        WHERE id=$1 AND sync_lease_token=$2 AND last_sync_status='syncing'
        AND ($3='failed' OR sync_lease_expires_at > clock_timestamp())")
        .bind(id).bind(token).bind(phase).bind(&error).bind(commit).bind(count).bind(SYNC_SCHEMA_VERSION)
        .execute(&mut *tx).await?.rows_affected();
    if changed != 1 {
        return Err(MarketplaceError::SyncInProgress(id));
    }
    sqlx::query("INSERT INTO platform_repository_sync_audit (repository_id, lease_token, phase, error) VALUES ($1,$2,$3,$4)")
        .bind(id).bind(token).bind(phase).bind(&error).execute(&mut *tx).await?;
    sqlx::query("UPDATE platform_repository_sync_requests SET completed_at=clock_timestamp(), error=$3
        WHERE repository_id=$1 AND lease_token=$2 AND completed_at IS NULL")
        .bind(id).bind(token).bind(error).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(())
}

async fn run_with_heartbeat<T>(
    pool: &PgPool,
    id: Uuid,
    token: Uuid,
    work: impl std::future::Future<Output = Result<T, MarketplaceError>>,
) -> Result<T, MarketplaceError> {
    tokio::pin!(work);
    let mut heartbeat = tokio::time::interval(Duration::from_secs(60));
    heartbeat.tick().await;
    let deadline = tokio::time::sleep(Duration::from_secs(3600));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            result = &mut work => return result,
            _ = &mut deadline => return Err(MarketplaceError::Internal("Platform sync exceeded one hour".into())),
            _ = heartbeat.tick() => {
                let renewal = sqlx::query("UPDATE enrichment_marketplace_repos SET sync_lease_expires_at=clock_timestamp()+INTERVAL '15 minutes'
                    WHERE id=$1 AND sync_lease_token=$2 AND last_sync_status='syncing' AND sync_lease_expires_at > clock_timestamp()")
                    .bind(id).bind(token).execute(pool);
                let result = tokio::time::timeout(Duration::from_secs(30), renewal).await
                    .map_err(|_| MarketplaceError::Internal("Platform sync lease renewal timed out".into()))??;
                if result.rows_affected() != 1 { return Err(MarketplaceError::SyncInProgress(id)); }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::types::MarketplaceCatalogEntry;
    use super::*;

    async fn assert_request_admission(pool: &PgPool, id: Uuid) -> Uuid {
        let tenant = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let (first, duplicate) = tokio::join!(
            request_sync(pool, id, tenant, actor, None),
            request_sync(pool, id, tenant, actor, None),
        );
        let request = match (first, duplicate) {
            (Ok(request), Err(RequestError::RateLimited(seconds))) |
            (Err(RequestError::RateLimited(seconds)), Ok(request)) => {
                assert!((1..=600).contains(&seconds));
                request
            }
            results => panic!("Expected exactly one accepted request: {results:?}"),
        };
        let second_tenant = request_sync(pool, id, Uuid::new_v4(), actor, None).await.unwrap();
        assert_eq!(request.request_id, second_tenant.request_id);
        let token = claim(pool, id).await.unwrap();
        assert!(matches!(claim(pool, id).await, Err(MarketplaceError::SyncInProgress(_))));
        let during_sync = request_sync(pool, id, Uuid::new_v4(), actor, None).await.unwrap();
        assert_eq!(request.request_id, during_sync.request_id);
        let linked: Uuid = sqlx::query_scalar("SELECT lease_token FROM platform_repository_sync_requests WHERE id=$1")
            .bind(request.request_id).fetch_one(pool).await.unwrap();
        assert_eq!(linked, token);
        let audited: (Uuid, Uuid) = sqlx::query_as("SELECT tenant_id, actor_id FROM platform_repository_sync_request_audit WHERE request_id=$1 ORDER BY created_at LIMIT 1")
            .bind(request.request_id).fetch_one(pool).await.unwrap();
        assert_eq!(audited, (tenant, actor));
        sqlx::query("UPDATE platform_repository_sync_request_audit SET created_at=NOW()-INTERVAL '11 minutes' WHERE tenant_id=$1")
            .bind(tenant).execute(pool).await.unwrap();
        assert_eq!(request_sync(pool, id, tenant, actor, None).await.unwrap().request_id, request.request_id);
        token
    }

    #[tokio::test]
    #[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
    async fn repository_sync_platform_catalog_fences_writes_and_respects_schedule() {
        let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").expect("disposable PostgreSQL URL");
        let admin = PgPool::connect(&url).await.unwrap();
        let schema = format!("platform_sync_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let options: sqlx::postgres::PgConnectOptions = url.parse().unwrap();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .connect_with(options.options([("search_path", schema.as_str())]))
            .await
            .unwrap();
        sqlx::raw_sql("CREATE TABLE users (id UUID PRIMARY KEY); CREATE TABLE custom_enrichments (id UUID PRIMARY KEY);
            CREATE TABLE rule_repositories (last_sync_status TEXT, last_sync_error TEXT);
            CREATE TABLE parser_repositories (last_sync_status TEXT, last_sync_error TEXT);")
            .execute(&pool).await.unwrap();
        let catalog_ddl = include_str!("../../../migrations/postgres/101_marketplace_catalog.sql")
            .split("-- Seed IPinfo Lite")
            .next()
            .unwrap();
        sqlx::raw_sql(catalog_ddl).execute(&pool).await.unwrap();
        sqlx::raw_sql("ALTER TABLE marketplace_catalog ADD COLUMN changelog TEXT")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::raw_sql(include_str!(
            "../../../migrations/postgres/329_repository_sync_leases.sql"
        ))
        .execute(&pool)
        .await
        .unwrap();
        sqlx::raw_sql(include_str!("../../../migrations/postgres/330_platform_repository_sync_requests.sql"))
            .execute(&pool).await.unwrap();
        sqlx::raw_sql(include_str!("../../../migrations/postgres/341_marketplace_sync_schema_version.sql"))
            .execute(&pool).await.unwrap();
        let repository = MarketplaceRepository::new(pool.clone());
        let mut ids = Vec::new();
        for slug in ["nano-integrations", "nano-enrichments"] {
            let id = Uuid::new_v4();
            let token = Uuid::new_v4();
            ids.push(id);
            sqlx::query("INSERT INTO enrichment_marketplace_repos
                (id,name,slug,url,auto_sync_enabled,last_sync_status,sync_started_at,sync_lease_expires_at,sync_lease_token)
                VALUES ($1,$2,$2,'https://github.com/nano-rs/test',true,'syncing',NOW()-INTERVAL '16 minutes',NOW()-INTERVAL '1 minute',$3)")
                .bind(id).bind(slug).bind(token).execute(&pool).await.unwrap();
            let token = assert_request_admission(&pool, id).await;
            let writer = repository.with_platform_lease(id, token);
            let entry = MarketplaceCatalogEntry {
                slug: slug.into(),
                name: slug.into(),
                category: "data".into(),
                source_type: "repository".into(),
                repository_id: Some(id),
                execution_backend: "native".into(),
                requires_credential: "none".into(),
                // There is intentionally no enrichment_sources table: platform
                // sync must never hydrate tenant runtime state.
                native_source_id: Some("platform-fixture".into()),
                ..Default::default()
            };
            writer.upsert_catalog_entry(&entry).await.unwrap();
            writer.get_catalog_entry(slug).await.unwrap();
            sqlx::query("UPDATE enrichment_marketplace_repos SET sync_lease_token=$2 WHERE id=$1")
                .bind(id)
                .bind(Uuid::new_v4())
                .execute(&pool)
                .await
                .unwrap();
            assert!(matches!(
                finish(
                    &pool,
                    id,
                    token,
                    &Err(MarketplaceError::Internal("late worker".into()))
                )
                .await,
                Err(MarketplaceError::SyncInProgress(_))
            ));
            assert!(matches!(
                writer.upsert_catalog_entry(&entry).await,
                Err(MarketplaceError::SyncInProgress(_))
            ));
            assert!(matches!(
                writer.remove_stale_repo_entries(id, &[]).await,
                Err(MarketplaceError::SyncInProgress(_))
            ));
        }
        assert_eq!(
            repository.list_repos_for_auto_sync().await.unwrap().len(),
            2
        );
        for id in &ids {
            let token: Uuid = sqlx::query_scalar(
                "SELECT sync_lease_token FROM enrichment_marketplace_repos WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
            let result = Ok(RepoSyncResult {
                repository_id: *id,
                status: "success".into(),
                commit: Some("fixture".into()),
                enrichment_count: 1,
                enrichments_added: 1,
                enrichments_updated: 0,
                enrichments_removed: 0,
                duration_ms: 1,
                error: None,
            });
            sqlx::query("UPDATE enrichment_marketplace_repos SET sync_started_at=NOW()-INTERVAL '16 minutes',
                sync_lease_expires_at=NOW()-INTERVAL '1 minute' WHERE id=$1")
                .bind(id).execute(&pool).await.unwrap();
            assert!(matches!(
                finish(&pool, *id, token, &result).await,
                Err(MarketplaceError::SyncInProgress(_))
            ));
            sqlx::query("UPDATE enrichment_marketplace_repos SET sync_lease_expires_at=NOW()+INTERVAL '15 minutes' WHERE id=$1")
                .bind(id).execute(&pool).await.unwrap();
            sqlx::query("UPDATE platform_repository_sync_requests SET lease_token=$2 WHERE repository_id=$1")
                .bind(id).bind(token).execute(&pool).await.unwrap();
            finish(&pool, *id, token, &result).await.unwrap();
            let version: i32 = sqlx::query_scalar(
                "SELECT last_sync_schema_version FROM enrichment_marketplace_repos WHERE id=$1",
            )
            .bind(id)
            .fetch_one(&pool)
            .await
            .unwrap();
            assert_eq!(version, SYNC_SCHEMA_VERSION, "a successful platform sync records the version");
            assert_eq!(repository.get_repo(*id).await.unwrap().last_sync_schema_version, SYNC_SCHEMA_VERSION);
        }
        assert!(repository
            .list_repos_for_auto_sync()
            .await
            .unwrap()
            .is_empty());
        sqlx::query("UPDATE enrichment_marketplace_repos SET sync_interval_hours=1, last_synced_at=NOW()-INTERVAL '2 hours' WHERE id=$1")
            .bind(ids[0]).execute(&pool).await.unwrap();
        assert_eq!(
            repository.list_repos_for_auto_sync().await.unwrap()[0].id,
            ids[0]
        );
        sqlx::query("UPDATE enrichment_marketplace_repos SET auto_sync_enabled=false")
            .execute(&pool)
            .await
            .unwrap();
        assert!(repository
            .list_repos_for_auto_sync()
            .await
            .unwrap()
            .is_empty());
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM marketplace_catalog")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 2);
        let audited: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM platform_repository_sync_audit")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(audited, 6);
        assert!(pending_repositories(&pool).await.unwrap().is_empty());
        sqlx::query("UPDATE enrichment_marketplace_repos SET auto_sync_enabled=false WHERE id=$1")
            .bind(ids[0]).execute(&pool).await.unwrap();
        let manual = request_sync(&pool, ids[0], Uuid::new_v4(), Uuid::new_v4(), None).await.unwrap();
        assert!(manual.managed_by_platform);
        let token = claim(&pool, ids[0]).await.unwrap();
        finish(&pool, ids[0], token, &Err(MarketplaceError::Internal("fixture failure".into()))).await.unwrap();
        assert!(pending_repositories(&pool).await.unwrap().is_empty());
        assert!(matches!(claim(&pool, ids[0]).await, Err(MarketplaceError::SyncInProgress(_))));
        sqlx::query("UPDATE enrichment_marketplace_repos SET auto_sync_enabled=true, last_synced_at=NULL WHERE id=$1")
            .bind(ids[0]).execute(&pool).await.unwrap();
        let scheduled = claim(&pool, ids[0]).await.unwrap();
        let joined = request_sync(&pool, ids[0], Uuid::new_v4(), Uuid::new_v4(), None).await.unwrap();
        let linked: Uuid = sqlx::query_scalar("SELECT lease_token FROM platform_repository_sync_requests WHERE id=$1")
            .bind(joined.request_id).fetch_one(&pool).await.unwrap();
        assert_eq!(linked, scheduled);
        finish(&pool, ids[0], scheduled, &Err(MarketplaceError::Internal("fixture failure".into()))).await.unwrap();
        assert!(pending_repositories(&pool).await.unwrap().is_empty());
        sqlx::query("UPDATE enrichment_marketplace_repos SET enabled=false WHERE id=$1")
            .bind(ids[0]).execute(&pool).await.unwrap();
        for id in [ids[0], Uuid::new_v4()] {
            assert!(matches!(request_sync(&pool, id, Uuid::new_v4(), Uuid::new_v4(), None).await,
                Err(RequestError::Unavailable)));
        }
        pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(&admin)
            .await
            .unwrap();
    }
}
