// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL reads of `landing_sources` / `landing_files` (364, 374).
//! NAN-4629: several tenants may share one database (an MSSP sovereign
//! install), so every read is bound to the caller's tenant: no other
//! tenant's source, name, file or count is ever returned. Rows without a
//! tenant (pre-374, not yet adopted by the converter) belong to no tenant.

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::{clamp_files_limit, LandingFile, LandingSourceStatus};

#[derive(Error, Debug)]
pub enum LandingSourceRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct LandingSourceRepository {
    pool: PgPool,
}

fn row_to_status(row: &sqlx::postgres::PgRow) -> Result<LandingSourceStatus, sqlx::Error> {
    Ok(LandingSourceStatus {
        source_id: row.try_get("source_id")?,
        name: row.try_get("name")?,
        route_key: row.try_get("route_key")?,
        credential_id: row.try_get("credential_id")?,
        state: row.try_get("state")?,
        created_at: row.try_get("created_at")?,
        revoked_at: row.try_get("revoked_at")?,
        files_accepted: row.try_get("files_accepted")?,
        files_refused: row.try_get("files_refused")?,
        files_in_progress: row.try_get("files_in_progress")?,
        rows_accepted: row.try_get("rows_accepted")?,
        rows_refused: row.try_get("rows_refused")?,
        redeliveries: row.try_get("redeliveries")?,
        last_seen_at: row.try_get("last_seen_at")?,
        last_finished_at: row.try_get("last_finished_at")?,
        last_refusal_reason: row.try_get("last_refusal_reason")?,
        last_refusal_at: row.try_get("last_refusal_at")?,
    })
}

fn row_to_file(row: &sqlx::postgres::PgRow) -> Result<LandingFile, sqlx::Error> {
    Ok(LandingFile {
        id: row.try_get("id")?,
        object_key: row.try_get("object_key")?,
        etag: row.try_get("etag")?,
        source_id: row.try_get("source_id")?,
        size_bytes: row.try_get("size_bytes")?,
        state: row.try_get("state")?,
        rows_accepted: row.try_get("rows_accepted")?,
        rows_refused: row.try_get("rows_refused")?,
        reason: row.try_get("reason")?,
        content_sha256: row.try_get("content_sha256")?,
        bronze_key: row.try_get("bronze_key")?,
        attempts: row.try_get("attempts")?,
        redeliveries: row.try_get("redeliveries")?,
        lease_until: row.try_get("lease_until")?,
        first_seen_at: row.try_get("first_seen_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

/// Every bucket-drop source of `$1` (the tenant) with its totals. Each
/// lateral is bound to the source's tenant as well, so a foreign file that
/// names this source id is never counted.
pub(crate) const LIST_SOURCES_SQL: &str = "SELECT s.source_id, ls.name, s.route_key, s.credential_id, s.state,
                    s.created_at, s.revoked_at,
                    COALESCE(f.files_accepted, 0)::BIGINT AS files_accepted,
                    COALESCE(f.files_refused, 0)::BIGINT AS files_refused,
                    COALESCE(f.files_in_progress, 0)::BIGINT AS files_in_progress,
                    COALESCE(f.rows_accepted, 0)::BIGINT AS rows_accepted,
                    COALESCE(f.rows_refused, 0)::BIGINT AS rows_refused,
                    COALESCE(f.redeliveries, 0)::BIGINT AS redeliveries,
                    f.last_seen_at, f.last_finished_at,
                    r.reason AS last_refusal_reason,
                    r.finished_at AS last_refusal_at
             FROM landing_sources s
             JOIN log_sources ls ON ls.id = s.source_id
             LEFT JOIN LATERAL (
                 SELECT COUNT(*) FILTER (WHERE state = 'accepted') AS files_accepted,
                        COUNT(*) FILTER (WHERE state = 'refused') AS files_refused,
                        COUNT(*) FILTER (WHERE state IN ('listed', 'claimed')) AS files_in_progress,
                        SUM(rows_accepted) AS rows_accepted,
                        SUM(rows_refused) AS rows_refused,
                        SUM(redeliveries) AS redeliveries,
                        MAX(first_seen_at) AS last_seen_at,
                        MAX(finished_at) AS last_finished_at
                 FROM landing_files
                 WHERE source_id = s.source_id AND tenant_id = $1
             ) f ON TRUE
             LEFT JOIN LATERAL (
                 SELECT reason, COALESCE(finished_at, first_seen_at) AS finished_at
                 FROM landing_files
                 WHERE source_id = s.source_id AND tenant_id = $1 AND state = 'refused'
                 ORDER BY finished_at DESC NULLS LAST, id DESC
                 LIMIT 1
             ) r ON TRUE
             WHERE s.tenant_id = $1
             ORDER BY (s.state = 'active') DESC, s.created_at DESC, s.source_id";

/// A source's files, `$1` the tenant.
pub(crate) const LIST_FILES_SQL: &str = "SELECT id, object_key, etag, source_id, size_bytes, state, rows_accepted,
                    rows_refused, reason, content_sha256, bronze_key, attempts, redeliveries,
                    lease_until, first_seen_at, finished_at
             FROM landing_files
             WHERE tenant_id = $1 AND source_id = $2 AND ($3::TEXT IS NULL OR state = $3)
             ORDER BY first_seen_at DESC, id DESC
             LIMIT $4";

/// Whether the source is the tenant's (`$1`).
pub(crate) const SOURCE_EXISTS_SQL: &str =
    "SELECT EXISTS (SELECT 1 FROM landing_sources WHERE tenant_id = $1 AND source_id = $2)";

impl LandingSourceRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The tenant's bucket-drop sources with their totals, active first,
    /// newest first.
    pub async fn list_sources(
        &self,
        tenant_id: &str,
    ) -> Result<Vec<LandingSourceStatus>, LandingSourceRepositoryError> {
        let rows = sqlx::query(LIST_SOURCES_SQL)
            .bind(tenant_id)
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_status).collect::<Result<_, _>>()?)
    }

    /// The tenant's source's most recent files, newest first. `limit` is
    /// clamped to `1..=200`; `state` must already be validated by the caller.
    pub async fn list_files(
        &self,
        tenant_id: &str,
        source_id: Uuid,
        limit: Option<i64>,
        state: Option<&str>,
    ) -> Result<Vec<LandingFile>, LandingSourceRepositoryError> {
        let rows = sqlx::query(LIST_FILES_SQL)
            .bind(tenant_id)
            .bind(source_id)
            .bind(state)
            .bind(clamp_files_limit(limit))
            .fetch_all(&self.pool)
            .await?;
        Ok(rows.iter().map(row_to_file).collect::<Result<_, _>>()?)
    }

    /// Whether `source_id` is one of the tenant's bucket-drop sources.
    pub async fn source_exists(
        &self,
        tenant_id: &str,
        source_id: Uuid,
    ) -> Result<bool, LandingSourceRepositoryError> {
        let row = sqlx::query(SOURCE_EXISTS_SQL)
            .bind(tenant_id)
            .bind(source_id)
            .fetch_one(&self.pool)
            .await?;
        Ok(row.try_get(0)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every `FROM landing_sources` / `FROM landing_files` in a status query
    /// must be bound to the caller's tenant (`$1`). Removing any tenant
    /// predicate fails this; the two-tenant PG test proves the rows.
    #[test]
    fn every_status_query_is_bound_to_the_tenant() {
        fn count(sql: &str, needle: &str) -> usize {
            sql.matches(needle).count()
        }
        // list_sources: the source table plus both laterals.
        assert_eq!(count(LIST_SOURCES_SQL, "FROM landing_sources s"), 1);
        assert_eq!(count(LIST_SOURCES_SQL, "WHERE s.tenant_id = $1"), 1);
        assert_eq!(count(LIST_SOURCES_SQL, "FROM landing_files"), 2);
        assert_eq!(count(LIST_SOURCES_SQL, "WHERE source_id = s.source_id AND tenant_id = $1"), 2);
        assert_eq!(count(LIST_FILES_SQL, "FROM landing_files"), 1);
        assert!(LIST_FILES_SQL.contains("WHERE tenant_id = $1 AND source_id = $2"));
        assert!(SOURCE_EXISTS_SQL.contains("WHERE tenant_id = $1 AND source_id = $2"));
        for sql in [LIST_SOURCES_SQL, LIST_FILES_SQL, SOURCE_EXISTS_SQL] {
            assert!(!sql.contains("tenant_id IS NULL"), "{sql}");
        }
    }

    /// NAN-4629 on PostgreSQL: two tenants on one database. Each tenant's
    /// view lists only its own sources, names and counts; a foreign file that
    /// names this tenant's source id is not counted; another tenant's source
    /// is unknown (no files, `source_exists` false); unadopted rows are nobody's.
    #[tokio::test]
    #[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
    async fn the_status_view_never_crosses_tenants() {
        let Ok(url) = std::env::var("NANOSIEM_TEST_DATABASE_URL") else { return };
        const A: &str = "0f1e2d3c-4b5a-4968-8776-655443322110";
        const B: &str = "7b2d3f1a-0c8e-4d6f-a1b2-c3d4e5f60718";
        let schema = format!("nan4629_api_{}", Uuid::new_v4().simple());
        let search_path = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .after_connect(move |conn, _| {
                let schema = search_path.clone();
                Box::pin(async move {
                    sqlx::Executor::execute(conn, format!("SET search_path TO {schema}").as_str()).await.map(|_| ())
                })
            })
            .connect(&url)
            .await
            .expect("connect");
        sqlx::raw_sql(&format!(
            "CREATE SCHEMA {schema}; CREATE TABLE {schema}.log_sources (id UUID PRIMARY KEY, name TEXT NOT NULL);"
        ))
        .execute(&pool)
        .await
        .expect("setup");
        sqlx::raw_sql(include_str!("../../../migrations/postgres/364_landing_ocsf.sql")).execute(&pool).await.expect("364");
        sqlx::raw_sql(include_str!("../../../migrations/postgres/374_landing_tenant_lister.sql")).execute(&pool).await.expect("374");
        let (a_src, b_src, legacy) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        for (id, name, tenant, user) in [
            (a_src, "a-firewall", Some(A), "nlapia"),
            (b_src, "b-secret-name", Some(B), "nlapib"),
            (legacy, "legacy-unadopted", None, "nlapil"),
        ] {
            sqlx::query("INSERT INTO log_sources (id, name) VALUES ($1, $2)").bind(id).bind(name).execute(&pool).await.unwrap();
            sqlx::query(
                "INSERT INTO landing_sources (source_id, route_key, credential_id, object_user, tenant_id) \
                 VALUES ($1, 'tenzir_x', $2, $3, $4)",
            )
            .bind(id)
            .bind(Uuid::new_v4())
            .bind(user)
            .bind(tenant)
            .execute(&pool)
            .await
            .unwrap();
        }
        // A: one accepted file. B: two refused files, one of them naming A's
        // source id (it can only be B's row: its tenant is B).
        for (key, source, tenant, state, rows) in [
            ("landing-ocsf-v1/tenant_id=a/source=a/1", a_src, A, "accepted", 5_i64),
            ("landing-ocsf-v1/tenant_id=b/source=b/1", b_src, B, "refused", 7),
            ("landing-ocsf-v1/tenant_id=b/source=a/2", a_src, B, "refused", 9),
        ] {
            sqlx::query(
                "INSERT INTO landing_files (tenant_id, object_key, etag, source_id, size_bytes, state, rows_accepted, \
                                            rows_refused, reason, finished_at) \
                 VALUES ($1, $2, 'e', $3, 1, $4, $5, $5, CASE WHEN $4 = 'refused' THEN 'source_unknown' END, NOW())",
            )
            .bind(tenant)
            .bind(key)
            .bind(source)
            .bind(state)
            .bind(rows)
            .execute(&pool)
            .await
            .unwrap();
        }
        let repo = LandingSourceRepository::new(pool.clone());
        let a = repo.list_sources(A).await.unwrap();
        assert_eq!(a.iter().map(|s| (s.source_id, s.name.as_str())).collect::<Vec<_>>(), vec![(a_src, "a-firewall")]);
        assert_eq!((a[0].files_accepted, a[0].files_refused, a[0].rows_accepted, a[0].rows_refused), (1, 0, 5, 5));
        assert_eq!(a[0].last_refusal_reason, None, "B's refusal naming A's source is not A's");
        let b = repo.list_sources(B).await.unwrap();
        assert_eq!(b.iter().map(|s| s.source_id).collect::<Vec<_>>(), vec![b_src]);
        assert_eq!((b[0].files_refused, b[0].rows_refused), (1, 7));
        assert!(repo.list_sources("c0ffee00-0000-4000-8000-000000000000").await.unwrap().is_empty());
        // Files and existence: own only.
        assert!(repo.source_exists(A, a_src).await.unwrap());
        assert!(!repo.source_exists(A, b_src).await.unwrap());
        assert!(!repo.source_exists(B, a_src).await.unwrap());
        assert!(!repo.source_exists(A, legacy).await.unwrap() && !repo.source_exists(B, legacy).await.unwrap());
        let files = repo.list_files(A, a_src, None, None).await.unwrap();
        assert_eq!(files.iter().map(|f| f.object_key.as_str()).collect::<Vec<_>>(), vec!["landing-ocsf-v1/tenant_id=a/source=a/1"]);
        assert!(repo.list_files(A, b_src, None, None).await.unwrap().is_empty());
        let b_files_naming_a = repo.list_files(B, a_src, None, None).await.unwrap();
        assert_eq!(b_files_naming_a.len(), 1, "B sees its own row only");
        sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE")).execute(&pool).await.unwrap();
    }
}
