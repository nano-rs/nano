// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL access for `ingest_tokens` / `ingest_token_settings` (358).
//! Every statement is scoped by `tenant_id`.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::{
    is_push_capable, route_key, BindableSource, IngestToken, IngestTokenSettings, TokenFileEntry,
};

#[derive(Error, Debug)]
pub enum IngestTokenRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("an active ingest token named {0:?} already exists")]
    DuplicateName(String),
}

pub struct IngestTokenRepository {
    pool: PgPool,
}

/// Token columns plus the bound source (`log_sources` is the deployment's
/// parser registry on open core / dedicated; joined by id).
const TOKEN_SELECT: &str = "SELECT t.id, t.name, t.token_prefix, t.created_at, t.created_by, t.last_used_at,
        t.revoked_at, t.revoked_by, t.source_id, t.source_bound_at, t.request_count,
        ls.name AS source_name, ls.source_type AS source_transport, ls.match_values AS source_match_values
   FROM ingest_tokens t
   LEFT JOIN log_sources ls ON ls.id = t.source_id";

/// The route key of a joined source, when it can still receive pushed events.
fn joined_route(row: &sqlx::postgres::PgRow) -> Result<Option<(String, String)>, sqlx::Error> {
    let name: Option<String> = row.try_get("source_name")?;
    let transport: Option<String> = row.try_get("source_transport")?;
    let match_values: Option<Vec<String>> = row.try_get("source_match_values")?;
    Ok(match (name, transport) {
        (Some(name), Some(transport)) if is_push_capable(&transport) => {
            let route = route_key(match_values.as_deref(), &name);
            Some((name, route))
        }
        _ => None,
    })
}

fn row_to_token(row: &sqlx::postgres::PgRow) -> Result<IngestToken, sqlx::Error> {
    let revoked_at: Option<DateTime<Utc>> = row.try_get("revoked_at")?;
    let source = joined_route(row)?;
    let state = if revoked_at.is_some() {
        "revoked"
    } else if source.is_none() {
        "unbound"
    } else {
        "active"
    };
    let (source_name, route_key) = source.unzip();
    Ok(IngestToken {
        credential_id: row.try_get("id")?,
        name: row.try_get("name")?,
        token_prefix: row.try_get("token_prefix")?,
        state: state.to_string(),
        source_id: row.try_get("source_id")?,
        source_name,
        route_key,
        source_bound_at: row.try_get("source_bound_at")?,
        request_count: row.try_get("request_count")?,
        created_at: row.try_get("created_at")?,
        created_by: row.try_get("created_by")?,
        last_used_at: row.try_get("last_used_at")?,
        revoked_at,
        revoked_by: row.try_get("revoked_by")?,
        revocable: revoked_at.is_none(),
    })
}

fn row_to_source(row: &sqlx::postgres::PgRow) -> Result<BindableSource, sqlx::Error> {
    let name: String = row.try_get("name")?;
    let match_values: Option<Vec<String>> = row.try_get("match_values")?;
    Ok(BindableSource {
        source_id: row.try_get("id")?,
        route_key: route_key(match_values.as_deref(), &name),
        name,
        source_type: row.try_get("source_type")?,
        enabled: row.try_get("enabled")?,
    })
}

fn row_to_settings(row: &sqlx::postgres::PgRow) -> Result<IngestTokenSettings, sqlx::Error> {
    Ok(IngestTokenSettings {
        install_token_enabled: row.try_get("install_token_enabled")?,
        install_token_source_id: row.try_get("install_token_source_id")?,
        install_token_source_bound_at: row.try_get("install_token_source_bound_at")?,
        updated_at: row.try_get("updated_at")?,
        updated_by: row.try_get("updated_by")?,
    })
}

const SETTINGS_COLUMNS: &str =
    "install_token_enabled, install_token_source_id, install_token_source_bound_at, updated_at, updated_by";

impl IngestTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Every token of the tenant, active first, newest first.
    pub async fn list(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<IngestToken>, IngestTokenRepositoryError> {
        let rows = sqlx::query(&format!(
            "{TOKEN_SELECT} WHERE t.tenant_id = $1
             ORDER BY (t.revoked_at IS NULL) DESC, t.created_at DESC, t.id"
        ))
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_token).collect::<Result<_, _>>()?)
    }

    pub async fn get(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<IngestToken>, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "{TOKEN_SELECT} WHERE t.tenant_id = $1 AND t.id = $2"
        ))
        .bind(tenant_id)
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_token).transpose()?)
    }

    /// Log sources a token can be bound to (push-capable transports), by name.
    pub async fn bindable_sources(&self) -> Result<Vec<BindableSource>, IngestTokenRepositoryError> {
        let rows = sqlx::query(
            "SELECT id, name, source_type, match_values, enabled FROM log_sources ORDER BY lower(name), id",
        )
        .fetch_all(&self.pool)
        .await?;
        let sources: Vec<BindableSource> = rows.iter().map(row_to_source).collect::<Result<_, _>>()?;
        Ok(sources
            .into_iter()
            .filter(|source| is_push_capable(&source.source_type))
            .collect())
    }

    /// One bindable source; `None` when it does not exist or cannot receive
    /// pushed events.
    pub async fn bindable_source(
        &self,
        source_id: Uuid,
    ) -> Result<Option<BindableSource>, IngestTokenRepositoryError> {
        let row = sqlx::query(
            "SELECT id, name, source_type, match_values, enabled FROM log_sources WHERE id = $1",
        )
        .bind(source_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row
            .as_ref()
            .map(row_to_source)
            .transpose()?
            .filter(|source| is_push_capable(&source.source_type)))
    }

    /// Inserts a token bound to `source_id`. `sha256_hex` is the hash of a
    /// freshly generated value; the value itself never reaches this layer.
    pub async fn create(
        &self,
        tenant_id: Uuid,
        name: &str,
        token_prefix: &str,
        sha256_hex: &str,
        source_id: Uuid,
        created_by: Option<Uuid>,
    ) -> Result<IngestToken, IngestTokenRepositoryError> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO ingest_tokens
                (tenant_id, name, token_prefix, token_sha256, created_by, source_id, source_bound_at, source_bound_by)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), $5)
             RETURNING id",
        )
        .bind(tenant_id)
        .bind(name)
        .bind(token_prefix)
        .bind(sha256_hex)
        .bind(created_by)
        .bind(source_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| match &error {
            sqlx::Error::Database(db)
                if db.constraint() == Some("ingest_tokens_active_name") =>
            {
                IngestTokenRepositoryError::DuplicateName(name.to_string())
            }
            _ => IngestTokenRepositoryError::Database(error),
        })?;
        self.get(tenant_id, id)
            .await?
            .ok_or(IngestTokenRepositoryError::Database(sqlx::Error::RowNotFound))
    }

    /// Binds an active token whose binding is still `expected` (its current
    /// `source_id`, `None` when it never had one). `None` when the token is
    /// revoked, gone, or was bound concurrently.
    pub async fn bind(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        expected: Option<Uuid>,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<Option<IngestToken>, IngestTokenRepositoryError> {
        let updated = sqlx::query(
            "UPDATE ingest_tokens
                SET source_id = $4, source_bound_at = NOW(), source_bound_by = $5
              WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL
                AND source_id IS NOT DISTINCT FROM $3",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(expected)
        .bind(source_id)
        .bind(actor)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Ok(None);
        }
        self.get(tenant_id, id).await
    }

    /// Revokes an active token. `None` when the token does not exist or was
    /// already revoked (the caller distinguishes with [`Self::get`]).
    pub async fn revoke(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        revoked_by: Option<Uuid>,
    ) -> Result<Option<IngestToken>, IngestTokenRepositoryError> {
        let updated = sqlx::query(
            "UPDATE ingest_tokens SET revoked_at = NOW(), revoked_by = $3
             WHERE tenant_id = $1 AND id = $2 AND revoked_at IS NULL",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(revoked_by)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Ok(None);
        }
        self.get(tenant_id, id).await
    }

    /// The tokens Vector's file lists: active and bound to a source that can
    /// still receive pushed events, each with that source's route key. An
    /// unbound token is not listed, so Vector refuses it.
    pub async fn active_entries(
        &self,
        tenant_id: Uuid,
    ) -> Result<Vec<TokenFileEntry>, IngestTokenRepositoryError> {
        let rows = sqlx::query(
            "SELECT t.id, t.token_sha256, ls.name AS source_name, ls.source_type AS source_transport,
                    ls.match_values AS source_match_values
               FROM ingest_tokens t
               JOIN log_sources ls ON ls.id = t.source_id
              WHERE t.tenant_id = $1 AND t.revoked_at IS NULL
              ORDER BY t.id",
        )
        .bind(tenant_id)
        .fetch_all(&self.pool)
        .await?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            if let Some((_, route)) = joined_route(row)? {
                entries.push(TokenFileEntry {
                    id: row.try_get("id")?,
                    sha256: row.try_get("token_sha256")?,
                    route,
                });
            }
        }
        Ok(entries)
    }

    pub async fn settings(
        &self,
        tenant_id: Uuid,
    ) -> Result<IngestTokenSettings, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "SELECT {SETTINGS_COLUMNS} FROM ingest_token_settings WHERE tenant_id = $1"
        ))
        .bind(tenant_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => row_to_settings(&row)?,
            None => IngestTokenSettings::default(),
        })
    }

    pub async fn set_install_token_enabled(
        &self,
        tenant_id: Uuid,
        enabled: bool,
        updated_by: Option<Uuid>,
    ) -> Result<IngestTokenSettings, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "INSERT INTO ingest_token_settings (tenant_id, install_token_enabled, updated_by, updated_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (tenant_id) DO UPDATE
               SET install_token_enabled = EXCLUDED.install_token_enabled,
                   updated_by = EXCLUDED.updated_by,
                   updated_at = EXCLUDED.updated_at
             RETURNING {SETTINGS_COLUMNS}"
        ))
        .bind(tenant_id)
        .bind(enabled)
        .bind(updated_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_to_settings(&row)?)
    }

    /// Binds the install token while its binding is still `expected`. `None`
    /// when it was bound concurrently.
    pub async fn bind_install_token(
        &self,
        tenant_id: Uuid,
        expected: Option<Uuid>,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<Option<IngestTokenSettings>, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "INSERT INTO ingest_token_settings
                (tenant_id, install_token_enabled, install_token_source_id, install_token_source_bound_at,
                 install_token_source_bound_by, updated_by, updated_at)
             VALUES ($1, TRUE, $3, NOW(), $4, $4, NOW())
             ON CONFLICT (tenant_id) DO UPDATE
               SET install_token_source_id = EXCLUDED.install_token_source_id,
                   install_token_source_bound_at = EXCLUDED.install_token_source_bound_at,
                   install_token_source_bound_by = EXCLUDED.install_token_source_bound_by,
                   updated_by = EXCLUDED.updated_by,
                   updated_at = EXCLUDED.updated_at
             WHERE ingest_token_settings.install_token_source_id IS NOT DISTINCT FROM $2
             RETURNING {SETTINGS_COLUMNS}"
        ))
        .bind(tenant_id)
        .bind(expected)
        .bind(source_id)
        .bind(actor)
        .fetch_optional(&self.pool)
        .await?;
        Ok(row.as_ref().map(row_to_settings).transpose()?)
    }

    /// Records Vector's per-credential request counters (`counts` = the raw
    /// counter values just sampled). Each token's `request_count` grows by
    /// the counter's increase since `vector_request_counter` (the whole value
    /// on the first sample or after a counter reset), and `last_used_at`
    /// moves to `at` when it grew (never backwards). Atomic per row, so
    /// several replicas sampling the same value count it once. Returns the
    /// number of tokens that were used.
    pub async fn record_usage(
        &self,
        tenant_id: Uuid,
        counts: &[(Uuid, f64)],
        at: DateTime<Utc>,
    ) -> Result<u64, IngestTokenRepositoryError> {
        if counts.is_empty() {
            return Ok(0);
        }
        let ids: Vec<Uuid> = counts.iter().map(|(id, _)| *id).collect();
        let values: Vec<f64> = counts.iter().map(|(_, value)| *value).collect();
        let used: i64 = sqlx::query_scalar(
            "WITH updated AS (
                 UPDATE ingest_tokens t
                    SET request_count = t.request_count + GREATEST(
                            CASE WHEN t.vector_request_counter IS NULL OR s.counter < t.vector_request_counter
                                 THEN s.counter ELSE s.counter - t.vector_request_counter END, 0)::BIGINT,
                        last_used_at = CASE
                            WHEN (t.vector_request_counter IS NULL AND s.counter > 0)
                                 OR s.counter > t.vector_request_counter
                                 OR (s.counter < t.vector_request_counter AND s.counter > 0)
                            THEN GREATEST(t.last_used_at, $4)
                            ELSE t.last_used_at END,
                        vector_request_counter = s.counter
                   FROM unnest($2::uuid[], $3::float8[]) AS s(id, counter)
                  WHERE t.tenant_id = $1 AND t.id = s.id
                    AND t.vector_request_counter IS DISTINCT FROM s.counter
                 RETURNING t.last_used_at
             )
             SELECT count(*) FILTER (WHERE last_used_at = $4) FROM updated",
        )
        .bind(tenant_id)
        .bind(&ids)
        .bind(&values)
        .bind(at)
        .fetch_one(&self.pool)
        .await?;
        Ok(used.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    //! DB-backed: needs a disposable PostgreSQL at NANOSIEM_TEST_DATABASE_URL.
    //! Each test creates a throwaway schema with `tenants`, a minimal
    //! `log_sources`, and migrations 358 + 363.
    use super::*;

    const T1: Uuid = Uuid::from_u128(0x100);
    const T2: Uuid = Uuid::from_u128(0x200);
    const APACHE: Uuid = Uuid::from_u128(0xa1);
    const FIREWALL: Uuid = Uuid::from_u128(0xf1);
    const OTLP: Uuid = Uuid::from_u128(0x07);

    fn migration(sql: &str, schema: &str) -> String {
        sql.replace("public.", &format!("{schema}."))
            .replace("SET LOCAL lock_timeout = '5s';", "")
    }

    /// A schema with 358 applied. `before_363` runs between 358 and 363 (the
    /// state an upgrade migrates); 363 runs after it.
    async fn pool_with(before_363: &str) -> Option<(PgPool, String)> {
        let url = std::env::var("NANOSIEM_TEST_DATABASE_URL").ok()?;
        let schema = format!("nan3806_{}", Uuid::new_v4().simple());
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .after_connect({
                let schema = schema.clone();
                move |conn, _| {
                    let schema = schema.clone();
                    Box::pin(async move {
                        sqlx::Executor::execute(
                            conn,
                            format!("SET search_path TO {schema}").as_str(),
                        )
                        .await
                        .map(|_| ())
                    })
                }
            })
            .connect(&url)
            .await
            .expect("connect");
        let setup = format!(
            "CREATE SCHEMA {schema};
             CREATE TABLE {schema}.tenants (id UUID PRIMARY KEY);
             INSERT INTO {schema}.tenants VALUES ('{T1}'), ('{T2}');
             CREATE TABLE {schema}.log_sources (
                 id UUID PRIMARY KEY, name TEXT NOT NULL, source_type TEXT NOT NULL,
                 match_values TEXT[], enabled BOOLEAN NOT NULL DEFAULT TRUE);"
        );
        sqlx::raw_sql(&setup).execute(&pool).await.expect("setup");
        sqlx::raw_sql(&migration(
            include_str!("../../../migrations/postgres/358_ingest_tokens.sql"),
            &schema,
        ))
        .execute(&pool)
        .await
        .expect("migration 358");
        if !before_363.is_empty() {
            sqlx::raw_sql(before_363).execute(&pool).await.expect("pre-363 state");
        }
        sqlx::raw_sql(&migration(
            include_str!("../../../migrations/postgres/363_ingest_token_sources.sql"),
            &schema,
        ))
        .execute(&pool)
        .await
        .expect("migration 363");
        Some((pool, schema))
    }

    async fn drop_schema(pool: &PgPool, schema: &str) {
        sqlx::raw_sql(&format!("DROP SCHEMA {schema} CASCADE"))
            .execute(pool)
            .await
            .unwrap();
    }

    fn legacy_token(tenant: Uuid, name: &str) -> String {
        let token = super::super::generate_token();
        format!(
            "INSERT INTO ingest_tokens (tenant_id, name, token_prefix, token_sha256)
             VALUES ('{tenant}', '{name}', '{}', '{}');",
            token.prefix, token.sha256_hex
        )
    }

    fn source(id: Uuid, name: &str, source_type: &str, values: &str, enabled: bool) -> String {
        format!(
            "INSERT INTO log_sources (id, name, source_type, match_values, enabled)
             VALUES ('{id}', '{name}', '{source_type}', {values}, {enabled});"
        )
    }

    #[tokio::test]
    #[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
    async fn lifecycle_is_tenant_scoped_and_bound() {
        // APACHE is installed after 363: with it as the only push source at
        // migration time, 363 would bind T1's install token (T1 is the
        // open-core compatibility tenant), and this test checks the unbound
        // default. migration_binds_unambiguous_tokens covers that binding.
        let Some((pool, schema)) =
            pool_with(&source(OTLP, "OTLP logs", "otlp", "ARRAY['otlp_log']", true)).await
        else {
            return;
        };
        sqlx::raw_sql(&source(APACHE, "Apache", "routed", "ARRAY['apache_access','apache']", true))
            .execute(&pool)
            .await
            .unwrap();
        let repo = IngestTokenRepository::new(pool.clone());

        // OTLP never takes a token; the push source does.
        let sources = repo.bindable_sources().await.unwrap();
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].route_key, "apache_access");
        assert!(repo.bindable_source(OTLP).await.unwrap().is_none());

        let a = super::super::generate_token();
        let created = repo
            .create(T1, "firewall", &a.prefix, &a.sha256_hex, APACHE, None)
            .await
            .unwrap();
        assert_eq!(created.state, "active");
        assert_eq!(created.source_id, Some(APACHE));
        assert_eq!(created.route_key.as_deref(), Some("apache_access"));
        assert!(created.revocable);

        // Name unique among active tokens of a tenant, case-insensitively.
        let b = super::super::generate_token();
        assert!(matches!(
            repo.create(T1, "FIREWALL", &b.prefix, &b.sha256_hex, APACHE, None)
                .await,
            Err(IngestTokenRepositoryError::DuplicateName(_))
        ));
        // Another tenant may use the name; it never sees T1's tokens.
        repo.create(T2, "firewall", &b.prefix, &b.sha256_hex, APACHE, None)
            .await
            .unwrap();
        assert_eq!(repo.list(T2).await.unwrap().len(), 1);
        assert!(repo.get(T2, created.credential_id).await.unwrap().is_none());
        assert!(repo
            .revoke(T2, created.credential_id, None)
            .await
            .unwrap()
            .is_none());

        // The file lists the token with its source's route key.
        let entries = repo.active_entries(T1).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].sha256, a.sha256_hex);
        assert_eq!(entries[0].route, "apache_access");

        // A bound token is never rebound.
        assert!(repo
            .bind(T1, created.credential_id, None, APACHE, None)
            .await
            .unwrap()
            .is_none());

        // Deleting the source unbinds the token: listed as unbound, left out of
        // the file (Vector refuses it), and bindable again.
        sqlx::query("DELETE FROM log_sources WHERE id = $1")
            .bind(APACHE)
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(
            repo.get(T1, created.credential_id).await.unwrap().unwrap().state,
            "unbound"
        );
        assert!(repo.active_entries(T1).await.unwrap().is_empty());
        sqlx::raw_sql(&source(FIREWALL, "Firewall", "splunk_hec", "NULL", true))
            .execute(&pool)
            .await
            .unwrap();
        let rebound = repo
            .bind(T1, created.credential_id, Some(APACHE), FIREWALL, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rebound.state, "active");
        assert_eq!(rebound.route_key.as_deref(), Some("firewall"));

        let revoked = repo
            .revoke(T1, created.credential_id, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(revoked.state, "revoked");
        assert!(repo
            .revoke(T1, created.credential_id, None)
            .await
            .unwrap()
            .is_none());
        assert!(repo.active_entries(T1).await.unwrap().is_empty());
        // The name is free again once revoked.
        let c = super::super::generate_token();
        let c_token = repo
            .create(T1, "firewall", &c.prefix, &c.sha256_hex, FIREWALL, None)
            .await
            .unwrap();

        // Settings default to enabled + unbound and are per tenant.
        let settings = repo.settings(T1).await.unwrap();
        assert!(settings.install_token_enabled);
        assert_eq!(settings.install_token_source_id, None);
        assert!(
            !repo
                .set_install_token_enabled(T1, false, None)
                .await
                .unwrap()
                .install_token_enabled
        );
        assert!(!repo.settings(T1).await.unwrap().install_token_enabled);
        assert!(repo.settings(T2).await.unwrap().install_token_enabled);
        let bound = repo
            .bind_install_token(T1, None, FIREWALL, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(bound.install_token_source_id, Some(FIREWALL));
        assert!(!bound.install_token_enabled, "binding keeps the enabled flag");
        assert!(repo
            .bind_install_token(T1, None, FIREWALL, None)
            .await
            .unwrap()
            .is_none());

        // Request counts accumulate from Vector's counter; resets and
        // repeated samples never double count; last_used never moves back.
        let id = c_token.credential_id;
        let now = Utc::now();
        assert_eq!(repo.record_usage(T1, &[(id, 5.0)], now).await.unwrap(), 1);
        assert_eq!(repo.record_usage(T1, &[(id, 5.0)], now).await.unwrap(), 0);
        assert_eq!(repo.record_usage(T1, &[(id, 8.0)], now).await.unwrap(), 1);
        assert_eq!(repo.record_usage(T1, &[(id, 2.0)], now).await.unwrap(), 1);
        let earlier = now - chrono::Duration::minutes(5);
        repo.record_usage(T1, &[(id, 3.0)], earlier).await.unwrap();
        let token = repo.get(T1, id).await.unwrap().unwrap();
        assert_eq!(token.request_count, 5 + 3 + 2 + 1);
        assert_eq!(
            token.last_used_at.map(|t| t.timestamp_micros()),
            Some(now.timestamp_micros())
        );
        // Another tenant's counter never touches T1.
        repo.record_usage(T2, &[(id, 100.0)], now).await.unwrap();
        assert_eq!(repo.get(T1, id).await.unwrap().unwrap().request_count, 11);

        // The token hash is never in a listed row.
        let listed = serde_json::to_string(&repo.list(T1).await.unwrap()).unwrap();
        assert!(!listed.contains(&c.sha256_hex));
        assert!(!listed.contains(&c.value));

        drop_schema(&pool, &schema).await;
    }

    /// Migration 363, unambiguous case: one enabled push source (OTLP and
    /// disabled sources do not count) binds every live token and the install
    /// token; revoked tokens stay as they were.
    #[tokio::test]
    #[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
    async fn migration_binds_unambiguous_tokens() {
        let Some((pool, schema)) = pool_with(&format!(
            "{}{}{}{}{}
             UPDATE ingest_tokens SET revoked_at = NOW() WHERE name = 'old';",
            source(APACHE, "Apache", "routed", "ARRAY['apache_access']", true),
            source(OTLP, "OTLP logs", "otlp", "ARRAY['otlp_log']", true),
            source(FIREWALL, "Firewall", "splunk_hec", "NULL", false),
            legacy_token(T1, "edge-01"),
            legacy_token(T1, "old"),
        ))
        .await
        else {
            return;
        };
        let repo = IngestTokenRepository::new(pool.clone());
        let tokens = repo.list(T1).await.unwrap();
        let edge = tokens.iter().find(|t| t.name == "edge-01").unwrap();
        assert_eq!(edge.state, "active");
        assert_eq!(edge.source_id, Some(APACHE));
        assert!(edge.source_bound_at.is_some());
        let old = tokens.iter().find(|t| t.name == "old").unwrap();
        assert_eq!(old.state, "revoked");
        assert_eq!(old.source_id, None);
        let settings = repo.settings(T1).await.unwrap();
        assert_eq!(settings.install_token_source_id, Some(APACHE));
        assert!(settings.install_token_enabled);
        let entries = repo.active_entries(T1).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, "apache_access");

        // Idempotent: a second run changes nothing.
        sqlx::raw_sql(&migration(
            include_str!("../../../migrations/postgres/363_ingest_token_sources.sql"),
            &schema,
        ))
        .execute(&pool)
        .await
        .unwrap();
        assert_eq!(repo.list(T1).await.unwrap(), tokens);
        drop_schema(&pool, &schema).await;
    }

    /// Migration 363, several push sources: only a token whose name names
    /// exactly one source is bound; the rest (and the install token) stay
    /// unbound, out of the file, refused until an admin binds them.
    #[tokio::test]
    #[ignore = "requires a disposable NANOSIEM_TEST_DATABASE_URL"]
    async fn migration_leaves_ambiguous_tokens_unbound() {
        let Some((pool, schema)) = pool_with(&format!(
            "{}{}{}{}{}",
            source(APACHE, "Apache", "routed", "ARRAY['apache_access','web']", true),
            source(FIREWALL, "Firewall", "splunk_hec", "ARRAY['pan_traffic','web']", true),
            legacy_token(T1, "PAN_traffic"),
            legacy_token(T1, "web"),
            legacy_token(T1, "edge-01"),
        ))
        .await
        else {
            return;
        };
        let repo = IngestTokenRepository::new(pool.clone());
        let tokens = repo.list(T1).await.unwrap();
        let by_name = |name: &str| tokens.iter().find(|t| t.name == name).unwrap().clone();
        assert_eq!(by_name("PAN_traffic").source_id, Some(FIREWALL));
        assert_eq!(by_name("PAN_traffic").state, "active");
        for name in ["web", "edge-01"] {
            assert_eq!(by_name(name).state, "unbound", "{name}");
            assert_eq!(by_name(name).source_id, None, "{name}");
        }
        assert_eq!(repo.settings(T1).await.unwrap().install_token_source_id, None);
        let entries = repo.active_entries(T1).await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].route, "pan_traffic");

        // An admin binds the unbound token: it joins the file.
        let web = by_name("web");
        repo.bind(T1, web.credential_id, None, APACHE, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(repo.active_entries(T1).await.unwrap().len(), 2);
        drop_schema(&pool, &schema).await;
    }
}
