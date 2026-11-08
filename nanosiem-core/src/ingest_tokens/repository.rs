// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL access for `ingest_tokens` / `ingest_token_settings` (290).
//! Single-tenant: the settings table is a singleton row.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::{
    is_push_capable, route_key, BindableSource, IngestToken, IngestTokenSettings,
    InstallTokenMode, TokenFileEntry, MULTIPLEX_ROUTE,
};

#[derive(Error, Debug)]
pub enum IngestTokenRepositoryError {
    #[error("database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("an active ingest token named {0:?} already exists")]
    DuplicateName(String),
}

/// Verified sender identity passed from the OTLP edge to Vector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindableSourceCredential {
    pub id: Uuid,
    pub route: String,
}

pub struct IngestTokenRepository {
    pool: PgPool,
}

/// Token columns plus the bound source (joined by id).
const TOKEN_SELECT: &str = "SELECT t.id, t.name, t.token_prefix, t.created_at, t.created_by, t.last_used_at,
        t.revoked_at, t.revoked_by, t.source_id, t.source_bound_at, t.request_count, t.rotated_from,
        ls.name AS source_name, ls.source_type AS source_transport, ls.match_values AS source_match_values
   FROM ingest_tokens t
   LEFT JOIN log_sources ls ON ls.id = t.source_id";

const SOURCE_COLUMNS: &str = "id, name, source_type, match_values, enabled, deployed";

const SETTINGS_COLUMNS: &str = "install_token_enabled, install_token_mode, install_token_source_id,
        install_token_source_bound_at, updated_at, updated_by";

/// A bound source's route key, or `None` when the source cannot carry one: it
/// cannot receive pushed events, or its route key would collide with the
/// multiplex marker.
fn bound_route(name: &str, transport: &str, match_values: Option<&[String]>) -> Option<String> {
    if !is_push_capable(transport) {
        return None;
    }
    let route = route_key(match_values, name);
    routable(&route).then_some(route)
}

/// A route key a token may carry: not empty, not the multiplex marker, and not
/// the internal enrichment lane (`nano_enrich*` feeds identity / IOC / asset
/// tables, never a sender's log source).
fn routable(route: &str) -> bool {
    !route.is_empty()
        && route != MULTIPLEX_ROUTE
        && !route.to_ascii_lowercase().starts_with("nano_enrich")
}

/// The route key of a joined source, when it can still receive pushed events.
fn joined_route(row: &sqlx::postgres::PgRow) -> Result<Option<(String, String)>, sqlx::Error> {
    let name: Option<String> = row.try_get("source_name")?;
    let transport: Option<String> = row.try_get("source_transport")?;
    let match_values: Option<Vec<String>> = row.try_get("source_match_values")?;
    Ok(match (name, transport) {
        (Some(name), Some(transport)) => {
            bound_route(&name, &transport, match_values.as_deref()).map(|route| (name, route))
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
        rotated_from: row.try_get("rotated_from")?,
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
        deployed: row.try_get("deployed")?,
    })
}

fn bindable(source: BindableSource) -> Option<BindableSource> {
    (is_push_capable(&source.source_type) && routable(&source.route_key)).then_some(source)
}

fn row_to_settings(row: &sqlx::postgres::PgRow) -> Result<IngestTokenSettings, sqlx::Error> {
    let mode: String = row.try_get("install_token_mode")?;
    Ok(IngestTokenSettings {
        install_token_enabled: row.try_get("install_token_enabled")?,
        install_token_mode: InstallTokenMode::parse(&mode),
        install_token_source_id: row.try_get("install_token_source_id")?,
        install_token_source_bound_at: row.try_get("install_token_source_bound_at")?,
        updated_at: row.try_get("updated_at")?,
        updated_by: row.try_get("updated_by")?,
    })
}

fn duplicate_name(error: sqlx::Error, name: &str) -> IngestTokenRepositoryError {
    match &error {
        sqlx::Error::Database(db) if db.constraint() == Some("ingest_tokens_active_name") => {
            IngestTokenRepositoryError::DuplicateName(name.to_string())
        }
        _ => IngestTokenRepositoryError::Database(error),
    }
}

impl IngestTokenRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Every token, active first, newest first. Pending rotation
    /// replacements are not listed (their value has not been handed out yet).
    pub async fn list(&self) -> Result<Vec<IngestToken>, IngestTokenRepositoryError> {
        let rows = sqlx::query(&format!(
            "{TOKEN_SELECT} WHERE NOT t.rotation_pending
             ORDER BY (t.revoked_at IS NULL) DESC, t.created_at DESC, t.id"
        ))
        .fetch_all(&self.pool)
        .await?;
        Ok(rows.iter().map(row_to_token).collect::<Result<_, _>>()?)
    }

    pub async fn get(&self, id: Uuid) -> Result<Option<IngestToken>, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!("{TOKEN_SELECT} WHERE t.id = $1"))
            .bind(id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_token).transpose()?)
    }

    /// Log sources a token can be bound to (push-capable transports), by name.
    pub async fn bindable_sources(&self) -> Result<Vec<BindableSource>, IngestTokenRepositoryError> {
        let rows = sqlx::query(&format!(
            "SELECT {SOURCE_COLUMNS} FROM log_sources ORDER BY lower(name), id"
        ))
        .fetch_all(&self.pool)
        .await?;
        let sources: Vec<BindableSource> = rows.iter().map(row_to_source).collect::<Result<_, _>>()?;
        Ok(sources.into_iter().filter_map(bindable).collect())
    }

    /// One bindable source; `None` when it does not exist or cannot receive
    /// pushed events.
    pub async fn bindable_source(
        &self,
        source_id: Uuid,
    ) -> Result<Option<BindableSource>, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!("SELECT {SOURCE_COLUMNS} FROM log_sources WHERE id = $1"))
            .bind(source_id)
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.as_ref().map(row_to_source).transpose()?.and_then(bindable))
    }

    /// Inserts a token bound to `source_id`. `sha256_hex` is the hash of a
    /// freshly generated value; the value itself never reaches this layer.
    pub async fn create(
        &self,
        name: &str,
        token_prefix: &str,
        sha256_hex: &str,
        source_id: Uuid,
        created_by: Option<Uuid>,
    ) -> Result<IngestToken, IngestTokenRepositoryError> {
        let id: Uuid = sqlx::query_scalar(
            "INSERT INTO ingest_tokens
                (name, token_prefix, token_sha256, created_by, source_id, source_bound_at, source_bound_by)
             VALUES ($1, $2, $3, $4, $5, NOW(), $4)
             RETURNING id",
        )
        .bind(name)
        .bind(token_prefix)
        .bind(sha256_hex)
        .bind(created_by)
        .bind(source_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|error| duplicate_name(error, name))?;
        self.get(id)
            .await?
            .ok_or(IngestTokenRepositoryError::Database(sqlx::Error::RowNotFound))
    }

    /// Rotation phase 1: inserts a pending replacement with the same name
    /// and source (`rotated_from` = `id`). The old token stays active. `None`
    /// when the token is not active and bound, or a rotation is already pending.
    pub async fn rotate_begin(
        &self,
        id: Uuid,
        token_prefix: &str,
        sha256_hex: &str,
        actor: Option<Uuid>,
    ) -> Result<Option<IngestToken>, IngestTokenRepositoryError> {
        let new_id: Option<Uuid> = sqlx::query_scalar(
            "INSERT INTO ingest_tokens
                (name, token_prefix, token_sha256, created_by, source_id, source_bound_at,
                 source_bound_by, rotated_from, rotation_pending)
             SELECT t.name, $2, $3, $4, t.source_id, NOW(), $4, t.id, TRUE
               FROM ingest_tokens t
              WHERE t.id = $1 AND t.revoked_at IS NULL AND NOT t.rotation_pending
                AND t.source_id IS NOT NULL
             ON CONFLICT DO NOTHING
             RETURNING id",
        )
        .bind(id)
        .bind(token_prefix)
        .bind(sha256_hex)
        .bind(actor)
        .fetch_optional(&self.pool)
        .await?;
        match new_id {
            Some(new_id) => self.get(new_id).await,
            None => Ok(None),
        }
    }

    /// Rotation phase 2, after the file listing the replacement is published:
    /// revokes the old token and activates the replacement in one
    /// transaction. Returns `(old, new)`; `None` when the pending row is gone.
    pub async fn rotate_commit(
        &self,
        old_id: Uuid,
        new_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<Option<(IngestToken, IngestToken)>, IngestTokenRepositoryError> {
        let mut tx = self.pool.begin().await?;
        sqlx::query(
            "UPDATE ingest_tokens SET revoked_at = NOW(), revoked_by = $2
              WHERE id = $1 AND revoked_at IS NULL",
        )
        .bind(old_id)
        .bind(actor)
        .execute(&mut *tx)
        .await?;
        let activated = sqlx::query(
            "UPDATE ingest_tokens SET rotation_pending = FALSE
              WHERE id = $1 AND rotated_from = $2 AND rotation_pending AND revoked_at IS NULL",
        )
        .bind(new_id)
        .bind(old_id)
        .execute(&mut *tx)
        .await?;
        if activated.rows_affected() == 0 {
            return Ok(None);
        }
        tx.commit().await?;
        let old = self.get(old_id).await?;
        let new = self.get(new_id).await?;
        Ok(old.zip(new))
    }

    /// Rolls a pending rotation back (the replacement's value was never
    /// handed out). The old token is untouched.
    pub async fn rotate_abort(&self, new_id: Uuid) -> Result<(), IngestTokenRepositoryError> {
        sqlx::query("DELETE FROM ingest_tokens WHERE id = $1 AND rotation_pending")
            .bind(new_id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Deletes pending rotation replacements older than `older_than` (left by
    /// a crash between the two phases; their value was never returned).
    pub async fn purge_stale_pending(
        &self,
        older_than: std::time::Duration,
    ) -> Result<u64, IngestTokenRepositoryError> {
        let done = sqlx::query(
            "DELETE FROM ingest_tokens
              WHERE rotation_pending AND created_at < NOW() - make_interval(secs => $1)",
        )
        .bind(older_than.as_secs_f64())
        .execute(&self.pool)
        .await?;
        Ok(done.rows_affected())
    }

    /// Binds an active token whose binding is still `expected` (its current
    /// `source_id`). `None` when the token is revoked, gone, or was bound
    /// concurrently.
    pub async fn bind(
        &self,
        id: Uuid,
        expected: Option<Uuid>,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<Option<IngestToken>, IngestTokenRepositoryError> {
        let updated = sqlx::query(
            "UPDATE ingest_tokens
                SET source_id = $3, source_bound_at = NOW(), source_bound_by = $4
              WHERE id = $1 AND revoked_at IS NULL AND NOT rotation_pending
                AND source_id IS NOT DISTINCT FROM $2",
        )
        .bind(id)
        .bind(expected)
        .bind(source_id)
        .bind(actor)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Ok(None);
        }
        self.get(id).await
    }

    /// Revokes an active token. `None` when the token does not exist or was
    /// already revoked (the caller distinguishes with [`Self::get`]).
    pub async fn revoke(
        &self,
        id: Uuid,
        revoked_by: Option<Uuid>,
    ) -> Result<Option<IngestToken>, IngestTokenRepositoryError> {
        let updated = sqlx::query(
            "UPDATE ingest_tokens SET revoked_at = NOW(), revoked_by = $2
             WHERE id = $1 AND revoked_at IS NULL AND NOT rotation_pending",
        )
        .bind(id)
        .bind(revoked_by)
        .execute(&self.pool)
        .await?;
        if updated.rows_affected() == 0 {
            return Ok(None);
        }
        self.get(id).await
    }

    /// Authenticate an OTLP sender against current database state, without a
    /// positive cache. Disabled/deleted sources and revoked/unbound tokens fail
    /// closed. The hash is never logged or returned.
    pub async fn otlp_credential(
        &self,
        hash: &str,
    ) -> Result<Option<BindableSourceCredential>, IngestTokenRepositoryError> {
        let row = sqlx::query(OTLP_CREDENTIAL_SQL)
        .bind(hash)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let transport: String = row.try_get("source_type")?;
        let name: String = row.try_get("name")?;
        let values: Option<Vec<String>> = row.try_get("match_values")?;
        Ok(bound_route(&name, &transport, values.as_deref()).map(|route| {
            BindableSourceCredential {
                id: row.get("id"),
                route,
            }
        }))
    }

    /// The tokens Vector's file lists: active and bound to a source that can
    /// still receive pushed events, each with that source's route key. An
    /// unbound token is not listed, so Vector refuses it.
    pub async fn active_entries(&self) -> Result<Vec<TokenFileEntry>, IngestTokenRepositoryError> {
        let rows = sqlx::query(
            "SELECT t.id, t.token_sha256, ls.name AS source_name, ls.source_type AS source_transport,
                    ls.match_values AS source_match_values
               FROM ingest_tokens t
               JOIN log_sources ls ON ls.id = t.source_id
              WHERE t.revoked_at IS NULL
              ORDER BY t.id",
        )
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

    pub async fn settings(&self) -> Result<IngestTokenSettings, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "SELECT {SETTINGS_COLUMNS} FROM ingest_token_settings WHERE singleton"
        ))
        .fetch_optional(&self.pool)
        .await?;
        Ok(match row {
            Some(row) => row_to_settings(&row)?,
            None => IngestTokenSettings::default(),
        })
    }

    pub async fn set_install_token_enabled(
        &self,
        enabled: bool,
        updated_by: Option<Uuid>,
    ) -> Result<IngestTokenSettings, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "INSERT INTO ingest_token_settings (singleton, install_token_enabled, updated_by, updated_at)
             VALUES (TRUE, $1, $2, NOW())
             ON CONFLICT (singleton) DO UPDATE
               SET install_token_enabled = EXCLUDED.install_token_enabled,
                   updated_by = EXCLUDED.updated_by,
                   updated_at = EXCLUDED.updated_at
             RETURNING {SETTINGS_COLUMNS}"
        ))
        .bind(enabled)
        .bind(updated_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_to_settings(&row)?)
    }

    /// Leaves legacy multiplex mode for strict mode. One-way: the API never
    /// re-enters the deprecated mode.
    pub async fn set_install_token_strict(
        &self,
        updated_by: Option<Uuid>,
    ) -> Result<IngestTokenSettings, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "INSERT INTO ingest_token_settings (singleton, install_token_mode, updated_by, updated_at)
             VALUES (TRUE, 'strict', $1, NOW())
             ON CONFLICT (singleton) DO UPDATE
               SET install_token_mode = 'strict',
                   updated_by = EXCLUDED.updated_by,
                   updated_at = EXCLUDED.updated_at
             RETURNING {SETTINGS_COLUMNS}"
        ))
        .bind(updated_by)
        .fetch_one(&self.pool)
        .await?;
        Ok(row_to_settings(&row)?)
    }

    /// Binds the install token while its binding is still `expected`, and
    /// switches it to strict mode (a bound install token routes on its source,
    /// never on what the sender declares). `None` when it was bound
    /// concurrently.
    pub async fn bind_install_token(
        &self,
        expected: Option<Uuid>,
        source_id: Uuid,
        actor: Option<Uuid>,
    ) -> Result<Option<IngestTokenSettings>, IngestTokenRepositoryError> {
        let row = sqlx::query(&format!(
            "INSERT INTO ingest_token_settings
                (singleton, install_token_enabled, install_token_mode, install_token_source_id,
                 install_token_source_bound_at, install_token_source_bound_by, updated_by, updated_at)
             VALUES (TRUE, TRUE, 'strict', $2, NOW(), $3, $3, NOW())
             ON CONFLICT (singleton) DO UPDATE
               SET install_token_mode = 'strict',
                   install_token_source_id = EXCLUDED.install_token_source_id,
                   install_token_source_bound_at = EXCLUDED.install_token_source_bound_at,
                   install_token_source_bound_by = EXCLUDED.install_token_source_bound_by,
                   updated_by = EXCLUDED.updated_by,
                   updated_at = EXCLUDED.updated_at
             WHERE ingest_token_settings.install_token_source_id IS NOT DISTINCT FROM $1
             RETURNING {SETTINGS_COLUMNS}"
        ))
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
                            THEN GREATEST(t.last_used_at, $3)
                            ELSE t.last_used_at END,
                        vector_request_counter = s.counter
                   FROM unnest($1::uuid[], $2::float8[]) AS s(id, counter)
                  WHERE t.id = s.id
                    AND t.vector_request_counter IS DISTINCT FROM s.counter
                 RETURNING t.last_used_at
             )
             SELECT count(*) FILTER (WHERE last_used_at = $3) FROM updated",
        )
        .bind(&ids)
        .bind(&values)
        .bind(at)
        .fetch_one(&self.pool)
        .await?;
        Ok(used.max(0) as u64)
    }
}


/// The OTLP edge's credential lookup. A token bound to an undeployed (draft)
/// source authenticates, exactly as HEC and HTTP do through Vector's tokens
/// file: connect-first sources receive before their parser exists
/// (NAN-4912/NAN-4922). `enabled` refuses only a deployed source, the same rule
/// as `log_sources::connect::connect_state`.
pub const OTLP_CREDENTIAL_SQL: &str = "SELECT t.id, ls.name, ls.source_type, ls.match_values FROM ingest_tokens t
             JOIN log_sources ls ON ls.id = t.source_id
             WHERE t.token_sha256 = $1 AND t.revoked_at IS NULL AND (ls.enabled OR NOT ls.deployed)";
