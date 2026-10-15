// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser repository for database operations
//!
//! NOTE: As of migration 051, this repository queries the `log_sources` table
//! instead of the deprecated `parsers` table. The `parsers` table was dropped
//! to eliminate data sync issues between the two tables.

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::types::{NewParser, Parser, ParserDeployment, UpdateParser};

#[derive(Error, Debug)]
pub enum ParserRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Parser not found: {0}")]
    NotFound(Uuid),
    #[error("Parser with name '{0}' already exists")]
    DuplicateName(String),
    /// NAN-2305: the name is unique as a string but its generated Vector
    /// identifier is taken (migration 283's unique index).
    #[error("{0}")]
    GeneratedNameConflict(String),
}

/// NAN-2305: translate the generated-identity unique violation into an error
/// the operator can act on.
///
/// Reachable two ways past `ParserService::ensure_generated_identity_free`: a
/// write racing another write, and a name whose ASCII-normalized form collides
/// while the Unicode-aware Rust check saw none (`Café` vs `Cafe` — see
/// migration 283). Without this the caller gets an opaque 500 for something a
/// rename fixes.
fn map_name_unique_violation(err: sqlx::Error, name: &str) -> ParserRepositoryError {
    if let sqlx::Error::Database(db_err) = &err {
        // PG SQLSTATE 23505 = unique_violation.
        if db_err.code().as_deref() == Some("23505")
            && db_err.constraint() == Some("log_sources_generated_vector_identity")
        {
            return ParserRepositoryError::GeneratedNameConflict(format!(
                "the name '{name}' generates a Vector config filename and router route that \
                 another log source already uses. Generated identifiers lowercase the name and \
                 replace every non-alphanumeric character with '_'. Choose a name that differs \
                 by more than case, spacing or punctuation."
            ));
        }
    }
    ParserRepositoryError::from(err)
}

/// The ONE canonical projection of "what is actually deployed" for every log
/// source. Shared by the direct-deploy path (`LogSourceService`) and by the
/// publication renderer (`ParserService::render_to_vector_config`), so the two
/// can no longer disagree about what a parser IS. NAN-2304.
///
/// Two properties this query owes its callers:
///
/// 1. **The active version, never the editor's working draft.**
///    `log_sources.parser_vrl` / `extension_*` are the working copy the parser
///    editor writes on every save. Publication used to read them directly, so
///    an unvalidated draft nobody chose to deploy shipped straight to Vector:
///    those columns are `source_revision` trigger inputs (migration 229) and
///    the publication reconciler runs every 5s. The active
///    `log_source_versions` row is the published artefact; the working copy is
///    only the fallback for sources that have never been published.
/// 2. **Every deployment-affecting column.** `ParserRepository::list` omitted
///    `sampling_*` and `extension_*`, and `row_to_parser` defaults absent
///    columns OFF — so publishing silently deleted a sampling or extension
///    transform that a direct deploy had emitted.
///
/// `LEFT JOIN LATERAL … LIMIT 1` rather than a plain join on `is_active`: the
/// partial index on `log_source_versions` is not unique, so a plain join would
/// multiply one log source into duplicate parsers — which the NAN-2247
/// source_type collision guard would then refuse to deploy — if two rows were
/// ever active at once. The lateral yields at most one row by construction.
///
/// Disabled sources are included deliberately: `deploy_parsers` needs them in
/// the slice to prune their generated files and legacy credential files, and
/// every downstream consumer filters on `enabled` itself.
const EFFECTIVE_DEPLOYED_PARSERS_SQL: &str = r#"
SELECT
    ls.id, ls.name, ls.description, ls.source_type,
    CASE WHEN active.present THEN active.parser_vrl ELSE ls.parser_vrl END
        AS parser_vrl,
    COALESCE(active.output_fields, ls.output_fields) AS output_fields,
    CASE WHEN active.present THEN active.extension_vrl ELSE ls.extension_vrl END
        AS extension_vrl,
    CASE WHEN active.present THEN active.extension_enabled ELSE ls.extension_enabled END
        AS extension_enabled,
    ls.dispatch_source_config_id, ls.enabled, ls.validated, ls.validation_error,
    ls.namespace, ls.timezone, ls.match_values, ls.category, ls.vendor, ls.product,
    ls.kind, ls.enrich_kind, ls.enrich_source, ls.target_table, ls.normalize_vrl,
    ls.sampling_ratio, ls.sampling_exclude_condition,
    ls.created_at, ls.updated_at
FROM log_sources ls
LEFT JOIN LATERAL (
    SELECT
        TRUE AS present,
        lsv.parser_vrl,
        lsv.output_fields,
        lsv.extension_vrl,
        lsv.extension_enabled
    FROM log_source_versions lsv
    WHERE lsv.log_source_id = ls.id AND lsv.is_active = TRUE
    ORDER BY lsv.version_number DESC, lsv.id DESC
    LIMIT 1
) active ON TRUE
ORDER BY ls.name
"#;

/// Load the effective deployed parser set — see [`EFFECTIVE_DEPLOYED_PARSERS_SQL`].
///
/// Free function (not a method) for the same reason as
/// [`resolve_parser_dispatch_routes`]: `LogSourceService` and `ParserService`
/// both need it and neither owns the other's repository. NAN-2304.
pub async fn list_effective_deployed_parsers(pool: &PgPool) -> Result<Vec<Parser>, sqlx::Error> {
    let rows = sqlx::query(EFFECTIVE_DEPLOYED_PARSERS_SQL)
        .fetch_all(pool)
        .await?;
    Ok(rows.iter().map(row_to_parser).collect())
}

pub struct ParserRepository {
    pool: PgPool,
}

impl ParserRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// See [`list_effective_deployed_parsers`]. NAN-2304.
    pub async fn list_effective_deployed(&self) -> Result<Vec<Parser>, ParserRepositoryError> {
        Ok(list_effective_deployed_parsers(&self.pool).await?)
    }

    pub async fn list(&self) -> Result<Vec<Parser>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                -- NAN-2304: these are deployment-affecting. Omitting them made
                -- `row_to_parser` silently default sampling OFF and the
                -- extension overlay absent for every consumer of this row.
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                created_at, updated_at
            FROM log_sources
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_parser).collect())
    }

    pub async fn list_enabled(&self) -> Result<Vec<Parser>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                -- NAN-2304: these are deployment-affecting. Omitting them made
                -- `row_to_parser` silently default sampling OFF and the
                -- extension overlay absent for every consumer of this row.
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                created_at, updated_at
            FROM log_sources
            WHERE enabled = true
            ORDER BY name
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_parser).collect())
    }

    pub async fn find_by_id(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                -- NAN-2304: these are deployment-affecting. Omitting them made
                -- `row_to_parser` silently default sampling OFF and the
                -- extension overlay absent for every consumer of this row.
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                created_at, updated_at
            FROM log_sources
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    /// NAN-2305: `(id, name)` for every log source, and nothing else.
    ///
    /// The generated-identity guard runs on every create and rename and only
    /// needs names. `list` selects `parser_vrl` and `normalize_vrl` for every
    /// row, so reusing it would drag megabytes of VRL through a name
    /// comparison on each save.
    pub async fn list_identities(&self) -> Result<Vec<(Uuid, String)>, ParserRepositoryError> {
        Ok(
            sqlx::query_as::<_, (Uuid, String)>("SELECT id, name FROM log_sources ORDER BY name")
                .fetch_all(&self.pool)
                .await?,
        )
    }

    pub async fn find_by_name(&self, name: &str) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                -- NAN-2304: these are deployment-affecting. Omitting them made
                -- `row_to_parser` silently default sampling OFF and the
                -- extension overlay absent for every consumer of this row.
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                created_at, updated_at
            FROM log_sources
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| ParserRepositoryError::NotFound(Uuid::nil()))?;

        Ok(row_to_parser(&row))
    }

    pub async fn create(&self, parser: &NewParser) -> Result<Parser, ParserRepositoryError> {
        // Check for duplicate name
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_sources WHERE name = $1")
            .bind(&parser.name)
            .fetch_one(&self.pool)
            .await?;

        if existing > 0 {
            return Err(ParserRepositoryError::DuplicateName(parser.name.clone()));
        }

        let row = sqlx::query(
            r#"
            INSERT INTO log_sources (
                name, description, source_type, parser_vrl, output_fields,
                dispatch_source_config_id
            )
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                created_at, updated_at
            "#,
        )
        .bind(&parser.name)
        .bind(&parser.description)
        .bind(&parser.source_type)
        .bind(&parser.parser_vrl)
        .bind(&parser.output_fields)
        .bind(parser.dispatch_source_config_id)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| map_name_unique_violation(e, &parser.name))?;

        Ok(row_to_parser(&row))
    }

    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateParser,
    ) -> Result<Parser, ParserRepositoryError> {
        // First check if parser exists
        self.find_by_id(id).await?;

        // Check for duplicate name if name is being changed
        if let Some(ref name) = update.name {
            let existing: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM log_sources WHERE name = $1 AND id != $2")
                    .bind(name)
                    .bind(id)
                    .fetch_one(&self.pool)
                    .await?;

            if existing > 0 {
                return Err(ParserRepositoryError::DuplicateName(name.clone()));
            }
        }

        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                source_type = COALESCE($4, source_type),
                parser_vrl = COALESCE($5, parser_vrl),
                output_fields = COALESCE($6, output_fields),
                dispatch_source_config_id = COALESCE($7, dispatch_source_config_id),
                enabled = COALESCE($8, enabled),
                validated = false,
                validation_error = NULL
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.source_type)
        .bind(&update.parser_vrl)
        .bind(&update.output_fields)
        .bind(update.dispatch_source_config_id)
        .bind(update.enabled)
        .fetch_one(&self.pool)
        .await
        // Only a rename can trip the generated-identity index, so an update
        // that leaves `name` alone maps straight through — quoting an empty
        // name back at the caller would be worse than the raw error.
        .map_err(|e| match update.name.as_deref() {
            Some(name) => map_name_unique_violation(e, name),
            None => ParserRepositoryError::from(e),
        })?;

        Ok(row_to_parser(&row))
    }

    pub async fn delete(&self, id: Uuid) -> Result<(), ParserRepositoryError> {
        let result = sqlx::query("DELETE FROM log_sources WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(ParserRepositoryError::NotFound(id));
        }

        Ok(())
    }

    pub async fn set_validation_status(
        &self,
        id: Uuid,
        validated: bool,
        error: Option<&str>,
    ) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                validated = $2,
                validation_error = $3
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(validated)
        .bind(error)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_parser(&row))
    }

    pub async fn enable(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET enabled = true
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    pub async fn disable(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET enabled = false
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    /// Record a deployment action in the log_source_deployments table
    pub async fn record_deployment(
        &self,
        parser_id: Uuid,
        action: &str,
        status: &str,
        error_message: Option<&str>,
        config_snapshot: Option<&str>,
    ) -> Result<ParserDeployment, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            INSERT INTO log_source_deployments (log_source_id, action, status, error_message, config_snapshot)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id, log_source_id, action, status, error_message, config_snapshot, deployed_at
            "#
        )
        .bind(parser_id)
        .bind(action)
        .bind(status)
        .bind(error_message)
        .bind(config_snapshot)
        .fetch_one(&self.pool)
        .await?;

        Ok(ParserDeployment {
            id: row.get("id"),
            parser_id: row.get("log_source_id"),
            action: row.get("action"),
            status: row.get("status"),
            error_message: row.get("error_message"),
            config_snapshot: row.get("config_snapshot"),
            deployed_at: row.get("deployed_at"),
        })
    }

    /// Get deployment history for a parser
    pub async fn get_deployment_history(
        &self,
        parser_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ParserDeployment>, ParserRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, log_source_id, action, status, error_message, config_snapshot, deployed_at
            FROM log_source_deployments
            WHERE log_source_id = $1
            ORDER BY deployed_at DESC
            LIMIT $2
            "#,
        )
        .bind(parser_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| ParserDeployment {
                id: row.get("id"),
                parser_id: row.get("log_source_id"),
                action: row.get("action"),
                status: row.get("status"),
                error_message: row.get("error_message"),
                config_snapshot: row.get("config_snapshot"),
                deployed_at: row.get("deployed_at"),
            })
            .collect())
    }

    /// Mark a parser as deployed (enabled and validated)
    pub async fn mark_deployed(&self, id: Uuid) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                enabled = true,
                validated = true,
                validation_error = NULL,
                deployed = true,
                deployed_at = NOW()
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }

    /// Mark a parser deployment as failed
    pub async fn mark_deployment_failed(
        &self,
        id: Uuid,
        error: &str,
    ) -> Result<Parser, ParserRepositoryError> {
        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                enabled = false,
                validated = false,
                validation_error = $2,
                deployed = false
            WHERE id = $1
            RETURNING
                id, name, description, source_type,
                parser_vrl, output_fields,
                dispatch_source_config_id, enabled, validated, validation_error,
                namespace, timezone, match_values, category, vendor, product,
                kind, enrich_kind, enrich_source, target_table, normalize_vrl,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(error)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(ParserRepositoryError::NotFound(id))?;

        Ok(row_to_parser(&row))
    }
}

/// NAN-3765: an enabled parser left out of a rendered Vector configuration
/// because the stream it consumes is not part of that configuration — its
/// source configuration is not deployed (yet), no longer exists, or the
/// deployment has no listener for its transport.
///
/// Such a parser is rendered as if disabled, so its filter can never reference
/// a missing component (Vector refuses the whole set, and a restart on it does
/// not boot). Everything else in the set still deploys: one parser waiting on
/// its source configuration must not block unrelated changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WaitingParser {
    pub parser_id: Uuid,
    pub parser_name: String,
    /// Operator-facing reason, e.g. "waiting for source configuration 'Hub'
    /// to be deployed".
    pub reason: String,
}

/// What the generator knows about one dispatch target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DispatchTarget {
    pub name: String,
    /// `source_configurations.deployed`: the runtime authority for whether the
    /// target's `<name>_route` is rendered (`render_deployed_to_vector_config`).
    pub deployed: bool,
}

/// Which always-on ingress channels the deployment's static base config
/// defines. A parser on a transport with no listener has no upstream at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IngressPresence {
    pub hec: bool,
    pub otlp: bool,
}

impl IngressPresence {
    pub(crate) fn from_env() -> Self {
        Self {
            hec: crate::parsers::hec_normalize_present(),
            otlp: crate::parsers::vector_config::otlp_source_present(),
        }
    }
}

/// NAN-928 / NAN-930: stamp `dispatch_route_name` on every parser that
/// carries a `dispatch_source_config_id`. The Vector config generator
/// reads `dispatch_route_name` to emit a filter on the source-config's route.
///
/// NAN-3765: a parser whose upstream is not part of the rendered set is
/// returned as a [`WaitingParser`] and disabled IN MEMORY (never in the
/// database), so the generator skips it. Previously an orphaned or unbound
/// fetch parser failed every deploy and publication (blocking unrelated
/// changes), and one bound to an undeployed source configuration rendered a
/// filter on a missing route, which Vector refused (CT 106 publication 28).
///
/// Free function (not a method) so both `ParserService::deploy_to_vector`
/// (parser-only path that the API startup hook fires) and
/// `LogSourceService::deploy*` (log-source publish path) can share the
/// resolution — without this dedup, the two paths drifted: parser-deploy
/// produced a parser-owned Kafka source while log-source-deploy produced the
/// correct dispatched filter. NAN-930 follow-up.
///
/// `safe_name` is computed in Rust (matches `source_configs::service::
/// safe_name`) so it stays Unicode-correct against `[^A-Za-z0-9]` regex
/// semantics (see RouteClaim doc).
pub async fn resolve_parser_dispatch_routes(
    pool: &sqlx::PgPool,
    parsers: &mut [Parser],
) -> Result<Vec<WaitingParser>, sqlx::Error> {
    use std::collections::HashMap;
    let mut unique: Vec<Uuid> = parsers
        .iter()
        .filter_map(|p| p.dispatch_source_config_id)
        .collect();
    unique.sort();
    unique.dedup();

    let targets: HashMap<Uuid, DispatchTarget> = if unique.is_empty() {
        HashMap::new()
    } else {
        sqlx::query_as::<_, (Uuid, String, bool)>(
            "SELECT id, name, deployed FROM source_configurations WHERE id = ANY($1)",
        )
        .bind(&unique)
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(id, name, deployed)| (id, DispatchTarget { name, deployed }))
        .collect()
    };

    Ok(apply_resolved_dispatch_routes(
        parsers,
        &targets,
        IngressPresence::from_env(),
    ))
}

/// Pure helper for `resolve_parser_dispatch_routes`'s in-memory phase.
///
/// Stamps `dispatch_route_name` on parsers whose dispatch target resolves, and
/// disables (in memory) every enabled parser whose upstream cannot be part of
/// the rendered set, returning those as [`WaitingParser`]s:
///
/// - fetch parser bound to a source configuration that is not deployed;
/// - fetch parser bound to a source configuration that no longer exists, or
///   not bound at all (pre-NAN-949 these fell through to a parser-owned
///   source; NAN-949 then failed the whole deploy instead);
/// - HEC / OTLP parser on a deployment whose base config has no HEC / OTLP
///   listener (`NANOSIEM_VECTOR_HEC_NORMALIZE_PRESENT` /
///   `NANOSIEM_VECTOR_OTLP_PRESENT` = false).
///
/// Split out so the classification is unit-testable without a live PG pool.
pub(crate) fn apply_resolved_dispatch_routes(
    parsers: &mut [Parser],
    targets: &std::collections::HashMap<Uuid, DispatchTarget>,
    ingress: IngressPresence,
) -> Vec<WaitingParser> {
    use crate::parsers::vector_config::{transport_of, Transport};

    let mut waiting: Vec<WaitingParser> = Vec::new();
    for parser in parsers.iter_mut() {
        let transport = transport_of(&parser.source_type);
        let is_fetch = transport == Transport::Fetch && parser.kind != "enrichment";
        let mut reason: Option<String> = None;

        if let Some(id) = parser.dispatch_source_config_id {
            match targets.get(&id) {
                Some(target) => {
                    let safe: String = target
                        .name
                        .chars()
                        .map(|c| if c.is_alphanumeric() { c } else { '_' })
                        .collect::<String>()
                        .to_lowercase();
                    parser.dispatch_route_name = Some(format!("{}_route", safe));
                    if is_fetch && !target.deployed {
                        reason = Some(format!(
                            "waiting for source configuration '{}' to be deployed",
                            target.name
                        ));
                    }
                }
                None => {
                    reason = Some(format!(
                        "source configuration {id} no longer exists; bind this log source \
                         to an existing source configuration"
                    ));
                }
            }
        } else if is_fetch {
            reason = Some(format!(
                "no source configuration is bound for {} input; bind one with DISPATCH FROM",
                parser.source_type
            ));
        }

        if reason.is_none() {
            reason = match transport {
                Transport::SplunkHec if !ingress.hec => {
                    Some("this deployment has no HEC listener".to_string())
                }
                Transport::Otlp if !ingress.otlp => {
                    Some("this deployment has no OTLP listener".to_string())
                }
                _ => None,
            };
        }

        let Some(reason) = reason else { continue };
        if !parser.enabled {
            continue;
        }
        tracing::warn!(
            parser = %parser.name,
            source_type = %parser.source_type,
            %reason,
            "log source not rendered into the Vector configuration",
        );
        parser.enabled = false;
        // Never let a skipped parser carry a route the set does not declare.
        parser.dispatch_route_name = None;
        waiting.push(WaitingParser {
            parser_id: parser.id,
            parser_name: parser.name.clone(),
            reason,
        });
    }
    waiting
}

/// Convert a database row to a Parser struct
fn row_to_parser(row: &sqlx::postgres::PgRow) -> Parser {
    Parser {
        id: row.get("id"),
        name: row.get("name"),
        description: row.get("description"),
        source_type: row.get("source_type"),
        parser_vrl: row.get("parser_vrl"),
        output_fields: row.get("output_fields"),
        feed_id: None, // log_sources doesn't have feed_id
        // NAN-928: try_get so existing parsers built from log_source rows
        // that pre-date migration 189 still load cleanly with None.
        dispatch_source_config_id: row.try_get("dispatch_source_config_id").unwrap_or(None),
        // Resolved at deploy time by the service layer.
        dispatch_route_name: None,
        namespace: row
            .try_get("namespace")
            .unwrap_or_else(|_| "default".to_string()),
        enabled: row.get("enabled"),
        validated: row.get("validated"),
        validation_error: row.get("validation_error"),
        timezone: row
            .try_get("timezone")
            .unwrap_or_else(|_| "UTC".to_string()),
        match_values: row.try_get("match_values").ok(),
        sampling_ratio: row.try_get("sampling_ratio").unwrap_or(None),
        sampling_exclude_condition: row.try_get("sampling_exclude_condition").unwrap_or(None),
        extension_vrl: row.try_get("extension_vrl").unwrap_or(None),
        extension_enabled: row.try_get("extension_enabled").unwrap_or(false),
        category: row.get("category"),
        vendor: row.get("vendor"),
        product: row.get("product"),
        // NAN-1149: try_get so rows predating migration 198 still load as logs.
        kind: row.try_get("kind").unwrap_or_else(|_| "log".to_string()),
        enrich_kind: row.try_get("enrich_kind").unwrap_or(None),
        enrich_source: row.try_get("enrich_source").unwrap_or(None),
        target_table: row.try_get("target_table").unwrap_or(None),
        normalize_vrl: row.try_get("normalize_vrl").unwrap_or(None),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::collections::HashMap;

    fn parser_with_dispatch(name: &str, dispatch_id: Option<Uuid>) -> Parser {
        Parser {
            id: Uuid::new_v4(),
            name: name.to_string(),
            description: None,
            source_type: "kafka".to_string(),
            parser_vrl: String::new(),
            output_fields: None,
            feed_id: None,
            dispatch_source_config_id: dispatch_id,
            dispatch_route_name: None,
            namespace: "default".to_string(),
            enabled: true,
            validated: true,
            validation_error: None,
            timezone: "UTC".to_string(),
            match_values: None,
            sampling_ratio: None,
            sampling_exclude_condition: None,
            extension_vrl: None,
            extension_enabled: false,
            category: None,
            vendor: None,
            product: None,
            kind: "log".to_string(),
            enrich_kind: None,
            enrich_source: None,
            target_table: None,
            normalize_vrl: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ----------------------------------------------------------------------
    // NAN-949 / NAN-3765: dispatch resolution. Parsers whose upstream is not
    // part of the rendered set are skipped (WaitingParser), never rendered
    // against a missing route and never failing unrelated deploys.
    // ----------------------------------------------------------------------

    const ALL_INGRESS: IngressPresence = IngressPresence {
        hec: true,
        otlp: true,
    };

    fn target(name: &str, deployed: bool) -> DispatchTarget {
        DispatchTarget {
            name: name.to_string(),
            deployed,
        }
    }

    #[test]
    fn apply_resolved_dispatch_routes_stamps_route_for_resolved_parser() {
        let sc_id = Uuid::new_v4();
        let mut parsers = vec![parser_with_dispatch("ds_auth", Some(sc_id))];
        let mut map = HashMap::new();
        map.insert(sc_id, target("Prod Kafka", true));

        let waiting = apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS);
        assert!(waiting.is_empty(), "{waiting:?}");
        assert!(parsers[0].enabled);
        assert_eq!(
            parsers[0].dispatch_route_name.as_deref(),
            Some("prod_kafka_route"),
            "resolved parser must get safe_name(config.name) + _route",
        );
    }

    /// NAN-3765 (CT 106 publication 28): the parser was bound to a source
    /// configuration whose route only arrived one publication later. It must
    /// wait, not render a filter on the missing route.
    #[test]
    fn apply_resolved_dispatch_routes_skips_parser_bound_to_undeployed_source_config() {
        let sc_id = Uuid::new_v4();
        let mut parsers = vec![
            parser_with_dispatch("lab_azure_parser", Some(sc_id)),
            parser_with_dispatch("unrelated", None),
        ];
        parsers[1].source_type = "routed".to_string();
        let mut map = HashMap::new();
        map.insert(sc_id, target("Lab Hub", false));

        let waiting = apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS);
        assert_eq!(waiting.len(), 1, "{waiting:?}");
        assert_eq!(waiting[0].parser_name, "lab_azure_parser");
        assert!(
            waiting[0]
                .reason
                .contains("waiting for source configuration 'Lab Hub'"),
            "{}",
            waiting[0].reason
        );
        assert!(
            !parsers[0].enabled,
            "waiting parser is skipped by the generator"
        );
        assert!(parsers[0].dispatch_route_name.is_none());
        assert!(parsers[1].enabled, "unrelated parsers still deploy");
    }

    #[test]
    fn apply_resolved_dispatch_routes_skips_orphan_parser() {
        // The source configuration was deleted. Pre-NAN-949 this fell through
        // to a parser-owned source (localhost:9092); NAN-949 then failed every
        // deploy. Now only this parser is held back.
        let orphan_id = Uuid::new_v4();
        let mut parsers = vec![parser_with_dispatch("ds_auth", Some(orphan_id))];
        let map: HashMap<Uuid, DispatchTarget> = HashMap::new();

        let waiting = apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS);
        assert_eq!(waiting.len(), 1);
        assert!(waiting[0].reason.contains(&orphan_id.to_string()));
        assert!(waiting[0].reason.contains("no longer exists"));
        assert!(!parsers[0].enabled);
        assert!(
            parsers[0].dispatch_route_name.is_none(),
            "orphan parser must not carry a route"
        );
    }

    #[test]
    fn apply_resolved_dispatch_routes_ignores_routed_parsers_without_dispatch_id() {
        // Routed parsers consume the shared source_router and do not require a
        // source-configuration dispatch binding.
        let mut parsers = vec![parser_with_dispatch("plain_routed", None)];
        parsers[0].source_type = "routed".to_string();
        let map: HashMap<Uuid, DispatchTarget> = HashMap::new();

        assert!(apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS).is_empty());
        assert!(parsers[0].enabled);
        assert!(parsers[0].dispatch_route_name.is_none());
    }

    #[test]
    fn apply_resolved_dispatch_routes_skips_fetch_parser_without_dispatch_id() {
        let mut parsers = vec![parser_with_dispatch("legacy_kafka", None)];
        let map: HashMap<Uuid, DispatchTarget> = HashMap::new();

        let waiting = apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS);
        assert_eq!(waiting.len(), 1);
        assert!(
            waiting[0].reason.contains("DISPATCH FROM"),
            "{}",
            waiting[0].reason
        );
        assert!(!parsers[0].enabled);
    }

    #[test]
    fn apply_resolved_dispatch_routes_reports_every_waiting_parser() {
        let good = Uuid::new_v4();
        let mut parsers = vec![
            parser_with_dispatch("good_one", Some(good)),
            parser_with_dispatch("orphan_a", Some(Uuid::new_v4())),
            parser_with_dispatch("orphan_b", Some(Uuid::new_v4())),
        ];
        let mut map = HashMap::new();
        map.insert(good, target("Good", true));

        let waiting = apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS);
        let names: Vec<&str> = waiting.iter().map(|w| w.parser_name.as_str()).collect();
        assert_eq!(names, vec!["orphan_a", "orphan_b"]);
        assert!(parsers[0].enabled);
        assert_eq!(
            parsers[0].dispatch_route_name.as_deref(),
            Some("good_route")
        );
    }

    /// NAN-3765: with no HEC / OTLP listener in the base config
    /// (`NANOSIEM_VECTOR_HEC_NORMALIZE_PRESENT=false`), those parsers have no
    /// upstream at all and are held back instead of dangling.
    #[test]
    fn apply_resolved_dispatch_routes_skips_parsers_without_a_listener() {
        let mut parsers = vec![
            parser_with_dispatch("hec_okta", None),
            parser_with_dispatch("otlp_app", None),
        ];
        parsers[0].source_type = "splunk_hec".to_string();
        parsers[1].source_type = "otlp".to_string();
        let map: HashMap<Uuid, DispatchTarget> = HashMap::new();

        let mut present = parsers.clone();
        assert!(apply_resolved_dispatch_routes(&mut present, &map, ALL_INGRESS).is_empty());

        let waiting = apply_resolved_dispatch_routes(
            &mut parsers,
            &map,
            IngressPresence {
                hec: false,
                otlp: false,
            },
        );
        assert_eq!(waiting.len(), 2, "{waiting:?}");
        assert!(waiting[0].reason.contains("no HEC listener"));
        assert!(waiting[1].reason.contains("no OTLP listener"));
        assert!(parsers.iter().all(|p| !p.enabled));
    }

    #[test]
    fn apply_resolved_dispatch_routes_ignores_disabled_parsers() {
        let mut parsers = vec![parser_with_dispatch("off", Some(Uuid::new_v4()))];
        parsers[0].enabled = false;
        let map: HashMap<Uuid, DispatchTarget> = HashMap::new();
        assert!(apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS).is_empty());
    }

    #[test]
    fn apply_resolved_dispatch_routes_handles_empty_parsers_slice() {
        let mut parsers: Vec<Parser> = vec![];
        let map: HashMap<Uuid, DispatchTarget> = HashMap::new();
        assert!(apply_resolved_dispatch_routes(&mut parsers, &map, ALL_INGRESS).is_empty());
    }
}
