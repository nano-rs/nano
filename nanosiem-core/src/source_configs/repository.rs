// SPDX-License-Identifier: AGPL-3.0-or-later

//! Source Configuration repository for database operations

use sqlx::{PgPool, QueryBuilder};
use thiserror::Error;
use tracing::warn;
use uuid::Uuid;

const LIST_PAGE_MAX: i64 = 1000;

use super::types::{
    ListParams, NewRoutingRule, NewSourceConfiguration, RoutingRule, SourceConfigDeployment,
    SourceConfiguration, SourceConfigurationWithRules, UpdateRoutingRule,
    UpdateSourceConfiguration,
};

#[derive(Error, Debug)]
pub enum SourceConfigRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Source configuration not found: {0}")]
    NotFound(String),
    #[error("Source configuration already exists: {0}")]
    AlreadyExists(String),
    /// NAN-883: a DB-level uniqueness constraint other than the name index
    /// fired (e.g. the partial unique index on `config_type` for
    /// `splunk_hec`). Distinct from `AlreadyExists` so the API layer can
    /// surface it as 409 with the constraint-specific message instead of
    /// the generic "name already exists" copy.
    #[error("Conflict: {0}")]
    Conflict(String),
    /// Optimistic-concurrency precondition failed: the row changed after the
    /// caller last read it.
    #[error("Source configuration was modified by another update: {0}")]
    StaleVersion(Uuid),
    /// The credential reference changed after the service authorized and
    /// validated its source-config snapshot but before the update reached SQL.
    #[error("Source configuration credential changed concurrently: {0}")]
    CredentialChanged(Uuid),
    #[error("Routing rule not found: {0}")]
    RuleNotFound(String),
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

#[derive(Clone)]
pub struct SourceConfigRepository {
    pool: PgPool,
}

/// NAN-930: Vector-route-name safe identifier rule. Single source of truth
/// for the source_configs side of the codebase — `SourceConfigService` has
/// its own private `safe_name` (in `service.rs`) which uses the same rule;
/// keeping them character-for-character identical is what makes the
/// claim-to-route join correct. Unicode-aware `is_alphanumeric` is the
/// canonical filter — must NOT be computed in SQL where regex character
/// classes are ASCII-only and would drift on non-ASCII names.
fn route_safe_name(name: &str) -> String {
    name.chars()
        .map(|c| if c.is_alphanumeric() { c } else { '_' })
        .collect::<String>()
        .to_lowercase()
}

/// NAN-930: a deployed parser's claim over a Vector source-config routing
/// transform. Used by `update_dynamic_router` to (a) substitute claimed
/// routes with their `<route>_unclaimed` filter in `source_router.inputs`,
/// and (b) emit the matching filter transform block when it's not already
/// present in `_router.toml`.
#[derive(Debug, Clone)]
pub struct RouteClaim {
    /// Vector route name being claimed (e.g. `splunk_hec_route`,
    /// `kafka_source_route`).
    pub route: String,
    /// Parser name — used as filter-condition fallback when match_values is empty.
    pub parser_name: String,
    /// Source-type values the parser-filter accepts. Union across all
    /// claimants of a route forms the `includes([...])` condition the
    /// `_unclaimed` filter negates.
    pub match_values: Vec<String>,
}

impl SourceConfigRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// NAN-930: load route-claim info for every enabled parser that consumes
    /// from a Vector route shared with `source_router`. Used by the source-
    /// config deploy path (`update_dynamic_router`) so its surgical update
    /// of `source_router.inputs` keeps the parser-claim substitution intact.
    ///
    /// Returns one entry per claiming parser. Two parsers claiming the same
    /// route appear as separate entries — callers union them.
    ///
    /// - HEC parsers (`source_type IN ('splunk_hec','splunk','hec')`) always
    ///   claim `splunk_hec_route` (the OOTB singleton).
    /// - Fetch-source parsers (`source_type IN ('kafka','aws_s3','aws_sqs','gcp_pubsub')`)
    ///   claim `<safe(name)>_route` of their `dispatch_source_config_id`.
    ///
    /// **safe_name is computed in Rust, not in SQL**, so the route name
    /// derivation always matches what `parsers/vector_config/router.rs::
    /// get_source_config_routes` actually generates (Unicode-aware
    /// `char::is_alphanumeric` vs PG's ASCII-only `[^A-Za-z0-9]` regex
    /// would otherwise drift on non-ASCII source-config names — e.g.
    /// `café-kafka` → Rust `café_kafka` vs PG `caf__kafka`).
    pub async fn load_route_claims(
        &self,
    ) -> Result<Vec<RouteClaim>, SourceConfigRepositoryError> {
        // Fetch raw fields — route name is derived in Rust to keep the
        // safe_name rule canonical. HEC parsers have no source-config
        // dispatch; the LEFT JOIN yields NULL for `sc_name` and the
        // caller maps that to `splunk_hec_route`.
        let rows = sqlx::query_as::<_, (String, String, Option<Vec<String>>, Option<String>)>(
            r#"
            SELECT
                ls.source_type,
                ls.name AS parser_name,
                ls.match_values,
                sc.name AS sc_name
            FROM log_sources ls
            LEFT JOIN source_configurations sc ON sc.id = ls.dispatch_source_config_id
            WHERE ls.enabled = true
              AND (
                  ls.source_type IN ('splunk_hec', 'splunk', 'hec')
                  OR (
                      ls.source_type IN ('kafka', 'aws_s3', 'aws_sqs', 'gcp_pubsub')
                      AND ls.dispatch_source_config_id IS NOT NULL
                      AND sc.id IS NOT NULL
                  )
              )
            ORDER BY ls.name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .filter_map(|(source_type, parser_name, match_values, sc_name)| {
                let route = match source_type.as_str() {
                    "splunk_hec" | "splunk" | "hec" => "splunk_hec_route".to_string(),
                    _ => {
                        // Fetch-source parsers must have a non-null sc.name —
                        // the WHERE clause guarantees it, but be defensive.
                        let sc_name = sc_name?;
                        format!("{}_route", route_safe_name(&sc_name))
                    }
                };
                Some(RouteClaim {
                    route,
                    parser_name,
                    match_values: match_values.unwrap_or_default(),
                })
            })
            .collect())
    }

    // ========================================================================
    // Source Configuration CRUD
    // ========================================================================

    /// List source configurations with optional filters
    pub async fn list(
        &self,
        params: Option<ListParams>,
    ) -> Result<Vec<SourceConfiguration>, SourceConfigRepositoryError> {
        let params = params.unwrap_or_default();

        let mut qb: QueryBuilder<sqlx::Postgres> = QueryBuilder::new(
            "SELECT id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type \
             FROM source_configurations WHERE 1=1",
        );

        if let Some(config_type) = params.config_type {
            qb.push(" AND config_type = ").push_bind(config_type);
        }
        if let Some(enabled) = params.enabled {
            qb.push(" AND enabled = ").push_bind(enabled);
        }
        if let Some(deployed) = params.deployed {
            qb.push(" AND deployed = ").push_bind(deployed);
        }
        if let Some(search) = params.search {
            let pattern = format!("%{}%", search);
            qb.push(" AND (name ILIKE ").push_bind(pattern.clone());
            qb.push(" OR description ILIKE ").push_bind(pattern);
            qb.push(")");
        }

        qb.push(" ORDER BY name ASC");

        let limit = params.limit.unwrap_or(LIST_PAGE_MAX).clamp(1, LIST_PAGE_MAX);
        let offset = params.offset.unwrap_or(0).max(0);
        qb.push(" LIMIT ").push_bind(limit);
        qb.push(" OFFSET ").push_bind(offset);

        let configs: Vec<SourceConfiguration> = qb
            .build_query_as::<SourceConfigRow>()
            .fetch_all(&self.pool)
            .await?
            .into_iter()
            .map(|r| r.into())
            .collect();

        // Source-config tables typically hold tens to low hundreds of rows; if
        // we ever hit the cap it likely means truncation that the caller is
        // unaware of (the API endpoint enriches every row and returns the full
        // list). Surface it so we'd notice in logs.
        if configs.len() as i64 == limit {
            warn!(
                limit,
                "source_configurations list hit page cap — results may be truncated"
            );
        }

        Ok(configs)
    }

    /// Get a source configuration by ID
    pub async fn get(&self, id: Uuid) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        let config = sqlx::query_as::<_, SourceConfigRow>(
            "SELECT id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type \
             FROM source_configurations WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SourceConfigRepositoryError::NotFound(id.to_string()))?;

        Ok(config.into())
    }

    /// Get a source configuration by name
    pub async fn get_by_name(
        &self,
        name: &str,
    ) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        let config = sqlx::query_as::<_, SourceConfigRow>(
            "SELECT id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type \
             FROM source_configurations WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SourceConfigRepositoryError::NotFound(name.to_string()))?;

        Ok(config.into())
    }

    /// Get a source configuration with its routing rules
    pub async fn get_with_rules(
        &self,
        id: Uuid,
    ) -> Result<SourceConfigurationWithRules, SourceConfigRepositoryError> {
        let config = self.get(id).await?;
        let rules = self.list_rules(id).await?;

        Ok(SourceConfigurationWithRules {
            config,
            routing_rules: rules,
        })
    }

    /// NAN-883: surface the partial-unique-index violation on `splunk_hec`
    /// as `Conflict` (→ HTTP 409) instead of a generic 500. The race
    /// window for the application-level list-then-insert in
    /// `SourceConfigService::create` is closed by migration 184's partial
    /// unique index; this is the translation when the race lands at the
    /// INSERT. Name-collision races fall through to `AlreadyExists` and
    /// keep their existing 400 mapping.
    fn map_create_insert_error(
        err: sqlx::Error,
        request: &NewSourceConfiguration,
    ) -> SourceConfigRepositoryError {
        if let sqlx::Error::Database(db_err) = &err {
            // PG SQLSTATE 23505 = unique_violation.
            if db_err.code().as_deref() == Some("23505") {
                let constraint = db_err.constraint().unwrap_or("");
                if constraint == "source_configurations_single_splunk_hec" {
                    return SourceConfigRepositoryError::Conflict(format!(
                        "Only one {} source configuration is supported per deployment.",
                        request.config_type
                    ));
                }
                return SourceConfigRepositoryError::AlreadyExists(request.name.clone());
            }
        }
        SourceConfigRepositoryError::from(err)
    }

    /// Create a new source configuration
    pub async fn create(
        &self,
        request: NewSourceConfiguration,
    ) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        // Check for duplicate name
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM source_configurations WHERE name = $1",
        )
        .bind(&request.name)
        .fetch_one(&self.pool)
        .await?;

        if existing > 0 {
            return Err(SourceConfigRepositoryError::AlreadyExists(request.name));
        }

        let config = sqlx::query_as::<_, SourceConfigRow>(
            "INSERT INTO source_configurations \
             (name, description, config_type, connection_config, credential_id, default_source_type) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type",
        )
        .bind(&request.name)
        .bind(&request.description)
        .bind(&request.config_type)
        .bind(&request.connection_config)
        .bind(&request.credential_id)
        .bind(&request.default_source_type)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| Self::map_create_insert_error(e, &request))?;

        let config: SourceConfiguration = config.into();

        // Create initial routing rules if provided. Each rule may seed the
        // config's default_source_type (NAN-1919) via create_rule, so once any
        // rule is created we re-fetch and return the current row instead of the
        // pre-seed INSERT-RETURNING snapshot (which would report a stale NULL
        // default_source_type).
        if let Some(rules) = request.routing_rules {
            if !rules.is_empty() {
                for rule in rules {
                    self.create_rule(config.id, rule).await?;
                }
                return self.get(config.id).await;
            }
        }

        Ok(config)
    }

    /// Update a source configuration
    pub async fn update(
        &self,
        id: Uuid,
        request: UpdateSourceConfiguration,
    ) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        let expected_credential_id = self.get(id).await?.credential_id;
        self.update_with_credential_guard(id, request, expected_credential_id)
            .await
    }

    /// Update only while the credential reference still matches the snapshot
    /// that the caller authorized.
    pub async fn update_with_credential_guard(
        &self,
        id: Uuid,
        request: UpdateSourceConfiguration,
        expected_credential_id: Option<Uuid>,
    ) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        // Build dynamic update query
        let mut updates = Vec::new();
        let mut param_idx = 1;

        if request.name.is_some() {
            param_idx += 1;
            updates.push(format!("name = ${}", param_idx));
        }
        if request.description.is_some() {
            param_idx += 1;
            updates.push(format!("description = ${}", param_idx));
        }
        if request.config_type.is_some() {
            param_idx += 1;
            updates.push(format!("config_type = ${}", param_idx));
        }
        if request.connection_config.is_some() {
            param_idx += 1;
            updates.push(format!("connection_config = ${}", param_idx));
        }
        if request.credential_id.is_some() {
            param_idx += 1;
            updates.push(format!("credential_id = ${}", param_idx));
        }
        if request.enabled.is_some() {
            param_idx += 1;
            updates.push(format!("enabled = ${}", param_idx));
        }
        if request.default_source_type.is_some() {
            param_idx += 1;
            updates.push(format!("default_source_type = ${}", param_idx));
        }

        if updates.is_empty() {
            let current = self.get(id).await?;
            if request
                .expected_updated_at
                .is_some_and(|expected| expected != current.updated_at)
            {
                return Err(SourceConfigRepositoryError::StaleVersion(id));
            }
            return Ok(current);
        }

        // Bind the credential snapshot into the write predicate. Without this
        // compare-and-set guard, an under-scoped update could authorize a
        // credentialless row, race an authorized credential attachment, then
        // rewrite the newly credential-bearing destination.
        let expected_updated_at_param = param_idx + 1;
        let expected_credential_param = param_idx + 2;
        let query = format!(
            "UPDATE source_configurations SET {} \
             WHERE id = $1 \
               AND (${expected_updated_at_param}::timestamptz IS NULL \
                    OR updated_at = ${expected_updated_at_param}) \
               AND credential_id IS NOT DISTINCT FROM ${expected_credential_param} \
             RETURNING id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type",
            updates.join(", "),
        );

        // Build query dynamically
        let mut query_builder = sqlx::query_as::<_, SourceConfigRow>(&query).bind(id);

        if let Some(ref name) = request.name {
            query_builder = query_builder.bind(name);
        }
        if let Some(ref description) = request.description {
            query_builder = query_builder.bind(description);
        }
        if let Some(ref config_type) = request.config_type {
            query_builder = query_builder.bind(config_type);
        }
        if let Some(ref connection_config) = request.connection_config {
            query_builder = query_builder.bind(connection_config);
        }
        if let Some(ref credential_id) = request.credential_id {
            query_builder = query_builder.bind(credential_id);
        }
        if let Some(enabled) = request.enabled {
            query_builder = query_builder.bind(enabled);
        }
        if let Some(ref default_source_type) = request.default_source_type {
            query_builder = query_builder.bind(default_source_type);
        }
        query_builder = query_builder.bind(request.expected_updated_at);
        query_builder = query_builder.bind(expected_credential_id);

        match query_builder.fetch_optional(&self.pool).await? {
            Some(config) => Ok(config.into()),
            None => {
                // The atomic UPDATE can miss because the row disappeared, the
                // optimistic version is stale, or the credential reference
                // changed after authorization. This probe is diagnostic only;
                // no write occurs outside the compare-and-set.
                let current_credential_id: Option<Option<Uuid>> = sqlx::query_scalar(
                    "SELECT credential_id FROM source_configurations WHERE id = $1",
                )
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
                let Some(current_credential_id) = current_credential_id else {
                    return Err(SourceConfigRepositoryError::NotFound(id.to_string()));
                };
                if current_credential_id != expected_credential_id {
                    return Err(SourceConfigRepositoryError::CredentialChanged(id));
                }
                Err(SourceConfigRepositoryError::StaleVersion(id))
            }
        }
    }

    /// Delete a source configuration
    pub async fn delete(&self, id: Uuid) -> Result<(), SourceConfigRepositoryError> {
        let result = sqlx::query("DELETE FROM source_configurations WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(SourceConfigRepositoryError::NotFound(id.to_string()));
        }

        Ok(())
    }

    /// Mark a source configuration as deployed
    pub async fn mark_deployed(
        &self,
        id: Uuid,
    ) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        let config = sqlx::query_as::<_, SourceConfigRow>(
            "UPDATE source_configurations SET deployed = true, deployed_at = NOW() WHERE id = $1 \
             RETURNING id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SourceConfigRepositoryError::NotFound(id.to_string()))?;

        Ok(config.into())
    }

    /// Mark a source configuration as undeployed
    pub async fn mark_undeployed(
        &self,
        id: Uuid,
    ) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        let config = sqlx::query_as::<_, SourceConfigRow>(
            "UPDATE source_configurations SET deployed = false, deployed_at = NULL WHERE id = $1 \
             RETURNING id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SourceConfigRepositoryError::NotFound(id.to_string()))?;

        Ok(config.into())
    }

    /// Toggle enabled status
    pub async fn toggle_enabled(
        &self,
        id: Uuid,
        enabled: bool,
    ) -> Result<SourceConfiguration, SourceConfigRepositoryError> {
        let config = sqlx::query_as::<_, SourceConfigRow>(
            "UPDATE source_configurations SET enabled = $2 WHERE id = $1 \
             RETURNING id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type",
        )
        .bind(id)
        .bind(enabled)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SourceConfigRepositoryError::NotFound(id.to_string()))?;

        Ok(config.into())
    }

    /// List all enabled source configurations (for deployment)
    pub async fn list_enabled(
        &self,
    ) -> Result<Vec<SourceConfiguration>, SourceConfigRepositoryError> {
        let configs = sqlx::query_as::<_, SourceConfigRow>(
            "SELECT id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type \
             FROM source_configurations WHERE enabled = true ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        Ok(configs)
    }

    /// List the complete deployed set for canonical Vector generation. Unlike
    /// the analyst-facing paginated list, this must never truncate routing
    /// inputs at the API page cap.
    pub async fn list_deployed(
        &self,
    ) -> Result<Vec<SourceConfiguration>, SourceConfigRepositoryError> {
        let configs = sqlx::query_as::<_, SourceConfigRow>(
            "SELECT id, name, description, config_type, connection_config, credential_id, \
             enabled, deployed, deployed_at, created_at, updated_at, default_source_type \
             FROM source_configurations WHERE deployed = true ORDER BY name ASC",
        )
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|row| row.into())
        .collect();

        Ok(configs)
    }

    // ========================================================================
    // Routing Rules CRUD
    // ========================================================================

    /// List routing rules for a source configuration
    pub async fn list_rules(
        &self,
        source_configuration_id: Uuid,
    ) -> Result<Vec<RoutingRule>, SourceConfigRepositoryError> {
        let rules = sqlx::query_as::<_, RoutingRuleRow>(
            "SELECT id, source_configuration_id, priority, match_field, match_type, \
             match_value, target_source_type, created_at \
             FROM routing_rules WHERE source_configuration_id = $1 \
             ORDER BY priority ASC",
        )
        .bind(source_configuration_id)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        Ok(rules)
    }

    /// List routing rules for many source configurations in a single query.
    ///
    /// Replaces the N+1 pattern of calling `list_rules` once per config in
    /// `source_configs` enrichment paths. Returns a map keyed by
    /// `source_configuration_id`; configs with no rules are omitted from the
    /// map (caller should treat as empty Vec).
    pub async fn list_rules_for_configs(
        &self,
        ids: &[Uuid],
    ) -> Result<std::collections::HashMap<Uuid, Vec<RoutingRule>>, SourceConfigRepositoryError>
    {
        if ids.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rows = sqlx::query_as::<_, RoutingRuleRow>(
            "SELECT id, source_configuration_id, priority, match_field, match_type, \
             match_value, target_source_type, created_at \
             FROM routing_rules WHERE source_configuration_id = ANY($1) \
             ORDER BY source_configuration_id, priority ASC",
        )
        .bind(ids)
        .fetch_all(&self.pool)
        .await?;

        let mut out: std::collections::HashMap<Uuid, Vec<RoutingRule>> =
            std::collections::HashMap::with_capacity(ids.len());
        for row in rows {
            let rule: RoutingRule = row.into();
            out.entry(rule.source_configuration_id)
                .or_default()
                .push(rule);
        }
        Ok(out)
    }

    /// Create a new routing rule
    pub async fn create_rule(
        &self,
        source_configuration_id: Uuid,
        request: NewRoutingRule,
    ) -> Result<RoutingRule, SourceConfigRepositoryError> {
        // Get next priority if not specified
        let priority = if let Some(p) = request.priority {
            p
        } else if request.match_type == "default" {
            // Default rules always go at the end (high priority number = low priority)
            1000
        } else {
            // Non-default rules: insert before any default rule
            // Find max priority of non-default rules (should be < 1000)
            let max_non_default: Option<i32> = sqlx::query_scalar(
                "SELECT MAX(priority) FROM routing_rules \
                 WHERE source_configuration_id = $1 AND match_type != 'default'",
            )
            .bind(source_configuration_id)
            .fetch_one(&self.pool)
            .await?;

            // Query the actual default rule priority instead of assuming 1000
            let min_default: Option<i32> = sqlx::query_scalar(
                "SELECT MIN(priority) FROM routing_rules \
                 WHERE source_configuration_id = $1 AND match_type = 'default'",
            )
            .bind(source_configuration_id)
            .fetch_one(&self.pool)
            .await?;
            let ceiling = min_default.unwrap_or(1000) - 1;

            // Use max non-default + 10, but cap to stay before the default rule
            let next = max_non_default.unwrap_or(0) + 10;
            next.min(ceiling)
        };

        // Resolve priority collisions: find next available slot if taken
        let priority = self
            .find_available_priority(source_configuration_id, priority)
            .await?;

        let rule = sqlx::query_as::<_, RoutingRuleRow>(
            "INSERT INTO routing_rules \
             (source_configuration_id, priority, match_field, match_type, match_value, target_source_type) \
             VALUES ($1, $2, $3, $4, $5, $6) \
             RETURNING id, source_configuration_id, priority, match_field, match_type, \
             match_value, target_source_type, created_at",
        )
        .bind(source_configuration_id)
        .bind(priority)
        .bind(&request.match_field)
        .bind(&request.match_type)
        .bind(&request.match_value)
        .bind(&request.target_source_type)
        .fetch_one(&self.pool)
        .await?;

        let rule: RoutingRule = rule.into();

        // NAN-1919: seed the parent config's default_source_type from the first
        // routing rule's target so unmatched pull-source events fall back to a
        // real source type instead of "unknown". Conditional UPDATE — a no-op
        // once a value is established, so later rules never overwrite it. Done
        // here (not in the service layer) so both the service `create_rule`
        // path and the initial-rules loop in `create` seed identically.
        self.set_default_source_type_if_unset(source_configuration_id, &rule.target_source_type)
            .await?;

        Ok(rule)
    }

    /// NAN-1919: set `default_source_type` only when it is currently unset
    /// (NULL or empty string). Seeded from the first routing rule's target so
    /// unmatched pull-transport events fall back to a real source type instead
    /// of `"unknown"`. Idempotent — an already-set value is left untouched.
    pub async fn set_default_source_type_if_unset(
        &self,
        source_configuration_id: Uuid,
        value: &str,
    ) -> Result<(), SourceConfigRepositoryError> {
        sqlx::query(
            "UPDATE source_configurations SET default_source_type = $1 \
             WHERE id = $2 AND (default_source_type IS NULL OR default_source_type = '')",
        )
        .bind(value)
        .bind(source_configuration_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Update a routing rule
    pub async fn update_rule(
        &self,
        rule_id: Uuid,
        mut request: UpdateRoutingRule,
    ) -> Result<RoutingRule, SourceConfigRepositoryError> {
        // NAN-1271: fallback-last invariant. A `default` (catch-all) rule must
        // always sort AFTER every non-default rule — it is the route's `else`,
        // and the UI orders by priority. create_rule and reorder_rules already
        // pin defaults last; update_rule is the one write path that applied a
        // caller-supplied priority unguarded (how a fallback ended up at
        // priority 0, showing first in the UI). Clamp a default's priority to
        // sit above all non-defaults here so it can never be written ahead of a
        // real rule.
        if let Some(req_priority) = request.priority {
            let current = self.get_rule(rule_id).await?;
            let effective_type = request
                .match_type
                .as_deref()
                .unwrap_or(&current.match_type);
            if effective_type == "default" {
                let max_non_default: Option<i32> = sqlx::query_scalar(
                    "SELECT MAX(priority) FROM routing_rules \
                     WHERE source_configuration_id = $1 AND match_type != 'default' AND id != $2",
                )
                .bind(current.source_configuration_id)
                .bind(rule_id)
                .fetch_one(&self.pool)
                .await?;
                let pinned = max_non_default.map_or(1000, |m| (m + 10).max(1000));
                if req_priority != pinned {
                    request.priority = Some(pinned);
                }
            }
        }

        let mut updates = Vec::new();
        let mut param_idx = 1;

        if request.priority.is_some() {
            param_idx += 1;
            updates.push(format!("priority = ${}", param_idx));
        }
        if request.match_field.is_some() {
            param_idx += 1;
            updates.push(format!("match_field = ${}", param_idx));
        }
        if request.match_type.is_some() {
            param_idx += 1;
            updates.push(format!("match_type = ${}", param_idx));
        }
        if request.match_value.is_some() {
            param_idx += 1;
            updates.push(format!("match_value = ${}", param_idx));
        }
        if request.target_source_type.is_some() {
            param_idx += 1;
            updates.push(format!("target_source_type = ${}", param_idx));
        }

        if updates.is_empty() {
            return self.get_rule(rule_id).await;
        }

        let query = format!(
            "UPDATE routing_rules SET {} WHERE id = $1 \
             RETURNING id, source_configuration_id, priority, match_field, match_type, \
             match_value, target_source_type, created_at",
            updates.join(", ")
        );

        let mut query_builder = sqlx::query_as::<_, RoutingRuleRow>(&query).bind(rule_id);

        if let Some(priority) = request.priority {
            query_builder = query_builder.bind(priority);
        }
        if let Some(ref match_field) = request.match_field {
            query_builder = query_builder.bind(match_field);
        }
        if let Some(ref match_type) = request.match_type {
            query_builder = query_builder.bind(match_type);
        }
        if let Some(ref match_value) = request.match_value {
            query_builder = query_builder.bind(match_value);
        }
        if let Some(ref target_source_type) = request.target_source_type {
            query_builder = query_builder.bind(target_source_type);
        }

        let rule = query_builder
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| SourceConfigRepositoryError::RuleNotFound(rule_id.to_string()))?;

        Ok(rule.into())
    }

    /// Get a routing rule by ID
    pub async fn get_rule(
        &self,
        rule_id: Uuid,
    ) -> Result<RoutingRule, SourceConfigRepositoryError> {
        let rule = sqlx::query_as::<_, RoutingRuleRow>(
            "SELECT id, source_configuration_id, priority, match_field, match_type, \
             match_value, target_source_type, created_at \
             FROM routing_rules WHERE id = $1",
        )
        .bind(rule_id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| SourceConfigRepositoryError::RuleNotFound(rule_id.to_string()))?;

        Ok(rule.into())
    }

    /// Delete a routing rule
    pub async fn delete_rule(&self, rule_id: Uuid) -> Result<(), SourceConfigRepositoryError> {
        let result = sqlx::query("DELETE FROM routing_rules WHERE id = $1")
            .bind(rule_id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(SourceConfigRepositoryError::RuleNotFound(
                rule_id.to_string(),
            ));
        }

        Ok(())
    }

    /// Reorder routing rules (update priorities)
    pub async fn reorder_rules(
        &self,
        source_configuration_id: Uuid,
        rule_order: Vec<Uuid>,
    ) -> Result<Vec<RoutingRule>, SourceConfigRepositoryError> {
        // Find which rule IDs are default rules so we can pin them at 1000
        let default_rule_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM routing_rules \
             WHERE source_configuration_id = $1 AND match_type = 'default'",
        )
        .bind(source_configuration_id)
        .fetch_all(&self.pool)
        .await?;

        // First, set all priorities to temporary high values to avoid unique constraint violations
        // We add 100000 to each priority to move them out of the way
        sqlx::query(
            "UPDATE routing_rules SET priority = priority + 100000 WHERE source_configuration_id = $1",
        )
        .bind(source_configuration_id)
        .execute(&self.pool)
        .await?;

        // Now set the final priorities based on the new order
        // Default rules are pinned at 1000; non-default get sequential 10, 20, 30...
        let mut non_default_idx = 0usize;
        for rule_id in rule_order.iter() {
            let priority = if default_rule_ids.contains(rule_id) {
                1000
            } else {
                non_default_idx += 1;
                (non_default_idx * 10) as i32
            };
            sqlx::query("UPDATE routing_rules SET priority = $1 WHERE id = $2 AND source_configuration_id = $3")
                .bind(priority)
                .bind(rule_id)
                .bind(source_configuration_id)
                .execute(&self.pool)
                .await?;
        }

        self.list_rules(source_configuration_id).await
    }

    // ========================================================================
    // Deployment History
    // ========================================================================

    /// Add a deployment record
    pub async fn add_deployment(
        &self,
        source_configuration_id: Uuid,
        action: &str,
        status: &str,
        error_message: Option<&str>,
        config_snapshot: Option<&str>,
    ) -> Result<SourceConfigDeployment, SourceConfigRepositoryError> {
        let deployment = sqlx::query_as::<_, DeploymentRow>(
            "INSERT INTO source_configuration_deployments \
             (source_configuration_id, action, status, error_message, config_snapshot) \
             VALUES ($1, $2, $3, $4, $5) \
             RETURNING id, source_configuration_id, action, status, error_message, \
             config_snapshot, deployed_at",
        )
        .bind(source_configuration_id)
        .bind(action)
        .bind(status)
        .bind(error_message)
        .bind(config_snapshot)
        .fetch_one(&self.pool)
        .await?;

        Ok(deployment.into())
    }

    /// Find an available priority slot, incrementing by 1 if the desired priority is taken.
    /// This prevents unique constraint violations on (source_configuration_id, priority).
    /// Returns an error if no slot is available before the default rule.
    async fn find_available_priority(
        &self,
        source_configuration_id: Uuid,
        desired: i32,
    ) -> Result<i32, SourceConfigRepositoryError> {
        // Get all existing priorities for this source config
        let existing: Vec<i32> = sqlx::query_scalar(
            "SELECT priority FROM routing_rules WHERE source_configuration_id = $1 ORDER BY priority",
        )
        .bind(source_configuration_id)
        .fetch_all(&self.pool)
        .await?;

        // Find the ceiling: minimum default rule priority
        let min_default: Option<i32> = sqlx::query_scalar(
            "SELECT MIN(priority) FROM routing_rules \
             WHERE source_configuration_id = $1 AND match_type = 'default'",
        )
        .bind(source_configuration_id)
        .fetch_one(&self.pool)
        .await?;
        let ceiling = min_default.unwrap_or(i32::MAX);

        let mut priority = desired;
        while existing.contains(&priority) {
            priority += 1;
            if priority >= ceiling {
                return Err(SourceConfigRepositoryError::InvalidConfig(
                    "No available priority slot before the default routing rule. \
                     Please reorder existing rules to free up space."
                        .to_string(),
                ));
            }
        }
        Ok(priority)
    }

    /// Get deployment history
    pub async fn get_deployments(
        &self,
        source_configuration_id: Uuid,
        limit: Option<i64>,
    ) -> Result<Vec<SourceConfigDeployment>, SourceConfigRepositoryError> {
        let limit = limit.unwrap_or(50);

        let deployments = sqlx::query_as::<_, DeploymentRow>(
            "SELECT id, source_configuration_id, action, status, error_message, \
             config_snapshot, deployed_at \
             FROM source_configuration_deployments \
             WHERE source_configuration_id = $1 \
             ORDER BY deployed_at DESC LIMIT $2",
        )
        .bind(source_configuration_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .into_iter()
        .map(|r| r.into())
        .collect();

        Ok(deployments)
    }
}

// ============================================================================
// Row types for sqlx
// ============================================================================

#[derive(sqlx::FromRow)]
struct SourceConfigRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    config_type: String,
    connection_config: serde_json::Value,
    credential_id: Option<Uuid>,
    enabled: bool,
    deployed: bool,
    deployed_at: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    default_source_type: Option<String>,
}

impl From<SourceConfigRow> for SourceConfiguration {
    fn from(row: SourceConfigRow) -> Self {
        Self {
            id: row.id,
            name: row.name,
            description: row.description,
            config_type: row.config_type,
            connection_config: row.connection_config,
            credential_id: row.credential_id,
            enabled: row.enabled,
            deployed: row.deployed,
            deployed_at: row.deployed_at,
            created_at: row.created_at,
            updated_at: row.updated_at,
            default_source_type: row.default_source_type,
            events_24h: None,
            bytes_per_day_24h: None,
            last_event_at: None,
        }
    }
}

#[derive(sqlx::FromRow)]
struct RoutingRuleRow {
    id: Uuid,
    source_configuration_id: Uuid,
    priority: i32,
    match_field: String,
    match_type: String,
    match_value: Option<String>,
    target_source_type: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<RoutingRuleRow> for RoutingRule {
    fn from(row: RoutingRuleRow) -> Self {
        Self {
            id: row.id,
            source_configuration_id: row.source_configuration_id,
            priority: row.priority,
            match_field: row.match_field,
            match_type: row.match_type,
            match_value: row.match_value,
            target_source_type: row.target_source_type,
            created_at: row.created_at,
            fires_24h: None,
            last_fired_at: None,
        }
    }
}

#[derive(sqlx::FromRow)]
struct DeploymentRow {
    id: Uuid,
    source_configuration_id: Uuid,
    action: String,
    status: String,
    error_message: Option<String>,
    config_snapshot: Option<String>,
    deployed_at: chrono::DateTime<chrono::Utc>,
}

impl From<DeploymentRow> for SourceConfigDeployment {
    fn from(row: DeploymentRow) -> Self {
        Self {
            id: row.id,
            source_configuration_id: row.source_configuration_id,
            action: row.action,
            status: row.status,
            error_message: row.error_message,
            config_snapshot: row.config_snapshot,
            deployed_at: row.deployed_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::QueryBuilder;

    // Mirrors the WHERE-clause construction in `SourceConfigRepository::list`.
    // Kept in sync by hand — if the production code changes shape, update both.
    fn build_list_sql(params: ListParams) -> String {
        let mut qb: QueryBuilder<sqlx::Postgres> =
            QueryBuilder::new("SELECT id FROM source_configurations WHERE 1=1");

        if let Some(config_type) = params.config_type {
            qb.push(" AND config_type = ").push_bind(config_type);
        }
        if let Some(enabled) = params.enabled {
            qb.push(" AND enabled = ").push_bind(enabled);
        }
        if let Some(deployed) = params.deployed {
            qb.push(" AND deployed = ").push_bind(deployed);
        }
        if let Some(search) = params.search {
            let pattern = format!("%{}%", search);
            qb.push(" AND (name ILIKE ").push_bind(pattern.clone());
            qb.push(" OR description ILIKE ").push_bind(pattern);
            qb.push(")");
        }

        qb.push(" ORDER BY name ASC");

        let limit = params
            .limit
            .unwrap_or(LIST_PAGE_MAX)
            .clamp(1, LIST_PAGE_MAX);
        let offset = params.offset.unwrap_or(0).max(0);
        qb.push(" LIMIT ").push_bind(limit);
        qb.push(" OFFSET ").push_bind(offset);

        qb.into_sql()
    }

    #[test]
    fn list_search_payload_is_parameterized_not_interpolated() {
        // Classic injection probe — must end up bound, never spliced into SQL.
        let payload = "'; DROP TABLE source_configurations; --";
        let sql = build_list_sql(ListParams {
            search: Some(payload.to_string()),
            ..Default::default()
        });

        assert!(
            !sql.contains(payload),
            "search payload was interpolated into SQL: {sql}"
        );
        assert!(sql.contains("ILIKE $"), "expected bound ILIKE: {sql}");
    }

    #[test]
    fn list_config_type_is_parameterized() {
        let payload = "agent' OR '1'='1";
        let sql = build_list_sql(ListParams {
            config_type: Some(payload.to_string()),
            ..Default::default()
        });

        assert!(
            !sql.contains(payload),
            "config_type was interpolated into SQL: {sql}"
        );
        assert!(sql.contains("config_type = $"), "expected bound eq: {sql}");
    }
}
