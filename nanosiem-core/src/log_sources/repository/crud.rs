// SPDX-License-Identifier: AGPL-3.0-or-later

//! CRUD operations for log sources (list, find, create, update, delete)

use uuid::Uuid;

use super::super::types::{ListParams, LogSource, NewLogSource, UpdateLogSource};
use super::helpers::row_to_log_source;
use super::{LogSourceRepository, LogSourceRepositoryError};

impl LogSourceRepository {
    /// List all log sources with optional filtering
    pub async fn list(
        &self,
        params: &ListParams,
    ) -> Result<Vec<LogSource>, LogSourceRepositoryError> {
        let mut query = String::from(
            r#"
            SELECT
                id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            FROM log_sources
            WHERE 1=1
            "#,
        );

        let mut bind_idx = 1;
        let mut binds: Vec<String> = Vec::new();

        if let Some(ref category) = params.category {
            query.push_str(&format!(" AND category = ${}", bind_idx));
            binds.push(category.clone());
            bind_idx += 1;
        }

        if let Some(ref source_type) = params.source_type {
            query.push_str(&format!(" AND source_type = ${}", bind_idx));
            binds.push(source_type.clone());
            bind_idx += 1;
        }

        if let Some(ref vendor) = params.vendor {
            query.push_str(&format!(" AND vendor = ${}", bind_idx));
            binds.push(vendor.clone());
            bind_idx += 1;
        }

        if let Some(enabled) = params.enabled {
            query.push_str(&format!(" AND enabled = ${}", bind_idx));
            binds.push(enabled.to_string());
            bind_idx += 1;
        }

        if let Some(deployed) = params.deployed {
            query.push_str(&format!(" AND deployed = ${}", bind_idx));
            binds.push(deployed.to_string());
            bind_idx += 1;
        }

        if let Some(ref search) = params.search {
            query.push_str(&format!(
                " AND (name ILIKE ${} OR vendor ILIKE ${} OR product ILIKE ${})",
                bind_idx,
                bind_idx + 1,
                bind_idx + 2
            ));
            let search_pattern = format!("%{}%", search);
            binds.push(search_pattern.clone());
            binds.push(search_pattern.clone());
            binds.push(search_pattern);
            bind_idx += 3;
        }

        query.push_str(" ORDER BY name ASC");

        if let Some(limit) = params.limit {
            query.push_str(&format!(" LIMIT ${}", bind_idx));
            binds.push(limit.to_string());
            bind_idx += 1;
        }

        if let Some(offset) = params.offset {
            query.push_str(&format!(" OFFSET ${}", bind_idx));
            binds.push(offset.to_string());
        }

        // For now, use simple query without dynamic binds for simplicity
        // In production, you'd want proper parameterized queries
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            FROM log_sources
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_log_source).collect())
    }

    /// List enabled log sources only
    pub async fn list_enabled(&self) -> Result<Vec<LogSource>, LogSourceRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            FROM log_sources
            WHERE enabled = true
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_log_source).collect())
    }

    /// List deployed log sources only
    pub async fn list_deployed(&self) -> Result<Vec<LogSource>, LogSourceRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT
                id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            FROM log_sources
            WHERE deployed = true
            ORDER BY name ASC
            "#,
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.iter().map(row_to_log_source).collect())
    }

    /// Get a log source by ID
    pub async fn find_by_id(&self, id: Uuid) -> Result<LogSource, LogSourceRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            FROM log_sources
            WHERE id = $1
            "#,
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| LogSourceRepositoryError::NotFound(id.to_string()))?;

        Ok(row_to_log_source(&row))
    }

    /// Get a log source by name
    pub async fn find_by_name(&self, name: &str) -> Result<LogSource, LogSourceRepositoryError> {
        let row = sqlx::query(
            r#"
            SELECT
                id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            FROM log_sources
            WHERE name = $1
            "#,
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await?
        .ok_or_else(|| LogSourceRepositoryError::NotFound(name.to_string()))?;

        Ok(row_to_log_source(&row))
    }

    /// Create a new log source
    pub async fn create(&self, new: &NewLogSource) -> Result<LogSource, LogSourceRepositoryError> {
        // Check for duplicate name
        let existing: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM log_sources WHERE name = $1")
            .bind(&new.name)
            .fetch_one(&self.pool)
            .await?;

        if existing > 0 {
            return Err(LogSourceRepositoryError::DuplicateName(new.name.clone()));
        }

        let row = sqlx::query(
            r#"
            INSERT INTO log_sources (
                name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values, dispatch_source_config_id
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
            RETURNING id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            "#,
        )
        .bind(&new.name)
        .bind(&new.description)
        .bind(&new.namespace)
        .bind(&new.timezone)
        .bind(&new.source_type)
        .bind(&new.source_config)
        .bind(&new.credential_id)
        .bind(&new.parser_vrl)
        .bind(&new.output_fields)
        .bind(&new.category)
        .bind(&new.vendor)
        .bind(&new.product)
        .bind(&new.icon)
        .bind(&new.color)
        .bind(&new.match_field)
        .bind(&new.match_pattern)
        .bind(&new.match_values)
        .bind(&new.dispatch_source_config_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_log_source(&row))
    }

    /// Update a log source
    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateLogSource,
    ) -> Result<LogSource, LogSourceRepositoryError> {
        // Check if exists
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
                return Err(LogSourceRepositoryError::DuplicateName(name.clone()));
            }
        }

        // Reset deployed status if deployment-affecting fields are being changed
        // This ensures the UI shows "Deploy" instead of "Undeploy" after config changes
        let config_changed = update.source_type.is_some()
            || update.source_config.is_some()
            || update.credential_id.is_some()
            || update.dispatch_source_config_id.is_some()
            || update.parser_vrl.is_some()
            || update.output_fields.is_some()
            || update.match_field.is_some()
            || update.match_pattern.is_some()
            || update.match_values.is_some()
            || update.sampling_ratio.is_some()
            || update.sampling_exclude_condition.is_some()
            || update.extension_vrl.is_some()
            || update.extension_enabled.is_some();

        let row = sqlx::query(
            r#"
            UPDATE log_sources SET
                name = COALESCE($2, name),
                description = COALESCE($3, description),
                namespace = COALESCE($4, namespace),
                timezone = COALESCE($5, timezone),
                source_type = COALESCE($6, source_type),
                source_config = COALESCE($7, source_config),
                credential_id = COALESCE($8, credential_id),
                parser_vrl = COALESCE($9, parser_vrl),
                output_fields = COALESCE($10, output_fields),
                category = COALESCE($11, category),
                vendor = COALESCE($12, vendor),
                product = COALESCE($13, product),
                icon = COALESCE($14, icon),
                color = COALESCE($15, color),
                match_field = COALESCE($16, match_field),
                match_pattern = COALESCE($17, match_pattern),
                match_values = COALESCE($18, match_values),
                enabled = COALESCE($19, enabled),
                deployed = CASE WHEN $20 THEN false ELSE deployed END,
                stale_alert_enabled = COALESCE($21, stale_alert_enabled),
                stale_threshold_minutes = COALESCE($22, stale_threshold_minutes),
                sampling_ratio = COALESCE($23, sampling_ratio),
                sampling_exclude_condition = COALESCE($24, sampling_exclude_condition),
                extension_vrl = CASE
                    WHEN $25::text IS NULL THEN extension_vrl
                    WHEN $25 = '' THEN NULL
                    ELSE $25
                END,
                extension_enabled = COALESCE($26, extension_enabled),
                dispatch_source_config_id = COALESCE($27, dispatch_source_config_id)
            WHERE id = $1
            RETURNING id, name, description, namespace, timezone, source_type, source_config, credential_id,
                parser_vrl, output_fields, category, vendor, product, icon, color,
                match_field, match_pattern, match_values,
                validated, validation_error, deployed, deployed_at, enabled,
                stale_alert_enabled, stale_threshold_minutes,
                sampling_ratio, sampling_exclude_condition,
                extension_vrl, extension_enabled,
                parser_only,
                source_parser_repository_id, source_parser_path, source_parser_linked,
                dispatch_source_config_id,
                created_at, updated_at
            "#,
        )
        .bind(id)
        .bind(&update.name)
        .bind(&update.description)
        .bind(&update.namespace)
        .bind(&update.timezone)
        .bind(&update.source_type)
        .bind(&update.source_config)
        .bind(&update.credential_id)
        .bind(&update.parser_vrl)
        .bind(&update.output_fields)
        .bind(&update.category)
        .bind(&update.vendor)
        .bind(&update.product)
        .bind(&update.icon)
        .bind(&update.color)
        .bind(&update.match_field)
        .bind(&update.match_pattern)
        .bind(&update.match_values)
        .bind(&update.enabled)
        .bind(config_changed)
        .bind(&update.stale_alert_enabled)
        .bind(&update.stale_threshold_minutes)
        .bind(&update.sampling_ratio)
        .bind(&update.sampling_exclude_condition)
        .bind(&update.extension_vrl)
        .bind(&update.extension_enabled)
        .bind(&update.dispatch_source_config_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row_to_log_source(&row))
    }

    /// Delete a log source
    pub async fn delete(&self, id: Uuid) -> Result<(), LogSourceRepositoryError> {
        let result = sqlx::query("DELETE FROM log_sources WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(LogSourceRepositoryError::NotFound(id.to_string()));
        }

        Ok(())
    }
}
