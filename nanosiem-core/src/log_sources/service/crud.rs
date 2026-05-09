// SPDX-License-Identifier: AGPL-3.0-or-later

//! CRUD operations for log sources

use sqlx;
use uuid::Uuid;

use super::helpers::log_source_to_parser;
use super::LogSourceService;
use super::LogSourceServiceError;
use crate::log_sources::types::{ListParams, LogSource, NewLogSource, SourceType, UpdateLogSource};
use crate::parsers::Parser;

impl LogSourceService {
    /// List all log sources with optional filtering
    pub async fn list(
        &self,
        params: Option<ListParams>,
    ) -> Result<Vec<LogSource>, LogSourceServiceError> {
        let params = params.unwrap_or_default();
        Ok(self.repository().list(&params).await?)
    }

    /// List enabled log sources
    pub async fn list_enabled(&self) -> Result<Vec<LogSource>, LogSourceServiceError> {
        Ok(self.repository().list_enabled().await?)
    }

    /// List deployed log sources
    pub async fn list_deployed(&self) -> Result<Vec<LogSource>, LogSourceServiceError> {
        Ok(self.repository().list_deployed().await?)
    }

    /// Get a log source by ID
    pub async fn get(&self, id: Uuid) -> Result<LogSource, LogSourceServiceError> {
        Ok(self.repository().find_by_id(id).await?)
    }

    /// Get a log source by name
    pub async fn get_by_name(&self, name: &str) -> Result<LogSource, LogSourceServiceError> {
        Ok(self.repository().find_by_name(name).await?)
    }

    /// Create a new log source
    pub async fn create(&self, new: NewLogSource) -> Result<LogSource, LogSourceServiceError> {
        // Validate source type
        if SourceType::from_str(&new.source_type).is_none() {
            return Err(LogSourceServiceError::InvalidSourceType(
                new.source_type.clone(),
            ));
        }

        // Create in database
        let log_source = self.repository().create(&new).await?;

        tracing::info!(
            "Created log source '{}' ({}) with source type '{}'",
            log_source.name,
            log_source.id,
            log_source.source_type
        );

        // Validate VRL and set validation status
        let validation = self.validate_vrl(&log_source.parser_vrl).await;
        let error_msg = if validation.valid {
            None
        } else {
            Some(validation.errors.join("; "))
        };

        self.repository()
            .set_validation_status(log_source.id, validation.valid, error_msg.as_deref())
            .await?;

        // Return the updated log source with correct validation status
        self.repository()
            .find_by_id(log_source.id)
            .await
            .map_err(|e| e.into())
    }

    /// Update a log source
    pub async fn update(
        &self,
        id: Uuid,
        update: UpdateLogSource,
    ) -> Result<LogSource, LogSourceServiceError> {
        // Validate source type if being updated
        if let Some(ref source_type) = update.source_type {
            if SourceType::from_str(source_type).is_none() {
                return Err(LogSourceServiceError::InvalidSourceType(
                    source_type.clone(),
                ));
            }
        }

        let log_source = self.repository().update(id, &update).await?;

        // If VRL was updated, validate and set the correct status
        if update.parser_vrl.is_some() {
            let validation = self.validate_vrl(&log_source.parser_vrl).await;
            let error_msg = if validation.valid {
                None
            } else {
                Some(validation.errors.join("; "))
            };

            self.repository()
                .set_validation_status(id, validation.valid, error_msg.as_deref())
                .await?;
        }

        tracing::info!(
            "Updated log source '{}' ({})",
            log_source.name,
            log_source.id
        );

        // Return the updated log source with correct validation status
        self.repository().find_by_id(id).await.map_err(|e| e.into())
    }

    /// Delete a log source
    ///
    /// This removes the log source from the database and cleans up the Vector config files.
    /// The combiner and router configs are also updated to remove references to the deleted log source.
    pub async fn delete(&self, id: Uuid) -> Result<(), LogSourceServiceError> {
        let log_source = self.repository().find_by_id(id).await?;
        let log_source_name = log_source.name.clone();
        let was_deployed = log_source.deployed;

        // Delete from database first
        self.repository().delete(id).await?;

        // Clean up the config file for this log source
        if let Err(e) = self
            .vector_config
            .remove_parser_config(&log_source_name)
            .await
        {
            tracing::warn!(
                "Failed to remove Vector config for '{}': {}",
                log_source_name,
                e
            );
        }

        // Redeploy to update combiner and router (removes references to deleted log source)
        if was_deployed {
            let enabled = self.list_enabled_for_deploy().await?;
            let with_creds = self.inject_credentials_for_all(&enabled).await?;
            let parsers: Vec<Parser> = with_creds.into_iter().map(log_source_to_parser).collect();

            if let Err(e) = self.vector_config.deploy_and_reload(&parsers).await {
                tracing::warn!(
                    "Failed to redeploy after deleting log source '{}': {}",
                    log_source_name,
                    e
                );
            }
        }

        // Clean up orphaned routing rules that targeted this log source's source_type.
        // We only delete from the DB — no source config deploy or router update needed.
        // The next explicit source config deploy will regenerate configs without these rules.
        let source_type = &log_source.source_type;
        match sqlx::query("DELETE FROM routing_rules WHERE target_source_type = $1")
            .bind(source_type)
            .execute(&self.pool)
            .await
        {
            Ok(result) if result.rows_affected() > 0 => {
                tracing::info!(
                    "Removed {} orphaned routing rule(s) targeting source_type '{}'",
                    result.rows_affected(),
                    source_type
                );
            }
            Err(e) => {
                tracing::warn!(
                    "Failed to clean up routing rules for source_type '{}': {}",
                    source_type,
                    e
                );
            }
            _ => {}
        }

        tracing::info!("Deleted log source '{}' ({})", log_source_name, id);

        Ok(())
    }
}
