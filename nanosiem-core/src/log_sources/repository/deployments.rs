// SPDX-License-Identifier: AGPL-3.0-or-later

//! Deployment history operations for log sources

use sqlx::Row;
use uuid::Uuid;

use super::super::types::LogSourceDeployment;
use super::{LogSourceRepository, LogSourceRepositoryError};

impl LogSourceRepository {
    /// Record a deployment action
    pub async fn record_deployment(
        &self,
        log_source_id: Uuid,
        action: &str,
        status: &str,
        error_message: Option<&str>,
        config_snapshot: Option<&str>,
    ) -> Result<Uuid, LogSourceRepositoryError> {
        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO log_source_deployments (log_source_id, action, status, error_message, config_snapshot)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(log_source_id)
        .bind(action)
        .bind(status)
        .bind(error_message)
        .bind(config_snapshot)
        .fetch_one(&self.pool)
        .await?;

        Ok(id)
    }

    /// Get deployment history for a log source
    pub async fn get_deployment_history(
        &self,
        log_source_id: Uuid,
        limit: i64,
    ) -> Result<Vec<LogSourceDeployment>, LogSourceRepositoryError> {
        let rows = sqlx::query(
            r#"
            SELECT id, log_source_id, action, status, error_message, config_snapshot, deployed_at
            FROM log_source_deployments
            WHERE log_source_id = $1
            ORDER BY deployed_at DESC
            LIMIT $2
            "#,
        )
        .bind(log_source_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .iter()
            .map(|row| LogSourceDeployment {
                id: row.get("id"),
                log_source_id: row.get("log_source_id"),
                action: row.get("action"),
                status: row.get("status"),
                error_message: row.get("error_message"),
                config_snapshot: row.get("config_snapshot"),
                deployed_at: row.get("deployed_at"),
            })
            .collect())
    }
}
