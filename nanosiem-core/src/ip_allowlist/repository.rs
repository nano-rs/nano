// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist repository for PostgreSQL operations

use sqlx::{PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use super::types::{
    CreateIpAllowlistEntry, IpAllowlistEntry, IpAllowlistScope, UpdateIpAllowlistEntry,
};

#[derive(Error, Debug)]
pub enum IpAllowlistRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Not found: {0}")]
    NotFound(Uuid),
    #[error("Duplicate entry: CIDR {cidr} already exists in scope {scope}")]
    DuplicateEntry { cidr: String, scope: String },
}

pub struct IpAllowlistRepository {
    pool: PgPool,
}

impl IpAllowlistRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// List all allowlist entries, optionally filtered by scope
    pub async fn list(
        &self,
        scope: Option<IpAllowlistScope>,
    ) -> Result<Vec<IpAllowlistEntry>, IpAllowlistRepositoryError> {
        let rows = if let Some(scope) = scope {
            sqlx::query(
                "SELECT id, scope, cidr, description, enabled, created_by, created_at, updated_at
                 FROM ip_allowlists
                 WHERE scope = $1
                 ORDER BY scope, cidr",
            )
            .bind(scope.as_str())
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                "SELECT id, scope, cidr, description, enabled, created_by, created_at, updated_at
                 FROM ip_allowlists
                 ORDER BY scope, cidr",
            )
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows.iter().map(row_to_entry).collect())
    }


    /// Get a single entry by ID
    pub async fn get(&self, id: Uuid) -> Result<IpAllowlistEntry, IpAllowlistRepositoryError> {
        let row = sqlx::query(
            "SELECT id, scope, cidr, description, enabled, created_by, created_at, updated_at
             FROM ip_allowlists
             WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await?
        .ok_or(IpAllowlistRepositoryError::NotFound(id))?;

        Ok(row_to_entry(&row))
    }

    /// Create a new allowlist entry
    pub async fn create(
        &self,
        entry: &CreateIpAllowlistEntry,
        created_by: Option<Uuid>,
    ) -> Result<IpAllowlistEntry, IpAllowlistRepositoryError> {
        let row = sqlx::query(
            "INSERT INTO ip_allowlists (scope, cidr, description, enabled, created_by)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING id, scope, cidr, description, enabled, created_by, created_at, updated_at",
        )
        .bind(entry.scope.as_str())
        .bind(&entry.cidr)
        .bind(&entry.description)
        .bind(entry.enabled)
        .bind(created_by)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("idx_ip_allowlists_scope_cidr") {
                    return IpAllowlistRepositoryError::DuplicateEntry {
                        cidr: entry.cidr.clone(),
                        scope: entry.scope.to_string(),
                    };
                }
            }
            IpAllowlistRepositoryError::DatabaseError(e)
        })?;

        Ok(row_to_entry(&row))
    }

    /// Update an existing allowlist entry
    pub async fn update(
        &self,
        id: Uuid,
        update: &UpdateIpAllowlistEntry,
    ) -> Result<IpAllowlistEntry, IpAllowlistRepositoryError> {
        // First check it exists
        let existing = self.get(id).await?;

        let scope = update
            .scope
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| existing.scope.as_str().to_string());
        let cidr = update.cidr.as_deref().unwrap_or(&existing.cidr).to_string();
        let description = if update.description.is_some() {
            update.description.clone()
        } else {
            existing.description.clone()
        };
        let enabled = update.enabled.unwrap_or(existing.enabled);

        let row = sqlx::query(
            "UPDATE ip_allowlists
             SET scope = $2, cidr = $3, description = $4, enabled = $5
             WHERE id = $1
             RETURNING id, scope, cidr, description, enabled, created_by, created_at, updated_at",
        )
        .bind(id)
        .bind(&scope)
        .bind(&cidr)
        .bind(&description)
        .bind(enabled)
        .fetch_one(&self.pool)
        .await
        .map_err(|e| {
            if let sqlx::Error::Database(ref db_err) = e {
                if db_err.constraint() == Some("idx_ip_allowlists_scope_cidr") {
                    return IpAllowlistRepositoryError::DuplicateEntry {
                        cidr: cidr.clone(),
                        scope: scope.clone(),
                    };
                }
            }
            IpAllowlistRepositoryError::DatabaseError(e)
        })?;

        Ok(row_to_entry(&row))
    }

    /// Delete an allowlist entry
    pub async fn delete(&self, id: Uuid) -> Result<(), IpAllowlistRepositoryError> {
        let result = sqlx::query("DELETE FROM ip_allowlists WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;

        if result.rows_affected() == 0 {
            return Err(IpAllowlistRepositoryError::NotFound(id));
        }

        Ok(())
    }
}

/// Convert a database row to an IpAllowlistEntry
fn row_to_entry(row: &sqlx::postgres::PgRow) -> IpAllowlistEntry {
    let scope_str: String = row.get("scope");
    IpAllowlistEntry {
        id: row.get("id"),
        scope: IpAllowlistScope::from_str(&scope_str).unwrap_or(IpAllowlistScope::Global),
        cidr: row.get("cidr"),
        description: row.get("description"),
        enabled: row.get("enabled"),
        created_by: row.get("created_by"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    }
}
