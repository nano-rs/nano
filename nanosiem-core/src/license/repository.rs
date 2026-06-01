// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL repository for cached license status

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use super::types::{LicenseState, LicenseStatus};

/// Repository for reading/writing cached license status in PostgreSQL
#[derive(Clone)]
pub struct LicenseRepository {
    pool: PgPool,
}

impl LicenseRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Load the cached license status. Returns default (active) if no row exists.
    pub async fn get_status(&self) -> Result<LicenseStatus, sqlx::Error> {
        let row = sqlx::query_as::<_, LicenseRow>(
            "SELECT status, valid, tier, locked_reason, grace_ends_at, expires_at, last_checked_at, last_heartbeat_at
             FROM license_status WHERE id = TRUE"
        )
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(LicenseRow::into_status).unwrap_or_default())
    }

    /// Update the cached license status from a license check response.
    pub async fn update_status(&self, status: &LicenseStatus) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO license_status (id, status, valid, tier, locked_reason, grace_ends_at, expires_at, last_checked_at, raw_response, updated_at)
             VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, NULL, NOW())
             ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                valid = EXCLUDED.valid,
                tier = EXCLUDED.tier,
                locked_reason = EXCLUDED.locked_reason,
                grace_ends_at = EXCLUDED.grace_ends_at,
                expires_at = EXCLUDED.expires_at,
                last_checked_at = EXCLUDED.last_checked_at,
                updated_at = NOW()"
        )
        .bind(status.state.as_str())
        .bind(status.valid)
        .bind(&status.tier)
        .bind(&status.locked_reason)
        .bind(status.grace_ends_at)
        .bind(status.expires_at)
        .bind(status.last_checked_at)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

#[derive(sqlx::FromRow)]
struct LicenseRow {
    status: String,
    valid: bool,
    tier: Option<String>,
    locked_reason: Option<String>,
    grace_ends_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    last_checked_at: Option<DateTime<Utc>>,
    last_heartbeat_at: Option<DateTime<Utc>>,
}

impl LicenseRow {
    fn into_status(self) -> LicenseStatus {
        LicenseStatus {
            state: LicenseState::from_str(&self.status),
            valid: self.valid,
            tier: self.tier,
            locked_reason: self.locked_reason,
            grace_ends_at: self.grace_ends_at,
            expires_at: self.expires_at,
            last_checked_at: self.last_checked_at,
            last_heartbeat_at: self.last_heartbeat_at,
        }
    }
}
