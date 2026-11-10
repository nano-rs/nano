// SPDX-License-Identifier: AGPL-3.0-or-later

//! PostgreSQL repository for cached license status

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use super::release_notice::ReleaseNotice;
use super::token_rejection::{TokenRejectedNotice, TokenRejection};
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
            "SELECT status, valid, tier, locked_reason, grace_ends_at, expires_at, last_checked_at, last_heartbeat_at, COALESCE(offline, FALSE) AS offline, raw_response
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
             VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, NOW())
             ON CONFLICT (id) DO UPDATE SET
                status = EXCLUDED.status,
                valid = EXCLUDED.valid,
                tier = EXCLUDED.tier,
                locked_reason = EXCLUDED.locked_reason,
                grace_ends_at = EXCLUDED.grace_ends_at,
                expires_at = EXCLUDED.expires_at,
                last_checked_at = EXCLUDED.last_checked_at,
                -- Merge: keys this write does not own (the NAN-5114
                -- `release` notice) survive a status update.
                raw_response = COALESCE(license_status.raw_response, '{}'::jsonb) || EXCLUDED.raw_response,
                updated_at = NOW()"
        )
        .bind(status.state.as_str())
        .bind(status.valid)
        .bind(&status.tier)
        .bind(&status.locked_reason)
        .bind(status.grace_ends_at)
        .bind(status.expires_at)
        .bind(status.last_checked_at)
        .bind(serde_json::json!({ "entitlement": status.entitlement }))
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// NAN-5114: record the newest-release facts from a successful online
    /// check-in (`None` clears them). Only the `release` key is touched.
    pub async fn update_release_notice(
        &self,
        notice: Option<&ReleaseNotice>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE license_status
             SET raw_response = COALESCE(raw_response, '{}'::jsonb) || jsonb_build_object('release', $1::jsonb),
                 updated_at = NOW()
             WHERE id = TRUE",
        )
        .bind(serde_json::to_value(notice).unwrap_or(serde_json::Value::Null))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// NAN-5194: record that the licence server refused the token. Only the
    /// `token_rejected` key is touched, and its `first_rejected_at` survives
    /// repeated rejections. A fresh install with no row gets a locked
    /// placeholder row (never a successful observation: `last_checked_at`
    /// stays NULL, so admission still fails closed).
    pub async fn record_token_rejection(
        &self,
        rejection: &TokenRejection,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO license_status (id, status, valid, raw_response, updated_at)
             VALUES (TRUE, 'locked', FALSE, jsonb_build_object('token_rejected', $1::jsonb), NOW())
             ON CONFLICT (id) DO UPDATE SET
                raw_response = COALESCE(license_status.raw_response, '{}'::jsonb)
                    || jsonb_build_object('token_rejected', $1::jsonb || jsonb_build_object(
                        'first_rejected_at',
                        COALESCE(
                            license_status.raw_response -> 'token_rejected' -> 'first_rejected_at',
                            $1::jsonb -> 'first_rejected_at'
                        )
                    )),
                updated_at = NOW()",
        )
        .bind(serde_json::to_value(rejection).unwrap_or(serde_json::Value::Null))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// NAN-5194: forget a token rejection (after a successful check-in).
    pub async fn clear_token_rejection(&self) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE license_status
             SET raw_response = raw_response - 'token_rejected', updated_at = NOW()
             WHERE id = TRUE AND raw_response ? 'token_rejected'",
        )
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// NAN-5194: the recorded token rejection with its lock date (14 days
    /// after the last successful check-in), or `None` (never rejected,
    /// cleared, air-gapped, malformed).
    pub async fn get_token_rejected_notice(
        &self,
    ) -> Result<Option<TokenRejectedNotice>, sqlx::Error> {
        let row: Option<(Option<serde_json::Value>, Option<DateTime<Utc>>, bool)> =
            sqlx::query_as(
                "SELECT raw_response -> 'token_rejected', last_checked_at, COALESCE(offline, FALSE)
                 FROM license_status WHERE id = TRUE",
            )
            .fetch_optional(&self.pool)
            .await?;
        Ok(row.and_then(|(raw, last_checked_at, offline)| {
            if offline {
                return None;
            }
            let rejection: TokenRejection = serde_json::from_value(raw?).ok()?;
            Some(TokenRejectedNotice::new(rejection, last_checked_at))
        }))
    }

    /// NAN-5114: the newest-release facts from the last successful online
    /// check-in, or `None` (no row, never reported, air-gapped, malformed).
    pub async fn get_release_notice(&self) -> Result<Option<ReleaseNotice>, sqlx::Error> {
        let raw: Option<Option<serde_json::Value>> = sqlx::query_scalar(
            "SELECT raw_response -> 'release' FROM license_status WHERE id = TRUE",
        )
        .fetch_optional(&self.pool)
        .await?;
        Ok(raw
            .flatten()
            .filter(|value| !value.is_null())
            .and_then(|value| serde_json::from_value(value).ok()))
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
    offline: bool,
    raw_response: Option<serde_json::Value>,
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
            offline: self.offline,
            entitlement: self
                .raw_response
                .and_then(|raw| raw.get("entitlement").cloned())
                .and_then(|value| serde_json::from_value(value).ok()),
        }
    }
}
