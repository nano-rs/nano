// SPDX-License-Identifier: AGPL-3.0-or-later

//! Audit log repository for logging and querying audit events
//!
//! Requirements: 9.1, 9.2, 9.3, 9.4, 9.5

use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::auth::types::{AuditLog, AuditLogWithNames};

#[derive(Error, Debug)]
pub enum AuditRepositoryError {
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("Audit log not found: {0}")]
    NotFound(Uuid),
}

/// One UTC calendar day's count of audited actions attributed to an actor.
///
/// Backs the per-API-key call-volume endpoint. This counts *audited* actions
/// (mutations + authorization denials carrying the actor's `api_key_id`), not
/// raw request volume — read-only traffic is not audited.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct DailyActionCount {
    pub day: chrono::NaiveDate,
    pub count: i64,
}

/// Well-known audit actions
pub mod audit_actions {
    // Authentication events
    pub const LOGIN_SUCCESS: &str = "auth.login.success";
    pub const LOGIN_FAILED: &str = "auth.login.failed";
    pub const LOGOUT: &str = "auth.logout";
    pub const TOKEN_REFRESH: &str = "auth.token.refresh";
    pub const PASSWORD_RESET_REQUEST: &str = "auth.password.reset_request";
    pub const PASSWORD_RESET_COMPLETE: &str = "auth.password.reset_complete";
    pub const PASSWORD_CHANGE: &str = "auth.password.change";

    // User management
    pub const USER_CREATE: &str = "user.create";
    pub const USER_UPDATE: &str = "user.update";
    pub const USER_DELETE: &str = "user.delete";
    pub const USER_LOCK: &str = "user.lock";
    pub const USER_UNLOCK: &str = "user.unlock";
    pub const USER_DISABLE: &str = "user.disable";
    pub const USER_ENABLE: &str = "user.enable";

    // Group management
    pub const GROUP_CREATE: &str = "group.create";
    pub const GROUP_UPDATE: &str = "group.update";
    pub const GROUP_DELETE: &str = "group.delete";
    pub const GROUP_MEMBER_ADD: &str = "group.member.add";
    pub const GROUP_MEMBER_REMOVE: &str = "group.member.remove";
    pub const GROUP_ROLE_ASSIGN: &str = "group.role.assign";

    // Role management
    pub const ROLE_CREATE: &str = "role.create";
    pub const ROLE_UPDATE: &str = "role.update";
    pub const ROLE_DELETE: &str = "role.delete";
    pub const ROLE_PERMISSION_UPDATE: &str = "role.permission.update";

    // Session management
    pub const SESSION_CREATE: &str = "session.create";
    pub const SESSION_TERMINATE: &str = "session.terminate";
    pub const SESSION_TERMINATE_ALL: &str = "session.terminate_all";
    pub const SESSION_CLEANUP: &str = "session.cleanup";

    // API key management
    pub const APIKEY_CREATE: &str = "apikey.create";
    pub const APIKEY_DELETE: &str = "apikey.delete";
    pub const APIKEY_ENABLE: &str = "apikey.enable";
    pub const APIKEY_DISABLE: &str = "apikey.disable";
    pub const APIKEY_RESET: &str = "apikey.reset";
    pub const APIKEY_USE: &str = "apikey.use";

    // OIDC provider management
    pub const OIDC_PROVIDER_CREATE: &str = "oidc.provider.create";
    pub const OIDC_PROVIDER_UPDATE: &str = "oidc.provider.update";
    pub const OIDC_PROVIDER_DELETE: &str = "oidc.provider.delete";
    pub const OIDC_LOGIN: &str = "oidc.login";

    // Risk management
    pub const RISK_CLEAR_ENTITY: &str = "risk.clear.entity";
    pub const RISK_CLEAR_ALL: &str = "risk.clear.all";

    // Identity provider management
    pub const IDENTITY_PROVIDER_CREATED: &str = "identity_provider.created";
    pub const IDENTITY_PROVIDER_UPDATED: &str = "identity_provider.updated";
    pub const IDENTITY_PROVIDER_DELETED: &str = "identity_provider.deleted";
    pub const IDENTITY_PROVIDER_CREDENTIALS_UPDATED: &str = "identity_provider.credentials_updated";
    pub const IDENTITY_SYNC_TRIGGERED: &str = "identity_sync.triggered";
    pub const IDENTITY_SYNC_COMPLETED: &str = "identity_sync.completed";
    pub const IDENTITY_USERS_PUSHED: &str = "identity_users.pushed";

    // MFA events
    pub const MFA_SETUP_INITIATED: &str = "auth.mfa.setup_initiated";
    pub const MFA_SETUP_COMPLETE: &str = "auth.mfa.setup_complete";
    pub const MFA_DISABLED: &str = "auth.mfa.disabled";
    pub const MFA_CHALLENGE_ISSUED: &str = "auth.mfa.challenge_issued";
    pub const MFA_CHALLENGE_SUCCESS: &str = "auth.mfa.challenge_success";
    pub const MFA_CHALLENGE_FAILED: &str = "auth.mfa.challenge_failed";
    pub const MFA_BACKUP_CODE_USED: &str = "auth.mfa.backup_code_used";
    pub const MFA_BACKUP_CODES_REGENERATED: &str = "auth.mfa.backup_codes_regenerated";
    pub const MFA_ADMIN_RESET: &str = "auth.mfa.admin_reset";
    pub const MFA_ENFORCED_GLOBALLY: &str = "auth.mfa.enforced_globally";

    // Authorization failures
    pub const AUTH_DENIED: &str = "auth.denied";
}

/// Repository for audit log operations
#[derive(Clone)]
pub struct AuditRepository {
    pool: PgPool,
}

impl AuditRepository {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Log an audit event
    /// Requirements: 9.1, 9.2, 9.3, 9.4
    pub async fn log_event(
        &self,
        user_id: Option<Uuid>,
        api_key_id: Option<Uuid>,
        action: &str,
        resource_type: Option<&str>,
        resource_id: Option<Uuid>,
        details: Option<serde_json::Value>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
        success: bool,
    ) -> Result<AuditLog, AuditRepositoryError> {
        let log = sqlx::query_as::<_, AuditLog>(
            r#"
            INSERT INTO audit_logs (
                user_id, api_key_id, action, resource_type, resource_id,
                details, ip_address, user_agent, success
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *
            "#,
        )
        .bind(user_id)
        .bind(api_key_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(details)
        .bind(ip_address)
        .bind(user_agent)
        .bind(success)
        .fetch_one(&self.pool)
        .await?;

        Ok(log)
    }

    /// Get a single audit log entry
    pub async fn get_log(&self, id: Uuid) -> Result<AuditLog, AuditRepositoryError> {
        sqlx::query_as::<_, AuditLog>("SELECT * FROM audit_logs WHERE id = $1")
            .bind(id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(AuditRepositoryError::NotFound(id))
    }

    /// Get recent audit logs for a user
    pub async fn get_user_recent_logs(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<AuditLog>, AuditRepositoryError> {
        let logs = sqlx::query_as::<_, AuditLog>(
            r#"
            SELECT * FROM audit_logs
            WHERE user_id = $1
            ORDER BY timestamp DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(logs)
    }

    /// Get recent failed login attempts for a user
    pub async fn get_failed_logins(
        &self,
        user_id: Uuid,
        since_minutes: i64,
    ) -> Result<i64, AuditRepositoryError> {
        let count = sqlx::query_scalar::<_, i64>(
            r#"
            SELECT COUNT(*)
            FROM audit_logs
            WHERE user_id = $1
              AND action = $2
              AND success = FALSE
              AND timestamp > NOW() - ($3 || ' minutes')::interval
            "#,
        )
        .bind(user_id)
        .bind(audit_actions::LOGIN_FAILED)
        .bind(since_minutes.to_string())
        .fetch_one(&self.pool)
        .await?;

        Ok(count)
    }

    /// Delete old audit logs (for retention policy).
    ///
    /// Deletes in batches of 10,000 to avoid long-running transactions that
    /// could cause lock contention after months of accumulation.
    pub async fn delete_old_logs(&self, days: i64) -> Result<u64, AuditRepositoryError> {
        let mut total_deleted = 0u64;
        loop {
            let result = sqlx::query(
                "DELETE FROM audit_logs WHERE id IN (
                    SELECT id FROM audit_logs
                    WHERE timestamp < NOW() - ($1 || ' days')::interval
                    LIMIT 10000
                )",
            )
            .bind(days.to_string())
            .execute(&self.pool)
            .await?;

            let deleted = result.rows_affected();
            total_deleted += deleted;
            if deleted < 10000 {
                break;
            }
            // Small sleep between batches to reduce PG load
            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        }
        Ok(total_deleted)
    }

    /// Count audited actions performed by an API key, bucketed by UTC calendar
    /// day, for the window starting at `start` (inclusive).
    ///
    /// Returns only days with activity (sparse) ordered oldest-first; callers
    /// densify into a continuous series. See [`DailyActionCount`] for the
    /// caveat on what "audited actions" covers.
    pub async fn get_api_key_daily_usage(
        &self,
        api_key_id: Uuid,
        start: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<DailyActionCount>, AuditRepositoryError> {
        let rows = sqlx::query_as::<_, DailyActionCount>(
            r#"
            SELECT (timestamp AT TIME ZONE 'UTC')::date AS day,
                   COUNT(*)::bigint AS count
            FROM audit_logs
            WHERE api_key_id = $1
              AND timestamp >= $2
            GROUP BY day
            ORDER BY day
            "#,
        )
        .bind(api_key_id)
        .bind(start)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows)
    }
}

// Implement FromRow for AuditLogWithNames manually since it has nested fields
impl<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> for AuditLogWithNames {
    fn from_row(row: &'r sqlx::postgres::PgRow) -> Result<Self, sqlx::Error> {
        use sqlx::Row;

        Ok(AuditLogWithNames {
            log: AuditLog {
                id: row.try_get("id")?,
                timestamp: row.try_get("timestamp")?,
                user_id: row.try_get("user_id")?,
                api_key_id: row.try_get("api_key_id")?,
                action: row.try_get("action")?,
                resource_type: row.try_get("resource_type")?,
                resource_id: row.try_get("resource_id")?,
                details: row.try_get("details")?,
                ip_address: row.try_get("ip_address")?,
                user_agent: row.try_get("user_agent")?,
                success: row.try_get("success")?,
            },
            user_name: row.try_get("user_name")?,
            user_email: row.try_get("user_email")?,
            api_key_name: row.try_get("api_key_name")?,
        })
    }
}
