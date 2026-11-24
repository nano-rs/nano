// SPDX-License-Identifier: AGPL-3.0-or-later

//! Demo session service
//!
//! Manages ephemeral demo sessions: creation, resource tracking, and cleanup.
//! Demo users are real `users` rows with a curated permission set, tracked via
//! the `demo.sessions` and `demo.session_resources` tables.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use thiserror::Error;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::auth::{
    repository::{SessionRepository, UserRepository},
    service::hash_token,
    types::{
        AuthResponse, CreateUserRequest, LandingPage, QueryMode, TimeRangePreset, TokenPair,
        UserInfo,
    },
    TokenService,
};

/// Resource types trackable in demo sessions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DemoResourceType {
    Rule,
    Case,
    Dashboard,
    Notebook,
    SavedSearch,
}

impl DemoResourceType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Case => "case",
            Self::Dashboard => "dashboard",
            Self::Notebook => "notebook",
            Self::SavedSearch => "saved_search",
        }
    }
}

impl std::fmt::Display for DemoResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A demo session
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow, utoipa::ToSchema)]
pub struct DemoSession {
    pub id: Uuid,
    pub token: String,
    pub burned_at: Option<DateTime<Utc>>,
    pub user_id: Uuid,
    pub display_name: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
    pub cleaned_up: bool,
    pub cleaned_up_at: Option<DateTime<Utc>>,
}

/// Status response for a demo session
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DemoSessionStatus {
    pub session_id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub remaining_hours: f64,
    pub resource_counts: DemoResourceCounts,
}

/// Resource counts for a demo session
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DemoResourceCounts {
    pub rules: i64,
    pub cases: i64,
    pub dashboards: i64,
    pub notebooks: i64,
    pub saved_searches: i64,
}

/// Demo session creation response
#[derive(Debug, Clone, Serialize)]
pub struct DemoSessionResponse {
    pub session: DemoSession,
    pub auth: AuthResponse,
}

/// Demo session quotas
#[derive(Debug, Clone)]
pub struct DemoQuotas {
    pub max_rules: i64,
    pub max_cases: i64,
    pub max_dashboards: i64,
    pub max_notebooks: i64,
    pub max_saved_searches: i64,
}

impl Default for DemoQuotas {
    fn default() -> Self {
        Self {
            max_rules: 20,
            max_cases: 10,
            max_dashboards: 5,
            max_notebooks: 10,
            max_saved_searches: 20,
        }
    }
}

#[derive(Debug, Error)]
pub enum DemoError {
    #[error("Demo mode is not enabled")]
    NotEnabled,
    #[error("Demo session not found")]
    SessionNotFound,
    #[error("Demo session expired")]
    SessionExpired,
    #[error("Demo link has already been used")]
    TokenAlreadyBurned,
    #[error("Invalid demo link")]
    InvalidToken,
    #[error("Rate limit exceeded: maximum {0} demo sessions per IP per hour")]
    RateLimitExceeded(u32),
    #[error("Demo quota exceeded for {resource_type}: maximum {max} allowed")]
    QuotaExceeded { resource_type: String, max: i64 },
    #[error("Database error: {0}")]
    DatabaseError(#[from] sqlx::Error),
    #[error("User creation failed: {0}")]
    UserError(String),
    #[error("Token error: {0}")]
    TokenError(String),
}

pub struct DemoService {
    pool: PgPool,
    user_repo: UserRepository,
    session_repo: SessionRepository,
    token_service: std::sync::Arc<TokenService>,
    session_ttl_hours: i64,
    max_sessions_per_ip: u32,
    quotas: DemoQuotas,
}

impl DemoService {
    pub fn new(
        pool: PgPool,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        token_service: std::sync::Arc<TokenService>,
        session_ttl_hours: i64,
        max_sessions_per_ip: u32,
    ) -> Self {
        Self {
            pool,
            user_repo,
            session_repo,
            token_service,
            session_ttl_hours,
            max_sessions_per_ip,
            quotas: DemoQuotas::default(),
        }
    }

    /// Create a new demo session with an ephemeral user.
    pub async fn create_session(
        &self,
        display_name: Option<String>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<DemoSessionResponse, DemoError> {
        // Rate limit by IP
        if let Some(ip) = ip_address {
            self.check_rate_limit(ip).await?;
        }

        // Create ephemeral user
        let session_id = Uuid::now_v7();
        let email = format!("demo-{}@demo.nano.local", session_id);
        let name = display_name
            .clone()
            .unwrap_or_else(|| "Demo User".to_string());
        // Generate a random password — demo users never log in with credentials.
        // It must still satisfy the authoritative policy, which
        // `UserRepository::create_user` now enforces for every caller.
        let password = generate_demo_password();

        let user = self
            .user_repo
            .create_user(&CreateUserRequest {
                email: email.clone(),
                name: name.clone(),
                password,
                group_ids: vec![], // Gets auto-added to Everyone by trigger
            })
            .await
            .map_err(|e| DemoError::UserError(e.to_string()))?;

        // Create demo session in demo schema
        let expires_at = Utc::now() + Duration::hours(self.session_ttl_hours);
        let demo_token = generate_demo_token();
        let session: DemoSession = sqlx::query_as(
            r#"
            INSERT INTO demo.sessions (id, token, user_id, display_name, ip_address, user_agent, expires_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING *
            "#,
        )
        .bind(session_id)
        .bind(&demo_token)
        .bind(user.id)
        .bind(&display_name)
        .bind(ip_address)
        .bind(user_agent)
        .bind(expires_at)
        .fetch_one(&self.pool)
        .await?;

        // Issue tokens with demo permissions
        let roles = vec!["demo_analyst".to_string()];
        let permissions: Vec<String> = crate::auth::permissions::demo_permissions();

        // Create a row in the main sessions table so that the standard
        // auth refresh_token flow can look up the refresh token hash and
        // rotate it.  Without this, demo users get logged out when the
        // access token expires (~15 min) because the refresh silently fails.
        let token_pair = self
            .open_auth_session(user.id, roles.clone(), ip_address, user_agent)
            .await?;

        let auth_response = AuthResponse {
            user: UserInfo {
                id: user.id,
                email,
                name,
                roles,
                permissions,
                preferred_query_mode: QueryMode::Standard,
                default_time_range: TimeRangePreset::Last24Hours,
                landing_page: LandingPage::Home,
            },
            tokens: token_pair,
        };

        info!(
            session_id = %session.id,
            user_id = %user.id,
            expires_at = %expires_at,
            ip = ?ip_address,
            "Demo session created"
        );

        Ok(DemoSessionResponse {
            session,
            auth: auth_response,
        })
    }

    /// Open an auth session row and mint its tokens. The access token is
    /// bound to the new session (`sid`, NAN-5573) so logout ends only it.
    async fn open_auth_session(
        &self,
        user_id: Uuid,
        roles: Vec<String>,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) -> Result<TokenPair, DemoError> {
        let refresh_token = self
            .token_service
            .create_refresh_token(user_id)
            .map_err(|e| DemoError::TokenError(e.to_string()))?;
        let session_expires_at =
            Utc::now() + Duration::seconds(self.token_service.refresh_token_ttl());
        let auth_session = self
            .session_repo
            .create_session(
                user_id,
                &hash_token(&refresh_token),
                ip_address,
                user_agent,
                session_expires_at,
            )
            .await
            .map_err(|e| DemoError::UserError(format!("session creation failed: {e}")))?;
        let access_token = self
            .token_service
            .create_access_token_for_session(user_id, roles, auth_session.id)
            .map_err(|e| DemoError::TokenError(e.to_string()))?;
        Ok(TokenPair::new(
            access_token,
            refresh_token,
            self.token_service.access_token_ttl(),
        ))
    }

    /// Claim a demo session by token.
    /// The token is reusable for the lifetime of the session (72h default),
    /// so the user can bookmark or re-open the link to resume their session.
    pub async fn claim_token(&self, token: &str) -> Result<DemoSessionResponse, DemoError> {
        let session: Option<DemoSession> =
            sqlx::query_as("SELECT * FROM demo.sessions WHERE token = $1 AND cleaned_up = FALSE")
                .bind(token)
                .fetch_optional(&self.pool)
                .await?;

        let session = match session {
            Some(s) => s,
            None => return Err(DemoError::InvalidToken),
        };

        if session.expires_at < Utc::now() {
            return Err(DemoError::SessionExpired);
        }

        // Update last_active_at on each claim
        sqlx::query("UPDATE demo.sessions SET last_active_at = NOW() WHERE id = $1")
            .bind(session.id)
            .execute(&self.pool)
            .await
            .ok();

        // Issue tokens
        let roles = vec!["demo_analyst".to_string()];
        let permissions: Vec<String> = crate::auth::permissions::demo_permissions();

        // Clean up any previous auth sessions for this user (re-claims
        // would otherwise stack orphan rows until the 7-day TTL expires)
        let _ = self.session_repo.delete_user_sessions(session.user_id).await;

        // Create a session row so the standard refresh_token flow works
        let token_pair = self
            .open_auth_session(
                session.user_id,
                roles.clone(),
                session.ip_address.as_deref(),
                session.user_agent.as_deref(),
            )
            .await?;

        // Get user info
        let user = self
            .user_repo
            .get_user_by_id(session.user_id)
            .await
            .map_err(|e| DemoError::UserError(e.to_string()))?;

        let auth_response = AuthResponse {
            user: UserInfo {
                id: user.id,
                email: user.email,
                name: user.name,
                roles,
                permissions,
                preferred_query_mode: QueryMode::Standard,
                default_time_range: TimeRangePreset::Last24Hours,
                landing_page: LandingPage::Home,
            },
            tokens: token_pair,
        };

        info!(
            session_id = %session.id,
            user_id = %session.user_id,
            "Demo token claimed"
        );

        Ok(DemoSessionResponse {
            session,
            auth: auth_response,
        })
    }

    /// Get the demo session for a user ID (if one exists and is active).
    pub async fn get_session_for_user(&self, user_id: Uuid) -> Result<DemoSession, DemoError> {
        let session: Option<DemoSession> = sqlx::query_as(
            r#"
            SELECT * FROM demo.sessions
            WHERE user_id = $1 AND cleaned_up = FALSE
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        match session {
            Some(s) if s.expires_at < Utc::now() => Err(DemoError::SessionExpired),
            Some(s) => Ok(s),
            None => Err(DemoError::SessionNotFound),
        }
    }

    /// Get session status including resource counts.
    pub async fn get_session_status(&self, user_id: Uuid) -> Result<DemoSessionStatus, DemoError> {
        let session = self.get_session_for_user(user_id).await?;
        let counts = self.get_resource_counts(session.id).await?;
        let remaining = (session.expires_at - Utc::now()).num_minutes() as f64 / 60.0;

        Ok(DemoSessionStatus {
            session_id: session.id,
            expires_at: session.expires_at,
            remaining_hours: remaining.max(0.0),
            resource_counts: counts,
        })
    }

    /// Track a resource created by a demo user.
    pub async fn track_resource(
        &self,
        user_id: Uuid,
        resource_type: DemoResourceType,
        resource_id: Uuid,
    ) -> Result<(), DemoError> {
        let session = self.get_session_for_user(user_id).await?;

        // Check quota
        self.check_quota(session.id, resource_type).await?;

        sqlx::query(
            r#"
            INSERT INTO demo.session_resources (session_id, resource_type, resource_id)
            VALUES ($1, $2, $3)
            ON CONFLICT DO NOTHING
            "#,
        )
        .bind(session.id)
        .bind(resource_type.as_str())
        .bind(resource_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get resource IDs created by OTHER demo sessions (not this user's).
    /// Used to filter list queries so demo users only see pre-seeded content + their own.
    pub async fn get_other_demo_resource_ids(
        &self,
        user_id: Uuid,
        resource_type: DemoResourceType,
    ) -> Result<Vec<Uuid>, DemoError> {
        let ids: Vec<Uuid> = sqlx::query_scalar(
            r#"
            SELECT sr.resource_id
            FROM demo.session_resources sr
            JOIN demo.sessions s ON sr.session_id = s.id
            WHERE sr.resource_type = $1
              AND s.user_id != $2
            "#,
        )
        .bind(resource_type.as_str())
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(ids)
    }

    /// Check if a user is a demo user (has an active demo session).
    pub async fn is_demo_user(&self, user_id: Uuid) -> bool {
        sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM demo.sessions WHERE user_id = $1 AND cleaned_up = FALSE)",
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await
        .unwrap_or(false)
    }

    /// Clean up all expired demo sessions and their resources.
    pub async fn cleanup_expired_sessions(&self) -> Result<u64, DemoError> {
        // Snapshot the candidate sessions WITHOUT holding a batch-wide lock. Each
        // session is then cleaned in its OWN transaction (NAN-2026). Previously the
        // whole batch shared one transaction, so a single failing session (e.g. a
        // FK violation deleting its user) aborted the transaction and every
        // subsequent statement failed with "current transaction is aborted"; the
        // final commit rolled everything back, so NO session was ever marked
        // cleaned_up — the same sessions re-failed every run and demo data
        // accumulated. Per-session transactions contain a failure to just that
        // session and let the healthy ones commit.
        let expired_sessions: Vec<DemoSession> = sqlx::query_as(
            "SELECT * FROM demo.sessions WHERE expires_at < NOW() AND cleaned_up = FALSE",
        )
        .fetch_all(&self.pool)
        .await?;

        if expired_sessions.is_empty() {
            return Ok(0);
        }

        info!(
            count = expired_sessions.len(),
            "Cleaning up expired demo sessions"
        );

        let mut cleaned = 0u64;
        for session in &expired_sessions {
            let mut tx = match self.pool.begin().await {
                Ok(tx) => tx,
                Err(e) => {
                    error!(session_id = %session.id, error = %e,
                        "Failed to begin demo session cleanup transaction");
                    continue;
                }
            };

            // Re-lock the row under this transaction so a concurrent cleanup run
            // (multi-replica / leader failover) can't double-process it. SKIP
            // LOCKED yields it to whoever already holds it; the cleaned_up filter
            // skips one that was finished between the snapshot and now.
            let claimed: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM demo.sessions WHERE id = $1 AND cleaned_up = FALSE FOR UPDATE SKIP LOCKED",
            )
            .bind(session.id)
            .fetch_optional(&mut *tx)
            .await
            .unwrap_or(None);
            if claimed.is_none() {
                let _ = tx.rollback().await;
                continue;
            }

            match self.cleanup_session_in_tx(session, &mut tx).await {
                Ok(()) => match tx.commit().await {
                    Ok(()) => cleaned += 1,
                    Err(e) => error!(
                        session_id = %session.id, user_id = %session.user_id, error = %e,
                        "Failed to commit demo session cleanup"
                    ),
                },
                Err(e) => {
                    let _ = tx.rollback().await;
                    error!(
                        session_id = %session.id, user_id = %session.user_id, error = %e,
                        "Failed to clean up demo session"
                    );
                }
            }
        }

        Ok(cleaned)
    }

    /// Enterprise half of [`Self::delete_untracked_demo_writes`]: cases the
    /// demo user created, their standalone notebooks, and their notes and
    /// handoffs on cases and notebooks that belong to someone else.
    #[cfg(feature = "enterprise")]
    async fn delete_untracked_demo_case_writes(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        demo_user_id: Uuid,
    ) -> Result<(), DemoError> {
        for (table, sql) in [
            ("cases", "DELETE FROM cases WHERE created_by = $1"),
            (
                "notebooks",
                "DELETE FROM notebooks WHERE owner_id = $1 AND case_id IS NULL",
            ),
            ("notebook_entries", "DELETE FROM notebook_entries WHERE created_by = $1"),
            ("case_handoffs", "DELETE FROM case_handoffs WHERE source_user_id = $1"),
        ] {
            let exists: bool =
                sqlx::query_scalar("SELECT to_regclass('public.' || $1) IS NOT NULL")
                    .bind(table)
                    .fetch_one(&mut **tx)
                    .await?;
            if exists {
                sqlx::query(sql).bind(demo_user_id).execute(&mut **tx).await?;
            }
        }
        Ok(())
    }

    /// Delete everything an ephemeral demo user wrote that the tracked
    /// resources do not cover.
    async fn delete_untracked_demo_writes(
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        demo_user_id: Uuid,
    ) -> Result<(), DemoError> {
        // Order matters: cases first (their notebooks, handoffs and entries go
        // with them), then the demo user's standalone notebooks, then whatever
        // they wrote on cases and notebooks that belong to someone else. A
        // demo-owned notebook of a PRE-SEEDED case is left to the trigger,
        // which hands it to the case assignee or the system AI user, so seeded
        // demo content survives.
        // Case and notebook tables exist only on the enterprise edition; the
        // open build compiles no statement naming them.
        #[cfg(feature = "enterprise")]
        Self::delete_untracked_demo_case_writes(tx, demo_user_id).await?;
        sqlx::query("DELETE FROM feedback WHERE user_id = $1")
            .bind(demo_user_id)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    /// Clean up a single demo session within an existing transaction.
    async fn cleanup_session_in_tx(
        &self,
        session: &DemoSession,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    ) -> Result<(), DemoError> {
        // Delete tracked resources from core tables (order matters for FK constraints)
        let resource_types = ["saved_search", "notebook", "dashboard", "case", "rule"];

        for rt in &resource_types {
            let resource_ids: Vec<Uuid> = sqlx::query_scalar(
                "SELECT resource_id FROM demo.session_resources WHERE session_id = $1 AND resource_type = $2",
            )
            .bind(session.id)
            .bind(rt)
            .fetch_all(&mut **tx)
            .await?;

            if resource_ids.is_empty() {
                continue;
            }

            // Delete from the corresponding core table.
            // Table name is from a hardcoded match, not user input — safe to interpolate.
            let table = match *rt {
                "rule" => "detection_rules",
                "case" => "cases",
                "dashboard" => "dashboards",
                "notebook" => "notebooks",
                "saved_search" => "saved_searches",
                _ => continue,
            };

            let query = format!("DELETE FROM {} WHERE id = ANY($1)", table);
            sqlx::query(sqlx::AssertSqlSafe(query.as_str()))
                .bind(&resource_ids)
                .execute(&mut **tx)
                .await?;
        }

        // NAN-5721: author references now SET NULL and a trigger hands shared
        // notebooks to a new owner, so deleting the user no longer sweeps up
        // what a demo visitor wrote outside the tracked resources (notes on
        // pre-seeded cases, handoffs, feedback, untracked notebooks and
        // cases). Remove it explicitly. Scoped to this session's ephemeral
        // demo user (`session.user_id` comes from demo.sessions), never a
        // real account.
        Self::delete_untracked_demo_writes(tx, session.user_id).await?;

        // Delete the user (cascades sessions, user_groups, etc.)
        sqlx::query("DELETE FROM users WHERE id = $1")
            .bind(session.user_id)
            .execute(&mut **tx)
            .await?;

        // Mark session as cleaned up (FK ON DELETE CASCADE may already handle this,
        // but we set it explicitly for visibility in queries)
        sqlx::query(
            "UPDATE demo.sessions SET cleaned_up = TRUE, cleaned_up_at = NOW() WHERE id = $1",
        )
        .bind(session.id)
        .execute(&mut **tx)
        .await
        .ok(); // May fail if cascaded, that's fine

        info!(
            session_id = %session.id,
            user_id = %session.user_id,
            "Demo session cleaned up"
        );

        Ok(())
    }

    /// Check rate limit for demo session creation by IP.
    async fn check_rate_limit(&self, ip_address: &str) -> Result<(), DemoError> {
        let recent_count: i64 = sqlx::query_scalar(
            r#"
            SELECT COUNT(*) FROM demo.sessions
            WHERE ip_address = $1 AND created_at > NOW() - INTERVAL '1 hour'
            "#,
        )
        .bind(ip_address)
        .fetch_one(&self.pool)
        .await?;

        if recent_count >= self.max_sessions_per_ip as i64 {
            warn!(
                ip = %ip_address,
                count = recent_count,
                max = self.max_sessions_per_ip,
                "Demo session rate limit exceeded"
            );
            return Err(DemoError::RateLimitExceeded(self.max_sessions_per_ip));
        }

        Ok(())
    }

    /// Check if a resource quota would be exceeded.
    async fn check_quota(
        &self,
        session_id: Uuid,
        resource_type: DemoResourceType,
    ) -> Result<(), DemoError> {
        let max = match resource_type {
            DemoResourceType::Rule => self.quotas.max_rules,
            DemoResourceType::Case => self.quotas.max_cases,
            DemoResourceType::Dashboard => self.quotas.max_dashboards,
            DemoResourceType::Notebook => self.quotas.max_notebooks,
            DemoResourceType::SavedSearch => self.quotas.max_saved_searches,
        };

        let current: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM demo.session_resources WHERE session_id = $1 AND resource_type = $2",
        )
        .bind(session_id)
        .bind(resource_type.as_str())
        .fetch_one(&self.pool)
        .await?;

        if current >= max {
            return Err(DemoError::QuotaExceeded {
                resource_type: resource_type.to_string(),
                max,
            });
        }

        Ok(())
    }

    /// Get resource counts for a session.
    async fn get_resource_counts(&self, session_id: Uuid) -> Result<DemoResourceCounts, DemoError> {
        let counts: Vec<(String, i64)> = sqlx::query_as(
            r#"
            SELECT resource_type, COUNT(*) as count
            FROM demo.session_resources
            WHERE session_id = $1
            GROUP BY resource_type
            "#,
        )
        .bind(session_id)
        .fetch_all(&self.pool)
        .await?;

        let mut result = DemoResourceCounts {
            rules: 0,
            cases: 0,
            dashboards: 0,
            notebooks: 0,
            saved_searches: 0,
        };

        for (rt, count) in counts {
            match rt.as_str() {
                "rule" => result.rules = count,
                "case" => result.cases = count,
                "dashboard" => result.dashboards = count,
                "notebook" => result.notebooks = count,
                "saved_search" => result.saved_searches = count,
                _ => {}
            }
        }

        Ok(result)
    }

    /// Update last_active_at for session keepalive.
    pub async fn touch_session(&self, user_id: Uuid) -> Result<(), DemoError> {
        sqlx::query(
            "UPDATE demo.sessions SET last_active_at = NOW() WHERE user_id = $1 AND cleaned_up = FALSE",
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }
}

/// How long a `demo.sessions` existence answer is reused (NAN-5825). Token
/// refresh asks on every refresh; both answers are cached so a non-demo
/// install pays one `to_regclass` round trip per database per TTL, and expire
/// so a demo schema created later (or dropped) is picked up within it.
pub(crate) const DEMO_SCHEMA_PROBE_TTL: std::time::Duration = std::time::Duration::from_secs(30);

/// Per-database (`host:port/database`) cache of the demo-schema probe. An
/// errored probe is never cached, so a transient failure cannot hide a demo
/// schema for the TTL.
#[derive(Default)]
pub(crate) struct DemoSchemaCache {
    entries: std::collections::HashMap<String, (bool, std::time::Instant)>,
}

impl DemoSchemaCache {
    pub(crate) fn get(&self, key: &str, now: std::time::Instant) -> Option<bool> {
        self.entries
            .get(key)
            .filter(|(_, at)| now.saturating_duration_since(*at) < DEMO_SCHEMA_PROBE_TTL)
            .map(|(present, _)| *present)
    }

    pub(crate) fn put(&mut self, key: &str, present: bool, now: std::time::Instant) {
        self.entries.insert(key.to_owned(), (present, now));
    }

    pub(crate) fn forget(&mut self, key: &str) {
        self.entries.remove(key);
    }
}

static DEMO_SCHEMA_CACHE: std::sync::LazyLock<std::sync::Mutex<DemoSchemaCache>> =
    std::sync::LazyLock::new(Default::default);

fn demo_cache() -> std::sync::MutexGuard<'static, DemoSchemaCache> {
    DEMO_SCHEMA_CACHE.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The database a pool talks to, as the cache key.
fn database_key(pool: &PgPool) -> String {
    let options = pool.connect_options();
    format!(
        "{}:{}/{}",
        options.get_host(),
        options.get_port(),
        options.get_database().unwrap_or("")
    )
}

/// NAN-5825: whether this database has the demo schema. Probed with
/// `to_regclass`, which returns NULL instead of failing, so a non-demo install
/// never sends a statement PostgreSQL rejects (and logs as an ERROR).
async fn demo_sessions_present(pool: &PgPool) -> bool {
    let key = database_key(pool);
    let now = std::time::Instant::now();
    if let Some(present) = demo_cache().get(&key, now) {
        return present;
    }
    match sqlx::query_scalar::<_, bool>("SELECT to_regclass('demo.sessions') IS NOT NULL")
        .fetch_one(pool)
        .await
    {
        Ok(present) => {
            demo_cache().put(&key, present, now);
            present
        }
        Err(_) => false,
    }
}

/// Check if a user has an active (non-expired, non-cleaned-up) demo session.
/// Works with just a PgPool — no DemoService needed.
///
/// NAN-5825: token refresh calls this for every user, so on an install
/// without the demo schema it answers `false` from the (cached) schema probe
/// instead of querying a relation that does not exist. Fails closed: any
/// error is `false`; an `undefined_table` error (the schema was dropped since
/// the probe) also forgets the cached answer.
pub async fn is_demo_session_active(pool: &PgPool, user_id: Uuid) -> bool {
    if !demo_sessions_present(pool).await {
        return false;
    }
    match sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM demo.sessions WHERE user_id = $1 AND cleaned_up = FALSE AND expires_at > NOW())",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    {
        Ok(active) => active,
        Err(error) => {
            if error
                .as_database_error()
                .and_then(|db| db.code())
                .is_some_and(|code| code == "42P01")
            {
                demo_cache().forget(&database_key(pool));
            }
            false
        }
    }
}

#[cfg(test)]
mod demo_schema_cache_tests {
    use super::{DemoSchemaCache, DEMO_SCHEMA_PROBE_TTL};
    use std::time::{Duration, Instant};

    /// NAN-5825 review: both answers are cached per database and expire, so a
    /// demo schema created later is seen within the TTL and one database's
    /// answer never leaks into another's.
    #[test]
    fn answers_are_per_database_and_expire() {
        let t0 = Instant::now();
        let mut cache = DemoSchemaCache::default();
        assert_eq!(cache.get("pg:5432/a", t0), None);
        cache.put("pg:5432/a", false, t0);
        cache.put("pg:5432/b", true, t0);
        assert_eq!(cache.get("pg:5432/a", t0 + Duration::from_secs(1)), Some(false));
        assert_eq!(cache.get("pg:5432/b", t0 + Duration::from_secs(1)), Some(true));
        assert_eq!(cache.get("pg:5432/c", t0), None);
        let later = t0 + DEMO_SCHEMA_PROBE_TTL;
        assert_eq!(cache.get("pg:5432/a", later), None, "a cached absence expires");
        assert_eq!(cache.get("pg:5432/b", later), None, "a cached presence expires");
        cache.put("pg:5432/b", true, t0);
        cache.forget("pg:5432/b");
        assert_eq!(cache.get("pg:5432/b", t0), None);
    }
}

/// Get resource IDs created by OTHER demo users. Standalone version for use
/// without a full DemoService (e.g., from the search microservice).
pub async fn get_other_demo_resource_ids_standalone(
    pool: &PgPool,
    user_id: Uuid,
    resource_type: &str,
) -> Vec<Uuid> {
    sqlx::query_scalar(
        r#"
        SELECT sr.resource_id
        FROM demo.session_resources sr
        JOIN demo.sessions s ON sr.session_id = s.id
        WHERE sr.resource_type = $1
          AND s.user_id != $2
        "#,
    )
    .bind(resource_type)
    .bind(user_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Track a resource created by a demo user. Standalone version for use
/// without a full DemoService (e.g., from the search microservice).
/// No-op if the user doesn't have an active demo session.
pub async fn track_demo_resource_standalone(
    pool: &PgPool,
    user_id: Uuid,
    resource_type: &str,
    resource_id: Uuid,
) {
    // Find the user's active demo session
    let session_id: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM demo.sessions WHERE user_id = $1 AND cleaned_up = FALSE AND expires_at > NOW() ORDER BY created_at DESC LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if let Some(sid) = session_id {
        let _ = sqlx::query(
            "INSERT INTO demo.session_resources (session_id, resource_type, resource_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(sid)
        .bind(resource_type)
        .bind(resource_id)
        .execute(pool)
        .await;
    }
}

/// Random throwaway password for an ephemeral demo identity.
///
/// Demo users never authenticate with a password, but `create_user` validates
/// every plaintext against `PasswordRequirements::default()`, and a random
/// alphanumeric token satisfies the uppercase/lowercase/digit classes only by
/// chance and the special-character class never. The fixed suffix guarantees one
/// character from each required class; the 32 random characters carry the
/// entropy.
fn generate_demo_password() -> String {
    format!("{}Aa1!", generate_demo_token())
}

/// Generate a URL-safe random token for demo session links.
fn generate_demo_token() -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut rng = rand::rng();
    (0..32)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}
