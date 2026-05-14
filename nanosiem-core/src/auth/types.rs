// SPDX-License-Identifier: AGPL-3.0-or-later

//! Authentication and RBAC type definitions
//!
//! Requirements: 2.5, 5.1

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

use crate::typeid;

/// User status enum
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, utoipa::ToSchema)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Locked,
    Disabled,
}

impl Default for UserStatus {
    fn default() -> Self {
        Self::Active
    }
}

impl std::fmt::Display for UserStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            UserStatus::Active => write!(f, "active"),
            UserStatus::Locked => write!(f, "locked"),
            UserStatus::Disabled => write!(f, "disabled"),
        }
    }
}

impl std::str::FromStr for UserStatus {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "active" => Ok(UserStatus::Active),
            "locked" => Ok(UserStatus::Locked),
            "disabled" => Ok(UserStatus::Disabled),
            _ => Err(format!("Invalid user status: {}", s)),
        }
    }
}

/// Query mode preference
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default, utoipa::ToSchema,
)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum QueryMode {
    #[default]
    Standard, // PPL - validated, detection-ready
    Advanced, // Raw SQL - full ClickHouse power
}

impl std::fmt::Display for QueryMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryMode::Standard => write!(f, "standard"),
            QueryMode::Advanced => write!(f, "advanced"),
        }
    }
}

impl std::str::FromStr for QueryMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "standard" => Ok(QueryMode::Standard),
            "advanced" => Ok(QueryMode::Advanced),
            _ => Err(format!(
                "Invalid query mode: {}. Must be 'standard' or 'advanced'",
                s
            )),
        }
    }
}

/// Default time range preset for searches
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default, utoipa::ToSchema,
)]
#[sqlx(type_name = "VARCHAR", rename_all = "snake_case")]
pub enum TimeRangePreset {
    #[serde(rename = "last_15_minutes")]
    Last15Minutes,
    #[serde(rename = "last_hour")]
    LastHour,
    #[serde(rename = "last_4_hours")]
    Last4Hours,
    #[default]
    #[serde(rename = "last_24_hours")]
    Last24Hours,
    #[serde(rename = "last_7_days")]
    Last7Days,
    #[serde(rename = "last_30_days")]
    Last30Days,
}

/// Search hub display style preference
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default, utoipa::ToSchema,
)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum SearchHubStyle {
    #[default]
    Popover,
    Drawer,
}

impl std::fmt::Display for SearchHubStyle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SearchHubStyle::Popover => write!(f, "popover"),
            SearchHubStyle::Drawer => write!(f, "drawer"),
        }
    }
}

impl std::str::FromStr for SearchHubStyle {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "popover" => Ok(SearchHubStyle::Popover),
            "drawer" => Ok(SearchHubStyle::Drawer),
            _ => Err(format!(
                "Invalid search hub style: {}. Must be 'popover' or 'drawer'",
                s
            )),
        }
    }
}

/// Landing page preference
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, sqlx::Type, Default, utoipa::ToSchema,
)]
#[sqlx(type_name = "VARCHAR", rename_all = "lowercase")]
#[serde(rename_all = "lowercase")]
pub enum LandingPage {
    Search,
    #[default]
    Home,
    Cases,
    Dashboards,
    Rules,
}

impl std::fmt::Display for LandingPage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LandingPage::Search => write!(f, "search"),
            LandingPage::Home => write!(f, "home"),
            LandingPage::Cases => write!(f, "cases"),
            LandingPage::Dashboards => write!(f, "dashboards"),
            LandingPage::Rules => write!(f, "rules"),
        }
    }
}

impl std::str::FromStr for LandingPage {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "search" => Ok(LandingPage::Search),
            "home" => Ok(LandingPage::Home),
            "cases" => Ok(LandingPage::Cases),
            "dashboards" => Ok(LandingPage::Dashboards),
            "rules" => Ok(LandingPage::Rules),
            _ => Err(format!("Invalid landing page: {}. Must be 'search', 'home', 'cases', 'dashboards', or 'rules'", s)),
        }
    }
}

impl std::fmt::Display for TimeRangePreset {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeRangePreset::Last15Minutes => write!(f, "last_15_minutes"),
            TimeRangePreset::LastHour => write!(f, "last_hour"),
            TimeRangePreset::Last4Hours => write!(f, "last_4_hours"),
            TimeRangePreset::Last24Hours => write!(f, "last_24_hours"),
            TimeRangePreset::Last7Days => write!(f, "last_7_days"),
            TimeRangePreset::Last30Days => write!(f, "last_30_days"),
        }
    }
}

impl std::str::FromStr for TimeRangePreset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "last_15_minutes" => Ok(TimeRangePreset::Last15Minutes),
            "last_hour" => Ok(TimeRangePreset::LastHour),
            "last_4_hours" => Ok(TimeRangePreset::Last4Hours),
            "last_24_hours" => Ok(TimeRangePreset::Last24Hours),
            "last_7_days" => Ok(TimeRangePreset::Last7Days),
            "last_30_days" => Ok(TimeRangePreset::Last30Days),
            _ => Err(format!("Invalid time range preset: {}", s)),
        }
    }
}

/// User account
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct User {
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub email: String,
    pub name: String,
    #[serde(skip_serializing)]
    pub password_hash: Option<String>,
    pub status: String,
    #[serde(skip_serializing)]
    pub failed_login_attempts: i32,
    #[serde(skip_serializing)]
    pub locked_until: Option<DateTime<Utc>>,
    #[serde(skip_serializing)]
    pub password_reset_token: Option<String>,
    #[serde(skip_serializing)]
    pub password_reset_expires: Option<DateTime<Utc>>,
    #[serde(default, with = "typeid::oidc_provider::opt")]
    #[schema(value_type = Option<String>)]
    pub oidc_provider_id: Option<Uuid>,
    pub oidc_subject: Option<String>,
    /// Groups from the most recent OIDC login token (for debugging group mappings)
    pub last_oidc_groups: Option<Vec<String>>,
    pub last_login_at: Option<DateTime<Utc>>,
    pub preferred_query_mode: Option<String>,
    pub default_time_range: Option<String>,
    pub search_hub_style: Option<String>,
    pub landing_page: Option<String>,
    // MFA fields
    #[serde(skip_serializing)]
    pub mfa_enabled: bool,
    #[serde(skip_serializing)]
    pub totp_secret_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub totp_secret_nonce: Option<String>,
    #[serde(skip_serializing)]
    pub backup_codes_encrypted: Option<Vec<u8>>,
    #[serde(skip_serializing)]
    pub backup_codes_nonce: Option<String>,
    #[serde(skip_serializing)]
    pub mfa_setup_pending: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create a new local user
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateUserRequest {
    pub email: String,
    pub name: String,
    pub password: String,
    #[serde(default, with = "typeid::group::vec")]
    #[schema(value_type = Vec<String>)]
    pub group_ids: Vec<Uuid>,
}

/// Request to update a user
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub name: Option<String>,
    pub password: Option<String>,
    pub status: Option<String>,
    /// Group IDs to set (replaces current non-Everyone groups). Omit to leave unchanged.
    pub group_ids: Option<Vec<String>>,
}

/// User with groups for API responses
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct UserWithGroups {
    #[serde(flatten)]
    pub user: User,
    pub groups: Vec<GroupSummary>,
}

/// Group summary for embedding in user responses
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct GroupSummary {
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
}

/// Group
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Group {
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Group with roles and member count
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct GroupWithDetails {
    #[serde(flatten)]
    pub group: Group,
    pub roles: Vec<RoleSummary>,
    pub member_count: i64,
}

/// Role summary for embedding
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct RoleSummary {
    #[serde(with = "typeid::role")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
}

/// Request to create a group
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateGroupRequest {
    pub name: String,
    pub description: Option<String>,
    #[serde(default, with = "typeid::role::vec")]
    #[schema(value_type = Vec<String>)]
    pub role_ids: Vec<Uuid>,
}

/// Request to update a group
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateGroupRequest {
    pub name: Option<String>,
    pub description: Option<String>,
}

/// Role
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Role {
    #[serde(with = "typeid::role")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Role with permissions
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct RoleWithPermissions {
    #[serde(flatten)]
    pub role: Role,
    pub permissions: Vec<String>,
}

/// Request to create a role
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
}

/// Request to update a role
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateRoleRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
}

/// Permission definition
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Permission {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub category: String,
}

/// Session
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct Session {
    #[serde(with = "typeid::session")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub user_id: Uuid,
    #[serde(skip_serializing)]
    pub refresh_token_hash: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
}

/// Session for API response (with current session indicator)
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct SessionResponse {
    #[serde(flatten)]
    pub session: Session,
    pub is_current: bool,
}

/// OIDC Provider configuration
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct OidcProvider {
    #[serde(with = "typeid::oidc_provider")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub issuer: String,
    pub client_id: String,
    #[serde(skip_serializing)]
    pub client_secret_encrypted: Vec<u8>,
    pub scopes: Vec<String>,
    pub group_claim: Option<String>,
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to create an OIDC provider
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateOidcProviderRequest {
    pub name: String,
    pub slug: String,
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    pub scopes: Option<Vec<String>>,
    pub group_claim: Option<String>,
}

/// Request to update an OIDC provider
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateOidcProviderRequest {
    pub name: Option<String>,
    pub issuer: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub group_claim: Option<String>,
    pub enabled: Option<bool>,
}

/// OIDC group mapping
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct OidcGroupMapping {
    #[serde(with = "typeid::oidc_group_mapping")]
    #[schema(value_type = String)]
    pub id: Uuid,
    #[serde(with = "typeid::oidc_provider")]
    #[schema(value_type = String)]
    pub provider_id: Uuid,
    pub oidc_group: String,
    #[serde(with = "typeid::group")]
    #[schema(value_type = String)]
    pub local_group_id: Uuid,
}

/// API Key
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct ApiKey {
    #[serde(with = "typeid::api_key")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    #[serde(skip_serializing)]
    pub key_hash: String,
    pub key_prefix: String,
    pub permissions: Vec<String>,
    pub enabled: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub rate_limit: Option<i32>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub last_used_ip: Option<String>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub created_by: Option<Uuid>,
    pub created_at: DateTime<Utc>,
}

/// API Key creation response (includes the full key, shown only once)
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct ApiKeyCreated {
    #[serde(with = "typeid::api_key")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub key: String,
    pub name: String,
    pub key_prefix: String,
    pub created_at: DateTime<Utc>,
}

/// Request to create an API key
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub description: Option<String>,
    pub permissions: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub rate_limit: Option<i32>,
}

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct AuditLog {
    #[serde(with = "typeid::audit")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    #[serde(default, with = "typeid::user::opt")]
    #[schema(value_type = Option<String>)]
    pub user_id: Option<Uuid>,
    #[serde(default, with = "typeid::api_key::opt")]
    #[schema(value_type = Option<String>)]
    pub api_key_id: Option<Uuid>,
    pub action: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<Uuid>,
    pub details: Option<serde_json::Value>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: bool,
}

/// Audit log with user/api key names for display
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuditLogWithNames {
    #[serde(flatten)]
    pub log: AuditLog,
    pub user_name: Option<String>,
    pub user_email: Option<String>,
    pub api_key_name: Option<String>,
}

/// JWT token claims
/// Requirements: 2.5
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TokenClaims {
    /// Issuer - identifies the token issuer (security: prevents token substitution)
    pub iss: String,
    /// Audience - intended recipient (security: prevents cross-service token reuse)
    pub aud: String,
    /// Subject (user ID)
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub sub: Uuid,
    /// Role names (used for UI display, not authorization decisions)
    pub roles: Vec<String>,
    /// Permissions resolved server-side by auth middleware.
    /// Not included in the JWT payload — populated after token validation.
    #[serde(default, skip_serializing)]
    pub permissions: Vec<String>,
    /// Expiration timestamp (Unix epoch)
    pub exp: i64,
    /// Issued at timestamp (Unix epoch)
    pub iat: i64,
    /// JWT ID (for revocation)
    #[serde(with = "typeid::session")]
    #[schema(value_type = String)]
    pub jti: Uuid,
    /// Token purpose: "access" (default) or "mfa_challenge"
    #[serde(default = "default_token_purpose")]
    pub purpose: String,
}

fn default_token_purpose() -> String {
    "access".to_string()
}

impl TokenClaims {
    /// Check if the token has a specific permission
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(&permission.to_string())
    }

    /// Check if the token has any of the specified permissions
    pub fn has_any_permission(&self, permissions: &[&str]) -> bool {
        permissions.iter().any(|p| self.has_permission(p))
    }

    /// Check if the token has all of the specified permissions
    pub fn has_all_permissions(&self, permissions: &[&str]) -> bool {
        permissions.iter().all(|p| self.has_permission(p))
    }
}

/// Token pair (access + refresh)
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct TokenPair {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

impl TokenPair {
    pub fn new(access_token: String, refresh_token: String, expires_in: i64) -> Self {
        Self {
            access_token,
            refresh_token,
            token_type: "Bearer".to_string(),
            expires_in,
        }
    }
}

/// Login request
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct AuthResponse {
    pub user: UserInfo,
    pub tokens: TokenPair,
}

/// User info for auth response (minimal)
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct UserInfo {
    #[serde(with = "typeid::user")]
    #[schema(value_type = String)]
    pub id: Uuid,
    pub email: String,
    pub name: String,
    pub roles: Vec<String>,
    pub permissions: Vec<String>,
    pub preferred_query_mode: QueryMode,
    pub default_time_range: TimeRangePreset,
    pub landing_page: LandingPage,
}

/// User preferences for settings
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct UserPreferences {
    pub preferred_query_mode: QueryMode,
    pub default_time_range: TimeRangePreset,
    pub search_hub_style: SearchHubStyle,
    pub landing_page: LandingPage,
}

/// Request to update user preferences
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateUserPreferencesRequest {
    pub preferred_query_mode: Option<QueryMode>,
    pub default_time_range: Option<TimeRangePreset>,
    pub search_hub_style: Option<SearchHubStyle>,
    pub landing_page: Option<LandingPage>,
}

/// Refresh token request
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct RefreshTokenRequest {
    pub refresh_token: Option<String>,
}

/// Password reset request
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct PasswordResetRequest {
    pub email: String,
}

/// Password reset completion
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct PasswordResetCompletion {
    pub token: String,
    pub new_password: String,
}

// === MFA Types ===

/// Result of a login attempt (may require MFA)
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(tag = "status")]
pub enum LoginResult {
    /// Full authentication complete
    #[serde(rename = "authenticated")]
    Success(AuthResponse),
    /// MFA verification required before token issuance
    #[serde(rename = "mfa_required")]
    MfaRequired { challenge_token: String },
    /// Admin-enforced MFA setup required before first login
    #[serde(rename = "mfa_setup_required")]
    MfaSetupRequired { challenge_token: String },
}

/// Response from MFA setup initiation
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct MfaSetupResponse {
    /// Base32-encoded TOTP secret for manual entry
    pub secret: String,
    /// otpauth:// URI for QR code scanning
    pub otpauth_uri: String,
    /// Base64-encoded PNG QR code image
    pub qr_code_base64: String,
}

/// Request to start MFA setup. Body is optional — only required when the
/// caller is mid-forced-enrollment (no Bearer session yet) and needs to
/// authenticate via the short-lived `mfa_challenge` token from the prior
/// login response. Bearer-authenticated calls (voluntary enrolment from
/// User Settings) leave the body empty.
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct MfaSetupRequest {
    /// MFA challenge token from a `MfaSetupRequired` login response. When
    /// present and valid, authenticates the request in lieu of a Bearer
    /// session. Ignored when a valid Authorization header is also
    /// present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
}

/// Request to verify MFA setup with first TOTP code
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct MfaVerifySetupRequest {
    /// 6-digit TOTP code from authenticator app
    pub code: String,
    /// MFA challenge token — same role as on `MfaSetupRequest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge_token: Option<String>,
}

/// Response after MFA setup is complete
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct MfaSetupCompleteResponse {
    /// 10 one-time backup codes (shown once, store securely)
    pub backup_codes: Vec<String>,
}

/// Request to complete MFA challenge during login
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct MfaChallengeRequest {
    /// Challenge token from login response
    pub challenge_token: String,
    /// TOTP code or backup code
    pub code: String,
}

/// MFA status for a user
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct MfaStatusResponse {
    pub mfa_enabled: bool,
    pub mfa_setup_pending: bool,
    /// Whether the admin requires MFA for all users
    pub mfa_required_globally: bool,
}

/// Request to disable MFA (requires password confirmation)
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct MfaDisableRequest {
    pub password: String,
}

/// Request to regenerate backup codes (requires password confirmation)
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct MfaRegenerateBackupCodesRequest {
    pub password: String,
}

/// System configuration entry
#[derive(Debug, Clone, Serialize, Deserialize, FromRow, utoipa::ToSchema)]
pub struct SystemConfig {
    pub key: String,
    pub value: serde_json::Value,
    pub updated_at: DateTime<Utc>,
}

/// Well-known system config keys
pub mod config_keys {
    /// Whether the system has been initialized (first admin created)
    pub const SYSTEM_INITIALIZED: &str = "system_initialized";
    /// JWT secret key
    pub const JWT_SECRET: &str = "jwt_secret";
    /// Access token TTL in seconds
    pub const ACCESS_TOKEN_TTL: &str = "access_token_ttl";
    /// Refresh token TTL in seconds
    pub const REFRESH_TOKEN_TTL: &str = "refresh_token_ttl";
    /// Session inactivity timeout in seconds
    pub const SESSION_TIMEOUT: &str = "session_timeout";
    /// Account lockout threshold (failed attempts)
    pub const LOCKOUT_THRESHOLD: &str = "lockout_threshold";
    /// Account lockout duration in seconds
    pub const LOCKOUT_DURATION: &str = "lockout_duration";
}

/// Default configuration values
pub mod config_defaults {
    /// Default access token TTL: 15 minutes
    pub const ACCESS_TOKEN_TTL: i64 = 900;
    /// Default refresh token TTL: 7 days
    pub const REFRESH_TOKEN_TTL: i64 = 604800;
    /// Default session timeout: 24 hours
    pub const SESSION_TIMEOUT: i64 = 86400;
    /// Default lockout threshold: 5 attempts
    pub const LOCKOUT_THRESHOLD: i32 = 5;
    /// Default lockout duration: 15 minutes
    pub const LOCKOUT_DURATION: i64 = 900;
}

/// Built-in role IDs
pub mod builtin_roles {
    use uuid::Uuid;

    pub const ADMIN_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);
    pub const EDITOR_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000002);
    pub const READONLY_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000003);
}

/// Built-in group IDs
pub mod builtin_groups {
    use uuid::Uuid;

    pub const EVERYONE_ID: Uuid = Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);
}
