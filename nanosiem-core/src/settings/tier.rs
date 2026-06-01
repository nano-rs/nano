// SPDX-License-Identifier: AGPL-3.0-or-later

//! Organization tier-based restrictions
//!
//! Defines plan tiers (Unrestricted, Hobby, Startup, Growth, Team, Starter, Pro, Enterprise)
//! and enforces limits on data sources, detection rules, team members, API access,
//! AI request volume, and model tier. Default tier is Unrestricted (no limits) for
//! dev/self-hosted/internal deployments.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Organization tier levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationTier {
    Unrestricted,
    Hobby,
    Startup,
    Growth,
    Team,
    Starter,
    Pro,
    Enterprise,
}

impl Default for OrganizationTier {
    fn default() -> Self {
        Self::Unrestricted
    }
}

impl std::fmt::Display for OrganizationTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unrestricted => write!(f, "unrestricted"),
            Self::Hobby => write!(f, "hobby"),
            Self::Startup => write!(f, "startup"),
            Self::Growth => write!(f, "growth"),
            Self::Team => write!(f, "team"),
            Self::Starter => write!(f, "starter"),
            Self::Pro => write!(f, "pro"),
            Self::Enterprise => write!(f, "enterprise"),
        }
    }
}

impl std::str::FromStr for OrganizationTier {
    type Err = TierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "unrestricted" => Ok(Self::Unrestricted),
            "hobby" => Ok(Self::Hobby),
            "startup" => Ok(Self::Startup),
            "growth" => Ok(Self::Growth),
            "team" => Ok(Self::Team),
            "starter" => Ok(Self::Starter),
            "pro" => Ok(Self::Pro),
            "enterprise" => Ok(Self::Enterprise),
            _ => Err(TierError::InvalidTier(s.to_string())),
        }
    }
}

/// API access level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum ApiAccessLevel {
    /// No API access
    None,
    /// Read-only: search and alert queries only
    Readonly,
    /// Full API access
    Full,
}

impl std::fmt::Display for ApiAccessLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "none"),
            Self::Readonly => write!(f, "readonly"),
            Self::Full => write!(f, "full"),
        }
    }
}

impl std::str::FromStr for ApiAccessLevel {
    type Err = TierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "none" => Ok(Self::None),
            "readonly" => Ok(Self::Readonly),
            "full" => Ok(Self::Full),
            _ => Err(TierError::Validation(format!(
                "Invalid API access level: {}",
                s
            ))),
        }
    }
}

/// AI model tier — controls which AI models are available
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum AiModelTier {
    /// Haiku, Flash Lite only
    Economy,
    /// Standard + lite models
    Standard,
    /// All models
    Full,
}

impl std::fmt::Display for AiModelTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Economy => write!(f, "economy"),
            Self::Standard => write!(f, "standard"),
            Self::Full => write!(f, "full"),
        }
    }
}

impl std::str::FromStr for AiModelTier {
    type Err = TierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "economy" => Ok(Self::Economy),
            "standard" => Ok(Self::Standard),
            "full" => Ok(Self::Full),
            _ => Err(TierError::Validation(format!(
                "Invalid AI model tier: {}",
                s
            ))),
        }
    }
}

/// Tier limits configuration
///
/// `None` values mean unlimited (no restriction).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TierLimits {
    pub tier: OrganizationTier,
    /// Maximum number of data sources (None = unlimited)
    pub max_data_sources: Option<u32>,
    /// Maximum number of custom detection rules (None = unlimited)
    pub max_detection_rules: Option<u32>,
    /// Maximum number of team members (None = unlimited)
    pub max_team_members: Option<u32>,
    /// Maximum daily ingestion in GB (None = unlimited)
    pub max_daily_gb: Option<f64>,
    /// Maximum events per second (None = unlimited)
    pub max_eps: Option<u32>,
    /// API access level
    pub api_access: ApiAccessLevel,
    /// Whether SSO/SAML is enabled
    pub sso_enabled: bool,
    /// Whether HA (high availability) is enabled
    pub ha_enabled: bool,
    /// Maximum AI credits per month (None = unlimited).
    /// Lite models cost 2 credits, full models cost 10 credits.
    pub ai_credits_per_month: Option<u32>,
    /// AI model tier — controls which models are available
    pub ai_model_tier: AiModelTier,
}

impl TierLimits {
    /// Get the default limits for a given tier.
    /// These are the hardcoded defaults; DB values can override for Enterprise.
    pub fn for_tier(tier: OrganizationTier) -> Self {
        match tier {
            OrganizationTier::Unrestricted => Self {
                tier,
                max_data_sources: None,
                max_detection_rules: None,
                max_team_members: None,
                max_daily_gb: None,
                max_eps: None,
                api_access: ApiAccessLevel::Full,
                sso_enabled: true,
                ha_enabled: true,
                ai_credits_per_month: None,
                ai_model_tier: AiModelTier::Full,
            },
            OrganizationTier::Hobby => Self {
                tier,
                max_data_sources: Some(10),
                max_detection_rules: Some(15),
                max_team_members: Some(3),
                max_daily_gb: Some(2.0),
                max_eps: Some(30),
                api_access: ApiAccessLevel::None,
                sso_enabled: false,
                ha_enabled: false,
                ai_credits_per_month: Some(3_000),
                ai_model_tier: AiModelTier::Economy,
            },
            OrganizationTier::Startup => Self {
                tier,
                max_data_sources: Some(20),
                max_detection_rules: Some(30),
                max_team_members: Some(8),
                max_daily_gb: Some(5.0),
                max_eps: Some(75),
                api_access: ApiAccessLevel::None,
                sso_enabled: false,
                ha_enabled: false,
                ai_credits_per_month: Some(10_000),
                ai_model_tier: AiModelTier::Standard,
            },
            OrganizationTier::Growth => Self {
                tier,
                max_data_sources: Some(30),
                max_detection_rules: Some(50),
                max_team_members: Some(12),
                max_daily_gb: Some(10.0),
                max_eps: Some(155),
                api_access: ApiAccessLevel::Full,
                sso_enabled: false,
                ha_enabled: false,
                ai_credits_per_month: Some(25_000),
                ai_model_tier: AiModelTier::Full,
            },
            OrganizationTier::Team => Self {
                tier,
                max_data_sources: None,
                max_detection_rules: None,
                max_team_members: Some(15),
                max_daily_gb: Some(25.0),
                max_eps: Some(385),
                api_access: ApiAccessLevel::Full,
                sso_enabled: false,
                ha_enabled: true,
                ai_credits_per_month: Some(50_000),
                ai_model_tier: AiModelTier::Full,
            },
            // "Business" tier (canonical `tiers.ts` key `starter`). Sells at
            // 50 GB/day / 770 EPS — double Team. Do not copy Team's 25/385 here.
            OrganizationTier::Starter => Self {
                tier,
                max_data_sources: None,
                max_detection_rules: None,
                max_team_members: None,
                max_daily_gb: Some(50.0),
                max_eps: Some(770),
                api_access: ApiAccessLevel::Full,
                sso_enabled: true,
                ha_enabled: true,
                ai_credits_per_month: Some(150_000),
                ai_model_tier: AiModelTier::Full,
            },
            OrganizationTier::Pro => Self {
                tier,
                max_data_sources: None,
                max_detection_rules: None,
                max_team_members: None,
                max_daily_gb: Some(100.0),
                max_eps: Some(1_550),
                api_access: ApiAccessLevel::Full,
                sso_enabled: true,
                ha_enabled: true,
                ai_credits_per_month: Some(400_000),
                ai_model_tier: AiModelTier::Full,
            },
            OrganizationTier::Enterprise => Self {
                tier,
                max_data_sources: None,
                max_detection_rules: None,
                max_team_members: None,
                max_daily_gb: None,
                max_eps: None,
                api_access: ApiAccessLevel::Full,
                sso_enabled: true,
                ha_enabled: true,
                ai_credits_per_month: None,
                ai_model_tier: AiModelTier::Full,
            },
        }
    }

    /// Check if any limit is enforced (i.e., not Unrestricted)
    pub fn is_enforced(&self) -> bool {
        self.tier != OrganizationTier::Unrestricted
    }
}

/// Result of a tier limit check
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TierLimitExceeded {
    /// Which resource hit the limit
    pub resource: String,
    /// Current tier name
    pub tier: String,
    /// The limit that was exceeded
    pub limit: u32,
    /// Current usage count
    pub current: u32,
    /// Suggested upgrade message
    pub upgrade_hint: String,
}

/// Errors for tier operations
#[derive(Debug, thiserror::Error)]
pub enum TierError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    #[error("Invalid tier: {0}")]
    InvalidTier(String),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Tier limit exceeded: {0}")]
    LimitExceeded(String),
    #[error("Feature not available: {0}")]
    FeatureNotAvailable(String),
    #[error("API access restricted: {0}")]
    ApiAccessRestricted(String),
    #[error("AI rate limit exceeded: {0}")]
    AiRateLimitExceeded(String),
    #[error("AI model not available: {0}")]
    AiModelNotAvailable(String),
}

/// Repository for tier settings in system_settings table
pub struct TierSettings {
    pool: PgPool,
}

impl TierSettings {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Get current tier configuration, merging DB overrides with tier defaults
    pub async fn get_tier_limits(&self) -> Result<TierLimits, TierError> {
        let row = sqlx::query_as::<
            _,
            (
                String,                        // tier
                Option<i32>,                   // tier_max_data_sources
                Option<i32>,                   // tier_max_detection_rules
                Option<i32>,                   // tier_max_team_members
                Option<rust_decimal::Decimal>, // tier_max_daily_gb
                Option<i32>,                   // tier_max_eps
                String,                        // tier_api_access
                Option<bool>,                  // tier_sso_enabled (NULL = use tier default)
                Option<serde_json::Value>,     // tier_limits_override
            ),
        >(
            r#"
            SELECT
                tier,
                tier_max_data_sources,
                tier_max_detection_rules,
                tier_max_team_members,
                tier_max_daily_gb,
                tier_max_eps,
                tier_api_access,
                tier_sso_enabled,
                tier_limits_override
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((
                tier_str,
                max_data_sources,
                max_detection_rules,
                max_team_members,
                max_daily_gb,
                max_eps,
                api_access_str,
                sso_enabled,
                _limits_override,
            )) => {
                let tier: OrganizationTier = tier_str.parse()?;
                let defaults = TierLimits::for_tier(tier);

                // DB columns override tier defaults when explicitly set (non-NULL)
                Ok(TierLimits {
                    tier,
                    max_data_sources: max_data_sources
                        .map(|v| v as u32)
                        .or(defaults.max_data_sources),
                    max_detection_rules: max_detection_rules
                        .map(|v| v as u32)
                        .or(defaults.max_detection_rules),
                    max_team_members: max_team_members
                        .map(|v| v as u32)
                        .or(defaults.max_team_members),
                    max_daily_gb: max_daily_gb
                        .map(|v| {
                            use rust_decimal::prelude::ToPrimitive;
                            v.to_f64().unwrap_or(0.0)
                        })
                        .or(defaults.max_daily_gb),
                    max_eps: max_eps.map(|v| v as u32).or(defaults.max_eps),
                    api_access: api_access_str.parse().unwrap_or(defaults.api_access),
                    sso_enabled: sso_enabled.unwrap_or(defaults.sso_enabled),
                    ha_enabled: defaults.ha_enabled,
                    ai_credits_per_month: defaults.ai_credits_per_month,
                    ai_model_tier: defaults.ai_model_tier,
                })
            }
            None => Ok(TierLimits::for_tier(OrganizationTier::default())),
        }
    }

    /// Update the organization tier
    pub async fn set_tier(&self, tier: OrganizationTier) -> Result<TierLimits, TierError> {
        let defaults = TierLimits::for_tier(tier);

        sqlx::query(
            r#"
            UPDATE system_settings SET
                tier = $1,
                tier_max_data_sources = $2,
                tier_max_detection_rules = $3,
                tier_max_team_members = $4,
                tier_max_daily_gb = $5,
                tier_max_eps = $6,
                tier_api_access = $7,
                tier_sso_enabled = $8,
                tier_limits_override = NULL,
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(tier.to_string())
        .bind(defaults.max_data_sources.map(|v| v as i32))
        .bind(defaults.max_detection_rules.map(|v| v as i32))
        .bind(defaults.max_team_members.map(|v| v as i32))
        .bind(
            defaults
                .max_daily_gb
                .map(rust_decimal::Decimal::from_f64_retain),
        )
        .bind(defaults.max_eps.map(|v| v as i32))
        .bind(defaults.api_access.to_string())
        .bind(defaults.sso_enabled)
        .execute(&self.pool)
        .await?;

        Ok(defaults)
    }

    /// Update specific tier limit overrides (for Enterprise customization)
    pub async fn update_limits(&self, limits: UpdateTierLimits) -> Result<TierLimits, TierError> {
        if let Some(max_ds) = limits.max_data_sources {
            sqlx::query("UPDATE system_settings SET tier_max_data_sources = $1, updated_at = NOW() WHERE id = 'default'")
                .bind(max_ds as i32)
                .execute(&self.pool)
                .await?;
        }
        if let Some(max_rules) = limits.max_detection_rules {
            sqlx::query("UPDATE system_settings SET tier_max_detection_rules = $1, updated_at = NOW() WHERE id = 'default'")
                .bind(max_rules as i32)
                .execute(&self.pool)
                .await?;
        }
        if let Some(max_members) = limits.max_team_members {
            sqlx::query("UPDATE system_settings SET tier_max_team_members = $1, updated_at = NOW() WHERE id = 'default'")
                .bind(max_members as i32)
                .execute(&self.pool)
                .await?;
        }
        if let Some(max_gb) = limits.max_daily_gb {
            sqlx::query("UPDATE system_settings SET tier_max_daily_gb = $1, updated_at = NOW() WHERE id = 'default'")
                .bind(rust_decimal::Decimal::from_f64_retain(max_gb))
                .execute(&self.pool)
                .await?;
        }
        if let Some(max_eps) = limits.max_eps {
            sqlx::query("UPDATE system_settings SET tier_max_eps = $1, updated_at = NOW() WHERE id = 'default'")
                .bind(max_eps as i32)
                .execute(&self.pool)
                .await?;
        }

        self.get_tier_limits().await
    }

    /// Get daily usage for a specific date
    pub async fn get_daily_usage(&self, date: chrono::NaiveDate) -> Result<DailyUsage, TierError> {
        let row = sqlx::query_as::<_, (i64, i64, i32)>(
            "SELECT bytes_ingested, events_ingested, peak_eps FROM daily_usage WHERE date = $1",
        )
        .bind(date)
        .fetch_optional(&self.pool)
        .await?;

        match row {
            Some((bytes, events, eps)) => Ok(DailyUsage {
                date,
                bytes_ingested: bytes as u64,
                events_ingested: events as u64,
                peak_eps: eps as u32,
            }),
            None => Ok(DailyUsage {
                date,
                bytes_ingested: 0,
                events_ingested: 0,
                peak_eps: 0,
            }),
        }
    }

    /// Record ingestion usage (upsert for today)
    pub async fn record_usage(&self, bytes: u64, events: u64, eps: u32) -> Result<(), TierError> {
        sqlx::query(
            r#"
            INSERT INTO daily_usage (date, bytes_ingested, events_ingested, peak_eps, updated_at)
            VALUES (CURRENT_DATE, $1, $2, $3, NOW())
            ON CONFLICT (date) DO UPDATE SET
                bytes_ingested = daily_usage.bytes_ingested + EXCLUDED.bytes_ingested,
                events_ingested = daily_usage.events_ingested + EXCLUDED.events_ingested,
                peak_eps = GREATEST(daily_usage.peak_eps, EXCLUDED.peak_eps),
                updated_at = NOW()
            "#,
        )
        .bind(bytes as i64)
        .bind(events as i64)
        .bind(eps as i32)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Get usage history for a date range
    pub async fn get_usage_range(
        &self,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
    ) -> Result<Vec<DailyUsage>, TierError> {
        let rows = sqlx::query_as::<_, (chrono::NaiveDate, i64, i64, i32)>(
            r#"
            SELECT date, bytes_ingested, events_ingested, peak_eps
            FROM daily_usage
            WHERE date >= $1 AND date <= $2
            ORDER BY date DESC
            "#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|(date, bytes, events, eps)| DailyUsage {
                date,
                bytes_ingested: bytes as u64,
                events_ingested: events as u64,
                peak_eps: eps as u32,
            })
            .collect())
    }

    /// Increment AI credit counter for the current month and check against limit.
    /// `cost` is the credit cost (use `ai_request_cost()` to determine from model).
    /// Returns the new total. If limit is exceeded, returns AiRateLimitExceeded error.
    pub async fn increment_ai_credits(
        &self,
        cost: i32,
        limit: Option<u32>,
    ) -> Result<i32, TierError> {
        let current_month = chrono::Utc::now().format("%Y-%m").to_string();

        let count: i32 = sqlx::query_scalar(
            r#"
            INSERT INTO ai_request_counts (month, request_count)
            VALUES ($1, $2)
            ON CONFLICT (month)
            DO UPDATE SET request_count = ai_request_counts.request_count + $2,
                          updated_at = NOW()
            RETURNING request_count
            "#,
        )
        .bind(&current_month)
        .bind(cost)
        .fetch_one(&self.pool)
        .await?;

        if let Some(max) = limit {
            if count > max as i32 {
                return Err(TierError::AiRateLimitExceeded(format!(
                    "AI credit limit reached ({}/month). Upgrade your plan for more.",
                    max
                )));
            }
        }

        Ok(count)
    }

    /// Get AI credits used for the current month
    pub async fn get_ai_credits_used(&self) -> Result<i32, TierError> {
        let current_month = chrono::Utc::now().format("%Y-%m").to_string();

        let count: Option<i32> =
            sqlx::query_scalar("SELECT request_count FROM ai_request_counts WHERE month = $1")
                .bind(&current_month)
                .fetch_optional(&self.pool)
                .await?;

        Ok(count.unwrap_or(0))
    }
}

/// Request to update specific tier limits
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct UpdateTierLimits {
    pub max_data_sources: Option<u32>,
    pub max_detection_rules: Option<u32>,
    pub max_team_members: Option<u32>,
    pub max_daily_gb: Option<f64>,
    pub max_eps: Option<u32>,
}

/// Daily usage stats
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DailyUsage {
    pub date: chrono::NaiveDate,
    pub bytes_ingested: u64,
    pub events_ingested: u64,
    pub peak_eps: u32,
}

/// Full tier status response (tier + limits + current usage)
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TierStatus {
    pub limits: TierLimits,
    pub usage: TierUsage,
}

/// Current usage counts for tier enforcement
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TierUsage {
    pub data_sources: u32,
    pub detection_rules: u32,
    pub team_members: u32,
    pub today: DailyUsage,
}

/// AI usage stats for the current billing period.
///
/// Usage is tracked in **credits**: lite/economy models cost 2 credits (0.2 requests),
/// standard/full models cost 10 credits (1.0 request). Limits are stored as credits.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AiUsage {
    /// AI credits used this month
    pub credits_used: i32,
    /// Monthly credit limit (None = unlimited)
    pub credits_limit: Option<u32>,
    /// AI model tier
    pub model_tier: AiModelTier,
}

/// Cost of an AI request using a lite/economy model (0.2 requests)
pub const AI_CREDIT_LITE: i32 = 2;
/// Cost of an AI request using a standard/full model (1.0 request)
pub const AI_CREDIT_FULL: i32 = 10;

/// Determine the credit cost for an AI request based on the model being used.
/// Economy/lite models cost 2 credits; everything else costs 10.
pub fn ai_request_cost(model_id: &str) -> i32 {
    let model_lower = model_id.to_lowercase();
    let economy_models = ["haiku", "flash-lite", "claude-haiku", "gemini-flash"];
    if economy_models.iter().any(|m| model_lower.contains(m)) {
        AI_CREDIT_LITE
    } else {
        AI_CREDIT_FULL
    }
}

/// Proactive warning when a resource is approaching its tier limit
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TierWarning {
    /// Resource approaching limit (e.g., "detection_rules", "data_sources")
    pub resource: String,
    /// Current count
    pub current: u32,
    /// Maximum allowed
    pub limit: u32,
    /// Percentage used (0-100)
    pub percent_used: u8,
    /// Human-readable message
    pub message: String,
}

/// Warning threshold: emit warnings at 80%+ usage
const WARNING_THRESHOLD_PERCENT: u8 = 80;

/// Generate proactive warnings for resources approaching tier limits
pub fn generate_warnings(limits: &TierLimits, usage: &TierUsage) -> Vec<TierWarning> {
    let mut warnings = Vec::new();

    let checks: &[(&str, u32, Option<u32>)] = &[
        (
            "detection_rules",
            usage.detection_rules,
            limits.max_detection_rules,
        ),
        ("data_sources", usage.data_sources, limits.max_data_sources),
        ("team_members", usage.team_members, limits.max_team_members),
    ];

    for (resource, current, limit) in checks {
        if let Some(max) = limit {
            if *max > 0 {
                let percent = ((*current as f64 / *max as f64) * 100.0).min(100.0) as u8;
                if percent >= WARNING_THRESHOLD_PERCENT {
                    warnings.push(TierWarning {
                        resource: resource.to_string(),
                        current: *current,
                        limit: *max,
                        percent_used: percent,
                        message: format!(
                            "You're using {}/{} {} ({:.0}% of your {} plan limit)",
                            current,
                            max,
                            resource.replace('_', " "),
                            percent,
                            limits.tier
                        ),
                    });
                }
            }
        }
    }

    // Check daily volume
    if let Some(max_gb) = limits.max_daily_gb {
        if max_gb > 0.0 {
            let used_gb = usage.today.bytes_ingested as f64 / 1_073_741_824.0;
            let percent = ((used_gb / max_gb) * 100.0).min(100.0) as u8;
            if percent >= WARNING_THRESHOLD_PERCENT {
                warnings.push(TierWarning {
                    resource: "daily_volume".to_string(),
                    current: (used_gb * 100.0) as u32, // store as centibytes for precision
                    limit: (max_gb * 100.0) as u32,
                    percent_used: percent,
                    message: format!(
                        "Daily ingestion at {:.1}/{:.1} GB ({:.0}% of your {} plan limit)",
                        used_gb, max_gb, percent, limits.tier
                    ),
                });
            }
        }
    }

    warnings
}

/// Check a count against an optional limit. Returns Ok if within limit or unlimited.
pub fn check_limit(
    resource: &str,
    current: u32,
    limit: Option<u32>,
    tier: OrganizationTier,
    upgrade_hint: &str,
) -> Result<(), TierError> {
    if let Some(max) = limit {
        if current >= max {
            return Err(TierError::LimitExceeded(format!(
                "{} limit reached: {}/{} (tier: {}). {}",
                resource, current, max, tier, upgrade_hint
            )));
        }
    }
    Ok(())
}

/// Check if API access is allowed on the current tier (any level above None)
pub fn check_api_access(limits: &TierLimits) -> Result<(), TierError> {
    if limits.api_access == ApiAccessLevel::None {
        return Err(TierError::ApiAccessRestricted(
            "API access is not available on your plan. Upgrade to Growth or higher.".into(),
        ));
    }
    Ok(())
}

/// Check if API write access is allowed on the current tier
pub fn check_api_write_access(limits: &TierLimits) -> Result<(), TierError> {
    match limits.api_access {
        ApiAccessLevel::None => Err(TierError::ApiAccessRestricted(
            "API access is not available on your plan. Upgrade to Growth or higher.".into(),
        )),
        ApiAccessLevel::Readonly => Err(TierError::ApiAccessRestricted(
            "Write API access is not available on your plan. Upgrade to Growth or higher.".into(),
        )),
        ApiAccessLevel::Full => Ok(()),
    }
}

/// Check if SSO is available on the current tier
pub fn check_sso_access(limits: &TierLimits) -> Result<(), TierError> {
    if !limits.sso_enabled {
        return Err(TierError::FeatureNotAvailable(
            "SSO/SAML is not available on your plan. Upgrade to Starter or higher.".into(),
        ));
    }
    Ok(())
}

/// Validate that a model is accessible on the given AI model tier
pub fn check_model_access(model: &str, model_tier: &AiModelTier) -> Result<(), TierError> {
    let economy_models = ["haiku", "flash-lite", "claude-haiku", "gemini-flash"];
    let standard_models = ["sonnet", "claude-sonnet", "gemini-pro", "gpt-4o-mini"];

    match model_tier {
        AiModelTier::Full => Ok(()),
        AiModelTier::Standard => {
            let model_lower = model.to_lowercase();
            if economy_models.iter().any(|m| model_lower.contains(m))
                || standard_models.iter().any(|m| model_lower.contains(m))
            {
                Ok(())
            } else {
                Err(TierError::AiModelNotAvailable(format!(
                    "Model '{}' requires the Growth plan or higher.",
                    model
                )))
            }
        }
        AiModelTier::Economy => {
            let model_lower = model.to_lowercase();
            if economy_models.iter().any(|m| model_lower.contains(m)) {
                Ok(())
            } else {
                Err(TierError::AiModelNotAvailable(format!(
                    "Model '{}' requires the Startup plan or higher.",
                    model
                )))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unrestricted_has_no_limits() {
        let limits = TierLimits::for_tier(OrganizationTier::Unrestricted);
        assert_eq!(limits.max_data_sources, None);
        assert_eq!(limits.max_detection_rules, None);
        assert_eq!(limits.max_team_members, None);
        assert_eq!(limits.max_daily_gb, None);
        assert_eq!(limits.max_eps, None);
        assert_eq!(limits.api_access, ApiAccessLevel::Full);
        assert!(limits.sso_enabled);
        assert!(limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, None);
        assert_eq!(limits.ai_model_tier, AiModelTier::Full);
        assert!(!limits.is_enforced());
    }

    #[test]
    fn test_hobby_limits() {
        let limits = TierLimits::for_tier(OrganizationTier::Hobby);
        assert_eq!(limits.max_data_sources, Some(10));
        assert_eq!(limits.max_detection_rules, Some(15));
        assert_eq!(limits.max_team_members, Some(3));
        assert_eq!(limits.max_daily_gb, Some(2.0));
        assert_eq!(limits.max_eps, Some(30));
        assert_eq!(limits.api_access, ApiAccessLevel::None);
        assert!(!limits.sso_enabled);
        assert!(!limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, Some(3_000));
        assert_eq!(limits.ai_model_tier, AiModelTier::Economy);
        assert!(limits.is_enforced());
    }

    #[test]
    fn test_startup_limits() {
        let limits = TierLimits::for_tier(OrganizationTier::Startup);
        assert_eq!(limits.max_data_sources, Some(20));
        assert_eq!(limits.max_detection_rules, Some(30));
        assert_eq!(limits.max_team_members, Some(8));
        assert_eq!(limits.max_daily_gb, Some(5.0));
        assert_eq!(limits.max_eps, Some(75));
        assert_eq!(limits.api_access, ApiAccessLevel::None);
        assert!(!limits.sso_enabled);
        assert!(!limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, Some(10_000));
        assert_eq!(limits.ai_model_tier, AiModelTier::Standard);
    }

    #[test]
    fn test_growth_limits() {
        let limits = TierLimits::for_tier(OrganizationTier::Growth);
        assert_eq!(limits.max_data_sources, Some(30));
        assert_eq!(limits.max_detection_rules, Some(50));
        assert_eq!(limits.max_team_members, Some(12));
        assert_eq!(limits.max_daily_gb, Some(10.0));
        assert_eq!(limits.max_eps, Some(155));
        assert_eq!(limits.api_access, ApiAccessLevel::Full);
        assert!(!limits.sso_enabled);
        assert!(!limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, Some(25_000));
        assert_eq!(limits.ai_model_tier, AiModelTier::Full);
    }

    #[test]
    fn test_team_limits() {
        let limits = TierLimits::for_tier(OrganizationTier::Team);
        assert_eq!(limits.max_team_members, Some(15));
        assert_eq!(limits.max_daily_gb, Some(25.0));
        assert_eq!(limits.max_eps, Some(385));
        assert_eq!(limits.api_access, ApiAccessLevel::Full);
        assert!(!limits.sso_enabled);
        assert!(limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, Some(50_000));
        assert_eq!(limits.ai_model_tier, AiModelTier::Full);
    }

    #[test]
    fn test_starter_limits() {
        let limits = TierLimits::for_tier(OrganizationTier::Starter);
        assert_eq!(limits.max_data_sources, None);
        assert_eq!(limits.max_detection_rules, None);
        assert_eq!(limits.max_team_members, None);
        assert_eq!(limits.max_daily_gb, Some(50.0));
        assert_eq!(limits.max_eps, Some(770));
        assert_eq!(limits.api_access, ApiAccessLevel::Full);
        assert!(limits.sso_enabled);
        assert!(limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, Some(150_000));
    }

    #[test]
    fn test_pro_limits() {
        let limits = TierLimits::for_tier(OrganizationTier::Pro);
        assert_eq!(limits.max_team_members, None);
        assert_eq!(limits.max_daily_gb, Some(100.0));
        assert_eq!(limits.max_eps, Some(1_550));
        assert!(limits.sso_enabled);
        assert!(limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, Some(400_000));
        assert_eq!(limits.ai_model_tier, AiModelTier::Full);
    }

    #[test]
    fn test_enterprise_unlimited() {
        let limits = TierLimits::for_tier(OrganizationTier::Enterprise);
        assert_eq!(limits.max_data_sources, None);
        assert_eq!(limits.max_team_members, None);
        assert!(limits.sso_enabled);
        assert!(limits.ha_enabled);
        assert_eq!(limits.ai_credits_per_month, None);
    }

    #[test]
    fn test_check_limit_within() {
        assert!(check_limit("rules", 10, Some(50), OrganizationTier::Hobby, "Upgrade").is_ok());
    }

    #[test]
    fn test_check_limit_exceeded() {
        assert!(check_limit("rules", 50, Some(50), OrganizationTier::Hobby, "Upgrade").is_err());
    }

    #[test]
    fn test_check_limit_unlimited() {
        assert!(check_limit("rules", 999999, None, OrganizationTier::Unrestricted, "").is_ok());
    }

    #[test]
    fn test_api_access() {
        let hobby = TierLimits::for_tier(OrganizationTier::Hobby);
        assert!(check_api_write_access(&hobby).is_err());
        assert!(check_api_access(&hobby).is_err());

        let growth = TierLimits::for_tier(OrganizationTier::Growth);
        assert!(check_api_write_access(&growth).is_ok());
        assert!(check_api_access(&growth).is_ok());

        let starter = TierLimits::for_tier(OrganizationTier::Starter);
        assert!(check_api_write_access(&starter).is_ok());
    }

    #[test]
    fn test_sso_access() {
        assert!(check_sso_access(&TierLimits::for_tier(OrganizationTier::Hobby)).is_err());
        assert!(check_sso_access(&TierLimits::for_tier(OrganizationTier::Growth)).is_err());
        assert!(check_sso_access(&TierLimits::for_tier(OrganizationTier::Starter)).is_ok());
        assert!(check_sso_access(&TierLimits::for_tier(OrganizationTier::Pro)).is_ok());
    }

    #[test]
    fn test_model_access() {
        // Economy tier: only economy models
        assert!(check_model_access("claude-haiku-3", &AiModelTier::Economy).is_ok());
        assert!(check_model_access("gemini-flash-2", &AiModelTier::Economy).is_ok());
        assert!(check_model_access("claude-sonnet-4", &AiModelTier::Economy).is_err());
        assert!(check_model_access("claude-opus-4", &AiModelTier::Economy).is_err());

        // Standard tier: economy + standard models
        assert!(check_model_access("claude-haiku-3", &AiModelTier::Standard).is_ok());
        assert!(check_model_access("claude-sonnet-4", &AiModelTier::Standard).is_ok());
        assert!(check_model_access("gpt-4o-mini", &AiModelTier::Standard).is_ok());
        assert!(check_model_access("claude-opus-4", &AiModelTier::Standard).is_err());

        // Full tier: everything
        assert!(check_model_access("claude-opus-4", &AiModelTier::Full).is_ok());
        assert!(check_model_access("claude-sonnet-4", &AiModelTier::Full).is_ok());
    }

    #[test]
    fn test_tier_parse() {
        assert_eq!(
            "hobby".parse::<OrganizationTier>().unwrap(),
            OrganizationTier::Hobby
        );
        assert_eq!(
            "growth".parse::<OrganizationTier>().unwrap(),
            OrganizationTier::Growth
        );
        assert_eq!(
            "UNRESTRICTED".parse::<OrganizationTier>().unwrap(),
            OrganizationTier::Unrestricted
        );
        assert!("invalid".parse::<OrganizationTier>().is_err());
    }

    #[test]
    fn test_ai_model_tier_parse() {
        assert_eq!(
            "economy".parse::<AiModelTier>().unwrap(),
            AiModelTier::Economy
        );
        assert_eq!(
            "standard".parse::<AiModelTier>().unwrap(),
            AiModelTier::Standard
        );
        assert_eq!("full".parse::<AiModelTier>().unwrap(), AiModelTier::Full);
        assert!("invalid".parse::<AiModelTier>().is_err());
    }
}
