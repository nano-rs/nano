// SPDX-License-Identifier: AGPL-3.0-or-later

//! v2 offering entitlements and legacy tier compatibility.
//!
//! v2 has three independent axes: edition (`open` or `licensed`), operator
//! (`self-run` or `hosted`), and GB/day capacity. Capacity never selects
//! features. The retired plan names remain accepted at configuration and
//! license boundaries, but normalize to the licensed offering with the full
//! feature set.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;

/// Organization tier levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum OrganizationTier {
    Open,
    Licensed,
    /// Compatibility-only aliases accepted from pre-v2 rows, env and licenses.
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
            Self::Open => write!(f, "open"),
            Self::Licensed => write!(f, "licensed"),
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
            "open" | "open_source" | "opensource" => Ok(Self::Open),
            "licensed" => Ok(Self::Licensed),
            "unrestricted" => Ok(Self::Unrestricted),
            "hobby" => Ok(Self::Hobby),
            "startup" => Ok(Self::Startup),
            "growth" => Ok(Self::Growth),
            "team" => Ok(Self::Team),
            "starter" => Ok(Self::Starter),
            "business" => Ok(Self::Starter),
            "pro" => Ok(Self::Pro),
            "enterprise" => Ok(Self::Enterprise),
            _ => Err(TierError::InvalidTier(s.to_string())),
        }
    }
}

/// Product edition. Open source is enforced by the build split; licensed
/// deployments receive every feature shipped in the enterprise build.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum EntitlementEdition {
    Open,
    Licensed,
}

impl std::fmt::Display for EntitlementEdition {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Licensed => "licensed",
        })
    }
}

impl std::str::FromStr for EntitlementEdition {
    type Err = TierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "open" | "open_source" | "opensource" => Ok(Self::Open),
            "licensed" | "enterprise" => Ok(Self::Licensed),
            _ => Err(TierError::Validation(format!(
                "Invalid entitlement edition: {s}"
            ))),
        }
    }
}

/// Who operates the deployment. This axis controls nano-provided AI credits;
/// it does not change product features.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub enum EntitlementOperator {
    #[serde(rename = "self-run")]
    #[schema(rename = "self-run")]
    SelfRun,
    #[serde(rename = "hosted")]
    Hosted,
}

impl std::fmt::Display for EntitlementOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SelfRun => "self-run",
            Self::Hosted => "hosted",
        })
    }
}

impl std::str::FromStr for EntitlementOperator {
    type Err = TierError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "self-run" | "self_run" | "selfhosted" | "self-hosted" | "byoc" | "sovereign" => {
                Ok(Self::SelfRun)
            }
            "hosted" | "managed" => Ok(Self::Hosted),
            _ => Err(TierError::Validation(format!(
                "Invalid entitlement operator: {s}"
            ))),
        }
    }
}

/// Canonical v2 entitlement identity.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Entitlement {
    pub edition: EntitlementEdition,
    pub operator: EntitlementOperator,
    /// Contracted ingest capacity in decimal GB/day. `None` means the contract
    /// does not state a numeric capacity (for example open source or custom).
    pub capacity_gb_per_day: Option<f64>,
}

impl Entitlement {
    pub fn from_legacy_tier(tier: OrganizationTier, operator: EntitlementOperator) -> Self {
        let edition = if tier == OrganizationTier::Open {
            EntitlementEdition::Open
        } else {
            EntitlementEdition::Licensed
        };
        let capacity_gb_per_day = match tier {
            OrganizationTier::Hobby => Some(2.0),
            OrganizationTier::Startup => Some(5.0),
            OrganizationTier::Growth => Some(10.0),
            OrganizationTier::Team => Some(25.0),
            OrganizationTier::Starter => Some(50.0),
            OrganizationTier::Pro => Some(100.0),
            OrganizationTier::Open
            | OrganizationTier::Licensed
            | OrganizationTier::Unrestricted
            | OrganizationTier::Enterprise => None,
        };
        Self {
            edition,
            operator,
            capacity_gb_per_day,
        }
    }

    pub fn offering_name(&self) -> &'static str {
        match (self.edition, self.operator) {
            (EntitlementEdition::Open, _) => "Open source",
            (EntitlementEdition::Licensed, EntitlementOperator::SelfRun) => "nano Self-run",
            (EntitlementEdition::Licensed, EntitlementOperator::Hosted) => "nano Hosted",
        }
    }

    /// Normalize the string carried by online and legacy air-gap licenses.
    pub fn from_license_tier_claim(
        claim: &str,
        operator: EntitlementOperator,
    ) -> Result<Self, TierError> {
        Ok(Self::from_legacy_tier(claim.parse()?, operator))
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

/// Compatibility response carrying the canonical v2 entitlement plus the
/// retired limit fields older clients understand.
///
/// Feature-count fields are always `None` in v2. `max_daily_gb` mirrors the
/// contracted capacity for old clients, but is not a feature gate.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct TierLimits {
    pub entitlement: Entitlement,
    /// Canonical compatibility value (`open` or `licensed`). Retired tier names
    /// are accepted as inputs but are never emitted here.
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
    /// Whether SSO/SAML is present in this edition/build.
    pub sso_enabled: bool,
    /// Whether HA (high availability) is enabled
    pub ha_enabled: bool,
    /// Hosted monthly AI allowance. `None` means customer-provided, uncapped AI.
    /// Hosted deployments with no provisioned allowance report zero and refuse
    /// AI calls rather than silently running unmetered.
    /// Lite models cost 2 credits, full models cost 10 credits.
    pub ai_credits_per_month: Option<u32>,
    /// Compatibility field. All configured models are available in v2.
    pub ai_model_tier: AiModelTier,
    /// Maximum number of Observability metric monitors (None = unlimited). (NAN-1544)
    pub max_metric_monitors: Option<u32>,
    /// Maximum number of Observability synthetic checks (None = unlimited). (NAN-1544)
    pub max_synthetic_checks: Option<u32>,
    /// Maximum number of Observability SLOs (None = unlimited). (NAN-1544)
    pub max_slos: Option<u32>,
}

/// Env var carrying a contractual monthly AI credit ceiling (NAN-2347).
pub const AI_CREDITS_CEILING_ENV: &str = "NANO_AI_CREDITS_PER_MONTH";

/// Parse a provisioned ceiling as a positive integer number of credits.
/// Missing, zero, and malformed hosted values resolve to the constructor's
/// fail-closed zero allowance. Parsed through `i32` because `increment_ai_credits`
/// compares and stores the counter as PostgreSQL INTEGER — a value past
/// `i32::MAX` would wrap negative there and reject the very first request.
fn parse_ai_credits_ceiling(raw: &str) -> Option<u32> {
    raw.trim()
        .parse::<i32>()
        .ok()
        .filter(|v| *v > 0)
        .map(|v| v as u32)
}

/// Contractual Hosted AI allowance. Self-run and open constructors ignore it.
///
/// **Test pollution warning**: reads process-wide env state — see the note on
/// `allow_local()` in `tiering/validation.rs`. Tests cover the pure pieces
/// (`parse_ai_credits_ceiling`, `for_tier_with_ceiling`) instead of toggling
/// the var.
fn env_ai_credits_ceiling() -> Option<u32> {
    std::env::var(AI_CREDITS_CEILING_ENV)
        .ok()
        .and_then(|v| parse_ai_credits_ceiling(&v))
}

/// Provisioning override for the contracted GB/day capacity.
pub const CAPACITY_GB_PER_DAY_ENV: &str = "NANO_CAPACITY_GB_PER_DAY";

pub fn parse_capacity_gb_per_day(raw: &str) -> Option<f64> {
    raw.trim()
        .parse::<f64>()
        .ok()
        .filter(|value| value.is_finite() && *value > 0.0)
}

impl TierLimits {
    /// Compatibility constructor. Every retired paid tier normalizes to the
    /// licensed, self-run offering; only its historical GB/day value survives
    /// as capacity metadata.
    pub fn for_tier(tier: OrganizationTier) -> Self {
        Self::for_tier_with_ceiling(tier, env_ai_credits_ceiling())
    }

    /// Compatibility constructor without process-wide env state.
    pub fn for_tier_unoverridden(tier: OrganizationTier) -> Self {
        Self::for_tier_with_ceiling(tier, None)
    }

    fn for_tier_with_ceiling(tier: OrganizationTier, ceiling: Option<u32>) -> Self {
        let entitlement = Entitlement::from_legacy_tier(tier, EntitlementOperator::SelfRun);
        Self::for_entitlement_with_ceiling(entitlement, ceiling)
    }

    pub fn for_entitlement(entitlement: Entitlement) -> Self {
        Self::for_entitlement_with_ceiling(entitlement, env_ai_credits_ceiling())
    }

    /// NAN-5055: a check-in grant replaces the provisioned env ceiling for a
    /// hosted licensed deployment. Self-run/open stay uncapped (`None`).
    pub fn for_entitlement_with_granted_ai_credits(
        entitlement: Entitlement,
        granted: Option<u32>,
    ) -> Self {
        Self::for_entitlement_with_ceiling(entitlement, granted.or_else(env_ai_credits_ceiling))
    }

    pub fn for_entitlement_unoverridden(entitlement: Entitlement) -> Self {
        Self::for_entitlement_with_ceiling(entitlement, None)
    }

    fn for_entitlement_with_ceiling(entitlement: Entitlement, ceiling: Option<u32>) -> Self {
        let tier = match entitlement.edition {
            EntitlementEdition::Open => OrganizationTier::Open,
            EntitlementEdition::Licensed => OrganizationTier::Licensed,
        };
        let licensed = entitlement.edition == EntitlementEdition::Licensed;
        let ai_credits_per_month = match (licensed, entitlement.operator) {
            (true, EntitlementOperator::Hosted) => Some(ceiling.unwrap_or(0)),
            _ => None,
        };
        Self {
            entitlement,
            tier,
            max_data_sources: None,
            max_detection_rules: None,
            max_team_members: None,
            max_daily_gb: entitlement.capacity_gb_per_day,
            max_eps: None,
            api_access: ApiAccessLevel::Full,
            sso_enabled: licensed,
            ha_enabled: true,
            ai_credits_per_month,
            ai_model_tier: AiModelTier::Full,
            max_metric_monitors: None,
            max_synthetic_checks: None,
            max_slos: None,
        }
    }

    /// Whether a legacy feature-count cap remains. V2 constructors always
    /// return false; callers retain this for rolling-upgrade compatibility.
    pub fn is_enforced(&self) -> bool {
        self.max_data_sources.is_some()
            || self.max_detection_rules.is_some()
            || self.max_team_members.is_some()
            || self.max_metric_monitors.is_some()
            || self.max_synthetic_checks.is_some()
            || self.max_slos.is_some()
            || self.api_access != ApiAccessLevel::Full
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

    /// Resolve the canonical v2 entitlement. Retired `tier_max_*` columns are
    /// deliberately ignored: they remain only so an N-1 binary can roll beside
    /// this release without a missing-column or write-contract failure.
    pub async fn get_tier_limits(&self) -> Result<TierLimits, TierError> {
        let row = sqlx::query_as::<_, (String, String, Option<rust_decimal::Decimal>, Option<i32>)>(
            r#"
            SELECT
                entitlement_edition,
                entitlement_operator,
                entitlement_capacity_gb_per_day,
                entitlement_ai_credits_per_month
            FROM system_settings
            WHERE id = 'default'
            "#,
        )
        .fetch_optional(&self.pool)
        .await?;
        let mut granted_ai_credits = None;
        let entitlement = match row {
            Some((edition, operator, capacity, granted)) => {
                granted_ai_credits = granted.and_then(|value| u32::try_from(value).ok()).filter(|value| *value > 0);
                use rust_decimal::prelude::ToPrimitive;
                Entitlement {
                    edition: edition.parse()?,
                    operator: operator.parse()?,
                    capacity_gb_per_day: capacity.and_then(|value| value.to_f64()),
                }
            }
            None => Entitlement {
                edition: EntitlementEdition::Open,
                operator: EntitlementOperator::SelfRun,
                capacity_gb_per_day: None,
            },
        };
        Ok(TierLimits::for_entitlement_with_granted_ai_credits(
            entitlement,
            granted_ai_credits,
        ))
    }

    /// NAN-5055: record (or clear) the AI allowance granted by an admitted,
    /// authenticated online license check-in. The online checker is the only
    /// writer; boot reconciliation clears it whenever online licensing is not
    /// the admission authority, so a grant cannot outlive its source.
    pub async fn set_granted_ai_credits(&self, credits: Option<u32>) -> Result<(), TierError> {
        let persisted = match credits {
            Some(value) => Some(
                i32::try_from(value)
                    .ok()
                    .filter(|value| *value > 0)
                    .ok_or_else(|| {
                        TierError::Validation(
                            "granted AI credits must be a positive PostgreSQL INTEGER".into(),
                        )
                    })?,
            ),
            None => None,
        };
        sqlx::query(
            r#"
            UPDATE system_settings SET
                entitlement_ai_credits_per_month = $1,
                updated_at = NOW()
            WHERE id = 'default'
              AND entitlement_ai_credits_per_month IS DISTINCT FROM $1
            "#,
        )
        .bind(persisted)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Persist a canonical entitlement while keeping the old tier columns safe
    /// for rolling N-1 readers. `unrestricted` is the only legacy value that
    /// gives an older binary the v2 full-feature behavior.
    pub async fn set_entitlement(&self, entitlement: Entitlement) -> Result<TierLimits, TierError> {
        if entitlement
            .capacity_gb_per_day
            .is_some_and(|value| !value.is_finite() || value <= 0.0)
        {
            return Err(TierError::Validation(
                "capacity_gb_per_day must be a positive finite number".into(),
            ));
        }
        let persisted_capacity = match entitlement.capacity_gb_per_day {
            Some(value) => Some(rust_decimal::Decimal::from_f64_retain(value).ok_or_else(
                || {
                    TierError::Validation(
                        "capacity_gb_per_day cannot be represented by PostgreSQL NUMERIC".into(),
                    )
                },
            )?),
            None => None,
        };
        sqlx::query(
            r#"
            UPDATE system_settings SET
                entitlement_edition = $1,
                entitlement_operator = $2,
                entitlement_capacity_gb_per_day = $3,
                tier = 'unrestricted',
                tier_max_data_sources = NULL,
                tier_max_detection_rules = NULL,
                tier_max_team_members = NULL,
                tier_max_daily_gb = NULL,
                tier_max_eps = NULL,
                tier_api_access = 'full',
                tier_sso_enabled = TRUE,
                tier_limits_override = NULL,
                updated_at = NOW()
            WHERE id = 'default'
            "#,
        )
        .bind(entitlement.edition.to_string())
        .bind(entitlement.operator.to_string())
        .bind(persisted_capacity)
        .execute(&self.pool)
        .await?;
        // Re-read so callers (admin responses, boot log) see the same
        // allowance the meter enforces, including a check-in grant (NAN-5055).
        self.get_tier_limits().await
    }

    /// Retired setter retained for API/env/license compatibility.
    pub async fn set_tier(&self, tier: OrganizationTier) -> Result<TierLimits, TierError> {
        let current = self.get_tier_limits().await?;
        let mut entitlement = Entitlement::from_legacy_tier(tier, current.entitlement.operator);
        if entitlement.capacity_gb_per_day.is_none() {
            entitlement.capacity_gb_per_day = current.entitlement.capacity_gb_per_day;
        }
        self.set_entitlement(entitlement).await
    }

    /// Map an old or new license tier claim onto v2. Unknown claim values are
    /// rejected; all accepted pre-v2 paid names gain the full licensed feature
    /// set and retain only their historical capacity metadata.
    pub async fn admit_license_tier(
        &self,
        claim: &str,
        operator: EntitlementOperator,
    ) -> Result<TierLimits, TierError> {
        let current = self.get_tier_limits().await?;
        let mut entitlement = Entitlement::from_license_tier_claim(claim, operator)?;
        if entitlement.capacity_gb_per_day.is_none() {
            entitlement.capacity_gb_per_day = current.entitlement.capacity_gb_per_day;
        }
        self.set_entitlement(entitlement).await
    }

    /// Compatibility endpoint. Feature-count overrides are retired; only the
    /// old `max_daily_gb` input is interpreted, as v2 capacity metadata.
    pub async fn update_limits(&self, limits: UpdateTierLimits) -> Result<TierLimits, TierError> {
        let mut entitlement = self.get_tier_limits().await?.entitlement;
        if let Some(capacity) = limits.max_daily_gb {
            entitlement.capacity_gb_per_day = Some(capacity);
        }
        self.set_entitlement(entitlement).await
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

    /// NAN-5170: record the metered total for one UTC day. Idempotent and
    /// monotonic: a re-meter of the same day only ever raises the stored
    /// value, so the rollup's TTL eroding an old day can never shrink it.
    pub async fn upsert_metered_usage(
        &self,
        date: chrono::NaiveDate,
        bytes: u64,
        events: u64,
    ) -> Result<(), TierError> {
        sqlx::query(
            r#"
            INSERT INTO daily_usage (date, bytes_ingested, events_ingested, peak_eps, updated_at)
            VALUES ($1, $2, $3, 0, NOW())
            ON CONFLICT (date) DO UPDATE SET
                bytes_ingested = GREATEST(daily_usage.bytes_ingested, EXCLUDED.bytes_ingested),
                events_ingested = GREATEST(daily_usage.events_ingested, EXCLUDED.events_ingested),
                updated_at = NOW()
            "#,
        )
        .bind(date)
        .bind(i64::try_from(bytes).unwrap_or(i64::MAX))
        .bind(i64::try_from(events).unwrap_or(i64::MAX))
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// NAN-5170: the earliest day ever metered, if any. Only fully metered
    /// days are written, so every later day is fully metered too.
    pub async fn earliest_metered_day(&self) -> Result<Option<chrono::NaiveDate>, TierError> {
        Ok(sqlx::query_scalar::<_, Option<chrono::NaiveDate>>("SELECT min(date) FROM daily_usage")
            .fetch_one(&self.pool)
            .await?)
    }

    /// NAN-5170: metered days in `[from, to]` (ascending) with the time each
    /// was last metered, so a reporter can tell a finished day from one that
    /// was last measured before it ended.
    pub async fn get_metered_days(
        &self,
        from: chrono::NaiveDate,
        to: chrono::NaiveDate,
    ) -> Result<Vec<MeteredDay>, TierError> {
        let rows = sqlx::query_as::<_, (chrono::NaiveDate, i64, chrono::DateTime<chrono::Utc>)>(
            "SELECT date, bytes_ingested, updated_at FROM daily_usage
             WHERE date >= $1 AND date <= $2 ORDER BY date ASC",
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(date, bytes, metered_at)| MeteredDay {
                date,
                bytes_ingested: u64::try_from(bytes).unwrap_or(0),
                metered_at,
            })
            .collect())
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
        // NAN-5136: a zero-cost call (a self-hosted model) is not metered, so
        // it is not gated by the monthly allowance either. Without this, a
        // tenant already at its ceiling could not use its own model server.
        if cost <= 0 {
            return self.get_ai_credits_used().await;
        }

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

        enforce_ai_allowance(count, limit)?;

        Ok(count)
    }

    /// Resolve the current tier limit and charge `cost` credits in one call
    /// (NAN-2348). The convenience wrapper for charge sites that don't
    /// already hold `TierLimits` — background agents and the `| ai` pipe.
    ///
    /// `Err(AiRateLimitExceeded)` means the monthly ceiling is reached and
    /// the caller must skip its model call; any other error means the limit
    /// could not be resolved or recorded, and callers should fail closed
    /// (skip) rather than run unmetered.
    pub async fn charge_ai_credits(&self, cost: i32) -> Result<(), TierError> {
        let limits = self.get_tier_limits().await?;
        self.increment_ai_credits(cost, limits.ai_credits_per_month)
            .await?;
        Ok(())
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

    /// Per-agent AI usage rollup over `[from, to)` from the `ai_usage_events`
    /// ledger (NAN-1519), ordered by credit-equivalent descending — the "what
    /// consumed the budget" breakdown.
    pub async fn get_ai_usage_by_agent(
        &self,
        from: chrono::DateTime<chrono::Utc>,
        to: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<AgentUsage>, TierError> {
        // NB: SUM over a bigint column returns `numeric` in Postgres, which does
        // NOT decode into Rust i64 — cast each SUM back to ::bigint. (credits is an
        // integer column so SUM→bigint already, but cast for uniformity.)
        let rows = sqlx::query_as::<_, (String, i64, i64, i64, i64, i64, i64)>(
            r#"
            SELECT agent,
                   COUNT(*)                                        AS calls,
                   COALESCE(SUM(prompt_tokens), 0)::bigint         AS prompt_tokens,
                   COALESCE(SUM(completion_tokens), 0)::bigint     AS completion_tokens,
                   COALESCE(SUM(cached_tokens), 0)::bigint         AS cached_tokens,
                   COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
                   COALESCE(SUM(credits), 0)::bigint               AS credits
            FROM ai_usage_events
            WHERE occurred_at >= $1 AND occurred_at < $2
            GROUP BY agent
            ORDER BY credits DESC, calls DESC
            "#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(agent, calls, prompt, completion, cached, cache_creation, credits)| AgentUsage {
                    agent,
                    calls,
                    prompt_tokens: prompt,
                    completion_tokens: completion,
                    cached_tokens: cached,
                    cache_creation_tokens: cache_creation,
                    credits,
                },
            )
            .collect())
    }

    /// Daily AI usage series over `[from, to)` (NAN-1519), one row per UTC day
    /// that had activity, ascending — the consumption-over-time trend.
    pub async fn get_ai_usage_daily(
        &self,
        from: chrono::DateTime<chrono::Utc>,
        to: chrono::DateTime<chrono::Utc>,
    ) -> Result<Vec<DailyAiUsage>, TierError> {
        let rows = sqlx::query_as::<_, (chrono::NaiveDate, i64, i64, i64, i64, i64)>(
            r#"
            -- SUM(bigint)→numeric in Postgres; cast back to ::bigint for i64 decode.
            SELECT (occurred_at AT TIME ZONE 'UTC')::date AS day,
                   COUNT(*)                                    AS calls,
                   COALESCE(SUM(prompt_tokens), 0)::bigint     AS prompt_tokens,
                   COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
                   COALESCE(SUM(cached_tokens), 0)::bigint     AS cached_tokens,
                   COALESCE(SUM(credits), 0)::bigint           AS credits
            FROM ai_usage_events
            WHERE occurred_at >= $1 AND occurred_at < $2
            GROUP BY day
            ORDER BY day ASC
            "#,
        )
        .bind(from)
        .bind(to)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(date, calls, prompt, completion, cached, credits)| DailyAiUsage {
                    date,
                    calls,
                    prompt_tokens: prompt,
                    completion_tokens: completion,
                    cached_tokens: cached,
                    credits,
                },
            )
            .collect())
    }

    /// Most recent AI calls (NAN-1519), newest first — the per-call event log.
    pub async fn get_recent_ai_events(&self, limit: i64) -> Result<Vec<AiUsageEvent>, TierError> {
        let limit = limit.clamp(1, 500);
        let rows = sqlx::query_as::<
            _,
            (
                chrono::DateTime<chrono::Utc>,
                String,
                String,
                String,
                i64,
                i64,
                i64,
                i64,
                i32,
            ),
        >(
            r#"
            SELECT occurred_at, agent, model_id, provider,
                   prompt_tokens, completion_tokens, cached_tokens, cache_creation_tokens, credits
            FROM ai_usage_events
            ORDER BY occurred_at DESC
            LIMIT $1
            "#,
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(
                |(
                    occurred_at,
                    agent,
                    model_id,
                    provider,
                    prompt,
                    completion,
                    cached,
                    cache_creation,
                    credits,
                )| AiUsageEvent {
                    occurred_at,
                    agent,
                    model_id,
                    provider,
                    prompt_tokens: prompt,
                    completion_tokens: completion,
                    cached_tokens: cached,
                    cache_creation_tokens: cache_creation,
                    credits,
                },
            )
            .collect())
    }
}

fn enforce_ai_allowance(count: i32, limit: Option<u32>) -> Result<(), TierError> {
    if let Some(max) = limit {
        if count > max as i32 {
            return Err(TierError::AiRateLimitExceeded(format!(
                "Hosted AI allowance reached ({max}/month)."
            )));
        }
    }
    Ok(())
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

/// One metered UTC day (NAN-5170): total bytes and when it was last metered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeteredDay {
    pub date: chrono::NaiveDate,
    pub bytes_ingested: u64,
    pub metered_at: chrono::DateTime<chrono::Utc>,
}

/// Hours a finished UTC day is held back before its total counts as final
/// (NAN-5170): in-flight batches buffered before midnight have landed by then.
pub const FINAL_HOLD_HOURS: i64 = 3;

impl MeteredDay {
    /// True once the day was metered at least [`FINAL_HOLD_HOURS`] after it
    /// ended (UTC), i.e. its total is final rather than a running snapshot.
    pub fn is_final(&self) -> bool {
        self.date
            .succ_opt()
            .and_then(|next| next.and_hms_opt(0, 0, 0))
            .is_some_and(|end| {
                self.metered_at.naive_utc() >= end + chrono::Duration::hours(FINAL_HOLD_HOURS)
            })
    }
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

/// Per-agent AI usage rollup over a time range (NAN-1519).
///
/// Token counts are real provider-reported totals; `credits` is the summed
/// per-call credit-equivalent (relative attribution, not a billing figure —
/// the billed total lives in `ai_request_counts`, see [`AiUsage`]).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AgentUsage {
    /// Logical agent label (e.g. `detection`, `shadow_hunting`, `unknown`).
    pub agent: String,
    /// Number of LLM calls attributed to this agent.
    pub calls: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cached_tokens: i64,
    pub cache_creation_tokens: i64,
    /// Summed per-call credit-equivalent.
    pub credits: i64,
}

/// One day's AI usage rollup (NAN-1519), keyed by UTC date.
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct DailyAiUsage {
    pub date: chrono::NaiveDate,
    pub calls: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cached_tokens: i64,
    pub credits: i64,
}

/// One recorded AI call from the `ai_usage_events` ledger (NAN-1519).
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AiUsageEvent {
    pub occurred_at: chrono::DateTime<chrono::Utc>,
    pub agent: String,
    pub model_id: String,
    pub provider: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cached_tokens: i64,
    pub cache_creation_tokens: i64,
    pub credits: i32,
}

/// Cost of an AI request using a lite/economy model (0.2 requests)
pub const AI_CREDIT_LITE: i32 = 2;
/// Cost of an AI request using a standard/full model (1.0 request)
pub const AI_CREDIT_FULL: i32 = 10;
/// Cost of an AI request answered by the operator's own self-hosted model
/// (NAN-5136): nothing. Self-run AI is bring-your-own.
pub const AI_CREDIT_NONE: i32 = 0;

/// The full-request charge for call sites that bill a flat
/// [`AI_CREDIT_FULL`] (closure summary, shadow investigation), except when the
/// model is self-hosted, which costs nothing (NAN-5136).
pub fn full_request_cost(model_id: &str) -> i32 {
    if crate::ai_provider::is_self_hosted_model(model_id) {
        AI_CREDIT_NONE
    } else {
        AI_CREDIT_FULL
    }
}

/// Name-heuristic credit cost for an AI request — the **fallback** used only
/// when the model carries no catalog tier (see [`resolve_ai_request_cost`],
/// which is the catalog-driven primary path). Economy/lite models cost 2
/// credits; everything else costs 10.
///
/// Kept deliberately small: it only needs to cover models absent from the
/// catalog (e.g. custom in-app models). The authoritative classification lives
/// in the model catalog (`available_models.cost_tier`, synced from
/// `models.yaml`'s `tier:`), not in this list.
pub fn ai_request_cost(model_id: &str) -> i32 {
    // NAN-5136: the operator's own model server is BYO AI — nano provides no
    // inference, so it consumes no nano AI credits.
    if crate::ai_provider::is_self_hosted_model(model_id) {
        return AI_CREDIT_NONE;
    }
    let model_lower = model_id.to_lowercase();
    // "glm" (Zhipu GLM family) is very cheap — bill it as lite. Insurance for
    // custom GLM entries that aren't in the upstream catalog with a tier.
    let economy_models = ["haiku", "flash-lite", "claude-haiku", "gemini-flash", "glm"];
    if economy_models.iter().any(|m| model_lower.contains(m)) {
        AI_CREDIT_LITE
    } else {
        AI_CREDIT_FULL
    }
}

/// Map a catalog `cost_tier` to credits (NAN-1521): `economy` →
/// [`AI_CREDIT_LITE`], any other tier → [`AI_CREDIT_FULL`]. When the tier is
/// absent/NULL (uncatalogued or custom model) falls back to the
/// [`ai_request_cost`] name heuristic. Shared by [`resolve_ai_request_cost`]
/// (single lookup) and the usage recorder's batched lookup so both classify
/// identically.
pub fn credits_for_cost_tier(cost_tier: Option<&str>, model_id: &str) -> i32 {
    if crate::ai_provider::is_self_hosted_model(model_id) {
        return AI_CREDIT_NONE;
    }
    match cost_tier {
        Some(t) if t.eq_ignore_ascii_case("economy") => AI_CREDIT_LITE,
        Some(_) => AI_CREDIT_FULL,
        None => ai_request_cost(model_id),
    }
}

/// Resolve the credit cost for a model — **catalog-first** (NAN-1521).
///
/// Reads `available_models.cost_tier` (the upstream `models.yaml` `tier:` synced
/// by `model_catalog_sync`) and maps it via [`credits_for_cost_tier`]. Falls
/// back to the name heuristic when the model is absent/has no tier or on any DB
/// error — usage billing must never fail the AI call.
#[cfg(feature = "enterprise")]
pub async fn resolve_ai_request_cost(pool: &PgPool, model_id: &str) -> i32 {
    let row: Result<Option<Option<String>>, sqlx::Error> =
        sqlx::query_scalar("SELECT cost_tier FROM available_models WHERE model_id = $1")
            .bind(model_id)
            .fetch_optional(pool)
            .await;

    // No row, NULL cost_tier, or DB error → None → heuristic fallback.
    let cost_tier = match row {
        Ok(Some(Some(tier))) => Some(tier),
        _ => None,
    };
    credits_for_cost_tier(cost_tier.as_deref(), model_id)
}

/// Open core has no model catalog, so model billing always uses the stable
/// name-based fallback.
#[cfg(not(feature = "enterprise"))]
pub async fn resolve_ai_request_cost(_pool: &PgPool, model_id: &str) -> i32 {
    ai_request_cost(model_id)
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
    /// Percentage used. Not capped: a deployment ingesting 38x its
    /// contracted capacity reports 3846 (NAN-5170).
    pub percent_used: u32,
    /// Human-readable message
    pub message: String,
}

/// Warning threshold: emit warnings at 80%+ usage
const WARNING_THRESHOLD_PERCENT: u32 = 80;

/// True (uncapped) whole percentage of `used` against `limit`, floored.
/// NAN-5170: the old `.min(100.0) as u8` hid real overage at "100%".
pub fn true_percent(used: f64, limit: f64) -> u32 {
    if !(limit > 0.0) || !used.is_finite() || used <= 0.0 {
        return 0;
    }
    let percent = (used / limit) * 100.0;
    if percent >= u32::MAX as f64 {
        u32::MAX
    } else {
        percent.floor() as u32
    }
}

/// `3846` -> `"3,846"`.
pub fn group_thousands(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (index, ch) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index) % 3 == 0 {
            out.push(',');
        }
        out.push(ch);
    }
    out
}

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
                let percent = true_percent(*current as f64, *max as f64);
                if percent >= WARNING_THRESHOLD_PERCENT {
                    warnings.push(TierWarning {
                        resource: resource.to_string(),
                        current: *current,
                        limit: *max,
                        percent_used: percent,
                        message: format!(
                            "You're using {}/{} {} ({}% of the configured deployment limit)",
                            current,
                            max,
                            resource.replace('_', " "),
                            group_thousands(percent.into())
                        ),
                    });
                }
            }
        }
    }

    // Check daily volume
    if let Some(max_gb) = limits.max_daily_gb {
        if max_gb > 0.0 {
            let used_gb = usage.today.bytes_ingested as f64 / 1_000_000_000.0;
            let percent = true_percent(used_gb, max_gb);
            if percent >= WARNING_THRESHOLD_PERCENT {
                warnings.push(TierWarning {
                    resource: "daily_volume".to_string(),
                    // Hundredths of a GB for precision (saturating).
                    current: (used_gb * 100.0).min(u32::MAX as f64) as u32,
                    limit: (max_gb * 100.0).min(u32::MAX as f64) as u32,
                    percent_used: percent,
                    message: format!(
                        "Today's ingest is {:.1} GB against {:.1} GB/day ({}% of contracted capacity). Ingest is never blocked.",
                        used_gb,
                        max_gb,
                        group_thousands(percent.into())
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

/// Compatibility guard for a rolling-upgrade row carrying an old API limit.
pub fn check_api_access(limits: &TierLimits) -> Result<(), TierError> {
    if limits.api_access == ApiAccessLevel::None {
        return Err(TierError::ApiAccessRestricted(
            "API access is disabled for this deployment.".into(),
        ));
    }
    Ok(())
}

/// Check if API write access is allowed on the current tier
pub fn check_api_write_access(limits: &TierLimits) -> Result<(), TierError> {
    match limits.api_access {
        ApiAccessLevel::None => Err(TierError::ApiAccessRestricted(
            "API access is disabled for this deployment.".into(),
        )),
        ApiAccessLevel::Readonly => Err(TierError::ApiAccessRestricted(
            "Write API access is disabled for this deployment.".into(),
        )),
        ApiAccessLevel::Full => Ok(()),
    }
}

/// Check whether SSO is shipped by the current edition/build.
pub fn check_sso_access(limits: &TierLimits) -> Result<(), TierError> {
    if !limits.sso_enabled {
        return Err(TierError::FeatureNotAvailable(
            "SSO/SAML is not included in this build.".into(),
        ));
    }
    Ok(())
}

/// Compatibility API: v2 never selects models by plan. Provider configuration
/// decides which models exist, while hosted allowance enforcement is separate.
pub fn check_model_access(_model: &str, _model_tier: &AiModelTier) -> Result<(), TierError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entitlement(operator: EntitlementOperator) -> Entitlement {
        Entitlement {
            edition: EntitlementEdition::Licensed,
            operator,
            capacity_gb_per_day: Some(25.0),
        }
    }

    #[test]
    fn ai_ceiling_parse_accepts_positive_postgres_integers_only() {
        assert_eq!(parse_ai_credits_ceiling("5000000"), Some(5_000_000));
        assert_eq!(parse_ai_credits_ceiling(" 42 "), Some(42));
        assert_eq!(parse_ai_credits_ceiling("0"), None);
        assert_eq!(parse_ai_credits_ceiling("unlimited"), None);
        assert_eq!(parse_ai_credits_ceiling("-1"), None);
        assert_eq!(parse_ai_credits_ceiling("2147483647"), Some(2_147_483_647));
        assert_eq!(parse_ai_credits_ceiling("2147483648"), None);
    }

    fn usage_with_bytes(bytes: u64) -> TierUsage {
        TierUsage {
            data_sources: 0,
            detection_rules: 0,
            team_members: 0,
            today: DailyUsage {
                date: chrono::NaiveDate::from_ymd_opt(2026, 11, 9).unwrap(),
                bytes_ingested: bytes,
                events_ingested: 0,
                peak_eps: 0,
            },
        }
    }

    fn limits_with_capacity(gb: f64) -> TierLimits {
        let mut limits = TierLimits::for_tier_unoverridden(OrganizationTier::Licensed);
        limits.max_daily_gb = Some(gb);
        limits
    }

    #[test]
    fn capacity_warning_reports_true_overage_not_capped_at_100() {
        // 38.46 GB against 1 GB/day.
        let warnings = generate_warnings(&limits_with_capacity(1.0), &usage_with_bytes(38_460_000_000));
        let volume = warnings.iter().find(|w| w.resource == "daily_volume").unwrap();
        assert_eq!(volume.percent_used, 3846);
        assert!(volume.message.contains("3,846% of contracted capacity"), "{}", volume.message);
        assert!(volume.message.contains("never blocked"));
    }

    #[test]
    fn capacity_warning_starts_at_80_percent() {
        let limits = limits_with_capacity(10.0);
        assert!(generate_warnings(&limits, &usage_with_bytes(7_990_000_000)).is_empty());
        let at = generate_warnings(&limits, &usage_with_bytes(8_000_000_000));
        assert_eq!(at[0].percent_used, 80);
    }

    #[test]
    fn true_percent_and_grouping_edges() {
        assert_eq!(true_percent(0.0, 10.0), 0);
        assert_eq!(true_percent(5.0, 0.0), 0);
        assert_eq!(true_percent(f64::NAN, 1.0), 0);
        assert_eq!(true_percent(1e30, 1.0), u32::MAX);
        assert_eq!(group_thousands(0), "0");
        assert_eq!(group_thousands(999), "999");
        assert_eq!(group_thousands(1000), "1,000");
        assert_eq!(group_thousands(1234567), "1,234,567");
    }

    #[test]
    fn capacity_parse_accepts_only_positive_finite_values() {
        assert_eq!(parse_capacity_gb_per_day(" 25.5 "), Some(25.5));
        assert_eq!(parse_capacity_gb_per_day("0"), None);
        assert_eq!(parse_capacity_gb_per_day("-1"), None);
        assert_eq!(parse_capacity_gb_per_day("NaN"), None);
        assert_eq!(parse_capacity_gb_per_day("inf"), None);
        assert_eq!(parse_capacity_gb_per_day("nope"), None);
    }

    #[test]
    fn every_legacy_paid_tier_maps_to_full_licensed_features() {
        let legacy = [
            OrganizationTier::Hobby,
            OrganizationTier::Startup,
            OrganizationTier::Growth,
            OrganizationTier::Team,
            OrganizationTier::Starter,
            OrganizationTier::Pro,
            OrganizationTier::Enterprise,
            OrganizationTier::Unrestricted,
        ];
        for tier in legacy {
            let limits = TierLimits::for_tier_unoverridden(tier);
            assert_eq!(
                limits.entitlement.edition,
                EntitlementEdition::Licensed,
                "{tier:?}"
            );
            assert_eq!(limits.tier, OrganizationTier::Licensed, "{tier:?}");
            assert_eq!(limits.api_access, ApiAccessLevel::Full, "{tier:?}");
            assert!(limits.sso_enabled, "{tier:?}");
            assert!(limits.ha_enabled, "{tier:?}");
            assert_eq!(limits.max_data_sources, None, "{tier:?}");
            assert_eq!(limits.max_detection_rules, None, "{tier:?}");
            assert_eq!(limits.max_team_members, None, "{tier:?}");
            assert_eq!(limits.max_eps, None, "{tier:?}");
            assert_eq!(limits.max_metric_monitors, None, "{tier:?}");
            assert_eq!(limits.max_synthetic_checks, None, "{tier:?}");
            assert_eq!(limits.max_slos, None, "{tier:?}");
            assert_eq!(limits.ai_model_tier, AiModelTier::Full, "{tier:?}");
            assert!(!limits.is_enforced(), "{tier:?}");
        }
    }

    #[test]
    fn old_tier_licence_claim_is_admitted_and_mapped() {
        let entitlement =
            Entitlement::from_license_tier_claim("starter", EntitlementOperator::SelfRun).unwrap();
        let limits = TierLimits::for_entitlement_unoverridden(entitlement);
        assert_eq!(limits.tier, OrganizationTier::Licensed);
        assert_eq!(limits.entitlement.capacity_gb_per_day, Some(50.0));
        assert!(limits.sso_enabled);
        assert!(limits.ha_enabled);
        assert!(Entitlement::from_license_tier_claim(
            "unknown-future-plan",
            EntitlementOperator::SelfRun,
        )
        .is_err());
    }

    #[test]
    fn legacy_tier_capacity_is_metadata_not_a_feature_selector() {
        let cases = [
            (OrganizationTier::Hobby, Some(2.0)),
            (OrganizationTier::Startup, Some(5.0)),
            (OrganizationTier::Growth, Some(10.0)),
            (OrganizationTier::Team, Some(25.0)),
            (OrganizationTier::Starter, Some(50.0)),
            (OrganizationTier::Pro, Some(100.0)),
            (OrganizationTier::Enterprise, None),
        ];
        for (tier, expected) in cases {
            let limits = TierLimits::for_tier_unoverridden(tier);
            assert_eq!(limits.entitlement.capacity_gb_per_day, expected);
            assert_eq!(limits.max_daily_gb, expected);
            assert!(limits.sso_enabled);
        }
    }

    #[test]
    fn hosted_allowance_is_enforced_independently_of_capacity() {
        let limits = TierLimits::for_entitlement_with_ceiling(
            entitlement(EntitlementOperator::Hosted),
            Some(5_000_000),
        );
        assert_eq!(limits.ai_credits_per_month, Some(5_000_000));
        assert_eq!(limits.ai_model_tier, AiModelTier::Full);
        assert!(limits.sso_enabled);
        assert!(enforce_ai_allowance(5_000_000, limits.ai_credits_per_month).is_ok());
        assert!(matches!(
            enforce_ai_allowance(5_000_001, limits.ai_credits_per_month),
            Err(TierError::AiRateLimitExceeded(_))
        ));
    }

    #[test]
    fn hosted_without_a_provisioned_allowance_fails_closed() {
        let limits = TierLimits::for_entitlement_with_ceiling(
            entitlement(EntitlementOperator::Hosted),
            None,
        );
        assert_eq!(limits.ai_credits_per_month, Some(0));
    }

    #[test]
    fn self_run_byo_ai_is_uncapped() {
        let limits = TierLimits::for_entitlement_with_ceiling(
            entitlement(EntitlementOperator::SelfRun),
            Some(5_000_000),
        );
        assert_eq!(limits.ai_credits_per_month, None);
        assert_eq!(limits.ai_model_tier, AiModelTier::Full);
        assert!(check_model_access("customer/model", &AiModelTier::Economy).is_ok());
        assert!(enforce_ai_allowance(i32::MAX, limits.ai_credits_per_month).is_ok());
    }

    #[test]
    fn open_edition_is_identified_without_paid_plan_limits() {
        let limits = TierLimits::for_entitlement_unoverridden(Entitlement {
            edition: EntitlementEdition::Open,
            operator: EntitlementOperator::SelfRun,
            capacity_gb_per_day: None,
        });
        assert_eq!(limits.tier, OrganizationTier::Open);
        assert!(!limits.sso_enabled);
        assert!(limits.ha_enabled);
        assert_eq!(limits.api_access, ApiAccessLevel::Full);
        assert!(!limits.is_enforced());
    }

    #[test]
    fn model_names_are_never_plan_gated() {
        for model_tier in [
            AiModelTier::Economy,
            AiModelTier::Standard,
            AiModelTier::Full,
        ] {
            assert!(check_model_access("claude-opus", &model_tier).is_ok());
            assert!(check_model_access("private-gateway/model", &model_tier).is_ok());
        }
    }

    #[test]
    fn check_limit_remains_compatible_with_old_rows() {
        assert!(check_limit("rules", 10, Some(50), OrganizationTier::Hobby, "").is_ok());
        assert!(check_limit("rules", 50, Some(50), OrganizationTier::Hobby, "").is_err());
        assert!(check_limit("rules", u32::MAX, None, OrganizationTier::Licensed, "").is_ok());
    }

    #[test]
    fn ai_request_cost_is_provider_agnostic() {
        assert_eq!(ai_request_cost("claude-haiku-4-5"), AI_CREDIT_LITE);
        assert_eq!(ai_request_cost("gemini-2.0-flash-lite"), AI_CREDIT_LITE);
        assert_eq!(ai_request_cost("glm-4.6"), AI_CREDIT_LITE);
        assert_eq!(ai_request_cost("z-ai/GLM-4-Flash"), AI_CREDIT_LITE);
        assert_eq!(ai_request_cost("claude-sonnet-4-6"), AI_CREDIT_FULL);
        assert_eq!(ai_request_cost("claude-opus-4-8"), AI_CREDIT_FULL);
    }

    #[test]
    fn old_and_new_tier_names_parse_during_the_support_window() {
        assert_eq!(
            "open".parse::<OrganizationTier>().unwrap(),
            OrganizationTier::Open
        );
        assert_eq!(
            "licensed".parse::<OrganizationTier>().unwrap(),
            OrganizationTier::Licensed
        );
        assert_eq!(
            "hobby".parse::<OrganizationTier>().unwrap(),
            OrganizationTier::Hobby
        );
        assert_eq!(
            "business".parse::<OrganizationTier>().unwrap(),
            OrganizationTier::Starter
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
}
