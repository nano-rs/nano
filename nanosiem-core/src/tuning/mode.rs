// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-wide AI tuning mode (NAN-3219).
//!
//! One switch above the per-rule `detection_rules.auto_tuning_enabled`
//! toggle; the two are ANDed. Stored per tenant on hosted-shared
//! (`shared_tenant_ai_settings.ai_tuning_mode`, read in the signed
//! tenant transaction) and once per deployment on dedicated
//! (`system_settings.ai_tuning_mode`), both added by enterprise migration
//! 9010950 with the default `on`.
//!
//! * [`AiTuningMode::On`] — automatic proposals + the Tune wizard (default).
//! * [`AiTuningMode::Manual`] — metrics and baselines keep flowing, but no
//!   automatic proposals or notifications; the Tune wizard and `@tune` work.
//! * [`AiTuningMode::Off`] — no automatic tuning work at all (no metrics
//!   either); the Tune wizard and `@tune` are refused.

use sqlx::PgPool;

/// The tenant's AI tuning mode.
#[derive(
    Debug,
    Clone,
    Copy,
    Default,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum AiTuningMode {
    /// Automatic proposals and the Tune wizard (default).
    #[default]
    On,
    /// Tune wizard only: no automatic proposals or notifications.
    Manual,
    /// No AI tuning: no automatic work, and the Tune wizard is refused.
    Off,
}

/// The one message every refused Tune surface returns when the mode is `off`.
pub const AI_TUNING_OFF_MESSAGE: &str = "AI tuning is turned off for this tenant. \
An administrator with the settings:ai permission can turn it back on in Settings → AI & pivt → Models.";

impl AiTuningMode {
    pub const ALL: [AiTuningMode; 3] = [AiTuningMode::On, AiTuningMode::Manual, AiTuningMode::Off];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::On => "on",
            Self::Manual => "manual",
            Self::Off => "off",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "on" => Some(Self::On),
            "manual" => Some(Self::Manual),
            "off" => Some(Self::Off),
            _ => None,
        }
    }

    /// Background metrics / baselines / breach bookkeeping may run.
    pub fn collects_metrics(self) -> bool {
        !matches!(self, Self::Off)
    }

    /// Automatic (AI-generated) proposals and their notifications may run.
    pub fn automatic_proposals(self) -> bool {
        matches!(self, Self::On)
    }

    /// The interactive Tune wizard / pivt `@tune` may run.
    pub fn wizard_allowed(self) -> bool {
        !matches!(self, Self::Off)
    }
}

impl std::fmt::Display for AiTuningMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The dedicated tuning scheduler's background tasks, for the mode gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TuningTask {
    /// Rule metrics collection (no AI).
    Metrics,
    /// Baseline updates (no AI).
    Baselines,
    /// Threshold detection → automatic proposals.
    Breaches,
    /// Silent-rule diagnostics → automatic proposals (AI phrasing).
    SilentRules,
    /// Tuning notification batching.
    Notifications,
}

impl TuningTask {
    /// Whether this task may run under `mode`.
    pub fn allowed(self, mode: AiTuningMode) -> bool {
        match self {
            Self::Metrics | Self::Baselines => mode.collects_metrics(),
            Self::Breaches | Self::SilentRules | Self::Notifications => mode.automatic_proposals(),
        }
    }
}

/// Dedicated: read the deployment's mode from `system_settings`.
///
/// Read through `to_jsonb(row)` so an open-core build (whose schema never
/// gets the enterprise column) and a deployment that has not yet applied
/// 9010950 both answer the default `on` instead of failing.
pub async fn read_deployment_ai_tuning_mode(pool: &PgPool) -> Result<AiTuningMode, sqlx::Error> {
    let stored: Option<Option<String>> = sqlx::query_scalar(
        "SELECT to_jsonb(s) ->> 'ai_tuning_mode' FROM system_settings s WHERE s.id = 'default'",
    )
    .fetch_optional(pool)
    .await?;
    Ok(stored
        .flatten()
        .as_deref()
        .and_then(AiTuningMode::parse)
        .unwrap_or_default())
}

/// Dedicated: change the deployment's mode. Returns `(previous, stored)`.
/// `RowNotFound` when the `default` settings row (or the column) is missing.
pub async fn write_deployment_ai_tuning_mode(
    pool: &PgPool,
    mode: AiTuningMode,
) -> Result<(AiTuningMode, AiTuningMode), sqlx::Error> {
    let (previous, stored): (String, String) = sqlx::query_as(
        "WITH prev AS (
             SELECT ai_tuning_mode FROM system_settings WHERE id = 'default' FOR UPDATE
         )
         UPDATE system_settings s
            SET ai_tuning_mode = $1, updated_at = NOW()
           FROM prev
          WHERE s.id = 'default'
         RETURNING prev.ai_tuning_mode, s.ai_tuning_mode",
    )
    .bind(mode.as_str())
    .fetch_one(pool)
    .await?;
    Ok((
        AiTuningMode::parse(&previous).unwrap_or_default(),
        AiTuningMode::parse(&stored).unwrap_or_default(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_on() {
        assert_eq!(AiTuningMode::default(), AiTuningMode::On);
    }

    #[test]
    fn round_trips_and_rejects_unknown_names() {
        for mode in AiTuningMode::ALL {
            assert_eq!(AiTuningMode::parse(mode.as_str()), Some(mode));
            assert_eq!(
                serde_json::to_value(mode).unwrap(),
                serde_json::json!(mode.as_str())
            );
        }
        assert_eq!(AiTuningMode::parse("manual_only"), None);
        assert_eq!(AiTuningMode::parse("ON"), None);
        assert!(serde_json::from_value::<AiTuningMode>(serde_json::json!("disabled")).is_err());
    }

    #[test]
    fn capability_matrix() {
        use AiTuningMode::*;
        assert!(On.collects_metrics() && On.automatic_proposals() && On.wizard_allowed());
        assert!(
            Manual.collects_metrics() && !Manual.automatic_proposals() && Manual.wizard_allowed()
        );
        assert!(!Off.collects_metrics() && !Off.automatic_proposals() && !Off.wizard_allowed());
    }

    #[test]
    fn dedicated_scheduler_tasks_honour_the_mode() {
        use AiTuningMode::*;
        use TuningTask::*;
        let all = [Metrics, Baselines, Breaches, SilentRules, Notifications];
        for task in all {
            assert!(task.allowed(On), "{task:?} runs when on");
            assert!(
                !task.allowed(Off),
                "{task:?} never runs when off (metrics included)"
            );
        }
        assert!(Metrics.allowed(Manual));
        assert!(Baselines.allowed(Manual));
        assert!(!Breaches.allowed(Manual), "manual: no automatic proposals");
        assert!(
            !SilentRules.allowed(Manual),
            "manual: no automatic proposals"
        );
        assert!(!Notifications.allowed(Manual), "manual: no notifications");
    }
}
