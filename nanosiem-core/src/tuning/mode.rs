// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant-wide AI tuning mode (NAN-3219).
//!
//! One switch above the per-rule `detection_rules.auto_tuning_enabled`
//! toggle; the two are ANDed. Stored once per deployment on
//! `system_settings.ai_tuning_mode`, added by enterprise overlay migration
//! 9000086 with the default `on`. Open-core builds never get the column and
//! read the default `on` (see [`read_deployment_ai_tuning_mode`]).
//!
//! * [`AiTuningMode::On`] — automatic proposals + the Tune wizard (default).
//! * [`AiTuningMode::Manual`] — metrics and baselines keep flowing, but no
//!   automatic proposals or notifications; the Tune wizard and `@tune` work.
//! * [`AiTuningMode::Off`] — no automatic tuning work at all (no metrics
//!   either); the Tune wizard and `@tune` are refused.

use sqlx::PgPool;

/// The deployment's AI tuning mode.
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
pub const AI_TUNING_OFF_MESSAGE: &str = "AI tuning is turned off for this deployment. \
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
#[path = "mode_tests.rs"]
mod tests;
