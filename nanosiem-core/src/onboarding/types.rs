// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onboarding wizard types

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Onboarding wizard steps
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum OnboardingStep {
    AiSetup,
    OrgContext,
    TeamSetup,
    SsoSetup,
    FirstFeed,
    CreateParser,
    FirstSearches,
}

impl OnboardingStep {
    /// All steps in order
    pub fn all() -> &'static [OnboardingStep] {
        &[
            Self::AiSetup,
            Self::OrgContext,
            Self::TeamSetup,
            Self::SsoSetup,
            Self::FirstFeed,
            Self::CreateParser,
            Self::FirstSearches,
        ]
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AiSetup => "ai_setup",
            Self::OrgContext => "org_context",
            Self::TeamSetup => "team_setup",
            Self::SsoSetup => "sso_setup",
            Self::FirstFeed => "first_feed",
            Self::CreateParser => "create_parser",
            Self::FirstSearches => "first_searches",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ai_setup" => Some(Self::AiSetup),
            "org_context" => Some(Self::OrgContext),
            "team_setup" => Some(Self::TeamSetup),
            "sso_setup" => Some(Self::SsoSetup),
            "first_feed" => Some(Self::FirstFeed),
            "create_parser" => Some(Self::CreateParser),
            "first_searches" => Some(Self::FirstSearches),
            _ => None,
        }
    }

    /// Next step after this one, or None if this is the last
    pub fn next(&self) -> Option<Self> {
        let all = Self::all();
        let idx = all.iter().position(|s| s == self)?;
        all.get(idx + 1).copied()
    }

    /// Previous step before this one, or None if this is the first
    pub fn previous(&self) -> Option<Self> {
        let all = Self::all();
        let idx = all.iter().position(|s| s == self)?;
        if idx == 0 {
            None
        } else {
            all.get(idx - 1).copied()
        }
    }
}

/// Per-user onboarding progress
#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct OnboardingProgress {
    pub user_id: Uuid,
    pub current_step: OnboardingStep,
    pub completed_steps: Vec<OnboardingStep>,
    pub skipped_steps: Vec<OnboardingStep>,
    pub step_data: serde_json::Value,
    pub dismissed: bool,
    pub completed_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Request to update the current step
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct UpdateProgressRequest {
    pub current_step: OnboardingStep,
}

/// Request to complete or skip a step
#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct StepActionRequest {
    pub step: OnboardingStep,
    /// Optional data to store for this step
    pub data: Option<serde_json::Value>,
}

/// System configuration status for auto-detection
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OnboardingStatus {
    pub has_ai_provider: bool,
    pub has_org_context: bool,
    pub has_users: bool,
    pub has_sso: bool,
    pub has_log_sources: bool,
    pub has_parsers: bool,
    pub has_search_history: bool,
}
