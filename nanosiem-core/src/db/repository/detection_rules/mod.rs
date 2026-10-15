// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection rule repository for CRUD operations
//!
//! Submodules organized by concern:
//! - `types`: Error types, helper structs, and repository definition
//! - `crud`: Create, read, update, delete operations
//! - `listing`: Query methods for listing/filtering rules
//! - `lifecycle`: Mode transition methods (promote, demote, pause, resume)
//! - `stats`: Execution stats and daily statistics
//! - `auto_tuning`: Auto-tuning configuration and eligibility
//! - `scheduling`: Distributed scheduler claim/release operations
//! - `case_permissions`: Case visibility and group association management

mod auto_tuning;
mod case_permissions;
mod crud;
mod late_replay;
mod lifecycle;
mod listing;
mod scheduling;
mod stats;
mod types;

pub use late_replay::{
    LateReplayClaim, LateReplayPlan, LateReplayReleaseOutcome,
    LAKE_DETECTION_EVENT_PUBLICATION_UPSERT_SQL, PUBLICATION_VISIBILITY_SETTLE_SECONDS,
};
pub use types::{DailyStat, DetectionRuleRepository, DetectionRuleRepositoryError};
