// SPDX-License-Identifier: AGPL-3.0-or-later

//! AI Detection Auto-Tuning Module
//!
//! Provides intelligent, automated optimization of detection rules through:
//! - Continuous baseline monitoring and anomaly detection
//! - AI-powered rule analysis and tuning proposals
//! - Validation testing against historical data
//! - Safe deployment with full audit trails and revert capabilities
//! - Rule versioning and change tracking
//!
//! # Open-core surface
//!
//! Per the open-core split (NAN-744), only the rule-version history
//! (`versions.rs`), tuning data types, and the base-rate scheduler /
//! threshold detector / metrics-collection runtime live in core. Phase 3.5
//! lifted the AI-driven runtime — `agent`, `orchestrator`, `hint_agent`,
//! `safety`, `ai_error` — to `nanosiem-enterprise::tuning`; the open-core
//! scheduler now consumes a `dyn TuningProposalGenerator` (defined in
//! `nanosiem-core::extensions::tuning_proposal_generator`) so it stays
//! decoupled from the enterprise concrete types.

pub mod baseline;
pub mod cache;
pub mod metrics;
pub mod notifications;
pub mod rate_limiter;
pub mod repository;
pub mod scheduler;
pub mod silent_actions;
pub mod test_engine;
pub mod threshold;
pub mod types;
pub mod versions;

// Open-core surface: data types + version history + base-rate scheduler.
pub use baseline::*;
pub use cache::*;
pub use metrics::*;
pub use notifications::*;
pub use rate_limiter::*;
pub use repository::*;
pub use scheduler::*;
pub use silent_actions::*;
pub use test_engine::*;
pub use threshold::*;
pub use types::*;
pub use versions::*;
