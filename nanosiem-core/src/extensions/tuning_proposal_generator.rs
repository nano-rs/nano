// SPDX-License-Identifier: AGPL-3.0-or-later

//! `TuningProposalGenerator` — extension point for AI-driven detection rule
//! tuning.
//!
//! Used by `tuning/scheduler.rs::start_threshold_detection_task`, which
//! previously held an `Option<Arc<TuningOrchestrator>>` directly. The
//! orchestrator + agent + hint_agent + safety checker live in the enterprise
//! crate (`nanosiem-enterprise::tuning`); this trait lets the open-core
//! scheduler keep running base-rate threshold detection without depending on
//! any of the AI machinery.
//!
//! Open core wires `None` (no proposal generation — just breach monitoring).
//! Enterprise wires `Some(Arc::new(TuningOrchestrator::new(...)))`.

use async_trait::async_trait;

use crate::extensions::ExtensionError;

/// Generates tuning proposals from threshold breaches.
///
/// The single entry point mirrors today's `TuningOrchestrator::process_breaches`
/// — it queries threshold breaches itself, runs the AI agent / hint_agent /
/// safety checks, and writes proposals + notifications. Returns the number of
/// proposals generated so the scheduler can log a summary.
#[async_trait]
pub trait TuningProposalGenerator: Send + Sync {
    /// Process threshold breaches and generate tuning proposals. Returns the
    /// number of proposals generated this cycle (zero when no breaches need
    /// tuning, when AI is disabled per-rule, or when safety checks reject the
    /// generated proposals).
    async fn process_breaches(&self) -> Result<usize, ExtensionError>;
}
