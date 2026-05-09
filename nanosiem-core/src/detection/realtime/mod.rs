// SPDX-License-Identifier: AGPL-3.0-or-later

//! Real-time Rule Evaluation
//!
//! Provides real-time evaluation of incoming logs against enabled detection rules.
//! Generates alerts immediately when rules match.
//!
//! Note: Real-time evaluation does not query the log database - it evaluates
//! incoming events in-memory against compiled rules. PostgreSQL is used for:
//! - Loading rule definitions
//! - Storing generated alerts
//! - Updating rule statistics
//! - Logging findings (detection matches and alerts)
//! - Cumulative risk queries for meta-detections
//! - Auto-grouping alerts into cases

mod config;
mod evaluator;
mod matching;
#[cfg(any())]
mod tests;

pub use config::RealtimeConfig;
pub use evaluator::RealtimeEvaluator;
