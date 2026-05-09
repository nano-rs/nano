// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health monitoring module
//!
//! This module provides health monitoring for:
//! - AI provider connectivity
//! - Data feed staleness
//!
//! It runs as a background scheduler that periodically checks health
//! and creates notifications for admin users when issues are detected.

pub mod ai_monitor;
pub mod feed_monitor;
pub mod repository;
pub mod scheduler;
pub mod types;

pub use ai_monitor::AiMonitor;
pub use feed_monitor::FeedMonitor;
pub use repository::{HealthRepository, HealthRepositoryError};
pub use scheduler::HealthScheduler;
pub use types::{
    AiProviderStatus, FeedStalenessStatus, HealthIssue, HealthIssueType, HealthSchedulerConfig,
};
