// SPDX-License-Identifier: AGPL-3.0-or-later

//! Health monitoring module
//!
//! This module provides health monitoring for:
//! - AI provider connectivity
//! - Data feed staleness
//! - Stuck (unkillable) ClickHouse queries
//!
//! It runs as a background scheduler that periodically checks health
//! and creates notifications for admin users when issues are detected.

pub mod ai_monitor;
pub mod feed_monitor;
pub mod repository;
pub mod scheduler;
pub mod stuck_query_monitor;
pub mod types;

pub use ai_monitor::{AiMonitor, AiProviderConnectivityChecker};
pub use feed_monitor::FeedMonitor;
pub use repository::{HealthRepository, HealthRepositoryError};
pub use scheduler::HealthScheduler;
pub use stuck_query_monitor::StuckQueryMonitor;
pub use types::{
    AiProviderStatus, FeedStalenessStatus, HealthIssue, HealthIssueType, HealthSchedulerConfig,
    StuckQueryStatus,
};
