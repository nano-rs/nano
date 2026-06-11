// SPDX-License-Identifier: AGPL-3.0-or-later

//! Scheduler Module
//!
//! Provides scheduled data fetch job management for automatic data retrieval
//! from remote URLs on a cron schedule.
//!
//! Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7

pub mod repository;
pub mod secrets;
pub mod service;
pub mod types;

pub use repository::{JobStats, SchedulerRepository, SchedulerRepositoryError};
pub use secrets::{merge_auth_headers, redact_auth_headers};
pub use service::{
    calculate_next_run, calculate_next_runs, describe_cron, normalize_cron, validate_cron,
    SchedulerError, SchedulerService,
};
pub use types::{
    JobExecution, JobFilter, JobStatus, NewScheduledJob, RetryPolicy, ScheduledJob,
    UpdateScheduledJob,
};
