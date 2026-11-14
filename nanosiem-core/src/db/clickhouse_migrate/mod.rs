// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse Migration Runner
//!
//! Provides automatic schema migrations for ClickHouse, similar to sqlx for PostgreSQL.
//! Tracks applied migrations in a `_migrations` table and applies pending ones on startup.
//!
//! Includes ClickHouse Cloud compatibility: automatically detects CH Cloud environments
//! and strips unsupported settings/index types before executing statements.

mod agentlane;
mod busy_retry;
mod cluster_reachability;
mod detection;
mod distributed;
mod ocsf_legacy_drop;
mod prevalence_cadence;
mod runner;
mod schema_profile_guard;
mod sql_transform;
mod tracking;
mod types;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod agentlane_tests;
#[cfg(test)]
mod prevalence_cadence_tests;
#[cfg(test)]
mod soft_fail_tests;
#[cfg(test)]
mod busy_retry_tests;

pub use cluster_reachability::server_cluster_rows_predicate;
pub(crate) use detection::configured_or_detected_cluster;
pub use ocsf_legacy_drop::{
    LegacyDayCheck, LegacyDayStatus, OcsfLegacyDropOutcome, OcsfLegacyDropPlan, OCSF_LEGACY_TABLE,
};
pub use schema_profile_guard::{
    check_unset_profile_against_install, classify_installed_logs_schema, InstalledLogsSchema,
};
pub use agentlane::{
    agentlane_settings_from_env, AgentlaneEnv, AgentlaneOutcome, AgentlaneSettings,
    NodeCredentials, AGENTLANE_PROFILE, AGENTLANE_ROLE, AGENTLANE_WORKLOAD,
    MAX_BYTES_TO_READ_ENV, MAX_CONCURRENT_THREADS_ENV, MAX_MEMORY_PER_TOKEN_ENV, MAX_ROWS_TO_READ_ENV,
    WORKLOAD_MAX_MEMORY_ENV,
};
pub use prevalence_cadence::prevalence_refresh_minutes_from_env;
pub use types::{ClickHouseMigrateError, ClickHouseMigrator, Migration};

#[cfg(test)]
#[path = "legacy_self_source_tests.rs"]
mod legacy_self_source_tests;
