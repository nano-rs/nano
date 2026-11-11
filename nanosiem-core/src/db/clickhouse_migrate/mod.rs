// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse Migration Runner
//!
//! Provides automatic schema migrations for ClickHouse, similar to sqlx for PostgreSQL.
//! Tracks applied migrations in a `_migrations` table and applies pending ones on startup.
//!
//! Includes ClickHouse Cloud compatibility: automatically detects CH Cloud environments
//! and strips unsupported settings/index types before executing statements.

mod cluster_reachability;
mod detection;
mod distributed;
mod ocsf_legacy_drop;
mod runner;
mod schema_profile_guard;
mod sql_transform;
mod tracking;
mod types;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod soft_fail_tests;

pub(crate) use cluster_reachability::server_cluster_rows_predicate;
pub(crate) use detection::configured_or_detected_cluster;
pub use ocsf_legacy_drop::{
    LegacyDayCheck, LegacyDayStatus, OcsfLegacyDropOutcome, OcsfLegacyDropPlan, OCSF_LEGACY_TABLE,
};
pub use schema_profile_guard::{
    check_unset_profile_against_install, classify_installed_logs_schema, InstalledLogsSchema,
};
pub use types::{ClickHouseMigrateError, ClickHouseMigrator, Migration};
