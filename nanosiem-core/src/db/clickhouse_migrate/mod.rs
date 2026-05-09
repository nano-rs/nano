// SPDX-License-Identifier: AGPL-3.0-or-later

//! ClickHouse Migration Runner
//!
//! Provides automatic schema migrations for ClickHouse, similar to sqlx for PostgreSQL.
//! Tracks applied migrations in a `_migrations` table and applies pending ones on startup.
//!
//! Includes ClickHouse Cloud compatibility: automatically detects CH Cloud environments
//! and strips unsupported settings/index types before executing statements.

mod detection;
mod distributed;
mod runner;
mod sql_transform;
mod tracking;
mod types;

#[cfg(test)]
mod tests;

pub use types::{ClickHouseMigrateError, ClickHouseMigrator, Migration};
