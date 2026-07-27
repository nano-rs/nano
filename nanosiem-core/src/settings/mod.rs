// SPDX-License-Identifier: AGPL-3.0-or-later

//! System Settings Module
//!
//! Manages system-wide configuration including data retention policies
//! for both PostgreSQL (metadata) and ClickHouse (log telemetry),
//! S3 storage tiering for cost-effective long-term retention,
//! organizational context for AI prompt customization,
//! and developer settings for scheduler control.

mod developer_repository;
pub mod disk_pressure;
pub mod local_auth;
mod organizational_context;
mod retention;
pub mod search_admission;
pub mod search_query_limits;
mod service;
pub mod tier;
mod tiering;

pub use developer_repository::*;
pub use disk_pressure::*;
pub use local_auth::*;
pub use organizational_context::*;
pub use retention::*;
pub use search_admission::*;
pub use search_query_limits::*;
pub use service::*;
pub use tier::*;
pub use tiering::*;
