// SPDX-License-Identifier: AGPL-3.0-or-later

//! Demo mode support
//!
//! Provides session-scoped ephemeral demo experiences for prospects.
//! Only active when DEPLOYMENT_MODE=demo. All demo-specific schema lives
//! in a separate PostgreSQL schema (`demo.*`) that regular deployments never create.

pub mod migrations;
pub mod service;

pub use migrations::run_demo_migrations;
pub use service::{
    DemoError, DemoResourceCounts, DemoResourceType, DemoService, DemoSession, DemoSessionStatus,
    get_other_demo_resource_ids_standalone, is_demo_session_active, track_demo_resource_standalone,
};
