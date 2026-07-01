// SPDX-License-Identifier: AGPL-3.0-or-later

//! NanoSIEM REST API Library
//!
//! This crate provides the REST API server for NanoSIEM including:
//! - Search endpoints (piped query, raw SQL, explain)
//! - Detection rule management endpoints
//! - Alert management endpoints
//! - Field metadata endpoints
//! - Saved search endpoints

pub mod config;
pub mod error;
pub mod handlers;
pub mod metrics;
pub mod middleware;
pub mod openapi;
pub mod routes;
pub mod state;
pub mod utils;

pub use config::ApiConfig;
pub use error::ApiError;
pub use metrics::AppMetrics;
pub use routes::create_router;
pub use state::AppState;
