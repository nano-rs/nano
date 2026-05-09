// SPDX-License-Identifier: AGPL-3.0-or-later

//! Storage Tiering Service
//!
//! Manages S3-compatible storage tiering for ClickHouse logs.
//! Supports hot (local), warm (S3-backed), and cold (archive) storage tiers.

mod service;
mod types;
mod validation;

pub use service::*;
pub use types::*;
