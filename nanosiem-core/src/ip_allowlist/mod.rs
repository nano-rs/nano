// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist module
//!
//! Provides IP-based access control for the SIEM API, Search, and Frontend services.
//! When no allowlist rules exist, the feature is disabled (allow-all).

pub mod repository;
pub mod service;
pub mod types;

pub use repository::{IpAllowlistRepository, IpAllowlistRepositoryError};
pub use service::{IpAllowlistService, IpAllowlistServiceError};
pub use types::*;
