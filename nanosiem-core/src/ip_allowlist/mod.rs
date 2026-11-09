// SPDX-License-Identifier: AGPL-3.0-or-later

//! IP Allowlist module
//!
//! Provides IP-based access control for the SIEM API, Search, and Frontend services.
//! When no allowlist rules exist, the feature is disabled (allow-all) — a
//! conclusion drawn only from a successful load. When the rules cannot be
//! loaded, the last-known rule set is enforced; if none was ever loaded,
//! protected routes refuse non-loopback clients (NAN-5077, fail closed).

pub mod repository;
pub mod service;
pub mod types;

pub use repository::{IpAllowlistRepository, IpAllowlistRepositoryError};
pub use service::{
    AllowlistDecision, IpAllowlistService, IpAllowlistServiceError, LOAD_FAILED_DEDUP_PREFIX,
    LOAD_FAILED_STALE_SECS,
};
pub use types::*;
