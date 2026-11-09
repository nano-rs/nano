// SPDX-License-Identifier: AGPL-3.0-or-later

//! Licence admission for enterprise deployments
//!
//! Provides a license checker service that communicates with nano-main
//! to enforce subscription status. A complete online tuple uses that checker;
//! deployments without the tuple require signed C05 authority (or the bounded
//! legacy-upgrade grace) and otherwise fail closed for licensed-only features.

pub mod checker;
pub mod release_notice;
mod repository;
mod types;

pub use checker::LicenseChecker;
pub use release_notice::ReleaseNotice;
pub use repository::LicenseRepository;
pub use types::{
    EntitlementGrant, LicenseEntitlement, LicenseResponse, LicenseState, LicenseStatus,
    MAX_GRANTED_AI_CREDITS_PER_MONTH,
};
