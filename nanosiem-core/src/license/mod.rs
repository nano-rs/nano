// SPDX-License-Identifier: AGPL-3.0-or-later

//! Licence admission for enterprise deployments
//!
//! Provides a license checker service that communicates with nano-main
//! to enforce subscription status. A complete online tuple uses that checker;
//! deployments without the tuple require signed C05 authority (or the bounded
//! legacy-upgrade grace) and otherwise fail closed for licensed-only features.

pub mod checker;
pub mod install_identity;
pub mod release_notice;
mod repository;
pub mod token_rejection;
mod types;
// NAN-5170: Self-run usage reporting + offline usage export. Enterprise
// only; the mirror strip removes the file (tools/sync-to-nano-mirror.sh).
#[cfg(feature = "enterprise")]
pub mod usage_report;

pub use checker::LicenseChecker;
pub use install_identity::{InstallIdentityRepository, INSTALL_ID_HEADER};
pub use release_notice::ReleaseNotice;
pub use repository::LicenseRepository;
pub use token_rejection::{TokenRejectedNotice, TokenRejection};
pub use types::{
    EntitlementGrant, LicenseEntitlement, LicenseResponse, LicenseState, LicenseStatus,
    MAX_GRANTED_AI_CREDITS_PER_MONTH,
};
