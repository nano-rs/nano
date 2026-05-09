// SPDX-License-Identifier: AGPL-3.0-or-later

//! License enforcement for BYOC deployments
//!
//! Provides a license checker service that communicates with nano-main
//! to enforce subscription status. Self-hosted deployments without
//! LICENSE_URL configured operate without restrictions.

pub mod checker;
mod repository;
mod types;

pub use checker::LicenseChecker;
pub use repository::LicenseRepository;
pub use types::{LicenseResponse, LicenseState, LicenseStatus};
