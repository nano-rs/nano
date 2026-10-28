// SPDX-License-Identifier: AGPL-3.0-or-later

//! Onboarding wizard module
//!
//! Per-user onboarding progress tracking for the setup wizard.

mod repository;
mod status_probe;
mod types;

pub use repository::OnboardingRepository;
pub use status_probe::*;
pub use types::*;
