// SPDX-License-Identifier: AGPL-3.0-or-later

//! Prevalence Tracking Module
//!
//! Provides real-time prevalence tracking for file hashes and domains in NanoSIEM:
//! - File hash (MD5/SHA256) prevalence tracking
//! - Domain/subdomain prevalence tracking
//! - First-seen and last-seen timestamps
//! - Configurable time windows (1h, 24h, 7d, 30d)
//! - Rarity detection based on configurable thresholds
//! - Configurable settings with hot-reload support

pub mod lookup;
pub mod repository;
pub mod service;
pub mod settings;
pub mod stamped;
pub mod types;

pub use lookup::{LakePrevalenceClient, LakePrevalenceSnapshots, PrevalenceLookup};
pub use repository::PrevalenceRepository;
pub use service::{PrevalenceError, PrevalenceService, MAX_BULK_ARTIFACTS};
pub use settings::{PrevalenceSettings, PrevalenceSettingsError, RarityThresholdSetting};
pub use types::*;
