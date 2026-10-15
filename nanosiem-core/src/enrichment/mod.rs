// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment module for IP geolocation, ASN, and threat intelligence data
//!
//! This module provides:
//! - Enrichment source management (IPinfo Lite, ThreatFox, etc.)
//! - IP enrichment data storage and lookup
//! - IOC (Indicators of Compromise) enrichment from threat intel feeds
//! - Sync service for downloading and updating enrichment data
//! - Auto-sync scheduler for automatic updates

pub mod ioc;
pub mod ipinfo_mmdb;
pub mod lake_ip_context;
pub mod lean_assignments;
pub mod lane_client;
pub mod repository;
pub mod scheduler;
pub mod service;
pub mod types;

pub use ipinfo_mmdb::{IpinfoMmdbError, IpinfoMmdbSnapshot};
pub use lake_ip_context::{LakeIpContextClient, LakeIpContextCounts, LakeIpContextError};
pub use lane_client::{EnrichmentLaneClient, EnrichmentLaneError, ENRICH_SOURCE_TYPE};
pub use repository::{EnrichmentRepository, EnrichmentRepositoryError};
pub use scheduler::{EnrichmentScheduler, EnrichmentSchedulerConfig};
pub use service::{EnrichmentError, EnrichmentService, EnrichmentSyncResult, LogEnrichment};
pub use types::*;
