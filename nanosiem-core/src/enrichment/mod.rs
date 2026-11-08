// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment module for IP geolocation, ASN, and threat intelligence data
//!
//! This module provides:
//! - Enrichment source metadata (`enrichment_sources`)
//! - IP enrichment lookups against the ingest-time dictionary
//! - IOC (Indicators of Compromise) enrichment from threat intel feeds
//!
//! IPinfo Lite geo/ASN comes only from nano's signed platform feed bundle
//! (`platform_enrichment`); NAN-4959 removed the native IPinfo download job.

pub mod ioc;
pub mod ip_geo;
pub mod lane_client;
pub mod repository;
pub mod service;
pub mod types;

pub use lane_client::{EnrichmentLaneClient, EnrichmentLaneError, ENRICH_SOURCE_TYPE};
pub use repository::{EnrichmentRepository, EnrichmentRepositoryError};
pub use service::{EnrichmentError, EnrichmentService, LogEnrichment};
pub use types::*;
