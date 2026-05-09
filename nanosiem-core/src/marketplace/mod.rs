// SPDX-License-Identifier: AGPL-3.0-or-later

//! Enrichment Marketplace
//!
//! Unifies data enrichments, agent enrichments, custom enrichments, and identity
//! providers into a single browsable catalog. Supports:
//!
//! - **System enrichments**: Built-in enrichments shipped with NanoSIEM
//! - **Repository enrichments**: Pulled from external GitHub repos (manifests + code)
//! - **Custom enrichments**: User-created via the wizard/AI code generator
//!
//! # Architecture
//!
//! ```text
//! GitHub Repos ──→ SyncService ──→ marketplace_catalog (PostgreSQL)
//!                                       │
//!                                       ├── native backend → enrichment_sources / agent_enrichment_providers
//!                                       ├── deno backend   → custom_enrichments (Deno sandbox)
//!                                       └── identity backend → identity_providers
//! ```

pub mod cache;
pub mod coverage;
pub mod error;
pub mod install_service;
pub mod repository;
pub mod sync_service;
pub mod types;

pub use cache::MarketplaceCoverageCache;
pub use coverage::{ArtifactCoverage, CoverageState, MarketplaceCoverage, MarketplaceCoverageService};
pub use error::MarketplaceError;
pub use install_service::MarketplaceInstallService;
pub use repository::MarketplaceRepository;
pub use sync_service::MarketplaceSyncService;
pub use types::*;
