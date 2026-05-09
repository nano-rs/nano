// SPDX-License-Identifier: AGPL-3.0-or-later

//! Processing utilities for search results
//!
//! This module contains functions for processing and enriching search results:
//! - Post-processing: Apply commands to results after SQL execution
//! - Enrichment: Add lookup table data to results

pub mod enrichment;
pub mod post_processing;

// Re-export the main functions used by service
pub use enrichment::{apply_inputlookup_enrichment, apply_lookup_enrichment};
pub use post_processing::{
    apply_post_prevalence_commands, apply_post_prevalence_commands_with_limit,
};
