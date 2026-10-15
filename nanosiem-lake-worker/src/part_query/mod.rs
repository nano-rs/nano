// SPDX-License-Identifier: AGPL-3.0-or-later

//! `query[T]`: the lean-lake query process over parts (NAN-2865 phase 3,
//! NAN-2869). Codes against the part contract (`crate::parts`,
//! `docs-internal/NAN-2865-part-contract.md`).
//!
//! - [`log_view`]: the verified, incrementally folded live set (never LIST).
//! - [`fetch`]: provenance verification and the NAN-2853 verified cache.
//! - [`prune`]: token-index and bloom/statistics row-group pruning.
//! - [`engine`]: nPL over parts through the reader's compiler and planner.
//! - [`partials`]: counts, prevalence, entity ranges and risk from partials.
//! - [`detections`]: the scheduling gate and late-part re-run windows.
//! - [`jobs`]: async/durable search jobs over parts.
//! - [`server`]: the unix-socket HTTP surface of the process.

mod cloud_facets;
pub(crate) mod entity_count;
mod cold_batches;
#[cfg(test)]
mod cold_batches_native_tests;
mod debug;
pub mod credentials;
pub mod detections;
pub mod engine;
pub(crate) mod entity_cache;
pub mod fetch;
pub mod host_hint;
pub mod identity;
pub mod identity_merged;
mod identity_spill;
pub mod job_results;
pub mod jobs;
pub mod keyword_count;
pub(crate) mod lanes;
pub mod log_view;
pub mod memo;
pub mod membership;
pub mod metadata_cache;
pub mod memory_budget;
pub mod partials;
pub mod prewarm_pacing;
pub(crate) mod prevalence_rows;
pub mod progressive;
pub mod density;
pub mod token_seed;
pub mod two_pass;
pub mod range_fetch;
pub mod result_cache;
pub mod fragment_cache;
mod fragment_aggregate;
mod token_cache;
pub(crate) mod select_evidence;
pub mod prune;
pub mod risk;
pub mod rollup_rows;
pub mod server;
pub mod slow_queries;
pub mod sql_probe;
pub mod trusted_local_detect;
pub mod view_jobs;

pub use engine::{BroadNplRequest, EngineSettings, PartQueryEngine, PartQueryError};
pub use fetch::PartFetcher;
pub use log_view::{Advance, PartLogView};

mod local_hot_window;

mod risk_ledger;
mod product_state;
mod detail_scan;
mod parquet_concat;
pub mod product_publish;
