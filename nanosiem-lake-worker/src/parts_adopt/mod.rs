// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean-lake phase 4 (NAN-2870): adopt existing history as parts, in place.
//!
//! A one-time, resumable, bounded job makes a tenant's existing compacted
//! Iceberg data objects (those of the current owner-signed generation, before
//! T0) available as parts **without rewriting or moving any data**. For each
//! object it:
//! 1. verifies the object against its signed stamp (read-only source);
//! 2. builds the sidecars in one streaming pass: token index, rollup /
//!    prevalence / entity-range partials, entity blooms for any bloom column
//!    the object lacks, and the contract Merkle roots;
//! 3. writes them and a signed provenance record (`inputs.kind = adopted`,
//!    referencing the original key, SHA-256 and signed stamp) under the
//!    parts layout;
//! 4. commits batches of parts with signed `adopt` log entries.
//!
//! See `docs-internal/NAN-2865-part-contract.md` section 8.1 and the runbook
//! `docs-internal/NAN-2870-adopt-history-runbook.md`.

pub mod build;
pub mod job;
pub mod leaves;
pub mod parity;
pub mod partials;
pub mod plan;
pub mod source;

pub use build::{build_adopted_sidecars, BuildBudgets, BuiltSidecars};
pub use job::{adopted_parts, run_adoption, AdoptHooks, AdoptOptions, AdoptReport, AdoptSigner, AdoptStage};
pub use parity::{check_parity, GenerationCounts, ParityReport};
pub use plan::{extract_stamp_ledger, verify_generation, AdoptionPlan, PlannedObject};
pub use source::{AdoptSource, BucketMirrorSource};

#[cfg(test)]
mod tests;
