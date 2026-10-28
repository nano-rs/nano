// SPDX-License-Identifier: AGPL-3.0-or-later

//! `ingest[T]` for the lean-lake part model (NAN-2868), implementing
//! `crate::parts` (the contract, `docs-internal/NAN-2865-part-contract.md`).

pub mod admission_attempts;
pub mod agent_lane;
pub mod bronze_list;
pub mod cell;
pub mod count_record;
pub mod credential_activity;
pub mod dedup;
mod diagnostics;
mod timing;
pub mod discovery;
pub mod edge;
pub mod export;
pub mod iceberg_export;
pub mod late_dedup;
pub mod lean_erasure;
pub mod finding_outbox;
pub mod finding_attempts;
pub mod finding_floors;
pub mod finding_append;
pub mod finding_gate;
pub mod hold;
pub mod ingest;
pub mod maintenance;
pub mod memory;
pub mod merge;
pub(crate) mod merge_lanes;
pub(crate) mod merge_quota;
pub mod part_gc_cell;
pub mod part_gc_gate;
pub mod owner_tls;
pub(crate) mod platform_tls;
pub mod native_writer;
pub mod partials;
pub mod prevalence;
pub(crate) mod prevalence_io;
pub mod prevalence_owner_store;
pub mod prevalence_spell;
pub mod quarantine;
pub mod quarantine_store;
pub mod quarantine_ledger;
pub mod r2_put;
pub mod reindex;
pub mod restamp;
pub mod s3_store;
pub mod schema;
pub mod stall_watchdog;
pub mod writer;
pub mod writer_lease;
pub mod host_sort;
pub mod class_sort;
#[cfg(test)]
mod catchup_bench;

pub use discovery::{NoticeQueue, SourceNotice, SpoolQueue};
pub use ingest::{IngestConfig, IngestHealth, Ingestor};

pub mod startup;

/// The default lib test target shares one process/CPU allocation. Keep the
/// measured ingestion fixture and multi-million-row component/heap workloads
/// from borrowing each other's budget. Test-only: no ingest scheduling policy.
#[cfg(test)]
pub(crate) mod test_resources {
    // Timed scenarios take a write guard; untimed large components share reads.
    pub(crate) static PREVALENCE_WORKLOAD: tokio::sync::RwLock<()> = tokio::sync::RwLock::const_new(());
}
