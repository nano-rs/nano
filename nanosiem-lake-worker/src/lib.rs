// SPDX-License-Identifier: AGPL-3.0-or-later

//! Native execution boundary for Nano's tenant-pinned OCSF Iceberg workers.
//!
//! Query compilation, authorization, immutable generation binding, sidecar
//! planning, and admission remain outside this module. This crate owns the
//! deliberately small unsafe boundary to a digest-pinned `libchdb` artifact.

pub mod admission_archive;
pub mod bootstrap_generation;
pub mod local_hot_window;
pub mod cell_logging;
pub mod cgroup_memory;
pub mod cell_refresh;
pub mod bounds;
pub mod startup_bounds;
pub mod bronze;
pub mod bronze_uid_ledger;
pub mod config;
pub mod count_aggregate;
pub mod derivative_tier;
pub mod enrichment;
pub(crate) mod ocsf_domains;
pub mod lean_enrichment_snapshot;
pub mod lean_identity_snapshot;
pub mod lean_identity_merge;
pub mod identity_enrichment;
pub mod lean_ip_context;
pub mod landing;
pub mod landing_admission;
pub mod landing_cell;
pub mod landing_hosted;
pub mod lean_identity_query;
pub mod lean_ioc_query;
pub mod lean_collector_errors;
pub mod lean_enrichment_coordinator;
pub mod lean_platform_bundle;
pub mod lean_platform_policy;
pub mod lean_platform_feeds;
pub mod enrichment_read;
// Hosted (hosted-shared) modules: compiled only into the enterprise
// build and stripped from the open mirror (NAN-3861). Open code reaches them
// only through `shared_mode`'s hooks.
#[cfg(target_os = "linux")]
#[cfg(feature = "enterprise")]
pub mod platform_stamping;
#[cfg(feature = "enterprise")]
pub mod bronze_reclaim;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_catalog_commit;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_catalog_commit_adapters;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_catalog_s3;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_copy_registry;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_delete_authority;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_hooks;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_purge;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_iceberg;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_r2;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_retention;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_writer;
#[cfg(feature = "enterprise")]
pub mod enterprise_shared_writer_retry;
#[cfg(test)]
#[cfg(feature = "enterprise")]
mod enterprise_shared_writer_retry_tests;
pub mod edge_log;
pub mod erasure;
pub mod object_identity;
pub mod shared_mode;
#[cfg(test)]
mod test_heap;
#[cfg(test)]
pub(crate) mod landing_fixture;
pub mod error_log;
pub mod executor;
pub mod generation;
pub mod generation_bundle;
pub mod generation_proof;
pub mod generation_boot;
pub mod hot_tail_cache;
pub mod hot_tail_disk_tier;
pub mod hot_tail_slow_path;
pub mod iceberg;
pub mod ingest_source_counters;
pub mod identity;
pub mod identity_observations;
pub mod cloud_facet_summaries;
pub mod asset_facet_summaries;
pub mod ioc_publish;
pub mod ioc_snapshot_prune;
pub mod internal_domains_snapshot;
pub mod ip_context;
pub mod job;
pub mod job_capacity;
pub mod lake_part_gc;
pub mod native;
pub mod native_dns;
pub mod orphan_temp;
pub mod otel_handoff;
pub mod otel_iceberg;
pub mod otel_lean;
pub mod otel_local;
pub mod otel_metric_catalog;
pub mod part_ingest;
pub mod part_query;
pub mod product_payloads;
pub mod retro_job;
pub mod parts;
pub mod parts_adopt;
pub mod pipeline;
pub mod process_limits;
pub mod planner;
pub mod postgres;
pub mod prevalence;
pub mod prevalence_build;
pub mod prevalence_stamp;
pub mod publisher_disk_budget;
pub mod reader_object_cache;
pub mod producer_cache;
pub mod rest_commit;
pub mod risk;
pub mod rollup;
pub mod sidecar;
pub mod tail_ledger;
pub mod tenant_object_cache;
pub mod text_sidecar;
pub mod verify;
pub mod worker_identity;

pub mod r2_ops;

pub mod query_timing;
pub mod thread_budget;
#[cfg(test)]
mod query_capacity_native_tests;
pub mod perf_overrides;



pub mod writer_reclaim;

pub mod tail_predicate;

#[cfg(test)]
mod nan4831_profile;
