// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean-lake cell supervisor (NAN-2871, phase 5 of NAN-2865).
//!
//! A *cell* is a shared pod that runs one `ingest[T]` and one `query[T]`
//! process per **active** tenant, each confined to its own uid, directories,
//! landlock domain, seccomp filter and cgroup. Idle tenants cost ≈0: their
//! processes are reaped after `idle_timeout_secs` and their cgroups removed.
//!
//! - [`contract`]: the supervisor ⇄ tenant-process protocol (phase 2/3 code
//!   against this).
//! - [`child`]: the tenant-side runtime (`bootstrap`, `TenantService`).
//! - [`supervisor`]: spawn / warm pool / reap / limits / status / signals.
//! - [`router`]: the authenticated HTTP front for nanosiem-api/search.
//! - [`tenant_dirs`] (tenant tree under the cell's exact capabilities, and
//!   its purge on placement removal), [`report`] (purge ledger + status push
//!   to the platform, NAN-3000).
//! - [`jail`], [`limits`], [`fdpass`], [`uidmap`], [`secrets`], [`budget`].
//! - [`resources`] (guarantee/burst/ceiling policy), [`watchdog`] (its
//!   `/proc` measurement and enforcement), [`procfs`], [`pidfd`],
//!   [`identity`] (NAN-2872).
//! - [`upstream`]: the egress watchdog behind `/readyz` (NAN-3440).

pub mod budget;
pub mod child;
pub mod config;
pub mod contract;
#[cfg(target_os = "linux")]
pub mod crash_capture;
pub mod disk_ceiling;
pub mod fdpass;
pub mod features;
pub mod handover;
pub mod identity;
pub mod jail;
pub mod limits;
pub mod oom;
pub mod part_channel;
pub mod pidfd;
pub mod policy;
pub mod procfs;
pub mod probe;
pub mod report;
pub mod resources;
pub mod router;
pub mod secrets;
pub mod signals;
pub mod spawn_flight;
pub mod supervisor;
pub mod tenant_token;
pub mod tenant_dirs;
pub mod trusted_local;
pub mod uidmap;
pub mod upstream;
pub mod watchdog;
pub mod volume_usage;

/// Native sealed worker launcher; no hosted behavior change.
pub mod worker_launch;
