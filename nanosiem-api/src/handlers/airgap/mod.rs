// SPDX-License-Identifier: AGPL-3.0-or-later

//! Air-gapped deployment import handlers (NAN-1201).
//!
//! Enterprise-only surface for side-loading signed offline bundles into a
//! zero-egress install. The parent `pub mod airgap;` declaration in
//! `handlers/mod.rs` is `#[cfg(feature = "enterprise")]`, so this whole subtree
//! compiles only in the enterprise edition.
//!
//!  - [`parsers`]    — signed parser bundle → log sources + Vector deploy (NAN-1204)
//!  - [`enrichment`] — signed IP geo/ASN + IOC bundles → ClickHouse dicts (NAN-1205)
//!  - [`license`]    — signed offline license bundle → local license mode (NAN-1206)
//!  - [`rules`]      — signed rule bundle → detection rules (NAN-1220)
//!  - [`playbooks`]  — signed playbook bundle → playbook library (NAN-1220)

pub mod enrichment;
pub mod license;
pub mod parsers;
pub mod playbooks;
pub mod rules;
