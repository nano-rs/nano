// SPDX-License-Identifier: AGPL-3.0-or-later
//! nano content channels (NAN-4955): every built-in content pull comes from
//! the app as a signed content bundle. No install fetches built-in content
//! from GitHub, in the open edition as in enterprise.
//!
//! - [`channels`]: the compiled-in channel registry (repo @ branch → channel
//!   id, route, subscribers). Unknown channels are refused everywhere.
//! - [`contract`]: the `NANCONT1` container and its Ed25519 descriptor (the
//!   NAN-4759 portable contract's pieces under a content signing domain).
//! - [`tree`]: the deterministic payload (gzip'd tar, git blob SHA-1 ids).
//! - [`store`]: installed snapshots in PostgreSQL (migration 309).
//! - [`source`]: first-party repository reads served from the snapshots
//!   (`GitHubClient` and the marketplace sync call it instead of GitHub).
//! - [`consumer`]: fetch → verify → accept → install → apply; leader-only
//!   schedule, check now, air-gap import.
//!
//! Bundles are produced by the app (app.nano.rs), not by any install.

pub mod channels;
#[cfg(unix)]
pub mod consumer;
#[cfg(nano_content_acceptance)]
mod content_acceptance_root;
pub mod contract;
pub mod source;
pub mod store;
pub mod tree;
