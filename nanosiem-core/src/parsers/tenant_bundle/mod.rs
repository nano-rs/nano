// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-tenant parser bundles for hosted-shared tenants (NAN-2604).
//!
//! A tenant bundle is the release-pinned platform Vector config (the base)
//! plus a tenant overlay generated from the tenant's published parsers by the
//! open-core generator. This module is the pure half of the bundle build Job:
//!
//! * [`overlay::apply_overlay`] — base + published sources → candidate tree;
//! * [`overlay::verify_against_base`] — the structural guard, usable on any
//!   bundle (platform bytes identical, overlay confined to tenant parser
//!   components, no blocked VRL, no metadata writes, no interpolation);
//! * [`archive`] — deterministic, bounded gzip-tar;
//! * [`build`] — the Job's `generate` and `finalize` stages around the
//!   sandboxed `vector validate` / `vector test` run in the cell's own image.
//!
//! Job image, entrypoint and renderable templates live in
//! `deploy/parser-bundle-build/`.

pub mod archive;
pub mod bronze_buffer_bytes;
pub mod bronze_row_contract;
pub mod build;
pub mod diff;
pub mod model;
pub mod overlay;
pub mod platform_audit_lane;
pub mod pull;
pub mod scan;
pub mod source_ack;
pub mod vector_tests;

#[cfg(test)]
mod pull_tests;
#[cfg(test)]
mod pull_capture_tests;
#[cfg(test)]
mod pull_runtime_tests;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod pipe_native_tests;
#[cfg(test)]
mod pipe_metadata_tests;
#[cfg(test)]
mod pipe_input_tests;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TenantBundleError {
    #[error("invalid build input: {0}")]
    Input(String),
    #[error("platform base is unusable: {0}")]
    Base(String),
    #[error("{message}")]
    Overlay {
        /// The tenant source slug the refusal concerns, when there is one.
        slug: Option<String>,
        message: String,
    },
    #[error("bundle archive: {0}")]
    Archive(String),
    #[error("io: {0}")]
    Io(String),
}
