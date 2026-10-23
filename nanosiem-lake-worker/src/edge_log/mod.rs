// SPDX-License-Identifier: AGPL-3.0-or-later

//! ingest[T]'s consumer of the tenant edge log (NAN-2874, NAN-2865 edge lever).
//!
//! The tenant Worker's Container Vector sink appends each batch to the
//! tenant's edge-log Durable Object instead of writing a Bronze R2 object
//! (`NANO_EDGE_LOG_MODE=do`). ingest[T] pulls those batches through
//! `/edge-log/v1/*` with its own tenant-scoped credential, writes L0 parts,
//! and commits the consumed range after the part log's `add` entry lands.
//!
//! - [`protocol`]: wire types and the verified pull decoding.
//! - [`client`]: the transport trait and the HTTPS client.
//! - [`source`]: [`source::EdgeLogSource`], what ingest[T] calls.
//!
//! Design: `docs-internal/NAN-2865-edge-direct-design.md`; provenance:
//! part contract section 4.1.1.

pub mod backlog;
pub mod client;
pub mod protocol;
pub mod source;

pub use client::{EdgeLogTransport, HttpEdgeLogClient};
pub use protocol::{CommitOutcome, CommitRequest, Lease, PullBatch, PullOutcome, Segment};
pub use source::{EdgeAck, EdgeLogFenced, EdgeLogSource, EdgeLogSourceConfig, EdgeLogStatus, EdgeNotice, EdgePointRequest};

#[cfg(test)]
mod tests;
