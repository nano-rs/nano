// SPDX-License-Identifier: AGPL-3.0-or-later

//! The pull-feed runner service (NAN-4914 phase 4, single-tenant port of
//! main's NAN-3490 / NAN-3743 dedicated runner): runs bundled connector specs
//! as scheduled feeds and delivers their events to the local Vector.
//!
//! ```text
//!  FeedStore::claim_due (lease + generation, FOR UPDATE SKIP LOCKED;
//!        │                the bound credential is opened here)
//!        ▼  (concurrency budget permits)
//!  Runner::run_claimed ─► engine::run ─► HecSink (POST to Vector HEC,
//!        │                              then poll the ack)
//!        │                     │
//!        │                     ▼  only after the acknowledgement
//!        │              FencedCheckpoints::save ─► FeedStore::save_checkpoint
//!        ▼                                         (fenced on the lease)
//!  FeedStore::finish (next run, backoff, run record) + metrics + audit line
//! ```
//!
//! Invariants:
//! - A stream's cursor is written only after every event read before it got
//!   an ingest acknowledgement. A crash between the POST and its ack re-sends
//!   the page on the next run: at-least-once, no gap. Checkpoints live in
//!   PostgreSQL, so they survive runner restarts.
//! - Every checkpoint write and the run outcome are fenced on the claim's
//!   `lease_generation`; a runner that lost its lease (another replica, a
//!   pause, a reset, a removal) cannot move a cursor.
//! - Ingest 429/5xx back off and retry inside the run; when the retry budget
//!   is spent the run fails without advancing the cursor.
//! - A new stream starts point-forward (`now − 5 min`, NAN-3697); there is no
//!   backfill.
//! - The spec is a reviewed bundled spec pinned on the feed by sha256; the
//!   ingest destination is the runner's configuration ([`ingest`]), never a
//!   feed's input.

pub mod admin;
pub mod directory;
pub mod feed;
pub mod hec;
pub mod ingest;
pub mod pg;
pub mod reset;
pub mod runner;
pub mod store;

pub use feed::{ClaimedFeed, FeedDefinition, RunRecord, RunStatus, Secret};
pub use hec::{EmitStats, HecConfig, HecSink};
pub use ingest::{IngestRoute, StaticIngest};
pub use runner::{Runner, RunnerConfig, TickSummary};
pub use store::{FeedStore, MemoryFeedStore, StoreError};
