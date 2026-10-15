//! The feed runner service (NAN-3490 lane L1): runs connector specs as
//! scheduled feeds and delivers their events through the tenant's ingress.
//!
//! ```text
//!  FeedStore::tenants ─► per tenant: provision_credentials (feeds with no
//!        │                ingest token yet: NAN-2590 request / reveal, see
//!        │                [`credential`]), then claim_due (lease + generation)
//!        │
//!        ▼  (tenant budget + global budget permits)
//!  Runner::run_claimed ─► engine::run ─► HecSink (POST to the tenant ingress,
//!        │                              per-feed credential; 2xx = receipt)
//!        │                     │
//!        │                     ▼  only after the receipt
//!        │              FencedCheckpoints::save ─► FeedStore::save_checkpoint
//!        ▼                                         (fenced on the lease)
//!  FeedStore::finish (next run, backoff, run record) + metrics + audit line
//! ```
//!
//! Invariants:
//! - A stream's cursor is written only after every event read before it got
//!   an ingress receipt (the engine's checkpoint-after-ack rule, plus
//!   [`hec::HecSink`] returning only on a 2xx). A crash between the POST and
//!   its receipt re-sends the page on the next run: at-least-once, no gap.
//! - Every checkpoint write and the run outcome are fenced on the claim's
//!   `lease_generation`; a runner that lost its lease cannot move a cursor.
//! - Ingress 429/5xx back off and retry inside the run; when the retry
//!   budget is spent the run fails without advancing the cursor.
//! - The tenant comes from the store's tenant inventory, never from a spec,
//!   a feed's config or an event. On hosted-shared every statement runs in
//!   a signed tenant transaction ([`pg::Tenancy::Shared`]).
//! - A hosted feed's ingest token is held only by the platform: requested by
//!   the tenant's worker member with an X25519 reveal key, sealed to that key
//!   by the platform, revealed once and sealed with the deployment cipher in the
//!   same transaction. A feed without a token is never claimed.

pub mod admin;
#[cfg(feature = "enterprise")]
pub mod credential;
pub mod feed;
pub mod hec;
#[cfg(feature = "enterprise")]
pub mod hosted_plan;
pub mod pg;
pub mod reset;
pub mod runner;
pub mod store;

pub use feed::{ClaimedFeed, FeedDefinition, RunRecord, RunStatus, Secret, TenantSlot};
pub use hec::{EmitStats, HecConfig, HecSink};
pub use runner::{Runner, RunnerConfig, TickSummary};
pub use store::{CredentialPass, FeedStore, MemoryFeedStore, PendingDelete, StoreError};
