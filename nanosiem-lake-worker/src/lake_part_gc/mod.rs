// SPDX-License-Identifier: AGPL-3.0-or-later

//! Lean-lake part GC executor (NAN-2879, contract section 6.4).
//!
//! The executor holds no R2 delete credential. For every file it wants gone
//! it asks the owner for a `lake_part_delete` permit (the owner has control
//! attest the evidence against its complete index of the part log), verifies
//! the permit locally, then has the tenant Worker's retention authority fence
//! re-creation, delete, and append an absence receipt. Only an exact receipt
//! counts as a delete.
//!
//! - [`request`]: [`LakePartDeleteRequest`], its validation and permit id.
//! - [`planner`]: the verified log view and the pure planner [`plan`].
//! - [`index`]: the control part-log index sync (`lake-part-log:index`).
//! - [`executor`]: [`run_pass`], [`execute`] and the refusal policy.
//! - [`store_reader`]: the part-log reader over the tenant's part store.
//! - [`delete_control`]: the delete-control wire contract.
//! - [`quarantine_expiry`]: NAN-4567, expired bronze quarantine keys.
//! - `http` (hosted build only): the owner / Worker HTTP implementations of
//!   the seams.

pub mod delete_control;
pub mod executor;
#[cfg(feature = "enterprise")]
pub mod http;
pub mod index;
pub(crate) mod history;
pub mod local;
pub mod local_bronze;
pub mod planner;
pub mod quarantine_expiry;
pub mod receipt_backfill;
pub mod receipt_reconcile_exchange;
pub mod request;
pub mod store_reader;

pub use executor::{
    execute, run_pass, CatalogCustodyHeld, LakePartDeleteAuthority, LakePartGcState, PassInput, LakePartDeletePermit, LakePartDeleteReceipt, LakePartRefusal,
    PassReport, RefusalAction,
};
#[cfg(feature = "enterprise")]
pub use http::{HttpLakePartDeleteAuthority, HttpLakePartIndexClient};
pub use store_reader::StorePartLogReader;
pub use index::{
    catch_up_view, catch_up_view_bounded, report_deleted, sync_index, AdoptedClaim, DeletedKey, CheckpointClaim, IndexStatus, IndexSyncOutcome, LakePartIndexClient, PartLogReader, VerifiedEntryBytes,
};
pub use planner::{live_part_keys, plan, GcPolicy, LakePartLogView, ListedPartObject, PlanReport, Removal, RemovalKind};
pub use request::{parse_part_file_key, LakePartDeleteReason, LakePartDeleteRequest, PartFileKey};

/// Worker capability operation and owner permit operation name.
pub const OPERATION: &str = "lake_part_delete";
/// Owner route that authorizes one delete.
pub const AUTHORIZE_PATH: &str = "/internal/v1/enterprise-shared/lake-part-deletes:authorize";
/// Owner-forwarded control route that indexes the part log.
pub const INDEX_PATH: &str = "/internal/v1/enterprise-shared/lake-part-log:index";
/// Worker routes.
pub const WORKER_CAPABILITIES_PATH: &str = "/admin/retention/capabilities";
pub const WORKER_PREPARE_PATH: &str = "/admin/retention/lake-part/prepare";
pub const WORKER_RETIRE_PATH: &str = "/admin/retention/lake-part/retire";
