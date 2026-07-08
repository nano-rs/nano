// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection-as-Code push target (NAN-1745).
//!
//! Lets a customer register **their** detection-as-code GitHub repo as a write
//! destination. When AI tuning produces a change for a rule, nano opens a Pull
//! Request in that repo for review instead of mutating `detection_rules`
//! directly — the customer's own DaC pipeline redeploys the rule to nano after
//! they merge.
//!
//! This is the reverse direction of [`crate::rule_repository`], which is a
//! read-only, unauthenticated PULL feed. Here the GitHub PAT is stored
//! encrypted and the client makes authenticated write calls.
//!
//! ```text
//!   detection_rules ──tuned──► serializer ──► GitHub write client ──► PR
//!        (nano)                (nPL file)      (create branch,        (customer
//!                                               put file, open PR)     repo, review)
//! ```

mod github_write;
mod models;
mod push_service;
mod repository;
mod serializer;
mod validation;

pub use github_write::{GitHubWriteClient, GitHubWriteError, OpenedPr};
pub use models::{DetectionCodeTarget, NewDetectionCodeTarget, UpdateDetectionCodeTarget};
pub use push_service::{DetectionCodePushService, PushError};
pub use repository::{DetectionCodeTargetError, DetectionCodeTargetRepository};
pub use serializer::{serialize_rule_to_npl, SerializeError};
pub use validation::{
    validate_git_ref, validate_path_template, validate_ref_prefix, TargetValidationError,
};
