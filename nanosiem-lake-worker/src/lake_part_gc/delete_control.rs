// SPDX-License-Identifier: AGPL-3.0-or-later

//! The delete-control wire contract part GC speaks to the tenant Worker's
//! retention authority and the owner (NAN-3861: extracted from the hosted
//! delete broker so open part GC does not depend on it).
//!
//! The values are protocol: the Worker capability handshake compares
//! [`DELETE_CONTROL_SCHEMA_VERSION`] and [`DELETE_CONTROL_CONTRACT`] byte for
//! byte, so they never change with a rename.

use serde::{Deserialize, Serialize};

/// The owner authorization is a short start permit, like the writer's.
pub const DELETE_AUTHORIZATION_MAX_TTL: chrono::Duration = chrono::Duration::minutes(5);
/// Control identity schema this client speaks (wave 4 = 1; wave 6 adds the
/// delete class, erasure block and owner authorization).
pub const DELETE_CONTROL_SCHEMA_VERSION: u8 = 2;
pub const DELETE_CONTROL_CONTRACT: &str = "enterprise_shared_r2_delete_control_v2";

/// The owner's signature over one delete identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteOwnerAuthorization {
    pub schema_version: u8,
    pub signer_key_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub identity_sha256: String,
    pub signature_base64: String,
}
