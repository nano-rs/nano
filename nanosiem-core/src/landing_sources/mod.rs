// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3807: read-only status of OCSF bucket-drop sources (open core).
//!
//! A sender that already maps to OCSF 1.9 (Tenzir) writes files into the
//! install's object store under its source folder; the landing converter
//! records every object it claims in `landing_files`
//! (`migrations/postgres/364_landing_ocsf.sql`). Sources are created and
//! revoked by the `lean-landing-admin` CLI, which holds the object-store
//! admin rights the API does not have, so this module only reads.
//!
//! Neither table holds a secret: the object user's key is never stored and
//! `reason` is a value-free code.

mod repository;

pub use repository::{LandingSourceRepository, LandingSourceRepositoryError};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Most files one `list_files` call returns.
pub const MAX_FILES_LIMIT: i64 = 200;
/// Files returned when the caller gives no limit.
pub const DEFAULT_FILES_LIMIT: i64 = 50;

/// Landing-file states (`landing_files.state`).
pub const FILE_STATES: [&str; 3] = ["claimed", "accepted", "refused"];

/// One bucket-drop source with its file and row totals.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LandingSourceStatus {
    /// The log source id; also the `source=<id>` folder senders write under.
    pub source_id: Uuid,
    /// The log source name.
    pub name: String,
    pub route_key: String,
    /// Credential id of the source's write-only object-store user.
    pub credential_id: Uuid,
    /// `active` or `revoked`.
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub files_accepted: i64,
    pub files_refused: i64,
    /// Files claimed by the converter and not yet finished.
    pub files_in_progress: i64,
    pub rows_accepted: i64,
    pub rows_refused: i64,
    /// Finished files written again with the same etag (deleted, not reconverted).
    pub redeliveries: i64,
    /// When the converter last saw a new file from this source.
    pub last_seen_at: Option<DateTime<Utc>>,
    pub last_finished_at: Option<DateTime<Utc>>,
    /// Value-free reason code of the newest refused file.
    pub last_refusal_reason: Option<String>,
    pub last_refusal_at: Option<DateTime<Utc>>,
}

/// One landed object, as recorded by the converter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct LandingFile {
    pub id: i64,
    pub object_key: String,
    pub etag: String,
    pub source_id: Option<Uuid>,
    pub size_bytes: i64,
    /// `claimed`, `accepted` or `refused`.
    pub state: String,
    pub rows_accepted: i64,
    pub rows_refused: i64,
    /// Value-free reason code (refusals and partial refusals).
    pub reason: Option<String>,
    pub content_sha256: Option<String>,
    /// The bronze object the file was converted into.
    pub bronze_key: Option<String>,
    pub attempts: i32,
    pub redeliveries: i32,
    pub lease_until: Option<DateTime<Utc>>,
    pub first_seen_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
}

/// Clamps a caller-supplied file limit to `1..=MAX_FILES_LIMIT`.
pub fn clamp_files_limit(limit: Option<i64>) -> i64 {
    limit
        .unwrap_or(DEFAULT_FILES_LIMIT)
        .clamp(1, MAX_FILES_LIMIT)
}

/// Whether `state` is a known landing-file state.
pub fn is_file_state(state: &str) -> bool {
    FILE_STATES.contains(&state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_limit_is_clamped() {
        assert_eq!(clamp_files_limit(None), DEFAULT_FILES_LIMIT);
        assert_eq!(clamp_files_limit(Some(0)), 1);
        assert_eq!(clamp_files_limit(Some(-5)), 1);
        assert_eq!(clamp_files_limit(Some(10)), 10);
        assert_eq!(clamp_files_limit(Some(10_000)), MAX_FILES_LIMIT);
    }

    #[test]
    fn file_states_are_the_migration_states() {
        assert!(is_file_state("claimed"));
        assert!(is_file_state("accepted"));
        assert!(is_file_state("refused"));
        assert!(!is_file_state("ACCEPTED"));
        assert!(!is_file_state("deleted"));
    }
}
