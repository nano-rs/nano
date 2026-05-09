// SPDX-License-Identifier: AGPL-3.0-or-later

//! Shared utility functions for the API handlers.

use serde::Serialize;

// `extract_client_ip` and `extract_user_agent` were lifted to
// nanosiem-api-lib (NAN-751). They are re-exported here so existing
// `use crate::utils::*` imports continue to resolve.
pub use nanosiem_api_lib::{extract_client_ip, extract_user_agent};

/// Response for bulk operations (used by alerts, cases, etc.)
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct BulkResponse {
    pub affected: usize,
}
