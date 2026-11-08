// SPDX-License-Identifier: AGPL-3.0-or-later

//! Detection-as-code push target endpoint handlers (NAN-1745).
//!
//! CRUD over the customer's configured GitHub repo + write-only token + a
//! connectivity/permission probe. The AI-tuning side that actually opens PRs
//! lives in `nanosiem_core::detection_code_target` and the tuning triggers.

mod crud;
mod test;
pub mod types;

pub use crud::*;
pub use test::*;
pub use types::*;

use nanosiem_core::detection_code_target::{
    DetectionCodeTarget, DetectionCodeTargetError, DetectionCodeTargetRepository,
};

use super::AuditExt;
use crate::{error::ApiError, state::AppState};

/// Build the push-target repository from app state, reusing the shared
/// encryption service (same key material as the rest of the app).
pub(crate) fn get_target_repo(state: &AppState) -> DetectionCodeTargetRepository {
    DetectionCodeTargetRepository::with_crypto(
        state.pool.clone(),
        (*state.encryption_service).clone(),
    )
}

/// Map repository errors to API errors.
pub(crate) fn map_target_err(e: DetectionCodeTargetError) -> ApiError {
    match e {
        DetectionCodeTargetError::NotFound(id) => {
            ApiError::NotFound(format!("Push target not found: {id}"))
        }
        DetectionCodeTargetError::DuplicateName(name) => {
            ApiError::Conflict(format!("A push target named '{name}' already exists"))
        }
        DetectionCodeTargetError::InUse(id) => ApiError::Conflict(format!(
            "Push target {id} is claimed by an actionable tuning PR operation; retry or reject that proposal first"
        )),
        DetectionCodeTargetError::Encryption(msg) => {
            ApiError::InternalError(format!("Encryption error: {msg}"))
        }
        DetectionCodeTargetError::Database(e) => {
            ApiError::InternalError(format!("Database error: {e}"))
        }
    }
}

/// OpenAPI documentation for detection-as-code push target endpoints.
#[derive(utoipa::OpenApi)]
#[openapi(
    paths(
        list_targets,
        get_target,
        create_target,
        update_target,
        delete_target,
        set_token,
        test_connection,
    ),
    components(schemas(
        DetectionCodeTarget,
        ListTargetsResponse,
        CreateTargetRequest,
        UpdateTargetRequest,
        SetTokenRequest,
        TestConnectionResponse,
    ))
)]
pub struct DetectionCodeTargetsApiDoc;
