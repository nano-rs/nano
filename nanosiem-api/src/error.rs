// SPDX-License-Identifier: AGPL-3.0-or-later

//! API error types and handling
//!
//! `ApiError` and most `From` impls (the ones that only reference
//! `nanosiem-core` types) live in `nanosiem-api-lib` so the enterprise
//! handler crate can return the same type without depending on `nanosiem-api`
//! (which would create a circular dependency). NAN-752 lifted them.
//!
//! `From` impls that reference enterprise-tier error types
//! (`nanosiem_enterprise::CaseServiceError` etc.) live in the
//! `nanosiem-enterprise` crate to satisfy the orphan rule. They're applied
//! automatically when `nanosiem-enterprise` is linked.

pub use nanosiem_api_lib::{ApiError, ErrorDetail, ErrorResponse};
