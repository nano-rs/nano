//! Shared pagination resolution.
//!
//! Many list endpoints across `nanosiem-api` and `nanosiem-enterprise` accept a
//! `limit` + `offset` pair on the query string. Historically each handler
//! re-declared its own `ListXxxQuery { limit, offset }` and re-implemented the
//! clamp/default inline — and those clamps **drifted**: different defaults,
//! different caps, and different lower-bound conventions. See NAN-1619.
//!
//! This type centralizes the *clamp mechanics*. It deliberately does **not**
//! unify the per-endpoint default/cap *values* — each call site passes its own
//! `(default, max)` so behavior is byte-identical to the inline clamp it
//! replaced. Reconciling the drifting caps is a separate decision (tracked as a
//! follow-up to NAN-1619).
//!
//! ## Why the struct is not flattened into the query structs
//!
//! The natural refactor would be `#[serde(flatten)] pagination: Pagination` on
//! each `ListXxxQuery`. That is **not viable** for axum query parameters:
//!
//! - `serde_urlencoded` (what `axum::extract::Query` uses) does not support
//!   `#[serde(flatten)]` — it fails at runtime with a type error because the
//!   flatten buffer loses urlencoded's string→number coercion.
//! - utoipa's `IntoParams` renders a flattened nested struct as a single
//!   object `$ref` query parameter rather than expanding it into separate
//!   `limit` / `offset` parameters, which would change the OpenAPI spec.
//!
//! So each endpoint keeps its own inline `limit` / `offset` fields (OpenAPI and
//! runtime deserialization unchanged) and only the resolution logic is shared,
//! via the three constructors below — one per clamp convention found in the
//! codebase.
//!
//! ## The three clamp conventions
//!
//! | method | limit | offset |
//! |--------|-------|--------|
//! | [`Pagination::resolved`] | `unwrap_or(default).clamp(1, max)` | `unwrap_or(0).max(0)` |
//! | [`Pagination::resolved_capped`] | `unwrap_or(default).min(max)` | `unwrap_or(0)` |
//! | [`Pagination::resolved_capped_floored_offset`] | `unwrap_or(default).min(max)` | `unwrap_or(0).max(0)` |

use serde::Deserialize;

/// Shared `limit` + `offset` pagination pair plus the clamp conventions used
/// across the API.
///
/// Construct one from a handler's inline query fields with [`Pagination::new`]
/// and resolve via [`resolved`](Pagination::resolved),
/// [`resolved_capped`](Pagination::resolved_capped), or
/// [`resolved_capped_floored_offset`](Pagination::resolved_capped_floored_offset),
/// passing that endpoint's own default and maximum so behavior is unchanged.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct Pagination {
    /// Maximum number of results to return.
    pub limit: Option<i64>,
    /// Number of results to skip.
    pub offset: Option<i64>,
}

impl Pagination {
    /// Build from a handler's inline `limit` / `offset` query fields.
    pub fn new(limit: Option<i64>, offset: Option<i64>) -> Self {
        Self { limit, offset }
    }

    /// Resolve flooring the limit at 1 and the offset at 0.
    ///
    /// Reproduces `limit.unwrap_or(default).clamp(1, max)` +
    /// `offset.unwrap_or(0).max(0)`.
    pub fn resolved(&self, default: i64, max: i64) -> (i64, i64) {
        let limit = self.limit.unwrap_or(default).clamp(1, max);
        let offset = self.offset.unwrap_or(0).max(0);
        (limit, offset)
    }

    /// Resolve upper-bounding the limit only (no lower floor) and passing the
    /// offset through unfloored.
    ///
    /// Reproduces `limit.unwrap_or(default).min(max)` + `offset.unwrap_or(0)`.
    pub fn resolved_capped(&self, default: i64, max: i64) -> (i64, i64) {
        let limit = self.limit.unwrap_or(default).min(max);
        let offset = self.offset.unwrap_or(0);
        (limit, offset)
    }

    /// Resolve upper-bounding the limit only (no lower floor) but flooring the
    /// offset at 0.
    ///
    /// Reproduces `limit.unwrap_or(default).min(max)` +
    /// `offset.unwrap_or(0).max(0)`.
    pub fn resolved_capped_floored_offset(&self, default: i64, max: i64) -> (i64, i64) {
        let limit = self.limit.unwrap_or(default).min(max);
        let offset = self.offset.unwrap_or(0).max(0);
        (limit, offset)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(limit: Option<i64>, offset: Option<i64>) -> Pagination {
        Pagination::new(limit, offset)
    }

    #[test]
    fn resolved_clamps_limit_and_floors_offset() {
        assert_eq!(p(None, None).resolved(50, 100), (50, 0));
        assert_eq!(p(Some(500), None).resolved(50, 100), (100, 0)); // upper cap
        assert_eq!(p(Some(0), None).resolved(50, 100), (1, 0)); // lower floor 1
        assert_eq!(p(Some(-5), None).resolved(50, 100), (1, 0));
        assert_eq!(p(None, Some(-9)).resolved(50, 100), (50, 0)); // offset floored
        assert_eq!(p(None, Some(20)).resolved(50, 100), (50, 20));
    }

    #[test]
    fn resolved_capped_caps_limit_only() {
        assert_eq!(p(None, None).resolved_capped(50, 100), (50, 0));
        assert_eq!(p(Some(500), None).resolved_capped(50, 100), (100, 0)); // upper cap
        assert_eq!(p(Some(0), None).resolved_capped(50, 100), (0, 0)); // NO lower floor
        assert_eq!(p(Some(-5), None).resolved_capped(50, 100), (-5, 0));
        assert_eq!(p(None, Some(-9)).resolved_capped(50, 100), (50, -9)); // offset NOT floored
        assert_eq!(p(None, Some(20)).resolved_capped(50, 100), (50, 20));
    }

    #[test]
    fn resolved_capped_floored_offset_caps_limit_floors_offset() {
        assert_eq!(p(None, None).resolved_capped_floored_offset(25, 100), (25, 0));
        assert_eq!(
            p(Some(500), None).resolved_capped_floored_offset(25, 100),
            (100, 0)
        ); // upper cap
        assert_eq!(
            p(Some(0), None).resolved_capped_floored_offset(25, 100),
            (0, 0)
        ); // NO lower floor on limit
        assert_eq!(
            p(None, Some(-9)).resolved_capped_floored_offset(25, 100),
            (25, 0)
        ); // offset floored
        assert_eq!(
            p(None, Some(20)).resolved_capped_floored_offset(25, 100),
            (25, 20)
        );
    }
}
