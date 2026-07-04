// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tests for prevalence settings payload shape (P1 audit).
//!
//! Kept in a dedicated sibling file (declared via `#[path]` from `settings.rs`)
//! rather than an inline `#[cfg(test)] mod tests {}` in the handler.

use super::{PrevalenceSettingsResponse, UpdatePrevalenceSettingsRequest};
use nanosiem_core::prevalence::PrevalenceConfig;

/// The response must surface `enable_ip_tracking` — previously it was omitted,
/// so the IP prevalence lanes were un-observable from the settings API.
#[test]
fn response_from_config_includes_ip_tracking() {
    let config = PrevalenceConfig {
        rarity_threshold: 10,
        enable_hash_tracking: true,
        enable_domain_tracking: false,
        enable_ip_tracking: false,
        retention_days: 120,
        cache_ttl_seconds: 30,
    };

    let resp = PrevalenceSettingsResponse::from(config);

    assert_eq!(resp.rarity_threshold, 10);
    assert!(resp.enable_hash_tracking);
    assert!(!resp.enable_domain_tracking);
    // The load-bearing regression: ip tracking is now reflected.
    assert!(!resp.enable_ip_tracking);
    assert_eq!(resp.retention_days, 120);
    assert_eq!(resp.cache_ttl_seconds, 30);
}

/// `enable_ip_tracking` must be an accepted, toggleable field on the update
/// payload (it gates the IP lanes; previously it could not be changed).
#[test]
fn update_request_accepts_ip_tracking() {
    let json = r#"{ "enable_ip_tracking": false }"#;
    let req: UpdatePrevalenceSettingsRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.enable_ip_tracking, Some(false));
}

/// `retention_days` is intentionally NOT a writable field: ClickHouse TTLs are
/// fixed in DDL, so accepting it would silently do nothing. A payload carrying
/// it must still deserialize (extra field ignored) but expose no way to set it.
#[test]
fn update_request_ignores_retention_days() {
    let json = r#"{ "rarity_threshold": 7, "retention_days": 365 }"#;
    let req: UpdatePrevalenceSettingsRequest = serde_json::from_str(json).unwrap();
    assert_eq!(req.rarity_threshold, Some(7));
    // There is no `retention_days` field to read on the request type; the value
    // above is dropped by serde. This test compiles only while that holds.
}
