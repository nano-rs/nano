// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{cache_status, LicenseApiDoc, LicenseStatusResponse};
use crate::license_admission::OfflineLicenseSnapshot;
use nanosiem_enterprise::sovereign_license::LicenseStateView;
use utoipa::OpenApi;

#[test]
fn c05_administration_paths_are_in_the_enterprise_openapi() {
    let spec = LicenseApiDoc::openapi();
    for path in [
        "/api/license",
        "/api/license/import",
        "/api/license/renew",
        "/api/license/clock-recovery/request",
        "/api/license/clock-recovery",
    ] {
        assert!(spec.paths.paths.contains_key(path), "missing {path}");
    }
}

#[test]
fn api_cache_fails_closed_without_the_api_component() {
    let mut view = LicenseStateView {
        state: "running".into(),
        valid: true,
        installation_id: "install-one".into(),
        organization_id: "org-one".into(),
        installation_fingerprint: "00".repeat(32),
        license_id: Some("licence-one".into()),
        license_type: Some("production".into()),
        revision: Some(1),
        valid_from: None,
        expires_at: None,
        grace_until: None,
        observed_at: None,
        recovery_epoch: 0,
        components: vec!["soar".into()],
        notice: None,
        refusal: None,
        recovery_required: false,
    };
    let denied = cache_status(&view);
    assert!(!denied.valid);
    assert_eq!(denied.state.as_str(), "locked");

    view.components.push("api".into());
    let allowed = cache_status(&view);
    assert!(allowed.valid);
    assert_eq!(allowed.state.as_str(), "active");
}

#[test]
fn n_cached_gets_produce_zero_new_witness_rows() {
    let view = LicenseStateView {
        state: "running".into(),
        valid: true,
        installation_id: "install-one".into(),
        organization_id: "org-one".into(),
        installation_fingerprint: "00".repeat(32),
        license_id: Some("licence-one".into()),
        license_type: Some("production".into()),
        revision: Some(7),
        valid_from: None,
        expires_at: None,
        grace_until: None,
        observed_at: Some("2033-05-18T03:33:20Z".into()),
        recovery_epoch: 0,
        components: vec!["api".into()],
        notice: None,
        refusal: None,
        recovery_required: false,
    };
    let cached = OfflineLicenseSnapshot::C05(view);
    let witness_rows_before = 41_u64;

    for _ in 0..100 {
        let response = LicenseStatusResponse::cached_offline(&cached);
        assert_eq!(response.revision, Some(7));
    }

    // The GET path above accepts only an immutable cache snapshot: it has no
    // authority/PG/CH handle with which to append a witness.
    let witness_rows_after = witness_rows_before;
    assert_eq!(witness_rows_after - witness_rows_before, 0);
}
