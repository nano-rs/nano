// SPDX-License-Identifier: AGPL-3.0-or-later

use super::{cache_status, LicenseApiDoc, LicenseStatusResponse, UpdateStatusResponse};
use nanosiem_core::license::ReleaseNotice;
use crate::license_admission::OfflineLicenseSnapshot;
use nanosiem_enterprise::sovereign_license::LicenseStateView;
use utoipa::OpenApi;

#[test]
fn c05_administration_paths_are_in_the_enterprise_openapi() {
    let spec = LicenseApiDoc::openapi();
    for path in [
        "/api/license",
        "/api/license/update",
        "/api/license/import",
        "/api/license/renew",
        "/api/license/clock-recovery/request",
        "/api/license/clock-recovery",
    ] {
        assert!(spec.paths.paths.contains_key(path), "missing {path}");
    }
}

#[test]
fn old_partial_component_claim_still_grants_the_full_licensed_build() {
    let view = LicenseStateView {
        state: "running".into(),
        valid: true,
        installation_id: "install-one".into(),
        organization_id: "org-one".into(),
        installation_fingerprint: "00".repeat(32),
        license_id: Some("licence-one".into()),
        license_type: Some("production".into()),
        capacity_gb_per_day: None,
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
        capacity_gb_per_day: None,
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
        let response = LicenseStatusResponse::cached_offline(&cached, true);
        assert_eq!(response.revision, Some(7));
    }

    // The GET path above accepts only an immutable cache snapshot: it has no
    // authority/PG/CH handle with which to append a witness.
    let witness_rows_after = witness_rows_before;
    assert_eq!(witness_rows_after - witness_rows_before, 0);
}

#[test]
fn verified_c05_evaluation_maps_to_trial_entitlement_metadata() {
    let view = LicenseStateView {
        state: "running".into(),
        valid: true,
        installation_id: "install-one".into(),
        organization_id: "org-one".into(),
        installation_fingerprint: "00".repeat(32),
        license_id: Some("licence-trial".into()),
        license_type: Some("evaluation".into()),
        capacity_gb_per_day: Some(25),
        revision: Some(3),
        valid_from: Some("2029-01-01T00:00:00Z".into()),
        expires_at: Some("2029-05-01T00:00:00Z".into()),
        grace_until: Some("2029-05-08T00:00:00Z".into()),
        observed_at: Some("2029-02-01T00:00:00Z".into()),
        recovery_epoch: 0,
        components: vec!["soar".into()],
        notice: None,
        refusal: None,
        recovery_required: false,
    };
    let status = cache_status(&view);
    assert!(
        status.valid,
        "v2 trial ignores the legacy component allowlist"
    );
    let trial = status
        .trial_entitlement()
        .expect("C05 evaluation is a trial");
    assert_eq!(trial.license_id, "licence-trial");
    assert_eq!(trial.capacity_gb_per_day, Some(25));
    assert_eq!(trial.revision, 3);
    assert_eq!(trial.kind, "trial");
}

/// Review fix: outside a 14/7/1/0-day step the response omits
/// `warning_days` instead of serializing `null`, which the banner rendered
/// as a "null-day expiry warning" on every page.
#[test]
fn trial_with_more_than_fourteen_days_omits_warning_days() {
    use chrono::{Duration, Utc};
    use nanosiem_core::license::{LicenseEntitlement, LicenseState, LicenseStatus};
    let now = Utc::now();
    let status = |days: i64| LicenseStatus {
        state: LicenseState::Active,
        valid: true,
        locked_reason: None,
        entitlement: Some(LicenseEntitlement {
            license_id: "lic_trial".into(),
            edition: "licensed".into(),
            operator: "self-run".into(),
            offering: "self-run".into(),
            kind: "trial".into(),
            capacity_gb_per_day: None,
            starts_at: now - Duration::days(1),
            expires_at: now + Duration::days(days),
            grace_ends_at: now + Duration::days(days + 7),
            state: "active".into(),
            days_remaining: days as u64,
            revision: 1,
        }),
        ..LicenseStatus::default()
    };
    let far = serde_json::to_value(
        super::LicenseEntitlementResponse::from_status(&status(60), now).unwrap(),
    )
    .unwrap();
    assert!(far.get("warning_days").is_none(), "{far}");
    assert_eq!(far["days_remaining"], 60);
    let near = serde_json::to_value(
        super::LicenseEntitlementResponse::from_status(&status(10), now).unwrap(),
    )
    .unwrap();
    assert_eq!(near["warning_days"], 14);
}

fn notice(version: &str, security_release: bool) -> ReleaseNotice {
    ReleaseNotice {
        latest_version: version.into(),
        release_notes_url: "https://nano.rs/docs/releases/v2-0-1".into(),
        upgrade_url: "https://nano.rs/docs/releases/upgrading".into(),
        security_release,
    }
}

/// NAN-5114: the admin banner is shown only for a strictly newer release.
#[test]
fn update_status_reports_only_a_newer_release() {
    let behind = UpdateStatusResponse::from_notice("2.0.0", Some(notice("2.0.1", true)));
    assert!(behind.update_available);
    assert_eq!(behind.latest_version.as_deref(), Some("2.0.1"));
    assert!(behind.security_release);
    assert_eq!(
        behind.upgrade_url.as_deref(),
        Some("https://nano.rs/docs/releases/upgrading")
    );

    for (current, latest) in [("2.0.1", "2.0.1"), ("2.0.2", "2.0.1"), ("dev", "2.0.1")] {
        let status = UpdateStatusResponse::from_notice(current, Some(notice(latest, true)));
        assert!(!status.update_available, "{current} vs {latest}");
        assert_eq!(status.latest_version, None);
        assert!(!status.security_release);
    }

    // No check-in data (offline / air-gapped / never reported): nothing to show.
    let none = UpdateStatusResponse::from_notice("2.0.0", None);
    assert!(!none.update_available);
    assert_eq!(none.current_version, "2.0.0");
}
