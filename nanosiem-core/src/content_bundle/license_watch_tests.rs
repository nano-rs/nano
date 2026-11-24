// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5769: when the leader re-checks the enterprise channels between polls.
use super::*;

fn timing() -> CheckTiming {
    CheckTiming {
        first_check: Duration::from_secs(20),
        licence_probe_min: Duration::from_secs(15),
        licence_probe_max: Duration::from_secs(300),
    }
}

fn fp(byte: u8) -> Fingerprint {
    Some([byte; 32])
}

#[test]
fn defaults_are_the_production_cadence() {
    let t = CheckTiming::default();
    assert_eq!(t.first_check, Duration::from_secs(FIRST_CHECK_SECS));
    assert_eq!(t.licence_probe_min, Duration::from_secs(15));
    assert_eq!(t.licence_probe_max, Duration::from_secs(300));
}

#[test]
fn before_the_first_check_only_a_licensed_signal_checks() {
    let w = EnterpriseWatch::new(timing());
    assert_eq!(w.probe_at(), None);
    assert!(!w.wants_check(fp(1), false), "a probe before the first check: that check is due shortly");
    assert!(!w.wants_check(None, false));
    assert!(!w.wants_check(None, true), "a signal without a license is not a reason to fetch");
    // NAN-5769 review: a deferred first check must not swallow a real import.
    assert!(w.wants_check(fp(1), true), "a license-changed signal with a license checks at once");
}

#[test]
fn a_skip_for_no_license_is_not_clean_and_schedules_a_short_probe() {
    let now = Instant::now();
    let mut w = EnterpriseWatch::new(timing());
    // The skip itself returns Ok (`ok == true`): it still must not count as clean.
    w.checked(None, true, now);
    assert!(!w.clean());
    assert_eq!(w.probe_at(), Some(now + Duration::from_secs(15)), "probe in seconds, not the hourly poll");
}

#[test]
fn a_license_appearing_triggers_a_check_from_a_probe_or_a_signal() {
    let now = Instant::now();
    let mut w = EnterpriseWatch::new(timing());
    w.checked(None, true, now);
    assert!(w.wants_check(fp(1), false), "local probe finds the imported license");
    assert!(w.wants_check(fp(1), true), "license-changed signal");
    assert!(!w.wants_check(None, false), "still unlicensed: no platform request");
    assert!(!w.wants_check(None, true), "a signal without a license is not a reason to fetch");
}

#[test]
fn unlicensed_probes_back_off_to_the_cap_and_stay_local() {
    let now = Instant::now();
    let mut w = EnterpriseWatch::new(timing());
    w.checked(None, true, now);
    let mut gaps = vec![w.probe_at().unwrap() - now];
    for _ in 0..8 {
        assert!(!w.wants_check(None, false));
        w.idle(now);
        gaps.push(w.probe_at().unwrap() - now);
    }
    let secs: Vec<u64> = gaps.iter().map(Duration::as_secs).collect();
    assert_eq!(secs, vec![15, 30, 60, 120, 240, 300, 300, 300, 300]);
    // The hourly check, still unlicensed, keeps the backed-off cadence.
    w.checked(None, true, now);
    assert_eq!(w.probe_at(), Some(now + Duration::from_secs(300)));
}

#[test]
fn a_licensed_clean_check_stops_probing_and_ignores_unchanged_signals() {
    let now = Instant::now();
    let mut w = EnterpriseWatch::new(timing());
    w.checked(None, true, now);
    w.checked(fp(1), true, now);
    assert!(w.clean());
    assert_eq!(w.probe_at(), None);
    assert!(!w.wants_check(fp(1), true), "same license, clean: nothing to do");
    assert!(w.wants_check(fp(2), true), "a renewal is checked at once");
    w.idle(now);
    assert_eq!(w.probe_at(), None);
}

#[test]
fn a_signal_retries_a_failed_licensed_check_but_a_probe_does_not() {
    let now = Instant::now();
    let mut w = EnterpriseWatch::new(timing());
    w.checked(fp(1), false, now); // e.g. HTTP 403 before the check-in admitted the install
    assert!(!w.clean());
    assert!(w.wants_check(fp(1), true), "check-in newly admitted the install");
    assert!(!w.wants_check(fp(1), false), "a probe never re-fetches an unchanged credential");
}

#[test]
fn a_deferred_check_is_retried_at_the_probe_cadence() {
    let now = Instant::now();
    let mut w = EnterpriseWatch::new(timing());
    w.checked(None, true, now);
    w.idle(now); // probes at 15 s, then 30 s; the next gap is 60 s
    w.retry_later(now);
    assert_eq!(w.probe_at(), Some(now + Duration::from_secs(60)));
    assert!(w.wants_check(fp(1), false), "the license is still new to the watch");
}

#[test]
fn fingerprints_distinguish_credentials_and_absence() {
    let lic = |b: &[u8]| -> Result<(DistributionCredential, CredentialOrigin), String> {
        Ok((DistributionCredential::SignedLicense(b.to_vec()), CredentialOrigin::Installed))
    };
    let enrolled = |token: &str| -> Result<(DistributionCredential, CredentialOrigin), String> {
        Ok((
            DistributionCredential::Enrollment {
                deployment_id: "d".into(),
                token: token.into(),
                licence_origin: "https://api.nano.rs".into(),
            },
            CredentialOrigin::Online,
        ))
    };
    assert_eq!(fingerprint(&Err("none".into())), None);
    assert!(fingerprint(&lic(b"a")).is_some());
    assert_eq!(fingerprint(&lic(b"a")), fingerprint(&lic(b"a")));
    assert_ne!(fingerprint(&lic(b"a")), fingerprint(&lic(b"b")));
    assert_ne!(fingerprint(&enrolled("t1")), fingerprint(&enrolled("t2")));
}

#[test]
fn a_busy_lease_backs_off_from_seconds_to_the_retry_cap_and_resets() {
    let mut b = Backoff::new(Duration::from_secs(15), Duration::from_secs(300));
    let secs: Vec<u64> = (0..7).map(|_| b.next_delay().as_secs()).collect();
    assert_eq!(secs, vec![15, 30, 60, 120, 240, 300, 300]);
    b.reset();
    assert_eq!(b.next_delay(), Duration::from_secs(15));
}
