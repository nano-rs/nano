// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5029: an API key managing itself may only TIGHTEN its own expiry and
//! rate limit. Clearing, extending or raising either needs a session.

use super::self_update_is_tightening;
use chrono::{Duration, Utc};

#[test]
fn absent_fields_always_pass() {
    assert!(self_update_is_tightening(Some(Utc::now()), Some(10), None, None).is_ok());
    assert!(self_update_is_tightening(None, None, None, None).is_ok());
}

#[test]
fn a_key_cannot_remove_its_own_expiry() {
    let err = self_update_is_tightening(Some(Utc::now()), None, Some(None), None).unwrap_err();
    assert!(err.contains("expiry"));
}

#[test]
fn a_key_cannot_remove_its_own_rate_limit() {
    let err = self_update_is_tightening(None, Some(60), None, Some(None)).unwrap_err();
    assert!(err.contains("rate limit"));
}

#[test]
fn a_key_cannot_extend_its_own_expiry() {
    let now = Utc::now();
    assert!(self_update_is_tightening(Some(now), None, Some(Some(now + Duration::days(30))), None).is_err());
}

#[test]
fn a_key_cannot_raise_its_own_rate_limit() {
    assert!(self_update_is_tightening(None, Some(60), None, Some(Some(61))).is_err());
}

#[test]
fn a_key_may_shorten_its_expiry_or_lower_its_limit() {
    let now = Utc::now();
    assert!(self_update_is_tightening(
        Some(now + Duration::days(30)),
        Some(60),
        Some(Some(now + Duration::days(1))),
        Some(Some(10)),
    )
    .is_ok());
}

#[test]
fn a_key_without_expiry_or_limit_may_set_one() {
    // Setting a first expiry / limit is a tightening.
    assert!(self_update_is_tightening(
        None,
        None,
        Some(Some(Utc::now() + Duration::days(7))),
        Some(Some(100)),
    )
    .is_ok());
}
