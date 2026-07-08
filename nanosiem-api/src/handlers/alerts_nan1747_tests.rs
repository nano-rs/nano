// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-1747 pure-logic tests for the alerts handler: the page-limit / offset
//! clamps (A10) and the assignment typeid parse (A3). Kept in a sibling file
//! per the repo convention (tests in dedicated files, not large inline modules).

use super::{clamp_offset, clamp_page_limit};

#[test]
fn clamp_page_limit_floors_zero_and_negatives_to_one() {
    // The A10 bug: limit=0 → empty page with has_more=true → infinite SOAR loop;
    // negative → LIMIT -1 → 500. Both must floor to 1.
    assert_eq!(clamp_page_limit(0), 1);
    assert_eq!(clamp_page_limit(-5), 1);
    assert_eq!(clamp_page_limit(i64::MIN), 1);
}

#[test]
fn clamp_page_limit_caps_at_1000() {
    assert_eq!(clamp_page_limit(1001), 1000);
    assert_eq!(clamp_page_limit(i64::MAX), 1000);
}

#[test]
fn clamp_page_limit_passes_through_in_range() {
    assert_eq!(clamp_page_limit(1), 1);
    assert_eq!(clamp_page_limit(100), 100);
    assert_eq!(clamp_page_limit(1000), 1000);
}

#[test]
fn clamp_offset_floors_negatives_to_zero() {
    assert_eq!(clamp_offset(-1), 0);
    assert_eq!(clamp_offset(i64::MIN), 0);
    assert_eq!(clamp_offset(0), 0);
    assert_eq!(clamp_offset(250), 250);
}

#[test]
fn assign_parse_accepts_typeid_and_raw_uuid() {
    // A3: the FE sends a user typeid (`user_<base32>`). `Uuid::parse_str` rejects
    // it (the old bug); `parse_any` must accept BOTH the typeid and raw-UUID
    // forms and yield the same underlying UUID.
    let raw = uuid::Uuid::new_v4();
    let typeid = nanosiem_core::typeid::encode("user", &raw);
    assert!(
        uuid::Uuid::parse_str(&typeid).is_err(),
        "sanity: the typeid form is NOT a parseable UUID (this is the A3 bug)"
    );

    let (_, from_typeid) = nanosiem_core::typeid::parse_any(&typeid)
        .expect("parse_any must accept the typeid form");
    assert_eq!(from_typeid, raw);

    let (_, from_uuid) = nanosiem_core::typeid::parse_any(&raw.to_string())
        .expect("parse_any must accept the raw-UUID form");
    assert_eq!(from_uuid, raw);
}
