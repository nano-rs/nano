// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5770: the Unassigned list offered a just-deleted source's route key as
//! a new stream ("arriving · no source"). The key is set aside only under the
//! NAN-5760 rules (tombstone, literal non-reserved key, no live claim, events
//! from before the delete and none after it); a key that keeps arriving after
//! the delete is still offered.

use std::collections::HashMap;

use chrono::{DateTime, Duration, TimeZone, Utc};

use super::connect::*;
use crate::siem_health::removed_sources::{RemovedSourceKeys, Tombstone, LATE_ARRIVAL_GRACE_SECS};

fn deleted_at() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 20, 12, 0, 0).unwrap()
}

fn seen(key: &str, first: DateTime<Utc>, last: DateTime<Utc>) -> SourceActivity {
    SourceActivity { route_key: key.into(), events_24h: 2, first_seen: Some(first), last_seen: Some(last) }
}

fn tombstone(name: &str, values: Option<&[&str]>) -> Tombstone {
    Tombstone {
        name: name.into(),
        match_values: values.map(|v| v.iter().map(|s| s.to_string()).collect()),
        deleted_at: deleted_at(),
    }
}

/// The handler's pipeline minus I/O: candidates, evidence from the same
/// activity, then the split.
fn split(
    tombstones: &[Tombstone],
    live: &[(Option<Vec<String>>, String)],
    activity: &[SourceActivity],
) -> (Vec<UnassignedSource>, Vec<RemovedUnassignedSource>) {
    let mut removed = RemovedSourceKeys::from_parts(
        tombstones,
        live.iter().map(|(v, n)| (v.as_deref(), n.as_str())),
        std::iter::empty(),
    );
    removed.retain_evidenced(&activity_evidence(activity));
    set_aside_removed(unassigned_sources(&[], activity), &removed)
}

fn keys(list: &[UnassignedSource]) -> Vec<&str> {
    list.iter().map(|s| s.route_key.as_str()).collect()
}

#[test]
fn a_deleted_sources_quiet_key_is_set_aside_as_removed() {
    let before = deleted_at() - Duration::minutes(30);
    let activity = [
        seen("e2e_0e0caa2a98", before, before + Duration::minutes(1)),
        seen("fresh_sender", before, deleted_at() + Duration::hours(1)),
    ];
    let (offered, removed) = split(&[tombstone("e2e source", Some(&["e2e_0e0caa2a98"]))], &[], &activity);
    assert_eq!(keys(&offered), ["fresh_sender"]);
    assert_eq!(removed.len(), 1);
    assert_eq!(removed[0].route_key, "e2e_0e0caa2a98");
    assert_eq!(removed[0].log_source_name, "e2e source");
    assert_eq!(removed[0].deleted_at, deleted_at());
    assert_eq!(removed[0].events_24h, 2);
}

#[test]
fn a_key_that_keeps_arriving_after_the_delete_is_still_offered() {
    let before = deleted_at() - Duration::minutes(30);
    let after = deleted_at() + Duration::seconds(LATE_ARRIVAL_GRACE_SECS + 1);
    let (offered, removed) = split(&[tombstone("s", Some(&["still_sending"]))], &[], &[seen("still_sending", before, after)]);
    assert_eq!(keys(&offered), ["still_sending"]);
    assert!(removed.is_empty());
}

#[test]
fn in_flight_events_inside_the_grace_still_count_as_stopped() {
    let before = deleted_at() - Duration::minutes(30);
    let late = deleted_at() + Duration::seconds(LATE_ARRIVAL_GRACE_SECS);
    let (offered, removed) = split(&[tombstone("s", Some(&["draining"]))], &[], &[seen("draining", before, late)]);
    assert!(offered.is_empty());
    assert_eq!(removed.len(), 1);
}

#[test]
fn a_key_first_seen_after_the_delete_is_not_the_deleted_sources_stream() {
    let after = deleted_at() + Duration::seconds(10);
    let (offered, removed) = split(&[tombstone("s", Some(&["newcomer"]))], &[], &[seen("newcomer", after, after)]);
    assert_eq!(keys(&offered), ["newcomer"]);
    assert!(removed.is_empty());
}

#[test]
fn reserved_lanes_and_patterns_are_never_set_aside() {
    let before = deleted_at() - Duration::minutes(30);
    let activity = [seen("nano_internal", before, before), seen("generic", before, before), seen("a*b", before, before)];
    let (offered, removed) =
        split(&[tombstone("s", Some(&["nano_internal", "generic", "a*b"]))], &[], &activity);
    assert!(removed.is_empty(), "{removed:?}");
    assert!(keys(&offered).contains(&"nano_internal"), "a reserved lane stays visible: {offered:?}");
}

#[test]
fn no_tombstone_means_nothing_is_hidden() {
    // A never-deployed, never-token-bound draft leaves no tombstone (migration 398).
    let before = deleted_at() - Duration::minutes(30);
    let (offered, removed) = split(&[], &[], &[seen("draft_key", before, before)]);
    assert_eq!(keys(&offered), ["draft_key"]);
    assert!(removed.is_empty());
}

#[test]
fn a_key_with_no_event_times_has_no_evidence() {
    let activity = [SourceActivity { route_key: "blind".into(), events_24h: 5, first_seen: None, last_seen: None }];
    assert!(activity_evidence(&activity).is_empty());
    let (offered, removed) = split(&[tombstone("s", Some(&["blind"]))], &[], &activity);
    assert_eq!(keys(&offered), ["blind"]);
    assert!(removed.is_empty());
}

#[test]
fn empty_removed_set_is_a_no_op() {
    let before = deleted_at() - Duration::minutes(30);
    let list = unassigned_sources(&[], &[seen("k", before, before)]);
    let (offered, removed) = set_aside_removed(list.clone(), &RemovedSourceKeys::default());
    assert_eq!(offered, list);
    assert!(removed.is_empty());
    let _: HashMap<_, _> = activity_evidence(&[]);
}
