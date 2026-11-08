// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-4902 review: validate merges omitted MITRE lists from the stored rule,
//! the way the UPDATE it previews keeps them.

use super::effective_mitre_mapping;

fn s(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| v.to_string()).collect()
}

#[test]
fn techniques_only_update_keeps_the_stored_tactics() {
    let stored = (Some(s(&["TA0002"])), Some(s(&["T1059"])));
    let techniques = s(&["T1059.001"]);
    let (tactics, merged) = effective_mitre_mapping(Some(&stored), None, Some(&techniques));
    assert_eq!(tactics, s(&["TA0002"]).as_slice());
    assert_eq!(merged, techniques.as_slice());
}

#[test]
fn tactics_only_update_keeps_the_stored_techniques() {
    let stored = (Some(s(&["TA0002"])), Some(s(&["T1059"])));
    let tactics = s(&["TA0003"]);
    let (merged, techniques) = effective_mitre_mapping(Some(&stored), Some(&tactics), None);
    assert_eq!(merged, tactics.as_slice());
    assert_eq!(techniques, s(&["T1059"]).as_slice());
}

#[test]
fn explicit_empty_list_clears_rather_than_merges() {
    let stored = (Some(s(&["TA0002"])), Some(s(&["T1059"])));
    let empty: Vec<String> = Vec::new();
    let (tactics, techniques) = effective_mitre_mapping(Some(&stored), Some(&empty), None);
    assert!(tactics.is_empty());
    assert_eq!(techniques, s(&["T1059"]).as_slice());
}

#[test]
fn create_or_unknown_rule_defaults_omitted_lists_to_empty() {
    let techniques = s(&["T1059"]);
    let (tactics, merged) = effective_mitre_mapping(None, None, Some(&techniques));
    assert!(tactics.is_empty());
    assert_eq!(merged, techniques.as_slice());

    let stored_nulls = (None, None);
    let (tactics, merged) = effective_mitre_mapping(Some(&stored_nulls), None, Some(&techniques));
    assert!(tactics.is_empty());
    assert_eq!(merged, techniques.as_slice());
}
