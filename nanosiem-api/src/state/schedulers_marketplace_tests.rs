// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4946: a fresh install's marketplace catalog syncs a minute after boot,
//! not after the old hard-coded 30 minutes.

use super::marketplace_initial_delay_secs;

#[test]
fn marketplace_first_sync_defaults_to_one_minute() {
    assert_eq!(marketplace_initial_delay_secs(None), 60);
    assert_eq!(marketplace_initial_delay_secs(Some("junk")), 60);
    assert!(marketplace_initial_delay_secs(None) < 1800);
}

#[test]
fn marketplace_first_sync_delay_is_overridable_including_zero() {
    assert_eq!(marketplace_initial_delay_secs(Some(" 5 ")), 5);
    assert_eq!(marketplace_initial_delay_secs(Some("0")), 0);
}
