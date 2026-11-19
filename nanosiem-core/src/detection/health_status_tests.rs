// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5629: detection health is `critical` only while a rule is failing now.

use super::execution_status;

#[test]
fn a_rule_failing_now_is_critical() {
    assert_eq!(execution_status(1, 1, 0), "critical");
    assert_eq!(execution_status(2, 5, 3), "critical");
}

/// The reported box: `unsigned_kernel_driver_load` left a coverage gap and
/// then ran again (`consecutive_failures: 0`, `last_error: null`,
/// `currently_failing_rules: 0`). That is a recent-failure warning, not
/// critical.
#[test]
fn a_recovered_rule_with_a_recent_gap_is_degraded_not_critical() {
    assert_eq!(execution_status(0, 1, 1), "degraded");
    assert_eq!(execution_status(0, 0, 4), "degraded");
}

#[test]
fn a_recovered_rule_with_a_recent_error_is_degraded() {
    assert_eq!(execution_status(0, 1, 0), "degraded");
}

#[test]
fn nothing_failing_is_ok() {
    assert_eq!(execution_status(0, 0, 0), "ok");
}
