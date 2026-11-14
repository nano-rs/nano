// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5298 review: a `wait=true` deploy request never outlives the edge.

use super::SYNC_DEPLOY_WAIT;

/// nginx `proxy_read_timeout` (nginx.opensource.conf, compose nginx.app.conf,
/// the Helm edge configmap) and the web's 310 s give-up.
const EDGE_PROXY_READ_TIMEOUT_SECS: u64 = 300;

#[test]
fn a_waiting_deploy_answers_before_the_edge_gives_up() {
    assert!(SYNC_DEPLOY_WAIT.as_secs() < EDGE_PROXY_READ_TIMEOUT_SECS);
}

#[test]
fn a_waiting_deploy_still_covers_a_full_forward_reload_wait() {
    // A deploy whose reload uses its whole outcome wait still answers with
    // its result, not a 202, when nothing else is slow.
    assert!(SYNC_DEPLOY_WAIT.as_secs() > nanosiem_core::parsers::DEFAULT_RELOAD_ACK_MAX_SECS + 45);
}

/// NAN-5406: the OCSF gate runs before the job, so the wait for the job is
/// what is left of the synchronous budget: the request as a whole still
/// answers before the edge gives up, however long the gate took.
#[test]
fn time_spent_in_the_gate_comes_off_the_synchronous_wait() {
    use super::remaining_sync_wait;
    use std::time::Duration;
    assert_eq!(remaining_sync_wait(Duration::ZERO), SYNC_DEPLOY_WAIT);
    let gate = Duration::from_secs(100);
    assert_eq!(remaining_sync_wait(gate) + gate, SYNC_DEPLOY_WAIT);
    assert_eq!(remaining_sync_wait(SYNC_DEPLOY_WAIT * 2), Duration::ZERO);
    // A worst-case gate (a parser and an extension stage, each waiting the
    // full slot wait and then running to its wall clock) still leaves the job
    // time to answer synchronously.
    use nanosiem_core::parsers::test_sandbox::{DEPLOY_GATE_ADMISSION_WAIT, DEPLOY_GATE_WALL_SECONDS};
    let worst_gate = 2 * (DEPLOY_GATE_ADMISSION_WAIT + Duration::from_secs(DEPLOY_GATE_WALL_SECONDS));
    assert!(worst_gate < SYNC_DEPLOY_WAIT, "{worst_gate:?}");
}
