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
