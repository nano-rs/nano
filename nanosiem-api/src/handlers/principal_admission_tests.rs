// SPDX-License-Identifier: AGPL-3.0-or-later
//! Parser-test admission (security review 2026-11-08, NAN-5040 follow-up).

use super::*;
use crate::handlers::log_sources::parser_test_gate_sizing;
use nanosiem_core::principal_gate::PrincipalGate;
use std::time::Duration;

/// Exploit regression: a client that disconnects must not free its slot while
/// the blocking work it started keeps running.
#[tokio::test]
async fn dropped_request_keeps_the_slot_until_the_work_ends() {
    let gate = PrincipalGate::new("Parser test", 1, 1, 1);
    let (release, wait) = tokio::sync::oneshot::channel::<()>();
    let (started_tx, started) = tokio::sync::oneshot::channel::<()>();
    let permit = gate.try_acquire("user:a").unwrap();
    let request = tokio::spawn(run_admitted(permit, async move {
        // Stands in for the spawn_blocking VRL work.
        let _ = started_tx.send(());
        tokio::task::spawn_blocking(move || {
            let _ = wait.blocking_recv();
        })
        .await
        .unwrap();
    }));
    started.await.unwrap();
    // The client hangs up: the request future is dropped.
    request.abort();
    let _ = request.await;
    // The work is still running, so the slot is still held.
    assert!(gate.try_acquire("user:a").is_err(), "slot freed while work still runs");
    assert!(gate.try_acquire("user:b").is_err(), "global slot freed while work still runs");
    // Once the work ends, the slot is released.
    release.send(()).unwrap();
    for _ in 0..200 {
        if gate.try_acquire("user:a").is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("slot never released after the work ended");
}

/// Legitimate path: admitted work returns its value and releases the slot.
#[tokio::test]
async fn admitted_work_returns_and_releases() {
    let gate = PrincipalGate::new("Parser test", 1, 1, 1);
    let permit = gate.try_acquire("user:a").unwrap();
    assert_eq!(run_admitted(permit, async { 7 }).await.ok(), Some(7));
    assert!(gate.try_acquire("user:a").is_ok());
}

/// One principal can never take the whole server-wide ceiling, on any replica
/// size (a 2-CPU compose replica included), and the Lab's 4-way fan-out fits.
#[test]
fn gate_sizing_leaves_room_for_other_principals() {
    for cpus in [1, 2, 4, 8, 16, 64] {
        let (per, global) = parser_test_gate_sizing(cpus);
        assert!(global >= 16, "cpus={cpus}");
        assert!(per * 4 <= global, "cpus={cpus}: per={per} global={global}");
        assert!(per >= 2, "cpus={cpus}");
        assert!(per >= 4 || cpus < 8, "cpus={cpus}");
    }
    assert_eq!(parser_test_gate_sizing(2), (4, 16));
    // N principals behind one address each get their own allowance.
    let (per, global) = parser_test_gate_sizing(2);
    let gate = PrincipalGate::new("Parser test", per, global, 1);
    let permits: Vec<_> = (0..4)
        .flat_map(|u| (0..per).map(move |_| u))
        .map(|u| gate.try_acquire(&format!("user:{u}")).expect("admitted"))
        .collect();
    assert_eq!(permits.len(), global);
}
