// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn per_principal_limit_refuses_only_that_principal() {
    let gate = PrincipalGate::new("VRL test", 2, 16, 1);
    let _a1 = gate.try_acquire("user:a").unwrap();
    let _a2 = gate.try_acquire("user:a").unwrap();
    let err = gate.try_acquire("user:a").err().unwrap();
    assert_eq!(err.scope, GateScope::Principal);
    assert_eq!(err.limit, 2);
    assert!(err.to_string().contains("per-user limit of 2"), "{err}");
    // Another principal is unaffected.
    assert!(gate.try_acquire("user:b").is_ok());
}

/// Dan's shared-egress rule: many distinct principals arriving from ONE
/// source address are never throttled by each other. The gate has no notion
/// of an address at all; each principal gets its own allowance up to the
/// server-wide ceiling.
#[test]
fn distinct_principals_behind_one_ip_are_independent() {
    let gate = PrincipalGate::new("VRL test", 1, 64, 1);
    // 50 analysts behind one corporate NAT, each running one test.
    let permits: Vec<_> = (0..50)
        .map(|i| gate.try_acquire(&format!("user:{i}")).expect("each principal admitted"))
        .collect();
    assert_eq!(permits.len(), 50);
}

#[test]
fn global_ceiling_applies_and_does_not_leak_principal_slots() {
    let gate = PrincipalGate::new("VRL test", 1, 2, 3);
    let _a = gate.try_acquire("user:a").unwrap();
    let _b = gate.try_acquire("user:b").unwrap();
    let err = gate.try_acquire("user:c").err().unwrap();
    assert_eq!(err.scope, GateScope::Global);
    assert_eq!(err.retry_after_secs, 3);
    // The refused principal's slot was released: once capacity frees up, c is
    // admitted (and not stuck at its per-principal count).
    drop(_a);
    assert!(gate.try_acquire("user:c").is_ok());
}

#[test]
fn permits_release_on_drop() {
    let gate = PrincipalGate::new("VRL test", 1, 1, 1);
    let p = gate.try_acquire("api_key:k").unwrap();
    assert!(gate.try_acquire("api_key:k").is_err());
    drop(p);
    assert!(gate.try_acquire("api_key:k").is_ok());
}
