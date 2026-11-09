// SPDX-License-Identifier: AGPL-3.0-or-later

use std::cell::Cell;

use super::*;

fn memo(capacity: usize) -> VerdictMemo {
    VerdictMemo::new(capacity, [7u8; 32])
}

#[test]
fn a_verdict_for_one_source_is_never_applied_to_another() {
    let m = memo(16);
    assert_eq!(
        m.get_or_check("guard", "bad = get_env_var!(\"X\")", || Err("refused".into())),
        Err("refused".into())
    );
    // A different source must run its own check, even one differing by a byte.
    let ran = Cell::new(false);
    let other = m.get_or_check("guard", "bad = get_env_var!(\"Y\")", || {
        ran.set(true);
        Ok(())
    });
    assert!(ran.get(), "the other source's check must run");
    assert_eq!(other, Ok(()));
    // And the refused source stays refused.
    assert_eq!(
        m.get_or_check("guard", "bad = get_env_var!(\"X\")", || Ok(())),
        Err("refused".into())
    );
}

#[test]
fn the_same_source_and_kind_reuses_the_verdict() {
    let m = memo(16);
    let runs = Cell::new(0);
    for _ in 0..5 {
        let v = m.get_or_check("guard", ". = parse_json!(.message)", || {
            runs.set(runs.get() + 1);
            Ok(())
        });
        assert_eq!(v, Ok(()));
    }
    assert_eq!(runs.get(), 1);
}

#[test]
fn kinds_are_separate() {
    let m = memo(16);
    assert_eq!(m.get_or_check("condition", "true", || Err("not read-only".into())), Err("not read-only".into()));
    let ran = Cell::new(false);
    assert_eq!(
        m.get_or_check("program", "true", || {
            ran.set(true);
            Ok(())
        }),
        Ok(())
    );
    assert!(ran.get());
}

#[test]
fn a_different_allowlist_tag_never_reuses_a_verdict() {
    let a = VerdictMemo::new(16, [1u8; 32]);
    let b = VerdictMemo::new(16, [2u8; 32]);
    assert_ne!(a.key("guard", "x"), b.key("guard", "x"));
}

#[test]
fn the_memo_is_bounded_and_evicts_the_least_recently_used() {
    let m = memo(4);
    for i in 0..4 {
        m.get_or_check("guard", &format!("src{i}"), || Ok(()));
    }
    // Touch src0 so src1 becomes the least recently used.
    m.get_or_check("guard", "src0", || panic!("src0 is cached"));
    m.get_or_check("guard", "src4", || Ok(()));
    assert_eq!(m.len(), 4);
    let reran = Cell::new(false);
    m.get_or_check("guard", "src1", || {
        reran.set(true);
        Ok(())
    });
    assert!(reran.get(), "src1 was evicted");
    m.get_or_check("guard", "src0", || panic!("src0 must survive eviction"));
}

#[test]
fn the_allowlist_tag_is_stable_within_a_process() {
    assert_eq!(*ALLOWLIST_TAG, *ALLOWLIST_TAG);
    assert_ne!(*ALLOWLIST_TAG, [0u8; 32]);
}
