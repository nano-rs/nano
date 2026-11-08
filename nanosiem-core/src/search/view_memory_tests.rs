// SPDX-License-Identifier: AGPL-3.0-or-later
use super::*;

fn budget(global_mib: u64, request_mib: u64, wait_ms: u64) -> Arc<ViewMemoryBudget> {
    ViewMemoryBudget::new(ViewMemoryConfig::derive(
        None,
        Some(global_mib),
        Some(request_mib),
        Some(wait_ms),
    ))
}

#[test]
fn cgroup_limits_parse_v1_and_v2_shapes() {
    assert_eq!(parse_cgroup_memory_limit("1073741824\n"), Some(1 << 30));
    assert_eq!(parse_cgroup_memory_limit("max\n"), None);
    assert_eq!(parse_cgroup_memory_limit(""), None);
    assert_eq!(parse_cgroup_memory_limit("0"), None);
    assert_eq!(parse_cgroup_memory_limit("garbage"), None);
    // cgroup v1 "unlimited".
    assert_eq!(parse_cgroup_memory_limit("9223372036854771712"), None);
}

#[test]
fn budgets_derive_from_the_container_limit() {
    // The incident pod: a 1 GiB limit → ~40% for views, a third per request.
    let config = ViewMemoryConfig::derive(Some(1 << 30), None, None, None);
    assert_eq!(config.global_bytes, (1u64 << 30) / 100 * 40);
    assert_eq!(config.request_bytes, config.global_bytes / 3);
    assert_eq!(config.wait, DEFAULT_WAIT);

    // No readable limit → the conservative constant.
    let config = ViewMemoryConfig::derive(None, None, None, None);
    assert_eq!(config.global_bytes, FALLBACK_GLOBAL_BYTES);

    // Overrides win; a request never exceeds the global budget; floors hold.
    let config = ViewMemoryConfig::derive(Some(1 << 30), Some(100), Some(500), Some(250));
    assert_eq!(config.global_bytes, 100 * MIB);
    assert_eq!(config.request_bytes, 100 * MIB);
    assert_eq!(config.wait, Duration::from_millis(250));
    let config = ViewMemoryConfig::derive(Some(MIB), None, None, None);
    assert_eq!(config.global_bytes, MIN_BUDGET_BYTES);
    assert_eq!(config.request_bytes, MIN_BUDGET_BYTES);
}

#[tokio::test]
async fn a_request_over_its_budget_is_a_typed_view_too_large() {
    let budget = budget(64, 16, 100);
    let ledger = budget.ledger("asset-dossier");
    ledger.charge(10 * MIB).await.expect("within budget");
    let error = ledger.charge(7 * MIB).await.expect_err("over the per-request budget");
    match error {
        SearchError::ViewTooLarge { view, needed_bytes, budget_bytes } => {
            assert_eq!(view, "asset-dossier");
            assert_eq!(needed_bytes, 17 * MIB);
            assert_eq!(budget_bytes, 16 * MIB);
        }
        other => panic!("expected ViewTooLarge, got {other:?}"),
    }
    // The refused charge is not recorded and nothing leaks.
    assert_eq!(ledger.charged_bytes(), 10 * MIB);
    drop(ledger);
    assert_eq!(budget.available_mib(), 64);
}

#[tokio::test]
async fn concurrent_requests_are_bounded_by_the_global_budget() {
    let budget = budget(32, 16, 50);
    let first = budget.ledger("asset-events");
    let second = budget.ledger("asset-events");
    first.charge(16 * MIB).await.expect("first fits");
    second.charge(16 * MIB).await.expect("second fits");
    assert_eq!(budget.available_mib(), 0);

    // A third request cannot reserve while both hold their bytes.
    let third = budget.ledger("asset-artifacts");
    let error = third.charge(MIB).await.expect_err("global budget exhausted");
    assert!(matches!(error, SearchError::ViewMemoryBusy { .. }), "got {error:?}");
    assert_eq!(third.charged_bytes(), 0);

    // Finishing one request releases its reservation for the next.
    drop(first);
    assert_eq!(budget.available_mib(), 16);
    third.charge(MIB).await.expect("headroom after release");
    assert_eq!(third.reserved_mib().await, 1);
}

#[tokio::test]
async fn a_waiter_proceeds_when_headroom_frees_within_the_window() {
    let budget = budget(16, 16, 2_000);
    let holder = budget.ledger("cloud-dossier");
    holder.charge(16 * MIB).await.unwrap();
    let waiter = budget.ledger("cloud-dossier");
    let release = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(50)).await;
        drop(holder);
    });
    waiter.charge(4 * MIB).await.expect("acquires once the holder finishes");
    release.await.unwrap();
    assert_eq!(budget.available_mib(), 12);
}

#[tokio::test]
async fn reservations_grow_in_whole_mib_and_charges_outside_a_scope_are_free() {
    let budget = budget(64, 32, 50);
    let ledger = budget.ledger("tree-page");
    ledger.charge(100).await.unwrap();
    ledger.charge(100).await.unwrap();
    assert_eq!(ledger.reserved_mib().await, 1);
    ledger.charge(MIB).await.unwrap();
    assert_eq!(ledger.reserved_mib().await, 2);
    assert_eq!(budget.available_mib(), 62);

    // No scope → no accounting, never an error.
    assert!(current().is_none());
    charge_wire_bytes(u64::MAX / 4).await.expect("unscoped reads are not budgeted");

    // Inside a scope the amplified wire bytes land on the ledger.
    let scoped_ledger = budget.ledger("asset-dossier");
    scope(scoped_ledger.clone(), async {
        charge_wire_bytes(MIB).await.unwrap();
        let error = charge_wire_bytes(10 * MIB).await.expect_err("amplified over 32 MiB");
        assert!(matches!(error, SearchError::ViewTooLarge { .. }));
    })
    .await;
    assert_eq!(scoped_ledger.charged_bytes(), DECODE_AMPLIFICATION * MIB);
}

#[tokio::test]
async fn scoped_if_absent_keeps_an_enclosing_ledger_and_scopes_bare_work() {
    let budget = budget(64, 32, 50);
    let outer = budget.ledger("asset-dossier");
    scope(outer.clone(), async {
        scoped_if_absent("detection rule", async {
            assert_eq!(current().expect("still scoped").view(), "asset-dossier");
            charge_wire_bytes(MIB).await.unwrap();
        })
        .await;
    })
    .await;
    assert_eq!(outer.charged_bytes(), DECODE_AMPLIFICATION * MIB);

    // Bare work (a scheduled detection rule) gets its own ledger.
    assert!(current().is_none());
    let view = scoped_if_absent("detection rule", async {
        current().map(|ledger| ledger.view().to_string())
    })
    .await;
    assert_eq!(view.as_deref(), Some("detection rule"));
}
