// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn quorum_loss_is_recognised_by_name_or_code() {
    assert!(is_too_few_live_replicas(
        "Code: 285. DB::Exception: Number of alive replicas (1) is less than requested quorum (2/2). (TOO_FEW_LIVE_REPLICAS)"
    ));
    assert!(is_too_few_live_replicas("bad response: Code: 285. DB::Exception: ..."));
    // Other insert failures must not silently drop the quorum.
    assert!(!is_too_few_live_replicas(
        "Code: 286. DB::Exception: Quorum for previous write has not been satisfied yet. (UNSATISFIED_QUORUM_FOR_PREVIOUS_WRITE)"
    ));
    assert!(!is_too_few_live_replicas("Code: 241. DB::Exception: Memory limit exceeded. (MEMORY_LIMIT_EXCEEDED)"));
}

#[test]
fn eventual_reads_turn_sequential_consistency_off() {
    assert_eq!(ReadConsistency::Sequential.select_sequential_consistency(), "1");
    assert_eq!(ReadConsistency::Eventual.select_sequential_consistency(), "0");
}

fn page(rows: usize, byte_limited: bool) -> StoredPage {
    StoredPage {
        rows: vec![serde_json::Value::Null; rows],
        byte_limited,
    }
}

#[test]
fn short_or_long_pages_are_inconsistent_unless_byte_limited() {
    assert!(!page_inconsistent(&page(10, false), 10));
    assert!(page_inconsistent(&page(9, false), 10));
    assert!(!page_inconsistent(&page(9, true), 10));
    assert!(page_inconsistent(&page(11, false), 10));
    assert!(page_inconsistent(&page(11, true), 10));
}

#[test]
fn only_replica_consistency_errors_earn_an_eventual_reread() {
    for retryable in [
        "Code: 289. DB::Exception: Replica doesn't have part all_1_1_0 which was successfully written to quorum. (REPLICA_IS_NOT_IN_QUORUM)",
        "Code: 279. DB::Exception: All connection tries failed. (ALL_CONNECTION_TRIES_FAILED)",
        "Code: 232. DB::Exception: ... (ALL_REPLICAS_ARE_STALE)",
    ] {
        assert!(is_replica_consistency_error(retryable), "{retryable}");
    }
    for surfaced in [
        "Code: 497. DB::Exception: Not enough privileges. (ACCESS_DENIED)",
        "Code: 62. DB::Exception: Syntax error. (SYNTAX_ERROR)",
        "Code: 159. DB::Exception: Timeout exceeded: elapsed 300 seconds. (TIMEOUT_EXCEEDED)",
        "Code: 241. DB::Exception: Memory limit exceeded. (MEMORY_LIMIT_EXCEEDED)",
        "Code: 2890. something else",
    ] {
        assert!(!is_replica_consistency_error(surfaced), "{surfaced}");
    }
}
