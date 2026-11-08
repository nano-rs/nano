// SPDX-License-Identifier: AGPL-3.0-or-later

use super::migration_refresh_failures_sql;

#[test]
fn durable_refresh_health_uses_latest_state_and_flags_stuck_pending_work() {
    let sql = migration_refresh_failures_sql();

    assert!(sql.contains("FROM nanosiem._migration_refreshes FINAL"));
    assert!(sql.contains("state IN ('failed', 'exhausted')"));
    assert!(sql.contains("state = 'pending'"));
    assert!(sql.contains("INTERVAL 5 MINUTE"));
    assert!(sql.contains("--retry-exhausted"));
    assert!(sql.contains("substring(last_error, 1, 300)"));
}
