// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

#[test]
fn future_finding_uses_guarded_default_and_preserves_event_time() {
    let future = Utc::now() + chrono::Duration::hours(48);
    let metadata = serde_json::json!({
        "signal_type": "detection_match",
        "rule_id": "future-clock-rule",
        "rule_name": "Future clock",
        "severity": "high"
    });

    let payload = FindingLogger::build_ocsf_finding_event(&metadata, "future", future);
    let sql = ocsf_finding_insert_sql("nanosiem.ocsf_logs_raw");

    assert_eq!(payload["time"], future.timestamp_millis());
    assert!(sql.contains("(event, source_type)"));
    assert!(
        !sql.contains("timestamp"),
        "writer bypassed guarded DEFAULT: {sql}"
    );
}
