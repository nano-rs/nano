// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use crate::audit::{AuditEvent, AuditSource};

#[test]
fn future_audit_uses_guarded_default_and_preserves_event_time() {
    let future = Utc::now() + chrono::Duration::hours(48);
    let mut event = AuditEvent::builder(AuditSource::Audit, "future_clock_test").build();
    event.occurred_at = future;

    let payload = event.to_ocsf_event(event.occurred_at);
    let sql = ocsf_mirror_insert_sql("nanosiem.ocsf_logs_raw", 1);

    assert_eq!(payload["time"], future.timestamp_millis());
    assert!(sql.contains("(event, source_type, id)"));
    assert!(
        !sql.contains("timestamp"),
        "writer bypassed guarded DEFAULT: {sql}"
    );
}
