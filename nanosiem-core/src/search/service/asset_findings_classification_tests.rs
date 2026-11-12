// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5312: detection findings are logged with `source_type = "findings"`
//! (`detection/findings.rs`), but the UDM alert classifiers only knew the
//! legacy `signal` name, so findings never landed in the ALERT lane and the
//! asset view's "Open sequence" pivot searched a source that has no rows.

use super::asset::detect_event_kind;
use crate::search::classification::{ALERT_PREDICATE, EVENT_KIND_SQL};

#[test]
fn findings_rows_classify_as_alert() {
    for st in ["findings", "FINDINGS", "signal", "crowdstrike_alerts"] {
        let ev = serde_json::json!({ "source_type": st });
        assert_eq!(detect_event_kind(&ev), "ALERT", "{st}");
    }
    let ev = serde_json::json!({ "source_type": "windows_security" });
    assert_ne!(detect_event_kind(&ev), "ALERT");
}

#[test]
fn alert_sql_predicate_includes_findings() {
    assert!(ALERT_PREDICATE.contains("'findings'"), "{ALERT_PREDICATE}");
    assert!(ALERT_PREDICATE.contains("'signal'"), "{ALERT_PREDICATE}");
    assert!(EVENT_KIND_SQL.contains(ALERT_PREDICATE));
}
