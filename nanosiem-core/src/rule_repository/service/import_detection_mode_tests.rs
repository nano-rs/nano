//! Rule-file `detection_mode` spellings (NAN-5242). The API and the
//! detection-as-code exporter write `real-time`; older files and docs used
//! `realtime`. Both must import as real-time, or an exported real-time rule
//! silently comes back scheduled.
use super::import::parse_rule_file_detection_mode;
use crate::models::DetectionMode;

#[test]
fn both_spellings_import_as_real_time() {
    for value in ["realtime", "real-time", "Real-Time", "real_time", " realtime "] {
        assert!(
            matches!(parse_rule_file_detection_mode(Some(value)), DetectionMode::RealTime),
            "{value:?} must import as real-time"
        );
    }
}

#[test]
fn anything_else_stays_scheduled() {
    for value in [None, Some("scheduled"), Some(""), Some("streaming"), Some("real time later")] {
        assert!(
            matches!(parse_rule_file_detection_mode(value), DetectionMode::Scheduled),
            "{value:?} must stay scheduled"
        );
    }
}
