// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-4846: transport retries are keyed by request hour, independently of
//! event time. The signed part/log summary locates these keys after restart
//! and compaction without a new R2 object or a per-request remote lookup.

use serde::{Deserialize, Serialize};

pub const PREFIX: &str = "nano-request-v1:";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestHours {
    pub first: i32,
    pub last: i32,
}

impl RequestHours {
    pub fn contains(self, hour: i32) -> bool {
        self.first <= hour && hour <= self.last
    }
    pub fn include(&mut self, hour: i32) {
        self.first = self.first.min(hour);
        self.last = self.last.max(hour);
    }
    pub fn valid(self) -> bool {
        self.first >= 0 && self.first <= self.last && self.last < 100_000_000
    }
}

pub fn request_hour(uid: &str) -> Option<i32> {
    let (hour, digest) = uid.strip_prefix(PREFIX)?.split_once(':')?;
    if !super::is_sha256_hex(digest) {
        return None;
    }
    let hour = hour.parse::<i32>().ok()?;
    (0..100_000_000).contains(&hour).then_some(hour)
}

/// Separate the request-hour and event-hour namespaces in the existing
/// bounded UID window. The i64 namespace cannot collide with any i32 event hour.
pub fn window_hour(hour: i32) -> i64 {
    i64::MIN + i64::from(hour)
}
pub fn is_window_hour(hour: i64) -> bool {
    hour < i64::MIN + 100_000_000
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_request_identity_has_a_distinct_validated_hour_namespace() {
        let uid = format!("{PREFIX}500000:{}", "a".repeat(64));
        assert_eq!(request_hour(&uid), Some(500000));
        assert!(is_window_hour(window_hour(500000)));
        for uid in [
            "nano-request-v1:-1:bad",
            "nano-request-v1:100000000:bad",
            "customer-uid",
        ] {
            assert_eq!(request_hour(uid), None);
        }
    }
}
