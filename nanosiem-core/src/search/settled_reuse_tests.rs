// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;
use chrono::TimeZone;

fn now() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 10, 14, 12, 0, 0).unwrap()
}

#[test]
fn only_windows_older_than_the_late_arrival_grace_are_settled() {
    let now = now();
    assert!(is_settled_end(now - Duration::hours(1), now));
    assert!(is_settled_end(now - Duration::seconds(LATE_ARRIVAL_GRACE_SECS), now));
    assert!(!is_settled_end(now, now));
    assert!(!is_settled_end(now - Duration::seconds(LATE_ARRIVAL_GRACE_SECS - 1), now));
    assert_eq!(settled_after(now), now + Duration::seconds(LATE_ARRIVAL_GRACE_SECS));
}

#[test]
fn stateful_and_relative_queries_are_never_reused() {
    assert!(query_allows_settled_reuse("class_uid=4001 | stats count by src_endpoint.ip"));
    assert!(query_allows_settled_reuse("error | head 100"));
    for query in [
        "* | lookup assets host",
        "| inputlookup users",
        "* | ai summarize",
        "* | where prevalence_min < 3",
        "* | risk",
        "* | iocfeed",
        "* | tree",
        "* | lateral",
        "* | baseline",
        "* | eval t=now()",
        "* [ search foo ]",
        "error earliest=-1h",
        "* | where relative_time(time, \"-1d\") > 0",
    ] {
        assert!(!query_allows_settled_reuse(query), "{query}");
    }
}
