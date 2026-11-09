// SPDX-License-Identifier: AGPL-3.0-or-later
use super::{check, observe, TripwireRule};

#[test]
fn clean_generated_shapes_do_not_trip() {
    for sql in [
        "SELECT * FROM logs WHERE timestamp >= '2026-01-01 00:00:00' AND (lower(message) LIKE '%system.tables%')",
        "SELECT src_endpoint.autonomous_system.number AS n FROM ocsf_logs",
        "SELECT \"system\".x FROM t",
        "SELECT 'url(http://x)' AS s, 'executable(' AS e FROM logs",
        "SELECT count() AS c, uniq(user) AS u FROM logs GROUP BY src_ip SETTINGS max_threads=16",
        "SELECT arrayMap(x -> x + 1, [1, 2]) AS a FROM logs LIMIT 1 BY src_ip",
        "SELECT event.\"src_endpoint\".\"ip\" FROM ocsf_logs",
        "SELECT dictGetOrDefault('nanosiem.ip_prevalence_dict', 'host_count', toIPv6(src_ip), 9999) FROM logs",
        "SELECT \"url\"(1)",
    ] {
        assert!(check(sql).is_empty(), "{sql} -> {:?}", check(sql));
    }
}

#[test]
fn injection_shapes_trip() {
    let cases: &[(&str, TripwireRule)] = &[
        ("SELECT 1 -- x", TripwireRule::Comment),
        ("SELECT 1 /* x */", TripwireRule::Comment),
        ("SELECT 1; SELECT 2", TripwireRule::Semicolon),
        ("SELECT * FROM system.tables", TripwireRule::SystemSchema),
        ("SELECT (SELECT name FROM SYSTEM . settings LIMIT 1)", TripwireRule::SystemSchema),
        ("SELECT * FROM information_schema.tables", TripwireRule::SystemSchema),
        ("SELECT hostName()", TripwireRule::DisallowedFunction),
        ("SELECT avg(filesystemAvailable()) FROM logs", TripwireRule::DisallowedFunction),
        ("SELECT sleepEachRow(1) FROM logs", TripwireRule::DisallowedFunction),
        ("SELECT * FROM url('http://169.254.169.254/', 'TSV', 'x String')", TripwireRule::TableFunction),
        ("SELECT (SELECT any(x) FROM remote('h:9000', system.one))", TripwireRule::TableFunction),
        ("SELECT * FROM executable('x.sh', 'TSV', 'x String')", TripwireRule::TableFunction),
        ("SELECT * FROM S3('http://b/k', 'CSV', 'x String')", TripwireRule::TableFunction),
    ];
    for (sql, rule) in cases {
        let hits = check(sql);
        assert!(hits.contains(rule), "{sql} -> {hits:?}, expected {rule:?}");
    }
}

#[test]
fn observe_never_panics_or_fails() {
    // Unterminated literal (untokenizable), empty input, huge input, and a hit:
    // all return normally.
    observe("SELECT 'unterminated", "test");
    observe("", "test");
    observe(&"SELECT 1 ".repeat(20_000), "test");
    // Oversize input is skipped (counted), not scanned.
    observe(&"x".repeat(super::MAX_CHECKED_SQL_BYTES + 1), "test");
    observe("SELECT hostName()", "test");
    assert_eq!(check("SELECT 'unterminated"), vec![TripwireRule::Untokenizable]);
}
