// SPDX-License-Identifier: AGPL-3.0-or-later

use super::*;

const PG: Db = Db::Postgres;
const CH: Db = Db::ClickHouse;

#[test]
fn explicit_test_urls_are_loopback_high_ports() {
    for (db, url) in [
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem"),
        (PG, "postgresql://u:p@127.0.0.1:25432/nanosiem"),
        (PG, "postgres://u@localhost:5433/x?sslmode=disable"),
        (PG, "postgres://u:p@127.0.0.1:25432/x?sslmode=require&application_name=t"),
        (PG, "postgres://u:p@127.9.9.9:25432/x"),
        (PG, "postgres://u:p@[::1]:25432/x"),
        (PG, "postgres://u:p%40ss@127.0.0.1:25432/x"),
        (CH, "http://127.0.0.1:28123"),
        (CH, "http://u:p@127.0.0.1:28123/"),
        (CH, "http://[::1]:28123/"),
        (CH, "https://localhost:28443"),
    ] {
        assert!(is_explicit_test_url(db, url), "should be explicit: {url}");
    }
}

/// Every one of these must need the opt-in: default ports, remote hosts,
/// implicit ports, and every way to make the dialed target differ from the
/// authority a reader sees (NAN-5967 review P1-2).
#[test]
fn bypass_attempts_fail_closed() {
    for (db, url) in [
        // Default ports and implicit ports.
        (PG, "postgres://u:p@localhost:5432/nanosiem"),
        (PG, "postgres://u:p@localhost/nanosiem"),
        (PG, "postgres://u:p@127.0.0.1:15432/nanosiem"),
        (CH, "http://localhost:8123"),
        (CH, "http://127.0.0.1:18123"),
        (CH, "http://127.0.0.1:9000"),
        (CH, "http://127.0.0.1"),
        // Remote hosts.
        (PG, "postgres://u:p@db.internal:25432/nanosiem"),
        (PG, "postgres://u:p@10.0.0.5:5432/nanosiem"),
        (PG, "postgres://u:p@0.0.0.0:25432/nanosiem"),
        // Lookalike hostnames.
        (PG, "postgres://u:p@127.prod.internal:25432/nanosiem"),
        (PG, "postgres://u:p@127.0.0.1.nip.io:25432/nanosiem"),
        (PG, "postgres://u:p@localhost.evil.example:25432/nanosiem"),
        (PG, "postgres://u:p@127.1:25432/nanosiem"),
        // sqlx query overrides applied after the authority.
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?host=prod.internal&port=5432"),
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?hostaddr=10.0.0.5&port=5432"),
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?host=/var/run/postgresql&port=5432"),
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?port=5432"),
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?dbname=prod"),
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?user=postgres"),
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?unknown=1"),
        (PG, "postgres://u:p@127.0.0.1:25432/nanosiem?sslmode=disable&HOST=x"),
        // Sockets and missing hosts.
        (PG, "postgres:///nanosiem?host=/tmp"),
        (PG, "postgres://%2Fvar%2Frun%2Fpostgresql:25432/nanosiem"),
        // `@` outside the authority: the dialed host is the first one.
        (PG, "postgres://u:p@prod.internal:5432/db@127.0.0.1:25432"),
        (CH, "http://prod.internal:8123/x@127.0.0.1:28123"),
        (PG, "postgres://u:p@prod.internal:5432/db?x=@127.0.0.1:25432"),
        (PG, "postgres://u:p@prod.internal:5432/db#@127.0.0.1:25432"),
        // Multiple hosts.
        (PG, "postgres://u:p@127.0.0.1:25432,prod.internal:5432/nanosiem"),
        // Wrong scheme for the database, ClickHouse query parameters / paths.
        (PG, "http://127.0.0.1:25432/nanosiem"),
        (CH, "postgres://u:p@127.0.0.1:28123"),
        (CH, "http://127.0.0.1:28123/?database=prod"),
        (CH, "http://127.0.0.1:28123/proxy/prod"),
        (CH, "http://127.0.0.1:28123/#frag"),
        // Not URLs.
        (PG, "not a url"),
        (PG, ""),
        (CH, "127.0.0.1:28123"),
    ] {
        assert!(!is_explicit_test_url(db, url), "must need the opt-in: {url}");
    }
}

#[test]
fn redact_never_returns_credentials() {
    for (url, want) in [
        ("postgres://u:secret@127.0.0.1:25432/db?sslmode=x", "postgres://127.0.0.1:25432/db"),
        ("postgres://u:p%40ss%3Aw%3F%23%25@host:1/db", "postgres://host:1/db"),
        ("postgres://u:p@ss@host:1/db", "postgres://host:1/db"),
        ("postgres://u:p:ss@host:1/db", "postgres://host:1/db"),
        ("http://h:8123", "http://h:8123"),
        ("http://user:pw@h:8123/", "http://h:8123"),
        // A raw % in a password: kept out of the output all the same.
        ("postgres://user:sec%ret@prod.internal:5432/x", "postgres://prod.internal:5432/x"),
    ] {
        assert_eq!(redact(url), want, "{url}");
    }
    // Passwords holding raw ? # / % or other structure, malformed input:
    // nothing of the input may come back.
    for (url, secret) in [
        ("postgres://user:p?ss@prod.internal:5432/nanosiem", "p?ss"),
        ("postgres://user:pa#ss@prod.internal:5432/nanosiem", "pa#ss"),
        ("postgres://user:a@b?c@prod.internal:5432/nanosiem", "a@b?c"),
        ("postgres://user:a/b@prod.internal:5432/nanosiem", "a/b"),
        ("postgres://user:1/b@prod.internal:5432/nanosiem", "1/b"),
        ("postgres://user:secret", "secret"),
        ("user:secret://prod.internal:5432/nanosiem", "secret"),
        ("garbage-secret", "secret"),
        ("", ""),
    ] {
        let out = redact(url);
        assert_eq!(out, "<unparseable URL redacted>", "{url} -> {out}");
        if !secret.is_empty() {
            assert!(!out.contains(secret), "{url} leaked {secret}");
        }
    }
}

#[test]
fn unset_names_the_canonical_variable() {
    assert!(Unset::canonical(Db::Postgres).to_string().starts_with(PG_ENV));
    assert!(format!("{:?}", Unset::canonical(Db::ClickHouse)).starts_with(CH_ENV));
    let dedicated = Unset { db: Db::ClickHouse, var: "CH_MIXED_FLEET_URL".into() };
    assert!(dedicated.to_string().starts_with("CH_MIXED_FLEET_URL is not set"));
}

#[test]
fn with_database_replaces_only_the_path() {
    assert_eq!(with_database("postgres://u:p@127.0.0.1:25432/nanosiem", "scratch"), "postgres://u:p@127.0.0.1:25432/scratch");
    assert_eq!(with_database("postgres://u:p@127.0.0.1:25432", "scratch"), "postgres://u:p@127.0.0.1:25432/scratch");
    assert_eq!(
        with_database("postgres://u:a%2Fb@127.0.0.1:25432/x?sslmode=disable", "y"),
        "postgres://u:a%2Fb@127.0.0.1:25432/y?sslmode=disable"
    );
}

#[test]
fn dedicated_variables_must_be_test_variables() {
    for var in ["CH_MIXED_FLEET_TEST_URL", "MIGRATOR_BOOTSTRAP_CH_TEST_URL", "NAN5296_CH_TEST_URL"] {
        assert!(is_dedicated_test_var(var), "{var}");
    }
    for var in [
        "DATABASE_URL",
        "CLICKHOUSE_URL",
        "CH_MIXED_FLEET_URL",
        "MY_DATABASE_URL",
        "_TEST_URL",
        "lower_test_url",
        PG_ENV,
        CH_ENV,
        "NANO_TEST_DATABASE_URL",
        "TEST_DATABASE_URL",
        "NANOSIEM_TEST_CLICKHOUSE_URL",
    ] {
        assert!(!is_dedicated_test_var(var), "{var}");
        let result = std::panic::catch_unwind(|| dedicated_url(Db::Postgres, var));
        assert!(result.is_err(), "dedicated_url must refuse {var}");
    }
}

#[test]
fn dedicated_url_safety_panic_names_the_variable_read() {
    let message = std::panic::catch_unwind(|| check_url_for(Db::ClickHouse, "CH_MIXED_FLEET_TEST_URL", "http://prod.internal:8123"))
        .err()
        .and_then(|e| e.downcast::<String>().ok())
        .map(|s| *s);
    // Without the opt-in the check panics and names the variable read; with
    // it (a CI shell) it passes, which is the documented behavior.
    if !destructive_opt_in() {
        let message = message.expect("unsafe URL must panic without the opt-in");
        assert!(message.contains("Point CH_MIXED_FLEET_TEST_URL at"), "{message}");
        assert!(!message.contains("CLICKHOUSE_TEST_URL"), "{message}");
    }
}
