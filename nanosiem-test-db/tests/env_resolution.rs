// SPDX-License-Identifier: AGPL-3.0-or-later

//! Env-driven resolution (NAN-5967). Its own test binary with ONE test, so
//! changing the process environment cannot race any other test.

use nanosiem_test_db::{ch_url, dedicated_url, pg_url, Db};

const ALL: &[&str] = &[
    "DATABASE_URL",
    "CLICKHOUSE_URL",
    "NANOSIEM_TEST_DATABASE_URL",
    "NANO_TEST_DATABASE_URL",
    "TEST_DATABASE_URL",
    "CLICKHOUSE_TEST_URL",
    "NANOSIEM_TEST_CLICKHOUSE_URL",
    "SKIP_DB_TESTS",
    "NANOSIEM_ALLOW_DESTRUCTIVE_TESTS",
    "PANIC_PROBE_TEST_URL",
    "CLICKHOUSE_TEST_PASSWORD",
    "NANOSIEM_TEST_CLICKHOUSE_PASSWORD",
];

fn clear() {
    for name in ALL {
        std::env::remove_var(name);
    }
}

fn panic_message(f: impl FnOnce() + std::panic::UnwindSafe) -> Option<String> {
    let err = std::panic::catch_unwind(f).err()?;
    err.downcast::<String>().map(|s| *s).ok().or(Some(String::new()))
}

#[test]
fn production_variables_are_never_read_and_panics_name_the_variable() {
    clear();

    // Postgres: DATABASE_URL set (even to a URL the check would accept, and
    // even with the opt-in), test variables unset -> refused.
    std::env::set_var("DATABASE_URL", "postgres://u:p@127.0.0.1:25432/nanosiem");
    std::env::set_var("NANOSIEM_ALLOW_DESTRUCTIVE_TESTS", "1");
    let unset = pg_url().expect_err("DATABASE_URL must never satisfy pg_url()");
    assert_eq!(unset.var, "NANOSIEM_TEST_DATABASE_URL");
    assert!(unset.to_string().starts_with("NANOSIEM_TEST_DATABASE_URL is not set"), "{unset}");
    assert!(panic_message(|| drop(dedicated_url(Db::Postgres, "DATABASE_URL"))).is_some(), "dedicated_url(DATABASE_URL) must refuse");

    // ClickHouse: CLICKHOUSE_URL set, CLICKHOUSE_TEST_URL unset -> refused.
    std::env::set_var("CLICKHOUSE_URL", "http://127.0.0.1:28123");
    let unset = ch_url().expect_err("CLICKHOUSE_URL must never satisfy ch_url()");
    assert_eq!(unset.var, "CLICKHOUSE_TEST_URL");
    assert!(panic_message(|| drop(dedicated_url(Db::ClickHouse, "CLICKHOUSE_URL"))).is_some(), "dedicated_url(CLICKHOUSE_URL) must refuse");
    clear();

    // The safety panic names the variable actually read: a legacy name...
    std::env::set_var("NANO_TEST_DATABASE_URL", "postgres://u:p@prod.internal:5432/nanosiem");
    let message = panic_message(|| drop(pg_url())).expect("a remote URL must panic without the opt-in");
    assert!(message.contains("Point NANO_TEST_DATABASE_URL at"), "{message}");
    assert!(!message.contains("prod.internal:5432/nanosiem?") && !message.contains("u:p@"), "{message}");
    clear();

    // ... and a dedicated one.
    std::env::set_var("PANIC_PROBE_TEST_URL", "http://prod.internal:8123");
    let message = panic_message(|| drop(dedicated_url(Db::ClickHouse, "PANIC_PROBE_TEST_URL"))).expect("must panic");
    assert!(message.contains("Point PANIC_PROBE_TEST_URL at"), "{message}");
    clear();

    // The pair helper names the first variable missing.
    std::env::set_var("NANOSIEM_TEST_DATABASE_URL", "postgres://u:p@127.0.0.1:25432/x");
    let unset = nanosiem_test_db::pg_and_ch_urls().expect_err("no ClickHouse set");
    assert_eq!(unset.var, "CLICKHOUSE_TEST_URL");
    assert!(format!("Skipping: {unset}").starts_with("Skipping: CLICKHOUSE_TEST_URL is not set"));
    std::env::remove_var("NANOSIEM_TEST_DATABASE_URL");
    std::env::set_var("CLICKHOUSE_TEST_URL", "http://127.0.0.1:28123");
    assert_eq!(nanosiem_test_db::pg_and_ch_urls().unwrap_err().var, "NANOSIEM_TEST_DATABASE_URL");
    std::env::set_var("NANOSIEM_TEST_DATABASE_URL", "postgres://u:p@127.0.0.1:25432/x");
    assert!(nanosiem_test_db::pg_and_ch_urls().is_ok());
    clear();

    // An explicitly empty ClickHouse password is a real empty password;
    // unset is None (a stock passwordless container must keep working).
    assert_eq!(nanosiem_test_db::ch_password(), None);
    std::env::set_var("CLICKHOUSE_TEST_PASSWORD", "");
    assert_eq!(nanosiem_test_db::ch_password().as_deref(), Some(""));
    std::env::remove_var("CLICKHOUSE_TEST_PASSWORD");
    std::env::set_var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD", "");
    assert_eq!(nanosiem_test_db::ch_password().as_deref(), Some(""));
    std::env::set_var("CLICKHOUSE_TEST_PASSWORD", "pw");
    assert_eq!(nanosiem_test_db::ch_password().as_deref(), Some("pw"));
    clear();

    // Precedence: canonical, then legacy names in order.
    std::env::set_var("TEST_DATABASE_URL", "postgres://u:p@127.0.0.1:25433/c");
    std::env::set_var("NANO_TEST_DATABASE_URL", "postgres://u:p@127.0.0.1:25432/b");
    assert!(pg_url().unwrap().ends_with("/b"));
    std::env::set_var("NANOSIEM_TEST_DATABASE_URL", "postgres://u:p@127.0.0.1:25431/a");
    assert!(pg_url().unwrap().ends_with("/a"));
    // SKIP_DB_TESTS=1 reads as unset; SKIP_DB_TESTS=0 does not.
    std::env::set_var("SKIP_DB_TESTS", "1");
    assert!(pg_url().is_err());
    std::env::set_var("SKIP_DB_TESTS", "0");
    assert!(pg_url().is_ok());
    clear();
}
