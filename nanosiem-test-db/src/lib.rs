// SPDX-License-Identifier: AGPL-3.0-or-later

//! The one place DB-backed tests get their database URLs and connections
//! (NAN-5967). Test-only: crates list it under `[dev-dependencies]`.
//!
//! # Which database a test uses
//!
//! | Database   | Canonical variable           | Older names, still read (in this order) |
//! |------------|------------------------------|-----------------------------------------|
//! | Postgres   | `NANOSIEM_TEST_DATABASE_URL` | `NANO_TEST_DATABASE_URL`, `TEST_DATABASE_URL` |
//! | ClickHouse | `CLICKHOUSE_TEST_URL`        | `NANOSIEM_TEST_CLICKHOUSE_URL` |
//!
//! The first one set wins. The production names (`DATABASE_URL`,
//! `CLICKHOUSE_URL`) are never read, and there is no localhost default: a
//! plain `cargo test` on a laptop must never reach whatever stack is running.
//! `SKIP_DB_TESTS` set to anything but `0` / `false` makes every variable read
//! as unset.
//!
//! ClickHouse credentials come from `CLICKHOUSE_TEST_USER` /
//! `CLICKHOUSE_TEST_PASSWORD` (older: `NANOSIEM_TEST_CLICKHOUSE_USER` /
//! `NANOSIEM_TEST_CLICKHOUSE_PASSWORD`).
//!
//! # The safety check
//!
//! A URL counts as an explicit test URL only when it parses strictly and
//! points at a loopback address on a port that is not a well-known database
//! port: a tunnel or a throwaway container on a high port, like
//! `127.0.0.1:25432`. The decision uses the EFFECTIVE target: Postgres query
//! overrides (`?host=`, `?hostaddr=`, `?port=`, `?dbname=`, unknown keys),
//! socket paths and ClickHouse query parameters all fail closed. Anything
//! else (a dev stack on `localhost:5432` / `8123`, a remote host) makes the
//! helper panic with a clear message, unless the operator opts in with
//! `NANOSIEM_ALLOW_DESTRUCTIVE_TESTS=1` (CI does). Many of these suites delete
//! rows or drop tables, so the opt-in is the only consent we accept.
//!
//! # Scope
//!
//! For crates in the root nanosiem workspace (it inherits the workspace's
//! `sqlx` / `clickhouse` and the vendored `sqlx-core` patch). nano-desktop is
//! its own workspace with no database tests; it does not depend on this.
//!
//! # Skipping
//!
//! Functions named `*_url` / `*_pool` return `Result<_, Unset>`, so a test
//! that is not `#[ignore]`d skips cleanly when nothing is set:
//!
//! ```ignore
//! let Ok(pool) = nanosiem_test_db::pg_pool(2).await else { return };
//! ```
//!
//! An `#[ignore]`d test that must have a database just calls `.expect(..)`
//! or `require_*`, which panics with the variable name to set.

use std::fmt;

/// Canonical Postgres test URL variable.
pub const PG_ENV: &str = "NANOSIEM_TEST_DATABASE_URL";
/// Older Postgres names, read after [`PG_ENV`] in this order.
pub const PG_LEGACY_ENV: &[&str] = &["NANO_TEST_DATABASE_URL", "TEST_DATABASE_URL"];
/// Canonical ClickHouse test URL variable.
pub const CH_ENV: &str = "CLICKHOUSE_TEST_URL";
/// Older ClickHouse names, read after [`CH_ENV`].
pub const CH_LEGACY_ENV: &[&str] = &["NANOSIEM_TEST_CLICKHOUSE_URL"];
/// ClickHouse test user, then its older name.
pub const CH_USER_ENV: &[&str] = &["CLICKHOUSE_TEST_USER", "NANOSIEM_TEST_CLICKHOUSE_USER"];
/// ClickHouse test password, then its older name.
pub const CH_PASSWORD_ENV: &[&str] = &["CLICKHOUSE_TEST_PASSWORD", "NANOSIEM_TEST_CLICKHOUSE_PASSWORD"];
/// The explicit consent to run against a database that is not obviously throwaway.
pub const DESTRUCTIVE_OPT_IN_ENV: &str = "NANOSIEM_ALLOW_DESTRUCTIVE_TESTS";
/// Set (to anything but `0` / `false`) to make every test database read as unset.
pub const SKIP_ENV: &str = "SKIP_DB_TESTS";

/// Whether `var` may be passed to [`dedicated_url`]: ends in `_TEST_URL`,
/// is not a production name, and is not one of the shared test variables.
pub fn is_dedicated_test_var(var: &str) -> bool {
    let shared = [PG_ENV, CH_ENV].into_iter().chain(PG_LEGACY_ENV.iter().copied()).chain(CH_LEGACY_ENV.iter().copied());
    var.len() > "_TEST_URL".len()
        && var.ends_with("_TEST_URL")
        && var.bytes().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && !PRODUCTION_URL_VARS.contains(&var)
        && !shared.into_iter().any(|v| v == var)
}

/// Production URL variables. Tests never read them.
pub const PRODUCTION_URL_VARS: &[&str] = &["DATABASE_URL", "CLICKHOUSE_URL"];

/// Ports a developer's real stack listens on. A loopback URL on one of these
/// needs the opt-in. 5432/15432 Postgres; 8123/18123/8443 ClickHouse HTTP(S);
/// 9000/9440 ClickHouse native.
const DEV_PORTS: &[u16] = &[5432, 15432, 8123, 18123, 8443, 9000, 9440];

/// Which database a URL is for (names the variables in messages).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Db {
    Postgres,
    ClickHouse,
}

impl Db {
    fn vars(self) -> (&'static str, &'static [&'static str]) {
        match self {
            Db::Postgres => (PG_ENV, PG_LEGACY_ENV),
            Db::ClickHouse => (CH_ENV, CH_LEGACY_ENV),
        }
    }
}

/// No test database of this kind is configured. Its `Debug` and `Display`
/// say which variable to set, so `.expect("...")` and `.unwrap()` read well.
#[derive(Clone, PartialEq, Eq)]
pub struct Unset {
    pub db: Db,
    /// The variable to set.
    pub var: String,
}

impl Unset {
    fn canonical(db: Db) -> Self {
        Self { db, var: db.vars().0.to_string() }
    }
}

impl fmt::Display for Unset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.db {
            Db::Postgres => "Postgres",
            Db::ClickHouse => "ClickHouse",
        };
        write!(f, "{} is not set: point it at a throwaway {what} (no localhost default, NAN-5967)", self.var)
    }
}

impl fmt::Debug for Unset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl std::error::Error for Unset {}

fn first_set(names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
}

fn skipped() -> bool {
    std::env::var(SKIP_ENV).is_ok_and(|v| !matches!(v.trim(), "" | "0" | "false" | "FALSE"))
}

/// Whether the operator set [`DESTRUCTIVE_OPT_IN_ENV`] to `1` or `true`.
pub fn destructive_opt_in() -> bool {
    std::env::var(DESTRUCTIVE_OPT_IN_ENV).is_ok_and(|v| matches!(v.trim(), "1" | "true" | "TRUE"))
}

/// Panic unless the operator opted in. For suites that wipe shared tables or
/// drop databases no matter where the URL points. `what` names the target
/// (pass a [`redact`]ed URL, never a raw one).
pub fn assert_destructive_opt_in(what: &str) {
    if destructive_opt_in() {
        return;
    }
    panic!(
        "\nrefusing to run a destructive DB test against {what}.\n\
         This test deletes or drops data. If that database is disposable, opt in:\n\
         \x20 {DESTRUCTIVE_OPT_IN_ENV}=1 cargo test ...\n"
    );
}

/// Postgres query keys that never change which server or database is dialed
/// (TLS material, cache size, a session label, session options). Any other
/// key (`host`, `hostaddr`, `port`, `dbname`, `user`, unknown ones) makes the
/// URL not an explicit test URL: sqlx applies those AFTER the authority, so
/// the authority alone would not say where the connection goes.
const PG_NEUTRAL_QUERY_KEYS: &[&str] = &[
    "sslmode",
    "ssl-mode",
    "sslrootcert",
    "ssl-root-cert",
    "ssl-ca",
    "sslcert",
    "ssl-cert",
    "sslkey",
    "ssl-key",
    "statement-cache-capacity",
    "application_name",
];

/// Parse strictly: a valid URL whose only `@` is the userinfo separator.
/// A raw `@` in the path, query or fragment means the authority ended
/// earlier than a human reading it would think (an unencoded `/`, `?` or `#`
/// in a password), so the URL is refused rather than guessed at.
fn parse_strict(url: &str) -> Option<url::Url> {
    let parsed = url::Url::parse(url).ok()?;
    parsed.host_str()?;
    let after_authority = &parsed[url::Position::BeforePath..];
    if after_authority.contains('@') {
        return None;
    }
    Some(parsed)
}

fn is_loopback(host: &url::Host<&str>) -> bool {
    match host {
        // Non-special schemes (postgres://) keep IPv4 hosts as text: parse it,
        // so `127.prod.internal` or `127.0.0.1.nip.io` never count.
        url::Host::Domain(name) => {
            name.eq_ignore_ascii_case("localhost") || name.parse::<std::net::IpAddr>().is_ok_and(|ip| ip.is_loopback())
        }
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
    }
}

/// Whether `url` is an explicit test URL for `db`: strictly parsed, the
/// right scheme, a loopback host (`localhost`, `127.0.0.0/8`, `::1`) on an
/// explicit port that no real database listens on by default, and nothing
/// that could redirect the connection (Postgres query overrides, a socket,
/// ClickHouse query parameters). Everything else fails closed and needs the
/// destructive opt-in. See the crate docs.
pub fn is_explicit_test_url(db: Db, url: &str) -> bool {
    let Some(parsed) = parse_strict(url) else { return false };
    let Some(host) = parsed.host() else { return false };
    let Some(port) = parsed.port() else { return false };
    if !is_loopback(&host) || DEV_PORTS.contains(&port) || parsed.fragment().is_some() {
        return false;
    }
    match db {
        Db::Postgres => {
            if !matches!(parsed.scheme(), "postgres" | "postgresql") {
                return false;
            }
            if !parsed.query_pairs().all(|(k, _)| PG_NEUTRAL_QUERY_KEYS.contains(&k.as_ref())) {
                return false;
            }
            // Cross-check with the parser sqlx itself uses: it must land on
            // the same host and port, over TCP.
            let Ok(options) = url.parse::<sqlx::postgres::PgConnectOptions>() else { return false };
            let host_str = parsed.host_str().unwrap_or_default();
            let sqlx_host = options.get_host().trim_start_matches('[').trim_end_matches(']');
            options.get_socket().is_none()
                && options.get_port() == port
                && sqlx_host.eq_ignore_ascii_case(host_str.trim_start_matches('[').trim_end_matches(']'))
        }
        Db::ClickHouse => {
            matches!(parsed.scheme(), "http" | "https")
                && parsed.query().is_none()
                && matches!(parsed.path(), "" | "/")
        }
    }
}

/// `scheme://host[:port]/path` with user, password, query and fragment
/// removed, safe to print in a panic. When the URL does not parse strictly
/// (see [`is_explicit_test_url`]) it returns `<unparseable URL redacted>` and
/// none of the input.
pub fn redact(url: &str) -> String {
    const UNPARSEABLE: &str = "<unparseable URL redacted>";
    let Some(parsed) = parse_strict(url) else {
        return UNPARSEABLE.to_string();
    };
    let host = parsed.host_str().unwrap_or_default();
    let port = parsed.port().map(|p| format!(":{p}")).unwrap_or_default();
    format!("{}://{host}{port}{}", parsed.scheme(), parsed.path().trim_end_matches('/'))
}

/// `url` pointed at database `db` instead: the path is replaced, everything
/// else kept. For suites that create a scratch database on the test server
/// and then connect to it. Panics (without echoing the URL) when it does not
/// parse.
pub fn with_database(url: &str, db: &str) -> String {
    let mut parsed = parse_strict(url).unwrap_or_else(|| panic!("with_database: <unparseable URL redacted>"));
    parsed.set_path(&format!("/{db}"));
    parsed.to_string()
}

/// Panic unless `url` is an explicit test URL or the operator opted in.
pub fn check_url(db: Db, url: &str) {
    check_url_for(db, db.vars().0, url);
}

/// [`check_url`] whose panic names `var`, the variable actually read.
fn check_url_for(db: Db, var: &str, url: &str) {
    if is_explicit_test_url(db, url) || destructive_opt_in() {
        return;
    }
    panic!(
        "\nrefusing to use {target} as a test database.\n\
         Only a loopback address on a non-default port (a tunnel or throwaway\n\
         container, e.g. 127.0.0.1:25432) counts as a test URL without consent.\n\
         This looks like a real stack (a default port such as 5432 or 8123, or a\n\
         remote host), and DB tests write and delete data.\n\
         Point {var} at a throwaway database, or, if this one IS disposable:\n\
         \x20 {DESTRUCTIVE_OPT_IN_ENV}=1 cargo test ...\n",
        target = redact(url),
    );
}

fn resolve(db: Db) -> Result<String, Unset> {
    if skipped() {
        return Err(Unset::canonical(db));
    }
    let (canonical, legacy) = db.vars();
    let (var, url) = std::iter::once(canonical)
        .chain(legacy.iter().copied())
        .find_map(|name| first_set(&[name]).map(|url| (name, url)))
        .ok_or_else(|| Unset::canonical(db))?;
    // The panic names the variable actually read.
    check_url_for(db, var, &url);
    Ok(url)
}

/// A URL from a suite's own variable, for the few suites that need a
/// dedicated server rather than the shared test database (a mixed-version
/// ClickHouse fleet, a tiered-storage server, a bootstrap target). Same skip
/// and safety rules as [`pg_url`] / [`ch_url`]. Prefer those: a new suite
/// should not invent a variable.
///
/// `var` must be a test variable: its name ends in `_TEST_URL`
/// (`CH_MIXED_FLEET_TEST_URL`), and it is not one of the shared ones (use
/// [`pg_url`] / [`ch_url`] for those). Anything else panics, so a test can
/// never read `DATABASE_URL`, `CLICKHOUSE_URL` or another production name.
pub fn dedicated_url(db: Db, var: &str) -> Result<String, Unset> {
    assert!(
        is_dedicated_test_var(var),
        "dedicated_url({var}): tests read only dedicated *_TEST_URL variables here; \
         production variables are never read, and the shared test variables go \
         through pg_url() / ch_url()"
    );
    let unset = || Unset { db, var: var.to_string() };
    if skipped() {
        return Err(unset());
    }
    let url = first_set(&[var]).ok_or_else(unset)?;
    check_url_for(db, var, &url);
    Ok(url)
}

/// The test Postgres URL. `Err` when none is set (skip); panics when it is
/// not an explicit test URL and there is no opt-in.
pub fn pg_url() -> Result<String, Unset> {
    resolve(Db::Postgres)
}

/// The test ClickHouse HTTP URL. Same rules as [`pg_url`].
pub fn ch_url() -> Result<String, Unset> {
    resolve(Db::ClickHouse)
}

/// Both the test Postgres and the test ClickHouse URL, for suites that need
/// the pair. `Err` names the first one missing, so a skip message built from
/// it (`eprintln!("Skipping: {unset}")`) always names the right variable.
pub fn pg_and_ch_urls() -> Result<(String, String), Unset> {
    Ok((pg_url()?, ch_url()?))
}

/// [`pg_url`], panicking with the variable to set when it is missing. For
/// `#[ignore]`d tests that cannot run without a database.
pub fn require_pg_url() -> String {
    pg_url().unwrap_or_else(|unset| panic!("{unset}"))
}

/// [`ch_url`], panicking with the variable to set when it is missing.
pub fn require_ch_url() -> String {
    ch_url().unwrap_or_else(|unset| panic!("{unset}"))
}

/// Whether a test Postgres is configured (does not run the safety check).
pub fn pg_configured() -> bool {
    !skipped() && first_set(&[PG_ENV]).or_else(|| first_set(PG_LEGACY_ENV)).is_some()
}

/// Whether a test ClickHouse is configured (does not run the safety check).
pub fn ch_configured() -> bool {
    !skipped() && first_set(&[CH_ENV]).or_else(|| first_set(CH_LEGACY_ENV)).is_some()
}

/// The ClickHouse test user, if set.
pub fn ch_user() -> Option<String> {
    first_set(CH_USER_ENV)
}

/// The ClickHouse test password, if set.
///
/// An explicitly empty value is a real (empty) password, as on a stock
/// passwordless ClickHouse container: `Some("")`. Unset is `None`.
pub fn ch_password() -> Option<String> {
    CH_PASSWORD_ENV.iter().find_map(|name| std::env::var(name).ok())
}

// ---------------------------------------------------------------- Postgres

/// Pool options for the test Postgres with `max` connections, for callers
/// that add `after_connect` hooks or other settings before connecting to
/// [`require_pg_url`].
pub fn pg_pool_options(max: u32) -> sqlx::postgres::PgPoolOptions {
    sqlx::postgres::PgPoolOptions::new().max_connections(max)
}

/// A pool of `max` connections to the test Postgres. `Err` when unset.
/// Panics (with the URL redacted) when the database is unreachable.
pub async fn pg_pool(max: u32) -> Result<sqlx::PgPool, Unset> {
    let url = pg_url()?;
    Ok(connect_pg(pg_pool_options(max), &url).await)
}

/// [`pg_pool`] that panics when no database is set.
pub async fn require_pg_pool(max: u32) -> sqlx::PgPool {
    let url = require_pg_url();
    connect_pg(pg_pool_options(max), &url).await
}

/// Connect `options` to `url` (from [`pg_url`]), panicking with the URL
/// redacted when the database is unreachable.
pub async fn connect_pg(options: sqlx::postgres::PgPoolOptions, url: &str) -> sqlx::PgPool {
    options
        .connect(url)
        .await
        .unwrap_or_else(|e| panic!("connect to test Postgres at {}: {e}", redact(url)))
}

/// A throwaway Postgres schema: created on [`PgSchema::create`], every pool
/// connection's `search_path` pinned to it (then `public`, so extensions and
/// shared types still resolve), removed by [`PgSchema::drop`].
///
/// Call `drop` at the end of the test: Rust has no async `Drop`, so a schema
/// from a panicking test stays behind. Names start with the given prefix, so
/// leftovers are easy to find.
pub struct PgSchema {
    pub pool: sqlx::PgPool,
    pub name: String,
}

impl PgSchema {
    /// Create `<prefix>_<random>` on the test Postgres. `Err` when unset.
    /// `prefix` must be lowercase ASCII letters, digits and `_`.
    pub async fn create(prefix: &str, max: u32) -> Result<Self, Unset> {
        let url = pg_url()?;
        Ok(Self::create_at(&url, prefix, max).await)
    }

    /// [`PgSchema::create`] against an already-resolved `url`.
    pub async fn create_at(url: &str, prefix: &str, max: u32) -> Self {
        assert!(
            !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "schema prefix must be lowercase ASCII letters, digits and _: {prefix:?}"
        );
        let name = format!("{prefix}_{}", uuid::Uuid::new_v4().simple());
        // Create it on a plain connection first: the pool's after_connect
        // sets search_path to a schema that must already exist.
        let admin = connect_pg(pg_pool_options(1), url).await;
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("CREATE SCHEMA {name}")))
            .execute(&admin)
            .await
            .unwrap_or_else(|e| panic!("create schema {name}: {e}"));
        admin.close().await;
        let search_path = format!("SET search_path TO {name}, public");
        let options = pg_pool_options(max).after_connect(move |conn, _| {
            let sql = search_path.clone();
            Box::pin(async move { sqlx::Executor::execute(conn, sqlx::AssertSqlSafe(sql)).await.map(|_| ()) })
        });
        let pool = connect_pg(options, url).await;
        Self { pool, name }
    }

    /// Drop the schema and everything in it, then close the pool.
    pub async fn drop(self) {
        sqlx::raw_sql(sqlx::AssertSqlSafe(format!("DROP SCHEMA IF EXISTS {} CASCADE", self.name)))
            .execute(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("drop schema {}: {e}", self.name));
        self.pool.close().await;
    }
}

// -------------------------------------------------------------- ClickHouse

/// A `clickhouse::Client` for `url` (from [`ch_url`]) with the test
/// credentials applied when set.
pub fn ch_client_for(url: &str) -> clickhouse::Client {
    let mut client = clickhouse::Client::default().with_url(url);
    if let Some(user) = ch_user() {
        client = client.with_user(user);
    }
    if let Some(password) = ch_password() {
        client = client.with_password(password);
    }
    client
}

/// A client for the test ClickHouse (no default database). `Err` when unset.
pub fn ch_client() -> Result<clickhouse::Client, Unset> {
    Ok(ch_client_for(&ch_url()?))
}

/// [`ch_client`] that panics when no ClickHouse is set.
pub fn require_ch_client() -> clickhouse::Client {
    ch_client_for(&require_ch_url())
}

/// A throwaway ClickHouse database: created on [`ChDatabase::create`],
/// removed by [`ChDatabase::drop`]. `client` has it as the default database.
pub struct ChDatabase {
    pub client: clickhouse::Client,
    pub name: String,
    server: clickhouse::Client,
}

impl ChDatabase {
    /// Create `<prefix>_<random>` on the test ClickHouse. `Err` when unset.
    /// `prefix` must be lowercase ASCII letters, digits and `_`.
    pub async fn create(prefix: &str) -> Result<Self, Unset> {
        let server = ch_client()?;
        assert!(
            !prefix.is_empty() && prefix.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
            "database prefix must be lowercase ASCII letters, digits and _: {prefix:?}"
        );
        let name = format!("{prefix}_{}", uuid::Uuid::new_v4().simple());
        server
            .query(&format!("CREATE DATABASE {name}"))
            .execute()
            .await
            .unwrap_or_else(|e| panic!("create ClickHouse database {name}: {e}"));
        let client = server.clone().with_database(&name);
        Ok(Self { client, name, server })
    }

    /// Drop the database and everything in it.
    pub async fn drop(self) {
        self.server
            .query(&format!("DROP DATABASE IF EXISTS {}", self.name))
            .execute()
            .await
            .unwrap_or_else(|e| panic!("drop ClickHouse database {}: {e}", self.name));
    }
}

// The cases below name dev-stack URLs on purpose (to prove they are
// rejected); the NAN-5964 localhost guard skips this one file.
#[cfg(test)]
mod tests;
