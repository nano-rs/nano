//! NAN-811 regression: migrator must bootstrap a non-existent target database.
//!
//! Fresh-VM installs construct the migrator with `clickhouse_database=nanosiem`
//! but the actual `nanosiem` database doesn't exist yet (the entrypoint's
//! `CLICKHOUSE_DB` env was removed in NAN-810 because it ran DDL as the
//! `default` user, blocked by our default-profile allow_ddl=0). The migrator
//! must therefore create the database itself before it can do anything else.
//!
//! Prerequisites:
//!   docker run -d --rm --name test-ch-nan811 -p 18123:8123 \
//!     -e CLICKHOUSE_USER=admin -e CLICKHOUSE_PASSWORD=admin \
//!     -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
//!     clickhouse/clickhouse-server:26.10.3.7
//!
//! Run: cargo test -p nanosiem-core --test migrator_bootstrap -- --nocapture

use nanosiem_core::db::ClickHouseMigrator;
use std::path::PathBuf;

/// Default `http://localhost:18123`. Override with `MIGRATOR_BOOTSTRAP_CH_URL` when
/// another ClickHouse already owns that port: this test DROPs and recreates its own
/// database, so never point it at a server you don't own (NAN-4906).
fn ch_url() -> String {
    std::env::var("MIGRATOR_BOOTSTRAP_CH_URL").unwrap_or_else(|_| "http://localhost:18123".to_string())
}
/// Default `admin`/`admin` (the docker run above). Override with
/// `MIGRATOR_BOOTSTRAP_CH_USER` / `MIGRATOR_BOOTSTRAP_CH_PASSWORD` for a server
/// with other credentials; an auth failure reads as "unreachable" and skips.
fn ch_user() -> String {
    std::env::var("MIGRATOR_BOOTSTRAP_CH_USER").unwrap_or_else(|_| "admin".to_string())
}
fn ch_password() -> String {
    std::env::var("MIGRATOR_BOOTSTRAP_CH_PASSWORD").unwrap_or_else(|_| "admin".to_string())
}

fn fresh_db_name() -> String {
    // Use a per-run name so repeat runs don't see a database left over from a
    // previous successful run — the whole point is to exercise the "database
    // doesn't exist yet" path.
    format!(
        "test_nan811_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    )
}

async fn ch_reachable() -> bool {
    reqwest::Client::new()
        .get(format!("{}/?query=SELECT+1", ch_url()))
        .basic_auth(ch_user(), Some(ch_password()))
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

async fn drop_db(db: &str) {
    let _ = reqwest::Client::new()
        .post(format!("{}/?query=DROP+DATABASE+IF+EXISTS+{}", ch_url(), db))
        .basic_auth(ch_user(), Some(ch_password()))
        .send()
        .await;
}

fn build_client(database: &str) -> clickhouse::Client {
    clickhouse::Client::default()
        .with_url(ch_url())
        .with_database(database)
        .with_user(ch_user())
        .with_password(ch_password())
}

#[tokio::test]
async fn migrator_creates_target_database_when_missing() {
    if !ch_reachable().await {
        eprintln!(
            "Skipping: ClickHouse not reachable at {} \
             (start with: docker run -d --rm --name test-ch-nan811 \
             -p 18123:8123 -e CLICKHOUSE_USER=admin -e CLICKHOUSE_PASSWORD=admin \
             -e CLICKHOUSE_DEFAULT_ACCESS_MANAGEMENT=1 \
             clickhouse/clickhouse-server:26.10.3.7)",
            ch_url()
        );
        return;
    }

    let db = fresh_db_name();
    drop_db(&db).await; // belt + suspenders

    // Mirrors the production path: the migrator binary calls
    // create_admin_clickhouse_client() which sets .with_database(&db) on the
    // client before handing it to ClickHouseMigrator::new. On a fresh install
    // `db` does not exist yet — that's the bug.
    let client = build_client(&db);
    let mut migrator = ClickHouseMigrator::new(client, db.clone());

    // run_migrations() against an empty migrations dir exercises
    // ensure_migrations_table() (the first CH-touching operation in the
    // migrator) without needing an init.sql. This is exactly the spot that
    // 500s with `UNKNOWN_DATABASE` on fresh installs today.
    let tmp = tempfile::tempdir().expect("create tempdir for empty migrations");
    let result = migrator
        .run_migrations(&PathBuf::from(tmp.path()))
        .await;

    drop_db(&db).await; // cleanup before asserting so failures don't leak state

    result.expect("migrator must bootstrap the target database itself");
}
