// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5367: upgrading from a release whose migrator created the raw-SQL
//! users with SQL and no HOST clause (any address) tightens them to loopback +
//! private networks; a users.xml user is left untouched; a rerun is a no-op.
//!
//! ```text
//! docker run -d --name ch -p 127.0.0.1:18123:8123 clickhouse/clickhouse-server:26.10.3.7
//! NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:18123 \
//!   cargo test -p nanosiem-core --test clickhouse_sql_user_hosts -- --ignored
//! ```

use nanosiem_core::db::ClickHouseMigrator;

fn ch() -> clickhouse::Client {
    let url = std::env::var("NANOSIEM_TEST_CLICKHOUSE_URL")
        .expect("NANOSIEM_TEST_CLICKHOUSE_URL must target a disposable ClickHouse");
    let mut client = nanosiem_core::db::clickhouse_transport::client().with_url(url);
    if let Ok(user) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_USER") {
        client = client.with_user(user);
    }
    if let Ok(password) = std::env::var("NANOSIEM_TEST_CLICKHOUSE_PASSWORD") {
        client = client.with_password(password);
    }
    client
}

async fn exec(ch: &clickhouse::Client, sql: &str) {
    ch.query(sql).execute().await.unwrap_or_else(|e| panic!("{e}\n{sql}"));
}

#[derive(clickhouse::Row, serde::Deserialize, Debug)]
struct Hosts {
    storage: String,
    host_ip: Vec<String>,
    host_names: Vec<String>,
}

async fn hosts(ch: &clickhouse::Client, user: &str) -> Hosts {
    ch.query("SELECT storage, host_ip, host_names FROM system.users WHERE name = ?")
        .bind(user)
        .fetch_one::<Hosts>()
        .await
        .unwrap_or_else(|e| panic!("{user}: {e}"))
}

const USERS: [&str; 2] = ["nanosiem_rawsql", "nanosiem_rawsql_noaudit"];

#[tokio::test]
#[ignore = "requires NANOSIEM_TEST_CLICKHOUSE_URL pointing at a disposable ClickHouse"]
async fn upgrade_tightens_sql_created_any_address_users_and_leaves_xml_users() {
    let ch = ch();
    for user in USERS {
        exec(&ch, &format!("DROP USER IF EXISTS {user}")).await;
    }
    // The pre-NAN-5367 bootstrap: one user already created with no HOST
    // clause (HOST ANY); the other is missing and gets created now.
    exec(&ch, "CREATE USER nanosiem_rawsql IDENTIFIED BY 'old-release'").await;
    assert_eq!(hosts(&ch, "nanosiem_rawsql").await.host_ip, vec!["::/0".to_string()]);

    let result = futures::FutureExt::catch_unwind(std::panic::AssertUnwindSafe(async {
        let db = format!("nan5367_{}", uuid::Uuid::now_v7().simple());
        let mut migrator = ClickHouseMigrator::new(ch.clone(), &db).with_cluster(None);
        let created = migrator
            .ensure_rawsql_users(Some("pw-rawsql-5367"), Some("pw-noaudit-5367"))
            .await
            .expect("ensure_rawsql_users");
        assert_eq!(created, 1, "only the missing noaudit user is created");
        for user in USERS {
            let h = hosts(&ch, user).await;
            assert_ne!(h.storage, "users_xml");
            assert!(!h.host_ip.iter().any(|ip| ip.ends_with("/0")), "{user} still open: {h:?}");
            for net in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7"] {
                assert!(h.host_ip.iter().any(|ip| ip == net), "{user} lacks {net}: {h:?}");
            }
            assert!(h.host_names.iter().any(|n| n == "localhost"), "{user} lacks loopback: {h:?}");
        }
        // Rerun (every later migrate): nothing to create, nothing to alter.
        assert_eq!(migrator.ensure_rawsql_users(Some("x"), Some("y")).await.unwrap(), 0);
        for user in USERS {
            assert!(!migrator.tighten_sql_user_hosts(user, "").await.unwrap(), "{user} re-altered");
        }
        // users.xml storage is read-only: `default` (HOST ANY in the stock
        // image) is never touched.
        assert_eq!(hosts(&ch, "default").await.storage, "users_xml");
        assert!(!migrator.tighten_sql_user_hosts("default", "").await.unwrap());
    }))
    .await;
    for user in USERS {
        exec(&ch, &format!("DROP USER IF EXISTS {user}")).await;
    }
    exec(&ch, "DROP SETTINGS PROFILE IF EXISTS rawsql").await;
    if let Err(panic) = result {
        std::panic::resume_unwind(panic);
    }
}
