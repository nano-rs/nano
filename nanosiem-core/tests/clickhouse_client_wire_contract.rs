// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5412 (clickhouse-rs 0.14 -> 0.15.3): the client wire contract nano
//! relies on, proven against a real server. Run it against every ClickHouse
//! line we ship (26.10 at the time of writing):
//!
//!   NANOSIEM_TEST_CLICKHOUSE_URL=http://127.0.0.1:<port> \
//!   NANOSIEM_TEST_CLICKHOUSE_USER=default NANOSIEM_TEST_CLICKHOUSE_PASSWORD=<pw> \
//!   cargo test -p nanosiem-core --test clickhouse_client_wire_contract -- --ignored
//!
//! The admin user needs access management (creates throwaway readonly users).
//!
//! What 0.15.x changed under us, and what each test pins:
//! * LZ4 moved to `Accept-Encoding` negotiation (fixes a ClickHouse 26.9
//!   regression) and `enable_http_compression` is no longer sent on queries:
//!   LZ4 (the default for every production client) and uncompressed reads and
//!   inserts must return byte-identical data, including for readonly users.
//! * Server-side parameters (`Query::param`) now travel in a multipart body,
//!   not the URL: hostile values must bind exactly, readonly too. NOTE the new
//!   ceiling: each multipart field (every param, AND the SQL text itself once
//!   any param is set) is capped by the server's `http_max_field_value_size`
//!   (128 KiB default) and `http_max_fields` (1000). 0.14 was capped only by
//!   `http_max_uri_size` (1 MiB). Nano binds client-side (`Query::bind`, SQL
//!   in a plain body), so no production path uses `param` today; keep large
//!   values on `bind` or raise the server setting before moving them.
//! * Transport errors must still arrive as `Error::Network` and server errors
//!   as `Error::BadResponse` with the `Code: N` prefix, because the NAN-5424
//!   classification (`search_error_from_error`, `is_unreachable_replica_error`,
//!   agentlane `is_network`) matches on those variants.

use nanosiem_core::search::{search_error_from_error, SearchError};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

fn base() -> clickhouse::Client {
    clickhouse::Client::default().with_url(nanosiem_test_db::require_ch_url())
}

fn admin() -> clickhouse::Client {
    base()
        .with_user(nanosiem_test_db::ch_user().expect("CLICKHOUSE_TEST_USER must be set for this live suite"))
        .with_password(nanosiem_test_db::ch_password().unwrap_or_default())
        // Readonly users may not set anything, so only the writer pins this.
        .with_setting("async_insert", "0")
}

async fn exec(ch: &clickhouse::Client, sql: &str) {
    ch.query(sql)
        .execute()
        .await
        .unwrap_or_else(|error| panic!("{error}: {sql}"));
}

#[derive(clickhouse::Row, Serialize, Deserialize, Debug, PartialEq, Clone)]
struct WireRow {
    id: u64,
    body: String,
    tags: Vec<String>,
}

fn rows(n: u64) -> Vec<WireRow> {
    (0..n)
        .map(|id| WireRow {
            id,
            // Mixed, compressible and non-compressible content, plus UTF-8.
            body: format!("evt-{id:08} src_ip=10.{}.{}.{} user=ü{} {}", id % 255, (id / 255) % 255, id % 7, id % 97, "x".repeat((id % 300) as usize)),
            tags: vec![format!("t{}", id % 13), "näme".into()],
        })
        .collect()
}

/// Creates a throwaway database; dropped at the end of each test.
struct Scratch {
    ch: clickhouse::Client,
    db: String,
    users: std::sync::Mutex<Vec<String>>,
}

impl Scratch {
    async fn new(tag: &str) -> Self {
        let ch = admin();
        let db = format!("nan5412_{tag}_{}", Uuid::new_v4().simple());
        exec(&ch, &format!("CREATE DATABASE {db}")).await;
        exec(
            &ch,
            &format!(
                "CREATE TABLE {db}.wire (id UInt64, body String, tags Array(String)) \
                 ENGINE = MergeTree ORDER BY id"
            ),
        )
        .await;
        Self { ch, db, users: Default::default() }
    }

    async fn insert(&self, client: &clickhouse::Client, data: &[WireRow]) {
        // `insert()` escapes its argument as ONE identifier (0.14 too), so the
        // database goes on the client, as production does.
        let mut insert = client
            .clone()
            .with_database(&self.db)
            .insert::<WireRow>("wire")
            .await
            .expect("start insert");
        for row in data {
            insert.write(row).await.expect("write row");
        }
        insert.end().await.expect("end insert");
    }

    async fn readonly_user(&self, readonly: u8) -> clickhouse::Client {
        let user = format!("ro{readonly}_{}", Uuid::new_v4().simple());
        let password = Uuid::new_v4().simple().to_string();
        exec(
            &self.ch,
            &format!(
                "CREATE USER {user} IDENTIFIED WITH sha256_password BY '{password}' \
                 SETTINGS readonly = {readonly} READONLY"
            ),
        )
        .await;
        exec(&self.ch, &format!("GRANT SELECT ON {}.* TO {user}", self.db)).await;
        self.users.lock().unwrap().push(user.clone());
        base().with_user(user).with_password(password)
    }

    async fn drop(self) {
        exec(&self.ch, &format!("DROP DATABASE IF EXISTS {}", self.db)).await;
        let users = std::mem::take(&mut *self.users.lock().unwrap());
        for user in users {
            exec(&self.ch, &format!("DROP USER IF EXISTS {user}")).await;
        }
    }
}

async fn read_all(client: &clickhouse::Client, db: &str) -> Vec<WireRow> {
    client
        .query(&format!("SELECT ?fields FROM {db}.wire ORDER BY id"))
        .fetch_all::<WireRow>()
        .await
        .expect("read rows")
}

#[tokio::test]
#[ignore = "requires a lane-owned ClickHouse container (26.10)"]
async fn lz4_and_uncompressed_reads_and_inserts_are_byte_identical() {
    let scratch = Scratch::new("lz4").await;
    let data = rows(120_000);
    let lz4 = scratch.ch.clone().with_compression(clickhouse::Compression::Lz4);
    let none = scratch.ch.clone().with_compression(clickhouse::Compression::None);

    // Half the rows through each insert path.
    scratch.insert(&lz4, &data[..60_000]).await;
    scratch.insert(&none, &data[60_000..]).await;

    let via_lz4 = read_all(&lz4, &scratch.db).await;
    let via_none = read_all(&none, &scratch.db).await;
    assert_eq!(via_lz4.len(), data.len());
    assert!(via_lz4 == data, "LZ4 read differs from what was inserted");
    assert!(via_none == data, "uncompressed read differs from what was inserted");

    // The default client is LZ4.
    let via_default = read_all(&admin(), &scratch.db).await;
    assert!(via_default == data, "default-compression read differs");
    // Production clients also carry the NAN-4906 0.14 workaround
    // (`db::clickhouse_transport::client`); it must stay harmless on 0.15.
    let production_shape = admin().with_setting("network_compression_method", "LZ4");
    assert!(read_all(&production_shape, &scratch.db).await == data, "NAN-4906-shaped read differs");

    // Server-side digest agrees with the client-side data.
    let (count, digest): (u64, u64) = scratch
        .ch
        .query(&format!("SELECT count(), sum(cityHash64(id, body, tags)) FROM {}.wire", scratch.db))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(count, 120_000);
    let (_, digest_lz4): (u64, u64) = lz4
        .query(&format!("SELECT count(), sum(cityHash64(id, body, tags)) FROM {}.wire", scratch.db))
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(digest, digest_lz4);
    scratch.drop().await;
}

#[tokio::test]
#[ignore = "requires a lane-owned ClickHouse container (26.10)"]
async fn readonly_users_read_with_lz4_and_server_side_params() {
    let scratch = Scratch::new("ro").await;
    scratch.insert(&scratch.ch, &rows(5_000)).await;
    for readonly in [1u8, 2] {
        let user = scratch.readonly_user(readonly).await;
        for compression in [clickhouse::Compression::Lz4, clickhouse::Compression::None] {
            let client = user.clone().with_compression(compression);
            let got = read_all(&client, &scratch.db).await;
            assert_eq!(got.len(), 5_000, "readonly={readonly} read");
            let n: u64 = client
                .query(&format!("SELECT count() FROM {}.wire WHERE id < {{lim:UInt64}}", scratch.db))
                .param("lim", 1234u64)
                .fetch_one()
                .await
                .unwrap_or_else(|e| panic!("readonly={readonly} param query: {e}"));
            assert_eq!(n, 1234);
        }
    }
    scratch.drop().await;
}

#[tokio::test]
#[ignore = "requires a lane-owned ClickHouse container (26.10)"]
async fn server_side_params_bind_large_and_hostile_values_exactly() {
    let ch = admin();
    // Hostile text: quotes, backslashes, braces, newlines, NUL, multipart-ish
    // boundary lines, UTF-8. Must round-trip verbatim, never as SQL.
    let hostile = "a'b\"c\\d{e}f\n--boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\u{0}é🙂'; DROP TABLE x; --".to_string();
    let echoed: String = ch
        .query("SELECT {v:String}")
        .param("v", &hostile)
        .fetch_one()
        .await
        .expect("hostile param");
    assert_eq!(echoed, hostile);

    // Just under the server's per-field cap (http_max_field_value_size).
    let near_cap = "z".repeat(120 * 1024);
    let len: u64 = ch
        .query("SELECT length({v:String})")
        .param("v", &near_cap)
        .fetch_one()
        .await
        .expect("120 KiB param");
    assert_eq!(len, near_cap.len() as u64);

    // Over the cap: refused loudly by the server, never truncated.
    let over_cap = "z".repeat(200 * 1024);
    let err = ch
        .query("SELECT length({v:String})")
        .param("v", &over_cap)
        .fetch_one::<u64>()
        .await
        .unwrap_err();
    assert!(
        matches!(&err, clickhouse::error::Error::BadResponse(m) if m.contains("Field value too long")),
        "an over-cap param must fail as BadResponse, got {err:?}"
    );

    // Nano's production path: client-side bind, SQL in a plain body. Large
    // values there are bounded only by max_query_size, not the form cap.
    let big = "z".repeat(512 * 1024);
    let len: u64 = ch
        .query("SELECT length(?)")
        .bind(big.as_str())
        .with_setting("max_query_size", "2097152")
        .fetch_one()
        .await
        .expect("512 KiB client-side bind");
    assert_eq!(len, big.len() as u64);

    // ~59 KB serialized: under the per-field cap.
    let ids: Vec<u64> = (0..10_000).collect();
    let (count, sum): (u64, u64) = ch
        .query("SELECT length(a), arraySum(a) FROM (SELECT {ids:Array(UInt64)} AS a)")
        .param("ids", &ids)
        .fetch_one()
        .await
        .expect("10k-element array param");
    assert_eq!((count, sum), (10_000, ids.iter().sum()));

    let uuid = Uuid::new_v4();
    let back: String = ch
        .query("SELECT toString({u:UUID})")
        .param("u", uuid.to_string())
        .fetch_one()
        .await
        .unwrap();
    assert_eq!(back, uuid.to_string());

    // Client-side binding is still client-side: `?` binds, `??` is a literal.
    let (a, q): (String, String) = ch
        .query("SELECT ?, '??'")
        .bind(hostile.as_str())
        .fetch_one()
        .await
        .expect("client-side bind");
    assert_eq!((a.as_str(), q.as_str()), (hostile.as_str(), "?"));
}

#[tokio::test]
#[ignore = "requires a lane-owned ClickHouse container (26.10)"]
async fn transport_and_server_errors_keep_their_types() {
    // A port nothing listens on: refused connection.
    let dead = clickhouse::Client::default().with_url("http://127.0.0.1:1");
    let err = dead.query("SELECT 1").fetch_one::<u8>().await.unwrap_err();
    assert!(
        matches!(err, clickhouse::error::Error::Network(_)),
        "refused connection must be Error::Network, got {err:?}"
    );
    assert!(
        matches!(search_error_from_error(&err), SearchError::Unavailable(_)),
        "refused connection must classify as Unavailable"
    );

    // A refused insert is transport too (ingest/agentlane paths).
    let err = match dead.insert::<WireRow>("nowhere.wire").await {
        Err(e) => e,
        Ok(mut insert) => match insert.write(&rows(1)[0]).await {
            Err(e) => e,
            Ok(()) => insert.end().await.unwrap_err(),
        },
    };
    assert!(
        matches!(err, clickhouse::error::Error::Network(_)),
        "refused insert must be Error::Network, got {err:?}"
    );

    // Live server, bad statement: BadResponse carrying the code, NOT transport.
    let ch = admin();
    let err = ch.query("SELEC 1").fetch_one::<u8>().await.unwrap_err();
    let clickhouse::error::Error::BadResponse(message) = &err else {
        panic!("syntax error must be Error::BadResponse, got {err:?}");
    };
    assert!(message.contains("Code: 62"), "syntax error code missing: {message}");
    assert!(!matches!(search_error_from_error(&err), SearchError::Unavailable(_)));

    let err = ch
        .query("SELECT 1 FROM nan5412_no_such_db.no_such_table")
        .fetch_one::<u8>()
        .await
        .unwrap_err();
    let clickhouse::error::Error::BadResponse(message) = &err else {
        panic!("unknown table must be Error::BadResponse, got {err:?}");
    };
    assert!(message.contains("Code: 81") || message.contains("Code: 60"), "{message}");
    assert!(!matches!(search_error_from_error(&err), SearchError::Unavailable(_)));
}
