// SPDX-License-Identifier: AGPL-3.0-or-later
//! NAN-5565: the `max_query_size` lift reaches the wire, and only for
//! generated SQL.
//!
//! A local HTTP stub stands in for ClickHouse and records each request's
//! URL (where the client crate puts settings; the SQL is the POST body). The
//! source guard keeps every executor query on `sized_query`, so a new query
//! path cannot silently skip the lift.

use super::types::{max_query_size_for, ClickHouseExecutor, CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Start the stub: every request gets `200` with an empty body. Returns the
/// base URL and the recorded request targets (path + query string).
async fn stub_clickhouse() -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = seen.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let record = record.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 65536];
                // Head.
                let head_end = loop {
                    let n = match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break at + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
                let target = head
                    .lines()
                    .next()
                    .and_then(|line| line.split(' ').nth(1))
                    .unwrap_or_default()
                    .to_string();
                record.lock().unwrap().push(target);
                // Body: Content-Length, or chunked until the terminator.
                let lower = head.to_ascii_lowercase();
                let length = lower
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok());
                let chunked = lower.contains("transfer-encoding: chunked");
                loop {
                    let body = &buf[head_end..];
                    let done = match length {
                        Some(len) => body.len() >= len,
                        None if chunked => body.ends_with(b"0\r\n\r\n"),
                        None => true,
                    };
                    if done {
                        break;
                    }
                    match socket.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    }
                }
                let _ = socket
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (url, seen)
}

fn executor(url: &str) -> ClickHouseExecutor {
    ClickHouseExecutor::new(
        clickhouse::Client::default()
            .with_url(url)
            .with_compression(clickhouse::Compression::None),
    )
}

/// A raw-event SELECT whose text is past the default limit (no aggregation
/// tokens, so the paginated path takes the data + count branch).
fn big_sql() -> String {
    let keys: Vec<String> = (0..5000).map(|i| format!("'{:064x}'", i + 1)).collect();
    format!("SELECT * FROM logs WHERE file_hash IN ({})", keys.join(", "))
}

fn lifted_in(target: &str) -> Option<usize> {
    let query = target.split_once('?')?.1;
    query.split('&').find_map(|pair| {
        pair.strip_prefix("max_query_size=")
            .and_then(|v| v.parse().ok())
    })
}

fn settings() -> crate::search::admission::ClickHouseQuerySettings {
    crate::search::admission::ClickHouseQuerySettings {
        max_execution_time: 60,
        max_memory_usage_bytes: None,
        max_threads: 4,
        priority: 1,
        queue_max_wait_ms: 1000,
    }
}

#[tokio::test]
async fn generated_sql_carries_the_lift_on_every_query_it_sends() {
    let (url, seen) = stub_clickhouse().await;
    let sql = big_sql();
    assert!(sql.len() > CLICKHOUSE_DEFAULT_MAX_QUERY_SIZE);
    let generated = executor(&url).for_generated_sql(false);

    // Paginated data query + its parallel count companion.
    let _ = generated
        .execute_sql_with_settings(&sql, 100, 0, "q-1", &settings(), None, None, false)
        .await;
    // Plain dynamic query.
    let _ = generated.execute_dynamic_query(&sql, false).await;
    // Streaming.
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    let _ = generated
        .execute_dynamic_query_streaming(&sql, "q-2", None, tx, false)
        .await;

    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4, "data, count, dynamic, streaming: {seen:?}");
    for target in &seen {
        let lifted = lifted_in(target).unwrap_or_else(|| panic!("no max_query_size: {target}"));
        assert!(lifted > sql.len(), "{target}");
        assert!(Some(lifted) >= max_query_size_for(sql.len()), "{target}");
    }
}

#[tokio::test]
async fn other_sql_keeps_the_default_limit() {
    let (url, seen) = stub_clickhouse().await;
    let sql = big_sql();
    // Raw SQL and every other caller: the plain executor never lifts.
    let plain = executor(&url);
    let _ = plain.execute_dynamic_query(&sql, false).await;
    let _ = plain
        .execute_sql_with_settings(&sql, 100, 0, "q-3", &settings(), None, None, false)
        .await;
    // Generated SQL that fits the default sends nothing either.
    let _ = executor(&url)
        .for_generated_sql(false)
        .execute_dynamic_query("SELECT 1", false)
        .await;
    let seen = seen.lock().unwrap().clone();
    assert_eq!(seen.len(), 4, "{seen:?}");
    for target in &seen {
        assert_eq!(lifted_in(target), None, "{target}");
    }
}

#[test]
fn the_aggregation_decision_is_the_callers_for_generated_sql() {
    let client = clickhouse::Client::default();
    let plain = ClickHouseExecutor::new(client);
    // Text sniffing: an event-derived literal `sum(` reads as an aggregation.
    let sql = "SELECT * FROM logs WHERE d IN ('sum(x)')";
    assert!(plain.is_aggregation(sql));
    // Generated SQL: the caller's decision (made on the literal-free SQL).
    assert!(!plain.for_generated_sql(false).is_aggregation(sql));
    assert!(plain.for_generated_sql(true).is_aggregation("SELECT 1"));
}

/// Every ClickHouse query the executor builds goes through `sized_query`
/// (types.rs). `query_management.rs` (KILL / progress probes of fixed,
/// tiny SQL) is the only other place allowed to call `client.query(`.
#[test]
fn executor_queries_are_built_through_sized_query() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/search/execution/clickhouse_executor");
    let allowed = ["types.rs", "query_management.rs"];
    let pattern = regex::Regex::new(r"client\s*\.\s*query\s*\(").unwrap();
    let mut offenders = Vec::new();
    let mut stack = vec![dir];
    while let Some(path) = stack.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if !name.ends_with(".rs")
                || name.ends_with("tests.rs")
                || allowed.contains(&name.as_str())
            {
                continue;
            }
            let text = std::fs::read_to_string(&path).unwrap();
            if pattern.is_match(&text) {
                offenders.push(path.display().to_string());
            }
        }
    }
    assert!(offenders.is_empty(), "build queries with sized_query: {offenders:?}");
}
