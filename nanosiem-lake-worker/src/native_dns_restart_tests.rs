// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-3391: the object store restarts at a new address under the same name,
//! as `lake-object-store` does when Compose recreates it, and search must
//! recover without restarting the worker.
//!
//! The test needs the digest-verified chDB artifact and unprivileged user
//! namespaces. It re-executes itself under `unshare --user --map-root-user
//! --mount` and bind-mounts a private `/etc/hosts`, so the test can move
//! `nan3391-object-store` between loopback addresses (127.0.0.2 -> .3 -> .4
//! -> .5). A fake S3 endpoint stops on the old address (connections refused,
//! open sockets shut) and comes back on the new one.
//!
//! ```text
//! NANO_CHDB_LIBRARY_PATH=... NANO_CHDB_LIBRARY_SHA256=... cargo test -p nanosiem-lake-worker --lib \
//!   native_dns::restart_tests -- --ignored --nocapture
//! ```
//!
//! Before the fix (or with `NANO_CHDB_DNS_REFRESH_SECONDS=0`, which disables
//! the refresher), phase 1 times out: chDB keeps dialling the cached old
//! address with up to 500 S3 retries.

use crate::executor::{ExecutorMode, NativeExecutor};
use crate::native::NativeChdb;
use std::io::{BufRead, BufReader, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const IN_NAMESPACE: &str = "NANO_NAN3391_PRIVATE_HOSTS";
const HOST: &str = "nan3391-object-store";
const TEST_PATH: &str = "native_dns::restart_tests::object_store_restart_at_a_new_address_recovers_without_a_worker_restart";
/// Recovery bound for "the first request after the store is back".
const RECOVERY_BOUND: Duration = Duration::from_secs(15);
/// Hard stop for any single request, so a regression fails instead of hanging.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const ROWS: u64 = 2_000_000;

/// A minimal S3-compatible GET/HEAD endpoint for one object, with Range support.
struct FakeStore {
    stop: Arc<AtomicBool>,
    streams: Arc<Mutex<Vec<TcpStream>>>,
    served_bytes: Arc<AtomicU64>,
    accept: Option<JoinHandle<()>>,
}

impl FakeStore {
    fn start(ip: &str, port: u16, object: Arc<Vec<u8>>, chunk_delay: Duration) -> Self {
        let listener = TcpListener::bind((ip, port)).unwrap_or_else(|error| panic!("bind {ip}:{port}: {error}"));
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let streams = Arc::new(Mutex::new(Vec::<TcpStream>::new()));
        let served_bytes = Arc::new(AtomicU64::new(0));
        let accept = {
            let (stop, streams, served_bytes) = (stop.clone(), streams.clone(), served_bytes.clone());
            std::thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            streams.lock().unwrap().push(stream.try_clone().unwrap());
                            let (stop, object, served) = (stop.clone(), object.clone(), served_bytes.clone());
                            std::thread::spawn(move || serve(stream, &object, chunk_delay, &stop, &served));
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
                // The listener drops here: new connections are refused.
            })
        };
        Self { stop, streams, served_bytes, accept: Some(accept) }
    }

    /// Like the store process dying: stop listening and cut every open socket.
    fn kill(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(accept) = self.accept.take() {
            accept.join().unwrap();
        }
        for stream in self.streams.lock().unwrap().drain(..) {
            let _ = stream.shutdown(Shutdown::Both);
        }
    }
}

fn serve(stream: TcpStream, object: &[u8], chunk_delay: Duration, stop: &AtomicBool, served: &AtomicU64) {
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut writer = stream;
    loop {
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).unwrap_or(0) == 0 || stop.load(Ordering::SeqCst) {
            return;
        }
        let method = request_line.split_whitespace().next().unwrap_or("").to_string();
        let mut range = None;
        let mut body_length = 0_usize;
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end();
            if header.is_empty() {
                break;
            }
            let lower = header.to_ascii_lowercase();
            if let Some(value) = lower.strip_prefix("range: bytes=") {
                let (start, end) = value.split_once('-').unwrap();
                let start = start.parse::<usize>().unwrap_or(0);
                let end = end.parse::<usize>().unwrap_or(object.len() - 1).min(object.len() - 1);
                range = Some((start, end));
            } else if let Some(value) = lower.strip_prefix("content-length: ") {
                body_length = value.trim().parse().unwrap_or(0);
            }
        }
        if body_length > 0 {
            let mut body = vec![0_u8; body_length];
            if std::io::Read::read_exact(&mut reader, &mut body).is_err() {
                return;
            }
        }
        let (status, start, end) = match range {
            Some((start, end)) => ("206 Partial Content", start, end),
            None => ("200 OK", 0, object.len() - 1),
        };
        let mut head = format!(
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\
             ETag: \"nan3391\"\r\nLast-Modified: Thu, 08 Oct 2026 00:00:00 GMT\r\nAccept-Ranges: bytes\r\n",
            end + 1 - start
        );
        if range.is_some() {
            head.push_str(&format!("Content-Range: bytes {start}-{end}/{}\r\n", object.len()));
        }
        head.push_str("\r\n");
        if writer.write_all(head.as_bytes()).is_err() {
            return;
        }
        if method == "HEAD" {
            continue;
        }
        for chunk in object[start..=end].chunks(64 << 10) {
            if stop.load(Ordering::SeqCst) || writer.write_all(chunk).is_err() {
                return;
            }
            served.fetch_add(chunk.len() as u64, Ordering::SeqCst);
            if !chunk_delay.is_zero() {
                std::thread::sleep(chunk_delay);
            }
        }
    }
}

fn point_host_at(hosts: &std::path::Path, ip: &str) {
    // Rewrite in place: the bind mount follows the inode, not the path.
    std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(hosts)
        .and_then(|mut file| file.write_all(format!("127.0.0.1 localhost\n{ip} {HOST}\n").as_bytes()))
        .unwrap();
}

async fn timed_count(executor: &NativeExecutor, sql: &str) -> (Result<u64, String>, Duration) {
    let started = Instant::now();
    let result = match tokio::time::timeout(REQUEST_TIMEOUT, executor.execute_sql(sql.to_string(), vec![])).await {
        Err(_) => Err(format!("no answer within {REQUEST_TIMEOUT:?}")),
        Ok(Err(error)) => Err(error.to_string()),
        Ok(Ok(output)) => {
            let row: serde_json::Value = serde_json::from_slice(output.data.split(|b| *b == b'\n').next().unwrap()).unwrap();
            Ok(row["rows"].as_str().map_or_else(|| row["rows"].as_u64().unwrap(), |s| s.parse().unwrap()))
        }
    };
    (result, started.elapsed())
}

/// The first request after the store is back answers within `RECOVERY_BOUND`.
async fn first_answer_after_recovery(executor: &NativeExecutor, sql: &str, phase: &str) {
    let (result, elapsed) = timed_count(executor, sql).await;
    eprintln!("{phase}: first request after recovery -> {result:?} in {elapsed:.2?}");
    assert_eq!(result, Ok(ROWS), "{phase}: the first request after the store came back did not answer");
    assert!(elapsed < RECOVERY_BOUND, "{phase}: recovery took {elapsed:?} (bound {RECOVERY_BOUND:?})");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires NANO_CHDB_LIBRARY_PATH / NANO_CHDB_LIBRARY_SHA256 and unprivileged user namespaces (unshare)"]
async fn object_store_restart_at_a_new_address_recovers_without_a_worker_restart() {
    let Some(hosts) = std::env::var_os(IN_NAMESPACE) else {
        // Re-run this test as root of a private user+mount namespace.
        let scratch = tempfile::tempdir().unwrap();
        let hosts = scratch.path().join("hosts");
        point_host_at_new(&hosts, "127.0.0.2");
        let mut command = std::process::Command::new("unshare");
        command
            .args(["--user", "--map-root-user", "--mount", "--"])
            .arg(std::env::current_exe().unwrap())
            .args([TEST_PATH, "--exact", "--ignored", "--nocapture", "--test-threads=1"])
            .env(IN_NAMESPACE, &hosts)
            .env("NANO_CHDB_DNS_REFRESH_SECONDS", std::env::var("NANO_CHDB_DNS_REFRESH_SECONDS").unwrap_or_else(|_| "1".into()));
        // chDB honours proxy variables; the fake store is on loopback.
        for proxy in ["http_proxy", "https_proxy", "all_proxy", "no_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"] {
            command.env_remove(proxy);
        }
        let status = command.status().expect("unshare is required for this test");
        assert!(status.success(), "namespaced run failed: {status}");
        return;
    };
    let hosts = std::path::PathBuf::from(hosts);
    let mounted = std::process::Command::new("mount").arg("--bind").arg(&hosts).arg("/etc/hosts").status().unwrap();
    assert!(mounted.success(), "bind-mounting a private /etc/hosts failed");

    let runtime = NativeChdb::load_verified(
        std::env::var("NANO_CHDB_LIBRARY_PATH").unwrap(),
        &std::env::var("NANO_CHDB_LIBRARY_SHA256").unwrap(),
    )
    .unwrap();
    // chDB keeps process-global hooks; keep the library loaded until exit.
    std::mem::forget(runtime.clone());
    let executor = NativeExecutor::start_named_with_mode(runtime.clone(), 1, "nan3391", ExecutorMode::ReadOnly).unwrap();

    let scratch = tempfile::tempdir().unwrap();
    let parquet = scratch.path().join("events.parquet");
    let args = crate::executor::executor_connection_args(None);
    let writer = runtime.connect(&args.iter().map(String::as_str).collect::<Vec<_>>()).unwrap();
    writer
        .query_with_params(
            &format!(
                "INSERT INTO FUNCTION file('{}', Parquet) SELECT number AS n, toString(number) AS s FROM numbers({ROWS}) \
                 SETTINGS output_format_parquet_row_group_size=100000",
                parquet.display()
            ),
            "Null",
            &[],
        )
        .unwrap();
    drop(writer);
    let object = Arc::new(std::fs::read(&parquet).unwrap());

    let port = TcpListener::bind(("127.0.0.2", 0)).unwrap().local_addr().unwrap().port();
    let sql = format!(
        "SELECT count() AS rows, sum(n) AS total FROM s3('http://{HOST}:{port}/bucket/events.parquet', 'nano', 'nano-secret', Parquet) \
         SETTINGS max_threads=1"
    );

    // Warm: chDB resolves and caches the store's first address.
    let store = FakeStore::start("127.0.0.2", port, object.clone(), Duration::ZERO);
    let (warm, _) = timed_count(&executor, &sql).await;
    assert_eq!(warm, Ok(ROWS));

    // Phase 1: the store is recreated between requests and comes back at a
    // new address (a Compose recreate of lake-object-store).
    store.kill();
    point_host_at(&hosts, "127.0.0.3");
    let store = FakeStore::start("127.0.0.3", port, object.clone(), Duration::ZERO);
    first_answer_after_recovery(&executor, &sql, "phase 1 (restart between requests)").await;

    // Phase 2: the store dies while a query is reading from it, then comes
    // back at another address. The in-flight query must end (answer or
    // error) within the bound and must not wedge the single lane.
    store.kill();
    point_host_at(&hosts, "127.0.0.4");
    let slow = FakeStore::start("127.0.0.4", port, object.clone(), Duration::from_millis(25));
    let in_flight = {
        let (executor, sql) = (executor.clone(), sql.clone());
        tokio::spawn(async move { timed_count(&executor, &sql).await })
    };
    let reading_deadline = Instant::now() + RECOVERY_BOUND;
    while slow.served_bytes.load(Ordering::SeqCst) < (256 << 10) {
        assert!(Instant::now() < reading_deadline, "the in-flight query never started reading");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    slow.kill();
    let restarted = Instant::now();
    point_host_at(&hosts, "127.0.0.5");
    tokio::time::sleep(Duration::from_secs(2)).await;
    let _store = FakeStore::start("127.0.0.5", port, object.clone(), Duration::ZERO);
    let (in_flight_result, _) = in_flight.await.unwrap();
    let in_flight_ended = restarted.elapsed();
    eprintln!("phase 2: in-flight query -> {in_flight_result:?}, ended {in_flight_ended:.2?} after the store died");
    assert!(in_flight_ended < RECOVERY_BOUND + Duration::from_secs(2), "the in-flight query held the lane for {in_flight_ended:?}");
    first_answer_after_recovery(&executor, &sql, "phase 2 (restart during a read)").await;
    // Keep the lanes open through exit, like the runtime above: a lane closing
    // its connection (and chDB's S3 clients) while the process runs C++ static
    // destructors trips aws-c-common's allocator assertion (SIGABRT).
    std::mem::forget(executor);
}

fn point_host_at_new(hosts: &std::path::Path, ip: &str) {
    std::fs::write(hosts, format!("127.0.0.1 localhost\n{ip} {HOST}\n")).unwrap();
}
