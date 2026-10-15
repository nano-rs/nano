// SPDX-License-Identifier: AGPL-3.0-or-later
//! Local RESP fixture; no external Redis, infrastructure, or ignored tests.
use axum::{
    extract::State,
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use nanosiem_core::{
    redis_transport::ReconnectingConnection,
    search::{
        AdmissionConfig, AdmissionController, QueryPriority, RedisJobStore, SearchJobStore,
        SearchTenantScope,
    },
};
use nanosiem_search::{cache::SearchResultCache, error::SearchError};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpListener,
    sync::watch,
};
use tower::ServiceExt;
use uuid::Uuid;

struct Backend {
    url: String,
    online: watch::Sender<bool>,
    deny: Arc<AtomicBool>,
    writes: Arc<AtomicUsize>,
    drop_write_reply: Arc<AtomicBool>,
    hang: Arc<AtomicBool>,
    script_loaded: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Backend {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Backend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("redis://{}/", listener.local_addr().unwrap());
        let (online, rx) = watch::channel(true);
        let deny = Arc::new(AtomicBool::new(false));
        let writes = Arc::new(AtomicUsize::new(0));
        let drop_write_reply = Arc::new(AtomicBool::new(false));
        let script_loaded = Arc::new(AtomicBool::new(false));
        let hang = Arc::new(AtomicBool::new(false));
        let values = Arc::new(Mutex::new(HashMap::<Vec<u8>, Vec<u8>>::new()));
        let task = tokio::spawn({
            let deny = deny.clone();
            let writes = writes.clone();
            let drop_write_reply = drop_write_reply.clone();
            let hang = hang.clone();
            let script_loaded = script_loaded.clone();
            async move {
                loop {
                    let (socket, _) = listener.accept().await.unwrap();
                    if !*rx.borrow() {
                        drop(socket);
                        continue;
                    }
                    let mut rx = rx.clone();
                    rx.borrow_and_update();
                    let deny = deny.clone();
                    let values = values.clone();
                    let writes = writes.clone();
                    let drop_write_reply = drop_write_reply.clone();
                    let hang = hang.clone();
                    let script_loaded = script_loaded.clone();
                    tokio::spawn(async move {
                        let mut socket = BufReader::new(socket);
                        loop {
                            let command = tokio::select! {
                                _ = rx.changed() => break,
                                command = read_command(&mut socket) => match command { Ok(c) => c, Err(_) => break },
                            };
                            if hang.load(Ordering::SeqCst) && command[0] != b"CLIENT" {
                                let _ = rx.changed().await;
                                break;
                            }
                            let reply = match command[0].as_slice() {
                                b"EVALSHA" => {
                                    if script_loaded.load(Ordering::SeqCst) {
                                        b":1\r\n".to_vec()
                                    } else {
                                        b"-NOSCRIPT missing fixture script\r\n".to_vec()
                                    }
                                }
                                b"SCRIPT" => {
                                    script_loaded.store(true, Ordering::SeqCst);
                                    format!(
                                        "+{}\r\n",
                                        redis::Script::new(
                                            std::str::from_utf8(&command[2]).unwrap()
                                        )
                                        .get_hash()
                                    )
                                    .into_bytes()
                                }
                                b"PING" => b"+PONG\r\n".to_vec(),
                                b"CLIENT" => b"+OK\r\n".to_vec(),
                                b"EVAL" => {
                                    if deny.load(Ordering::SeqCst) {
                                        b":-2\r\n".to_vec()
                                    } else {
                                        b":1\r\n".to_vec()
                                    }
                                }
                                b"HMGET" => {
                                    let n = command.len() - 2;
                                    format!("*{n}\r\n{}", "$-1\r\n".repeat(n)).into_bytes()
                                }
                                b"SETEX" | b"SET" => {
                                    writes.fetch_add(1, Ordering::SeqCst);
                                    let value = if command[0] == b"SETEX" {
                                        &command[3]
                                    } else {
                                        &command[2]
                                    };
                                    values
                                        .lock()
                                        .unwrap()
                                        .insert(command[1].clone(), value.clone());
                                    if drop_write_reply.swap(false, Ordering::SeqCst) {
                                        break;
                                    }
                                    b"+OK\r\n".to_vec()
                                }
                                b"GET" => match values.lock().unwrap().get(&command[1]) {
                                    Some(value) => {
                                        let mut reply =
                                            format!("${}\r\n", value.len()).into_bytes();
                                        reply.extend(value);
                                        reply.extend(b"\r\n");
                                        reply
                                    }
                                    None => b"$-1\r\n".to_vec(),
                                },
                                _ => panic!("unexpected fixture command: {:?}", command[0]),
                            };
                            if socket.get_mut().write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    });
                }
            }
        });
        Self {
            url,
            online,
            deny,
            writes,
            drop_write_reply,
            hang,
            script_loaded,
            task,
        }
    }
    async fn connection(&self) -> ReconnectingConnection {
        ReconnectingConnection::new(redis::Client::open(self.url.as_str()).unwrap())
            .await
            .unwrap()
    }
}
async fn read_command(
    socket: &mut BufReader<tokio::net::TcpStream>,
) -> std::io::Result<Vec<Vec<u8>>> {
    let mut line = String::new();
    if socket.read_line(&mut line).await? == 0 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    let count: usize = line.trim().strip_prefix('*').unwrap().parse().unwrap();
    let mut command = Vec::new();
    for _ in 0..count {
        line.clear();
        socket.read_line(&mut line).await?;
        let len: usize = line.trim().strip_prefix('$').unwrap().parse().unwrap();
        let mut bytes = vec![0; len + 2];
        socket.read_exact(&mut bytes).await?;
        bytes.truncate(len);
        command.push(bytes);
    }
    Ok(command)
}
async fn admitted(State(controller): State<Arc<AdmissionController>>) -> Response {
    match controller
        .acquire_for_scope(
            "fixture",
            SearchTenantScope::EnterpriseShared(Uuid::from_u128(1)),
            Uuid::from_u128(2),
            QueryPriority::Interactive,
        )
        .await
    {
        Ok(_permit) => axum::http::StatusCode::OK.into_response(),
        Err(error) => SearchError::from(nanosiem_core::SearchError::from(error)).into_response(),
    }
}
async fn request(app: &Router) -> Response {
    app.clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}
async fn await_ping(conn: &mut ReconnectingConnection) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if redis::cmd("PING").query_async::<String>(conn).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("reconnected within five seconds of backend recovery");
}

#[tokio::test]
async fn admission_outage_http_readiness_and_recovery() {
    let backend = Backend::start().await;
    let mut connection = backend.connection().await;
    // NAN-3299: a per-user "full" answer now waits in the queue; a short
    // queue timeout turns the fixture's permanent denial into a prompt 429.
    let controller = Arc::new(AdmissionController::new(AdmissionConfig {
        queue_timeout_ms: 300,
        ..AdmissionConfig::default()
    }));
    controller.set_redis(connection.clone()).await;
    let app = Router::new()
        .route("/", get(admitted))
        .with_state(controller.clone());
    assert_eq!(request(&app).await.status(), 200);
    backend.deny.store(true, Ordering::SeqCst);
    let denial = request(&app).await;
    assert_eq!(denial.status(), 429);
    assert!(denial.headers().get("retry-after").is_none());
    let body = axum::body::to_bytes(denial.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "ADMISSION_DENIED");
    assert!(controller.backend_ready().await);
    backend.deny.store(false, Ordering::SeqCst);
    backend.online.send(false).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let since = Instant::now();
    for _ in 0..3 {
        let outage = request(&app).await;
        assert_eq!(outage.status(), 429);
        assert_eq!(outage.headers()["retry-after"], "2");
        let body = axum::body::to_bytes(outage.into_body(), 4096)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["code"], "ADMISSION_BACKEND_UNAVAILABLE");
        assert_eq!(body["error"]["dependency"], "admission_backend_unavailable");
        assert_eq!(body["error"]["retryable"], true);
    }
    assert!(since.elapsed() < Duration::from_secs(3));
    assert!(
        controller.backend_ready().await,
        "brief blip keeps readiness"
    );
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert!(
        controller.backend_ready().await,
        "ten seconds is below grace"
    );
    tokio::time::sleep(Duration::from_secs(6)).await;
    assert!(
        !controller.backend_ready().await,
        "continuous outage exceeds grace"
    );
    backend.online.send(true).unwrap();
    // Readiness must recover without an incoming search or Redis command.
    tokio::time::timeout(Duration::from_secs(5), async {
        while !controller.backend_ready().await {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .expect("idle admission recovers readiness without traffic");
    await_ping(&mut connection).await;
    assert!(controller.backend_ready().await);
    assert_eq!(request(&app).await.status(), 200);
}

#[tokio::test]
async fn cache_and_job_store_recover_on_existing_handles() {
    let backend = Backend::start().await;
    let cache = SearchResultCache::connect(&backend.url).await.unwrap();
    let mut connection = backend.connection().await;
    let jobs = RedisJobStore::new(connection.clone());
    cache.set_cached("fixture", &vec![1, 2, 3]).await;
    assert_eq!(
        cache.get_cached::<Vec<i32>>("fixture").await,
        Some(vec![1, 2, 3])
    );
    assert!(jobs.get_checked("missing").await.unwrap().is_none());
    assert!(jobs.begin_hosted_promotion("fixture-job").await.unwrap());
    backend.online.send(false).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(cache.get_cached::<Vec<i32>>("fixture").await, None);
    assert!(jobs.get_checked("missing").await.is_err());
    backend.script_loaded.store(false, Ordering::SeqCst);
    backend.online.send(true).unwrap();
    await_ping(&mut connection).await;
    tokio::time::timeout(Duration::from_secs(5), async {
        while cache.get_cached::<Vec<i32>>("fixture").await.is_none() {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .unwrap();
    assert!(jobs.get_checked("missing").await.unwrap().is_none());
    assert!(jobs.begin_hosted_promotion("fixture-job").await.unwrap());
}

#[tokio::test]
async fn lost_write_reply_is_not_replayed_and_startup_outage_recovers() {
    let backend = Backend::start().await;
    backend.online.send(false).unwrap();
    let mut connection = backend.connection().await;
    assert!(redis::cmd("PING")
        .query_async::<String>(&mut connection)
        .await
        .is_err());
    backend.online.send(true).unwrap();
    await_ping(&mut connection).await;
    backend.drop_write_reply.store(true, Ordering::SeqCst);
    assert!(redis::cmd("SET")
        .arg("write")
        .arg("once")
        .query_async::<()>(&mut connection)
        .await
        .is_err());
    await_ping(&mut connection).await;
    assert_eq!(
        backend.writes.load(Ordering::SeqCst),
        1,
        "uncertain write must never be replayed"
    );
    assert_eq!(
        redis::cmd("GET")
            .arg("write")
            .query_async::<String>(&mut connection)
            .await
            .unwrap(),
        "once"
    );
}

#[tokio::test]
async fn silent_socket_times_out_and_shared_clones_recover() {
    let backend = Backend::start().await;
    let mut connection = backend.connection().await;
    let mut existing_clone = connection.clone();
    backend.hang.store(true, Ordering::SeqCst);
    let start = Instant::now();
    assert!(redis::cmd("GET")
        .arg("key")
        .query_async::<String>(&mut connection)
        .await
        .is_err());
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "silent socket has bounded command latency"
    );
    backend.hang.store(false, Ordering::SeqCst);
    backend.online.send(false).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    backend.online.send(true).unwrap();
    await_ping(&mut connection).await;
    assert!(redis::cmd("SET")
        .arg("key")
        .arg("recovered")
        .query_async::<()>(&mut existing_clone)
        .await
        .is_ok());
    assert_eq!(backend.writes.load(Ordering::SeqCst), 1);
    let values: Vec<Option<String>> = redis::pipe()
        .cmd("GET")
        .arg("key")
        .cmd("GET")
        .arg("key")
        .query_async(&mut connection)
        .await
        .unwrap();
    assert_eq!(
        values,
        vec![Some("recovered".to_string()), Some("recovered".to_string())]
    );
}

#[tokio::test]
async fn api_error_conversion_keeps_unavailable_retry_contract() {
    let error = nanosiem_api_lib::api_error::ApiError::from(
        nanosiem_core::SearchError::AdmissionBackendUnavailable,
    );
    let response = error.into_response();
    assert_eq!(response.status(), 429);
    assert_eq!(response.headers()["retry-after"], "2");
    let body = axum::body::to_bytes(response.into_body(), 4096)
        .await
        .unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body["error"]["code"], "ADMISSION_BACKEND_UNAVAILABLE");
    assert_eq!(body["error"]["details"]["retryable"], true);
}
