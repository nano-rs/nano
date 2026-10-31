// SPDX-License-Identifier: AGPL-3.0-or-later

//! Open-core HEC front door. Vector's initial 200 allocates an ackId;
//! only a true indexer acknowledgement proves the Bronze PUT completed.
//! Match the hosted sender's poll-before-success contract for direct clients.

use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::{body::Incoming, Request, Response, StatusCode};
use sha2::{Digest, Sha256};
mod admission;
use std::{
    collections::BTreeMap,
    convert::Infallible,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_BODY: usize = 50 * 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(25);

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct HecAckRequest {
    pub acks: Vec<u64>,
}

#[derive(Clone)]
struct Proxy {
    client: reqwest::Client,
    upstream: String,
    receipts: Arc<Mutex<BTreeMap<[u8; 32], Instant>>>,
    bodies: Arc<tokio::sync::Semaphore>,
    pending_bytes: Arc<tokio::sync::Semaphore>,
    admission: Arc<admission::CommitAdmission>,
    auth_channel: String,
}

fn response(status: StatusCode, body: impl Into<Bytes>) -> Response<Full<Bytes>> {
    let mut reply = Response::builder()
        .status(status)
        .header("content-type", "application/json");
    if status == StatusCode::SERVICE_UNAVAILABLE {
        reply = reply.header("retry-after", "1");
    }
    reply.body(Full::new(body.into())).unwrap()
}

impl Proxy {
    fn new(upstream: String, config_root: std::path::PathBuf) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(DEADLINE)
            .build()?;
        Ok(Self {
            upstream,
            receipts: Arc::default(),
            bodies: Arc::new(tokio::sync::Semaphore::new(1)),
            pending_bytes: Arc::new(tokio::sync::Semaphore::new(MAX_BODY)),
            admission: Arc::new(admission::CommitAdmission::new(config_root, client.clone())),
            // Empty authentication queries carry no delivery ACKs. Reuse only
            // this probe channel: Vector allocates state even for empty ACK
            // queries, including requests native admission will reject.
            auth_channel: uuid::Uuid::from_bytes(random_id()?).to_string(),
            client,
        })
    }

    async fn handle(&self, request: Request<Incoming>) -> Response<Full<Bytes>> {
        match tokio::time::timeout(DEADLINE, forward(self, request)).await {
            Ok(Ok(reply)) => reply,
            _ => response(
                StatusCode::SERVICE_UNAVAILABLE,
                r#"{"text":"Durable delivery not confirmed; retry","code":9}"#,
            ),
        }
    }
}

#[utoipa::path(post, path = "/services/collector/{endpoint}", tag = "ingestion",
    params(("endpoint" = String, Path, description = "HEC event, raw, or ack endpoint")),
    request_body = String,
    responses((status = 200, description = "Every event is durable; ACK queries return sender-bound receipts"),
        (status = 401, description = "Invalid or revoked ingest token"),
        (status = 413, description = "Request exceeds 50 MiB"),
        (status = 503, description = "Native commit backpressure or durable delivery not confirmed; retry")),
    security(("hec_token" = [])))]
async fn forward(
    proxy: &Proxy,
    request: Request<Incoming>,
) -> anyhow::Result<Response<Full<Bytes>>> {
    let path = request.uri().path();
    let ingest = matches!(
        path,
        "/services/collector"
            | "/services/collector/"
            | "/services/collector/event"
            | "/services/collector/event/1.0"
            | "/services/collector/raw"
            | "/services/collector/raw/1.0"
    );
    if !ingest
        && !matches!(
            path,
            "/services/collector/ack"
                | "/services/collector/health"
                | "/services/collector/health/1.0"
        )
    {
        return Ok(response(StatusCode::NOT_FOUND, "{}"));
    }
    let ack_query = path == "/services/collector/ack";
    let (parts, body) = request.into_parts();
    let url = format!(
        "{}{}",
        proxy.upstream,
        parts.uri.path_and_query().unwrap().as_str()
    );
    if !ingest && !ack_query {
        // Health has no request payload. Never let an anonymous slow body
        // occupy a connection until the delivery deadline.
        let reply = proxy.client.request(parts.method, url).send().await?;
        return Ok(response(reply.status(), reply.bytes().await?));
    }
    // Authenticate headers before reading an upload. A sender without a valid
    // credential cannot monopolize the one large-body slot. The authoritative
    // token file and its revocation semantics remain owned by Vector.
    let mut check = proxy
        .client
        .post(format!("{}/services/collector/ack", proxy.upstream))
        .header("x-splunk-request-channel", &proxy.auth_channel)
        .json(&serde_json::json!({"acks": []}));
    if let Some(auth) = parts.headers.get("authorization") {
        check = check.header("authorization", auth.clone());
    }
    let checked = check.send().await?;
    let checked_status = checked.status();
    let checked_body = checked.bytes().await?;
    if !checked_status.is_success() {
        return Ok(response(checked_status, checked_body));
    }
    let authenticated: serde_json::Value = serde_json::from_slice(&checked_body)?;
    anyhow::ensure!(
        authenticated["acks"].is_object(),
        "invalid authentication ACK response"
    );
    if ingest {
        // Auth precedes status and body reads. Refuse new input before it can
        // accumulate in Bronze faster than native ingest can commit it.
        proxy.admission.check().await?;
    }
    let body_permit = if ingest {
        Some(proxy.bodies.clone().acquire_owned().await?)
    } else {
        None
    };
    let body = match Limited::new(body, if ingest { MAX_BODY } else { 128 * 1024 })
        .collect()
        .await
    {
        Ok(body) => body.to_bytes(),
        Err(_) => return Ok(response(StatusCode::PAYLOAD_TOO_LARGE, "{}")),
    };
    // Bound active pending uploads together, including bodies already handed
    // to Vector. Small concurrent requests can join one storage batch without
    // admitting sixteen maximum-size uploads into Vector's memory at once.
    let _pending_bytes = if ingest {
        match proxy
            .pending_bytes
            .clone()
            .try_acquire_many_owned(body.len().max(1) as u32)
        {
            Ok(permit) => Some(permit),
            Err(_) => {
                return Ok(response(
                    StatusCode::SERVICE_UNAVAILABLE,
                    r#"{"text":"Ingest busy; retry","code":9}"#,
                ))
            }
        }
    } else {
        None
    };
    let query_channel = reqwest::Url::parse(&format!("http://localhost{}", parts.uri))?
        .query_pairs()
        .find(|(key, _)| key == "channel")
        .map(|(_, value)| value.into_owned())
        .unwrap_or_default();
    let sender_channel = parts
        .headers
        .get("x-splunk-request-channel")
        .map(|h| h.as_bytes())
        .unwrap_or(query_channel.as_bytes());
    // A private channel prevents ackId reuse after a Vector restart from
    // confusing a prior request with a newly accepted, still pending batch.
    let mut headers = reqwest::header::HeaderMap::new();
    for name in [
        "authorization",
        "content-type",
        "content-encoding",
        "x-forwarded-for",
    ] {
        if let Some(value) = parts.headers.get(name) {
            headers.insert(name, value.clone());
        }
    }
    if ack_query {
        let query: HecAckRequest = match serde_json::from_slice(&body) {
            Ok(query) => query,
            Err(_) => return Ok(response(StatusCode::BAD_REQUEST, "{}")),
        };
        // The empty upstream probe authenticated this request, including a
        // cache hit. Public receipt IDs must never be sent to Vector's probe
        // channel, which never contains delivery ACKs.
        let ids = query.acks;
        if ids.len() > 1024 {
            return Ok(response(StatusCode::BAD_REQUEST, "{}"));
        }
        let mut acks = serde_json::Map::new();
        let mut receipts = proxy.receipts.lock().unwrap();
        for id in ids {
            let key = receipt_key(&headers, sender_channel, id);
            let delivered = receipts
                .remove(&key)
                .is_some_and(|expiry| expiry > Instant::now());
            acks.insert(id.to_string(), delivered.into());
        }
        return Ok(response(
            StatusCode::OK,
            serde_json::to_vec(&serde_json::json!({"acks": acks}))?,
        ));
    }
    // A new private delivery channel per upload is still required: reusing
    // delivery channels could mistake a restarted Vector's ackId for an old
    // pending request. The shared authentication-only channel is never used.
    let channel = uuid::Uuid::from_bytes(random_id()?).to_string();
    headers.insert("x-splunk-request-channel", channel.parse().unwrap());
    let reply = proxy
        .client
        .request(parts.method, url)
        .headers(headers.clone())
        .body(body)
        .send()
        .await?;
    let status = reply.status();
    let body = reply.bytes().await?;
    drop(body_permit);
    if !status.is_success() {
        return Ok(response(status, body));
    }
    let mut receipt: serde_json::Value = serde_json::from_slice(&body)?;
    let id = receipt["ackId"]
        .as_u64()
        .ok_or_else(|| anyhow::anyhow!("missing durable receipt"))?;
    // Poll with exactly the sender's credential and channel. Never substitute
    // an install/admin credential. Failure, restart, or an unknown ackId must
    // never produce success. Issue a separate receipt for polling clients.
    let polling_started = Instant::now();
    let mut poll_interval = Duration::from_millis(1);
    loop {
        let mut poll = proxy
            .client
            .post(format!("{}/services/collector/ack", proxy.upstream))
            .header("x-splunk-request-channel", &channel);
        if let Some(auth) = headers.get("authorization") {
            poll = poll.header("authorization", auth.clone());
        }
        let reply = poll.json(&serde_json::json!({"acks": [id]})).send().await?;
        anyhow::ensure!(reply.status().is_success(), "ack query refused");
        let result: serde_json::Value = reply.json().await?;
        if result["acks"][id.to_string()].as_bool() == Some(true) {
            // A durable PUT can finish after admission closes. Do not issue a
            // success receipt while native commit progress is backpressured.
            proxy.admission.check().await?;
            // Vector consumes a true ACK on read. Give polling senders a
            // separate receipt, bound to their token and channel. Receipts
            // expire and are bounded; losing one only causes a safe retry.
            let public_id = u64::from_le_bytes(
                uuid::Uuid::from_bytes(random_id()?).as_bytes()[..8]
                    .try_into()
                    .unwrap(),
            ) & ((1 << 53) - 1);
            let mut receipts = proxy.receipts.lock().unwrap();
            receipts.retain(|_, expiry| *expiry > Instant::now());
            if receipts.len() >= 8192 {
                receipts.pop_first();
            }
            receipts.insert(
                receipt_key(&headers, sender_channel, public_id),
                Instant::now() + Duration::from_secs(600),
            );
            receipt["ackId"] = public_id.into();
            return Ok(response(status, serde_json::to_vec(&receipt)?));
        }
        // Observe fast commits promptly, while retaining the existing polling
        // rate during storage stalls. Every success still needs a true ACK.
        tokio::time::sleep(poll_interval).await;
        let cap = if polling_started.elapsed() < Duration::from_millis(100) {
            Duration::from_millis(5)
        } else {
            Duration::from_millis(50)
        };
        poll_interval = (poll_interval * 2).min(cap);
    }
}

fn random_id() -> anyhow::Result<[u8; 16]> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random request id: {e}"))?;
    Ok(bytes)
}

fn receipt_key(headers: &reqwest::header::HeaderMap, channel: &[u8], id: u64) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(
        headers
            .get("authorization")
            .map(|h| h.as_bytes())
            .unwrap_or_default(),
    );
    hash.update([0]);
    hash.update(channel);
    hash.update(id.to_le_bytes());
    hash.finalize().into()
}

/// One collected body, a byte cap on pending uploads, and bounded header/auth
/// slots fit the memory guard. Success still requires the request's durable ACK.
#[utoipa::path(get, path = "/services/collector/health", tag = "ingestion",
    responses((status = 200, description = "HEC receiver health"),
        (status = 503, description = "HEC upstream unavailable")))]
pub async fn serve() -> anyhow::Result<()> {
    serve_on(
        tokio::net::TcpListener::bind("0.0.0.0:8088").await?,
        "http://vector:8088".into(),
        "/etc/nano-lake-cell".into(),
    )
    .await
}

async fn serve_on(
    listener: tokio::net::TcpListener,
    upstream: String,
    config_root: std::path::PathBuf,
) -> anyhow::Result<()> {
    let proxy = Proxy::new(upstream, config_root)?;
    let capacity = Arc::new(tokio::sync::Semaphore::new(16));
    loop {
        let permit = capacity.clone().acquire_owned().await?;
        let (stream, peer) = listener.accept().await?;
        let proxy = proxy.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let service = hyper::service::service_fn(move |mut request: Request<Incoming>| {
                let proxy = proxy.clone();
                if !request.headers().contains_key("x-forwarded-for") {
                    request
                        .headers_mut()
                        .insert("x-forwarded-for", peer.ip().to_string().parse().unwrap());
                }
                async move { Ok::<_, Infallible>(proxy.handle(request).await) }
            });
            // No keep-alive: a single idle connection cannot hold admission.
            let _ = hyper::server::conn::http1::Builder::new()
                .keep_alive(false)
                .header_read_timeout(Duration::from_secs(5))
                .timer(hyper_util::rt::TokioTimer::new())
                .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    struct Lab {
        url: String,
        delivered: Arc<AtomicBool>,
        missing_receipt: Arc<AtomicBool>,
        revoked: Arc<AtomicBool>,
        uploads: Arc<AtomicUsize>,
        native_status: Arc<Mutex<serde_json::Value>>,
        native_status_code: Arc<AtomicUsize>,
        status_reads: Arc<AtomicUsize>,
        config: tempfile::TempDir,
        auth_channels: Arc<Mutex<std::collections::BTreeSet<String>>>,
        delivery_channels: Arc<Mutex<std::collections::BTreeSet<String>>>,
        delivery_polls: Arc<Mutex<std::collections::BTreeSet<String>>>,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            for task in &self.tasks {
                task.abort();
            }
        }
    }

    fn input(objects: u64, age: f64) -> serde_json::Value {
        serde_json::json!({"objects": objects, "consumed_objects_total": 0, "oldest_age_seconds": age, "discovery_age_seconds": 0.0})
    }

    fn production_process(
        role: crate::contract::Role,
        heartbeat: crate::contract::Heartbeat,
    ) -> serde_json::Value {
        serde_json::to_value(crate::supervisor::ProcStatus {
            role,
            pid: 1,
            uid: 1000,
            uptime_secs: 120.0,
            idle_secs: 120.0,
            heartbeat_age_secs: 0.0,
            heartbeat,
            landlock: "full".into(),
            stopping: false,
            runs_rules: false,
            ingest_eps: None,
            ingest_memory_cap_bytes: None,
        })
        .unwrap()
    }

    async fn lab() -> Lab {
        let delivered = Arc::new(AtomicBool::new(false));
        let missing_receipt = Arc::new(AtomicBool::new(false));
        let revoked = Arc::new(AtomicBool::new(false));
        let uploads = Arc::new(AtomicUsize::new(0));
        let auth_channels = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let delivery_channels = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let delivery_polls = Arc::new(Mutex::new(std::collections::BTreeSet::new()));
        let channel_sets = (
            auth_channels.clone(),
            delivery_channels.clone(),
            delivery_polls.clone(),
        );
        let upstream = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_url = format!("http://{}", upstream.local_addr().unwrap());
        // Match supervisor status and the shared production heartbeat serializer.
        // Query has no ingest evidence: None is OMITTED, not serialized as null.
        let native_status = Arc::new(Mutex::new(serde_json::json!({"tenants": [{
            "tenant_id": "fixture", "processes": [
                production_process(crate::contract::Role::Ingest, crate::contract::Heartbeat {
                    ingest_pending_input: Some(serde_json::from_value(input(0, 0.0)).unwrap()),
                    ..Default::default()
                }),
                production_process(crate::contract::Role::Query, crate::contract::Heartbeat::default()),
            ]
        }]})));
        let native_status_code = Arc::new(AtomicUsize::new(200));
        let status_reads = Arc::new(AtomicUsize::new(0));
        let config = tempfile::tempdir().unwrap();
        std::fs::write(
            config.path().join("routes.json"),
            serde_json::json!({
                "fixture": {"cell_origin": upstream_url}
            })
            .to_string(),
        )
        .unwrap();
        std::fs::write(
            config.path().join("router-query.token"),
            "query-only-status",
        )
        .unwrap();
        let (native, native_code, reads) = (
            native_status.clone(),
            native_status_code.clone(),
            status_reads.clone(),
        );
        let (ready, missing, denied, received) = (
            delivered.clone(),
            missing_receipt.clone(),
            revoked.clone(),
            uploads.clone(),
        );
        let mock = tokio::spawn(async move {
            loop {
                let (stream, _) = upstream.accept().await.unwrap();
                let channel_sets = channel_sets.clone();
                let (native, native_code, reads) =
                    (native.clone(), native_code.clone(), reads.clone());
                let (ready, missing, denied, received) = (
                    ready.clone(),
                    missing.clone(),
                    denied.clone(),
                    received.clone(),
                );
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                        let (auth_channels, delivery_channels, delivery_polls) =
                            channel_sets.clone();
                        let (native, native_code, reads) =
                            (native.clone(), native_code.clone(), reads.clone());
                        let (ready, missing, denied, received) = (
                            ready.clone(),
                            missing.clone(),
                            denied.clone(),
                            received.clone(),
                        );
                        async move {
                            let auth = request
                                .headers()
                                .get("authorization")
                                .and_then(|h| h.to_str().ok());
                            let result = if request.uri().path() == "/v1/status" {
                                reads.fetch_add(1, Ordering::SeqCst);
                                if auth == Some("Bearer query-only-status") {
                                    response(
                                        StatusCode::from_u16(
                                            native_code.load(Ordering::SeqCst) as u16
                                        )
                                        .unwrap(),
                                        native.lock().unwrap().to_string(),
                                    )
                                } else {
                                    response(StatusCode::UNAUTHORIZED, "{}")
                                }
                            } else if auth == Some("Splunk malformed-ack-reply") {
                                response(StatusCode::OK, r#"{"code":4}"#)
                            } else if denied.load(Ordering::SeqCst)
                                || !matches!(auth, Some("Splunk sender" | "Splunk other"))
                            {
                                response(StatusCode::UNAUTHORIZED, "{}")
                            } else if request.uri().path().ends_with("/ack") {
                                let channel = request.headers()["x-splunk-request-channel"]
                                    .to_str()
                                    .unwrap()
                                    .to_owned();
                                let bytes = request.into_body().collect().await.unwrap().to_bytes();
                                let query: HecAckRequest = serde_json::from_slice(&bytes).unwrap();
                                if query.acks.is_empty() {
                                    auth_channels.lock().unwrap().insert(channel);
                                    response(StatusCode::OK, r#"{"acks":{}}"#)
                                } else {
                                    delivery_polls.lock().unwrap().insert(channel);
                                    response(StatusCode::OK, serde_json::json!({"acks": {"7": ready.load(Ordering::SeqCst)}}).to_string())
                                }
                            } else if missing.load(Ordering::SeqCst) {
                                response(StatusCode::OK, r#"{"code":0}"#)
                            } else {
                                delivery_channels.lock().unwrap().insert(
                                    request.headers()["x-splunk-request-channel"]
                                        .to_str()
                                        .unwrap()
                                        .to_owned(),
                                );
                                request.into_body().collect().await.unwrap();
                                received.fetch_add(1, Ordering::SeqCst);
                                response(StatusCode::OK, r#"{"code":0,"ackId":7}"#)
                            };
                            Ok::<_, Infallible>(result)
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let config_root = config.path().to_owned();
        let proxy = tokio::spawn(async move {
            serve_on(listener, upstream_url, config_root).await.unwrap();
        });
        Lab {
            url,
            delivered,
            missing_receipt,
            revoked,
            uploads,
            native_status,
            native_status_code,
            status_reads,
            config,
            auth_channels,
            delivery_channels,
            delivery_polls,
            tasks: vec![mock, proxy],
        }
    }

    fn post(
        client: &reqwest::Client,
        lab: &Lab,
        path: &str,
        token: &str,
        channel: &str,
    ) -> reqwest::RequestBuilder {
        client
            .post(format!("{}{path}", lab.url))
            .header("authorization", token)
            .header("x-splunk-request-channel", channel)
    }

    async fn wait_for_uploads(lab: &Lab, count: usize) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while lab.uploads.load(Ordering::SeqCst) < count {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("concurrent uploads must reach Vector before any durable ACK");
    }

    #[tokio::test]
    async fn concurrent_senders_join_a_commit_without_early_success() {
        let lab = lab().await;
        let mut requests = Vec::new();
        for _ in 0..16 {
            let request = post(
                &reqwest::Client::new(),
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "channel",
            )
            .body(r#"{"event":"batch"}"#);
            requests.push(tokio::spawn(async move { request.send().await.unwrap() }));
        }
        wait_for_uploads(&lab, 16).await;
        assert!(
            requests.iter().all(|request| !request.is_finished()),
            "upload acceptance is not durable delivery"
        );
        lab.delivered.store(true, Ordering::SeqCst);
        for request in requests {
            assert_eq!(request.await.unwrap().status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn concurrent_pending_senders_fail_closed_on_upstream_failure() {
        let lab = lab().await;
        let mut requests = Vec::new();
        for _ in 0..4 {
            let request = post(
                &reqwest::Client::new(),
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "channel",
            )
            .body("{}");
            requests.push(tokio::spawn(async move { request.send().await.unwrap() }));
        }
        wait_for_uploads(&lab, 4).await;
        lab.revoked.store(true, Ordering::SeqCst);
        for request in requests {
            assert_eq!(
                request.await.unwrap().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
    }

    #[tokio::test]
    async fn pending_upload_bytes_are_bounded_and_released_after_commit() {
        let lab = lab().await;
        let client = reqwest::Client::new();
        let request = post(
            &client,
            &lab,
            "/services/collector/raw",
            "Splunk sender",
            "channel",
        )
        .body(vec![b'x'; 30 * 1024 * 1024]);
        let first = tokio::spawn(async move { request.send().await.unwrap() });
        wait_for_uploads(&lab, 1).await;
        let second = post(
            &client,
            &lab,
            "/services/collector/raw",
            "Splunk sender",
            "channel",
        )
        .body(vec![b'x'; 30 * 1024 * 1024])
        .send()
        .await
        .unwrap();
        assert_eq!(second.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(lab.uploads.load(Ordering::SeqCst), 1);
        assert!(!first.is_finished());
        lab.delivered.store(true, Ordering::SeqCst);
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);
        let retry = post(
            &client,
            &lab,
            "/services/collector/raw",
            "Splunk sender",
            "channel",
        )
        .body(vec![b'x'; 30 * 1024 * 1024])
        .send()
        .await
        .unwrap();
        assert_eq!(retry.status(), StatusCode::OK);
        assert_eq!(lab.uploads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn success_waits_for_durable_put_and_polling_receipt_is_sender_bound() {
        let lab = lab().await;
        let client = reqwest::Client::new();
        let request = post(
            &client,
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "channel",
        )
        .body(r#"{"event":"burst"}"#)
        .send();
        tokio::pin!(request);
        assert!(
            tokio::time::timeout(Duration::from_millis(150), &mut request)
                .await
                .is_err(),
            "pending data must not get 200"
        );
        lab.delivered.store(true, Ordering::SeqCst);
        let receipt = request.await.unwrap();
        assert_eq!(receipt.status(), StatusCode::OK);
        let id = receipt.json::<serde_json::Value>().await.unwrap()["ackId"]
            .as_u64()
            .unwrap();
        for (token, channel, expected) in [
            ("Splunk other", "channel", false),
            ("Splunk sender", "wrong-channel", false),
            ("Splunk sender", "channel", true),
            ("Splunk sender", "channel", false),
        ] {
            let reply = post(&client, &lab, "/services/collector/ack", token, channel)
                .json(&serde_json::json!({"acks": [id]}))
                .send()
                .await
                .unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            assert_eq!(
                reply.json::<serde_json::Value>().await.unwrap()["acks"][id.to_string()],
                expected
            );
        }
    }

    #[tokio::test]
    async fn missing_receipt_and_invalid_credentials_never_report_success() {
        let lab = lab().await;
        lab.missing_receipt.store(true, Ordering::SeqCst);
        let client = reqwest::Client::new();
        let result = post(
            &client,
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "channel",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        assert_eq!(result.status(), StatusCode::SERVICE_UNAVAILABLE);
        for path in ["/services/collector/event", "/services/collector/ack"] {
            let result = post(&client, &lab, path, "Splunk revoked", "channel")
                .body(r#"{"acks":[7]}"#)
                .send()
                .await
                .unwrap();
            assert_eq!(result.status(), StatusCode::UNAUTHORIZED);
        }
    }

    #[tokio::test]
    async fn lost_or_pending_ack_cannot_become_a_success_receipt() {
        let lab = lab().await;
        let client = reqwest::Client::new();
        let request = post(
            &client,
            &lab,
            "/services/collector/raw",
            "Splunk sender",
            "channel",
        )
        .body("raw event")
        .send();
        assert!(tokio::time::timeout(Duration::from_millis(200), request)
            .await
            .is_err());
    }
    #[tokio::test]
    async fn query_channels_work_and_revocation_refuses_a_cached_receipt() {
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        let client = reqwest::Client::new();
        let reply = client
            .post(format!(
                "{}/services/collector/event?channel=query-channel",
                lab.url
            ))
            .header("authorization", "Splunk sender")
            .body("{}")
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        let id = reply.json::<serde_json::Value>().await.unwrap()["ackId"]
            .as_u64()
            .unwrap();
        lab.revoked.store(true, Ordering::SeqCst);
        let reply = client
            .post(format!(
                "{}/services/collector/ack?channel=query-channel",
                lab.url
            ))
            .header("authorization", "Splunk sender")
            .json(&serde_json::json!({"acks": [id]}))
            .send()
            .await
            .unwrap();
        assert_eq!(reply.status(), StatusCode::UNAUTHORIZED);
        lab.revoked.store(false, Ordering::SeqCst);
        let reply = client
            .post(format!(
                "{}/services/collector/ack?channel=query-channel",
                lab.url
            ))
            .header("authorization", "Splunk sender")
            .json(&serde_json::json!({"acks": [id]}))
            .send()
            .await
            .unwrap();
        assert_eq!(
            reply.json::<serde_json::Value>().await.unwrap()["acks"][id.to_string()],
            true
        );
    }

    #[tokio::test]
    async fn malformed_success_from_the_authentication_probe_cannot_authorize_receipt_queries() {
        let lab = lab().await;
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/ack",
            "Splunk malformed-ack-reply",
            "one",
        )
        .json(&serde_json::json!({"acks":[]}))
        .send()
        .await
        .unwrap();
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(lab.uploads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn backpressure_authentication_uses_one_probe_channel_and_unique_delivery_channels() {
        let lab = lab().await;
        let client = reqwest::Client::new();
        lab.native_status.lock().unwrap()["tenants"][0]["processes"][0]["heartbeat"]
            ["ingest_pending_input"] = input(1, 31.0);
        for _ in 0..100 {
            let reply = post(
                &client,
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        assert_eq!(lab.auth_channels.lock().unwrap().len(), 1);
        assert!(lab.delivery_channels.lock().unwrap().is_empty());
        lab.revoked.store(true, Ordering::SeqCst);
        assert_eq!(
            post(
                &client,
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one"
            )
            .body("{}")
            .send()
            .await
            .unwrap()
            .status(),
            StatusCode::UNAUTHORIZED
        );
        lab.revoked.store(false, Ordering::SeqCst);
        lab.native_status.lock().unwrap()["tenants"][0]["processes"][0]["heartbeat"]
            ["ingest_pending_input"] = input(0, 0.0);
        lab.delivered.store(true, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let mut receipt = 0;
        for _ in 0..4 {
            let reply = post(
                &client,
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            receipt = reply.json::<serde_json::Value>().await.unwrap()["ackId"]
                .as_u64()
                .unwrap();
        }
        let reply = post(
            &client,
            &lab,
            "/services/collector/ack",
            "Splunk sender",
            "one",
        )
        .json(&serde_json::json!({"acks":[receipt]}))
        .send()
        .await
        .unwrap();
        assert_eq!(
            reply.json::<serde_json::Value>().await.unwrap()["acks"][receipt.to_string()],
            true
        );
        let auth = lab.auth_channels.lock().unwrap();
        let delivery = lab.delivery_channels.lock().unwrap();
        assert_eq!(auth.len(), 1);
        assert_eq!(delivery.len(), 4);
        assert!(auth.is_disjoint(&delivery));
        assert!(*lab.delivery_polls.lock().unwrap() == *delivery);
    }

    #[tokio::test]
    async fn native_backlog_refuses_before_reading_an_upload_body() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let lab = lab().await;
        lab.native_status.lock().unwrap()["tenants"][0]["processes"][0]["heartbeat"]
            ["ingest_pending_input"] = input(1, 30.0);
        for (token, status) in [("revoked", "401"), ("sender", "503")] {
            let mut stream = tokio::net::TcpStream::connect(lab.url.trim_start_matches("http://"))
                .await
                .unwrap();
            stream.write_all(format!("POST /services/collector/event HTTP/1.1\r\nHost: localhost\r\nAuthorization: Splunk {token}\r\nContent-Length: 50000000\r\n\r\n").as_bytes()).await.unwrap();
            let mut answer = [0; 1024];
            let n = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut answer))
                .await
                .unwrap()
                .unwrap();
            assert!(
                String::from_utf8_lossy(&answer[..n]).starts_with(&format!("HTTP/1.1 {status}"))
            );
            if token == "revoked" {
                assert_eq!(lab.status_reads.load(Ordering::SeqCst), 0);
            }
        }
        assert_eq!(lab.uploads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn unavailable_stale_or_mismatched_native_status_fails_closed() {
        for case in 0..10 {
            let lab = lab().await;
            {
                let mut status = lab.native_status.lock().unwrap();
                let p = &mut status["tenants"][0]["processes"][0];
                match case {
                    0 => p["heartbeat_age_secs"] = 11.into(),
                    1 => p["heartbeat"]["ingest_pending_input"] = input(1, -1.0),
                    2 => p["stopping"] = true.into(),
                    3 => {
                        p["heartbeat"]["busy"] = true.into();
                        p["heartbeat"]["ingest_pending_input"] = input(1, 1.0);
                        p["heartbeat"]["last_progress_unix_ms"] = u64::MAX.into();
                    }
                    4 => {
                        p["heartbeat"]["busy"] = true.into();
                        p["uptime_secs"] = (-1).into();
                    }
                    5 => status["tenants"][0]["tenant_id"] = "another-tenant".into(),
                    6 => status["tenants"][0]["processes"] = serde_json::json!([]),
                    7 => *status = serde_json::json!({}),
                    8 => lab.native_status_code.store(503, Ordering::SeqCst),
                    _ => status["padding"] = "x".repeat(65536).into(),
                }
            }
            let reply = post(
                &reqwest::Client::new(),
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(
                reply.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "case {case}"
            );
            assert_eq!(reply.headers()["retry-after"], "1");
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn mixed_production_roles_admit_empty_and_drained_input() {
        use crate::contract::{Heartbeat, Role};
        for ingest_first in [true, false] {
            let lab = lab().await;
            lab.delivered.store(true, Ordering::SeqCst);
            {
                let mut status = lab.native_status.lock().unwrap();
                let processes = status["tenants"][0]["processes"].as_array_mut().unwrap();
                for role in [
                    Role::Detect,
                    Role::Maintenance,
                    Role::Product,
                    Role::Landing,
                ] {
                    processes.push(production_process(role, Heartbeat::default()));
                }
                assert!(processes
                    .iter()
                    .skip(1)
                    .all(|p| p["heartbeat"].get("ingest_pending_input").is_none()));
                processes[0]["heartbeat"]["busy"] = true.into(); // merge-only idle
                processes[0]["heartbeat"]["last_progress_unix_ms"] = 1.into();
                if !ingest_first {
                    processes.reverse();
                }
            }
            let client = reqwest::Client::new();
            let send = || {
                post(
                    &client,
                    &lab,
                    "/services/collector/event",
                    "Splunk sender",
                    "one",
                )
                .body("{}")
                .send()
            };
            assert_eq!(
                send().await.unwrap().status(),
                StatusCode::OK,
                "normal non-ingest heartbeats cannot close empty ingest admission"
            );
            for (objects, age, expected) in [
                (1, 30.0, StatusCode::SERVICE_UNAVAILABLE),
                (0, 0.0, StatusCode::OK),
            ] {
                {
                    let mut status = lab.native_status.lock().unwrap();
                    let ingest = status["tenants"][0]["processes"]
                        .as_array_mut()
                        .unwrap()
                        .iter_mut()
                        .find(|p| p["role"] == "ingest")
                        .unwrap();
                    ingest["heartbeat"]["ingest_pending_input"] = input(objects, age);
                }
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let reply = send().await.unwrap();
                assert_eq!(reply.status(), expected);
                if expected == StatusCode::SERVICE_UNAVAILABLE {
                    assert_eq!(reply.headers()["retry-after"], "1");
                    assert_eq!(lab.uploads.load(Ordering::SeqCst), 1);
                }
            }
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn mixed_roles_cannot_replace_missing_or_invalid_ingest_evidence() {
        for case in 0..6 {
            let lab = lab().await;
            {
                let mut status = lab.native_status.lock().unwrap();
                let processes = status["tenants"][0]["processes"].as_array_mut().unwrap();
                // Even ingest-like progress on another role is not authority.
                processes[1]["heartbeat"] = processes[0]["heartbeat"].clone();
                match case {
                    0 => {
                        processes.remove(0);
                    }
                    1 => {
                        let mut duplicate = processes[0].clone();
                        duplicate["heartbeat"] =
                            serde_json::to_value(crate::contract::Heartbeat::default()).unwrap();
                        processes.push(duplicate);
                    }
                    2 => {
                        processes[0]["heartbeat"]
                            .as_object_mut()
                            .unwrap()
                            .remove("ingest_pending_input");
                    }
                    3 => processes[0]["heartbeat"] = serde_json::Value::Null,
                    4 => processes[0]["heartbeat"]["ingest_pending_input"] = serde_json::json!({}),
                    _ => {
                        processes[0]["heartbeat"]
                            .as_object_mut()
                            .unwrap()
                            .remove("last_progress_unix_ms");
                    }
                }
            }
            let reply = post(
                &reqwest::Client::new(),
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(
                reply.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "case {case}"
            );
            assert_eq!(reply.headers()["retry-after"], "1");
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 0);
        }
    }

    // These exercise serve_on -> Proxy::new -> authenticated HTTP admission,
    // including both the upload and durable receipt checks. Old timestamps
    // model a two-minute idle without sleeping for two minutes in the suite.
    #[tokio::test]
    async fn idle_commit_age_does_not_stall_empty_or_new_pending_input() {
        for last_commit in [0_u64, 1] {
            let lab = lab().await;
            lab.delivered.store(true, Ordering::SeqCst);
            {
                let mut status = lab.native_status.lock().unwrap();
                let p = &mut status["tenants"][0]["processes"][0];
                p["uptime_secs"] = 120.into();
                p["heartbeat"]["last_progress_unix_ms"] = last_commit.into();
            }
            // Empty queue, merge-only busy, new pending input, drained queue,
            // then another arrival. None inherits the previous idle interval.
            for (busy, lag) in [
                (false, 0.0),
                (true, 0.0),
                (true, 0.25),
                (false, 0.0),
                (true, 0.25),
            ] {
                {
                    let mut status = lab.native_status.lock().unwrap();
                    let hb = &mut status["tenants"][0]["processes"][0]["heartbeat"];
                    hb["busy"] = busy.into();
                    hb["lag_seconds"] = lag.into();
                    hb["ingest_pending_input"] = input(u64::from(lag > 0.0), lag);
                }
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let reply = post(
                    &reqwest::Client::new(),
                    &lab,
                    "/services/collector/event",
                    "Splunk sender",
                    "one",
                )
                .body("{}")
                .send()
                .await
                .unwrap();
                assert_eq!(
                    reply.status(),
                    StatusCode::OK,
                    "last_commit={last_commit}, busy={busy}, lag={lag}"
                );
                assert!(reply.json::<serde_json::Value>().await.unwrap()["ackId"].is_u64());
            }
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 5);
        }
    }

    #[tokio::test]
    async fn pending_input_with_frozen_health_stalls_until_commit_or_queue_drain() {
        for (last_commit, retrying) in [(0_u64, false), (1, true)] {
            let lab = lab().await;
            lab.delivered.store(true, Ordering::SeqCst);
            {
                let mut status = lab.native_status.lock().unwrap();
                let p = &mut status["tenants"][0]["processes"][0];
                p["uptime_secs"] = 120.into();
                p["heartbeat"] = serde_json::json!({"busy": true, "retrying": retrying,
                    "lag_seconds": 29.5, "last_progress_unix_ms": last_commit,
                    "ingest_pending_input": input(1, 29.5)});
            }
            let client = reqwest::Client::new();
            let reply = post(
                &client,
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(
                reply.status(),
                StatusCode::OK,
                "pending for less than 30 seconds"
            );
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 1);
            // Fresh heartbeats keep repeating a snapshot taken before a stuck
            // commit. Lag stays below 30; the pending clock must keep advancing.
            for _ in 0..2 {
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let reply = post(
                    &client,
                    &lab,
                    "/services/collector/event",
                    "Splunk sender",
                    "one",
                )
                .body("{}")
                .send()
                .await
                .unwrap();
                assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(reply.headers()["retry-after"], "1");
                assert_eq!(lab.uploads.load(Ordering::SeqCst), 1);
            }
            {
                let mut status = lab.native_status.lock().unwrap();
                let hb = &mut status["tenants"][0]["processes"][0]["heartbeat"];
                if retrying {
                    // Rejected input can drain without a new data commit.
                    hb["busy"] = false.into();
                    hb["lag_seconds"] = 0.0.into();
                    hb["ingest_pending_input"] = input(0, 0.0);
                } else {
                    hb["last_progress_unix_ms"] = (std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_millis() as u64)
                        .into();
                    hb["lag_seconds"] = 0.25.into();
                    hb["ingest_pending_input"] = input(1, 0.25);
                }
                hb["retrying"] = false.into();
            }
            tokio::time::sleep(Duration::from_millis(1100)).await;
            let reply = post(
                &client,
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(reply.status(), StatusCode::OK);
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 2);
            if retrying {
                {
                    let mut status = lab.native_status.lock().unwrap();
                    let hb = &mut status["tenants"][0]["processes"][0]["heartbeat"];
                    hb["busy"] = true.into();
                    hb["lag_seconds"] = 0.25.into();
                    hb["ingest_pending_input"] = input(1, 0.25);
                }
                tokio::time::sleep(Duration::from_millis(1100)).await;
                let reply = post(
                    &client,
                    &lab,
                    "/services/collector/event",
                    "Splunk sender",
                    "one",
                )
                .body("{}")
                .send()
                .await
                .unwrap();
                assert_eq!(
                    reply.status(),
                    StatusCode::OK,
                    "new pending work after drain"
                );
                assert_eq!(lab.uploads.load(Ordering::SeqCst), 3);
            }
        }
    }

    // Reviewer regression: a failed first tick after a drain retains the old
    // zero-lag health, while the error path sets busy/retrying independently.
    #[tokio::test]
    async fn frozen_zero_lag_after_drain_must_close_admission() {
        for (busy, retrying) in [(false, false), (true, true)] {
            let lab = lab().await;
            lab.delivered.store(true, Ordering::SeqCst);
            {
                let mut status = lab.native_status.lock().unwrap();
                let p = &mut status["tenants"][0]["processes"][0];
                p["uptime_secs"] = 120.into();
                p["heartbeat"]["last_progress_unix_ms"] = 1.into();
            }
            let client = reqwest::Client::new();
            let send = || {
                post(
                    &client,
                    &lab,
                    "/services/collector/event",
                    "Splunk sender",
                    "one",
                )
                .body("{}")
                .send()
            };
            assert_eq!(send().await.unwrap().status(), StatusCode::OK);
            {
                let mut status = lab.native_status.lock().unwrap();
                let hb = &mut status["tenants"][0]["processes"][0]["heartbeat"];
                hb["busy"] = busy.into();
                hb["retrying"] = retrying.into();
                hb["ingest_pending_input"] = input(1, 0.0);
            }
            tokio::time::sleep(Duration::from_millis(1100)).await;
            assert_eq!(send().await.unwrap().status(), StatusCode::OK);
            tokio::time::sleep(Duration::from_secs(31)).await;
            let reply = send().await.unwrap();
            assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE,
            "pending input must close admission even when the first failed tick retains drained zero-lag health");
            assert_eq!(reply.headers()["retry-after"], "1");
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 2);
        }
    }

    #[tokio::test]
    async fn a_drain_between_observations_does_not_age_the_next_input() {
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        {
            let mut status = lab.native_status.lock().unwrap();
            let hb = &mut status["tenants"][0]["processes"][0]["heartbeat"];
            hb["ingest_pending_input"] = input(1, 29.5);
        }
        let client = reqwest::Client::new();
        let send = || {
            post(
                &client,
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
        };
        assert_eq!(send().await.unwrap().status(), StatusCode::OK);
        // Durable refusal/replay ACKs can drain work without advancing the
        // completed-tick commit timestamp. New input arrives before our read.
        {
            let mut status = lab.native_status.lock().unwrap();
            let hb = &mut status["tenants"][0]["processes"][0]["heartbeat"];
            hb["ingest_pending_input"] = input(1, 0.25);
            hb["ingest_pending_input"]["consumed_objects_total"] = 1.into();
        }
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(send().await.unwrap().status(), StatusCode::OK);
        assert_eq!(lab.uploads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn independent_empty_input_requires_fresh_discovery() {
        for case in 0..7 {
            let lab = lab().await;
            {
                let mut status = lab.native_status.lock().unwrap();
                let p = &mut status["tenants"][0]["processes"][0];
                let hb = &mut p["heartbeat"];
                match case {
                    0 => hb
                        .as_object_mut()
                        .unwrap()
                        .remove("ingest_pending_input")
                        .map(|_| ())
                        .unwrap(),
                    1 => {
                        hb["ingest_pending_input"]["discovery_age_seconds"] =
                            serde_json::Value::Null
                    }
                    2 => hb["ingest_pending_input"]["discovery_age_seconds"] = 11.into(),
                    3 => hb["ingest_pending_input"]["discovery_age_seconds"] = (-1).into(),
                    4 => hb["ingest_pending_input"]["oldest_age_seconds"] = 1.into(),
                    5 => hb["ingest_pending_input"]["objects"] = (-1).into(),
                    _ => {
                        hb["ingest_pending_input"]["discovery_age_seconds"] = 6.into();
                        p["heartbeat_age_secs"] = 5.into();
                    }
                }
            }
            let reply = post(
                &reqwest::Client::new(),
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(
                reply.status(),
                StatusCode::SERVICE_UNAVAILABLE,
                "case {case}"
            );
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 0);
        }
        // A completed-tick backlog can be stale after durable consumption.
        // The fresh queue observation proves idle even during merge work.
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        {
            let mut status = lab.native_status.lock().unwrap();
            let hb = &mut status["tenants"][0]["processes"][0]["heartbeat"];
            hb["busy"] = true.into();
            hb["lag_seconds"] = 120.into();
            hb["last_progress_unix_ms"] = 1.into();
        }
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "one",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_or_ambiguous_installed_route_and_invalid_status_token_refuse_ingest() {
        for case in 0..4 {
            let lab = lab().await;
            match case {
                0 => std::fs::remove_file(lab.config.path().join("routes.json")).unwrap(),
                1 => std::fs::write(lab.config.path().join("routes.json"), "{}").unwrap(),
                2 => std::fs::write(lab.config.path().join("router-query.token"), "revoked").unwrap(),
                _ => std::fs::write(lab.config.path().join("routes.json"), r#"{"one":{"cell_origin":"http://localhost"},"two":{"cell_origin":"http://localhost"}}"#).unwrap(),
            }
            let reply = post(
                &reqwest::Client::new(),
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send()
            .await
            .unwrap();
            assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(lab.uploads.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn native_status_timeout_refuses_input_within_a_bounded_time() {
        let lab = lab().await;
        let silent = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        std::fs::write(
            lab.config.path().join("routes.json"),
            serde_json::json!({
                "fixture": {"cell_origin": format!("http://{}", silent.local_addr().unwrap())}
            })
            .to_string(),
        )
        .unwrap();
        let reply = tokio::time::timeout(
            Duration::from_secs(3),
            post(
                &reqwest::Client::new(),
                &lab,
                "/services/collector/event",
                "Splunk sender",
                "one",
            )
            .body("{}")
            .send(),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(lab.uploads.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn admission_cache_bounds_status_load_and_reopens_after_commit_catches_up() {
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        lab.native_status.lock().unwrap()["tenants"][0]["processes"][0]["heartbeat"]
            ["ingest_pending_input"] = input(1, 31.0);
        let requests: Vec<_> = (0..16)
            .map(|_| {
                let request = post(
                    &reqwest::Client::new(),
                    &lab,
                    "/services/collector/event",
                    "Splunk sender",
                    "one",
                )
                .body("{}");
                tokio::spawn(async move { request.send().await.unwrap() })
            })
            .collect();
        for request in requests {
            assert_eq!(
                request.await.unwrap().status(),
                StatusCode::SERVICE_UNAVAILABLE
            );
        }
        assert_eq!(lab.status_reads.load(Ordering::SeqCst), 1);
        lab.native_status.lock().unwrap()["tenants"][0]["processes"][0]["heartbeat"]
            ["ingest_pending_input"] = input(0, 0.0);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "one",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
        assert_eq!(lab.uploads.load(Ordering::SeqCst), 1);
        assert_eq!(lab.status_reads.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_durable_put_cannot_issue_a_receipt_after_native_admission_closes() {
        let lab = lab().await;
        let pending = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "one",
        )
        .body("{}");
        let pending = tokio::spawn(async move { pending.send().await.unwrap() });
        wait_for_uploads(&lab, 1).await;
        lab.native_status.lock().unwrap()["tenants"][0]["processes"][0]["heartbeat"]
            ["ingest_pending_input"] = input(1, 31.0);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        lab.delivered.store(true, Ordering::SeqCst);
        assert_eq!(
            pending.await.unwrap().status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn commit_backpressure_does_not_hide_an_existing_durable_receipt() {
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "one",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        let id = reply.json::<serde_json::Value>().await.unwrap()["ackId"]
            .as_u64()
            .unwrap();
        lab.native_status.lock().unwrap()["tenants"][0]["processes"][0]["heartbeat"]
            ["ingest_pending_input"] = input(1, 31.0);
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/ack",
            "Splunk sender",
            "one",
        )
        .json(&serde_json::json!({"acks": [id]}))
        .send()
        .await
        .unwrap();
        assert_eq!(
            reply.json::<serde_json::Value>().await.unwrap()["acks"][id.to_string()],
            true
        );
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "one",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        assert_eq!(reply.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn gateway_openapi_documents_its_listener_and_credential() {
        use utoipa::OpenApi;
        let spec = serde_json::to_value(HecProxyApiDoc::openapi()).unwrap();
        assert!(spec["paths"]["/services/collector/{endpoint}"]["post"].is_object());
        assert!(spec["paths"]["/services/collector/health"]["get"].is_object());
        assert_eq!(
            spec["components"]["securitySchemes"]["hec_token"]["name"],
            "Authorization"
        );
    }

    #[tokio::test]
    async fn an_unauthenticated_slow_upload_cannot_hold_ingest_admission() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let lab = lab().await;
        lab.delivered.store(true, Ordering::SeqCst);
        let mut attacker = tokio::net::TcpStream::connect(lab.url.trim_start_matches("http://"))
            .await
            .unwrap();
        attacker.write_all(b"POST /services/collector/event HTTP/1.1\r\nHost: localhost\r\nAuthorization: Splunk revoked\r\nContent-Length: 50000000\r\n\r\n").await.unwrap();
        // The attacker never sends its promised body. Authentication must
        // refuse it from headers, while an authorized sender still completes.
        let mut answer = [0; 1024];
        let n = tokio::time::timeout(Duration::from_secs(2), attacker.read(&mut answer))
            .await
            .unwrap()
            .unwrap();
        assert!(std::str::from_utf8(&answer[..n])
            .unwrap()
            .contains("401 Unauthorized"));
        let reply = post(
            &reqwest::Client::new(),
            &lab,
            "/services/collector/event",
            "Splunk sender",
            "channel",
        )
        .body("{}")
        .send()
        .await
        .unwrap();
        assert_eq!(reply.status(), StatusCode::OK);
    }
}

/// The HEC gateway is a separate listener from nano-api.
#[derive(utoipa::OpenApi)]
#[openapi(paths(forward, serve), components(schemas(HecAckRequest)), modifiers(&HecSecurity))]
pub struct HecProxyApiDoc;

struct HecSecurity;

impl utoipa::Modify for HecSecurity {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
        openapi
            .components
            .get_or_insert_with(Default::default)
            .add_security_scheme(
                "hec_token",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::with_description(
                    "Authorization",
                    "HEC ingest credential: Splunk <token>",
                ))),
            );
    }
}
