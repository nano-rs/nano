// SPDX-License-Identifier: AGPL-3.0-or-later
use nanosiem_core::auth::TrustedTenantContext;
use nanosiem_core::enrichment::lake_ip_context::{LakeIpContextClient, LakeIpContextError, LakeIpContextResolver};
use nanosiem_core::enrichment::lean_assignments::LeanAssignmentSource;
use serde_json::{json, Value};
use uuid::Uuid;
use wiremock::{matchers::{method, path, header, query_param}, Mock, MockServer, ResponseTemplate};

fn tenant(id: Uuid) -> TrustedTenantContext {
    TrustedTenantContext { tenant_id: id, tenant_slug: "ignored-selector".into() }
}

fn assignment(url: &str, credential: &std::path::Path) -> Value {
    json!({"internal_endpoint": url, "credential_file": credential, "timeout_secs": 30})
}

#[tokio::test]
async fn authenticated_identity_selects_endpoint_token_and_rotation() {
    let root = tempfile::tempdir().unwrap();
    let a = MockServer::start().await;
    let b = MockServer::start().await;
    let id_a = Uuid::new_v4();
    let id_b = Uuid::new_v4();
    let token_a = "a".repeat(32);
    let token_b = "b".repeat(32);
    let credentials_a = root.path().join("a.token");
    let credentials_b = root.path().join("b.token");
    std::fs::write(&credentials_a, &token_a).unwrap();
    std::fs::write(&credentials_b, &token_b).unwrap();
    let file = root.path().join("assignments.json");
    let mut assignments = json!({id_a.to_string(): assignment(&a.uri(), &credentials_a), id_b.to_string(): assignment(&b.uri(), &credentials_b)});
    std::fs::write(&file, serde_json::to_vec(&assignments).unwrap()).unwrap();
    // NAN-3531: assignments are live-reloaded; a zero interval re-reads them
    // on every resolve so the endpoint rotation below is seen at once.
    let resolver = LakeIpContextResolver::with_source(std::sync::Arc::new(
        LeanAssignmentSource::with_interval(&file, std::time::Duration::ZERO),
    ));
    for (server, id, token) in [(&a, id_a, &token_a), (&b, id_b, &token_b)] {
        Mock::given(method("GET")).and(path("/v1/ip-context/stats"))
            .and(header("authorization", format!("Bearer {token}")))
            .and(query_param("tenant_id", id.to_string()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tenant_id": id, "result": {"total_networks": 1, "source_counts": {"cmdb": 1}, "snapshot_sha256": "f".repeat(64)}})))
            .expect(1).mount(server).await;
        let mut trusted = tenant(id);
        // A caller-controlled slug cannot select the other UUID's assignment.
        trusted.tenant_slug = if id == id_a { id_b.to_string() } else { id_a.to_string() };
        assert_eq!(resolver.resolve(&trusted).unwrap().stats().await.unwrap().total_networks, 1);
    }
    let rotated = MockServer::start().await;
    let token = "rotated-token-000000000000000000000000";
    std::fs::write(&credentials_a, token).unwrap();
    assignments[id_a.to_string()] = assignment(&rotated.uri(), &credentials_a);
    std::fs::write(&file, serde_json::to_vec(&assignments).unwrap()).unwrap();
    Mock::given(method("DELETE")).and(path("/v1/ip-context/sources/cmdb"))
        .and(header("authorization", format!("Bearer {token}")))
        .and(wiremock::matchers::body_json(json!({"tenant_id": id_a})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tenant_id": id_a, "result": {"tenant_id": id_a, "status": "published", "snapshot_sha256": "e".repeat(64), "rows": 0}})))
        .expect(1).mount(&rotated).await;
    resolver.resolve(&tenant(id_a)).unwrap().delete_source("cmdb").await.unwrap();
    assert!(resolver.resolve(&tenant(Uuid::new_v4())).is_err());
    assert!(LakeIpContextResolver::new(None).resolve(&tenant(id_a)).is_err());
}

#[tokio::test]
async fn missing_invalid_assignments_and_credentials_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("assignments.json");
    let credential = root.path().join("token");
    let id = Uuid::new_v4();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    for bytes in [b"not JSON".as_slice(), b"[]"] {
        std::fs::write(&file, bytes).unwrap();
        assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    }
    // NAN-3531: a malformed entry is dropped alone; the tenant is unassigned.
    std::fs::write(&file, b"{\"bad-uuid\":{}}").unwrap();
    assert!(matches!(LakeIpContextClient::from_lean_assignment_file(&file, id), Ok(None)));
    let base = assignment("http://127.0.0.1:9", &credential);
    for (field, value) in [("timeout_secs", json!(0)), ("timeout_secs", json!(3601)),
        ("credential_file", json!("relative")), ("internal_endpoint", json!("http://user:secret@localhost/")),
        ("internal_endpoint", json!("http://localhost/path")), ("unexpected", json!(true))] {
        let mut entry = base.clone(); entry[field] = value;
        std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): entry})).unwrap()).unwrap();
        assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    }
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): base.clone()})).unwrap()).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    for token in ["short".to_string(), "a\nb".repeat(32), "é".repeat(32)] {
        std::fs::write(&credential, token).unwrap();
        assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    }
    std::fs::write(&credential, "a".repeat(32)).unwrap();
    let other = Uuid::new_v4();
    for entry in [assignment("http://127.0.0.1:9/", &root.path().join("other")), assignment("http://127.0.0.1:10", &credential)] {
        std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): base.clone(), other.to_string(): entry})).unwrap()).unwrap();
        assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    }
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, Uuid::nil()).is_err());
}

#[tokio::test]
async fn response_contracts_and_redirects_are_rejected_without_reflecting_contents() {
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let redirect = MockServer::start().await;
    let id = Uuid::new_v4();
    let credential = root.path().join("token");
    std::fs::write(&credential, "a".repeat(32)).unwrap();
    let file = root.path().join("assignments.json");
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment(&server.uri(), &credential)})).unwrap()).unwrap();
    let client = LakeIpContextClient::from_lean_assignment_file(&file, id).unwrap().unwrap();
    for response in [json!({"tenant_id": Uuid::new_v4(), "result": {"total_networks": 0, "source_counts": {}, "snapshot_sha256": null}}),
        json!({"tenant_id": id, "result": {"total_networks": 2, "source_counts": {"cmdb": 1}, "snapshot_sha256": null}}),
        json!({"tenant_id": id, "result": {"total_networks": 1, "source_counts": {"cmdb": 1}, "snapshot_sha256": "invalid"}}),
        json!({"tenant_id": id, "result": {"total_networks": 0, "source_counts": {"one": usize::MAX, "two": 1}, "snapshot_sha256": null}}), json!({"source": "private-source-content"})] {
        server.reset().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(response)).mount(&server).await;
        assert!(matches!(client.stats().await, Err(LakeIpContextError::ResponseContract)));
    }
    server.reset().await;
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(307).insert_header("location", redirect.uri()).set_body_string("private-source-content")).mount(&server).await;
    let error = client.stats().await.unwrap_err().to_string();
    assert!(!error.contains("private-source-content"));
    assert!(redirect.received_requests().await.unwrap().is_empty());
    for result in [json!({"tenant_id": Uuid::new_v4(), "status": "published", "rows": 0, "snapshot_sha256": "f".repeat(64)}),
        json!({"tenant_id": id, "status": "bad", "rows": 0, "snapshot_sha256": "f".repeat(64)}),
        json!({"tenant_id": id, "status": "published", "rows": 10_000_001, "snapshot_sha256": "f".repeat(64)})] {
        server.reset().await;
        Mock::given(method("DELETE")).respond_with(ResponseTemplate::new(200).set_body_json(json!({"tenant_id": id, "result": result}))).mount(&server).await;
        assert!(matches!(client.delete_source("cmdb").await, Err(LakeIpContextError::ResponseContract)));
    }
}

#[tokio::test]
async fn batch_upload_pins_tenant_header_and_validates_publication() {
    use nanosiem_core::enrichment::lake_ip_context::LakeIpContextInput;
    let root = tempfile::tempdir().unwrap();
    let server = MockServer::start().await;
    let id = Uuid::new_v4();
    let credential = root.path().join("token");
    std::fs::write(&credential, "a".repeat(32)).unwrap();
    let file = root.path().join("assignments.json");
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment(&server.uri(), &credential)})).unwrap()).unwrap();
    let client = LakeIpContextClient::from_lean_assignment_file(&file, id).unwrap().unwrap();
    let row: LakeIpContextInput = serde_json::from_value(json!({
        "network": "192.0.2.0/24", "source_id": "cmdb", "updated_at": "2026-10-02T00:00:00Z"
    })).unwrap();
    assert!(client.upload_batch(&[]).await.is_err());
    assert!(server.received_requests().await.unwrap().is_empty());
    for result in [json!({"tenant_id": id, "status": "published", "rows": 1, "snapshot_sha256": "f".repeat(64)}),
        json!({"tenant_id": Uuid::new_v4(), "status": "published", "rows": 1, "snapshot_sha256": "f".repeat(64)}),
        json!({"tenant_id": id, "status": "published", "rows": 1, "snapshot_sha256": "bad"})] {
        server.reset().await;
        let valid = result["tenant_id"] == json!(id) && result["snapshot_sha256"] == json!("f".repeat(64));
        Mock::given(method("POST")).and(path("/v1/ip-context/batch"))
            .and(header("x-nano-tenant-id", id.to_string()))
            .and(header("content-type", "application/x-ndjson"))
            .and(header("authorization", format!("Bearer {}", "a".repeat(32))))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"tenant_id": id, "result": result})))
            .expect(1).mount(&server).await;
        let response = client.upload_batch(std::slice::from_ref(&row)).await;
        if valid { assert_eq!(response.unwrap(), 1); }
        else { assert!(matches!(response, Err(LakeIpContextError::ResponseContract))); }
        let requests = server.received_requests().await.unwrap();
        let sent: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(sent["source_id"], "cmdb");
        assert!(sent.get("tenant_id").is_none());
    }
}

#[cfg(unix)]
#[test]
fn credential_aliases_cannot_be_shared_between_assignments() {
    let root = tempfile::tempdir().unwrap();
    let credential = root.path().join("token");
    let alias = root.path().join("alias");
    std::fs::write(&credential, "a".repeat(32)).unwrap();
    std::os::unix::fs::symlink(&credential, &alias).unwrap();
    let file = root.path().join("assignments.json");
    let own = Uuid::new_v4();
    let other = Uuid::new_v4();
    std::fs::write(&file, serde_json::to_vec(&json!({
        own.to_string(): assignment("http://127.0.0.1:9", &credential),
        other.to_string(): assignment("http://127.0.0.1:10", &alias)
    })).unwrap()).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, own).is_err());
}

#[test]
fn assignment_and_credential_budgets_fail_closed() {
    use nanosiem_core::enrichment::lake_ip_context::{MAX_ASSIGNMENT_BYTES, MAX_ASSIGNMENTS, MAX_CREDENTIAL_BYTES};
    let root = tempfile::tempdir().unwrap();
    let file = root.path().join("assignments.json");
    let token = root.path().join("token");
    let id = Uuid::new_v4();
    std::fs::write(&file, vec![b' '; MAX_ASSIGNMENT_BYTES + 1]).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment("http://127.0.0.1:9", &token)})).unwrap()).unwrap();
    std::fs::write(&token, vec![b'a'; MAX_CREDENTIAL_BYTES + 1]).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    std::fs::write(&token, "a".repeat(32)).unwrap();
    let mut entries = serde_json::Map::new();
    entries.insert(id.to_string(), assignment("http://127.0.0.1:9", &token));
    for _ in 0..MAX_ASSIGNMENTS {
        entries.insert(Uuid::new_v4().to_string(), assignment("http://127.0.0.1:10", &token));
    }
    let bytes = serde_json::to_vec(&entries).unwrap();
    assert!(bytes.len() < MAX_ASSIGNMENT_BYTES);
    std::fs::write(&file, bytes).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
}

#[cfg(unix)]
#[test]
fn special_files_are_refused_and_mounted_secret_symlinks_are_accepted() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let fifo = root.path().join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    let id = Uuid::new_v4();
    // No writer: an ordinary blocking open would hang this test.
    assert!(LakeIpContextClient::from_lean_assignment_file(&fifo, id).is_err());
    let file = root.path().join("assignments.json");
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment("http://127.0.0.1:9", &fifo)})).unwrap()).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment("http://127.0.0.1:9", std::path::Path::new("/dev/null"))})).unwrap()).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).is_err());
    let token = root.path().join("real-token");
    let alias = root.path().join("mounted-token");
    std::fs::write(&token, "a".repeat(32)).unwrap();
    symlink(&token, &alias).unwrap();
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment("http://127.0.0.1:9", &alias)})).unwrap()).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&file, id).unwrap().is_some());
    let directory = root.path().join("directory");
    std::fs::create_dir(&directory).unwrap();
    assert!(LakeIpContextClient::from_lean_assignment_file(&directory, id).is_err());
}

// Real HTTP/1.1 chunk framing, without a Content-Length, exercises the streamed
// path rather than wiremock's length-delimited body implementation.
fn raw_response_server(headers: String, chunks: Vec<Vec<u8>>) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            if stream.read_exact(&mut byte).is_err() { return; }
            request.push(byte[0]);
        }
        if stream.write_all(headers.as_bytes()).is_err() { return; }
        for chunk in chunks {
            if write!(stream, "{:x}\r\n", chunk.len()).is_err()
                || stream.write_all(&chunk).is_err()
                || stream.write_all(b"\r\n").is_err() { return; }
        }
        let _ = stream.write_all(b"0\r\n\r\n");
    });
    (url, task)
}

#[tokio::test]
async fn response_byte_and_source_budgets_cover_length_and_chunked_bodies() {
    use nanosiem_core::enrichment::lake_ip_context::{MAX_SUCCESS_RESPONSE_BYTES, MAX_STATS_SOURCES};
    let root = tempfile::tempdir().unwrap();
    let token = root.path().join("token");
    std::fs::write(&token, "a".repeat(32)).unwrap();
    let file = root.path().join("assignments.json");
    let id = Uuid::new_v4();
    let server = MockServer::start().await;
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment(&server.uri(), &token)})).unwrap()).unwrap();
    let client = LakeIpContextClient::from_lean_assignment_file(&file, id).unwrap().unwrap();
    for status in [200, 400] {
        server.reset().await;
        Mock::given(method("GET")).respond_with(ResponseTemplate::new(status)
            .set_body_string("private-body".repeat(MAX_SUCCESS_RESPONSE_BYTES / 12 + 1)))
            .mount(&server).await;
        let error = client.stats().await.unwrap_err();
        if status == 200 { assert!(matches!(error, LakeIpContextError::ResponseContract)); }
        else { assert!(matches!(error, LakeIpContextError::Request(_))); }
        assert!(!error.to_string().contains("private-body"));
    }
    server.reset().await;
    let sources: serde_json::Map<String, Value> = (0..=MAX_STATS_SOURCES)
        .map(|i| (format!("source-{i}"), json!(1))).collect();
    Mock::given(method("GET")).respond_with(ResponseTemplate::new(200).set_body_json(json!({
        "tenant_id": id, "result": {"total_networks": sources.len(), "source_counts": sources, "snapshot_sha256": null}
    }))).mount(&server).await;
    assert!(matches!(client.stats().await, Err(LakeIpContextError::ResponseContract)));

    let normal = serde_json::to_vec(&json!({"tenant_id": id, "result": {
        "total_networks": 1, "source_counts": {"cmdb": 1}, "snapshot_sha256": "f".repeat(64)
    }})).unwrap();
    for (chunks, valid) in [(vec![normal], true), (vec![vec![b' '; 64 * 1024]; MAX_SUCCESS_RESPONSE_BYTES / (64 * 1024) + 1], false)] {
        let (url, task) = raw_response_server("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".into(), chunks);
        std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment(&url, &token)})).unwrap()).unwrap();
        let client = LakeIpContextClient::from_lean_assignment_file(&file, id).unwrap().unwrap();
        let result = client.stats().await;
        if valid { assert_eq!(result.unwrap().total_networks, 1); }
        else { assert!(matches!(result, Err(LakeIpContextError::ResponseContract))); }
        task.join().unwrap();
    }
    // A declared huge error body that is never delivered must be rejected on
    // headers alone, rather than producing a body-transport error on EOF.
    let (url, task) = raw_response_server("HTTP/1.1 400 Bad Request\r\nContent-Length: 999999999\r\nConnection: close\r\n\r\n".into(), vec![]);
    std::fs::write(&file, serde_json::to_vec(&json!({id.to_string(): assignment(&url, &token)})).unwrap()).unwrap();
    let client = LakeIpContextClient::from_lean_assignment_file(&file, id).unwrap().unwrap();
    let error = client.stats().await.unwrap_err().to_string();
    assert!(error.contains("HTTP 400"));
    assert!(!error.contains("transport"));
    task.join().unwrap();
}
