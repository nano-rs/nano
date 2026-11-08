use super::*;
use crate::db::DualPoolConfig;
use std::process::Stdio;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
};

const FIXTURES: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/clickhouse-tls/"
);

async fn reply(mut stream: impl AsyncRead + AsyncWrite + Unpin) -> bool {
    let mut request = Vec::new();
    let mut buf = [0u8; 1024];
    while request.len() < 8192 {
        let n = stream.read(&mut buf).await.unwrap();
        if n == 0 {
            return false;
        }
        request.extend_from_slice(&buf[..n]);
        if request.windows(8).any(|s| s == b"SELECT 1") {
            break;
        }
    }
    let request = String::from_utf8(request).unwrap();
    assert!(request.starts_with("POST "));
    assert!(request.contains("database=default"));
    assert!(request.contains("SELECT 1"));
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    true
}

// Each test's child uses the real admin-client construction path. SSL_CERT_*
// are set only on a fresh subprocess: parallel tests never mutate process env.
// The peer implements only the HTTP transport, not a ClickHouse SQL engine.
async fn case(name: &str, tls: bool, ca: &str, wrong_name: bool, accepted: bool) {
    if std::env::var("NANO_CLICKHOUSE_TLS_TEST_CHILD").as_deref() == Ok(name) {
        let url = std::env::var("CLICKHOUSE_URL").unwrap();
        let config = DualPoolConfig::with_auth("unused", url, "default", "fixture", "fixture");
        let (client, _) = config.create_admin_clickhouse_client();
        let result =
            tokio::time::timeout(Duration::from_secs(5), client.query("SELECT 1").execute())
                .await
                .unwrap();
        assert_eq!(
            result.is_ok(),
            accepted,
            "TLS/query outcome differs from expected transport verdict: {:?}",
            result.as_ref().err()
        );
        return;
    }
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let task = async {
            let (socket, _) = listener.accept().await.unwrap();
            if tls {
                let config = rustls::ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::aws_lc_rs::default_provider(),
                ))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(
                    vec![rustls::pki_types::CertificateDer::from(
                        include_bytes!("../../../tests/fixtures/clickhouse-tls/server.der")
                            .to_vec(),
                    )],
                    rustls::pki_types::PrivatePkcs8KeyDer::from(
                        include_bytes!("../../../tests/fixtures/clickhouse-tls/server.pk8")
                            .to_vec(),
                    )
                    .into(),
                )
                .unwrap();
                match tokio_rustls::TlsAcceptor::from(Arc::new(config))
                    .accept(socket)
                    .await
                {
                    Ok(stream) => reply(stream).await,
                    Err(_) => false,
                }
            } else {
                reply(socket).await
            }
        };
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
    });
    let empty = tempfile::tempdir().unwrap();
    let ca_file = if ca == "missing" {
        empty.path().join("absent.pem")
    } else {
        std::path::Path::new(FIXTURES).join(ca)
    };
    let host = if wrong_name { "127.0.0.1" } else { "localhost" };
    let scheme = if tls { "https" } else { "http" };
    let output = tokio::time::timeout(
        Duration::from_secs(15),
        tokio::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(format!("db::clickhouse_transport::tests::{name}"))
            .env("NANO_CLICKHOUSE_TLS_TEST_CHILD", name)
            .env("CLICKHOUSE_URL", format!("{scheme}://{host}:{port}"))
            .env("SSL_CERT_FILE", ca_file)
            .env("SSL_CERT_DIR", empty.path())
            .stdin(Stdio::null())
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        output.status.success(),
        "isolated TLS child failed: stdout={:.8192} stderr={:.8192}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        server.await.unwrap(),
        accepted,
        "refused TLS must never reach an HTTP request"
    );
}

#[tokio::test]
async fn private_ca_verified_https() {
    case("private_ca_verified_https", true, "ca.pem", false, true).await;
}
#[tokio::test]
async fn unrelated_ca_refuses_https() {
    case(
        "unrelated_ca_refuses_https",
        true,
        "wrong-ca.pem",
        false,
        false,
    )
    .await;
}
#[tokio::test]
async fn wrong_server_identity_refuses_https() {
    case(
        "wrong_server_identity_refuses_https",
        true,
        "ca.pem",
        true,
        false,
    )
    .await;
}
#[tokio::test]
async fn absent_ca_refuses_private_https() {
    case(
        "absent_ca_refuses_private_https",
        true,
        "missing",
        false,
        false,
    )
    .await;
}
#[tokio::test]
async fn absent_ca_preserves_plain_http_without_panic() {
    case(
        "absent_ca_preserves_plain_http_without_panic",
        false,
        "missing",
        false,
        true,
    )
    .await;
}

#[test]
fn public_fallback_never_expands_native_or_explicit_trust() {
    let private = rustls::pki_types::CertificateDer::from(
        include_bytes!("../../../tests/fixtures/clickhouse-tls/ca.der").to_vec(),
    );
    assert_eq!(trust_roots(vec![private.clone()], false).len(), 1);
    assert_eq!(trust_roots(vec![private], true).len(), 1);
    assert!(trust_roots(vec![], true).is_empty());
    assert_eq!(
        trust_roots(vec![], false).len(),
        webpki_roots::TLS_SERVER_ROOTS.len()
    );
}

#[test]
fn skip_null_typed_paths_only_from_26_9() {
    // CH-2610 (NAN-4923): the 26.8 rollback target must never receive the
    // setting (unknown setting = every query fails); 26.9+ gets it.
    for v in ["26.8.36.3", "26.5.7.64", "26.4.5.143", "25.12.1.1", "", "garbage", "26"] {
        assert!(!supports_skip_null_typed_paths(v), "{v}");
    }
    for v in ["26.9.27.3", "26.10.3.7", "27.1.1.1", " 26.10.3.7\n"] {
        assert!(supports_skip_null_typed_paths(v), "{v}");
    }
}

#[test]
fn external_set_spill_only_from_26_10() {
    // NAN-4934: measured absent on 26.8.36.3 and 26.9.27.3, present on 26.10.3.7.
    for v in ["26.8.36.3", "26.9.27.3", "26.5.7.64", "25.12.1.1", "", "garbage", "26"] {
        assert!(!supports_external_set_spill(v), "{v}");
    }
    for v in ["26.10.3.7", "26.11.1.1", "27.1.1.1", " 26.10.3.7\n"] {
        assert!(supports_external_set_spill(v), "{v}");
    }
}

#[test]
fn external_set_spill_threshold_follows_the_query_memory_limit() {
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    // Unknown (probe failed), unlimited (0) and small limits: small tier.
    assert_eq!(external_set_spill_bytes(0), 64 * MIB);
    assert_eq!(external_set_spill_bytes(5_000_000_000), 64 * MIB); // realtime profile
    assert_eq!(external_set_spill_bytes(16 * GIB - 1), 64 * MIB);
    assert_eq!(external_set_spill_bytes(16 * GIB), 128 * MIB);
    assert_eq!(external_set_spill_bytes(20_000_000_000), 128 * MIB); // shipped default/rawsql
    assert_eq!(external_set_spill_bytes(50_000_000_000), 128 * MIB); // analytics
    assert_eq!(external_set_spill_bytes(64 * GIB - 1), 128 * MIB);
    assert_eq!(external_set_spill_bytes(64 * GIB), 256 * MIB);
    assert_eq!(external_set_spill_bytes(u64::MAX), 256 * MIB);
}

#[test]
fn fleet_gates_need_every_server_to_know_the_setting() {
    // NAN-4934 (codex P1): one old replica behind the Service keeps a gated
    // setting off for the whole client; a failed probe keeps everything off.
    let v = |xs: &[&str]| -> Result<Vec<String>, String> { Ok(xs.iter().map(|s| s.to_string()).collect()) };
    // Mid-rollout 26.8 -> 26.10: neither setting.
    let mixed = v(&["26.10.3.7", "26.8.36.3"]);
    assert!(!fleet_supports(&mixed, supports_external_set_spill));
    assert!(!fleet_supports(&mixed, supports_skip_null_typed_paths));
    // 26.9 + 26.10: skip-null yes (26.9+), external set no (26.10+).
    let partial = v(&["26.10.3.7", "26.9.27.3"]);
    assert!(fleet_supports(&partial, supports_skip_null_typed_paths));
    assert!(!fleet_supports(&partial, supports_external_set_spill));
    // Rollout complete.
    let done = v(&["26.10.3.7", "26.10.3.7"]);
    assert!(fleet_supports(&done, supports_external_set_spill));
    assert!(fleet_supports(&done, supports_skip_null_typed_paths));
    // An unparseable version, an empty fleet or a probe error: off.
    assert!(!fleet_supports(&v(&["26.10.3.7", "garbage"]), supports_external_set_spill));
    assert!(!fleet_supports(&v(&[]), supports_external_set_spill));
    assert!(!fleet_supports(&Err("Code: 497".into()), supports_skip_null_typed_paths));
}

// NAN-4957: the default search memory ceiling follows the server limit.
#[test]
fn query_memory_ceiling_is_a_share_of_the_server_limit() {
    const GIB: u64 = 1 << 30;
    // 4G compose box: CH auto-sizes to 0.8 x 4 GiB.
    let limit_4g = 4 * GIB / 10 * 8;
    assert_eq!(query_memory_ceiling(None, limit_4g), Some(limit_4g / 100 * 40));
    assert!(query_memory_ceiling(None, limit_4g).unwrap() < 2 * GIB);
    // An explicit deployment ceiling wins, even above the share.
    assert_eq!(query_memory_ceiling(Some(3 * GIB), limit_4g), Some(3 * GIB));
    // Unknown limit: the ClickHouse profile stays in control.
    assert_eq!(query_memory_ceiling(None, 0), None);
}
