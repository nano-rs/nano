// SPDX-License-Identifier: AGPL-3.0-or-later

//! NAN-5214 regression: sqlx must be able to start TLS with PostgreSQL.
//!
//! Both rustls providers (aws-lc-rs and ring) are compiled into the workspace,
//! so rustls cannot choose one by itself and PANICS when sqlx builds its TLS
//! client config. Any PostgreSQL that negotiates TLS (managed RDS / Cloud SQL /
//! Azure, or nano's PostgreSQL HA) then crash-looped every service at boot.
//!
//! It lives in nanosiem-api, a graph where rustls has both `aws_lc_rs` and
//! `ring` enabled (ring arrives through reqwest -> rustls-platform-verifier,
//! also reachable from nanosiem-core), like every service binary. Its own
//! test binary (its own process), so nothing installed a provider first.
//!
//! The second test guards the call sites: every binary entry point that can
//! reach PostgreSQL or an HTTPS client must install the provider in `main`
//! (this test calls the install itself, so it cannot catch a missing call). A fake server accepts the SSLRequest ('S') and
//! hangs up. The connect uses `sslmode=verify-ca` with a root certificate,
//! the mode managed databases commonly use: building its no-hostname
//! verifier is where rustls needs the process provider. Before the fix the
//! connect panicked; with the provider installed it is a connection error.

use sqlx::postgres::{PgConnectOptions, PgConnection};
use sqlx::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A throwaway, test-only self-signed CA (no private key exists anywhere).
const TEST_ROOT_CA: &str = "-----BEGIN CERTIFICATE-----\nMIIBbjCCARSgAwIBAgIUOmiYxt//nOY0EdDlD9EsDDxYgh8wCgYIKoZIzj0EAwIw\nHDEaMBgGA1UEAwwRbmFuby10ZXN0LW9ubHktY2EwIBcNMjYxMTEwMTMwMzUyWhgP\nMjEyNjEwMTcxMzAzNTJaMBwxGjAYBgNVBAMMEW5hbm8tdGVzdC1vbmx5LWNhMFkw\nEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENAG68ZOqqZgGHo7OaMnbPAVV2Gt6OtRP\nGLQoZRjmBaSFtq5MOoSFkpS5vVaYPSYsxqFuw+oej00J7jwEqeAKTaMyMDAwHQYD\nVR0OBBYEFC0duIyhY5r7XJxWpWL7nHXVdQQ+MA8GA1UdEwEB/wQFMAMBAf8wCgYI\nKoZIzj0EAwIDSAAwRQIhAJrTMN+JHHRYkbFAqnRPdYjOtJEp0FfeTfEEuvHrxUXA\nAiAuUBPWhB81M8GG6wICYnb486HVrTrXGXQ6B3GbYkR75Q==\n-----END CERTIFICATE-----\n";

#[tokio::test]
async fn postgres_tls_negotiation_does_not_panic_once_the_provider_is_installed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let mut ssl_request = [0u8; 8];
            if socket.read_exact(&mut ssl_request).await.is_ok() {
                // Accept TLS, then close mid-handshake.
                let _ = socket.write_all(b"S").await;
            }
        }
    });

    assert!(
        !nanosiem_core::db::tls_provider::crypto_provider_installed(),
        "this test must run before any provider is installed in its process"
    );
    nanosiem_core::db::tls_provider::install_default_crypto_provider();
    assert!(nanosiem_core::db::tls_provider::crypto_provider_installed());

    let root = std::env::temp_dir().join(format!("nano-test-root-{}.pem", std::process::id()));
    std::fs::write(&root, TEST_ROOT_CA).unwrap();
    let options: PgConnectOptions = format!(
        "postgres://nano:nano@127.0.0.1:{port}/nano?sslmode=verify-ca&sslrootcert={}",
        root.display()
    )
    .parse()
    .unwrap();
    // A panic inside the task surfaces as a JoinError instead of aborting the test.
    let outcome = tokio::spawn(async move { PgConnection::connect_with(&options).await.map(|_| ()) }).await;
    let connect = outcome.expect("sqlx panicked while negotiating TLS with PostgreSQL");
    let _ = std::fs::remove_file(&root);
    assert!(connect.is_err(), "the fake server never completes a handshake");
}

/// Entry points (relative to the workspace root) that build PostgreSQL or
/// HTTPS rustls clients. Paths absent from this tree (the open-core mirror
/// strips the enterprise crate) are skipped.
const PROVIDER_ENTRY_POINTS: &[&str] = &[
    "nanosiem-api/src/main.rs",
    "nanosiem-api/src/bin/jobs.rs",
    "nanosiem-api/src/bin/clickhouse_migrator.rs",
    "nanosiem-search/src/main.rs",
    "nano-connector/src/bin/nano-connector-runner.rs",
    "nano-connector/src/bin/nano-connector.rs",
    "nanosiem-enterprise/src/bin/lake_platform_feed_publish/linux.rs",
    "nanosiem-enterprise/src/bin/nano_content_publish.rs",
];

#[test]
fn every_network_entry_point_installs_the_provider_in_main() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut checked = 0;
    for relative in PROVIDER_ENTRY_POINTS {
        let path = root.join(relative);
        let Ok(source) = std::fs::read_to_string(&path) else {
            continue;
        };
        let main_at = source
            .find("fn main(")
            .unwrap_or_else(|| panic!("{relative} has no fn main"));
        let body = &source[main_at..];
        let end = body.find("\n}\n").unwrap_or(body.len());
        assert!(
            body[..end].contains("install_default_crypto_provider()"),
            "{relative}: main must call nanosiem_core::db::tls_provider::install_default_crypto_provider()"
        );
        checked += 1;
    }
    assert!(checked >= 6, "expected the open-core entry points to exist, checked {checked}");
}
