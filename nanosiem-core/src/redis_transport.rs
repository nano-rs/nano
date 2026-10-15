// SPDX-License-Identifier: AGPL-3.0-or-later

//! Consistent verified Redis TLS for private group services. Credentials stay
//! in connection configuration; errors never echo a supplied URL or CA bytes.

use redis::{
    Client, ConnectionAddr, ErrorKind, IntoConnectionInfo, RedisError, RedisResult, TlsCertificates,
};
use std::{io::Read, path::Path};

fn invalid(message: &'static str) -> RedisError {
    (ErrorKind::InvalidClientConfig, message).into()
}

/// `NANOSIEM_REDIS_CA_FILE` selects an explicit PEM trust root for `rediss://`.
/// With no override, normal system roots are used for TLS and existing local
/// `redis://`/Unix socket configurations remain supported. An override cannot
/// silently downgrade to plaintext or disable hostname verification.
pub fn client_from_url(url: &str) -> RedisResult<Client> {
    let ca = std::env::var_os("NANOSIEM_REDIS_CA_FILE");
    client_with_ca(url, ca.as_deref().map(Path::new))
}

fn client_with_ca(url: &str, ca: Option<&Path>) -> RedisResult<Client> {
    let info = url
        .into_connection_info()
        .map_err(|_| invalid("Invalid Redis connection configuration"))?;
    if matches!(info.addr(), ConnectionAddr::TcpTls { insecure: true, .. }) {
        return Err(invalid("Redis TLS verification cannot be disabled"));
    }
    if matches!(info.addr(), ConnectionAddr::TcpTls { .. })
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        // Other workspace crates enable both Ring and AWS-LC, so Rustls cannot
        // infer a provider. Preserve an already configured process provider;
        // concurrent first connections safely share the install winner.
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    }
    let Some(path) = ca else {
        return Client::open(info).map_err(|_| invalid("Invalid Redis connection configuration"));
    };
    if !path.is_absolute()
        || !matches!(
            info.addr(),
            ConnectionAddr::TcpTls {
                insecure: false,
                ..
            }
        )
    {
        return Err(invalid(
            "An explicit Redis CA requires an absolute file path and verified rediss transport",
        ));
    }
    let file = std::fs::File::open(path).map_err(|_| invalid("Redis CA file is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| invalid("Redis CA metadata is unavailable"))?;
    const MAX_CA_BYTES: u64 = 1024 * 1024;
    if !metadata.is_file() || !(1..=MAX_CA_BYTES).contains(&metadata.len()) {
        return Err(invalid("Redis CA must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_CA_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid("Redis CA cannot be read"))?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CA_BYTES {
        return Err(invalid("Redis CA must be a bounded regular file"));
    }
    // Require a nonempty certificate stream; redis-rs otherwise accepts an
    // empty PEM trust store and postpones this configuration error to connect.
    const CERTIFICATE_MARKER: &[u8] = b"-----BEGIN CERTIFICATE-----";
    if !bytes
        .windows(CERTIFICATE_MARKER.len())
        .any(|part| part == CERTIFICATE_MARKER)
    {
        return Err(invalid("Redis CA contains no PEM certificates"));
    }
    Client::build_with_tls(
        info,
        TlsCertificates {
            client_tls: None,
            root_cert: Some(bytes),
        },
    )
    .map_err(|_| invalid("Invalid Redis TLS trust configuration"))
}

#[cfg(test)]
#[path = "redis_transport/tls_tests.rs"]
mod tls_tests;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preserves_legacy_local_connections_without_ca_override() {
        assert!(client_with_ca("redis://localhost:6379/0", None).is_ok());
        assert!(client_with_ca("rediss://localhost:6379/0", None).is_ok());
    }

    #[test]
    fn rejects_plaintext_downgrade_and_relative_ca_paths() {
        assert!(client_with_ca("redis://localhost", Some(Path::new("/private/ca.crt"))).is_err());
        assert!(client_with_ca("rediss://localhost", Some(Path::new("ca.crt"))).is_err());
        assert!(client_with_ca("rediss://localhost/#insecure", None).is_err());
    }

    #[test]
    fn errors_do_not_echo_urls_or_trust_material() {
        let error =
            client_with_ca("invalid://user:never-log-password@localhost", None).unwrap_err();
        assert!(!error.to_string().contains("never-log-password"));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), "not a certificate; never-log-cert-material").unwrap();
        let error = client_with_ca("rediss://localhost", Some(file.path())).unwrap_err();
        assert!(!error.to_string().contains("never-log-cert-material"));
        std::fs::write(file.path(), vec![b'x'; 1024 * 1024 + 1]).unwrap();
        assert!(client_with_ca("rediss://localhost", Some(file.path())).is_err());
    }
}

pub mod reconnecting;
pub use reconnecting::ReconnectingConnection;
