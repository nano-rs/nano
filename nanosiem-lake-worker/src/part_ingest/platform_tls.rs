// SPDX-License-Identifier: AGPL-3.0-or-later

//! Public platform API transport. The cluster owner's private CA must never
//! replace the public roots used by the credential exchange and catalog broker.
use anyhow::{ensure, Result};
use std::time::Duration;

/// Public PKI dependency. Tests add their generated platform CA to the same
/// production constructor; no host trust-store mutation or live credentials.
#[derive(Clone, Default)]
pub(crate) struct PlatformTrust {
    #[cfg(test)]
    pub(crate) additional_ca: Option<String>,
}

pub(crate) struct PlatformCatalogClient {
    client: reqwest::Client,
    timeout: Duration,
    https_only: bool,
    tls: rustls::ClientConfig,
}

impl PlatformCatalogClient {
    pub(crate) fn new(endpoint: &str, timeout: Duration, trust: PlatformTrust) -> Result<Self> {
        let url = reqwest::Url::parse(endpoint)?;
        ensure!(
            url.scheme() == "https"
                || cfg!(test)
                    && url.scheme() == "http"
                    && matches!(url.host_str(), Some("127.0.0.1" | "localhost")),
            "platform catalog requires https"
        );
        ensure!(
            url.username().is_empty()
                && url.password().is_none()
                && url.query().is_none()
                && url.fragment().is_none(),
            "invalid platform catalog origin"
        );
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        #[cfg(test)]
        if let Some(pem) = &trust.additional_ca {
            use rustls::pki_types::pem::PemObject;
            for cert in rustls::pki_types::CertificateDer::pem_slice_iter(pem.as_bytes()) {
                roots.add(cert?)?;
            }
        }
        let _ = trust;
        let tls = rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        let https_only = url.scheme() == "https";
        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls.clone())
            .https_only(https_only)
            .timeout(timeout)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        Ok(Self {
            client,
            timeout,
            https_only,
            tls,
        })
    }

    pub(crate) fn client(&self) -> reqwest::Client {
        self.client.clone()
    }

    /// Iceberg embeds reqwest 0.12. Keep identical public-root, redirect and
    /// deadline policy on that transport as on control/metadata requests.
    pub(crate) fn iceberg_client(&self) -> Result<reqwest12::Client> {
        Ok(reqwest12::Client::builder()
            .use_preconfigured_tls(self.tls.clone())
            .https_only(self.https_only)
            .timeout(self.timeout)
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest12::redirect::Policy::none())
            .build()?)
    }
}
