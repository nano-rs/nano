// SPDX-License-Identifier: AGPL-3.0-or-later

//! HTTPS client for the platform's owner endpoint (part signing and the
//! prevalence-state owner proxy). The owner serves a PRIVATE-CA certificate,
//! so the client trusts only the release-pinned `part_signing.ca_file`
//! bundle, never system roots, with hostname verification on. The bundle can
//! be re-read at any time ([`OwnerTlsClient::reload_ca`]); a changed bundle
//! rebuilds the client, so a CA rotation needs no restart. A bad or
//! half-written bundle keeps the current client.

use anyhow::{ensure, Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, RwLock};
use std::time::{Duration, Instant};

pub struct OwnerTlsClient {
    client: RwLock<reqwest::Client>,
    ca: Option<OwnerCa>,
    timeout: Duration,
}

/// The CA bundle file, the digest of the bundle the current client was
/// built from, and when it was last checked.
struct OwnerCa {
    path: PathBuf,
    digest: Mutex<[u8; 32]>,
    checked: Mutex<Instant>,
}

/// A client whose only trust roots are the certificates in `ca_pem`. Every
/// certificate in the bundle is trusted (old + new during a CA rotation).
fn build(ca_pem: Option<&[u8]>, timeout: Duration) -> Result<reqwest::Client> {
    let builder = reqwest::Client::builder().timeout(timeout).redirect(reqwest::redirect::Policy::none());
    let builder = match ca_pem {
        Some(pem) => {
            let roots = reqwest::Certificate::from_pem_bundle(pem).context("parse owner CA bundle")?;
            ensure!(!roots.is_empty(), "owner CA bundle has no certificates");
            // `tls_certs_only` drops the built-in and platform roots.
            builder.https_only(true).tls_certs_only(roots)
        }
        None => builder,
    };
    builder.build().context("build owner client")
}

fn read(path: &Path) -> Result<(Vec<u8>, [u8; 32])> {
    use sha2::Digest;
    let pem = std::fs::read(path).with_context(|| format!("read owner CA bundle {}", path.display()))?;
    let digest = sha2::Sha256::digest(&pem).into();
    Ok((pem, digest))
}

impl OwnerTlsClient {
    /// `ca_file` is required for an `https` URL; there is no fallback to
    /// system roots. Plain `http` is accepted only in tests.
    pub fn new(url: &str, ca_file: Option<&Path>, timeout: Duration) -> Result<Self> {
        let https = url.starts_with("https://");
        ensure!(https || cfg!(test), "owner endpoint must use https");
        ensure!(
            !https || ca_file.is_some(),
            "part_signing.ca_file is required for an https owner URL (system roots are never trusted)"
        );
        let (client, ca) = match ca_file {
            Some(path) => {
                let (pem, digest) = read(path)?;
                let ca = OwnerCa { path: path.to_path_buf(), digest: Mutex::new(digest), checked: Mutex::new(Instant::now()) };
                (build(Some(&pem), timeout)?, Some(ca))
            }
            None => (build(None, timeout)?, None),
        };
        Ok(Self { client: RwLock::new(client), ca, timeout })
    }

    /// The current client (a cheap handle clone).
    pub fn client(&self) -> reqwest::Client {
        self.client.read().expect("owner client lock").clone()
    }

    /// Re-read the CA bundle and rebuild the client if it changed. Returns
    /// whether the client was replaced. On any error the current client is
    /// kept.
    pub fn reload_ca(&self) -> Result<bool> {
        let Some(ca) = &self.ca else { return Ok(false) };
        *ca.checked.lock().expect("owner CA check lock") = Instant::now();
        let (pem, digest) = read(&ca.path)?;
        let mut current = ca.digest.lock().expect("owner CA digest lock");
        if *current == digest {
            return Ok(false);
        }
        let client = build(Some(&pem), self.timeout)?;
        *self.client.write().expect("owner client lock") = client;
        *current = digest;
        Ok(true)
    }

    /// [`Self::reload_ca`], logged.
    pub fn reload_ca_logged(&self, what: &str) {
        match self.reload_ca() {
            Ok(true) => tracing::info!(client = what, "owner CA bundle changed; client rebuilt"),
            Ok(false) => {}
            Err(error) => tracing::error!(client = what, error = %format!("{error:#}"),
                "owner CA bundle reload failed; keeping the current client"),
        }
    }

    /// [`Self::reload_ca_logged`] at most once per `every`: for clients with
    /// no refresh loop (the prevalence owner store inside SlateDB).
    pub fn reload_ca_if_due(&self, every: Duration, what: &str) {
        let Some(ca) = &self.ca else { return };
        if ca.checked.lock().expect("owner CA check lock").elapsed() >= every {
            self.reload_ca_logged(what);
        }
    }
}
