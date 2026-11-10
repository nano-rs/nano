// SPDX-License-Identifier: AGPL-3.0-or-later
//! The credential an install presents on nano's licence-authenticated
//! distribution routes (NAN-5220): the enterprise content route
//! (`/api/content/v1/enterprise/...`) and the sovereign feed route.
//!
//! This module is only the seam. The open edition registers no source, so it
//! never sends a credential and never subscribes to an enterprise channel.
//! An enterprise build registers one at start-up that resolves the
//! install's current licence on every check, so a renewal, a re-imported file or a new
//! check-in is picked up without a restart.
use std::sync::{Arc, OnceLock};

use async_trait::async_trait;

/// A credential for the licence-authenticated routes. `Debug` never prints
/// the licence bytes or the token.
#[derive(Clone, PartialEq, Eq)]
pub enum DistributionCredential {
    /// A signed C05/H01 licence artifact, sent as `X-Nano-License`. Accepted
    /// by the content and the sovereign feed routes.
    SignedLicense(Vec<u8>),
    /// The online licence's enrollment token (`LICENSE_TOKEN`) and deployment
    /// id, sent as `Authorization: Bearer` + `X-Nano-Deployment-Id`. Accepted
    /// by the enterprise content route only. It is a bearer credential for the
    /// licence server, so it is sent only to `licence_origin` (the
    /// `LICENSE_URL` origin), never to a mirror or any other host.
    Enrollment { deployment_id: String, token: String, licence_origin: String },
}

impl std::fmt::Debug for DistributionCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignedLicense(bytes) => write!(f, "SignedLicense(<{} bytes>)", bytes.len()),
            Self::Enrollment { deployment_id, licence_origin, .. } => f
                .debug_struct("Enrollment")
                .field("deployment_id", deployment_id)
                .field("token", &"<redacted>")
                .field("licence_origin", licence_origin)
                .finish(),
        }
    }
}

/// Where a credential came from (reported by the status API and logs).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum CredentialOrigin {
    /// `CONTENT_CHANNELS_LICENSE_FILE` / `PLATFORM_FEEDS_LICENSE_FILE`.
    File,
    /// The online licence (`LICENSE_URL`, `LICENSE_TOKEN`, `NANO_DEPLOYMENT_ID`).
    Online,
    /// The signed licence installed under Settings → License (or by the
    /// installer's `NANO_LICENSE_FILE`).
    Installed,
}

/// The outcome of one lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialLookup {
    Found { credential: DistributionCredential, origin: CredentialOrigin },
    /// No usable licence. `reason` is operator-facing and names what to do.
    Missing { reason: String },
}

/// Resolves the install's current credential. Called on every check, never
/// cached by the consumers.
#[async_trait]
pub trait CredentialSource: Send + Sync {
    async fn lookup(&self) -> CredentialLookup;
}

static SOURCE: OnceLock<Arc<dyn CredentialSource>> = OnceLock::new();

/// Register the credential source (once per process; enterprise builds only).
pub fn register_credential_source(source: Arc<dyn CredentialSource>) {
    let _ = SOURCE.set(source);
}

/// The registered source, if any (none in the open edition).
pub fn credential_source() -> Option<Arc<dyn CredentialSource>> {
    SOURCE.get().cloned()
}

/// Shown when an enterprise channel has no licence to present.
pub const NO_LICENCE_REASON: &str = "no licence installed on this install: set the online licence values \
     (LICENSE_URL, LICENSE_TOKEN, NANO_DEPLOYMENT_ID) or import a licence file under Settings → License";

/// `scheme://host[:port]` of a URL, lowercased; `None` when it does not parse.
pub fn url_origin(url: &str) -> Option<String> {
    let parsed = url::Url::parse(url.trim()).ok()?;
    let host = parsed.host_str()?;
    Some(match parsed.port() {
        Some(port) => format!("{}://{}:{port}", parsed.scheme(), host).to_ascii_lowercase(),
        None => format!("{}://{}", parsed.scheme(), host).to_ascii_lowercase(),
    })
}

#[cfg(test)]
#[path = "credential_tests.rs"]
mod tests;
