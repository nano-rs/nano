// SPDX-License-Identifier: AGPL-3.0-or-later

//! "Update available" facts from the online license check-in (NAN-5114).
//!
//! nano-main adds the newest published release to a Self-run deployment's
//! `GET /api/license/status` response (`latestVersion`, `releaseNotesUrl`,
//! `upgradeUrl`, `securityRelease`; FRO-940). They are public facts: a version
//! number and two links on the nano domain. They never affect admission, and a
//! missing, malformed or foreign-linked value is dropped rather than failing
//! the check-in. Air-gapped installs make no check-in, so they have none.

use serde::{Deserialize, Serialize};

/// Links are rendered as anchors in the admin UI: only https on nano's domain.
const NANO_DOMAIN: &str = "nano.rs";

/// The newest nano release, as nano-main reported it on the last successful
/// check-in. Persisted in `license_status.raw_response.release` so the API
/// process sees what the jobs process observed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseNotice {
    pub latest_version: String,
    pub release_notes_url: String,
    pub upgrade_url: String,
    pub security_release: bool,
}

impl ReleaseNotice {
    /// Build from the optional wire fields; `None` unless the version parses
    /// and both links are https URLs on the nano domain.
    pub fn from_wire(
        latest_version: Option<String>,
        release_notes_url: Option<String>,
        upgrade_url: Option<String>,
        security_release: Option<bool>,
    ) -> Option<Self> {
        let latest_version = latest_version?;
        let core = release_core(&latest_version)?;
        let release_notes_url = release_notes_url.filter(|url| is_nano_link(url))?;
        let upgrade_url = upgrade_url.filter(|url| is_nano_link(url))?;
        Some(Self {
            latest_version: format!("{}.{}.{}", core.0, core.1, core.2),
            release_notes_url,
            upgrade_url,
            security_release: security_release.unwrap_or(false),
        })
    }

    /// Whether this release is newer than `current`. An unparseable current
    /// version is never claimed to be behind.
    pub fn is_newer_than(&self, current: &str) -> bool {
        match (release_core(current), release_core(&self.latest_version)) {
            (Some(current), Some(latest)) => current < latest,
            _ => false,
        }
    }
}

/// `(major, minor, patch)` of `x.y.z`, ignoring a leading `v` and an edition
/// suffix (`2.0.1-open`). `None` for anything else.
pub fn release_core(value: &str) -> Option<(u64, u64, u64)> {
    let value = value.trim();
    let value = value.strip_prefix('v').unwrap_or(value);
    let core = value.split_once('-').map_or(value, |(core, _)| core);
    let mut parts = core.split('.');
    let mut next = || -> Option<u64> {
        let part = parts.next()?;
        if part.is_empty()
            || !part.bytes().all(|b| b.is_ascii_digit())
            || (part.len() > 1 && part.starts_with('0'))
        {
            return None;
        }
        part.parse().ok()
    };
    let parsed = (next()?, next()?, next()?);
    parts.next().is_none().then_some(parsed)
}

/// https, no credentials, host `nano.rs` or a subdomain of it.
pub fn is_nano_link(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && (host == NANO_DOMAIN || host.ends_with(&format!(".{NANO_DOMAIN}")))
}

#[cfg(test)]
#[path = "release_notice_tests.rs"]
mod tests;
