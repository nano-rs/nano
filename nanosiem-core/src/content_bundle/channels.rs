// SPDX-License-Identifier: AGPL-3.0-or-later
//! The compiled-in registry of nano content channels (NAN-4955).
//!
//! A channel is one reviewed content source at one pinned branch, published
//! by the app as one signed bundle. The same table drives the app side, the
//! distribution route allow-list (nano-main mirrors it) and this consumer: a
//! channel that is not listed here is refused everywhere, so content cannot
//! be introduced through configuration or data.
//!
//! [`CHANNELS`] are the channels every edition knows. An extension (a
//! non-open build) may add its own channels once, at start-up, with
//! [`register_extension_channels`]; an open build registers none, so it
//! refuses any other channel id as unknown.

use crate::schema::{SchemaId, LEGACY_UDM_CONTENT_BRANCH};

/// Which distribution route serves a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    /// Unauthenticated: the content is public repository content.
    Open,
    /// License-authenticated: content that is not public.
    Enterprise,
}

impl Route {
    pub fn as_str(self) -> &'static str {
        match self {
            Route::Open => "open",
            Route::Enterprise => "enterprise",
        }
    }
}

/// Which builds subscribe to a channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Subscribers {
    /// Open and enterprise builds.
    All,
    /// Only enterprise builds consume it (the open build has no consumer).
    EnterpriseOnly,
}

/// How a channel's content is applied on the install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Parsers,
    Rules,
    Playbooks,
    MarketplaceCatalog,
    ModelCatalog,
    /// The pinned MITRE ATT&CK STIX catalog.
    MitreCatalog,
    /// A channel registered by an extension; applied by the extension's
    /// applier (see `consumer::register_extension_applier`).
    Extension,
}

/// One channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    /// Stable id: `[a-z0-9-]+(\.[a-z0-9-]+)?`. Used in routes and R2 keys.
    pub id: &'static str,
    pub kind: Kind,
    /// `owner/repo` on github.com (the app's upstream; the consumer
    /// serves repository rows with this URL from the channel snapshot).
    /// Empty for channels whose upstream is not a git repository.
    pub repo: &'static str,
    /// Upstream branch (empty when `repo` is empty).
    pub branch: &'static str,
    /// Include only this repository-relative file in the signed snapshot.
    /// Most channels include the complete reviewed tree; a large upstream
    /// history such as MITRE ATT&CK is projected to the one pinned artifact
    /// the consumer reads.
    pub artifact_path: Option<&'static str>,
    pub route: Route,
    pub subscribers: Subscribers,
}

/// Every channel nano publishes. Keep in sync with nano-main
/// `services/content-distribution/channels.ts` (a test there pins the ids).
pub const CHANNELS: &[Channel] = &[
    Channel { id: "parsers.main", kind: Kind::Parsers, repo: "nano-rs/parsers", branch: "main", artifact_path: None, route: Route::Open, subscribers: Subscribers::All },
    Channel { id: "parsers.legacy-clickhouse", kind: Kind::Parsers, repo: "nano-rs/parsers", branch: LEGACY_UDM_CONTENT_BRANCH, artifact_path: None, route: Route::Open, subscribers: Subscribers::All },
    Channel { id: "rules.main", kind: Kind::Rules, repo: "nano-rs/rules", branch: "main", artifact_path: None, route: Route::Open, subscribers: Subscribers::All },
    Channel { id: "rules.legacy-clickhouse", kind: Kind::Rules, repo: "nano-rs/rules", branch: LEGACY_UDM_CONTENT_BRANCH, artifact_path: None, route: Route::Open, subscribers: Subscribers::All },
    Channel { id: "playbooks.main", kind: Kind::Playbooks, repo: "nano-rs/playbooks", branch: "main", artifact_path: None, route: Route::Open, subscribers: Subscribers::All },
    Channel { id: "enrichments.main", kind: Kind::MarketplaceCatalog, repo: "nano-rs/nano-enrichments", branch: "main", artifact_path: None, route: Route::Open, subscribers: Subscribers::All },
    Channel { id: "integrations.main", kind: Kind::MarketplaceCatalog, repo: "nano-rs/nano-integrations", branch: "main", artifact_path: None, route: Route::Open, subscribers: Subscribers::EnterpriseOnly },
    Channel { id: "models.main", kind: Kind::ModelCatalog, repo: "nano-rs/models", branch: "main", artifact_path: None, route: Route::Open, subscribers: Subscribers::EnterpriseOnly },
    Channel { id: "mitre-attack.v19-1", kind: Kind::MitreCatalog, repo: "mitre-attack/attack-stix-data", branch: "v19.1", artifact_path: Some("enterprise-attack/enterprise-attack.json"), route: Route::Open, subscribers: Subscribers::All },
];

static EXTENSION_CHANNELS: std::sync::OnceLock<&'static [Channel]> = std::sync::OnceLock::new();

/// Register an extension's channels (once per process, before the consumer
/// starts). Ids must be well formed and must not collide with [`CHANNELS`];
/// extension channels are never repository-backed by an open `Kind`.
pub fn register_extension_channels(channels: &'static [Channel]) -> Result<(), String> {
    for c in channels {
        if !id_ok(c.id)
            || CHANNELS.iter().any(|o| o.id == c.id)
            || c.kind != Kind::Extension
            || c.artifact_path.is_some()
        {
            return Err(format!("invalid extension channel {}", c.id));
        }
    }
    match EXTENSION_CHANNELS.set(channels) {
        Ok(()) => Ok(()),
        Err(_) if EXTENSION_CHANNELS.get().is_some_and(|set| *set == channels) => Ok(()),
        Err(_) => Err("extension channels are already registered".into()),
    }
}

/// Every channel this process knows: [`CHANNELS`] plus any registered
/// extension channels.
pub fn all() -> impl Iterator<Item = &'static Channel> {
    CHANNELS.iter().chain(EXTENSION_CHANNELS.get().copied().unwrap_or(&[]).iter())
}

/// GitHub organizations whose repositories are first-party content. `nanos-sh`
/// is the pre-rename organization (migration 178).
pub const FIRST_PARTY_OWNERS: &[&str] = &["nano-rs", "nanos-sh"];

pub fn by_id(id: &str) -> Option<&'static Channel> {
    all().find(|c| c.id == id)
}

/// Whether `owner` is a first-party organization (case-insensitive).
pub fn is_first_party_owner(owner: &str) -> bool {
    FIRST_PARTY_OWNERS.iter().any(|o| o.eq_ignore_ascii_case(owner.trim()))
}

/// The channel serving `owner/repo@branch`, if any. `nanos-sh` maps to
/// `nano-rs`; repo names compare case-insensitively without `.git`.
pub fn for_repo(owner: &str, repo: &str, branch: &str) -> Option<&'static Channel> {
    if !is_first_party_owner(owner) {
        return None;
    }
    let repo = repo.trim().trim_end_matches(".git").to_ascii_lowercase();
    let full = format!("nano-rs/{repo}");
    all().find(|c| !c.repo.is_empty() && c.repo == full && c.branch == branch.trim())
}

/// Channels this build subscribes to for the active schema profile: the
/// profile's branch of the profile-split repos (OCSF `main`, UDM
/// `legacy/clickhouse`), `main` of the rest, and the enterprise-only (and
/// registered extension) channels on enterprise builds.
pub fn subscribed(profile: SchemaId, enterprise: bool) -> Vec<&'static Channel> {
    let branch = crate::schema::content_branch_for(profile);
    all()
        .filter(|c| enterprise || c.subscribers == Subscribers::All)
        .filter(|c| match c.kind {
            Kind::Parsers | Kind::Rules => c.branch == branch,
            _ => true,
        })
        .collect()
}

/// Whether a channel id is well formed (also checked for registry entries).
pub fn id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'-' | b'.'))
        && !id.starts_with('.')
        && !id.ends_with('.')
        && !id.contains("..")
}
