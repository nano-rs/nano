// SPDX-License-Identifier: AGPL-3.0-or-later

//! Catalog entries nano's signed platform feed bundle provides (NAN-4959).
//!
//! IPinfo Lite, ThreatFox and the Tor exit list are pulled ONLY through
//! app.nano.rs, as one signed bundle (`platform_enrichment::consumer`). Their
//! marketplace entries can no longer install, sync, run or be enabled as
//! direct fetchers (native IPinfo download, a Deno ThreatFox / Tor pull): two
//! sources for one feed meant duplicate or conflicting verdicts, and a direct
//! pull bypasses the bundle's signature and rollback fence.

/// The bundle feed id a catalog slug stands for, if the bundle provides it.
/// Matches the slug aliases the web inventory uses (`BUNDLE_FEED_SLUGS`).
pub fn bundle_feed_for_slug(slug: &str) -> Option<&'static str> {
    match slug.trim().to_ascii_lowercase().as_str() {
        "ipinfo_lite" | "ipinfo-lite" => Some("ipinfo_lite"),
        "threatfox" => Some("threatfox"),
        "tor-exit-nodes" | "tor_exit_nodes" | "tor" => Some("tor_exit_nodes"),
        _ => None,
    }
}

/// Every catalog slug the bundle provides (for SQL `= ANY($1)` filters).
pub const BUNDLE_PROVIDED_SLUGS: &[&str] = &[
    "ipinfo_lite",
    "ipinfo-lite",
    "threatfox",
    "tor-exit-nodes",
    "tor_exit_nodes",
    "tor",
];

/// Operator-facing reason a bundle-provided entry refuses an action.
pub fn provided_by_bundle_message(slug: &str) -> String {
    format!(
        "{slug} is provided by nano's signed platform feed bundle (app.nano.rs); it cannot be \
         installed, synced or enabled as a direct feed. Refresh it with Check now or Import file \
         under Marketplace > Platform feeds."
    )
}

#[cfg(test)]
#[path = "platform_feed_tests.rs"]
mod tests;
