// SPDX-License-Identifier: AGPL-3.0-or-later
//! nano's signed platform feed bundle, consumed by the ClickHouse product
//! (NAN-4948, port of main's NAN-4759 contract).
//!
//! nano publishes ONE signed, location-independent artifact (`NANFEED1`,
//! [`portable`]) carrying IPinfo Lite (geo/ASN MMDB), ThreatFox and the Tor
//! exit list. Every install fetches it from nano instead of pulling each
//! vendor itself:
//!
//! - open: `GET https://api.nano.rs/api/feeds/v1/open/current`
//! - enterprise (license-authenticated): `…/sovereign/current`
//! - air-gap: the same `.nanfeed` file, imported through the API or CLI.
//!
//! The pieces:
//!
//! - [`portable`] / [`nanpfb`]: the contract and verifier, verbatim from main
//!   (Ed25519 signature over a domain-separated descriptor, compiled-in key
//!   ring with rotation by release, payload digest + exact length, NANPFB01
//!   header consistency, rollback refusal, hard expiry).
//! - [`payload`]: reads the sections of a verified payload (the IPinfo MMDB and
//!   the IOC rows).
//! - [`loader`]: writes them into the ClickHouse enrichment path the product
//!   already reads at ingest: `ip_enrichments` (→ `ip_enrichment_dict`, the
//!   `enriched_*` / OCSF `location` + `autonomous_system` columns) and
//!   `custom_enrichment_results` as marketplace IOC rows (→
//!   `ioc_enrichment_dict`, the `ioc_*` columns). Each install writes under a
//!   generation key and becomes visible in ONE commit row
//!   (`platform_feed_commits`, CH migration 184), so a failed load never mixes
//!   with the last good one.
//! - [`state`]: the PostgreSQL record of the installed (last good) bundle and
//!   the status contract served by `GET /api/enrichment/platform-feeds`.
//! - [`consumer`]: fetch → verify → accept → load → record; the leader-only
//!   scheduled check and the offline import share it.
//!
//! The hosted pieces of main (publisher, packed cache, lake cell readers,
//! region mirrors) are not ported.

#[cfg(unix)]
pub mod consumer;
#[cfg(unix)]
pub mod loader;
#[cfg(unix)]
pub mod nanpfb;
#[cfg(unix)]
pub mod payload;
#[cfg(unix)]
pub mod portable;
pub mod state;
#[cfg(all(test, unix))]
mod test_support;
