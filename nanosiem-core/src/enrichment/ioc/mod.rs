// SPDX-License-Identifier: AGPL-3.0-or-later

//! IOC (Indicators of Compromise) enrichment module
//!
//! Provides threat intelligence enrichment for:
//! - IP addresses (malicious IPs, TOR exit nodes)
//! - Domains (C2, malware distribution)
//! - File hashes (MD5, SHA256 malware hashes)
//!
//! Supports multiple IOC sources:
//! - ThreatFox (abuse.ch) for malware-related IOCs
//! - TOR Exit Nodes (Tor Project Onionoo API) for anonymizer detection

pub mod parser;
pub mod repository;
pub mod threatfox;
pub mod tor;
pub mod types;

pub use parser::parse_threatfox_ioc;
pub use repository::{IocRepository, IocRepositoryError};
pub use threatfox::{fetch_threatfox_iocs, ThreatFoxError};
pub use tor::{fetch_tor_exit_nodes, TorError};
pub use types::{
    IocEnrichment, IocLookupResult, IocStats, IocType, ParsedIoc, ThreatFoxConfig, ThreatFoxIoc,
    ThreatFoxResponse, TorConfig,
};
