// SPDX-License-Identifier: AGPL-3.0-or-later

//! InputLookup module for URL-based data enrichment
//!
//! This module provides the `inputlookup` command functionality for fetching
//! data from external URLs during search queries. It supports:
//!
//! - **Data source mode**: Fetch URL and return parsed rows as search results
//! - **Enrichment mode**: Join URL results with existing search results
//!
//! ## Security
//!
//! The module includes SSRF (Server-Side Request Forgery) protection:
//! - Blocks private IP addresses (10.x, 172.16-31.x, 192.168.x)
//! - Blocks localhost and loopback addresses
//! - Blocks link-local addresses (169.254.x)
//! - Blocks cloud metadata endpoints (169.254.169.254, etc.)
//! - Only allows http:// and https:// schemes
//! - Validates redirect targets
//!
//! ## Usage
//!
//! ```text
//! # Data source mode - fetch URL and return as results
//! | inputlookup url="https://feeds.example.com/iocs.csv" format=csv
//!
//! # Enrichment mode - join URL results with search results
//! index=firewall
//! | inputlookup url="https://api.ipinfo.io/{src_ip}/json" key=src_ip format=json
//! ```
//!
//! ## Configuration
//!
//! The service can be configured with:
//! - `max_response_size`: Maximum response size in bytes (default: 10MB)
//! - `default_timeout_secs`: Default request timeout (default: 30s)
//! - `default_cache_ttl_secs`: Default cache TTL (default: 300s)
//! - `default_max_rows`: Maximum rows to return (default: 10000)
//! - `rate_limit_per_minute`: Rate limit per user (default: 60)
//! - `allow_http`: Whether to allow plain HTTP (default: false)

mod fetcher;
mod response_parser;
mod service;
mod ssrf;
mod types;

pub use fetcher::{CacheStats, FetchError, FetchResult, UrlFetcher};
pub use response_parser::ParseError;
pub use service::{params_from_command, InputLookupError, InputLookupOutcome, InputLookupService};
pub use ssrf::{
    ai_base_url_validator, private_ai_endpoints_allowed, restricted_redirect_policy, IpCidr,
    SsrfConfig, SsrfError, SsrfValidator, ALLOW_PRIVATE_AI_ENDPOINTS_ENV,
};
pub use types::{InputLookupConfig, InputLookupFormat, InputLookupParams, UrlTemplate};
