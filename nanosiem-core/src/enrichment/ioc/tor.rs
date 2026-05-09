// SPDX-License-Identifier: AGPL-3.0-or-later

//! TOR Exit Nodes API client for fetching exit node IP addresses
//!
//! Fetches the list of TOR exit nodes from the official Tor Project Onionoo API.
//! These IPs are useful for detecting anonymized traffic in enterprise networks.

use super::types::{IocType, OnionooResponse, ParsedIoc, TorConfig};
use thiserror::Error;
use tracing::{info, instrument};

#[derive(Error, Debug)]
pub enum TorError {
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Fetch TOR exit node IPs from the Onionoo API
///
/// Returns a list of parsed IOCs for all exit node IP addresses.
#[instrument(skip(config), fields(endpoint = %config.api_endpoint))]
pub async fn fetch_tor_exit_nodes(config: &TorConfig) -> Result<Vec<ParsedIoc>, TorError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .build()?;

    info!(
        endpoint = %config.api_endpoint,
        "Fetching TOR exit nodes from Onionoo API"
    );

    let response = client
        .get(&config.api_endpoint)
        .header("Accept", "application/json")
        .send()
        .await?;

    if !response.status().is_success() {
        let status = response.status();
        if status.as_u16() == 429 {
            return Err(TorError::ApiError(
                "Rate limit exceeded for Tor Onionoo API".to_string(),
            ));
        }
        let body = response.text().await.unwrap_or_default();
        return Err(TorError::ApiError(format!(
            "HTTP {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        )));
    }

    let body: OnionooResponse = response
        .json()
        .await
        .map_err(|e| TorError::ParseError(format!("Failed to parse Onionoo response: {}", e)))?;

    let mut iocs = Vec::new();
    let mut ip_set = std::collections::HashSet::new();

    for relay in &body.relays {
        // Get exit addresses (preferred) or fall back to OR addresses
        let ips: Vec<&str> = if let Some(ref exit_addrs) = relay.exit_addresses {
            exit_addrs.iter().map(|s| s.as_str()).collect()
        } else if let Some(ref or_addrs) = relay.or_addresses {
            // Extract IP from "IP:Port" format
            or_addrs
                .iter()
                .filter_map(|addr| addr.split(':').next())
                .collect()
        } else {
            continue;
        };

        for ip in ips {
            // Skip if we've already processed this IP
            if !ip_set.insert(ip.to_string()) {
                continue;
            }

            // Build tags from relay flags
            let mut tags = vec!["tor_exit".to_string(), "anonymizer".to_string()];
            if let Some(ref flags) = relay.flags {
                for flag in flags {
                    let flag_lower = flag.to_lowercase();
                    if flag_lower == "guard" {
                        tags.push("tor_guard".to_string());
                    } else if flag_lower == "authority" {
                        tags.push("tor_authority".to_string());
                    }
                }
            }

            iocs.push(ParsedIoc {
                ioc_value: ip.to_string(),
                ioc_type: IocType::Ip,
                original_value: Some(ip.to_string()),
                threat_type: Some("anonymizer".to_string()),
                threat_type_desc: Some("TOR Exit Node - Anonymization Network".to_string()),
                malware: None,
                malware_alias: None,
                malware_printable: None,
                confidence_level: config.confidence_level,
                first_seen_at: relay.first_seen.as_ref().and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                }),
                last_seen_at: relay.last_seen.as_ref().and_then(|s| {
                    chrono::DateTime::parse_from_rfc3339(s)
                        .ok()
                        .map(|dt| dt.with_timezone(&chrono::Utc))
                }),
                tags,
                reference_url: Some("https://metrics.torproject.org/".to_string()),
                reporter: Some("Tor Project".to_string()),
            });
        }
    }

    info!(
        relay_count = body.relays.len(),
        unique_ips = iocs.len(),
        "Successfully fetched TOR exit nodes"
    );

    Ok(iocs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = TorConfig::default();
        assert!(config.api_endpoint.contains("onionoo.torproject.org"));
        assert_eq!(config.confidence_level, 100);
    }
}
