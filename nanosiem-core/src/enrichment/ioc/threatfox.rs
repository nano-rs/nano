// SPDX-License-Identifier: AGPL-3.0-or-later

//! ThreatFox API client for fetching IOC data from abuse.ch
//!
//! ThreatFox is a free platform that collects and shares IOCs (Indicators of Compromise)
//! associated with malware. This client fetches recent IOCs for enrichment.

use super::types::{ThreatFoxConfig, ThreatFoxIoc, ThreatFoxResponse};
use thiserror::Error;
use tracing::{info, instrument};

#[derive(Error, Debug)]
pub enum ThreatFoxError {
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),
    #[error("API error: {0}")]
    ApiError(String),
    #[error("Parse error: {0}")]
    ParseError(String),
}

/// Fetch IOCs from ThreatFox API
///
/// Uses the `get_iocs` query to retrieve recent IOCs from the past N days.
/// Returns a list of IOCs including IPs, domains, URLs, and file hashes.
#[instrument(skip(config), fields(endpoint = %config.api_endpoint, days = config.query_days))]
pub async fn fetch_threatfox_iocs(
    config: &ThreatFoxConfig,
) -> Result<Vec<ThreatFoxIoc>, ThreatFoxError> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout_secs))
        .build()?;

    let request_body = serde_json::json!({
        "query": "get_iocs",
        "days": config.query_days
    });

    info!(
        endpoint = %config.api_endpoint,
        days = config.query_days,
        "Fetching IOCs from ThreatFox"
    );

    let mut request = client.post(&config.api_endpoint).json(&request_body);

    // Add auth header if API key is configured
    if let Some(ref api_key) = config.api_key {
        if !api_key.is_empty() {
            request = request.header("Auth-Key", api_key);
        }
    }

    let response = request.send().await?;

    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        return Err(ThreatFoxError::ApiError(format!(
            "HTTP {}: {}",
            status,
            body.chars().take(200).collect::<String>()
        )));
    }

    let body_text = response.text().await.map_err(|e| {
        ThreatFoxError::ParseError(format!("Failed to read ThreatFox response: {}", e))
    })?;

    let body: ThreatFoxResponse = serde_json::from_str(&body_text).map_err(|e| {
        // Log first 500 chars of response for debugging
        let preview: String = body_text.chars().take(500).collect();
        tracing::warn!(
            error = %e,
            response_preview = %preview,
            response_len = body_text.len(),
            "Failed to parse ThreatFox JSON"
        );
        ThreatFoxError::ParseError(format!(
            "Failed to parse ThreatFox response: {} (len={})",
            e,
            body_text.len()
        ))
    })?;

    if body.query_status != "ok" {
        return Err(ThreatFoxError::ApiError(format!(
            "ThreatFox query status: {}",
            body.query_status
        )));
    }

    info!(
        ioc_count = body.data.len(),
        "Successfully received IOCs from ThreatFox"
    );

    Ok(body.data)
}

/// Get statistics about IOC types from a ThreatFox response
pub fn ioc_type_stats(iocs: &[ThreatFoxIoc]) -> IocTypeStats {
    let mut stats = IocTypeStats::default();

    for ioc in iocs {
        match ioc.ioc_type.as_str() {
            "ip:port" => stats.ip_port += 1,
            "domain" => stats.domain += 1,
            "url" => stats.url += 1,
            "md5_hash" => stats.md5_hash += 1,
            "sha256_hash" => stats.sha256_hash += 1,
            _ => stats.other += 1,
        }
    }

    stats
}

#[derive(Debug, Default)]
pub struct IocTypeStats {
    pub ip_port: usize,
    pub domain: usize,
    pub url: usize,
    pub md5_hash: usize,
    pub sha256_hash: usize,
    pub other: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ThreatFoxConfig::default();
        assert_eq!(
            config.api_endpoint,
            "https://threatfox-api.abuse.ch/api/v1/"
        );
        assert_eq!(config.query_days, 7);
        assert!(config.api_key.is_none());
    }

    #[test]
    fn test_parse_response_with_null_tags() {
        // ThreatFox can return null for tags field
        let json = r#"{
            "query_status": "ok",
            "data": [
                {
                    "id": "1",
                    "ioc": "192.168.1.1:8080",
                    "ioc_type": "ip:port",
                    "threat_type": "botnet_cc",
                    "threat_type_desc": "Botnet C&C",
                    "malware": "test",
                    "malware_alias": null,
                    "malware_printable": "Test",
                    "confidence_level": 100,
                    "first_seen": "2024-01-01 00:00:00 UTC",
                    "last_seen": null,
                    "reference": null,
                    "reporter": "test",
                    "tags": null
                },
                {
                    "id": "2",
                    "ioc": "example.com",
                    "ioc_type": "domain",
                    "threat_type": "payload_delivery",
                    "threat_type_desc": "Payload delivery",
                    "malware": "test2",
                    "malware_alias": null,
                    "malware_printable": "Test2",
                    "confidence_level": 75,
                    "first_seen": null,
                    "last_seen": null,
                    "reference": null,
                    "reporter": "test",
                    "tags": ["tag1", "tag2"]
                }
            ]
        }"#;

        let response: ThreatFoxResponse = serde_json::from_str(json).unwrap();
        assert_eq!(response.query_status, "ok");
        assert_eq!(response.data.len(), 2);
        assert!(response.data[0].tags.is_empty()); // null becomes empty vec
        assert_eq!(response.data[1].tags.len(), 2); // array preserved
    }
}
