// SPDX-License-Identifier: AGPL-3.0-or-later

//! CrowdStrike Falcon Data Replicator source configs (NAN-5005) on the nano
//! Vector fork's native `crowdstrike_fdr` source (`0.61.0-nano.6`+).
//!
//! FDR's SQS queue carries one batch manifest per message (not an S3 event
//! notification); the fork's source downloads every gzipped NDJSON object a
//! manifest lists and emits one event per line, with end-to-end
//! acknowledgements: a message is deleted only after every event of its batch
//! is accepted downstream (the ClickHouse sink's disk buffer).
//!
//! Credentials come from a bound `aws_s3`-provider credential, exactly as for
//! `aws_sqs` ([`SourceConfigService::aws_auth_table`]): static keys (what
//! CrowdStrike issues for FDR), a role to assume (`assume_role_arn` +
//! `external_id`, alone or chained from the keys), or nothing (the
//! deployment's ambient AWS identity). The keys are also presented to S3 in
//! the queue's region, for the bucket (access-point alias) each manifest names.
//!
//! Lookup snapshots (`fdrv2-*`: aidmaster, managedassets, ...) leave the
//! source on its separate `lookups` output, which nothing consumes, so they
//! are dropped by design: they are host inventory, not events, and the
//! CrowdStrike Falcon parser would turn them into junk OCSF records. Their
//! messages are still acknowledged and deleted. See [`LOOKUPS_POLICY`].

use super::service::{SourceConfigService, SourceConfigServiceError, MAX_SQS_VISIBILITY_SECS};

/// The `.source_type` an FDR source routes to by default: the match value of
/// the CrowdStrike Falcon parser (`parsers-ocsf/crowdstrike_falcon`, OCSF;
/// `parsers/crowdstrike_falcon`, UDM). FDR events are flat JSON dispatched on
/// `event_simpleName`, which that parser handles.
pub(crate) const FDR_DEFAULT_SOURCE_TYPE: &str = "crowdstrike_falcon";

/// Documented in the generated TOML next to the source.
pub(crate) const LOOKUPS_POLICY: &str =
    "fdrv2-* lookup snapshots go to the source's `lookups` output, which is not consumed: \
     they are dropped (and their messages deleted) by design";

/// `start_from` values the fork accepts besides an RFC 3339 timestamp.
const START_FROM_KEYWORDS: &[&str] = &["beginning", "now", "cursor"];
const DEFAULT_START_FROM: &str = "beginning";
const CHECKSUM_MODES: &[&str] = &["verify", "warn", "off"];
const MAX_FILE_CONCURRENCY: u32 = 64;
const MAX_INFLIGHT_MANIFESTS: u32 = 1_024;
/// The fork's own ceiling: SQS keeps a received message invisible 12 h at most.
const MAX_HOLD_SECS: u32 = 43_200;
const DEFAULT_REGION: &str = "us-west-2";

fn invalid(msg: impl std::fmt::Display) -> SourceConfigServiceError {
    SourceConfigServiceError::InvalidConfig(format!("crowdstrike_fdr: {msg}"))
}

fn str_field<'a>(conn: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    conn.get(key)
        .and_then(|v| v.as_str())
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// A positive integer `<= max`, or absent / null. Anything else is an error
/// naming the field (NAN-2188: never silently fall back to a default).
fn bounded_u32(
    conn: &serde_json::Value,
    key: &str,
    max: u32,
) -> Result<Option<u32>, SourceConfigServiceError> {
    match conn.get(key) {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(v) => v
            .as_i64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| *n > 0 && *n <= max)
            .map(Some)
            .ok_or_else(|| invalid(format!("connection_config.{key} must be an integer between 1 and {max}"))),
    }
}

/// The region in an SQS queue URL (`https://sqs.<region>.amazonaws.com/...`).
pub(crate) fn region_from_queue_url(queue_url: &str) -> Option<String> {
    let url = url::Url::parse(queue_url).ok()?;
    let host = url.host_str()?.to_ascii_lowercase();
    let rest = host.strip_prefix("sqs.")?;
    let (region, suffix) = rest.split_once('.')?;
    (suffix.starts_with("amazonaws.com") && !region.is_empty()).then(|| region.to_string())
}

fn check_queue_url(queue_url: &str) -> Result<(), SourceConfigServiceError> {
    let url = url::Url::parse(queue_url)
        .map_err(|_| invalid("connection_config.queue_url must be an absolute SQS queue URL"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(invalid("connection_config.queue_url must be an http(s) SQS queue URL"));
    }
    if url.path().trim_matches('/').is_empty() {
        return Err(invalid("connection_config.queue_url must name a queue (…/<account>/<queue>)"));
    }
    Ok(())
}

fn check_start_from(value: &str) -> Result<(), SourceConfigServiceError> {
    if START_FROM_KEYWORDS.contains(&value) || chrono::DateTime::parse_from_rfc3339(value).is_ok() {
        return Ok(());
    }
    Err(invalid(format!(
        "connection_config.start_from must be one of {START_FROM_KEYWORDS:?} or an RFC 3339 timestamp, not {value:?}"
    )))
}

/// Write-time checks. An empty config is accepted (the UI creates a pull
/// source unconfigured, then configures it); [`source_table`] requires the
/// queue URL at render.
pub(crate) fn validate_conn(conn: &serde_json::Value) -> Result<(), SourceConfigServiceError> {
    for key in ["queue_url", "region", "endpoint", "start_from", "checksum"] {
        if let Some(v) = conn.get(key) {
            if !v.is_string() && !v.is_null() {
                return Err(invalid(format!("connection_config.{key} must be a string")));
            }
        }
    }
    if let Some(queue_url) = str_field(conn, "queue_url") {
        check_queue_url(queue_url)?;
    }
    if let Some(endpoint) = str_field(conn, "endpoint") {
        check_queue_url_like_endpoint(endpoint)?;
    }
    if let Some(start_from) = str_field(conn, "start_from") {
        check_start_from(start_from)?;
    }
    if let Some(checksum) = str_field(conn, "checksum") {
        if !CHECKSUM_MODES.contains(&checksum) {
            return Err(invalid(format!(
                "connection_config.checksum must be one of {CHECKSUM_MODES:?}, not {checksum:?}"
            )));
        }
    }
    bounded_u32(conn, "file_concurrency", MAX_FILE_CONCURRENCY)?;
    bounded_u32(conn, "max_inflight_manifests", MAX_INFLIGHT_MANIFESTS)?;
    bounded_u32(conn, "visibility_timeout_secs", MAX_SQS_VISIBILITY_SECS)?;
    bounded_u32(conn, "max_hold_secs", MAX_HOLD_SECS)?;
    match conn.get("max_inflight_bytes") {
        None | Some(serde_json::Value::Null) => {}
        Some(v) if v.as_u64().is_some_and(|n| n > 0) => {}
        Some(_) => return Err(invalid("connection_config.max_inflight_bytes must be a positive integer")),
    }
    Ok(())
}

fn check_queue_url_like_endpoint(endpoint: &str) -> Result<(), SourceConfigServiceError> {
    let url = url::Url::parse(endpoint)
        .map_err(|_| invalid("connection_config.endpoint must be an absolute http(s) URL"))?;
    if !matches!(url.scheme(), "https" | "http") || url.host_str().is_none() {
        return Err(invalid("connection_config.endpoint must be an absolute http(s) URL"));
    }
    Ok(())
}

/// The `[sources.<name>]` table of an FDR source.
pub(crate) fn source_table(
    source_name: &str,
    conn: &serde_json::Value,
    creds: Option<&serde_json::Value>,
) -> Result<toml::Table, SourceConfigServiceError> {
    // Re-checked at render: rows can predate validation.
    validate_conn(conn)?;
    let queue_url = str_field(conn, "queue_url")
        .ok_or_else(|| invalid("connection_config.queue_url is required"))?;
    let region = str_field(conn, "region")
        .map(str::to_string)
        .or_else(|| region_from_queue_url(queue_url))
        .unwrap_or_else(|| DEFAULT_REGION.to_string());

    let mut source = toml::Table::new();
    source.insert("type".into(), "crowdstrike_fdr".into());
    source.insert("region".into(), region.clone().into());
    source.insert("queue_url".into(), queue_url.into());
    if let Some(endpoint) = str_field(conn, "endpoint") {
        source.insert("endpoint".into(), endpoint.into());
        // S3-compatible test endpoints (LocalStack) need path-style; real AWS
        // serves access-point aliases virtual-hosted (the fork's default).
        source.insert("force_path_style".into(), true.into());
    }
    source.insert(
        "start_from".into(),
        str_field(conn, "start_from").unwrap_or(DEFAULT_START_FROM).into(),
    );
    source.insert(
        "checksum".into(),
        str_field(conn, "checksum").unwrap_or("verify").into(),
    );
    let int = |v: u32| toml::Value::Integer(i64::from(v));
    for (key, max) in [
        ("file_concurrency", MAX_FILE_CONCURRENCY),
        ("max_inflight_manifests", MAX_INFLIGHT_MANIFESTS),
        ("visibility_timeout_secs", MAX_SQS_VISIBILITY_SECS),
        ("max_hold_secs", MAX_HOLD_SECS),
    ] {
        if let Some(v) = bounded_u32(conn, key, max)? {
            source.insert(key.into(), int(v));
        }
    }
    if let Some(bytes) = conn.get("max_inflight_bytes").and_then(serde_json::Value::as_u64) {
        let bytes = i64::try_from(bytes).map_err(|_| invalid("max_inflight_bytes is too large"))?;
        source.insert("max_inflight_bytes".into(), toml::Value::Integer(bytes));
    }
    // Lookups leave on the `lookups` output (not consumed; see LOOKUPS_POLICY).
    source.insert("route_lookups".into(), true.into());

    // Hold every message until its batch is delivered (the fork warns and
    // deletes on dispatch without this).
    let mut acknowledgements = toml::Table::new();
    acknowledgements.insert("enabled".into(), true.into());
    source.insert("acknowledgements".into(), toml::Value::Table(acknowledgements));
    // The raw line in `.message`: the Falcon parser parses it itself.
    let mut decoding = toml::Table::new();
    decoding.insert("codec".into(), "bytes".into());
    source.insert("decoding".into(), toml::Value::Table(decoding));

    if let Some(auth) = SourceConfigService::aws_auth_table(creds, &region, source_name) {
        source.insert("auth".into(), toml::Value::Table(auth));
    }
    Ok(source)
}

#[cfg(test)]
#[path = "crowdstrike_fdr_tests.rs"]
mod tests;
