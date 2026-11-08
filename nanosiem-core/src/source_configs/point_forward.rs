// SPDX-License-Identifier: AGPL-3.0-or-later

//! Point-forward for queue / subscription pull sources (NAN-4914 phase 1).
//!
//! A new `aws_s3`, `aws_sqs` or `gcp_pubsub` source config starts at current
//! activity: whatever the queue or subscription already held before the
//! source config existed is acknowledged (deleted / acked) and not ingested.
//! Kafka already starts at `auto_offset_reset = "latest"` and Event Hubs at
//! `start_position = "latest"`, so neither needs the guard.
//!
//! The guard is a Vector `filter` transform between the source and its
//! routing transform. It dates an event by the time the cloud accepted it,
//! never by "now", and compares against the source config's `created_at`
//! minus a grace window, so clock skew between PostgreSQL and the cloud never
//! skips a message sent just after the source was connected, and a late but
//! new event (a slow queue, a Vector restart) is still ingested:
//!
//! | source       | event time                                                    |
//! |--------------|---------------------------------------------------------------|
//! | `aws_sqs`    | `.timestamp` = the SQS `SentTimestamp`                        |
//! | `gcp_pubsub` | `.timestamp` = the message `publish_time`                     |
//! | `aws_s3`     | `.s3_event_time` (the S3 notification `eventTime`) when the   |
//! |              | Vector build adds it, else `.timestamp` (object LastModified) |
//!
//! An event with no usable time passes (fail-open: never skip what cannot be
//! dated). `connection_config.include_backlog = true` disables the guard for
//! a source whose backlog the customer does want.

use super::service::SourceConfigServiceError;
use super::types::SourceConfigurationWithRules;

/// An event is backlog only when it is older than the source's creation by
/// more than this (5 minutes; the same grace main's hosted pull used).
pub(crate) const BACKLOG_CUTOFF_GRACE_MS: i64 = 300_000;

/// `connection_config` key that opts a source out of the guard.
pub(crate) const INCLUDE_BACKLOG_KEY: &str = "include_backlog";

/// Suffix of the guard transform: `<safe_name>_point_forward`.
pub(crate) const POINT_FORWARD_SUFFIX: &str = "_point_forward";

/// Config types the guard applies to.
pub(crate) fn applies_to(config_type: &str) -> bool {
    matches!(config_type, "aws_s3" | "aws_sqs" | "gcp_pubsub")
}

/// `include_backlog`, when present, must be a boolean.
pub(crate) fn validate_conn(
    config_type: &str,
    conn: &serde_json::Value,
) -> Result<(), SourceConfigServiceError> {
    match conn.get(INCLUDE_BACKLOG_KEY) {
        None | Some(serde_json::Value::Null) | Some(serde_json::Value::Bool(_)) => Ok(()),
        Some(_) => Err(SourceConfigServiceError::InvalidConfig(format!(
            "{config_type} connection_config.{INCLUDE_BACKLOG_KEY} must be true or false"
        ))),
    }
}

/// The cutoff (unix ms) below which an event is skipped backlog, or `None`
/// when the guard does not apply to this config.
pub(crate) fn cutoff_unix_ms(config: &SourceConfigurationWithRules) -> Option<i64> {
    let c = &config.config;
    if !applies_to(&c.config_type) {
        return None;
    }
    let include_backlog = c
        .connection_config
        .get(INCLUDE_BACKLOG_KEY)
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if include_backlog {
        return None;
    }
    Some(
        c.created_at
            .timestamp_millis()
            .saturating_sub(BACKLOG_CUTOFF_GRACE_MS),
    )
}

/// The VRL that binds `nano_pull_sent` / `nano_pull_sent_error` for a config
/// type. `timestamp()` accepts only a timestamp value, so an object metadata
/// string named `s3_event_time` is never trusted.
fn send_time_vrl(config_type: &str) -> &'static str {
    match config_type {
        "aws_s3" => concat!(
            "nano_pull_sent, nano_pull_sent_error = timestamp(.s3_event_time)\n",
            "if nano_pull_sent_error != null {\n",
            "  nano_pull_sent, nano_pull_sent_error = timestamp(.timestamp)\n",
            "}\n",
        ),
        _ => "nano_pull_sent, nano_pull_sent_error = timestamp(.timestamp)\n",
    }
}

/// The `[transforms.<safe>_point_forward]` TOML block, reading from
/// `source_name`.
pub(crate) fn render_filter(
    transform_name: &str,
    source_name: &str,
    config_type: &str,
    cutoff_unix_ms: i64,
) -> String {
    let condition = format!(
        "# NAN-4914: point-forward. Skip (ack, never ingest) what the queue or\n\
         # subscription held before this source config existed (cutoff = created_at\n\
         # minus {BACKLOG_CUTOFF_GRACE_MS} ms grace). Undatable events pass.\n\
         {}\
         nano_pull_sent_error != null || to_unix_timestamp(nano_pull_sent, unit: \"milliseconds\") >= {cutoff_unix_ms}\n",
        send_time_vrl(config_type),
    );
    let mut transform = toml::Table::new();
    transform.insert("type".into(), "filter".into());
    transform.insert(
        "inputs".into(),
        toml::Value::Array(vec![toml::Value::String(source_name.to_string())]),
    );
    transform.insert("condition".into(), toml::Value::String(condition));
    let mut transforms = toml::Table::new();
    transforms.insert(transform_name.to_string(), toml::Value::Table(transform));
    let mut root = toml::Table::new();
    root.insert("transforms".to_string(), toml::Value::Table(transforms));
    toml::to_string(&root).expect("point-forward filter TOML must serialize")
}
