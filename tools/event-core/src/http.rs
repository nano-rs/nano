//! HTTP send functions for Vector ingestion

use anyhow::Result;
use reqwest::Client;
use tokio::time::Duration as TokioDuration;
use tracing::warn;

use crate::event::Event;

/// Send a single event as JSON POST
pub async fn send_event(
    client: &Client,
    url: &str,
    event: &Event,
    token: Option<&str>,
) -> Result<()> {
    let mut req = client
        .post(url)
        .header("Content-Type", "application/json")
        .header("X-Source-Type", &event.source_type)
        .json(event);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

/// Send a single source_type group as NDJSON with the correct X-Source-Type header.
async fn send_ndjson_group(
    client: &Client,
    url: &str,
    source_type: &str,
    events: &[&Event],
    token: Option<&str>,
) -> Result<()> {
    let body: String = events
        .iter()
        .map(|e| serde_json::to_string(e).unwrap())
        .collect::<Vec<_>>()
        .join("\n");

    let mut req = client
        .post(url)
        .header("Content-Type", "application/x-ndjson")
        .header("X-Source-Type", source_type)
        .body(body);

    if let Some(t) = token {
        req = req.bearer_auth(t);
    }
    req.send().await?.error_for_status()?;
    Ok(())
}

/// Send a single source_type group with exponential backoff retry.
async fn send_ndjson_group_with_retry(
    client: &Client,
    url: &str,
    source_type: &str,
    events: &[&Event],
    token: Option<&str>,
    max_retries: u32,
) -> Result<()> {
    let mut last_err = None;
    for attempt in 0..=max_retries {
        if attempt > 0 {
            let backoff = TokioDuration::from_millis(500 * 2u64.pow(attempt - 1));
            warn!(
                "[{}] Retry {}/{} after {:?}",
                source_type, attempt, max_retries, backoff
            );
            tokio::time::sleep(backoff).await;
        }
        match send_ndjson_group(client, url, source_type, events, token).await {
            Ok(()) => return Ok(()),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

/// Send multiple events as NDJSON, grouped by source_type.
pub async fn send_batch(
    client: &Client,
    url: &str,
    events: &[Event],
    token: Option<&str>,
) -> Result<()> {
    let mut grouped: std::collections::HashMap<&str, Vec<&Event>> =
        std::collections::HashMap::new();
    for event in events {
        grouped.entry(&event.source_type).or_default().push(event);
    }

    for (source_type, group) in &grouped {
        send_ndjson_group(client, url, source_type, group, token).await?;
    }
    Ok(())
}

/// Send batch with per-group retry. Each source_type group is retried independently
/// so a transient failure on one group doesn't re-send groups that already succeeded.
pub async fn send_batch_with_retry(
    client: &Client,
    url: &str,
    events: &[Event],
    token: Option<&str>,
    max_retries: u32,
) -> Result<()> {
    let mut grouped: std::collections::HashMap<&str, Vec<&Event>> =
        std::collections::HashMap::new();
    for event in events {
        grouped.entry(&event.source_type).or_default().push(event);
    }

    for (source_type, group) in &grouped {
        send_ndjson_group_with_retry(client, url, source_type, group, token, max_retries).await?;
    }
    Ok(())
}
