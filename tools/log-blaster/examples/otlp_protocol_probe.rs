// SPDX-License-Identifier: AGPL-3.0-or-later

use anyhow::{bail, Context, Result};
use chrono::Utc;
use event_core::http::{send_otlp_with_retry, OtlpSignal, Transport};
use reqwest::header::{HeaderMap, HeaderValue};
use serde_json::json;

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let base_url = args
        .next()
        .context("usage: otlp_protocol_probe <base-url> <marker>")?;
    let marker = args
        .next()
        .context("usage: otlp_protocol_probe <base-url> <marker>")?;
    if args.next().is_some() {
        bail!("usage: otlp_protocol_probe <base-url> <marker>");
    }
    if marker.is_empty()
        || marker.len() > 160
        || !marker
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("marker must be 1-160 URL-safe ASCII characters");
    }

    let token = std::env::var("VECTOR_AUTH_TOKEN")
        .context("VECTOR_AUTH_TOKEN must be set without command-line exposure")?;
    if token.is_empty() {
        bail!("VECTOR_AUTH_TOKEN must not be empty");
    }
    let idempotency_key = std::env::var("NANO_IDEMPOTENCY_KEY")
        .context("NANO_IDEMPOTENCY_KEY must be set without command-line exposure")?;
    if !(8..=128).contains(&idempotency_key.len())
        || !idempotency_key.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'~' | b'-'))
        })
    {
        bail!("NANO_IDEMPOTENCY_KEY must satisfy the hosted-ingress key contract");
    }

    let timestamp_nanos = match std::env::var("NANO_OTLP_TIMESTAMP_NANOS") {
        Ok(value)
            if !value.is_empty()
                && value.len() <= 20
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value
        }
        Ok(_) => bail!("NANO_OTLP_TIMESTAMP_NANOS must be a 1-20 digit timestamp"),
        Err(std::env::VarError::NotPresent) => Utc::now()
            .timestamp_nanos_opt()
            .context("current timestamp cannot be represented in nanoseconds")?
            .to_string(),
        Err(error) => return Err(error).context("read NANO_OTLP_TIMESTAMP_NANOS"),
    };
    let record = json!({
        "timeUnixNano": timestamp_nanos.clone(),
        "observedTimeUnixNano": timestamp_nanos,
        "severityNumber": 9,
        "severityText": "INFO",
        "body": { "stringValue": format!("NAN2361_CF_OTLP_PROTOCOL_PROBE {marker}") },
        "attributes": [
            { "key": "nan2361.run", "value": { "stringValue": marker } }
        ],
        "resource": { "attributes": [
            { "key": "service.name", "value": { "stringValue": "nan2361-cloudflare-probe" } }
        ] }
    });
    let transport = Transport::OtlpHttp {
        base_url,
        token: Some(token),
    };
    let mut default_headers = HeaderMap::new();
    default_headers.insert(
        "idempotency-key",
        HeaderValue::from_str(&idempotency_key).context("build idempotency header")?,
    );
    let client = reqwest::Client::builder()
        .default_headers(default_headers)
        .timeout(std::time::Duration::from_secs(45))
        .build()
        .context("build OTLP protocol probe client")?;

    send_otlp_with_retry(&client, &transport, OtlpSignal::Logs, &[record], 0)
        .await
        .context("send one OTLP/HTTP protobuf log")?;
    println!(
        "{}",
        json!({
            "sent": true,
            "encoding": "application/x-protobuf",
            "stable_idempotency_key_supplied": true,
        })
    );
    Ok(())
}
