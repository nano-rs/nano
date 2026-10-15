// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{ensure, Result};
use event_core::{
    event::Event,
    http::{send_hec_group_observed, send_vector_group_observed, RetryPolicy, Transport},
};
use parking_lot::Mutex;
use reqwest::Client;

use crate::{spike, Args, HomogeneousBlastSource, HOMOGENEOUS_BLAST_SOURCE_CYCLE};

pub const SOURCES: [&str; 5] = [
    "windows_sysmon",
    "windows_event",
    "conduit_proxy",
    "apache_http_server",
    "aws_cloudtrail",
];

fn canonical_source(source: &str) -> &str {
    if source == "apache_access" {
        "apache_http_server"
    } else {
        source
    }
}

#[derive(Clone, Default)]
pub struct SourceConfig {
    tokens: BTreeMap<String, String>,
    idempotency_key_prefix: Option<String>,
    pub cycle: Vec<usize>,
    pub configured: bool,
}

impl SourceConfig {
    pub fn has_idempotency_prefix(&self) -> bool {
        self.idempotency_key_prefix.is_some()
    }

    pub fn resolve(
        args: &mut Args,
        env_tokens: Option<&str>,
        fallback: Option<String>,
    ) -> Result<Self> {
        let mut config = Self {
            idempotency_key_prefix: args.idempotency_key_prefix.clone(),
            ..Self::default()
        };
        // CLI entries override environment entries for the same source.
        for entry in env_tokens
            .into_iter()
            .flat_map(|s| s.split(','))
            .chain(args.source_token.iter().map(String::as_str))
        {
            let (source, token) = entry
                .split_once('=')
                .ok_or_else(|| anyhow::anyhow!("source tokens must use source_type=token"))?;
            let source = canonical_source(source);
            ensure!(
                SOURCES.contains(&source),
                "unknown source type in source tokens"
            );
            ensure!(!token.trim().is_empty(), "source token must not be empty");
            ensure!(
                reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")).is_ok(),
                "invalid source token header"
            );
            config.tokens.insert(source.to_string(), token.to_string());
        }
        config.configured = !config.tokens.is_empty() || !args.sources.is_empty();
        if config.configured {
            ensure!(
                args.blast
                    && args.tenzir.is_none()
                    && !args.otlp
                    && !args.spike
                    && !args.seed_identities,
                "--source-token/SOURCE_TOKENS and --sources require Vector or HEC blast mode"
            );
            for source in &args.sources {
                ensure!(
                    SOURCES.contains(&canonical_source(source)),
                    "unknown source type in --sources: {source}"
                );
            }
        }
        args.token = fallback.filter(|t| !t.trim().is_empty());
        if config.tokens.is_empty() && args.token.is_none() {
            args.token = Some("nanosiem-default-token".to_string());
        }
        let mut enabled = [false; 5];
        for (i, source) in SOURCES.iter().enumerate() {
            if !args.sources.is_empty()
                && !args.sources.iter().any(|s| canonical_source(s) == *source)
            {
                continue;
            }
            enabled[i] = config.token(source, args.token.as_deref()).is_some();
            if !enabled[i] {
                tracing::warn!("Skipping source {source}: no credential configured");
            }
        }
        ensure!(
            enabled.iter().any(|e| *e),
            "no source in the selected mix has a credential"
        );
        config.cycle = HOMOGENEOUS_BLAST_SOURCE_CYCLE
            .iter()
            .enumerate()
            .filter_map(|(i, source)| {
                let index = match source {
                    HomogeneousBlastSource::Sysmon => 0,
                    HomogeneousBlastSource::WindowsEvent => 1,
                    HomogeneousBlastSource::Proxy => 2,
                    HomogeneousBlastSource::Apache => 3,
                    HomogeneousBlastSource::CloudTrail => 4,
                };
                enabled[index].then_some(i)
            })
            .collect();
        args.vector_source_homogeneous_batches |= !args.hec && !config.tokens.is_empty();
        Ok(config)
    }

    fn token<'a>(&'a self, source: &str, fallback: Option<&'a str>) -> Option<&'a str> {
        self.tokens
            .get(canonical_source(source))
            .map(String::as_str)
            .or(fallback)
    }

    pub fn mix(&self) -> spike::SourceMix {
        let mut mix = spike::SourceMix::default();
        for index in &self.cycle {
            let one = crate::homogeneous_blast_mix(*index);
            mix.sysmon += one.sysmon;
            mix.winevt += one.winevt;
            mix.proxy += one.proxy;
            mix.apache += one.apache;
            mix.cloudtrail += one.cloudtrail;
        }
        mix.normalized()
    }
}

/// Per-source event accounting. NAN-2988: `accepted` includes `retried`
/// (events the receiver shed or timed out at least once and then accepted on a
/// retry of the identical request). `refused`, `failed` and `rejected` are
/// events the blaster gave up on, i.e. really lost: `refused` when the last
/// attempt was a retryable status (the retry limit or deadline ran out),
/// `failed` when it was a network error, `rejected` for a permanent 4xx.
/// `network_errors` and `statuses` count attempts, not events.
#[derive(Default, Debug)]
pub struct SourceCounts {
    sent: u64,
    accepted: u64,
    retried: u64,
    refused: u64,
    failed: u64,
    rejected: u64,
    network_errors: u64,
    statuses: BTreeMap<u16, u64>,
}

impl SourceCounts {
    /// Events given up on (never accepted).
    pub fn lost(&self) -> u64 {
        self.refused + self.failed + self.rejected
    }
}

pub type Accounting = Arc<Mutex<BTreeMap<String, SourceCounts>>>;

pub fn summary(stats: &Accounting) -> String {
    stats
        .lock()
        .iter()
        .map(|(source, s)| {
            format!(
                "{source}:sent={} accepted={} retried={} lost={} refused={} failed={} rejected={} network_errors={} http={:?}",
                s.sent,
                s.accepted,
                s.retried,
                s.lost(),
                s.refused,
                s.failed,
                s.rejected,
                s.network_errors,
                s.statuses
            )
        })
        .collect::<Vec<_>>()
        .join(" | ")
}

pub async fn send_batch(
    client: &Client,
    transport: &Transport,
    batch: Vec<Event>,
    policy: RetryPolicy,
    config: &SourceConfig,
    stats: &Accounting,
) -> u64 {
    let mut groups: BTreeMap<String, Vec<Event>> = BTreeMap::new();
    for mut event in batch {
        // Hosted source mode: the credential is issued for the enrolled slug
        // (`apache_access`) and the Worker's identity check rejects any other
        // name on both lanes, so send the enrolled slug regardless of transport.
        if config.configured && canonical_source(&event.source_type) == "apache_http_server" {
            event.source_type = "apache_access".to_string();
        }
        groups
            .entry(event.source_type.clone())
            .or_default()
            .push(event);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for (source, events) in groups {
        let mut transport = transport.clone();
        if let Transport::Vector { token, .. } | Transport::Hec { token, .. } = &mut transport {
            *token = config.token(&source, token.as_deref()).map(str::to_string);
        }
        let prefix = config.idempotency_key_prefix.clone();
        let client = client.clone();
        let stats = stats.clone();
        tasks.spawn(async move {
            let count = events.len() as u64;
            stats.lock().entry(source.clone()).or_default().sent += count;
            let refs: Vec<_> = events.iter().collect();
            let observe = |status: Option<reqwest::StatusCode>| {
                let mut stats = stats.lock();
                let entry = stats.entry(source.clone()).or_default();
                if let Some(status) = status {
                    *entry.statuses.entry(status.as_u16()).or_default() += 1;
                } else {
                    entry.network_errors += 1;
                }
            };
            let result = if matches!(transport, Transport::Hec { .. }) {
                send_hec_group_observed(
                    &client,
                    &transport,
                    &refs,
                    policy,
                    prefix.as_deref(),
                    observe,
                )
                .await
            } else {
                send_vector_group_observed(&client, &transport, &source, &refs, policy, observe)
                    .await
            };
            let mut stats = stats.lock();
            let entry = stats.entry(source.clone()).or_default();
            match result {
                Ok(report) => {
                    entry.accepted += count;
                    if report.retried() {
                        entry.retried += count;
                    }
                    count
                }
                Err(failure) => {
                    if failure.permanent {
                        entry.rejected += count;
                    } else if failure.status.is_some() {
                        entry.refused += count;
                    } else {
                        entry.failed += count;
                    }
                    tracing::error!("Source {source}: batch of {count} events lost: {failure}");
                    0
                }
            }
        });
    }
    let mut accepted = 0;
    while let Some(result) = tasks.join_next().await {
        accepted += result.expect("source send task panicked");
    }
    accepted
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn tokens_override_env_and_fallback_without_losing_equals() {
        let mut args = Args::try_parse_from([
            "log-blaster",
            "--blast",
            "--source-token",
            "windows_sysmon=cli==",
        ])
        .unwrap();
        let config = SourceConfig::resolve(
            &mut args,
            Some("windows_sysmon=env,windows_event=other"),
            Some("fallback".into()),
        )
        .unwrap();
        assert_eq!(
            config.token("windows_sysmon", args.token.as_deref()),
            Some("cli==")
        );
        assert_eq!(
            config.token("windows_event", args.token.as_deref()),
            Some("other")
        );
        assert_eq!(
            config.token("conduit_proxy", args.token.as_deref()),
            Some("fallback")
        );
        assert_eq!(config.cycle.len(), 50);
        assert!(args.vector_source_homogeneous_batches);
    }

    #[test]
    fn env_tokens_imply_homogeneous_and_skip_uncredentialed_sources() {
        let mut args = Args::try_parse_from(["log-blaster", "--blast"]).unwrap();
        let config = SourceConfig::resolve(
            &mut args,
            Some("windows_event=one,apache_http_server=two"),
            None,
        )
        .unwrap();
        assert!(args.vector_source_homogeneous_batches);
        assert!(args.token.is_none());
        assert_eq!(config.cycle.len(), 10);
        let mix = config.mix();
        assert_eq!(mix.winevt, 0.5);
        assert_eq!(mix.apache, 0.5);
        assert_eq!(mix.sysmon + mix.proxy + mix.cloudtrail, 0.0);
    }

    #[test]
    fn explicit_sources_restrict_even_with_fallback() {
        let mut args = Args::try_parse_from([
            "log-blaster",
            "--blast",
            "--sources",
            "aws_cloudtrail,conduit_proxy",
        ])
        .unwrap();
        let config = SourceConfig::resolve(&mut args, None, Some("fallback".into())).unwrap();
        assert_eq!(config.cycle.len(), 10);
        assert_eq!(config.mix().proxy, 0.6);
        assert_eq!(config.mix().cloudtrail, 0.4);
        assert!(!args.vector_source_homogeneous_batches);
    }

    #[test]
    fn no_credential_for_selected_mix_fails() {
        let mut args =
            Args::try_parse_from(["log-blaster", "--blast", "--sources", "windows_event"]).unwrap();
        assert!(SourceConfig::resolve(&mut args, Some("windows_sysmon=one"), None).is_err());
    }

    #[test]
    fn invalid_tokens_do_not_echo_secrets() {
        for input in [
            "secret",
            "unknown=secret",
            "windows_sysmon=",
            "windows_sysmon=secret\n",
        ] {
            let mut args = Args::try_parse_from(["log-blaster", "--blast"]).unwrap();
            let error = SourceConfig::resolve(&mut args, Some(input), None)
                .err()
                .unwrap();
            assert!(!error.to_string().contains("secret"));
        }
    }

    #[test]
    fn hec_accepts_apache_aliases_and_sources_with_fallback() {
        for alias in ["apache_access", "apache_http_server"] {
            let mut args = Args::try_parse_from([
                "log-blaster",
                "--blast",
                "--hec",
                "--sources",
                alias,
                "--source-token",
                &format!("{alias}=cli"),
            ])
            .unwrap();
            let config = SourceConfig::resolve(&mut args, Some("apache_access=env"), None).unwrap();
            assert_eq!(config.token("apache_access", None), Some("cli"));
            assert_eq!(config.mix().apache, 1.0);
            assert!(!args.vector_source_homogeneous_batches);
        }
        let mut args = Args::try_parse_from([
            "log-blaster",
            "--blast",
            "--hec",
            "--sources",
            "apache_access",
        ])
        .unwrap();
        let config = SourceConfig::resolve(&mut args, None, Some("fallback".into())).unwrap();
        assert_eq!(config.mix().apache, 1.0);
        assert_eq!(
            config.token("apache_access", args.token.as_deref()),
            Some("fallback")
        );
        let mut args = Args::try_parse_from(["log-blaster", "--hec"]).unwrap();
        assert!(SourceConfig::resolve(&mut args, Some("apache_access=env"), None).is_err());
    }

    #[test]
    fn other_modes_reject_source_configuration() {
        for mode in ["--tenzir", "--otlp", "--seed-identities"] {
            let mut args = Args::try_parse_from(["log-blaster", "--blast", mode]).unwrap();
            assert!(SourceConfig::resolve(&mut args, Some("windows_sysmon=one"), None).is_err());
        }
        let mut args = Args::try_parse_from(["log-blaster", "--blast"]).unwrap();
        args.spike = true;
        assert!(SourceConfig::resolve(&mut args, Some("windows_sysmon=one"), None).is_err());
    }

    #[tokio::test]
    async fn mixed_responses_count_partial_success_and_select_wire_tokens() {
        check_mixed_responses(false).await;
    }

    #[tokio::test]
    async fn hec_ack_and_refusal_use_source_credentials_and_stable_batch_identity() {
        check_mixed_responses(true).await;
    }

    async fn check_mixed_responses(hec: bool) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            let mut windows_event_attempts = 0;
            for _ in 0..3 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut data = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&data);
                    if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                        let len: usize = headers
                            .lines()
                            .find_map(|line| {
                                line.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(str::to_string)
                            })
                            .unwrap()
                            .parse()
                            .unwrap();
                        if body.len() >= len {
                            break;
                        }
                    }
                }
                let request = String::from_utf8(data).unwrap().to_lowercase();
                let status = if hec {
                    assert!(request.starts_with("post /services/collector/event http/1.1"));
                    assert!(request.contains("content-type: application/json"));
                    assert!(!request.contains("x-source-type:"));
                    let channel = request
                        .lines()
                        .find_map(|l| l.strip_prefix("x-splunk-request-channel: "))
                        .unwrap();
                    assert_eq!(channel.len(), 36);
                    assert!(channel.chars().enumerate().all(|(i, c)| {
                        if [8, 13, 18, 23].contains(&i) {
                            c == '-'
                        } else {
                            c.is_ascii_hexdigit()
                        }
                    }));
                    assert!(request.contains(&format!("idempotency-key: test-{channel}")));
                    let body = request.split_once("\r\n\r\n").unwrap().1;
                    let envelopes: Vec<serde_json::Value> = body
                        .lines()
                        .map(|line| serde_json::from_str(line).unwrap())
                        .collect();
                    let envelope = &envelopes[0];
                    assert!(envelopes.iter().all(|e| e == envelope));
                    assert_eq!(
                        envelopes.len(),
                        if envelope["source"] == "apache_access" {
                            2
                        } else {
                            1
                        }
                    );
                    assert_eq!(envelope["event"], "test");
                    assert_eq!(envelope["time"], 1789689600.0);
                    assert_eq!(envelope["source"], envelope["sourcetype"]);
                    if envelope["source"] == "windows_event" {
                        assert!(request.contains("authorization: splunk fallback"));
                        windows_event_attempts += 1;
                        // NAN-2988: shed once (retried), then a permanent refusal.
                        if windows_event_attempts == 1 {
                            "503 Service Unavailable"
                        } else {
                            "401 Unauthorized"
                        }
                    } else {
                        assert_eq!(envelope["source"], "apache_access");
                        assert!(request.contains("authorization: splunk apache-secret"));
                        "200 OK"
                    }
                } else if request.contains("x-source-type: windows_event") {
                    assert!(request.contains("authorization: bearer fallback"));
                    windows_event_attempts += 1;
                    if windows_event_attempts == 1 {
                        "503 Service Unavailable"
                    } else {
                        "401 Unauthorized"
                    }
                } else {
                    assert!(request.contains("x-source-type: apache_access"));
                    assert!(request.contains("authorization: bearer apache-secret"));
                    assert!(request.contains("\"source_type\":\"apache_access\""));
                    "202 Accepted"
                };
                let body = if hec && status == "200 OK" {
                    r#"{"text":"Success","code":0,"ackId":42}"#
                } else {
                    ""
                };
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\nRetry-After: 0\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                requests.push(request);
            }
            requests
        });
        let mut args = Args::try_parse_from(["log-blaster", "--blast"]).unwrap();
        let config = SourceConfig::resolve(
            &mut args,
            Some("apache_http_server=apache-secret"),
            Some("fallback".into()),
        )
        .unwrap();
        let transport = if hec {
            Transport::new_hec(format!("{url}/services/collector/event"), args.token)
        } else {
            Transport::Vector {
                url,
                token: args.token,
                idempotency_key_prefix: Some("test".into()),
            }
        };
        let mut config = config;
        config.idempotency_key_prefix = Some("test".into());
        let batch = ["apache_access", "apache_access", "windows_event"]
            .into_iter()
            .map(|source| Event {
                source_type: source.into(),
                message: "test".into(),
                timestamp: "2026-09-18T00:00:00Z".into(),
                display_label: String::new(),
            })
            .collect();
        let stats = Accounting::default();
        let client = Client::builder().no_proxy().build().unwrap();
        assert_eq!(
            send_batch(
                &client,
                &transport,
                batch,
                RetryPolicy::bounded(1),
                &config,
                &stats
            )
            .await,
            2
        );
        let requests = server.await.unwrap();
        let keys: Vec<_> = requests
            .iter()
            .filter(|r| r.contains("windows_event"))
            .map(|r| {
                r.lines()
                    .find(|l| l.starts_with("idempotency-key:"))
                    .unwrap()
            })
            .collect();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], keys[1]);
        if hec {
            let channels: std::collections::BTreeSet<_> = requests
                .iter()
                .filter_map(|r| {
                    r.lines()
                        .find(|l| l.starts_with("x-splunk-request-channel:"))
                })
                .collect();
            assert_eq!(channels.len(), 2, "each logical batch gets its own channel");
            let retries: Vec<_> = requests
                .iter()
                .filter(|r| r.contains("windows_event"))
                .collect();
            assert_eq!(retries[0], retries[1], "retry preserves the entire request");
            assert!(summary(&stats).contains(
                "apache_access:sent=2 accepted=2 retried=0 lost=0 refused=0 failed=0 rejected=0"
            ));
        }
        let stats = stats.lock();
        // Both lanes account under the enrolled slug in source-configured mode.
        let apache = "apache_access";
        assert_eq!(stats[apache].accepted, 2);
        assert_eq!(stats[apache].sent, 2);
        assert_eq!(stats[apache].statuses[&if hec { 200 } else { 202 }], 1);
        assert_eq!(stats["windows_event"].sent, 1);
        // A permanent 4xx is dropped at once and counted lost as rejected.
        assert_eq!(stats["windows_event"].rejected, 1);
        assert_eq!(stats["windows_event"].refused, 0);
        assert_eq!(stats["windows_event"].lost(), 1);
        assert_eq!(stats["windows_event"].statuses[&503], 1);
        assert_eq!(stats["windows_event"].statuses[&401], 1);
    }

    /// A scripted HEC receiver: answers each connection with the next
    /// (status line, Retry-After) and records (arrival, request) pairs.
    pub(crate) async fn scripted_receiver(
        script: Vec<(&'static str, Option<&'static str>)>,
    ) -> (
        String,
        tokio::task::JoinHandle<Vec<(tokio::time::Instant, String)>>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!(
            "http://{}/services/collector/event",
            listener.local_addr().unwrap()
        );
        let server = tokio::spawn(async move {
            let mut seen = Vec::new();
            for (status, retry_after) in script {
                let (mut socket, _) = listener.accept().await.unwrap();
                let arrived = tokio::time::Instant::now();
                let mut data = Vec::new();
                let mut buf = [0; 4096];
                loop {
                    let n = socket.read(&mut buf).await.unwrap();
                    assert!(n > 0);
                    data.extend_from_slice(&buf[..n]);
                    let text = String::from_utf8_lossy(&data);
                    if let Some((headers, body)) = text.split_once("\r\n\r\n") {
                        let len: usize = headers
                            .lines()
                            .find_map(|l| {
                                l.to_lowercase()
                                    .strip_prefix("content-length: ")
                                    .map(str::to_string)
                            })
                            .unwrap()
                            .parse()
                            .unwrap();
                        if body.len() >= len {
                            break;
                        }
                    }
                }
                let body = if status.starts_with("200") {
                    r#"{"text":"Success","code":0}"#
                } else {
                    r#"{"text":"Server is busy","code":9}"#
                };
                let retry = retry_after.map_or(String::new(), |v| format!("Retry-After: {v}\r\n"));
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 {status}\r\n{retry}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
                seen.push((arrived, String::from_utf8(data).unwrap().to_lowercase()));
            }
            seen
        });
        (url, server)
    }

    fn hec_fixture(url: String) -> (Transport, SourceConfig, Vec<Event>) {
        let mut args = Args::try_parse_from(["log-blaster", "--blast"]).unwrap();
        let config =
            SourceConfig::resolve(&mut args, Some("windows_sysmon=sysmon-secret"), None).unwrap();
        let transport = Transport::new_hec(url, args.token);
        let batch = (0..3)
            .map(|i| Event {
                source_type: "windows_sysmon".into(),
                message: format!("event {i}"),
                timestamp: "2026-09-28T19:15:00Z".into(),
                display_label: String::new(),
            })
            .collect();
        (transport, config, batch)
    }

    fn header<'a>(request: &'a str, name: &str) -> &'a str {
        request
            .lines()
            .find_map(|l| l.strip_prefix(&format!("{name}: ")))
            .unwrap_or_else(|| panic!("missing {name}"))
    }

    /// NAN-2988: a shed batch is retried (same channel, key and body) after the
    /// receiver's Retry-After until accepted, and counted as retried, not lost.
    #[tokio::test]
    async fn shed_batches_retry_after_retry_after_until_accepted() {
        let (url, server) = scripted_receiver(vec![
            ("429 Too Many Requests", Some("1")),
            ("503 Service Unavailable", Some("0")),
            ("500 Internal Server Error", None),
            ("200 OK", None),
        ])
        .await;
        let (transport, config, batch) = hec_fixture(url);
        let stats = Accounting::default();
        let client = Client::builder().no_proxy().build().unwrap();
        let policy = RetryPolicy::until_accepted(Some(std::time::Duration::from_secs(60)));
        assert_eq!(
            send_batch(&client, &transport, batch, policy, &config, &stats).await,
            3
        );
        let seen = server.await.unwrap();
        assert_eq!(seen.len(), 4);
        let first = &seen[0].1;
        // Unkeyed retries can duplicate; the channel remains stable for HEC ACKs.
        assert!(!first.to_ascii_lowercase().contains("idempotency-key:"));
        assert!(!header(first, "x-splunk-request-channel").is_empty());
        for (_, request) in &seen[1..] {
            assert_eq!(request, first, "every retry is the identical request");
        }
        assert!(
            seen[1].0 - seen[0].0 >= std::time::Duration::from_millis(950),
            "Retry-After: 1 is honoured"
        );
        let stats = stats.lock();
        let sysmon = &stats["windows_sysmon"];
        assert_eq!(
            (sysmon.sent, sysmon.accepted, sysmon.retried, sysmon.lost()),
            (3, 3, 3, 0)
        );
        assert_eq!(sysmon.statuses[&429], 1);
        assert_eq!(sysmon.statuses[&503], 1);
        assert_eq!(sysmon.statuses[&500], 1);
        assert_eq!(sysmon.statuses[&200], 1);
    }

    /// NAN-2988: when the deadline runs out the batch is counted lost
    /// (refused), never silently accepted.
    #[tokio::test]
    async fn deadline_exhaustion_counts_the_batch_lost() {
        let (url, server) = scripted_receiver(vec![("503 Service Unavailable", Some("2"))]).await;
        let (transport, config, batch) = hec_fixture(url);
        let stats = Accounting::default();
        let client = Client::builder().no_proxy().build().unwrap();
        let policy = RetryPolicy::until_accepted(Some(std::time::Duration::from_secs(1)));
        assert_eq!(
            send_batch(&client, &transport, batch, policy, &config, &stats).await,
            0
        );
        assert_eq!(
            server.await.unwrap().len(),
            1,
            "a 2 s hint past a 1 s deadline is not retried"
        );
        let stats = stats.lock();
        let sysmon = &stats["windows_sysmon"];
        assert_eq!((sysmon.accepted, sysmon.refused, sysmon.lost()), (0, 3, 3));
    }
}
