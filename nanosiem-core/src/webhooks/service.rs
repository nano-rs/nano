// SPDX-License-Identifier: AGPL-3.0-or-later

//! Webhook Service
//!
//! Handles webhook delivery for alert events.
//! Fire-and-forget via tokio::spawn — never blocks the detection pipeline.

use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::source_scope_resolver::SourceScopeResolver;
use crate::inputlookup::{IpCidr, SsrfConfig, SsrfValidator};

use super::channels::{build_channel_body, ChannelType, FormatContext};
use super::models::*;
use super::repository::WebhookRepository;

type HmacSha256 = Hmac<Sha256>;

/// Maximum number of matched events included in the webhook payload
const MAX_MATCHED_EVENTS: usize = 10;

/// HTTP request timeout for webhook delivery
const DELIVERY_TIMEOUT_SECS: u64 = 10;

/// Maximum concurrent webhook deliveries (actual in-flight HTTP requests).
const MAX_CONCURRENT_DELIVERIES: usize = 20;

/// Upper bound on total outstanding delivery tasks (in-flight + queued-for-a-
/// permit). Each alert/case fans out one spawned task per subscribed webhook;
/// without a cap an alert storm (or a slow/black-hole endpoint holding the 20
/// concurrency permits) would accumulate unbounded tasks + cloned payloads and
/// can OOM. Beyond this cap deliveries are shed with a warning rather than
/// queued forever — webhooks are best-effort notifications.
const MAX_INFLIGHT_DELIVERIES: usize = 512;

/// Total delivery attempts (1 initial + retries) before giving up. Retryable
/// failures are transport errors, HTTP 5xx, and 429.
const MAX_DELIVERY_ATTEMPTS: u32 = 3;

/// Base backoff between delivery attempts; doubles each retry (0.5s, 1s).
const RETRY_BASE_DELAY_MS: u64 = 500;

/// Parse the `NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST` value — a comma-separated list
/// of CIDRs / bare IPs (e.g. `10.0.0.0/8, 192.168.5.0/24, 10.1.2.3`). Invalid
/// entries are logged and skipped rather than failing the whole subsystem, so
/// one typo can't take webhooks down. Pure (no env read) for testability.
pub(crate) fn parse_egress_allowlist(raw: &str) -> Vec<IpCidr> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter_map(|entry| match IpCidr::parse(entry) {
            Ok(c) => Some(c),
            Err(e) => {
                warn!("Ignoring invalid NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST entry '{entry}': {e}");
                None
            }
        })
        .collect()
}

/// Normalize a configured/env base into a scheme-qualified origin with no
/// trailing slash: `nano.example.com` → `https://nano.example.com`,
/// `http://host/` → `http://host`. Pure (no env read) for testability.
///
/// F-40: canonicalizes to a bare origin (`scheme://host[:port]`), stripping any
/// userinfo / path / query / fragment. This is the defense-in-depth read side:
/// a legacy DB row already holding a hostile value (e.g.
/// `https://nano.example.com@evil.example/phish?next=x#y`) is reduced to its
/// true origin here so it can't build first-party-looking deep links.
pub(crate) fn normalize_base_url(raw: &str) -> String {
    let trimmed = raw.trim().trim_end_matches('/');
    let with_scheme = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };
    // On a parse failure keep the scheme-qualified string; `ui_link` then
    // fails safe (returns None) rather than concatenating an unvalidated base.
    canonical_origin(&with_scheme).unwrap_or(with_scheme)
}

/// F-40: reduce a parsed http(s) URL to a bare origin string
/// (`scheme://host[:port]`), or `None` if it can't be parsed, uses a non-http(s)
/// scheme, or has no host. Inherently DROPS any userinfo, path, query, and
/// fragment — it only re-serializes scheme + host + explicit port.
pub(crate) fn canonical_origin(raw: &str) -> Option<String> {
    let url = url::Url::parse(raw.trim()).ok()?;
    if !matches!(url.scheme(), "http" | "https") {
        return None;
    }
    let host = url.host_str()?;
    let mut origin = format!("{}://{}", url.scheme(), host);
    if let Some(port) = url.port() {
        origin.push_str(&format!(":{port}"));
    }
    Some(origin)
}

/// F-40: validate a notification base URL is a *bare origin* and return its
/// canonical `scheme://host[:port]` form. Unlike [`canonical_origin`] (which
/// silently strips), this REJECTS (Err) a deceptive value — userinfo, a
/// non-root path, a query, or a fragment — so the write path can 400 instead of
/// storing a caller string that would build first-party-looking links resolving
/// to another host. Also rejects non-http(s) schemes and host-less URLs.
pub fn validate_base_origin(raw: &str) -> Result<String, String> {
    let url = url::Url::parse(raw.trim())
        .map_err(|_| "base_url must be a valid URL".to_string())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err("base_url must use http or https".to_string());
    }
    if !url.username().is_empty()
        || url.password().map(|p| !p.is_empty()).unwrap_or(false)
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
        || url.port() == Some(0)
    {
        return Err(
            "base_url must be a bare origin (scheme://host[:port]) with no user, path, query, or fragment"
                .to_string(),
        );
    }
    canonical_origin(&url.to_string()).ok_or_else(|| "base_url must include a host".to_string())
}

/// Hard cap on how many bytes of a receiver's response we read before dropping
/// the rest. A malicious/compromised endpoint must not be able to exhaust
/// memory by returning a huge body (the delivery-log truncation happens only
/// *after* the buffer, so the read itself must be bounded). 8 KiB comfortably
/// covers the 1 KiB we persist.
const RESPONSE_READ_CAP: usize = 8 * 1024;

#[derive(Clone)]
pub struct WebhookService {
    repo: WebhookRepository,
    /// Redacts restricted-source alert content at the webhook egress choke
    /// point (NAN-1800).
    ///
    /// ALWAYS `Some` in production: [`new`](Self::new) self-builds a resolver
    /// from the repository's pool, so redaction is live at every construction
    /// site. `None` is reachable only by constructing the struct directly in a
    /// test, and means "skip redaction entirely".
    ///
    /// NAN-2207: this doc previously claimed the service *could not* self-build
    /// a resolver and that egress redaction was therefore inert until a call
    /// site chained [`with_scope_resolver`](Self::with_scope_resolver). That was
    /// false — and load-bearing, because the only way to conclude "the
    /// redaction branch is dead code" is to believe it. Keep it accurate.
    scope_resolver: Option<SourceScopeResolver>,
    /// Gates actual in-flight HTTP requests.
    semaphore: Arc<Semaphore>,
    /// Bounds total outstanding delivery tasks (see `MAX_INFLIGHT_DELIVERIES`).
    /// A permit is taken before spawning; deliveries are shed when exhausted.
    inflight: Arc<Semaphore>,
}

impl WebhookService {
    pub fn new(repo: WebhookRepository) -> Self {
        // NOTE: the HTTP client is built per-delivery, not stored, because the
        // SSRF guard pins the connection to the target's validated IP(s) via
        // `resolve_to_addrs` (see `ssrf_checked_client`) — a shared client can't
        // be pinned to a per-URL address set. Redirects are disabled on every
        // client so there is no second, unvalidated hop.
        // Self-build the scope resolver from the repo's pool so restricted-source
        // redaction (NAN-1800) is active at every construction site. Its own
        // cache converges with other processes via the NAN-1807 version counter.
        let scope_resolver = Some(SourceScopeResolver::new(repo.pool()));
        Self {
            repo,
            scope_resolver,
            semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_DELIVERIES)),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_DELIVERIES)),
        }
    }

    /// Override the self-built [`SourceScopeResolver`] with a shared one
    /// (NAN-1800).
    ///
    /// Redaction is already active without this — [`new`](Self::new) builds a
    /// resolver from the repo's pool. Chaining this only swaps in an instance
    /// whose caches are shared with other consumers, which converges scope
    /// changes marginally faster than the NAN-1807 cross-process version poll.
    /// It has no production call site today.
    pub fn with_scope_resolver(mut self, resolver: SourceScopeResolver) -> Self {
        self.scope_resolver = Some(resolver);
        self
    }

    /// The SSRF validator used for BOTH the create-time URL check and the
    /// delivery-time re-resolve/pin. Single source of truth so the two can never
    /// diverge (a URL that passes at config time must be evaluated by identical
    /// rules at fire time). Delegates to the shared DNS-aware `SsrfValidator`
    /// (NAN-1369): loopback / private / CGNAT / link-local / cloud-metadata /
    /// scheme are all blocked. `allow_http` is on (webhook receivers are often
    /// plain-http); the instance's own hostname is blocked to keep the
    /// alert → webhook → alert self-reference loop guard.
    fn validator() -> SsrfValidator {
        let mut blocked_domains = vec!["localhost".to_string()];
        if let Ok(self_hostname) = std::env::var("NANOSIEM_HOSTNAME") {
            if !self_hostname.is_empty() {
                blocked_domains.push(self_hostname);
            }
        }

        // Internal-target egress controls (secure default: all private blocked).
        // Two knobs, most-scoped first:
        //   NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST — CIDRs/IPs that a webhook MAY
        //     reach even though they're private (e.g. "10.0.0.0/8,192.168.5.7").
        //     Preferred: it scopes egress to exactly the intended receivers
        //     (NAN-1633).
        //   NANOSIEM_WEBHOOK_ALLOW_PRIVATE=1 — legacy blanket opt-in that allows
        //     ALL private/loopback ranges. Kept for back-compat; the allowlist
        //     is the narrower, recommended replacement.
        // Either way, cloud-metadata, loopback, link-local, and the
        // `localhost` + self-hostname loop guard stay blocked (the allowlist
        // only rescues RFC1918 / CGNAT / IPv6-ULA; SsrfConfig upholds the rest).
        let allow_private = std::env::var("NANOSIEM_WEBHOOK_ALLOW_PRIVATE")
            .map(|v| matches!(v.as_str(), "1" | "true" | "TRUE"))
            .unwrap_or(false);
        let allowed_cidrs = std::env::var("NANOSIEM_WEBHOOK_EGRESS_ALLOWLIST")
            .ok()
            .map(|raw| parse_egress_allowlist(&raw))
            .unwrap_or_default();

        SsrfValidator::new(SsrfConfig {
            allow_http: true,
            blocked_domains,
            allow_private_networks: allow_private,
            allowed_cidrs,
            ..Default::default()
        })
    }

    /// Validate that a webhook URL is safe to call (not targeting internal
    /// services). Rejects private IPs, loopback, link-local (cloud metadata),
    /// cloud-metadata hostnames, self-referencing URLs, and non-HTTP schemes.
    /// Performs DNS resolution to catch rebinding at config time. This is the
    /// fast create/update UX check; `ssrf_checked_client` re-validates and pins
    /// again at delivery so a rebind after config-time can't get through.
    pub async fn validate_url(url: &str) -> Result<(), String> {
        Self::validator()
            .validate_with_dns(url)
            .await
            .map(|_| ())
            .map_err(|e| format!("Webhook URL rejected: {}", e))
    }

    /// Build a reqwest client whose connection is pinned to the validated,
    /// resolved IP(s) of `url` — the delivery-time SSRF guard (NAN-1546).
    ///
    /// Mirrors the synthetic runner: `validate_and_resolve` rejects bad schemes
    /// and blocked IP literals, then resolves the host and re-validates every
    /// resolved IP, returning the addrs to pin. We pin reqwest to exactly those
    /// via `resolve_to_addrs` so DNS can't be rebound to an internal IP between
    /// config-time validation and connect. Redirects are disabled so there is no
    /// second, unvalidated hop. Returns the rejection reason on block (recorded
    /// as the delivery failure).
    async fn ssrf_checked_client(url: &str) -> Result<reqwest::Client, String> {
        let (parsed, addrs) = Self::validator()
            .validate_and_resolve(url)
            .await
            .map_err(|e| format!("blocked by SSRF guard: {e}"))?;

        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(DELIVERY_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none());

        // IP-literal hosts return an empty Vec (reqwest dials the already-
        // validated literal). DNS-name hosts: pin reqwest to the pre-validated
        // addrs so DNS can't be rebound after validation.
        if !addrs.is_empty() {
            let host = parsed
                .host_str()
                .ok_or_else(|| "URL missing host".to_string())?;
            builder = builder.resolve_to_addrs(host, &addrs);
        }

        builder
            .build()
            .map_err(|e| format!("HTTP client build failed: {e}"))
    }

    /// Read at most `RESPONSE_READ_CAP` bytes of a receiver's response, then
    /// drop the rest. Bounds memory against a hostile endpoint returning a huge
    /// body — `reqwest::Response::text()`/`bytes()` would buffer it all first.
    async fn read_body_capped(mut response: reqwest::Response) -> String {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            if buf.len() >= RESPONSE_READ_CAP {
                break;
            }
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = RESPONSE_READ_CAP - buf.len();
                    let take = remaining.min(chunk.len());
                    buf.extend_from_slice(&chunk[..take]);
                    if take < chunk.len() {
                        break; // hit the cap mid-chunk; discard the remainder
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Resolve the external base origin (e.g. `https://nano.example.com`) for
    /// notification deep links. Resolution order (NAN-1790):
    ///   1. the admin-configured `system_settings.notification_base_url`
    ///   2. the `NANOSIEM_HOSTNAME` env var (as `https://<host>`; same source
    ///      the OIDC issuer uses)
    ///   3. `None` — deep links are omitted from payloads
    /// Returned without a trailing slash. Read once per fire so the deep link is
    /// consistent across all channels fanned out from a single alert. Public so
    /// the settings handler can surface the effective (resolved) base URL.
    pub async fn resolve_base_url(&self) -> Option<String> {
        // Prefer the DB setting; a DB error falls through to the env var rather
        // than dropping the link entirely.
        if let Ok(Some(configured)) = self.repo.notification_base_url().await {
            return Some(normalize_base_url(&configured));
        }
        std::env::var("NANOSIEM_HOSTNAME")
            .ok()
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
            .map(|h| normalize_base_url(&h))
    }

    /// Build a deep link back to a resource in the nano UI from a resolved
    /// `base` (see [`resolve_base_url`]), or `None` when no base is configured.
    /// `path` is the SPA route without a leading slash, e.g. `alerts/alert_…`.
    ///
    /// F-40: resolve `path` against `base` with proper URL joining instead of
    /// string concatenation, and return `None` on any parse error. Combined with
    /// the origin canonicalization in [`normalize_base_url`]/`validate_base_origin`,
    /// a hostile stored base can no longer produce first-party-looking links that
    /// resolve to an attacker host. `pub(crate)` so the join is unit-testable.
    pub(crate) fn ui_link(base: Option<&str>, path: &str) -> Option<String> {
        let base = base?;
        reqwest::Url::parse(base)
            .ok()
            .and_then(|u| u.join(path).ok())
            .map(|u| u.to_string())
    }

    /// Public, safe deep-link builder for durable notification producers.
    pub fn ui_link_public(base: Option<&str>, path: &str) -> Option<String> {
        Self::ui_link(base, path)
    }

    /// Should this alert's payload be redacted because it derives from a
    /// restricted source (NAN-1800)?
    ///
    /// Origin attribution comes from the stored `matched_events` blob: raw
    /// event rows carry `source_type`; aggregate rows carry the detection
    /// engine's trusted `_nano_source_types` annotation. Three regimes:
    ///
    /// - **No resolver wired** (`scope_resolver = None`): status-quo — no
    ///   redaction. Not a new leak; the construction site simply hasn't been
    ///   migrated to [`with_scope_resolver`](Self::with_scope_resolver) yet.
    /// - **Fully attributed blob**: redact iff ANY origin `source_type` is
    ///   restricted, per [`SourceScopeResolver::any_restricted`] (which is
    ///   fail-closed when the registry is unavailable).
    /// - **Unattributed blob** (notable results, empty array, non-array, or any
    ///   event missing both `source_type` and a trustworthy engine stamp): the
    ///   origin cannot be proven unrestricted, so FAIL CLOSED whenever any
    ///   restriction exists — redact if the registry is non-empty, and also
    ///   when the registry is unavailable. An empty registry (pre-feature)
    ///   never redacts unless the unresolved sentinel was still recovered.
    ///
    /// NAN-2207: an `audit` origin is NOT unconditionally redacted here (it
    /// still is for finding storage). NAN-2155 hard-wired it, which broke every
    /// SOAR integration built on an audit-sourced detection rule — the payload
    /// silently lost `matched_events` + `entity` while keeping
    /// `matched_event_count`, on deployments with no source scoping configured
    /// and therefore no RBAC boundary to protect. Audit evidence is redacted
    /// here iff an admin registered `audit` in `restricted_source_types`, via
    /// the ordinary registry branches below.
    async fn origin_restricted(&self, kind: &str, matched_events: &serde_json::Value) -> bool {
        let Some(resolver) = &self.scope_resolver else {
            return false;
        };
        // NAN-2227: observability alerts are not source-derived AT ALL. Their
        // `matched_events` is a producer-built descriptor of the monitor, series,
        // threshold and observed value — there is no ingested event in it and no
        // `source_type` to attribute. They nonetheless took the unattributed
        // fallback below and lost their payload on every deployment that had
        // configured ANY restricted source, which contradicted the alert ROW:
        // `distinct_source_types` stores `'{}'` for these, the value the read side
        // treats as "known not source-derived, visible to everyone". The webhook
        // and the alert disagreed about the same alert.
        //
        // `risk_notable` is deliberately NOT in this set: it maps to the SIEM
        // stream and is derived from the findings stream, so it CAN carry
        // restricted-origin entity data and must keep going through the checks.
        if matches!(kind, "metric_monitor" | "slo" | "synthetic") {
            return false;
        }
        let (source_types, fully_attributed) = origin_source_types(matched_events);
        // The unresolved sentinel wins before the completeness split. Otherwise
        // a mixed batch containing unresolved evidence plus one malformed row
        // would take the incomplete fallback and could egress when the
        // configurable registry is empty.
        if crate::auth::is_unresolved_provenance(&source_types) {
            return true;
        }
        if fully_attributed {
            resolver.any_restricted(&source_types).await
        } else {
            match resolver.restricted_snapshot().await {
                Ok(restricted) => !restricted.is_empty(),
                // Registry never loaded + PG down: fail closed.
                Err(_) => true,
            }
        }
    }

    /// Fire webhook notifications for a newly created alert of any `kind`
    /// (`detection` | `metric_monitor` | `slo` | `synthetic`).
    ///
    /// Loads enabled webhooks, filters by (a) subscription category — SIEM vs
    /// observability, derived from `kind` — and (b) severity, then spawns async
    /// delivery tasks. Never blocks the caller. `rule_id` is `None` for
    /// observability alerts (which have a monitor/check as `source_id`, not a
    /// rule); `rule_name` carries the human name of the producer either way.
    #[allow(clippy::too_many_arguments)]
    pub async fn fire_alert(
        &self,
        alert_id: Uuid,
        kind: &str,
        rule_id: Option<Uuid>,
        rule_name: &str,
        severity: &str,
        entity: Option<String>,
        matched_events: &serde_json::Value,
        created_at: chrono::DateTime<Utc>,
    ) {
        let webhooks = match self.repo.list_enabled().await {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to load webhooks: {}", e);
                return;
            }
        };

        if webhooks.is_empty() {
            return;
        }

        // Which subscription checkbox gates this alert (siem_alert | obs_alert).
        let category = alert_kind_to_event_type(kind);

        // Build the payload once for all webhooks
        let events_array = match matched_events.as_array() {
            Some(arr) => arr.iter().take(MAX_MATCHED_EVENTS).cloned().collect(),
            None => vec![],
        };
        // A13 (NAN-1747): this counts the STORED matched_events array, which is
        // capped at max_events_per_alert when the alert is written — so it is the
        // sample size, not the true match count. A large match undercounts here
        // (and in the payload's `matched_event_count`). Carrying the true count
        // would need it stored on the alert row (schema+model change, out of scope).
        let matched_event_count = matched_events.as_array().map_or(0, |a| a.len()) as i64;

        // Resolve the deep-link base once so every fanned-out channel links
        // consistently (NAN-1790).
        let base = self.resolve_base_url().await;

        // NAN-1800: webhook receivers sit OUTSIDE per-user RBAC — once a
        // restricted-source event body leaves here, source scoping is moot.
        // Redact the shared payload ONCE, before the fanout clone, so every
        // channel formatter (generic serializes full matched_events;
        // Slack/Teams/PagerDuty embed `entity`) is covered by construction.
        // The notification still fires as a redacted stub (rule name /
        // severity / count / link kept) — the receiver learns something
        // happened and pivots into the UI, where read-path RBAC applies.
        let origin_restricted = self.origin_restricted(kind, matched_events).await;
        if origin_restricted {
            info!(
                alert_id = %alert_id,
                rule_name = %rule_name,
                "Webhook payload redacted: alert derives from a restricted source (matched_events + entity stripped)"
            );
        }

        let payload = WebhookPayload {
            event_type: "alert.created".to_string(),
            kind: Some(kind.to_string()),
            alert_id: Some(alert_id),
            rule_id,
            rule_name: Some(rule_name.to_string()),
            severity: Some(severity.to_string()),
            entity: if origin_restricted { None } else { entity },
            link_url: Self::ui_link(
                base.as_deref(),
                &format!(
                    "alerts/{}",
                    crate::typeid::encode(crate::typeid::alert::PREFIX, &alert_id)
                ),
            ),
            matched_event_count: Some(matched_event_count),
            matched_events: if origin_restricted {
                None
            } else {
                Some(events_array)
            },
            created_at,
            health_event_id: None,
            health_status: None,
            health_category: None,
            health_resource_type: None,
            health_resource_id: None,
            health_summary: None,
            health_diagnostic_context: None,
            health_remediation: None,
            idempotency_key: None,
        };

        let severity_lower = severity.to_lowercase();

        for webhook in webhooks {
            // Subscription filter: skip webhooks not subscribed to this stream.
            if !webhook.subscribes_to(category) {
                debug!(
                    webhook_id = %webhook.id,
                    webhook_name = %webhook.name,
                    category = category,
                    "Skipping webhook: not subscribed to event stream"
                );
                continue;
            }

            // Detection-rule routing filter (NAN-1790): skip channels scoped to
            // specific rules when this alert didn't come from one of them.
            if !webhook.passes_rule_filter(rule_id) {
                debug!(
                    webhook_id = %webhook.id,
                    webhook_name = %webhook.name,
                    "Skipping channel: alert rule not in channel rule filter"
                );
                continue;
            }

            // Check severity filter
            if let Some(ref filter) = webhook.severity_filter {
                if !filter.is_empty() {
                    let matches = filter.iter().any(|s| s.to_lowercase() == severity_lower);
                    if !matches {
                        debug!(
                            webhook_id = %webhook.id,
                            webhook_name = %webhook.name,
                            severity = %severity,
                            "Skipping webhook: severity not in filter"
                        );
                        continue;
                    }
                }
            }

            // Bound total outstanding tasks: take an in-flight slot before
            // spawning, shed (don't queue) when saturated so a storm / slow
            // endpoint can't OOM us.
            let inflight_permit = match self.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        "Webhook delivery shed: in-flight cap reached (alert storm or slow endpoint)"
                    );
                    // A11 (NAN-1747): persist the shed as a failed delivery-log
                    // row so the delivery-log UI shows a trace precisely during a
                    // storm — otherwise a shed webhook leaves no record at all.
                    // No HTTP attempted → duration 0. Bounded: only fires once the
                    // in-flight cap (512) is reached.
                    self.record(
                        &webhook,
                        Some(alert_id),
                        "alert.created",
                        None,
                        None,
                        false,
                        Some("shed: in-flight cap"),
                        0,
                    )
                    .await;
                    continue;
                }
            };

            let svc = self.clone();
            let payload = payload.clone();
            let alert_id_copy = alert_id;

            // Fire-and-forget with concurrency limit
            tokio::spawn(async move {
                let _inflight = inflight_permit; // held for the task's lifetime
                let _permit = svc.semaphore.acquire().await;
                svc.deliver(&webhook, &payload, Some(alert_id_copy), "alert.created")
                    .await;
            });
        }
    }

    /// Fire webhook notifications for a case lifecycle event (created / status
    /// changed). Gated by the `case` subscription category. Called from the
    /// enterprise case service (cases are enterprise-only); no-op for any
    /// webhook that hasn't opted into the `case` stream.
    ///
    /// `event_type` is the fine-grained event name (`case.created` /
    /// `case.status_changed`); `case_id` is the raw UUID (encoded to a `case_…`
    /// typeid for the link-back). `title` / `status` / `assignee` populate the
    /// payload for the consumer.
    #[allow(clippy::too_many_arguments)]
    pub async fn fire_case_event(
        &self,
        case_id: Uuid,
        event_type: &str,
        title: &str,
        status: &str,
        assignee: Option<String>,
        created_at: chrono::DateTime<Utc>,
    ) {
        let webhooks = match self.repo.list_enabled().await {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to load webhooks: {}", e);
                return;
            }
        };
        if webhooks.is_empty() {
            return;
        }

        let base = self.resolve_base_url().await;

        // Reuse WebhookPayload: case events carry title in `rule_name`, status in
        // `severity`, assignee in `entity` — the generic string slots — plus the
        // case typeid link. `kind = "case"` disambiguates for the consumer.
        let payload = WebhookPayload {
            event_type: event_type.to_string(),
            kind: Some("case".to_string()),
            alert_id: None,
            rule_id: None,
            rule_name: Some(title.to_string()),
            severity: Some(status.to_string()),
            entity: assignee,
            link_url: Self::ui_link(
                base.as_deref(),
                &format!(
                    "cases/{}",
                    crate::typeid::encode(crate::typeid::case::PREFIX, &case_id)
                ),
            ),
            matched_event_count: None,
            matched_events: None,
            created_at,
            health_event_id: None,
            health_status: None,
            health_category: None,
            health_resource_type: None,
            health_resource_id: None,
            health_summary: None,
            health_diagnostic_context: None,
            health_remediation: None,
            idempotency_key: None,
        };

        for webhook in webhooks {
            if !webhook.subscribes_to(EVENT_TYPE_CASE) {
                continue;
            }
            let inflight_permit = match self.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        "Webhook case delivery shed: in-flight cap reached"
                    );
                    // A11 (NAN-1747): persist the shed as a failed delivery-log
                    // row (see fire_alert). `event_type` is the fine-grained case
                    // event name; no alert id for case events.
                    self.record(
                        &webhook,
                        None,
                        event_type,
                        None,
                        None,
                        false,
                        Some("shed: in-flight cap"),
                        0,
                    )
                    .await;
                    continue;
                }
            };
            let svc = self.clone();
            let payload = payload.clone();
            let event_type = event_type.to_string();
            tokio::spawn(async move {
                let _inflight = inflight_permit;
                let _permit = svc.semaphore.acquire().await;
                svc.deliver(&webhook, &payload, None, &event_type).await;
            });
        }
    }

    /// Fire `report_ready` webhooks when a scheduled report finishes (NAN-1793).
    ///
    /// Additive event stream (`EVENT_TYPE_REPORT`), gated by the opt-in `report`
    /// subscription category — a future notification-channels layer can route it.
    /// Reuses [`WebhookPayload`]'s generic slots the same way `fire_case_event`
    /// does: `rule_name` carries the report name, `severity` the run status,
    /// `entity` the source type (search | dashboard), and `matched_event_count`
    /// the result row count. Fire-and-forget; never blocks the scheduler.
    #[allow(clippy::too_many_arguments)]
    pub async fn fire_report_ready(
        &self,
        report_id: Uuid,
        report_name: &str,
        source_type: &str,
        status: &str,
        row_count: Option<i64>,
        created_at: chrono::DateTime<Utc>,
    ) {
        let webhooks = match self.repo.list_enabled().await {
            Ok(w) => w,
            Err(e) => {
                error!("Failed to load webhooks: {}", e);
                return;
            }
        };
        if webhooks.is_empty() {
            return;
        }

        let base = self.resolve_base_url().await;

        let payload = WebhookPayload {
            event_type: "report_ready".to_string(),
            kind: Some("report".to_string()),
            alert_id: None,
            rule_id: None,
            rule_name: Some(report_name.to_string()),
            severity: Some(status.to_string()),
            entity: Some(source_type.to_string()),
            link_url: Self::ui_link(
                base.as_deref(),
                &format!(
                    "reports/{}",
                    crate::typeid::encode(crate::typeid::report::PREFIX, &report_id)
                ),
            ),
            matched_event_count: row_count,
            matched_events: None,
            created_at,
            health_event_id: None,
            health_status: None,
            health_category: None,
            health_resource_type: None,
            health_resource_id: None,
            health_summary: None,
            health_diagnostic_context: None,
            health_remediation: None,
            idempotency_key: None,
        };

        for webhook in webhooks {
            if !webhook.subscribes_to(EVENT_TYPE_REPORT) {
                continue;
            }
            let inflight_permit = match self.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        "Webhook report delivery shed: in-flight cap reached"
                    );
                    self.record(
                        &webhook,
                        None,
                        "report_ready",
                        None,
                        None,
                        false,
                        Some("shed: in-flight cap"),
                        0,
                    )
                    .await;
                    continue;
                }
            };
            let svc = self.clone();
            let payload = payload.clone();
            tokio::spawn(async move {
                let _inflight = inflight_permit;
                let _permit = svc.semaphore.acquire().await;
                svc.deliver(&webhook, &payload, None, "report_ready").await;
            });
        }
    }

    /// Build a request with custom headers and HMAC signature. The `client` is
    /// the per-delivery SSRF-pinned client (see `ssrf_checked_client`).
    ///
    /// **Fails closed on a crypto error.** If a webhook has configured custom
    /// headers or an HMAC secret that cannot be decrypted (e.g. the encryption
    /// key was rotated), this returns `Err` and the caller must NOT send — a
    /// silent downgrade to an unsigned request, or one missing its configured
    /// auth headers, would be a security regression the receiver can't detect.
    fn build_request(
        &self,
        client: &reqwest::Client,
        webhook: &super::models::Webhook,
        payload_bytes: &[u8],
        sign_generic: bool,
    ) -> Result<reqwest::RequestBuilder, String> {
        let mut request = client
            .post(&webhook.url)
            .header("Content-Type", "application/json")
            .header("User-Agent", "NanoSIEM-Webhook/1.0");

        // Custom headers + HMAC signing apply ONLY to the generic channel
        // (`sign_generic`). Provider channels (Slack / Teams / PagerDuty)
        // authenticate by their secret URL or in-body routing key, and their
        // receivers reject unexpected headers; `secret_encrypted` for those
        // holds the routing key, NOT an HMAC secret, so it must never be signed
        // over here.
        if sign_generic {
            // Add custom headers. reqwest's typed `HeaderName`/`HeaderValue`
            // reject CRLF / control chars, so a header key/value can't be used
            // to inject a second header or smuggle a request; an invalid pair
            // surfaces as a build error at send. A decrypt failure fails closed.
            if let Some(ref encrypted) = webhook.headers_encrypted {
                if !encrypted.is_empty() {
                    let headers = self
                        .repo
                        .decrypt_json::<HashMap<String, String>>(encrypted)
                        .map_err(|e| {
                            format!("configured custom headers could not be decrypted: {e}")
                        })?;
                    for (key, value) in &headers {
                        request = request.header(key, value);
                    }
                }
            }

            // Add HMAC signature. If a secret is configured it MUST sign; a
            // decrypt failure fails closed rather than delivering unsigned.
            if let Some(ref encrypted_secret) = webhook.secret_encrypted {
                if !encrypted_secret.is_empty() {
                    let secret = self.repo.decrypt_string(encrypted_secret).map_err(|e| {
                        format!("configured HMAC secret could not be decrypted: {e}")
                    })?;
                    // Sign `<unix_ts>.<body>` (Stripe-style) and send the
                    // timestamp in `X-NanoSIEM-Timestamp` so a receiver can
                    // reject stale replays within a freshness window — HMAC-over-
                    // body alone is replayable forever. A fresh timestamp per
                    // attempt is fine (each retry is an independently-fresh
                    // request).
                    let timestamp = Utc::now().timestamp();
                    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                        .map_err(|e| format!("HMAC init failed: {e}"))?;
                    mac.update(timestamp.to_string().as_bytes());
                    mac.update(b".");
                    mac.update(payload_bytes);
                    let signature = hex::encode(mac.finalize().into_bytes());
                    request = request
                        .header("X-NanoSIEM-Timestamp", timestamp.to_string())
                        .header("X-NanoSIEM-Signature", format!("sha256={}", signature));
                }
            }
        }

        Ok(request)
    }

    /// Render the outbound body for a channel and whether it should be HMAC-
    /// signed (generic only). Decrypts the PagerDuty routing key here (fail
    /// closed — a channel whose secret can't be decrypted must not deliver an
    /// unauthenticated event). Deterministic, so `deliver` computes it once
    /// before the retry loop.
    fn channel_body(
        &self,
        webhook: &super::models::Webhook,
        payload: &WebhookPayload,
    ) -> Result<(Vec<u8>, bool), String> {
        // Strict: an unknown stored channel_type fails closed rather than
        // silently delivering as `generic` (which would sign + ship this row's
        // secret to its endpoint).
        let channel_type = webhook.resolve_channel_type()?;

        // PagerDuty carries its routing key in the encrypted secret column.
        let routing_key = if channel_type == ChannelType::PagerDuty {
            match &webhook.secret_encrypted {
                Some(enc) if !enc.is_empty() => Some(
                    self.repo
                        .decrypt_string(enc)
                        .map_err(|e| format!("PagerDuty routing key could not be decrypted: {e}"))?,
                ),
                _ => None, // build_channel_body reports the missing-key error
            }
        } else {
            None
        };

        let ctx = FormatContext {
            routing_key: routing_key.as_deref(),
        };
        let formatted = build_channel_body(channel_type, payload, &ctx)?;
        Ok((formatted.bytes, formatted.sign_hmac))
    }

    /// Deliver a webhook payload with delivery-time SSRF pinning and bounded
    /// retries, then log a single delivery-log row for the final outcome.
    ///
    /// Retry policy: up to `MAX_DELIVERY_ATTEMPTS` attempts, exponential backoff
    /// (`RETRY_BASE_DELAY_MS` doubling each retry). Transport errors, HTTP 5xx,
    /// and 429 are retried; 2xx succeeds; other 4xx are terminal (a bad request
    /// won't fix itself). Each attempt is traced; only the final result is
    /// persisted to the delivery log (one row per logical delivery). Runs inside
    /// the fire-and-forget spawn, so the backoff sleeps never block the caller.
    async fn deliver(
        &self,
        webhook: &super::models::Webhook,
        payload: &WebhookPayload,
        alert_id: Option<Uuid>,
        event_type: &str,
    ) -> WebhookTestResult {
        let start = Instant::now();

        // Render the provider-specific body once (deterministic across retries).
        // A formatter or secret-decrypt failure is recorded as a failed delivery
        // and never retried (it won't fix itself).
        let (payload_bytes, sign_generic) = match self.channel_body(webhook, payload) {
            Ok(v) => v,
            Err(reason) => {
                warn!(
                    webhook_id = %webhook.id,
                    webhook_name = %webhook.name,
                    reason = %reason,
                    "Webhook not sent (fail-closed): channel body could not be built"
                );
                let duration_ms = start.elapsed().as_millis() as i32;
                self.record(
                    webhook,
                    alert_id,
                    event_type,
                    None,
                    None,
                    false,
                    Some(&reason),
                    duration_ms,
                )
                .await;
                return WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(reason),
                    duration_ms: duration_ms as u64,
                };
            }
        };

        // Delivery-time SSRF guard: re-resolve + pin to validated IP(s). A
        // blocked target is recorded as a failed delivery and never sent — this
        // closes the DNS-rebind window between config-time validation and fire.
        let client = match Self::ssrf_checked_client(&webhook.url).await {
            Ok(c) => c,
            Err(reason) => {
                warn!(
                    webhook_id = %webhook.id,
                    webhook_name = %webhook.name,
                    reason = %reason,
                    "Webhook delivery blocked by SSRF guard"
                );
                let duration_ms = start.elapsed().as_millis() as i32;
                self.record(
                    webhook,
                    alert_id,
                    event_type,
                    None,
                    None,
                    false,
                    Some(&reason),
                    duration_ms,
                )
                .await;
                return WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(reason),
                    duration_ms: duration_ms as u64,
                };
            }
        };

        for attempt in 1..=MAX_DELIVERY_ATTEMPTS {
            // Fail closed on a crypto error (deterministic — don't burn retries).
            let request = match self.build_request(&client, webhook, &payload_bytes, sign_generic) {
                Ok(r) => r,
                Err(reason) => {
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        reason = %reason,
                        "Webhook not sent (fail-closed): request could not be built with configured auth"
                    );
                    let duration_ms = start.elapsed().as_millis() as i32;
                    self.record(
                        webhook,
                        alert_id,
                        event_type,
                        None,
                        None,
                        false,
                        Some(&reason),
                        duration_ms,
                    )
                    .await;
                    return WebhookTestResult {
                        success: false,
                        status_code: None,
                        error: Some(reason),
                        duration_ms: duration_ms as u64,
                    };
                }
            };
            let request = if let Some(key) = payload.idempotency_key.as_deref() {
                request.header("X-NanoSIEM-Idempotency-Key", key)
            } else {
                request
            };
            match request.body(payload_bytes.clone()).send().await {
                Ok(response) => {
                    let status = response.status().as_u16() as i32;
                    let success = response.status().is_success();
                    let retryable = response.status().is_server_error() || status == 429;
                    let body = Self::read_body_capped(response).await;

                    if success {
                        info!(
                            webhook_id = %webhook.id,
                            webhook_name = %webhook.name,
                            status_code = status,
                            attempt,
                            "Webhook delivered successfully"
                        );
                        let duration_ms = start.elapsed().as_millis() as i32;
                        self.record(
                            webhook,
                            alert_id,
                            event_type,
                            Some(status),
                            Some(&body),
                            true,
                            None,
                            duration_ms,
                        )
                        .await;
                        return WebhookTestResult {
                            success: true,
                            status_code: Some(status as u16),
                            error: None,
                            duration_ms: duration_ms as u64,
                        };
                    }

                    if retryable && attempt < MAX_DELIVERY_ATTEMPTS {
                        let delay = RETRY_BASE_DELAY_MS << (attempt - 1);
                        warn!(
                            webhook_id = %webhook.id,
                            status_code = status,
                            attempt,
                            next_delay_ms = delay,
                            "Webhook returned retryable status; retrying"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        continue;
                    }

                    // Terminal 4xx, or a retryable status on the final attempt.
                    warn!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        status_code = status,
                        attempt,
                        "Webhook delivery failed (non-success status)"
                    );
                    let duration_ms = start.elapsed().as_millis() as i32;
                    let err = format!("HTTP {status} after {attempt} attempt(s)");
                    self.record(
                        webhook,
                        alert_id,
                        event_type,
                        Some(status),
                        Some(&body),
                        false,
                        Some(&err),
                        duration_ms,
                    )
                    .await;
                    return WebhookTestResult {
                        success: false,
                        status_code: Some(status as u16),
                        error: Some(err),
                        duration_ms: duration_ms as u64,
                    };
                }
                Err(e) => {
                    // F-39: strip the URL from the transport error — reqwest
                    // formats it as "… for url (<full-url>)", and for a
                    // Slack/Teams webhook the URL path IS the bearer credential.
                    // This string is persisted to the delivery log and emitted
                    // to tracing, so it must never carry the secret.
                    let error_msg = e.without_url().to_string();

                    if attempt < MAX_DELIVERY_ATTEMPTS {
                        let delay = RETRY_BASE_DELAY_MS << (attempt - 1);
                        warn!(
                            webhook_id = %webhook.id,
                            error = %error_msg,
                            attempt,
                            next_delay_ms = delay,
                            "Webhook transport error; retrying"
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
                        continue;
                    }

                    error!(
                        webhook_id = %webhook.id,
                        webhook_name = %webhook.name,
                        error = %error_msg,
                        attempt,
                        "Webhook delivery failed (transport error, retries exhausted)"
                    );
                    let duration_ms = start.elapsed().as_millis() as i32;
                    let err = format!("{error_msg} after {attempt} attempt(s)");
                    self.record(
                        webhook,
                        alert_id,
                        event_type,
                        None,
                        None,
                        false,
                        Some(&err),
                        duration_ms,
                    )
                    .await;
                    return WebhookTestResult {
                        success: false,
                        status_code: None,
                        error: Some(err),
                        duration_ms: duration_ms as u64,
                    };
                }
            }
        }

        WebhookTestResult {
            success: false,
            status_code: None,
            error: Some("delivery attempts exhausted".to_string()),
            duration_ms: start.elapsed().as_millis() as u64,
        }
    }

    /// Deliver one durable payload to a pre-selected channel and wait for its
    /// final result. The caller owns outbox retry state; this method continues
    /// to provide the existing SSRF pinning, HMAC signing, provider formatting,
    /// bounded HTTP retries, and ordinary webhook delivery log.
    pub async fn deliver_persisted(
        &self,
        webhook_id: Uuid,
        payload: &WebhookPayload,
        subscription_type: &str,
        delivery_event_type: &str,
    ) -> Result<WebhookTestResult, String> {
        let webhook = self
            .repo
            .get(webhook_id)
            .await
            .map_err(|e| format!("Webhook not found: {e}"))?;
        if !webhook.enabled {
            return Err("notification channel is disabled".to_string());
        }
        if !webhook.subscribes_to(subscription_type) {
            return Err(format!(
                "notification channel is not subscribed to {subscription_type}"
            ));
        }
        let _permit = self.semaphore.acquire().await;
        Ok(self
            .deliver(&webhook, payload, None, delivery_event_type)
            .await)
    }

    /// Persist a single delivery-log row, logging (but not propagating) a
    /// logging failure. Centralizes the `log_delivery` error handling shared by
    /// `deliver` and `send_test`.
    #[allow(clippy::too_many_arguments)]
    async fn record(
        &self,
        webhook: &super::models::Webhook,
        alert_id: Option<Uuid>,
        event_type: &str,
        status_code: Option<i32>,
        response_body: Option<&str>,
        success: bool,
        error_message: Option<&str>,
        duration_ms: i32,
    ) {
        if let Err(e) = self
            .repo
            .log_delivery(
                webhook.id,
                alert_id,
                event_type,
                status_code,
                response_body,
                success,
                error_message,
                Some(duration_ms),
            )
            .await
        {
            error!(webhook_id = %webhook.id, "Failed to log webhook delivery: {}", e);
        }
    }

    /// Send a synchronous test delivery to a webhook endpoint.
    pub async fn send_test(&self, webhook_id: Uuid) -> Result<WebhookTestResult, String> {
        let webhook = self
            .repo
            .get(webhook_id)
            .await
            .map_err(|e| format!("Webhook not found: {}", e))?;

        let base = self.resolve_base_url().await;
        let payload = WebhookPayload {
            event_type: "webhook.test".to_string(),
            kind: None,
            alert_id: None,
            rule_id: None,
            rule_name: Some("nano test notification".to_string()),
            severity: Some("informational".to_string()),
            entity: None,
            link_url: Self::ui_link(base.as_deref(), "settings/notifications"),
            matched_event_count: Some(0),
            matched_events: Some(vec![]),
            created_at: Utc::now(),
            health_event_id: None,
            health_status: None,
            health_category: None,
            health_resource_type: None,
            health_resource_id: None,
            health_summary: None,
            health_diagnostic_context: None,
            health_remediation: None,
            idempotency_key: None,
        };

        let start = Instant::now();

        // Render the body for this channel's type (Slack/Teams/PagerDuty/generic).
        // A formatter or secret-decrypt failure surfaces as a failed test rather
        // than a 500 — the operator sees exactly why nothing could be sent.
        let (payload_bytes, sign_generic) = match self.channel_body(&webhook, &payload) {
            Ok(v) => v,
            Err(reason) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        None,
                        None,
                        false,
                        Some(&reason),
                        Some(duration_ms as i32),
                    )
                    .await;
                return Ok(WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(reason),
                    duration_ms,
                });
            }
        };

        // Test delivery is a single, synchronous attempt (immediate UX feedback,
        // no retries), but still SSRF-pinned like real delivery.
        let client = match Self::ssrf_checked_client(&webhook.url).await {
            Ok(c) => c,
            Err(reason) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        None,
                        None,
                        false,
                        Some(&reason),
                        Some(duration_ms as i32),
                    )
                    .await;
                return Ok(WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(reason),
                    duration_ms,
                });
            }
        };

        let request = match self.build_request(&client, &webhook, &payload_bytes, sign_generic) {
            Ok(r) => r,
            Err(reason) => {
                let duration_ms = start.elapsed().as_millis() as u64;
                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        None,
                        None,
                        false,
                        Some(&reason),
                        Some(duration_ms as i32),
                    )
                    .await;
                return Ok(WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(reason),
                    duration_ms,
                });
            }
        };
        let result = request.body(payload_bytes).send().await;
        let duration_ms = start.elapsed().as_millis() as u64;

        match result {
            Ok(response) => {
                let status = response.status().as_u16();
                let success = response.status().is_success();
                let body = Self::read_body_capped(response).await;

                // Log test delivery
                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        Some(status as i32),
                        Some(&body),
                        success,
                        if success {
                            None
                        } else {
                            Some("Non-success status code")
                        },
                        Some(duration_ms as i32),
                    )
                    .await;

                Ok(WebhookTestResult {
                    success,
                    status_code: Some(status),
                    error: if success {
                        None
                    } else {
                        Some(format!("HTTP {}", status))
                    },
                    duration_ms,
                })
            }
            Err(e) => {
                // F-39: strip the URL from the transport error — it is returned
                // directly in the test-endpoint API response and logged, and a
                // Slack/Teams webhook URL path is a bearer credential.
                let error_msg = e.without_url().to_string();

                let _ = self
                    .repo
                    .log_delivery(
                        webhook.id,
                        None,
                        "webhook.test",
                        None,
                        None,
                        false,
                        Some(&error_msg),
                        Some(duration_ms as i32),
                    )
                    .await;

                Ok(WebhookTestResult {
                    success: false,
                    status_code: None,
                    error: Some(error_msg),
                    duration_ms,
                })
            }
        }
    }

    /// Get the repository (for use by API handlers)
    pub fn repo(&self) -> &WebhookRepository {
        &self.repo
    }
}

/// Extract the distinct origin `source_type`s from a stored `matched_events`
/// blob (NAN-1800). Returns `(source_types, fully_attributed)`:
///
/// - `source_types`: deduped, normalized (`trim` + `lowercase` — OCSF
///   `source_type` is NOT ingest-lowercased) values found either in the
///   ingest-controlled per-event field or the engine-written aggregate stamp.
/// - `fully_attributed`: `true` only when the blob is a non-empty array whose
///   EVERY element carries a usable per-event `source_type` or a non-empty,
///   well-formed `_nano_source_types` stamp. Empty arrays, non-array blobs, and
///   malformed/unattributed elements are NOT fully attributed — the caller
///   must treat those fail-closed.
///
/// Pure so the attribution semantics are unit-testable without a database.
pub(crate) fn origin_source_types(matched_events: &serde_json::Value) -> (Vec<String>, bool) {
    let Some(events) = matched_events.as_array() else {
        return (Vec::new(), false);
    };
    if events.is_empty() {
        return (Vec::new(), false);
    }
    let mut types: BTreeSet<String> = BTreeSet::new();
    let mut fully_attributed = true;
    for event in events {
        let mut event_attributed = false;
        let mut external_source_present = false;

        // NAN-2155 (codex round 3): the per-event `source_type` is
        // ingest-controlled. A sender claiming the reserved
        // unresolved-provenance sentinel is treated as UNATTRIBUTED (not as an
        // unresolved origin), which is the fail-closed direction here — the
        // caller redacts an unattributed blob whenever any restriction exists.
        let external_source = event
            .get("source_type")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_lowercase())
            .filter(|s| !s.is_empty());
        if let Some(source_type) = external_source {
            external_source_present = true;
            if !crate::auth::is_reserved_source_type(&source_type) {
                types.insert(source_type);
                event_attributed = true;
            }
        }

        // Only engine-stamped aggregate rows lack a non-empty external field.
        // Ignore `_nano_source_types` beside a real (or forged reserved)
        // per-event field: accepting both would let ingest/query-controlled data
        // impersonate the engine annotation and suppress webhook delivery.
        if !external_source_present {
            // NAN-2155 (branch-wide review): aggregate rows intentionally lack the
            // per-event field. Their authoritative origin is the engine-written
            // annotation that also becomes `alerts.source_types`. Harvest it here
            // so the unresolved sentinel reaches `SourceScopeResolver::any_restricted`
            // and redacts unconditionally, even when the registry is empty.
            if let Some(stamp) = event.get("_nano_source_types") {
                match stamp.as_array() {
                    Some(values) if !values.is_empty() => {
                        let mut stamp_valid = true;
                        for value in values {
                            match value
                                .as_str()
                                .map(|s| s.trim().to_lowercase())
                                .filter(|s| !s.is_empty())
                            {
                                Some(source_type) => {
                                    // Unlike the ingest-controlled field above, the
                                    // engine annotation is the one channel allowed
                                    // to carry the reserved sentinel.
                                    types.insert(source_type);
                                }
                                None => stamp_valid = false,
                            }
                        }
                        if stamp_valid {
                            event_attributed = true;
                        } else {
                            fully_attributed = false;
                        }
                    }
                    // NAN-2227: an EMPTY array is a positive engine statement —
                    // "I resolved this window's provenance and nothing about it
                    // is source-derived" — not a failure to resolve. Two engine
                    // branches emit it deliberately:
                    //
                    //   * `ReservedOnly` — the window WAS attributed, but only to
                    //     forged reserved names we refuse to honour. Treating that
                    //     as unattributed would let one forged `X-Source-Type`
                    //     suppress a detection's evidence.
                    //   * `DatasetProvenance::NotSourceDerived` — spans/metrics,
                    //     whose tables have no `source_type` column and are not
                    //     covered by per-source RBAC at all.
                    //
                    // Every FAILURE branch stamps `fail_closed_stamp`, which is
                    // never empty (it always unions the sentinel and `audit`), so
                    // "empty" cannot arise from a fail-closed path. The stamp key
                    // is `_nano_`-prefixed and unforgeable by ingest, so this
                    // cannot be reached by a sender.
                    Some(values) if values.is_empty() => event_attributed = true,
                    // A non-array stamp is malformed and may not certify anything.
                    _ => fully_attributed = false,
                }
            }
        }

        if !event_attributed {
            fully_attributed = false;
        }
    }
    (types.into_iter().collect(), fully_attributed)
}
