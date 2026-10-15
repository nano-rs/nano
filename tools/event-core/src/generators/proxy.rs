// SPDX-License-Identifier: AGPL-3.0-or-later

//! Conduit MITM Proxy event generator using real traffic patterns + top legit domains
//!
//! Generates Conduit proxy access log JSON matching the real format from the lab.
//! The Conduit parser in nano-parsers expects fields like client_ip, host, full_url,
//! path, method, status_code, scheme, upstream_addr, tls_intercepted, threat_score, etc.

use chrono::{DateTime, Utc};
use rand::seq::IndexedRandom;
use rand::Rng;
use uuid::Uuid;

use crate::entity::Entity;
use crate::event::Event;
use crate::profiles;
use crate::web_session::DrawnRequest;

/// Top legitimate domains for realistic proxy traffic volume.
/// These get mixed with the real lab traffic patterns.
const TOP_DOMAINS: &[&str] = &[
    "google.com",
    "youtube.com",
    "facebook.com",
    "amazon.com",
    "wikipedia.org",
    "twitter.com",
    "instagram.com",
    "linkedin.com",
    "reddit.com",
    "microsoft.com",
    "apple.com",
    "netflix.com",
    "github.com",
    "stackoverflow.com",
    "cloudflare.com",
    "office.com",
    "live.com",
    "bing.com",
    "zoom.us",
    "adobe.com",
    "salesforce.com",
    "dropbox.com",
    "slack.com",
    "atlassian.com",
    "notion.so",
    "figma.com",
    "vercel.com",
    "aws.amazon.com",
    "portal.azure.com",
    "console.cloud.google.com",
    "docs.google.com",
    "drive.google.com",
    "mail.google.com",
    "calendar.google.com",
    "maps.google.com",
    "outlook.office365.com",
    "teams.microsoft.com",
    "onedrive.live.com",
    "sharepoint.com",
    "login.microsoftonline.com",
    "cdn.jsdelivr.net",
    "unpkg.com",
    "cdnjs.cloudflare.com",
    "fonts.googleapis.com",
    "ajax.googleapis.com",
    "api.github.com",
    "raw.githubusercontent.com",
    "registry.npmjs.org",
    "pypi.org",
    "crates.io",
    "docker.io",
    "hub.docker.com",
    "quay.io",
    "gcr.io",
    "gallery.ecr.aws",
    "medium.com",
    "dev.to",
    "hashnode.dev",
    "substack.com",
    "techcrunch.com",
    "arstechnica.com",
    "theverge.com",
    "wired.com",
    "bbc.com",
    "cnn.com",
    "nytimes.com",
    "washingtonpost.com",
    "reuters.com",
    "bloomberg.com",
    "ft.com",
    "espn.com",
    "weather.com",
    "zillow.com",
    "airbnb.com",
    "booking.com",
    "uber.com",
    "lyft.com",
    "doordash.com",
    "grubhub.com",
    "instacart.com",
    "stripe.com",
    "paypal.com",
    "braintree.com",
    "square.com",
    "plaid.com",
    "twilio.com",
    "sendgrid.com",
    "mailchimp.com",
    "hubspot.com",
    "intercom.io",
    "datadog.com",
    "splunk.com",
    "elastic.co",
    "grafana.com",
    "pagerduty.com",
    "sentry.io",
    "newrelic.com",
    "dynatrace.com",
    "sumologic.com",
    "loggly.com",
    "okta.com",
    "auth0.com",
    "onelogin.com",
    "duo.com",
    "crowdstrike.com",
    "sentinelone.com",
    "carbonblack.com",
    "paloaltonetworks.com",
    "fortinet.com",
    "zscaler.com",
    "snyk.io",
    "sonarqube.org",
    "veracode.com",
    "checkmarx.com",
    "whitesource.io",
    "jfrog.com",
    "sonatype.com",
    "nexus.sonatype.com",
    "artifactory.jfrog.io",
    "conan.io",
    "terraform.io",
    "ansible.com",
    "puppet.com",
    "chef.io",
    "saltstack.com",
    "kubernetes.io",
    "helm.sh",
    "istio.io",
    "envoyproxy.io",
    "linkerd.io",
    "prometheus.io",
    "thanos.io",
    "cortexmetrics.io",
    "jaegertracing.io",
    "zipkin.io",
    "kafka.apache.org",
    "rabbitmq.com",
    "redis.io",
    "mongodb.com",
    "postgresql.org",
    "mysql.com",
    "mariadb.org",
    "cockroachlabs.com",
    "timescale.com",
    "influxdata.com",
    "clickhouse.com",
    "questdb.io",
    "victoriametrics.com",
    "minio.io",
    "ceph.io",
    "spotify.com",
    "soundcloud.com",
    "twitch.tv",
    "discord.com",
    "telegram.org",
    "whatsapp.com",
    "signal.org",
    "viber.com",
    "skype.com",
    "webex.com",
    "canva.com",
    "miro.com",
    "lucidchart.com",
    "draw.io",
    "excalidraw.com",
    "trello.com",
    "asana.com",
    "monday.com",
    "basecamp.com",
    "clickup.com",
    "zendesk.com",
    "freshdesk.com",
    "servicenow.com",
    "jira.atlassian.com",
    "confluence.atlassian.com",
    "bitbucket.org",
    "gitlab.com",
    "codeberg.org",
    "sourcehut.org",
    "gitea.com",
    "npmjs.com",
    "yarnpkg.com",
    "pnpm.io",
    "bun.sh",
    "deno.land",
    "rust-lang.org",
    "go.dev",
    "python.org",
    "ruby-lang.org",
    "php.net",
    "typescriptlang.org",
    "kotlinlang.org",
    "swift.org",
    "dart.dev",
    "elixir-lang.org",
    "reactjs.org",
    "vuejs.org",
    "angular.io",
    "svelte.dev",
    "nextjs.org",
    "nuxt.com",
    "remix.run",
    "astro.build",
    "gatsby.com",
    "11ty.dev",
    "tailwindcss.com",
    "getbootstrap.com",
    "bulma.io",
    "chakra-ui.com",
    "mui.com",
    "d3js.org",
    "chartjs.org",
    "plotly.com",
    "recharts.org",
    "highcharts.com",
    "openai.com",
    "anthropic.com",
    "huggingface.co",
    "cohere.com",
    "stability.ai",
    "wandb.ai",
    "mlflow.org",
    "dvc.org",
    "labelbox.com",
    "scale.com",
    "kaggle.com",
    "arxiv.org",
    "scholar.google.com",
    "researchgate.net",
    "semanticscholar.org",
    "coursera.org",
    "udemy.com",
    "edx.org",
    "khanacademy.org",
    "codecademy.com",
    "leetcode.com",
    "hackerrank.com",
    "codewars.com",
    "exercism.org",
    "projecteuler.net",
];

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"];
const STATUS_CODES: &[u16] = &[
    200, 200, 200, 200, 200, 301, 302, 304, 304, 400, 401, 403, 404, 500, 502, 503,
];

const PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/api/v1/status",
    "/api/v2/data",
    "/assets/main.js",
    "/assets/style.css",
    "/favicon.ico",
    "/robots.txt",
    "/login",
    "/oauth/token",
    "/search",
    "/feed",
    "/notifications",
    "/settings",
    "/images/logo.png",
    "/fonts/inter.woff2",
    "/sw.js",
    "/manifest.json",
    "/.well-known/security.txt",
];

const CONTENT_TYPES: &[&str] = &[
    "text/html",
    "text/html",
    "application/json",
    "application/javascript",
    "text/css",
    "image/png",
    "image/jpeg",
    "font/woff2",
    "application/xml",
    "application/octet-stream",
];

const CATEGORIES: &[&str] = &[
    "technology",
    "technology",
    "technology",
    "business",
    "social_media",
    "news",
    "entertainment",
    "education",
    "shopping",
    "productivity",
    "cloud_services",
    "developer_tools",
    "search_engine",
    "cdn",
];

const CACHE_STATUSES: &[&str] = &["hit", "hit", "hit", "miss", "miss", "bypass", "expired"];

/// Deterministic Conduit event inputs for a scripted campaign.
///
/// Normal background traffic should continue through [`ProxyGenerator::generate`].
/// Injector scenarios use this shape when domains, paths, referrers, response
/// sizes, and threat signals are evidence in the campaign rather than noise.
pub struct ScriptedProxyEvent<'a> {
    pub host: &'a str,
    pub path: &'a str,
    pub method: &'a str,
    pub status: u16,
    pub upstream_ip: &'a str,
    pub referrer: Option<&'a str>,
    pub category: &'a str,
    pub content_type: &'a str,
    pub response_bytes: u64,
    pub threat_score: f64,
    pub threat_signals: &'a [&'a str],
}

pub struct ProxyGenerator;

impl ProxyGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a proxy event — 30% from real lab patterns, 70% from legit domain browsing
    pub fn generate(&self, timestamp: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let r: f64 = rng.random();
        if r < 0.30 {
            self.from_real_pattern(timestamp, entity, rng)
        } else {
            self.from_legit_browsing(timestamp, entity, rng)
        }
    }

    /// Emit a fully specified Conduit proxy event for a scripted campaign.
    pub fn scripted(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        spec: ScriptedProxyEvent<'_>,
    ) -> Event {
        let threat_tier = if spec.threat_score < 0.2 {
            "tier0"
        } else if spec.threat_score < 0.5 {
            "tier1"
        } else if spec.threat_score < 0.8 {
            "tier2"
        } else {
            "tier3"
        };
        let threat_signals = spec
            .threat_signals
            .iter()
            .map(|name| {
                serde_json::json!({
                    "name": name,
                    "score": spec.threat_score,
                    "tier": threat_tier,
                })
            })
            .collect::<Vec<_>>();
        let full_url = format!("https://{}{}", spec.host, spec.path);
        let action = if spec.status >= 400 { "deny" } else { "allow" };
        let request_bytes = if spec.method == "GET" { 0 } else { 768 };
        let user_agent = entity
            .web_session()
            .profile(&entity.hostname)
            .browser_user_agent();

        let mut log_entry = serde_json::json!({
            "id": Uuid::now_v7().to_string(),
            "timestamp": ts.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string(),
            "client_ip": entity.ip,
            "username": entity.user,
            "auth_method": "transparent",
            "method": spec.method,
            "scheme": "https",
            "host": spec.host,
            "port": 443,
            "path": spec.path,
            "full_url": full_url,
            "user_agent": user_agent,
            "category": spec.category,
            "action": action,
            "rule_id": serde_json::Value::Null,
            "status_code": spec.status,
            "request_bytes": request_bytes,
            "response_bytes": spec.response_bytes,
            "duration_ms": 184,
            "tls_intercepted": true,
            "upstream_addr": format!("{}:443", spec.upstream_ip),
            "cache_status": "miss",
            "content_type": spec.content_type,
            "threat_score": spec.threat_score,
            "threat_tier": threat_tier,
            "threat_blocked": false,
            "threat_signals": threat_signals,
        });
        // The live proxy omits `referer` when the request had no Referer header.
        if let Some(referer) = spec.referrer {
            log_entry["referer"] = serde_json::Value::from(referer);
        }

        Event {
            message: serde_json::to_string(&log_entry).unwrap(),
            timestamp: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            source_type: "conduit_proxy".to_string(),
            display_label: format!(
                "[proxy] {} {} https://{}{} → {}",
                entity.ip, spec.method, spec.host, spec.path, spec.status
            ),
        }
    }

    /// Generate from real lab proxy traffic patterns
    fn from_real_pattern(&self, ts: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let profiles = profiles::profiles();
        let pattern = profiles.sample_proxy_pattern(rng);

        let host = if pattern.url_domain.is_empty() {
            TOP_DOMAINS.choose(rng).unwrap().to_string()
        } else {
            pattern.url_domain.clone()
        };

        let method = if pattern.http_method.is_empty() {
            "GET"
        } else {
            &pattern.http_method
        };
        let status: u16 = if pattern.http_status_code == 0 {
            200
        } else {
            pattern.http_status_code
        };
        let scheme = if pattern.protocol.is_empty() {
            "https"
        } else {
            &pattern.protocol
        };
        let port = if pattern.dest_port == 0 {
            if scheme == "https" {
                443
            } else {
                80
            }
        } else {
            pattern.dest_port
        };
        let upstream_ip = if pattern.dest_ip.is_empty() {
            gen_public_ip(rng)
        } else {
            pattern.dest_ip.clone()
        };

        self.build_conduit_event(
            ts,
            entity,
            &host,
            port,
            scheme,
            method,
            status,
            &upstream_ip,
            rng,
        )
    }

    /// Generate from legit domain browsing (bulk of traffic)
    fn from_legit_browsing(&self, ts: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let (_, _referrer, dest_host) = entity.next_browse_request(rng);
        let host = if dest_host.is_empty() {
            TOP_DOMAINS.choose(rng).unwrap().to_string()
        } else {
            dest_host
        };

        let method = if rng.random_bool(0.85) {
            "GET"
        } else {
            HTTP_METHODS.choose(rng).unwrap()
        };
        let status = *STATUS_CODES.choose(rng).unwrap();
        let scheme = if rng.random_bool(0.90) {
            "https"
        } else {
            "http"
        };
        let port: u16 = if scheme == "https" { 443 } else { 80 };
        let upstream_ip = gen_public_ip(rng);

        self.build_conduit_event(
            ts,
            entity,
            &host,
            port,
            scheme,
            method,
            status,
            &upstream_ip,
            rng,
        )
    }

    /// Build a Conduit MITM Proxy access log entry matching the real format.
    fn build_conduit_event(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        host: &str,
        port: u16,
        scheme: &str,
        method: &str,
        status: u16,
        upstream_ip: &str,
        rng: &mut impl Rng,
    ) -> Event {
        let drawn_path = PATHS.choose(rng).unwrap();
        // NAN-3294: referer / user_agent from the client's web session. The
        // plan keeps the drawn host/path for browser traffic (sub-resources may
        // move to the open page's host) and replaces them for background
        // agents and the rare phishing chain.
        let plan = entity.web_session().plan(
            &entity.hostname,
            ts,
            DrawnRequest {
                scheme,
                host,
                path: drawn_path,
            },
            rng,
        );
        let ov = plan.overrides.as_ref();
        let (scheme, port) = match ov {
            Some(o) if o.force_https => ("https", 443u16),
            // A sub-resource moved onto the open page's host takes that page's
            // scheme; keep the port consistent with it.
            _ if plan.scheme != scheme => {
                let port = if plan.scheme == "https" { 443 } else { 80 };
                (plan.scheme.as_str(), port)
            }
            _ => (plan.scheme.as_str(), port),
        };
        let host = plan.host.as_str();
        let path = plan.path.as_str();
        let method = ov.map_or(method, |o| o.method);
        let full_url = format!("{}://{}{}", scheme, host, path);
        let duration_ms = rng.random_range(5u64..2000);
        let tls_intercepted = scheme == "https" && rng.random_bool(0.70);
        let category = *CATEGORIES.choose(rng).unwrap();
        let category = ov.map_or(category, |o| o.category);
        let cache_status = CACHE_STATUSES.choose(rng).unwrap();
        let content_type = *CONTENT_TYPES.choose(rng).unwrap();
        let content_type = ov.map_or(content_type, |o| o.content_type);

        let (request_bytes, response_bytes) = match status {
            304 => (0u64, 0u64),
            s if s >= 400 => (rng.random_range(0u64..500), rng.random_range(200u64..2000)),
            _ => (
                rng.random_range(0u64..2000),
                rng.random_range(500u64..500000),
            ),
        };
        let response_bytes = match ov {
            Some(o) if status != 304 && status < 400 => {
                rng.random_range(o.response_bytes.0..=o.response_bytes.1)
            }
            _ => response_bytes,
        };

        // Threat scoring — most traffic is benign (tier0, low score)
        let threat_score: f64 = if rng.random_bool(0.92) {
            rng.random_range(0.0..0.15)
        } else if rng.random_bool(0.7) {
            rng.random_range(0.15..0.5)
        } else {
            rng.random_range(0.5..1.0)
        };
        let threat_floor = ov.and_then(|o| o.threat);
        let threat_score = match threat_floor {
            Some((floor, _)) => threat_score.max(floor + threat_score * 0.3),
            None => threat_score,
        };
        let threat_tier = if threat_score < 0.2 {
            "tier0"
        } else if threat_score < 0.5 {
            "tier1"
        } else if threat_score < 0.8 {
            "tier2"
        } else {
            "tier3"
        };
        let threat_blocked = threat_score >= 0.9 && rng.random_bool(0.80);

        let action = if threat_blocked {
            "block"
        } else if status >= 400 {
            "deny"
        } else {
            "allow"
        };

        // Build threat_signals array — always has at least dga_entropy like real logs
        let mut threat_signals = vec![
            serde_json::json!({"name": "dga_entropy", "score": threat_score, "tier": threat_tier}),
        ];
        if let Some((_, signal)) = threat_floor {
            threat_signals.push(
                serde_json::json!({"name": signal, "score": threat_score * 0.9, "tier": threat_tier}),
            );
        } else if threat_score >= 0.5 {
            let extra_signals = [
                "reputation_low",
                "newly_registered",
                "suspicious_tld",
                "high_entropy_subdomain",
            ];
            let sig = extra_signals.choose(rng).unwrap();
            threat_signals.push(
                serde_json::json!({"name": sig, "score": threat_score * 0.8, "tier": threat_tier}),
            );
        }

        let mut log_entry = serde_json::json!({
            "id": Uuid::now_v7().to_string(),
            "timestamp": ts.format("%Y-%m-%dT%H:%M:%S%.9fZ").to_string(),
            "client_ip": entity.ip,
            "username": serde_json::Value::Null,
            "auth_method": serde_json::Value::Null,
            "method": method,
            "scheme": scheme,
            "host": host,
            "port": port,
            "path": path,
            "full_url": full_url,
            "user_agent": plan.user_agent,
            "category": category,
            "action": action,
            "rule_id": serde_json::Value::Null,
            "status_code": status,
            "request_bytes": request_bytes,
            "response_bytes": response_bytes,
            "duration_ms": duration_ms,
            "tls_intercepted": tls_intercepted,
            "upstream_addr": format!("{}:{}", upstream_ip, port),
            "cache_status": cache_status,
            "content_type": content_type,
            "threat_score": threat_score,
            "threat_tier": threat_tier,
            "threat_blocked": threat_blocked,
            "threat_signals": threat_signals,
        });
        // The live proxy omits `referer` when the request had no Referer header.
        if let Some(referer) = &plan.referer {
            log_entry["referer"] = serde_json::Value::from(referer.as_str());
        }

        Event {
            message: serde_json::to_string(&log_entry).unwrap(),
            timestamp: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            source_type: "conduit_proxy".to_string(),
            display_label: format!(
                "[proxy] {} {} {}://{}{} → {}",
                entity.ip, method, scheme, host, path, status
            ),
        }
    }
}

/// Generate a random public IP, avoiding private/reserved ranges.
fn gen_public_ip(rng: &mut impl Rng) -> String {
    loop {
        let a = rng.random_range(1u8..255);
        let b = rng.random_range(0u8..255);
        let c = rng.random_range(0u8..255);
        let d = rng.random_range(1u8..255);
        if a == 10
            || a == 127
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 168)
            || (a == 169 && b == 254)
            || a >= 224
        {
            continue;
        }
        return format!("{}.{}.{}.{}", a, b, c, d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web_session::{ClientProfile, PAGE_PATHS};
    use chrono::Duration;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use std::collections::{HashMap, HashSet};

    fn wire(entities: &[Entity], n: usize, seed: u64) -> Vec<serde_json::Value> {
        let gen = ProxyGenerator::new();
        let mut rng = StdRng::seed_from_u64(seed);
        let t0 = DateTime::parse_from_rfc3339("2026-10-08T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        (0..n)
            .map(|i| {
                let e = &entities[i % entities.len()];
                let ts = t0 + Duration::milliseconds(i as i64 * 400);
                serde_json::from_str(&gen.generate(ts, e, &mut rng).message).unwrap()
            })
            .collect()
    }

    fn fleet() -> Vec<Entity> {
        ["WS-ENG-001", "WS-FIN-002", "LT-HR-003", "SRV-CI01"]
            .iter()
            .enumerate()
            .map(|(i, h)| {
                Entity::new(
                    h,
                    &format!("user{i}"),
                    &format!("10.1.0.{}", i + 10),
                    "00:50:56:00:00:01",
                    "corp.local",
                )
            })
            .collect()
    }

    fn browser_ua(v: &serde_json::Value, entities: &[Entity]) -> bool {
        let ip = v["client_ip"].as_str().unwrap();
        let e = entities.iter().find(|e| e.ip == ip).unwrap();
        ClientProfile::for_host(&e.hostname).browser_ua == v["user_agent"].as_str()
    }

    /// Every referer on a browser sub-resource is a page URL that same client
    /// requested earlier, so `| tree web` gets real parent → child edges.
    #[test]
    fn subresource_referers_point_at_an_earlier_page_of_the_same_client() {
        let entities = fleet();
        let events = wire(&entities, 20_000, 1);
        let mut seen: HashMap<String, HashSet<String>> = HashMap::new();
        let mut checked = 0;
        for v in &events {
            let ip = v["client_ip"].as_str().unwrap().to_string();
            let url = v["full_url"].as_str().unwrap().to_string();
            let path = v["path"].as_str().unwrap();
            if let Some(r) = v.get("referer").and_then(|r| r.as_str()) {
                if !PAGE_PATHS.contains(&path) && !r.contains("mail") {
                    checked += 1;
                    assert!(
                        seen.get(&ip).is_some_and(|s| s.contains(r)),
                        "referer {r} for {url} was never a page of {ip}"
                    );
                }
            }
            seen.entry(ip).or_default().insert(url);
        }
        assert!(checked > 5_000, "only {checked} sub-resources checked");
    }

    #[test]
    fn background_agents_omit_referer_and_browsers_keep_one_ua() {
        let entities = fleet();
        let events = wire(&entities, 20_000, 2);
        let mut browser_uas: HashMap<&str, HashSet<&str>> = HashMap::new();
        let mut background = 0;
        for v in &events {
            assert!(v.get("referrer").is_none(), "legacy key emitted: {v}");
            let ua = v["user_agent"].as_str().expect("user_agent always present");
            if browser_ua(v, &entities) {
                browser_uas
                    .entry(v["client_ip"].as_str().unwrap())
                    .or_default()
                    .insert(ua);
            } else {
                background += 1;
                assert!(v.get("referer").is_none(), "background with referer: {v}");
                assert!(v["referer"].is_null());
            }
        }
        assert!(background > 1_000, "background={background}");
        // The headless Linux CI server has no browser at all.
        assert_eq!(browser_uas.len(), 3);
        assert!(
            browser_uas.values().all(|s| s.len() == 1),
            "{browser_uas:?}"
        );
    }

    #[test]
    fn output_is_deterministic_for_a_seed() {
        let strip = |mut v: serde_json::Value| {
            v.as_object_mut().unwrap().remove("id");
            v
        };
        let a: Vec<_> = wire(&fleet(), 3_000, 77).into_iter().map(strip).collect();
        let b: Vec<_> = wire(&fleet(), 3_000, 77).into_iter().map(strip).collect();
        assert_eq!(a, b);
    }

    #[test]
    fn existing_fields_are_kept() {
        let events = wire(&fleet(), 200, 3);
        for key in [
            "id",
            "timestamp",
            "client_ip",
            "username",
            "auth_method",
            "method",
            "scheme",
            "host",
            "port",
            "path",
            "full_url",
            "user_agent",
            "category",
            "action",
            "rule_id",
            "status_code",
            "request_bytes",
            "response_bytes",
            "duration_ms",
            "tls_intercepted",
            "upstream_addr",
            "cache_status",
            "content_type",
            "threat_score",
            "threat_tier",
            "threat_blocked",
            "threat_signals",
        ] {
            assert!(events.iter().all(|v| v.get(key).is_some()), "missing {key}");
        }
    }
}
