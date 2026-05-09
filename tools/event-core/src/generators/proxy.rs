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
        let (_, _referrer, dest_host) = entity.next_browse_request();
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
        let path = PATHS.choose(rng).unwrap();
        let full_url = format!("{}://{}{}", scheme, host, path);
        let duration_ms = rng.random_range(5u64..2000);
        let tls_intercepted = scheme == "https" && rng.random_bool(0.70);
        let category = CATEGORIES.choose(rng).unwrap();
        let cache_status = CACHE_STATUSES.choose(rng).unwrap();
        let content_type = CONTENT_TYPES.choose(rng).unwrap();

        let (request_bytes, response_bytes) = match status {
            304 => (0u64, 0u64),
            s if s >= 400 => (rng.random_range(0u64..500), rng.random_range(200u64..2000)),
            _ => (
                rng.random_range(0u64..2000),
                rng.random_range(500u64..500000),
            ),
        };

        // Threat scoring — most traffic is benign (tier0, low score)
        let threat_score: f64 = if rng.random_bool(0.92) {
            rng.random_range(0.0..0.15)
        } else if rng.random_bool(0.7) {
            rng.random_range(0.15..0.5)
        } else {
            rng.random_range(0.5..1.0)
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
        if threat_score >= 0.5 {
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

        let log_entry = serde_json::json!({
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
