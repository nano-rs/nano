//! Apache HTTP Server access log generator
//!
//! Produces Apache Combined Log Format lines matching what the Vector
//! `apache_http_server` parser expects via `parse_apache_log("combined")`.
//! Format: %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"

use chrono::{DateTime, Utc};
use rand::seq::IndexedRandom;
use rand::Rng;

use crate::entity::Entity;
use crate::event::Event;

const WEB_PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/about",
    "/contact",
    "/login",
    "/api/v1/status",
    "/api/v1/users",
    "/api/v1/search",
    "/dashboard",
    "/settings",
    "/profile",
    "/assets/css/main.css",
    "/assets/js/app.js",
    "/assets/img/logo.png",
    "/favicon.ico",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/docs",
    "/docs/api",
    "/docs/getting-started",
    "/health",
    "/metrics",
    "/api/v1/alerts",
    "/api/v1/events",
    "/api/v1/rules",
    "/reports/weekly",
    "/admin",
    "/admin/users",
    "/admin/settings",
    "/api/v2/ingest",
];

const REFERRERS: &[&str] = &[
    "-",
    "-",
    "-",
    "https://www.google.com/",
    "https://github.com/",
    "https://app.example.com/dashboard",
    "https://app.example.com/login",
    "https://app.example.com/",
];

const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "curl/8.5.0",
    "python-requests/2.31.0",
    "Go-http-client/2.0",
    "Prometheus/2.51.0",
];

const METHODS: &[&str] = &[
    "GET", "GET", "GET", "GET", "GET", "POST", "PUT", "DELETE", "HEAD",
];

/// Status codes weighted toward 200
const STATUS_CODES: &[u16] = &[
    200, 200, 200, 200, 200, 200, 200, 200, 301, 302, 304, 304, 400, 401, 403, 404, 404, 500, 502,
    503,
];

/// Generate a random public IP, avoiding private/reserved ranges.
fn gen_public_ip(rng: &mut impl Rng) -> String {
    loop {
        let a = rng.random_range(1u8..255);
        let b = rng.random_range(0u8..255);
        let c = rng.random_range(0u8..255);
        let d = rng.random_range(1u8..255);
        // Skip private/reserved: 10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x
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

pub struct ApacheGenerator;

impl ApacheGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate an Apache Combined Log Format event
    pub fn generate(
        &self,
        timestamp: DateTime<Utc>,
        _entity: &Entity,
        rng: &mut impl Rng,
    ) -> Event {
        let method = METHODS.choose(rng).unwrap();
        let path = WEB_PATHS.choose(rng).unwrap();
        let status = STATUS_CODES.choose(rng).unwrap();
        let size = match *status {
            304 => 0,
            204 => 0,
            s if s >= 300 && s < 400 => rng.random_range(0u32..200),
            s if s >= 400 => rng.random_range(200u32..2000),
            _ => rng.random_range(500u32..50000),
        };
        let referrer = REFERRERS.choose(rng).unwrap();
        let user_agent = USER_AGENTS.choose(rng).unwrap();

        // Public-facing web server — source IPs are external
        let src_ip = gen_public_ip(rng);

        // Apache Combined Log Format
        // %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"
        let log_line = format!(
            "{} - - [{}] \"{} {} HTTP/1.1\" {} {} \"{}\" \"{}\"",
            src_ip,
            timestamp.format("%d/%b/%Y:%H:%M:%S %z"),
            method,
            path,
            status,
            if size == 0 {
                "-".to_string()
            } else {
                size.to_string()
            },
            referrer,
            user_agent,
        );

        Event {
            message: log_line.clone(),
            timestamp: timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            source_type: "apache_access".to_string(),
            display_label: format!("[apache] {} {} {} {}", src_ip, method, path, status),
        }
    }
}
