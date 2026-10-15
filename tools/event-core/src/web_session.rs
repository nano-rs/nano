// SPDX-License-Identifier: AGPL-3.0-or-later

//! Per-client web session state for the Conduit proxy generator (NAN-3294).
//!
//! The live Conduit proxy now logs `referer` (omitted when the request had no
//! Referer header) and `user_agent`. `| tree web` builds parent → child edges
//! from `http_request.referrer` → `url`, so the generator has to produce real
//! browsing trees, not random referers:
//!
//! - every client host has a stable [`ClientProfile`]: one browser user agent
//!   (Chrome / Edge / Firefox on Windows for most of the fleet) plus a stable
//!   set of background agents (OS / browser updaters, telemetry, CLI tools);
//! - a page navigation has no referer (typed URL / bookmark) or the previous
//!   page's URL (link click) and becomes the session's current page;
//! - sub-resources (js / css / img / api / xhr) carry `referer` = the current
//!   page's full URL;
//! - background traffic (updaters, telemetry, CLI tools) has no referer;
//! - rarely, a page navigation is a phishing landing page and the client's next
//!   request downloads a payload (`.exe` / `.ps1` / `.zip`) whose referer is
//!   that phishing page.
//!
//! State is one small struct per entity (current page + an optional pending
//! download), so memory is bounded by the fleet size and a plan costs one
//! uncontended mutex and a few RNG draws. Every random choice draws from the
//! caller's RNG, and the per-host profile is a pure hash of the hostname, so a
//! seeded RNG gives byte-identical plans.

use chrono::{DateTime, Duration, Utc};
use rand::seq::IndexedRandom;
use rand::Rng;

use crate::variance::splitmix64;

/// A page stays "open" (eligible as the referer for sub-resources and link
/// clicks) for this long after its navigation.
const PAGE_TTL_SECS: i64 = 600;
/// A phishing download must follow its landing page within this window.
const DOWNLOAD_TTL_SECS: i64 = 180;
/// Probability that a browser page navigation is a phishing landing page.
const PHISH_RATE: f64 = 0.0005;
/// Probability that a phishing landing page leads to a payload download.
const PHISH_DOWNLOAD_RATE: f64 = 0.7;
/// Probability that a navigation is a link click from the open page.
const LINK_CLICK_RATE: f64 = 0.55;
/// Probability that a sub-resource is served by the page's own host (the rest
/// go to the drawn third-party host: CDNs, APIs, analytics).
const SAME_HOST_SUBRESOURCE_RATE: f64 = 0.65;

/// Paths from the generator's path table that are top-level page navigations.
pub const PAGE_PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/login",
    "/search",
    "/feed",
    "/settings",
];

/// Paths that browsers fetch without a page context (no Referer header).
const DIRECT_PATHS: &[&str] = &["/robots.txt", "/.well-known/security.txt"];

/// What kind of request a plan describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    /// Top-level page navigation (typed / bookmark / link click).
    Page,
    /// js / css / img / font / api / xhr loaded by the current page.
    SubResource,
    /// Browser request with no page context (robots.txt, security.txt).
    Direct,
    /// Updater / telemetry / CLI traffic, never with a referer.
    Background,
    /// Phishing landing page (a page navigation).
    PhishLanding,
    /// Payload download from a phishing page.
    PhishDownload,
}

/// Field overrides for requests whose shape is not the generic browsing mix.
#[derive(Debug, Clone)]
pub struct RequestOverride {
    pub method: &'static str,
    pub content_type: &'static str,
    pub category: &'static str,
    pub response_bytes: (u64, u64),
    /// Minimum threat score and the extra signal to report with it.
    pub threat: Option<(f64, &'static str)>,
    pub force_https: bool,
}

/// One planned Conduit request: the URL parts, `referer`, and `user_agent`.
#[derive(Debug, Clone)]
pub struct RequestPlan {
    pub kind: RequestKind,
    pub scheme: String,
    pub host: String,
    pub path: String,
    pub referer: Option<String>,
    pub user_agent: &'static str,
    pub overrides: Option<RequestOverride>,
}

impl RequestPlan {
    pub fn full_url(&self) -> String {
        format!("{}://{}{}", self.scheme, self.host, self.path)
    }
}

// =============================================================================
// User agents and background agents
// =============================================================================

const WINDOWS_BROWSERS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.3541.52",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36 Edg/155.0.3541.52",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36 Edg/154.0.3485.81",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:150.0) Gecko/20100101 Firefox/150.0",
];

const MAC_BROWSERS: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15",
];

const LINUX_BROWSERS: &[&str] = &[
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:150.0) Gecko/20100101 Firefox/150.0",
];

/// Browser UA used when a client without a browser (a Linux server) is the
/// subject of a scripted browser campaign.
pub const DEFAULT_BROWSER_UA: &str = WINDOWS_BROWSERS[0];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientOs {
    Windows,
    Mac,
    Linux,
}

/// A non-browser HTTP client: its UA, where it talks to, and its response shape.
#[derive(Debug)]
pub struct BackgroundAgent {
    pub user_agent: &'static str,
    pub host: &'static str,
    pub paths: &'static [&'static str],
    pub method: &'static str,
    pub content_type: &'static str,
    pub category: &'static str,
    pub response_bytes: (u64, u64),
    /// CLI tools are only installed on developer / admin hosts.
    pub cli: bool,
}

#[allow(clippy::too_many_arguments)]
const fn agent(
    user_agent: &'static str,
    host: &'static str,
    paths: &'static [&'static str],
    method: &'static str,
    content_type: &'static str,
    category: &'static str,
    response_bytes: (u64, u64),
    cli: bool,
) -> BackgroundAgent {
    BackgroundAgent {
        user_agent,
        host,
        paths,
        method,
        content_type,
        category,
        response_bytes,
        cli,
    }
}

const WINDOWS_AGENTS: &[BackgroundAgent] = &[
    agent(
        "Windows-Update-Agent/1022.2507.17012.0 Client-Protocol/2.81",
        "fe2.update.microsoft.com",
        &["/v6/ClientWebService/client.asmx", "/v6/ClientWebService/client.asmx/GetCookie"],
        "POST",
        "application/soap+xml",
        "software_updates",
        (2_000, 60_000),
        false,
    ),
    agent(
        "Microsoft-Delivery-Optimization/10.0",
        "tlu.dl.delivery.mp.microsoft.com",
        &[
            "/filestreamingservice/files/3f1c8a2e-7d4b-4e0a-9c55-1b2f6a9e0d41?P1=1791472800&P2=404&P3=2&P4=Yk3q",
            "/filestreamingservice/files/a7e90b13-52c8-4f61-8e2d-90c4b7d3f218?P1=1791476400&P2=404&P3=2&P4=Wm8x",
            "/filestreamingservice/files/0c5d2f77-19ab-4c3e-b6f0-e4a8d1c97b52?P1=1791480000&P2=404&P3=2&P4=Qz2r",
        ],
        "GET",
        "application/octet-stream",
        "software_updates",
        (500_000, 25_000_000),
        false,
    ),
    agent(
        "Microsoft Edge Update/1.3.199.29;winhttp",
        "msedge.api.cdp.microsoft.com",
        &["/api/v2/contents/Browser/namespaces/Default/names/msedge-stable-win-x64/versions/latest?action=select"],
        "POST",
        "application/json",
        "software_updates",
        (300, 2_000),
        false,
    ),
    agent(
        "GoogleUpdater 155.0.7391.0",
        "update.googleapis.com",
        &["/service/update2/json", "/service/update2/json?cup2key=14:1840226711"],
        "POST",
        "application/json",
        "software_updates",
        (400, 4_000),
        false,
    ),
    agent(
        "MSDW",
        "v10.events.data.microsoft.com",
        &["/OneCollector/1.0/", "/onecollector/1.0/?cors=true"],
        "POST",
        "application/json",
        "telemetry",
        (9, 200),
        false,
    ),
    agent(
        "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.26100.6584",
        "www.powershellgallery.com",
        &["/api/v2/FindPackagesById()?id='PSReadLine'", "/api/v2/package/Az.Accounts/5.3.0"],
        "GET",
        "application/xml",
        "developer_tools",
        (2_000, 400_000),
        true,
    ),
    agent(
        "curl/8.14.1",
        "raw.githubusercontent.com",
        &["/microsoft/winget-pkgs/master/README.md", "/PowerShell/PowerShell/master/tools/install-powershell.ps1"],
        "GET",
        "text/plain",
        "developer_tools",
        (1_000, 60_000),
        true,
    ),
    agent(
        "python-requests/2.32.5",
        "pypi.org",
        &["/simple/requests/", "/simple/urllib3/", "/pypi/boto3/json"],
        "GET",
        "application/vnd.pypi.simple.v1+json",
        "developer_tools",
        (5_000, 300_000),
        true,
    ),
    agent(
        "codex-tui/0.161.0 (Windows 10.0.26100; x86_64) WindowsTerminal",
        "api.openai.com",
        &["/v1/responses"],
        "POST",
        "text/event-stream",
        "ai_ml",
        (2_000, 120_000),
        true,
    ),
];

const MAC_AGENTS: &[BackgroundAgent] = &[
    agent(
        "com.apple.trustd/3.0",
        "ocsp2.apple.com",
        &["/ocsp03-apevsrsa2g101/ME4wTKADAgEAMEUwQzBBMAkGBSsOAwIaBQAEFDOB0e%2FbaLCFIU0u76%2BMSmlkPCpsBBRYuF5u"],
        "GET",
        "application/ocsp-response",
        "security_pki",
        (1_000, 3_000),
        false,
    ),
    agent(
        "softwareupdated (unknown version) CFNetwork/3860.100.1 Darwin/25.1.0",
        "swscan.apple.com",
        &["/content/catalogs/others/index-26-15-14-13-12-10.16-10.15-10.14-10.13.merged-1.sucatalog.gz"],
        "GET",
        "application/x-gzip",
        "software_updates",
        (200_000, 4_000_000),
        false,
    ),
    agent(
        "GoogleUpdater 155.0.7391.0",
        "update.googleapis.com",
        &["/service/update2/json"],
        "POST",
        "application/json",
        "software_updates",
        (400, 4_000),
        false,
    ),
    agent(
        "curl/8.7.1",
        "raw.githubusercontent.com",
        &["/Homebrew/install/HEAD/install.sh"],
        "GET",
        "text/plain",
        "developer_tools",
        (10_000, 40_000),
        true,
    ),
    agent(
        "codex-tui/0.161.0 (Mac OS 26.1.0; arm64) iTerm.app/3.6.4",
        "api.openai.com",
        &["/v1/responses"],
        "POST",
        "text/event-stream",
        "ai_ml",
        (2_000, 120_000),
        true,
    ),
];

const LINUX_AGENTS: &[BackgroundAgent] = &[
    agent(
        "Debian APT-HTTP/1.3 (2.6.1)",
        "deb.debian.org",
        &[
            "/debian/dists/bookworm/InRelease",
            "/debian/dists/bookworm-updates/InRelease",
            "/debian-security/dists/bookworm-security/InRelease",
        ],
        "GET",
        "application/octet-stream",
        "software_updates",
        (2_000, 160_000),
        false,
    ),
    agent(
        "curl/7.88.1",
        "raw.githubusercontent.com",
        &[
            "/helm/helm/main/scripts/get-helm-3",
            "/nvm-sh/nvm/v0.40.3/install.sh",
        ],
        "GET",
        "text/plain",
        "developer_tools",
        (5_000, 40_000),
        true,
    ),
    agent(
        "python-requests/2.28.1",
        "pypi.org",
        &["/simple/requests/", "/simple/certifi/"],
        "GET",
        "application/vnd.pypi.simple.v1+json",
        "developer_tools",
        (5_000, 300_000),
        true,
    ),
    agent(
        "Go-http-client/1.1",
        "api.github.com",
        &[
            "/repos/prometheus/node_exporter/releases/latest",
            "/repos/grafana/alloy/releases/latest",
        ],
        "GET",
        "application/json",
        "developer_tools",
        (2_000, 40_000),
        true,
    ),
    agent(
        "codex-tui/0.161.0 (Linux 6.12.48; x86_64) xterm-256color",
        "api.openai.com",
        &["/v1/responses"],
        "POST",
        "text/event-stream",
        "ai_ml",
        (2_000, 120_000),
        true,
    ),
];

// =============================================================================
// Phishing chains
// =============================================================================

const PHISH_HOSTS: &[&str] = &[
    "microsoft365-docview.com",
    "secure-docusign-review.net",
    "sharepoint-files-access.top",
    "invoice-portal-billing.xyz",
    "onedrive-shared-docs.click",
];

const PHISH_PAGES: &[&str] = &[
    "/view/document?id=8f2c91",
    "/s/a91d0c2/review",
    "/shared/Q3_Invoice",
    "/auth/office365/login.php",
];

/// Where users come from to a phishing page (webmail link), or `None` (link
/// opened from a desktop mail client: no Referer header).
const PHISH_SOURCES: &[Option<&str>] = &[
    Some("https://outlook.office365.com/mail/inbox"),
    Some("https://outlook.office365.com/mail/inbox"),
    Some("https://mail.google.com/mail/u/0/"),
    None,
];

const PHISH_PAYLOADS: &[(&str, &str)] = &[
    ("/download/Invoice_2026-10.zip", "application/zip"),
    ("/files/DocuSign_Review.exe", "application/x-msdownload"),
    ("/dl/update_viewer.ps1", "text/plain"),
    ("/download/Q3_Statement.zip", "application/zip"),
    ("/get/OneDriveSetup.exe", "application/x-msdownload"),
];

// =============================================================================
// Client profile
// =============================================================================

/// Stable per-host client identity: browser UA and background agents.
#[derive(Debug, Clone)]
pub struct ClientProfile {
    pub os: ClientOs,
    /// `None` for headless hosts (Linux servers): every request is background.
    pub browser_ua: Option<&'static str>,
    pub agents: Vec<&'static BackgroundAgent>,
    pub background_rate: f64,
}

/// FNV-1a over the hostname, finished with SplitMix64.
fn host_seed(hostname: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in hostname.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    splitmix64(h)
}

/// Deterministic unit float for (host seed, salt).
fn unit(seed: u64, salt: u64) -> f64 {
    (splitmix64(seed ^ splitmix64(salt)) >> 11) as f64 / (1u64 << 53) as f64
}

fn pick<T: Copy>(seed: u64, salt: u64, items: &[T]) -> T {
    items[(splitmix64(seed ^ splitmix64(salt)) % items.len() as u64) as usize]
}

/// Windows server roles; every other `SRV-*` role is a Linux box.
const WINDOWS_SERVER_ROLES: &[&str] = &["DC", "FILE", "MAIL", "LDAP", "WSUS"];

impl ClientProfile {
    /// Pure function of the hostname: the same host always gets the same
    /// browser and background agents, regardless of RNG state.
    pub fn for_host(hostname: &str) -> Self {
        let seed = host_seed(hostname);
        let upper = hostname.to_ascii_uppercase();

        if let Some(role) = upper.strip_prefix("SRV-") {
            let role = role.trim_end_matches(|c: char| c.is_ascii_digit());
            let windows = WINDOWS_SERVER_ROLES.contains(&role);
            let (os, pool) = if windows {
                (ClientOs::Windows, WINDOWS_AGENTS)
            } else {
                (ClientOs::Linux, LINUX_AGENTS)
            };
            // Servers: updaters plus admin CLI tools; Windows servers have an
            // Edge for the occasional admin browsing session.
            let agents = pool.iter().collect::<Vec<_>>();
            return Self {
                os,
                browser_ua: windows.then_some(WINDOWS_BROWSERS[3]),
                agents,
                background_rate: if windows { 0.85 } else { 1.0 },
            };
        }

        let os_roll = unit(seed, 1);
        let os = if upper.starts_with("LT-") {
            if os_roll < 0.80 {
                ClientOs::Windows
            } else if os_roll < 0.95 {
                ClientOs::Mac
            } else {
                ClientOs::Linux
            }
        } else if os_roll < 0.96 {
            ClientOs::Windows
        } else {
            ClientOs::Linux
        };
        let (browsers, pool) = match os {
            ClientOs::Windows => (WINDOWS_BROWSERS, WINDOWS_AGENTS),
            ClientOs::Mac => (MAC_BROWSERS, MAC_AGENTS),
            ClientOs::Linux => (LINUX_BROWSERS, LINUX_AGENTS),
        };
        let browser = pick(seed, 2, browsers);

        // Developer / admin hosts run CLI tools: all of ENG and IT, plus a
        // minority elsewhere.
        let technical = upper.contains("-ENG-") || upper.contains("-IT-");
        let dev = (technical && unit(seed, 3) < 0.85) || unit(seed, 3) < 0.08;

        let agents = pool
            .iter()
            .enumerate()
            .filter(|(i, a)| {
                if a.cli {
                    // Each dev host has its own subset of CLI tools.
                    dev && unit(seed, 100 + *i as u64) < 0.6
                } else {
                    // GoogleUpdater only where Chrome is the browser; Edge
                    // Update ships with Windows, so every Windows host has it.
                    !a.user_agent.starts_with("GoogleUpdater")
                        || (browser.contains("Chrome/") && !browser.contains("Edg/"))
                }
            })
            .map(|(_, a)| a)
            .collect::<Vec<_>>();

        Self {
            os,
            browser_ua: Some(browser),
            agents,
            background_rate: if dev { 0.18 } else { 0.08 },
        }
    }

    /// Browser UA for browser-shaped requests; headless hosts fall back to the
    /// fleet default so a scripted browser campaign still carries a UA.
    pub fn browser_user_agent(&self) -> &'static str {
        self.browser_ua.unwrap_or(DEFAULT_BROWSER_UA)
    }
}

// =============================================================================
// Session
// =============================================================================

#[derive(Debug, Clone)]
struct OpenPage {
    url: String,
    scheme: String,
    host: String,
    at: DateTime<Utc>,
}

#[derive(Debug, Clone)]
struct PendingDownload {
    landing_url: String,
    host: &'static str,
    path: &'static str,
    content_type: &'static str,
    at: DateTime<Utc>,
}

/// Per-entity browsing state. Bounded: one open page and at most one pending
/// phishing download.
#[derive(Debug, Default)]
pub struct WebSession {
    profile: Option<ClientProfile>,
    page: Option<OpenPage>,
    pending_download: Option<PendingDownload>,
}

/// The URL parts the generator drew from its existing distributions.
#[derive(Debug, Clone, Copy)]
pub struct DrawnRequest<'a> {
    pub scheme: &'a str,
    pub host: &'a str,
    pub path: &'a str,
}

impl WebSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn profile(&mut self, hostname: &str) -> &ClientProfile {
        self.profile
            .get_or_insert_with(|| ClientProfile::for_host(hostname))
    }

    fn live_page(&self, ts: DateTime<Utc>) -> Option<&OpenPage> {
        self.page.as_ref().filter(|p| {
            ts - p.at <= Duration::seconds(PAGE_TTL_SECS) && ts >= p.at - Duration::seconds(5)
        })
    }

    /// Plan the next request for this client. `drawn` carries the host / path
    /// the generator drew from its existing distributions; the plan keeps them
    /// unless the request is background or phishing traffic, or a sub-resource
    /// served by the open page's own host.
    pub fn plan(
        &mut self,
        hostname: &str,
        ts: DateTime<Utc>,
        drawn: DrawnRequest<'_>,
        rng: &mut impl Rng,
    ) -> RequestPlan {
        let profile = self
            .profile
            .get_or_insert_with(|| ClientProfile::for_host(hostname));
        let ua = profile.browser_user_agent();

        // 1. A phishing landing page leads straight to its payload.
        if let Some(dl) = self.pending_download.take() {
            if ts - dl.at <= Duration::seconds(DOWNLOAD_TTL_SECS) && ts >= dl.at {
                return RequestPlan {
                    kind: RequestKind::PhishDownload,
                    scheme: "https".into(),
                    host: dl.host.to_string(),
                    path: dl.path.to_string(),
                    referer: Some(dl.landing_url),
                    user_agent: ua,
                    overrides: Some(RequestOverride {
                        method: "GET",
                        content_type: dl.content_type,
                        category: "uncategorized",
                        response_bytes: (150_000, 6_000_000),
                        threat: Some((0.6, "newly_registered")),
                        force_https: true,
                    }),
                };
            }
        }

        // 2. Background agents: updaters, telemetry, CLI tools. Never a referer.
        if !profile.agents.is_empty()
            && (profile.browser_ua.is_none() || rng.random_bool(profile.background_rate))
        {
            let a = *profile.agents.choose(rng).expect("non-empty");
            let path = *a.paths.choose(rng).expect("agent paths");
            return RequestPlan {
                kind: RequestKind::Background,
                scheme: "https".into(),
                host: a.host.to_string(),
                path: path.to_string(),
                referer: None,
                user_agent: a.user_agent,
                overrides: Some(RequestOverride {
                    method: a.method,
                    content_type: a.content_type,
                    category: a.category,
                    response_bytes: a.response_bytes,
                    threat: None,
                    force_https: true,
                }),
            };
        }

        // 3. Browser traffic.
        if DIRECT_PATHS.contains(&drawn.path) {
            return RequestPlan {
                kind: RequestKind::Direct,
                scheme: drawn.scheme.to_string(),
                host: drawn.host.to_string(),
                path: drawn.path.to_string(),
                referer: None,
                user_agent: ua,
                overrides: None,
            };
        }

        if !PAGE_PATHS.contains(&drawn.path) {
            if let Some(page) = self.live_page(ts) {
                let (scheme, host) = if rng.random_bool(SAME_HOST_SUBRESOURCE_RATE) {
                    (page.scheme.clone(), page.host.clone())
                } else {
                    (drawn.scheme.to_string(), drawn.host.to_string())
                };
                return RequestPlan {
                    kind: RequestKind::SubResource,
                    scheme,
                    host,
                    path: drawn.path.to_string(),
                    referer: Some(page.url.clone()),
                    user_agent: ua,
                    overrides: None,
                };
            }
            // No open page: a sub-resource cannot come first, so this request
            // is the navigation that opens one.
        }

        let path = if PAGE_PATHS.contains(&drawn.path) {
            drawn.path
        } else {
            PAGE_PATHS.choose(rng).expect("page paths")
        };

        // 4. Rare phishing landing page, optionally followed by a download.
        if rng.random_bool(PHISH_RATE) {
            let host = *PHISH_HOSTS.choose(rng).expect("phish hosts");
            let page_path = *PHISH_PAGES.choose(rng).expect("phish pages");
            let source = *PHISH_SOURCES.choose(rng).expect("phish sources");
            let url = format!("https://{host}{page_path}");
            if rng.random_bool(PHISH_DOWNLOAD_RATE) {
                let (dl_path, ct) = *PHISH_PAYLOADS.choose(rng).expect("payloads");
                self.pending_download = Some(PendingDownload {
                    landing_url: url.clone(),
                    host,
                    path: dl_path,
                    content_type: ct,
                    at: ts,
                });
            }
            self.page = Some(OpenPage {
                url,
                scheme: "https".into(),
                host: host.to_string(),
                at: ts,
            });
            return RequestPlan {
                kind: RequestKind::PhishLanding,
                scheme: "https".into(),
                host: host.to_string(),
                path: page_path.to_string(),
                referer: source.map(str::to_string),
                user_agent: ua,
                overrides: Some(RequestOverride {
                    method: "GET",
                    content_type: "text/html",
                    category: "uncategorized",
                    response_bytes: (8_000, 90_000),
                    threat: Some((0.55, "newly_registered")),
                    force_https: true,
                }),
            };
        }

        // 5. Ordinary navigation: link click from the open page, or typed /
        //    bookmarked (no referer).
        let mut plan = RequestPlan {
            kind: RequestKind::Page,
            scheme: drawn.scheme.to_string(),
            host: drawn.host.to_string(),
            path: path.to_string(),
            referer: None,
            user_agent: ua,
            overrides: None,
        };
        if let Some(p) = self.live_page(ts) {
            // A link to the page itself would be a self-loop in the tree.
            if rng.random_bool(LINK_CLICK_RATE) && p.url != plan.full_url() {
                plan.referer = Some(p.url.clone());
            }
        }
        self.page = Some(OpenPage {
            url: plan.full_url(),
            scheme: plan.scheme.clone(),
            host: plan.host.clone(),
            at: ts,
        });
        plan
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const DRAWN_PATHS: &[&str] = &[
        "/",
        "/index.html",
        "/api/v1/status",
        "/assets/main.js",
        "/assets/style.css",
        "/favicon.ico",
        "/robots.txt",
        "/login",
        "/images/logo.png",
        "/fonts/inter.woff2",
    ];

    fn run(hostname: &str, n: usize, seed: u64) -> Vec<RequestPlan> {
        let mut rng = StdRng::seed_from_u64(seed);
        let mut s = WebSession::new();
        let t0 = DateTime::parse_from_rfc3339("2026-10-08T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        (0..n)
            .map(|i| {
                let path = *DRAWN_PATHS.choose(&mut rng).unwrap();
                let host = *["github.com", "cdn.jsdelivr.net", "bbc.com"]
                    .choose(&mut rng)
                    .unwrap();
                let ts = t0 + Duration::milliseconds(i as i64 * 1500);
                s.plan(
                    hostname,
                    ts,
                    DrawnRequest {
                        scheme: "https",
                        host,
                        path,
                    },
                    &mut rng,
                )
            })
            .collect()
    }

    #[test]
    fn subresources_reference_their_page() {
        let plans = run("WS-SALES-001", 5_000, 7);
        let mut page: Option<String> = None;
        let mut subs = 0;
        for p in &plans {
            match p.kind {
                RequestKind::Page | RequestKind::PhishLanding => page = Some(p.full_url()),
                RequestKind::SubResource => {
                    subs += 1;
                    assert_eq!(p.referer.as_deref(), page.as_deref(), "{p:?}");
                }
                _ => {}
            }
        }
        assert!(
            subs > 1_000,
            "expected a sub-resource-heavy mix, got {subs}"
        );
    }

    #[test]
    fn navigations_chain_from_previous_page() {
        let plans = run("WS-HR-002", 5_000, 11);
        let mut page: Option<String> = None;
        let (mut clicks, mut typed) = (0, 0);
        for p in &plans {
            if p.kind == RequestKind::Page {
                match &p.referer {
                    Some(r) => {
                        assert_eq!(Some(r), page.as_ref());
                        assert_ne!(r, &p.full_url(), "self-loop");
                        clicks += 1;
                    }
                    None => typed += 1,
                }
                page = Some(p.full_url());
            } else if p.kind == RequestKind::PhishLanding {
                page = Some(p.full_url());
            }
        }
        assert!(clicks > 0 && typed > 0, "clicks={clicks} typed={typed}");
    }

    #[test]
    fn background_traffic_has_no_referer() {
        for host in ["WS-ENG-001", "LT-IT-003", "SRV-WEB01", "SRV-DC01"] {
            let plans = run(host, 3_000, 3);
            let bg: Vec<_> = plans
                .iter()
                .filter(|p| p.kind == RequestKind::Background)
                .collect();
            assert!(!bg.is_empty(), "{host}: no background traffic");
            for p in bg {
                assert!(p.referer.is_none(), "{p:?}");
                assert!(!p
                    .user_agent
                    .starts_with("Mozilla/5.0 (Windows NT 10.0; Win64"));
            }
        }
        // Headless Linux servers send only background traffic.
        assert!(run("SRV-WEB01", 500, 5)
            .iter()
            .all(|p| p.kind == RequestKind::Background));
    }

    #[test]
    fn user_agents_are_stable_per_host() {
        for host in ["WS-ENG-001", "WS-FIN-014", "LT-MKT-002"] {
            let browser_uas: std::collections::HashSet<_> = run(host, 2_000, 9)
                .into_iter()
                .filter(|p| p.kind != RequestKind::Background)
                .map(|p| p.user_agent)
                .collect();
            assert_eq!(browser_uas.len(), 1, "{host}: {browser_uas:?}");
            assert_eq!(
                browser_uas.into_iter().next().unwrap(),
                ClientProfile::for_host(host).browser_user_agent()
            );
        }
        let fleet: std::collections::HashSet<_> = (0..300)
            .map(|i| ClientProfile::for_host(&format!("WS-OPS-{i:03}")).browser_user_agent())
            .collect();
        assert!(fleet.len() >= 4, "fleet UA mix too narrow: {fleet:?}");
        let windows = (0..300)
            .filter(|i| ClientProfile::for_host(&format!("WS-OPS-{i:03}")).os == ClientOs::Windows)
            .count();
        assert!(
            windows > 270,
            "workstations should be mostly Windows: {windows}"
        );
    }

    #[test]
    fn plans_are_deterministic_for_a_seed() {
        let a = run("LT-ENG-004", 2_000, 42);
        let b = run("LT-ENG-004", 2_000, 42);
        let key = |p: &RequestPlan| (p.full_url(), p.referer.clone(), p.user_agent);
        assert!(a.iter().map(key).eq(b.iter().map(key)));
    }

    #[test]
    fn phishing_page_leads_to_payload_download() {
        let mut downloads = 0;
        for i in 0..40 {
            let plans = run(&format!("WS-SALES-{i:03}"), 5_000, 100 + i);
            for (j, p) in plans.iter().enumerate() {
                if p.kind == RequestKind::PhishDownload {
                    downloads += 1;
                    let landing = &plans[j - 1];
                    assert_eq!(landing.kind, RequestKind::PhishLanding);
                    assert_eq!(p.referer.as_deref(), Some(landing.full_url().as_str()));
                    assert!(
                        [".exe", ".ps1", ".zip"]
                            .iter()
                            .any(|ext| p.path.ends_with(ext)),
                        "{p:?}"
                    );
                }
            }
        }
        assert!(downloads > 0, "no phishing download in 200k requests");
    }
}
