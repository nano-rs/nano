//! World state — entities, process trees, and browsing sessions
//!
//! Extracted from the original log-blaster state.rs.
//! Generates a deterministic population of network entities (workstations,
//! laptops, servers) with realistic hostnames, IPs, MACs, and users.

use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use rand::seq::IndexedRandom;
use rand::Rng;
use serde::Serialize;
use std::collections::HashMap;
use uuid::Uuid;

// =============================================================================
// Constants
// =============================================================================

const MAC_PREFIXES: &[&str] = &["00:50:56", "00:0c:29", "00:1c:42", "00:15:5d", "ac:de:48"];
const INTERFACES: &[&str] = &["eth0", "Ethernet", "Wi-Fi"];

const DEPARTMENTS: &[&str] = &[
    "ENG", "SALES", "HR", "FIN", "IT", "MKT", "LEGAL", "OPS", "EXEC", "SUPPORT",
];

const TITLES: &[&str] = &[
    "Engineer", "Senior Engineer", "Manager", "Director", "Analyst", "Specialist",
    "Coordinator", "Lead", "Administrator", "Associate",
];

const SERVER_ROLES: &[&str] = &[
    "WEB", "DB", "DC", "FILE", "MAIL", "DNS", "APP", "CI", "MON", "LOG", "PROXY", "VPN", "NTP",
    "LDAP", "WSUS",
];

const FIRST_NAMES: &[&str] = &[
    "james",
    "mary",
    "john",
    "patricia",
    "robert",
    "jennifer",
    "michael",
    "linda",
    "david",
    "elizabeth",
    "william",
    "barbara",
    "richard",
    "susan",
    "joseph",
    "jessica",
    "thomas",
    "sarah",
    "charles",
    "karen",
    "christopher",
    "lisa",
    "daniel",
    "nancy",
    "matthew",
    "betty",
    "anthony",
    "margaret",
    "mark",
    "sandra",
    "donald",
    "ashley",
    "steven",
    "kimberly",
    "paul",
    "emily",
    "andrew",
    "donna",
    "joshua",
    "michelle",
    "kevin",
    "carol",
    "brian",
    "amanda",
    "george",
    "dorothy",
    "timothy",
    "melissa",
    "ronald",
    "deborah",
];

const LAST_NAMES: &[&str] = &[
    "smith",
    "johnson",
    "williams",
    "brown",
    "jones",
    "garcia",
    "miller",
    "davis",
    "rodriguez",
    "martinez",
    "hernandez",
    "lopez",
    "gonzalez",
    "wilson",
    "anderson",
    "thomas",
    "taylor",
    "moore",
    "jackson",
    "martin",
    "lee",
    "perez",
    "thompson",
    "white",
    "harris",
    "sanchez",
    "clark",
    "ramirez",
    "lewis",
    "robinson",
    "walker",
    "young",
    "allen",
    "king",
    "wright",
    "scott",
    "torres",
    "nguyen",
    "hill",
    "flores",
    "green",
    "adams",
    "nelson",
    "baker",
    "hall",
    "rivera",
    "campbell",
    "mitchell",
    "carter",
    "roberts",
];

// =============================================================================
// Process Tree
// =============================================================================

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct Process {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub user: String,
    pub parent_pid: u32,
    pub parent_name: String,
    pub cmdline: String,
    pub guid: String,
}

#[derive(Debug)]
#[allow(dead_code)]
pub struct ProcessTree {
    processes: HashMap<u32, Process>,
    active_user_pids: Vec<u32>,
    pid_counter: u32,
}

#[allow(dead_code)]
impl ProcessTree {
    pub fn new(user: &str) -> Self {
        let mut tree = Self {
            processes: HashMap::new(),
            active_user_pids: Vec::new(),
            pid_counter: 1000,
        };
        tree.init_system_processes(user);
        tree
    }

    fn init_system_processes(&mut self, default_user: &str) {
        let mut rng = rand::rng();

        let system_procs = [
            (4, "System", "System", r"NT AUTHORITY\SYSTEM", 0, ""),
            (
                88 + rng.random_range(0..50),
                "smss.exe",
                r"C:\Windows\System32\smss.exe",
                r"NT AUTHORITY\SYSTEM",
                4,
                "System",
            ),
            (
                400 + rng.random_range(0..100),
                "csrss.exe",
                r"C:\Windows\System32\csrss.exe",
                r"NT AUTHORITY\SYSTEM",
                88,
                "smss.exe",
            ),
            (
                500 + rng.random_range(0..50),
                "wininit.exe",
                r"C:\Windows\System32\wininit.exe",
                r"NT AUTHORITY\SYSTEM",
                400,
                "csrss.exe",
            ),
            (
                550 + rng.random_range(0..50),
                "services.exe",
                r"C:\Windows\System32\services.exe",
                r"NT AUTHORITY\SYSTEM",
                500,
                "wininit.exe",
            ),
            (
                600 + rng.random_range(0..50),
                "lsass.exe",
                r"C:\Windows\System32\lsass.exe",
                r"NT AUTHORITY\SYSTEM",
                550,
                "services.exe",
            ),
            (
                700 + rng.random_range(0..50),
                "winlogon.exe",
                r"C:\Windows\System32\winlogon.exe",
                r"NT AUTHORITY\SYSTEM",
                400,
                "csrss.exe",
            ),
        ];

        for (pid, name, path, user, ppid, pname) in system_procs {
            self.processes.insert(
                pid,
                Process {
                    pid,
                    name: name.to_string(),
                    path: path.to_string(),
                    user: user.to_string(),
                    parent_pid: ppid,
                    parent_name: pname.to_string(),
                    cmdline: if path == "System" {
                        name.to_string()
                    } else {
                        format!("\"{}\"", path)
                    },
                    guid: Uuid::now_v7().to_string(),
                },
            );
        }

        let services_pid = self
            .find_by_name("services.exe")
            .map(|p| p.pid)
            .unwrap_or(550);
        for i in 0..rng.random_range(6..12) {
            let svc_pid = 800 + i * rng.random_range(50..150);
            let svc_group = match i % 4 {
                0 => "-k netsvcs",
                1 => "-k LocalServiceNetworkRestricted",
                2 => "-k DcomLaunch",
                _ => "-k LocalSystemNetworkRestricted",
            };
            self.processes.insert(
                svc_pid,
                Process {
                    pid: svc_pid,
                    name: "svchost.exe".to_string(),
                    path: r"C:\Windows\System32\svchost.exe".to_string(),
                    user: r"NT AUTHORITY\SYSTEM".to_string(),
                    parent_pid: services_pid,
                    parent_name: "services.exe".to_string(),
                    cmdline: format!(r#""C:\Windows\System32\svchost.exe" {}"#, svc_group),
                    guid: Uuid::now_v7().to_string(),
                },
            );
        }

        let winlogon_pid = self
            .find_by_name("winlogon.exe")
            .map(|p| p.pid)
            .unwrap_or(700);
        let explorer_pid = 3000 + rng.random_range(0..2000);
        self.processes.insert(
            explorer_pid,
            Process {
                pid: explorer_pid,
                name: "explorer.exe".to_string(),
                path: r"C:\Windows\explorer.exe".to_string(),
                user: default_user.to_string(),
                parent_pid: winlogon_pid,
                parent_name: "winlogon.exe".to_string(),
                cmdline: r#""C:\Windows\explorer.exe""#.to_string(),
                guid: Uuid::now_v7().to_string(),
            },
        );
        self.active_user_pids.push(explorer_pid);
        self.pid_counter = 5000 + rng.random_range(0..2000);
    }

    fn get_next_pid(&mut self) -> u32 {
        let mut rng = rand::rng();
        self.pid_counter += rng.random_range(4..=40);
        self.pid_counter
    }

    pub fn find_by_name(&self, name: &str) -> Option<&Process> {
        self.processes.values().find(|p| p.name == name)
    }

    pub fn random_active_parent(&self) -> Option<&Process> {
        let mut rng = rand::rng();
        self.active_user_pids
            .choose(&mut rng)
            .and_then(|pid| self.processes.get(pid))
    }

    pub fn get_explorer(&self) -> Option<&Process> {
        self.find_by_name("explorer.exe")
    }

    pub fn random_svchost(&self) -> Option<&Process> {
        let mut rng = rand::rng();
        let svchosts: Vec<_> = self
            .processes
            .values()
            .filter(|p| p.name == "svchost.exe")
            .collect();
        svchosts.choose(&mut rng).copied()
    }

    pub fn spawn(
        &mut self,
        name: &str,
        path: &str,
        cmdline: &str,
        user: &str,
        parent_pid: u32,
    ) -> Process {
        let pid = self.get_next_pid();
        let parent = self
            .processes
            .get(&parent_pid)
            .or_else(|| self.get_explorer())
            .cloned()
            .unwrap_or_else(|| self.processes.get(&4).cloned().unwrap());

        let proc = Process {
            pid,
            name: name.to_string(),
            path: path.to_string(),
            user: user.to_string(),
            parent_pid: parent.pid,
            parent_name: parent.name.clone(),
            cmdline: cmdline.to_string(),
            guid: Uuid::now_v7().to_string(),
        };

        self.processes.insert(pid, proc.clone());

        let can_spawn_children = matches!(
            name,
            "explorer.exe"
                | "cmd.exe"
                | "powershell.exe"
                | "pwsh.exe"
                | "chrome.exe"
                | "msedge.exe"
                | "firefox.exe"
                | "code.exe"
                | "outlook.exe"
                | "teams.exe"
                | "slack.exe"
                | "wscript.exe"
                | "cscript.exe"
                | "msiexec.exe"
                | "rundll32.exe"
                | "conhost.exe"
        );
        if can_spawn_children && !user.contains("AUTHORITY") {
            self.active_user_pids.push(pid);
        }

        if self.processes.len() > 300 {
            self.cleanup_old_processes();
        }

        proc
    }

    pub fn spawn_with_random_parent(
        &mut self,
        name: &str,
        path: &str,
        cmdline: &str,
        user: &str,
    ) -> (Process, Process) {
        let mut rng = rand::rng();

        let parent = if user.contains("AUTHORITY") {
            self.random_svchost()
                .or_else(|| self.find_by_name("services.exe"))
                .cloned()
        } else {
            let is_script_child = matches!(
                name,
                "whoami.exe"
                    | "net.exe"
                    | "ipconfig.exe"
                    | "systeminfo.exe"
                    | "tasklist.exe"
                    | "reg.exe"
                    | "wmic.exe"
                    | "certutil.exe"
            );

            if is_script_child && rng.random_bool(0.7) {
                self.find_by_name("cmd.exe")
                    .or_else(|| self.find_by_name("powershell.exe"))
                    .or_else(|| self.random_active_parent())
                    .cloned()
            } else if rng.random_bool(0.6) {
                self.random_active_parent().cloned()
            } else {
                self.get_explorer().cloned()
            }
        }
        .unwrap_or_else(|| self.processes.get(&4).cloned().unwrap());

        let child = self.spawn(name, path, cmdline, user, parent.pid);
        (child, parent)
    }

    fn cleanup_old_processes(&mut self) {
        let mut pids: Vec<u32> = self.processes.keys().copied().collect();
        pids.sort();
        let to_remove: Vec<u32> = pids
            .into_iter()
            .filter(|&pid| pid >= 1000)
            .rev()
            .skip(150)
            .collect();
        for pid in to_remove {
            self.processes.remove(&pid);
            self.active_user_pids.retain(|&p| p != pid);
        }
    }

    pub fn active_count(&self) -> usize {
        self.active_user_pids.len()
    }
}

// =============================================================================
// Browsing Session
// =============================================================================

/// Site navigation flows for realistic referrer chains
const SITE_FLOWS: &[(&str, &[&str])] = &[
    (
        "github.com",
        &[
            "/",
            "/explore",
            "/trending",
            "/notifications",
            "/user/repo",
            "/user/repo/issues",
            "/user/repo/pulls",
        ],
    ),
    (
        "docs.google.com",
        &[
            "/",
            "/document/d/123/edit",
            "/spreadsheets/d/456/edit",
            "/presentation/d/789/edit",
        ],
    ),
    (
        "stackoverflow.com",
        &[
            "/",
            "/questions",
            "/questions/12345/how-to-parse-json",
            "/tags/python",
        ],
    ),
    (
        "outlook.office365.com",
        &[
            "/",
            "/mail/inbox",
            "/mail/sentitems",
            "/calendar/view/month",
        ],
    ),
    (
        "teams.microsoft.com",
        &["/", "/conversations", "/files", "/calendar", "/calls"],
    ),
    (
        "learn.microsoft.com",
        &["/", "/en-us/azure/", "/en-us/dotnet/", "/en-us/windows/"],
    ),
    (
        "portal.azure.com",
        &[
            "/",
            "/resource-groups",
            "/virtual-machines",
            "/app-services",
        ],
    ),
    (
        "slack.com",
        &["/", "/messages", "/channels", "/files", "/apps"],
    ),
    (
        "jira.atlassian.com",
        &["/", "/browse/PROJ-123", "/browse/PROJ-456", "/boards/1"],
    ),
    (
        "www.linkedin.com",
        &["/", "/feed", "/mynetwork", "/jobs", "/messaging"],
    ),
    (
        "reddit.com",
        &["/", "/r/programming", "/r/technology", "/r/netsec"],
    ),
    (
        "news.ycombinator.com",
        &["/", "/news", "/newest", "/show", "/ask"],
    ),
    (
        "amazon.com",
        &["/", "/s?k=laptop", "/dp/B09ABC123", "/gp/cart/view.html"],
    ),
];

const ENTRY_POINTS: &[&str] = &[
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
];

#[derive(Debug)]
pub struct BrowsingSession {
    current_url: String,
    referrer: String,
    history: Vec<String>,
    session_site: Option<String>,
}

impl BrowsingSession {
    pub fn new() -> Self {
        let mut rng = rand::rng();
        Self {
            current_url: ENTRY_POINTS[rng.random_range(0..ENTRY_POINTS.len())].to_string(),
            referrer: String::new(),
            history: Vec::new(),
            session_site: None,
        }
    }

    pub fn next_request(&mut self) -> (String, String, String) {
        let mut rng = rand::rng();
        let action: f64 = rng.random();

        if action < 0.10 && !self.history.is_empty() {
            self.referrer = self.current_url.clone();
            self.current_url = self.history.pop().unwrap();
        } else if action < 0.30 || self.session_site.is_none() {
            self.history.clear();
            self.referrer = ENTRY_POINTS[rng.random_range(0..ENTRY_POINTS.len())].to_string();
            let (site, paths) = SITE_FLOWS[rng.random_range(0..SITE_FLOWS.len())];
            self.session_site = Some(site.to_string());
            let path = paths[rng.random_range(0..paths.len())];
            self.current_url = format!("https://{}{}", site, path);
        } else if action < 0.60 {
            self.history.push(self.current_url.clone());
            self.referrer = self.current_url.clone();
            let (site, paths) = SITE_FLOWS[rng.random_range(0..SITE_FLOWS.len())];
            self.session_site = Some(site.to_string());
            let path = paths[rng.random_range(0..paths.len())];
            self.current_url = format!("https://{}{}", site, path);
        } else {
            self.history.push(self.current_url.clone());
            self.referrer = self.current_url.clone();
            if let Some(ref site) = self.session_site {
                if let Some((_, paths)) = SITE_FLOWS.iter().find(|(s, _)| *s == site.as_str()) {
                    let path = paths[rng.random_range(0..paths.len())];
                    self.current_url = format!("https://{}{}", site, path);
                }
            }
        }

        let dest_host = self
            .current_url
            .replace("https://", "")
            .replace("http://", "");
        let dest_host = dest_host.split('/').next().unwrap_or("direct").to_string();

        let final_referrer = if self.referrer == self.current_url {
            String::new()
        } else {
            self.referrer.clone()
        };

        (self.current_url.clone(), final_referrer, dest_host)
    }
}

// =============================================================================
// Entity
// =============================================================================

#[allow(dead_code)]
pub struct Entity {
    pub hostname: String,
    pub user: String,
    pub ip: String,
    pub mac: String,
    pub interface: String,
    pub device_id: String,
    pub domain: String,
    process_tree: Mutex<ProcessTree>,
    browsing_session: Mutex<BrowsingSession>,
    pub is_compromised: bool,
    last_dhcp_event: Mutex<Option<DateTime<Utc>>>,
    dhcp_event_interval: Duration,
    pub neighbor_indices: Vec<usize>,
}

impl std::fmt::Debug for Entity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entity")
            .field("hostname", &self.hostname)
            .field("user", &self.user)
            .field("ip", &self.ip)
            .finish()
    }
}

#[allow(dead_code)]
impl Entity {
    pub fn new(hostname: &str, user: &str, ip: &str, mac: &str, domain: &str) -> Self {
        let mut rng = rand::rng();
        Self {
            hostname: hostname.to_string(),
            user: user.to_string(),
            ip: ip.to_string(),
            mac: mac.to_string(),
            interface: INTERFACES.choose(&mut rng).unwrap().to_string(),
            device_id: Uuid::now_v7().to_string(),
            domain: domain.to_string(),
            process_tree: Mutex::new(ProcessTree::new(user)),
            browsing_session: Mutex::new(BrowsingSession::new()),
            is_compromised: false,
            last_dhcp_event: Mutex::new(None),
            dhcp_event_interval: Duration::hours(4),
            neighbor_indices: Vec::new(),
        }
    }

    /// FQDN: hostname.domain (e.g., WS-ENG-001.corp.local)
    pub fn fqdn(&self) -> String {
        format!("{}.{}", self.hostname, self.domain)
    }

    pub fn spawn_process(
        &self,
        name: &str,
        path: &str,
        cmdline: &str,
        user: Option<&str>,
    ) -> (Process, Process) {
        let user = user.unwrap_or(&self.user);
        self.process_tree
            .lock()
            .spawn_with_random_parent(name, path, cmdline, user)
    }

    pub fn next_browse_request(&self) -> (String, String, String) {
        self.browsing_session.lock().next_request()
    }
}

// =============================================================================
// World State
// =============================================================================

pub struct WorldState {
    entities: Vec<Entity>,
    pub workstation_count: usize,
    pub laptop_count: usize,
    pub server_count: usize,
    pub user_count: usize,
    pub domain: String,
}

/// A `nano_enrich` identity record (kind=identity, source=ad) for one fleet
/// user — pushed to seed `user_registry` so generated logs enrich. The
/// `username` is exactly `WorldState::gen_user(i)` (the `user_registry_dict`
/// key, matched case-insensitively against the log's `.user`). NAN-1154.
#[derive(Debug, Clone, Serialize)]
pub struct IdentitySeedRecord {
    pub kind: &'static str,
    pub source: &'static str,
    pub external_id: String,
    pub username: String,
    pub upn: String,
    pub email: String,
    pub display_name: String,
    pub first_name: String,
    pub last_name: String,
    pub department: String,
    pub title: String,
    pub groups: Vec<String>,
    pub account_enabled: bool,
}

impl WorldState {
    pub fn new(asset_count: usize) -> Self {
        Self::with_domain(asset_count, "corp.local")
    }

    pub fn with_domain(asset_count: usize, domain: &str) -> Self {
        let mut state = Self {
            entities: Vec::new(),
            workstation_count: 0,
            laptop_count: 0,
            server_count: 0,
            user_count: 0,
            domain: domain.to_string(),
        };
        state.init_population(asset_count);
        state
    }

    fn gen_user(index: usize) -> String {
        let first = FIRST_NAMES[index % FIRST_NAMES.len()];
        let last = LAST_NAMES[index / FIRST_NAMES.len() % LAST_NAMES.len()];
        format!(r"CORP\{}{}", &first[..1], last)
    }

    fn gen_service_account(role: &str) -> String {
        format!(r"CORP\svc_{}", role.to_lowercase())
    }

    fn gen_ip(index: usize, is_server: bool) -> String {
        let site = if is_server { 2 } else { 1 };
        let subnet = (index / 254) + 1;
        let host = (index % 254) + 1;
        format!("10.{}.{}.{}", site, subnet, host)
    }

    fn gen_mac(index: usize) -> String {
        let prefix = MAC_PREFIXES[index % MAC_PREFIXES.len()];
        let mixed = index.wrapping_mul(2654435761);
        let b1 = ((mixed >> 16) & 0xFF) as u8;
        let b2 = ((mixed >> 8) & 0xFF) as u8;
        let b3 = (mixed & 0xFF) as u8;
        format!("{}:{:02x}:{:02x}:{:02x}", prefix, b1, b2, b3)
    }

    fn init_population(&mut self, asset_count: usize) {
        let asset_count = asset_count.max(3);
        let server_count = (asset_count * 5 / 100).max(1);
        let laptop_count = (asset_count * 25 / 100).max(1);
        let workstation_count = asset_count - server_count - laptop_count;

        let mut global_idx: usize = 0;
        let mut user_idx: usize = 0;
        let mut ws_ip_idx: usize = 0;
        let mut srv_ip_idx: usize = 0;
        let mut user_set = std::collections::HashSet::new();

        for i in 0..workstation_count {
            let dept = DEPARTMENTS[i % DEPARTMENTS.len()];
            let num = i / DEPARTMENTS.len() + 1;
            let hostname = format!("WS-{}-{:03}", dept, num);
            let user = Self::gen_user(user_idx);
            user_set.insert(user.clone());
            user_idx += 1;
            let ip = Self::gen_ip(ws_ip_idx, false);
            ws_ip_idx += 1;
            let mac = Self::gen_mac(global_idx);
            global_idx += 1;
            self.entities
                .push(Entity::new(&hostname, &user, &ip, &mac, &self.domain));
        }

        for i in 0..laptop_count {
            let dept = DEPARTMENTS[i % DEPARTMENTS.len()];
            let num = i / DEPARTMENTS.len() + 1;
            let hostname = format!("LT-{}-{:03}", dept, num);
            let user = Self::gen_user(user_idx);
            user_set.insert(user.clone());
            user_idx += 1;
            let ip = Self::gen_ip(ws_ip_idx, false);
            ws_ip_idx += 1;
            let mac = Self::gen_mac(global_idx);
            global_idx += 1;
            self.entities
                .push(Entity::new(&hostname, &user, &ip, &mac, &self.domain));
        }

        for i in 0..server_count {
            let role = SERVER_ROLES[i % SERVER_ROLES.len()];
            let num = i / SERVER_ROLES.len() + 1;
            let hostname = format!("SRV-{}{:02}", role, num);
            let user = Self::gen_service_account(role);
            user_set.insert(user.clone());
            let ip = Self::gen_ip(srv_ip_idx, true);
            srv_ip_idx += 1;
            let mac = Self::gen_mac(global_idx);
            global_idx += 1;
            self.entities
                .push(Entity::new(&hostname, &user, &ip, &mac, &self.domain));
        }

        self.workstation_count = workstation_count;
        self.laptop_count = laptop_count;
        self.server_count = server_count;
        self.user_count = user_set.len();

        let total = self.entities.len();
        if total > 1 {
            for i in 0..total {
                let n1 = (i + 1) % total;
                let neighbors = if i % 2 == 0 {
                    vec![n1]
                } else {
                    let n2 = (i + total / 3) % total;
                    if n2 == i || n2 == n1 {
                        vec![n1]
                    } else {
                        vec![n1, n2]
                    }
                };
                self.entities[i].neighbor_indices = neighbors;
            }
        }
    }

    pub fn entities(&self) -> &[Entity] {
        &self.entities
    }

    /// Identity records for the fleet's real (non-service) users — one per
    /// `gen_user(i)` over the workstation+laptop population. Push these as
    /// `nano_enrich` records to seed `user_registry`; a subsequent blast then
    /// produces logs whose `.user` matches the dict key and enriches. NAN-1154.
    pub fn identity_roster(&self) -> Vec<IdentitySeedRecord> {
        let user_count = self.workstation_count + self.laptop_count;
        (0..user_count)
            .map(|idx| {
                let first = FIRST_NAMES[idx % FIRST_NAMES.len()];
                let last = LAST_NAMES[idx / FIRST_NAMES.len() % LAST_NAMES.len()];
                let dept = DEPARTMENTS[idx % DEPARTMENTS.len()];
                let title = TITLES[idx % TITLES.len()];
                let email = format!(
                    "{}.{}@corp.example",
                    first.to_lowercase(),
                    last.to_lowercase()
                );
                IdentitySeedRecord {
                    kind: "identity",
                    source: "ad",
                    // Deterministic SID-like id, unique per user.
                    external_id: format!("S-1-5-21-1001-{}", 1000 + idx),
                    // EXACTLY the log's `.user` value → the user_registry_dict key.
                    username: Self::gen_user(idx),
                    upn: email.clone(),
                    email,
                    display_name: format!("{first} {last}"),
                    first_name: first.to_string(),
                    last_name: last.to_string(),
                    department: dept.to_string(),
                    title: title.to_string(),
                    groups: vec![dept.to_string(), "All Staff".to_string()],
                    account_enabled: true,
                }
            })
            .collect()
    }

    pub fn random_entity(&self) -> &Entity {
        let mut rng = rand::rng();
        self.entities.choose(&mut rng).unwrap()
    }

    pub fn get_entity(&self, hostname: &str) -> Option<&Entity> {
        self.entities.iter().find(|e| e.hostname == hostname)
    }

    /// NAN-1542 convergence: pick an entity from the low-index workstation pool
    /// that the lateral-chain ("patient zero") emitter seeds from. The chain
    /// emitter rotates `seed_idx = seed_cursor % workstation_count`, so security
    /// detections concentrate on these first workstations. Sourcing an OTLP
    /// trace's `host.name` / `client.address` from the SAME pool guarantees the
    /// service host overlaps a host with security signals — making the
    /// service-detail security cross-link demoable instead of relying on a
    /// 1-in-`assets` random collision.
    ///
    /// `n` (typically a monotonic tick counter) selects deterministically across
    /// the pool; servers are skipped (they're poor patient-zero seeds, mirroring
    /// the chain emitter). Returns `None` only for an empty world.
    pub fn convergence_entity(&self, n: usize) -> Option<&Entity> {
        if self.entities.is_empty() {
            return None;
        }
        // Mirror the chain emitter's seed pool: the first `workstation_count`
        // entities (workstations precede laptops/servers in init order).
        let pool = self.workstation_count.max(1).min(self.entities.len());
        self.entities.get(n % pool)
    }
}

impl Default for WorldState {
    fn default() -> Self {
        Self::new(2000)
    }
}

#[cfg(test)]
mod identity_roster_tests {
    use super::WorldState;
    use std::collections::HashSet;

    /// NAN-1154: every seeded identity's username MUST be a real fleet user
    /// (= gen_user(i)) so a blast's logs (whose `.user` is a fleet user) match
    /// the seeded user_registry rows and enrich. The roster is also the right
    /// size (one per workstation+laptop user) with required fields populated.
    #[test]
    fn roster_usernames_match_fleet_users() {
        let world = WorldState::new(200);
        let fleet_users: HashSet<&str> =
            world.entities().iter().map(|e| e.user.as_str()).collect();

        let roster = world.identity_roster();
        assert_eq!(roster.len(), world.workstation_count + world.laptop_count);
        assert!(!roster.is_empty());

        for rec in &roster {
            assert!(
                fleet_users.contains(rec.username.as_str()),
                "seeded username {:?} is not a fleet user — logs would never match it",
                rec.username
            );
            assert!(rec.username.starts_with(r"CORP\"));
            assert!(!rec.external_id.is_empty());
            assert!(rec.email.contains('@'));
            assert_eq!(rec.kind, "identity");
            assert_eq!(rec.source, "ad");
            assert!(rec.account_enabled);
        }
    }
}
