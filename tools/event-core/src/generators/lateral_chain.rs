//! Lateral movement chain generator.
//!
//! Produces coordinated bursts of events that the `| lateral` aggregate in
//! nanosiem-core can trace hop-by-hop across authentication, network, and
//! process evidence. A single "chain" emits:
//!
//!   hop 0 (seed) → hop 1 → hop 2 → hop 3
//!
//! Per hop it emits THREE events:
//!   - Sysmon 3 (network connection) from src → dest on a lateral port
//!     (445 SMB, 3389 RDP, 5985 WinRM, 22 SSH, 135 RPC)
//!   - WinEvt 4624 (successful logon) at dest with WorkstationName/IpAddress
//!     pointing back at src — this is the auth-class evidence the aggregate
//!     picks up via `auth_type != '' OR action ~ logon`
//!   - Sysmon 1 (process create) at dest for a remote-exec tool
//!     (psexesvc.exe, wmic.exe, winrs.exe, powershell.exe with invoke-command)
//!
//! All three events share the same `user` so edges collapse consistently in
//! the graph. Chains run through multiple hops so the critical-path BFS has
//! something to walk end-to-end.
//!
//! Entity selection: the seed is always the same workstation (index 0) so
//! demos are reproducible. Each hop walks `neighbor_indices` to pick the next
//! asset — when neighbors run out, the chain stops.

use chrono::{DateTime, Utc};
use rand::Rng;
use uuid::Uuid;

use crate::entity::{Entity, WorldState};
use crate::event::Event;

pub struct LateralChainGenerator;

/// Remote-exec tool flavours — each produces distinct UDM `method_detail`
/// buckets on the backend (`psexec`, `wmic`, `winrs`, `powershell_remoting`).
const REMOTE_EXEC_TOOLS: &[(&str, &str, u16)] = &[
    // (image_name, image_path, dest_port hint)
    ("psexesvc.exe", r"C:\Windows\PSEXESVC.exe", 445),
    ("wmic.exe", r"C:\Windows\System32\wbem\WMIC.exe", 135),
    ("winrs.exe", r"C:\Windows\System32\winrs.exe", 5985),
    ("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", 5985),
];

/// Lateral-relevant ports for the network-connection leg.
const LATERAL_PORTS: &[(u16, &str)] = &[
    (3389, "rdp"),
    (445, "smb"),
    (5985, "winrm"),
    (22, "ssh"),
    (135, "rpc"),
];

impl LateralChainGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Build a lateral-movement chain rooted at the given seed entity.
    ///
    /// Returns a flat list of events covering every hop (3 events per hop:
    /// network + auth + process). The chain walks `neighbor_indices` from
    /// each entity to the next until `max_hops` is reached or no more
    /// unvisited neighbors remain.
    pub fn emit_chain(
        &self,
        world: &WorldState,
        seed_idx: usize,
        max_hops: usize,
        now: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> Vec<Event> {
        let entities = world.entities();
        if entities.is_empty() || seed_idx >= entities.len() {
            return Vec::new();
        }

        // Walk the chain by BFS through neighbor_indices, taking the first
        // unvisited neighbor at each hop. Keeps the chain a strict path
        // (not a tree) so the backend critical-path BFS has a clear target.
        let mut path_idx: Vec<usize> = vec![seed_idx];
        let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
        visited.insert(seed_idx);
        let mut cursor = seed_idx;
        for _ in 0..max_hops {
            let next = entities[cursor]
                .neighbor_indices
                .iter()
                .find(|&&i| i < entities.len() && !visited.contains(&i))
                .copied();
            match next {
                Some(i) => {
                    path_idx.push(i);
                    visited.insert(i);
                    cursor = i;
                }
                None => break,
            }
        }

        if path_idx.len() < 2 {
            return Vec::new();
        }

        // Emit events hop by hop. Step the timestamp forward ~10–30s per hop
        // so the backend `dedup_edges` (minute-bucketed) keeps them distinct
        // and the critical-path BFS resolves in chronological order.
        let mut events: Vec<Event> = Vec::with_capacity(path_idx.len() * 3);
        let mut ts = now;
        for pair in path_idx.windows(2) {
            let src = &entities[pair[0]];
            let dest = &entities[pair[1]];

            let (dest_port, port_label) = LATERAL_PORTS[rng.random_range(0..LATERAL_PORTS.len())];
            // User for this hop: seed's user walks the chain (credential reuse /
            // token theft) — gives the backend a single stable `user` across
            // hops which makes the graph legible.
            let user = entities[seed_idx].user.clone();

            let net_event = self.network_connect(ts, src, dest, dest_port, port_label, &user, rng);
            events.push(net_event);

            let ts_auth = ts + chrono::Duration::seconds(1);
            let auth_event = self.logon_4624(ts_auth, src, dest, &user, rng);
            events.push(auth_event);

            let ts_proc = ts + chrono::Duration::seconds(2);
            let (tool_name, tool_path, _tool_port) =
                REMOTE_EXEC_TOOLS[rng.random_range(0..REMOTE_EXEC_TOOLS.len())];
            let proc_event = self.remote_exec_sysmon1(
                ts_proc,
                dest,
                src,
                tool_name,
                tool_path,
                &user,
                rng,
            );
            events.push(proc_event);

            ts = ts + chrono::Duration::seconds(rng.random_range(12..28));
        }

        events
    }

    // ─── Per-hop event builders ────────────────────────────────────────────

    /// Sysmon Event ID 3 — network connection from src → dest on a lateral port.
    fn network_connect(
        &self,
        ts: DateTime<Utc>,
        src: &Entity,
        dest: &Entity,
        dest_port: u16,
        port_label: &str,
        user: &str,
        rng: &mut impl Rng,
    ) -> Event {
        // Choose an initiator image that matches the protocol — mstsc for RDP,
        // svchost for SMB, wsmprovhost for WinRM. Keeps process_name aligned
        // with the chosen port so analysts can connect the dots on the src side.
        let image = match dest_port {
            3389 => r"C:\Windows\System32\mstsc.exe",
            445 => r"C:\Windows\System32\svchost.exe",
            5985 => r"C:\Windows\System32\wsmprovhost.exe",
            22 => r"C:\Windows\System32\OpenSSH\ssh.exe",
            _ => r"C:\Windows\System32\svchost.exe",
        };
        let src_port = rng.random_range(49152u16..65535);

        let event_data = serde_json::json!({
            "RuleName": "NetworkConnect",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": image,
            "User": format!(
                "{}\\{}",
                src.domain.to_uppercase(),
                user.split('\\').last().unwrap_or(user)
            ),
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIsIpv6": "false",
            "SourceIp": src.ip,
            "SourceHostname": src.fqdn(),
            "SourcePort": src_port.to_string(),
            "SourcePortName": "-",
            "DestinationIsIpv6": "false",
            "DestinationIp": dest.ip,
            "DestinationHostname": dest.fqdn(),
            "DestinationPort": dest_port.to_string(),
            "DestinationPortName": port_label,
        });

        sysmon_event(
            ts,
            src,
            3,
            "Network connection detected",
            event_data,
            &format!("{}→{}:{} ({})", src.hostname, dest.hostname, dest_port, port_label),
            "windows_sysmon",
        )
    }

    /// WinEvt 4624 — successful logon AT `dest` from `src`.
    fn logon_4624(
        &self,
        ts: DateTime<Utc>,
        src: &Entity,
        dest: &Entity,
        user: &str,
        rng: &mut impl Rng,
    ) -> Event {
        // Logon type 3 (Network) is the workhorse for SMB; 10 is RemoteInteractive
        // for RDP. Split roughly 60/40 since most chain steps hop via SMB.
        let logon_type = if rng.random_bool(0.6) { "3" } else { "10" };
        let protocol = ["Kerberos", "NTLM", "Negotiate"][rng.random_range(0..3)];
        let target_user = user.split('\\').last().unwrap_or(user);

        let event_data = serde_json::json!({
            "AuthenticationPackageName": protocol,
            "ElevatedToken": "%%1842",
            "ImpersonationLevel": "%%1833",
            "IpAddress": src.ip,
            "IpPort": rng.random_range(49152u16..65535).to_string(),
            "KeyLength": "0",
            "LmPackageName": "-",
            "LogonGuid": format!("{{{}}}", Uuid::now_v7()),
            "LogonProcessName": protocol,
            "LogonType": logon_type,
            "ProcessId": "0x0",
            "ProcessName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "SubjectUserName": "-",
            "SubjectUserSid": "S-1-0-0",
            "TargetDomainName": dest.domain.to_uppercase(),
            "TargetLogonId": format!("0x{:X}", rng.random_range(0x10000u32..0xFFFFF)),
            "TargetUserName": target_user,
            "TargetUserSid": format!(
                "S-1-5-21-{}-{}-{}-{}",
                rng.random_range(1000000000u32..4000000000),
                rng.random_range(1000000000u32..4000000000),
                rng.random_range(1000000000u32..4000000000),
                rng.random_range(1000u32..9999)
            ),
            "WorkstationName": src.hostname,
        });

        winevt_event(
            ts,
            dest,
            4624,
            "Logon",
            "An account was successfully logged on.",
            event_data,
            &["Audit Success"],
            &format!("logon {} from {} (lateral)", user, src.hostname),
        )
    }

    /// Sysmon Event ID 1 — remote-exec process creation at `dest`.
    /// Parent is services.exe (for service-installed tools like PSEXESVC) or
    /// svchost.exe (for WMI/WinRM). This matches what investigators see on a
    /// landed host after a successful lateral hop.
    fn remote_exec_sysmon1(
        &self,
        ts: DateTime<Utc>,
        dest: &Entity,
        src: &Entity,
        tool_name: &str,
        tool_path: &str,
        user: &str,
        rng: &mut impl Rng,
    ) -> Event {
        let (_parent_name, parent_path) = match tool_name {
            "psexesvc.exe" => (
                "services.exe",
                r"C:\Windows\System32\services.exe",
            ),
            "wmic.exe" | "winrs.exe" => (
                "svchost.exe",
                r"C:\Windows\System32\svchost.exe",
            ),
            _ => (
                "svchost.exe",
                r"C:\Windows\System32\svchost.exe",
            ),
        };
        let cmdline = match tool_name {
            "psexesvc.exe" => r"C:\Windows\PSEXESVC.exe".to_string(),
            "wmic.exe" => format!(
                r#"wmic.exe /node:{} process call create "cmd.exe /c whoami""#,
                dest.hostname
            ),
            "winrs.exe" => format!(
                r"winrs -r:{} -u:{} cmd.exe /c whoami",
                dest.fqdn(),
                user
            ),
            "powershell.exe" => format!(
                r#"powershell.exe -NoProfile -Command "Invoke-Command -ComputerName {} -ScriptBlock {{{{ whoami }}}}""#,
                dest.fqdn()
            ),
            _ => format!("\"{}\"", tool_path),
        };
        let process_hash = {
            // Synthesize a stable-ish hash so the same tool_name bucket together.
            let mut h = [0u8; 32];
            for (i, b) in tool_name.as_bytes().iter().enumerate() {
                h[i % 32] ^= b.wrapping_add(i as u8);
            }
            h.iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        };

        let event_data = serde_json::json!({
            "RuleName": "ProcessCreate",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": tool_path,
            "FileVersion": "-",
            "Description": "-",
            "Product": "-",
            "Company": "-",
            "OriginalFileName": tool_name,
            "CommandLine": cmdline,
            "CurrentDirectory": r"C:\Windows\system32\",
            "User": format!(
                "{}\\{}",
                dest.domain.to_uppercase(),
                user.split('\\').last().unwrap_or(user)
            ),
            "LogonGuid": format!("{{{}}}", Uuid::now_v7()),
            "LogonId": format!("0x{:X}", rng.random_range(0x10000u32..0xFFFFF)),
            "TerminalSessionId": "0",
            "IntegrityLevel": "High",
            "Hashes": format!("SHA256={}", process_hash),
            "ParentProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ParentProcessId": rng.random_range(500u32..900).to_string(),
            "ParentImage": parent_path,
            "ParentCommandLine": parent_path,
            "ParentUser": r"NT AUTHORITY\SYSTEM",
            // Include a breadcrumb tying the proc event back to its originator.
            "SourceHost": src.fqdn(),
        });

        sysmon_event(
            ts,
            dest,
            1,
            "Process Create",
            event_data,
            &format!("{} ← {} (remote exec)", tool_name, src.hostname),
            "windows_sysmon",
        )
    }
}

impl Default for LateralChainGenerator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Envelope helpers ────────────────────────────────────────────────────────

fn sysmon_event(
    ts: DateTime<Utc>,
    entity: &Entity,
    event_id: u16,
    task_name: &str,
    event_data: serde_json::Value,
    label: &str,
    source_type: &str,
) -> Event {
    let mut rng = rand::rng();
    let message = serde_json::json!({
        "channel": "Microsoft-Windows-Sysmon/Operational",
        "computer": entity.fqdn(),
        "event_data": event_data,
        "event_id": event_id,
        "event_record_id": rng.random_range(10000u64..999999),
        "keywords": ["Informational"],
        "level": 4,
        "opcode": 0,
        "provider_guid": "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}",
        "provider_name": "Microsoft-Windows-Sysmon",
        "task": event_id,
        "task_name": task_name,
        "time_created": ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "user_id": "S-1-5-18",
        "version": 5,
    });

    Event {
        message: message.to_string(),
        timestamp: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        source_type: source_type.to_string(),
        display_label: label.to_string(),
    }
}

fn winevt_event(
    ts: DateTime<Utc>,
    entity: &Entity,
    event_id: u16,
    task_name: &str,
    description: &str,
    event_data: serde_json::Value,
    keywords: &[&str],
    label: &str,
) -> Event {
    let mut rng = rand::rng();
    let message = serde_json::json!({
        "channel": "Security",
        "computer": entity.fqdn(),
        "event_data": event_data,
        "event_id": event_id,
        "event_record_id": rng.random_range(10000u64..999999),
        "keywords": keywords,
        "level": 0,
        "opcode": 0,
        "provider_guid": "{54849625-5478-4994-A5BA-3E3B0328C30D}",
        "provider_name": "Microsoft-Windows-Security-Auditing",
        "task": event_id,
        "task_name": task_name,
        "description": description,
        "time_created": ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        "user_id": "S-1-5-18",
        "version": 2,
    });

    Event {
        message: message.to_string(),
        timestamp: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
        source_type: "windows_event".to_string(),
        display_label: label.to_string(),
    }
}
