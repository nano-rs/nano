//! Sysmon event generator using real process chains and file hashes
//!
//! Produces Windows Event JSON matching the format the Vector Sysmon parser expects.
//! The `message` field contains a JSON object with `event_id`, `event_data`, `host`,
//! `channel`, `provider_name`, etc. — matching what the Windows Event Log agent produces.

use chrono::{DateTime, Utc};
use rand::Rng;
use uuid::Uuid;

use crate::entity::Entity;
use crate::event::Event;
use crate::profiles::{self, ProcessChain, ProfileData};

pub struct SysmonGenerator;

impl SysmonGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a Sysmon event weighted by the real event type distribution
    pub fn generate(&self, timestamp: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let profiles = profiles::profiles();
        let event_type = profiles.sample_sysmon_event(rng);

        match event_type.signature_id.as_str() {
            "1" => self.process_create(timestamp, entity, profiles, rng),
            "3" => self.network_connect(timestamp, entity, profiles, rng),
            "5" => self.process_terminate(timestamp, entity, rng),
            "7" => self.image_load(timestamp, entity, profiles, rng),
            "10" => self.process_access(timestamp, entity, profiles, rng),
            "11" => self.file_create(timestamp, entity, profiles, rng),
            "12" | "13" => {
                self.registry_event(timestamp, entity, profiles, rng, &event_type.signature_id)
            }
            "22" => self.dns_query(timestamp, entity, rng),
            "23" => self.file_delete(timestamp, entity, profiles, rng),
            _ => self.image_load(timestamp, entity, profiles, rng), // fallback to most common
        }
    }

    /// Event ID 1: Process Create — uses real process chains
    fn process_create(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        profiles: &ProfileData,
        rng: &mut impl Rng,
    ) -> Event {
        let chain = profiles.sample_process_chain(rng);
        let (child, parent) = self.spawn_from_chain(entity, chain);

        let event_data = serde_json::json!({
            "RuleName": "ProcessCreate",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", child.guid),
            "ProcessId": child.pid.to_string(),
            "Image": child.path,
            "FileVersion": "-",
            "Description": "-",
            "Product": "-",
            "Company": "-",
            "OriginalFileName": child.name,
            "CommandLine": child.cmdline,
            "CurrentDirectory": r"C:\Windows\system32\",
            "User": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
            "LogonGuid": format!("{{{}}}", Uuid::now_v7()),
            "LogonId": format!("0x{:X}", rng.random_range(0x10000u32..0xFFFFF)),
            "TerminalSessionId": "1",
            "IntegrityLevel": "Medium",
            "Hashes": format!("SHA256={}", chain.process_hash),
            "ParentProcessGuid": format!("{{{}}}", parent.guid),
            "ParentProcessId": parent.pid.to_string(),
            "ParentImage": parent.path,
            "ParentCommandLine": parent.cmdline,
            "ParentUser": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
        });

        self.build_event(ts, entity, 1, "Process Create", event_data, &child.name)
    }

    /// Event ID 3: Network Connection
    fn network_connect(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        profiles: &ProfileData,
        rng: &mut impl Rng,
    ) -> Event {
        let chain = profiles.sample_process_chain(rng);
        let dest_ip = format!(
            "{}.{}.{}.{}",
            rng.random_range(1u8..255),
            rng.random_range(0u8..255),
            rng.random_range(0u8..255),
            rng.random_range(1u8..255)
        );
        let dest_port = [80, 443, 8080, 8443, 53, 445, 3389, 5985][rng.random_range(0..8)];
        let src_port = rng.random_range(49152u16..65535);

        let event_data = serde_json::json!({
            "RuleName": "NetworkConnect",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": chain.process_path,
            "User": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
            "Protocol": "tcp",
            "Initiated": "true",
            "SourceIsIpv6": "false",
            "SourceIp": entity.ip,
            "SourceHostname": entity.fqdn(),
            "SourcePort": src_port.to_string(),
            "SourcePortName": "-",
            "DestinationIsIpv6": "false",
            "DestinationIp": dest_ip,
            "DestinationHostname": "-",
            "DestinationPort": dest_port.to_string(),
            "DestinationPortName": if dest_port == 443 { "https" } else if dest_port == 80 { "http" } else { "-" },
        });

        self.build_event(
            ts,
            entity,
            3,
            "Network connection detected",
            event_data,
            &format!("{}→{}:{}", chain.process_name, dest_ip, dest_port),
        )
    }

    /// Event ID 5: Process Terminate
    fn process_terminate(&self, ts: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let chain = profiles::profiles().sample_process_chain(rng);

        let event_data = serde_json::json!({
            "RuleName": "-",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": chain.process_path,
            "User": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
        });

        self.build_event(
            ts,
            entity,
            5,
            "Process terminated",
            event_data,
            &chain.process_name,
        )
    }

    /// Event ID 7: Image Loaded — most common event (~70%)
    fn image_load(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        profiles: &ProfileData,
        rng: &mut impl Rng,
    ) -> Event {
        let chain = profiles.sample_process_chain(rng);
        // Use file hash data for the loaded image
        let file = profiles.sample_file_hash(rng);

        let event_data = serde_json::json!({
            "RuleName": "ImageLoad",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": chain.process_path,
            "ImageLoaded": if file.file_path.is_empty() { r"C:\Windows\System32\kernel32.dll".to_string() } else { file.file_path.clone() },
            "FileVersion": "10.0.22621.1 (WinBuild.160101.0800)",
            "Description": "-",
            "Product": "Microsoft Windows Operating System",
            "Company": "Microsoft Corporation",
            "OriginalFileName": if file.file_name.is_empty() { "kernel32.dll".to_string() } else { file.file_name.clone() },
            "Hashes": format!("SHA256={}", if file.file_hash.is_empty() { &chain.process_hash } else { &file.file_hash }),
            "Signed": "true",
            "Signature": "Microsoft Windows",
            "SignatureStatus": "Valid",
            "User": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
        });

        self.build_event(
            ts,
            entity,
            7,
            "Image loaded (rule: ImageLoad)",
            event_data,
            &chain.process_name,
        )
    }

    /// Event ID 10: Process Access
    fn process_access(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        profiles: &ProfileData,
        rng: &mut impl Rng,
    ) -> Event {
        let source = profiles.sample_process_chain(rng);
        let target = profiles.sample_process_chain(rng);

        let event_data = serde_json::json!({
            "RuleName": "ProcessAccess",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "SourceProcessGUID": format!("{{{}}}", Uuid::now_v7()),
            "SourceProcessId": rng.random_range(1000u32..30000).to_string(),
            "SourceThreadId": rng.random_range(1000u32..10000).to_string(),
            "SourceImage": source.process_path,
            "TargetProcessGUID": format!("{{{}}}", Uuid::now_v7()),
            "TargetProcessId": rng.random_range(1000u32..30000).to_string(),
            "TargetImage": target.process_path,
            "GrantedAccess": "0x1000",
            "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4",
            "SourceUser": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
            "TargetUser": r"NT AUTHORITY\SYSTEM",
        });

        self.build_event(
            ts,
            entity,
            10,
            "Process accessed",
            event_data,
            &format!("{}→{}", source.process_name, target.process_name),
        )
    }

    /// Event ID 11: File Create
    fn file_create(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        profiles: &ProfileData,
        rng: &mut impl Rng,
    ) -> Event {
        let chain = profiles.sample_process_chain(rng);

        let event_data = serde_json::json!({
            "RuleName": "-",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": chain.process_path,
            "TargetFilename": format!(r"C:\Users\{}\AppData\Local\Temp\tmp{:08x}.tmp", entity.user.split('\\').last().unwrap_or("user"), rng.random::<u32>()),
            "CreationUtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "User": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
        });

        self.build_event(
            ts,
            entity,
            11,
            "File created",
            event_data,
            &chain.process_name,
        )
    }

    /// Event ID 12/13: Registry Event
    fn registry_event(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        profiles: &ProfileData,
        rng: &mut impl Rng,
        event_id: &str,
    ) -> Event {
        let chain = profiles.sample_process_chain(rng);
        let hives = [
            "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion",
            "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
            "HKLM\\SYSTEM\\CurrentControlSet\\Services",
        ];
        let hive = hives[rng.random_range(0..hives.len())];

        let mut event_data = serde_json::json!({
            "RuleName": if event_id == "12" { "RegistryEvent (Object create and delete)" } else { "RegistryEvent (Value Set)" },
            "EventType": if event_id == "12" { "CreateKey" } else { "SetValue" },
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": chain.process_path,
            "TargetObject": format!("{}\\{}", hive, chain.process_name.replace(".exe", "")),
            "User": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
        });

        if event_id == "13" {
            event_data["Details"] = serde_json::json!("DWORD (0x00000001)");
        }

        let eid: u16 = event_id.parse().unwrap_or(12);
        self.build_event(
            ts,
            entity,
            eid,
            if eid == 12 {
                "Registry object added or deleted"
            } else {
                "Registry value set"
            },
            event_data,
            &chain.process_name,
        )
    }

    /// Event ID 22: DNS Query
    fn dns_query(&self, ts: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let domains = [
            "google.com",
            "microsoft.com",
            "github.com",
            "amazonaws.com",
            "cloudflare.com",
            "office365.com",
            "windows.net",
            "akamaized.net",
            "login.microsoftonline.com",
            "cdn.jsdelivr.net",
        ];
        let domain = domains[rng.random_range(0..domains.len())];

        let event_data = serde_json::json!({
            "RuleName": "-",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "QueryName": domain,
            "QueryStatus": "0",
            "QueryResults": format!("type:  5 {};type:  1 {}.{}.{}.{}", domain, rng.random_range(1u8..255), rng.random_range(0u8..255), rng.random_range(0u8..255), rng.random_range(1u8..255)),
            "Image": r"C:\Windows\System32\svchost.exe",
            "User": r"NT AUTHORITY\NETWORK SERVICE",
        });

        self.build_event(ts, entity, 22, "Dns query", event_data, domain)
    }

    /// Event ID 23: File Delete
    fn file_delete(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        profiles: &ProfileData,
        rng: &mut impl Rng,
    ) -> Event {
        let file = profiles.sample_file_hash(rng);
        let chain = profiles.sample_process_chain(rng);

        let event_data = serde_json::json!({
            "RuleName": "-",
            "UtcTime": ts.format("%Y-%m-%d %H:%M:%S.%3f").to_string(),
            "ProcessGuid": format!("{{{}}}", Uuid::now_v7()),
            "ProcessId": rng.random_range(1000u32..30000).to_string(),
            "Image": chain.process_path,
            "TargetFilename": if file.file_path.is_empty() { format!(r"C:\Users\{}\AppData\Local\Temp\tmp{:08x}.tmp", entity.user.split('\\').last().unwrap_or("user"), rng.random::<u32>()) } else { file.file_path.clone() },
            "Hashes": if file.file_hash.is_empty() { format!("SHA256={}", chain.process_hash) } else { format!("SHA256={}", file.file_hash) },
            "IsExecutable": "false",
            "User": format!("{}\\{}", entity.domain.to_uppercase(), entity.user.split('\\').last().unwrap_or(&entity.user)),
        });

        self.build_event(
            ts,
            entity,
            23,
            "File Delete",
            event_data,
            &chain.process_name,
        )
    }

    /// Spawn a process using a real chain, adapting entity fields
    fn spawn_from_chain(
        &self,
        entity: &Entity,
        chain: &ProcessChain,
    ) -> (crate::entity::Process, crate::entity::Process) {
        let cmdline = if chain.command_line.is_empty() {
            format!("\"{}\"", chain.process_path)
        } else {
            chain.command_line.clone()
        };

        entity.spawn_process(&chain.process_name, &chain.process_path, &cmdline, None)
    }

    /// Build the final Event with the Windows Event JSON envelope
    fn build_event(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        event_id: u16,
        task_name: &str,
        event_data: serde_json::Value,
        label: &str,
    ) -> Event {
        let mut rng = rand::rng();
        let message = serde_json::json!({
            "channel": "Microsoft-Windows-Sysmon/Operational",
            "computer": entity.fqdn(),
            "event_data": event_data,
            "event_id": event_id,
            "host": entity.fqdn(),
            "keywords": "0x8000000000000000",
            "level": "Information",
            "level_value": 4,
            "process_id": rng.random_range(1000u32..10000),
            "provider_guid": "{5770385f-c22a-43e0-bf4c-06f5698ffbd9}",
            "provider_name": "Microsoft-Windows-Sysmon",
            "record_id": rng.random_range(100000u32..999999),
            "task": event_id,
            "task_name": task_name,
            "thread_id": rng.random_range(1000u32..10000),
            "timestamp": ts.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            "user_id": "S-1-5-18",
            "user_name": r"NT AUTHORITY\SYSTEM",
            "version": 3,
        });

        Event {
            message: serde_json::to_string(&message).unwrap(),
            timestamp: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            source_type: "windows_sysmon".to_string(),
            display_label: format!("[sysmon:{}] {} {}", event_id, entity.hostname, label),
        }
    }
}
