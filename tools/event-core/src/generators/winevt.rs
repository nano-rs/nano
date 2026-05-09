//! Windows Event generator for Security log events
//!
//! Produces Windows Security event JSON matching what the Vector agent collects.
//! Covers: 4624/4625 (logon), 4634 (logoff), 4688 (process create), 4672 (special privs).

use chrono::{DateTime, Utc};
use rand::Rng;
use uuid::Uuid;

use crate::entity::Entity;
use crate::event::Event;

pub struct WindowsEventGenerator;

impl WindowsEventGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a Windows Security event with realistic distribution
    pub fn generate(
        &self,
        timestamp: DateTime<Utc>,
        entity: &Entity,
        all_entities: &[Entity],
        rng: &mut impl Rng,
    ) -> Event {
        let r: f64 = rng.random();
        if r < 0.45 {
            self.logon_success(timestamp, entity, all_entities, rng)
        } else if r < 0.55 {
            self.logon_failure(timestamp, entity, all_entities, rng)
        } else if r < 0.75 {
            self.logoff(timestamp, entity, rng)
        } else if r < 0.90 {
            self.special_privileges(timestamp, entity, rng)
        } else {
            self.process_create_4688(timestamp, entity, rng)
        }
    }

    /// Event ID 4624: Successful logon
    fn logon_success(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        all_entities: &[Entity],
        rng: &mut impl Rng,
    ) -> Event {
        let logon_type = self.random_logon_type(rng);
        let src = self.pick_remote_source(entity, all_entities, rng);
        let protocol = ["Kerberos", "NTLM", "Negotiate"][rng.random_range(0..3)];

        let event_data = serde_json::json!({
            "AuthenticationPackageName": protocol,
            "ElevatedToken": "%%1842",
            "ImpersonationLevel": "%%1833",
            "IpAddress": src.0,
            "IpPort": rng.random_range(49152u16..65535).to_string(),
            "KeyLength": "0",
            "LmPackageName": "-",
            "LogonGuid": format!("{{{}}}", Uuid::now_v7()),
            "LogonProcessName": protocol,
            "LogonType": logon_type.to_string(),
            "ProcessId": "0x0",
            "ProcessName": "-",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "SubjectUserName": "-",
            "SubjectUserSid": "S-1-0-0",
            "TargetDomainName": entity.domain.to_uppercase(),
            "TargetLogonId": format!("0x{:X}", rng.random_range(0x10000u32..0xFFFFF)),
            "TargetUserName": entity.user.split('\\').last().unwrap_or(&entity.user),
            "TargetUserSid": format!("S-1-5-21-{}-{}-{}-{}", rng.random_range(1000000000u32..4000000000), rng.random_range(1000000000u32..4000000000), rng.random_range(1000000000u32..4000000000), rng.random_range(1000u32..9999)),
            "WorkstationName": src.1,
        });

        self.build_event(
            ts,
            entity,
            4624,
            "Logon",
            "An account was successfully logged on.",
            event_data,
            &["Audit Success"],
            &format!("logon {} from {}", entity.user, src.0),
        )
    }

    /// Event ID 4625: Failed logon
    fn logon_failure(
        &self,
        ts: DateTime<Utc>,
        entity: &Entity,
        all_entities: &[Entity],
        rng: &mut impl Rng,
    ) -> Event {
        let logon_type = self.random_logon_type(rng);
        let src = self.pick_remote_source(entity, all_entities, rng);
        let failure_reasons = [
            ("%%2313", "Unknown user name or bad password."),
            ("%%2304", "Account locked out."),
            ("%%2311", "Logon attempt after hours."),
        ];
        let (status, reason) = failure_reasons[rng.random_range(0..failure_reasons.len())];

        let event_data = serde_json::json!({
            "AuthenticationPackageName": "NTLM",
            "FailureReason": reason,
            "IpAddress": src.0,
            "IpPort": rng.random_range(49152u16..65535).to_string(),
            "LogonType": logon_type.to_string(),
            "Status": status,
            "SubStatus": "0xC000006A",
            "SubjectDomainName": "-",
            "SubjectLogonId": "0x0",
            "SubjectUserName": "-",
            "TargetDomainName": entity.domain.to_uppercase(),
            "TargetUserName": entity.user.split('\\').last().unwrap_or(&entity.user),
            "WorkstationName": src.1,
        });

        self.build_event(
            ts,
            entity,
            4625,
            "Logon",
            "An account failed to log on.",
            event_data,
            &["Audit Failure"],
            &format!("failed logon {} from {}", entity.user, src.0),
        )
    }

    /// Event ID 4634: Logoff
    fn logoff(&self, ts: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let event_data = serde_json::json!({
            "LogonType": "3",
            "TargetDomainName": entity.domain.to_uppercase(),
            "TargetLogonId": format!("0x{:X}", rng.random_range(0x10000u32..0xFFFFF)),
            "TargetUserName": entity.user.split('\\').last().unwrap_or(&entity.user),
            "TargetUserSid": format!("S-1-5-21-{}-{}", rng.random_range(1000000000u32..4000000000), rng.random_range(1000u32..9999)),
        });

        self.build_event(
            ts,
            entity,
            4634,
            "Logoff",
            "An account was logged off.",
            event_data,
            &["Audit Success"],
            &format!("logoff {}", entity.user),
        )
    }

    /// Event ID 4672: Special privileges assigned
    fn special_privileges(&self, ts: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let event_data = serde_json::json!({
            "SubjectDomainName": entity.domain.to_uppercase(),
            "SubjectLogonId": format!("0x{:X}", rng.random_range(0x10000u32..0xFFFFF)),
            "SubjectUserName": entity.user.split('\\').last().unwrap_or(&entity.user),
            "SubjectUserSid": format!("S-1-5-21-{}-{}", rng.random_range(1000000000u32..4000000000), rng.random_range(1000u32..9999)),
            "PrivilegeList": "SeSecurityPrivilege\n\t\t\tSeBackupPrivilege\n\t\t\tSeRestorePrivilege\n\t\t\tSeTakeOwnershipPrivilege\n\t\t\tSeDebugPrivilege\n\t\t\tSeSystemEnvironmentPrivilege\n\t\t\tSeLoadDriverPrivilege\n\t\t\tSeImpersonatePrivilege\n\t\t\tSeDelegateSessionUserImpersonatePrivilege\n\t\t\tSeEnableDelegationPrivilege",
        });

        self.build_event(
            ts,
            entity,
            4672,
            "Special Logon",
            "Special privileges assigned to new logon.",
            event_data,
            &["Audit Success"],
            &format!("privs {}", entity.user),
        )
    }

    /// Event ID 4688: Process creation (Security log version)
    fn process_create_4688(&self, ts: DateTime<Utc>, entity: &Entity, rng: &mut impl Rng) -> Event {
        let profiles = crate::profiles::profiles();
        let chain = profiles.sample_process_chain(rng);

        let event_data = serde_json::json!({
            "CommandLine": if chain.command_line.is_empty() { format!("\"{}\"", chain.process_path) } else { chain.command_line.clone() },
            "MandatoryLabel": "S-1-16-8192",
            "NewProcessId": format!("0x{:X}", rng.random_range(1000u32..30000)),
            "NewProcessName": chain.process_path,
            "ParentProcessName": chain.parent_process_path,
            "ProcessId": format!("0x{:X}", rng.random_range(1000u32..30000)),
            "SubjectDomainName": entity.domain.to_uppercase(),
            "SubjectLogonId": format!("0x{:X}", rng.random_range(0x10000u32..0xFFFFF)),
            "SubjectUserName": entity.user.split('\\').last().unwrap_or(&entity.user),
            "SubjectUserSid": format!("S-1-5-21-{}-{}", rng.random_range(1000000000u32..4000000000), rng.random_range(1000u32..9999)),
            "TokenElevationType": "%%1938",
        });

        self.build_event(
            ts,
            entity,
            4688,
            "Process Creation",
            "A new process has been created.",
            event_data,
            &["Audit Success"],
            &chain.process_name,
        )
    }

    fn random_logon_type(&self, rng: &mut impl Rng) -> u8 {
        let r: f64 = rng.random();
        if r < 0.35 {
            3
        }
        // Network
        else if r < 0.60 {
            2
        }
        // Interactive
        else if r < 0.75 {
            5
        }
        // Service
        else if r < 0.87 {
            10
        }
        // RemoteInteractive
        else if r < 0.95 {
            11
        }
        // CachedInteractive
        else {
            4
        } // Batch
    }

    fn pick_remote_source<'a>(
        &self,
        entity: &'a Entity,
        all_entities: &'a [Entity],
        rng: &mut impl Rng,
    ) -> (String, String) {
        if entity.neighbor_indices.is_empty() || all_entities.is_empty() {
            return (entity.ip.clone(), entity.hostname.clone());
        }
        let idx = entity.neighbor_indices[rng.random_range(0..entity.neighbor_indices.len())];
        if idx < all_entities.len() {
            (
                all_entities[idx].ip.clone(),
                all_entities[idx].hostname.clone(),
            )
        } else {
            (entity.ip.clone(), entity.hostname.clone())
        }
    }

    fn build_event(
        &self,
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
            "host": entity.fqdn(),
            "keyword_names": keywords,
            "keywords": "0x8020000000000000",
            "level": "Information",
            "level_value": 0,
            "message": description,
            "process_id": rng.random_range(500u32..5000),
            "provider_guid": "{54849625-5478-4994-a5ba-3e3b0328c30d}",
            "provider_name": "Microsoft-Windows-Security-Auditing",
            "record_id": rng.random_range(10000u32..999999),
            "task": 12544,
            "task_name": task_name,
            "thread_id": rng.random_range(1000u32..10000),
            "timestamp": ts.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string(),
            "version": 2,
        });

        Event {
            message: serde_json::to_string(&message).unwrap(),
            timestamp: ts.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            source_type: "windows_event".to_string(),
            display_label: format!("[winevt:{}] {} {}", event_id, entity.hostname, label),
        }
    }
}
