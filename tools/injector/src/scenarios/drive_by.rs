//! Drive-by download campaign — search ad redirect, archive delivery, script
//! execution, discovery, persistence, C2, and cleanup.
//!
//! All indicators are inert event data. Reserved `.test` domains and TEST-NET
//! addresses ensure the scenario cannot contact real campaign infrastructure.

use chrono::{DateTime, Utc};
use std::time::Duration;

use event_core::entity::{Entity, Process};
use event_core::generators::{ProxyGenerator, ScriptedProxyEvent, SysmonGenerator};

use super::{AttackScenario, AttackStep};

pub const DEFAULT_SAMPLE_SHA256: &str =
    "3e120cc23a568678151b2bc258291511e3fa0b5983f7cf301aac95e4c0d2a44c";
pub const DEFAULT_SAMPLE_NAME: &str = "EhDSjenZsx.js";

const PHISH_DOMAIN: &str = "search-check-results.test";
const PHISH_IP: &str = "198.51.100.42";
const C2_DOMAIN: &str = "cdn-session-check.test";
const C2_IP: &str = "203.0.113.77";

pub struct DriveByScenario {
    sample_sha256: String,
    sample_name: String,
}

impl DriveByScenario {
    pub fn new(sample_sha256: impl Into<String>, sample_name: impl Into<String>) -> Self {
        Self {
            sample_sha256: sample_sha256.into(),
            sample_name: sample_name.into(),
        }
    }
}

impl AttackScenario for DriveByScenario {
    fn name(&self) -> &str {
        "drive-by"
    }

    fn generate(&self, target: &Entity, _all_entities: &[Entity]) -> Vec<AttackStep> {
        let sysmon = SysmonGenerator::new();
        let proxy = ProxyGenerator::new();
        let now = Utc::now();
        let username = target.user.split('\\').next_back().unwrap_or("user");
        let downloads = format!(r"C:\Users\{username}\Downloads");
        let zip_path = format!(r"{downloads}\search_term.zip");
        let sample_path = format!(r"{downloads}\search_term\{}", self.sample_name);
        let stage_path = format!(r"C:\Users\{username}\AppData\Local\Temp\stage.ps1");

        // A normal, profiled browser starts the chain. Its executable hash comes
        // from the same profile as background log-blaster traffic.
        let (browser, browser_parent) = target.spawn_process(
            "msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r#""C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --profile-directory=Default"#,
            None,
        );

        let mut steps = vec![process_step(
            &sysmon,
            target,
            now,
            0,
            &browser,
            &browser_parent,
            "User Execution",
            "Browser session started",
        )];

        steps.push(proxy_step(
            &proxy,
            target,
            now,
            5,
            ScriptedProxyEvent {
                host: "www.google.com",
                path: "/search?q=windows+document+search+tool",
                method: "GET",
                status: 200,
                upstream_ip: "142.250.72.196",
                referrer: None,
                category: "search-engines",
                content_type: "text/html",
                response_bytes: 48_312,
                threat_score: 0.01,
                threat_signals: &["known_good"],
            },
            "Google search",
        ));

        steps.push(proxy_step(
            &proxy,
            target,
            now,
            12,
            ScriptedProxyEvent {
                host: "www.googleadservices.com",
                path: "/pagead/aclk?sa=L&ai=promoted-search-result",
                method: "GET",
                status: 302,
                upstream_ip: "142.250.72.194",
                referrer: Some("https://www.google.com/search?q=windows+document+search+tool"),
                category: "advertising",
                content_type: "text/html",
                response_bytes: 842,
                threat_score: 0.02,
                threat_signals: &["known_good"],
            },
            "Sponsored search result clicked",
        ));

        steps.push(AttackStep {
            delay: Duration::from_secs(14),
            events: vec![sysmon.dns_query_from(
                timestamp(now, 14),
                target,
                &browser,
                PHISH_DOMAIN,
                PHISH_IP,
            )],
            stage: "Initial Access".into(),
            description: format!("Browser resolved low-prevalence redirect domain {PHISH_DOMAIN}"),
        });

        steps.push(proxy_step(
            &proxy,
            target,
            now,
            15,
            ScriptedProxyEvent {
                host: PHISH_DOMAIN,
                path: "/search/windows-document-indexer",
                method: "GET",
                status: 200,
                upstream_ip: PHISH_IP,
                referrer: Some(
                    "https://www.googleadservices.com/pagead/aclk?sa=L&ai=promoted-search-result",
                ),
                category: "uncategorized",
                content_type: "text/html",
                response_bytes: 17_904,
                threat_score: 0.86,
                threat_signals: &["newly_registered", "reputation_low"],
            },
            "Phishing landing page loaded",
        ));

        steps.push(proxy_step(
            &proxy,
            target,
            now,
            24,
            ScriptedProxyEvent {
                host: PHISH_DOMAIN,
                path: "/downloads/search_term.zip",
                method: "GET",
                status: 200,
                upstream_ip: PHISH_IP,
                referrer: Some(&format!(
                    "https://{PHISH_DOMAIN}/search/windows-document-indexer"
                )),
                category: "uncategorized",
                content_type: "application/zip",
                response_bytes: 184_772,
                threat_score: 0.91,
                threat_signals: &["newly_registered", "reputation_low", "archive_download"],
            },
            "Archive downloaded from phishing site",
        ));

        steps.push(AttackStep {
            delay: Duration::from_secs(25),
            events: vec![sysmon.file_create_from(
                timestamp(now, 25),
                target,
                &browser,
                &zip_path,
                None,
            )],
            stage: "Initial Access".into(),
            description: format!("Browser wrote {zip_path}"),
        });

        // Opening a ZIP from the browser invokes Explorer's compressed-folder
        // handler. Preserve browser -> Explorer parentage for the handoff.
        let (archive, archive_parent) = target.spawn_process_from(
            &browser,
            "explorer.exe",
            r"C:\Windows\explorer.exe",
            &format!(r#"explorer.exe "{zip_path}""#),
            None,
        );
        steps.push(process_step(
            &sysmon,
            target,
            now,
            52,
            &archive,
            &archive_parent,
            "User Execution",
            "User opened downloaded ZIP archive",
        ));

        // This is the sole novel hash in the campaign. It belongs to the
        // extracted JavaScript file, not to Explorer or Windows Script Host.
        steps.push(AttackStep {
            delay: Duration::from_secs(55),
            events: vec![sysmon.file_create_from(
                timestamp(now, 55),
                target,
                &archive,
                &sample_path,
                Some(&self.sample_sha256),
            )],
            stage: "Initial Access".into(),
            description: format!("Extracted {} from search_term.zip", self.sample_name),
        });

        let (wscript, wscript_parent) = target.spawn_process_from(
            &archive,
            "wscript.exe",
            r"C:\Windows\System32\wscript.exe",
            &format!(r#"wscript.exe "{sample_path}""#),
            None,
        );
        steps.push(process_step(
            &sysmon,
            target,
            now,
            70,
            &wscript,
            &wscript_parent,
            "Execution",
            format!("Windows Script Host executed {}", self.sample_name),
        ));

        steps.push(AttackStep {
            delay: Duration::from_secs(72),
            events: vec![sysmon.dns_query_from(
                timestamp(now, 72),
                target,
                &wscript,
                C2_DOMAIN,
                C2_IP,
            )],
            stage: "Command & Control".into(),
            description: format!("Script host resolved {C2_DOMAIN}"),
        });
        steps.push(AttackStep {
            delay: Duration::from_secs(73),
            events: vec![sysmon.network_connect_from(
                timestamp(now, 73),
                target,
                &wscript,
                C2_DOMAIN,
                C2_IP,
                443,
            )],
            stage: "Command & Control".into(),
            description: "Windows Script Host opened TLS connection to C2".into(),
        });
        steps.push(proxy_step(
            &proxy,
            target,
            now,
            74,
            ScriptedProxyEvent {
                host: C2_DOMAIN,
                path: "/api/v1/session",
                method: "POST",
                status: 200,
                upstream_ip: C2_IP,
                referrer: None,
                category: "uncategorized",
                content_type: "application/octet-stream",
                response_bytes: 1_248,
                threat_score: 0.94,
                threat_signals: &["newly_registered", "reputation_low", "beacon_pattern"],
            },
            "First C2 check-in",
        ));

        steps.push(AttackStep {
            delay: Duration::from_secs(80),
            events: vec![sysmon.file_create_from(
                timestamp(now, 80),
                target,
                &wscript,
                &stage_path,
                None,
            )],
            stage: "Execution".into(),
            description: format!("Script host wrote PowerShell stage {stage_path}"),
        });

        let (powershell, powershell_parent) = target.spawn_process_from(
            &wscript,
            "powershell.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            &format!(
                r#"powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{stage_path}""#
            ),
            None,
        );
        steps.push(process_step(
            &sysmon,
            target,
            now,
            88,
            &powershell,
            &powershell_parent,
            "Execution",
            "Script host launched hidden PowerShell stage",
        ));

        let (whoami, whoami_parent) = target.spawn_process_from(
            &powershell,
            "whoami.exe",
            r"C:\Windows\System32\whoami.exe",
            "whoami.exe /all",
            None,
        );
        steps.push(process_step(
            &sysmon,
            target,
            now,
            100,
            &whoami,
            &whoami_parent,
            "Discovery",
            "Enumerate current identity and privileges",
        ));

        let (ipconfig, ipconfig_parent) = target.spawn_process_from(
            &powershell,
            "ipconfig.exe",
            r"C:\Windows\System32\ipconfig.exe",
            "ipconfig.exe /all",
            None,
        );
        steps.push(process_step(
            &sysmon,
            target,
            now,
            105,
            &ipconfig,
            &ipconfig_parent,
            "Discovery",
            "Enumerate local network configuration",
        ));

        let run_command = format!(
            r#"reg.exe add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v SearchIndexerUpdate /t REG_SZ /d "wscript.exe \"{sample_path}\"" /f"#
        );
        let (reg, reg_parent) = target.spawn_process_from(
            &powershell,
            "reg.exe",
            r"C:\Windows\System32\reg.exe",
            &run_command,
            None,
        );
        steps.push(process_step(
            &sysmon,
            target,
            now,
            120,
            &reg,
            &reg_parent,
            "Persistence",
            "Create per-user Run-key persistence",
        ));

        let cleanup_command = format!(r#"cmd.exe /c del /f /q "{zip_path}""#);
        let (cleanup, cleanup_parent) = target.spawn_process_from(
            &powershell,
            "cmd.exe",
            r"C:\Windows\System32\cmd.exe",
            &cleanup_command,
            None,
        );
        steps.push(process_step(
            &sysmon,
            target,
            now,
            150,
            &cleanup,
            &cleanup_parent,
            "Defense Evasion",
            "Delete downloaded archive after execution",
        ));

        steps
    }
}

fn timestamp(base: DateTime<Utc>, delay_secs: u64) -> DateTime<Utc> {
    base + chrono::Duration::seconds(delay_secs as i64)
}

#[allow(clippy::too_many_arguments)]
fn process_step(
    sysmon: &SysmonGenerator,
    target: &Entity,
    base: DateTime<Utc>,
    delay_secs: u64,
    child: &Process,
    parent: &Process,
    stage: &str,
    description: impl Into<String>,
) -> AttackStep {
    AttackStep {
        delay: Duration::from_secs(delay_secs),
        events: vec![sysmon.process_create_from_profile(
            timestamp(base, delay_secs),
            target,
            child,
            parent,
        )],
        stage: stage.into(),
        description: description.into(),
    }
}

#[allow(clippy::too_many_arguments)]
fn proxy_step(
    proxy: &ProxyGenerator,
    target: &Entity,
    base: DateTime<Utc>,
    delay_secs: u64,
    spec: ScriptedProxyEvent<'_>,
    description: impl Into<String>,
) -> AttackStep {
    AttackStep {
        delay: Duration::from_secs(delay_secs),
        events: vec![proxy.scripted(timestamp(base, delay_secs), target, spec)],
        stage: if delay_secs < 24 {
            "Initial Access".into()
        } else if delay_secs < 70 {
            "Execution".into()
        } else {
            "Command & Control".into()
        },
        description: description.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_core::entity::WorldState;

    #[test]
    fn drive_by_campaign_is_ordered_and_keeps_the_only_novel_hash_on_the_js_file() {
        let world = WorldState::new(3);
        let target = world.entities().first().expect("one target");
        let steps = DriveByScenario::new(DEFAULT_SAMPLE_SHA256, DEFAULT_SAMPLE_NAME)
            .generate(target, world.entities());

        assert_eq!(steps.len(), 19);
        assert!(steps.windows(2).all(|pair| pair[0].delay < pair[1].delay));

        let events = steps
            .iter()
            .flat_map(|step| step.events.iter())
            .collect::<Vec<_>>();
        let wire = events
            .iter()
            .map(|event| event.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        for required in [
            "www.google.com",
            "www.googleadservices.com",
            PHISH_DOMAIN,
            "search_term.zip",
            DEFAULT_SAMPLE_NAME,
            DEFAULT_SAMPLE_SHA256,
            "wscript.exe",
            "powershell.exe",
            "stage.ps1",
            "whoami.exe /all",
            "ipconfig.exe /all",
            "CurrentVersion\\\\Run",
            C2_DOMAIN,
        ] {
            assert!(
                wire.contains(required),
                "campaign wire payload missing `{required}`:\n{wire}"
            );
        }

        assert_eq!(
            wire.matches(DEFAULT_SAMPLE_SHA256).count(),
            1,
            "the malicious hash must describe only the extracted JS file"
        );
        assert_eq!(
            events
                .iter()
                .filter(|event| event.source_type == "conduit_proxy")
                .count(),
            5
        );

        let js_event = events
            .iter()
            .find(|event| event.message.contains(DEFAULT_SAMPLE_SHA256))
            .expect("hashed JS file event");
        assert_eq!(js_event.source_type, "windows_sysmon");
        assert!(js_event.message.contains(r#""event_id":11"#));

        let stage_event = events
            .iter()
            .find(|event| event.message.contains(r"stage.ps1"))
            .expect("PowerShell stage file event");
        assert!(stage_event.message.contains(r#""event_id":11"#));
        assert!(stage_event.message.contains(r#""Hashes":"""#));
        assert!(stage_event
            .message
            .contains(r#""Image":"C:\\Windows\\System32\\wscript.exe""#));

        let wscript_event = events
            .iter()
            .find(|event| {
                event
                    .message
                    .contains(r#""OriginalFileName":"wscript.exe""#)
            })
            .expect("wscript process event");
        assert!(
            wscript_event.message.contains(r#""Hashes":"""#),
            "unprofiled wscript must omit its hash instead of inventing a low-prevalence value"
        );
        assert!(
            wscript_event
                .message
                .contains(r#""ParentImage":"C:\\Windows\\explorer.exe""#),
            "the archive-open parentage must be preserved"
        );

        let powershell_event = events
            .iter()
            .find(|event| {
                event
                    .message
                    .contains(r#""OriginalFileName":"powershell.exe""#)
            })
            .expect("PowerShell process event");
        let normal_powershell_hash = event_core::profiles::profiles()
            .process_hash_for(
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                "powershell.exe",
            )
            .expect("PowerShell exists in normal profile");
        assert!(
            powershell_event
                .message
                .contains(&format!(r#""Hashes":"SHA256={normal_powershell_hash}""#)),
            "PowerShell must reuse its normal log-sender hash"
        );
        assert!(
            powershell_event
                .message
                .contains(r#""ParentImage":"C:\\Windows\\System32\\wscript.exe""#),
            "script-host parentage must be preserved"
        );
    }

    #[test]
    fn scripted_proxy_events_keep_target_identity_and_campaign_urls() {
        let target = Entity::new(
            "WS-FIN-042",
            r"CORP\alice",
            "10.1.4.2",
            "00:50:56:11:22:33",
            "corp.local",
        );
        let steps =
            DriveByScenario::new(DEFAULT_SAMPLE_SHA256, DEFAULT_SAMPLE_NAME).generate(&target, &[]);
        let proxy_wire = steps
            .iter()
            .flat_map(|step| step.events.iter())
            .filter(|event| event.source_type == "conduit_proxy")
            .map(|event| event.message.as_str())
            .collect::<Vec<_>>()
            .join("\n");

        assert!(proxy_wire.contains(r#""username":"CORP\\alice""#));
        assert!(proxy_wire.contains(r#""client_ip":"10.1.4.2""#));
        assert!(proxy_wire.contains(r#""content_type":"application/zip""#));
        assert!(proxy_wire.contains(r#""referrer":"https://www.google.com/"#));
    }
}
