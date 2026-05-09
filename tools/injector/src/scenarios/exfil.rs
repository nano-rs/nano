//! Data exfiltration scenario — staging, compression, upload

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::{ProxyGenerator, SysmonGenerator};

use super::{AttackScenario, AttackStep};

pub struct ExfilScenario;

impl AttackScenario for ExfilScenario {
    fn name(&self) -> &str {
        "exfil"
    }

    fn generate(&self, target: &Entity, _all_entities: &[Entity]) -> Vec<AttackStep> {
        let sysmon = SysmonGenerator::new();
        let proxy = ProxyGenerator::new();
        let mut rng = rand::rng();
        let now = Utc::now();

        vec![
            // Stage 1: Discovery — find valuable data
            AttackStep {
                delay: Duration::from_secs(0),
                events: {
                    target.spawn_process(
                        "cmd.exe",
                        r"C:\Windows\System32\cmd.exe",
                        r"cmd.exe /c dir /s /b C:\Users\*.docx C:\Users\*.xlsx C:\Users\*.pdf",
                        None,
                    );
                    vec![sysmon.generate(now, target, &mut rng)]
                },
                stage: "Collection".into(),
                description: "Enumerate documents for staging".into(),
            },
            // Stage 2: Copy files to staging directory
            AttackStep {
                delay: Duration::from_secs(30),
                events: {
                    let ts = now + chrono::Duration::seconds(30);
                    target.spawn_process("robocopy.exe", r"C:\Windows\System32\robocopy.exe",
                        r"robocopy C:\Users\Public\Documents C:\temp\staging *.docx *.xlsx *.pdf /S", None);
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Collection".into(),
                description: "Stage documents to temp directory".into(),
            },
            // Stage 3: Compress
            AttackStep {
                delay: Duration::from_secs(90),
                events: {
                    let ts = now + chrono::Duration::seconds(90);
                    target.spawn_process("powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        r#"powershell.exe -c "Compress-Archive -Path C:\temp\staging -DestinationPath C:\temp\backup.zip -Force""#, None);
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Exfiltration".into(),
                description: "Compress staged data".into(),
            },
            // Stage 4: Split into chunks (evade size-based detection)
            AttackStep {
                delay: Duration::from_secs(150),
                events: {
                    let ts = now + chrono::Duration::seconds(150);
                    target.spawn_process(
                        "certutil.exe",
                        r"C:\Windows\System32\certutil.exe",
                        r"certutil.exe -encode C:\temp\backup.zip C:\temp\backup.b64",
                        None,
                    );
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Exfiltration".into(),
                description: "Base64 encode for transfer".into(),
            },
            // Stage 5: Exfil via multiple HTTPS connections
            AttackStep {
                delay: Duration::from_secs(210),
                events: {
                    let ts = now + chrono::Duration::seconds(210);
                    vec![
                        proxy.generate(ts, target, &mut rng),
                        proxy.generate(ts, target, &mut rng),
                        proxy.generate(ts, target, &mut rng),
                    ]
                },
                stage: "Exfiltration".into(),
                description: "Upload chunks via HTTPS to cloud storage".into(),
            },
            // Stage 6: More exfil traffic
            AttackStep {
                delay: Duration::from_secs(240),
                events: {
                    let ts = now + chrono::Duration::seconds(240);
                    vec![
                        proxy.generate(ts, target, &mut rng),
                        proxy.generate(ts, target, &mut rng),
                    ]
                },
                stage: "Exfiltration".into(),
                description: "Continue upload".into(),
            },
            // Stage 7: Cleanup
            AttackStep {
                delay: Duration::from_secs(300),
                events: {
                    let ts = now + chrono::Duration::seconds(300);
                    target.spawn_process("cmd.exe", r"C:\Windows\System32\cmd.exe",
                        r"cmd.exe /c rd /s /q C:\temp\staging & del /f C:\temp\backup.zip C:\temp\backup.b64", None);
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Defense Evasion".into(),
                description: "Delete staging artifacts".into(),
            },
        ]
    }
}
