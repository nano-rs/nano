//! Persistence scenario — multiple persistence mechanisms

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::SysmonGenerator;

use super::{AttackScenario, AttackStep};

pub struct PersistenceScenario;

impl AttackScenario for PersistenceScenario {
    fn name(&self) -> &str {
        "persistence"
    }

    fn generate(&self, target: &Entity, _all_entities: &[Entity]) -> Vec<AttackStep> {
        let sysmon = SysmonGenerator::new();
        let mut rng = rand::rng();
        let now = Utc::now();

        vec![
            // Scheduled task
            AttackStep {
                delay: Duration::from_secs(0),
                events: {
                    target.spawn_process("schtasks.exe", r"C:\Windows\System32\schtasks.exe",
                        r#"schtasks.exe /create /tn "WindowsUpdate" /tr "C:\ProgramData\updater.exe" /sc onlogon /ru SYSTEM"#, None);
                    vec![sysmon.generate(now, target, &mut rng)]
                },
                stage: "Persistence".into(),
                description: "Create scheduled task — WindowsUpdate".into(),
            },
            // Registry Run key
            AttackStep {
                delay: Duration::from_secs(30),
                events: {
                    let ts = now + chrono::Duration::seconds(30);
                    target.spawn_process("reg.exe", r"C:\Windows\System32\reg.exe",
                        r#"reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v SecurityHelper /t REG_SZ /d "C:\ProgramData\helper.exe" /f"#, None);
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Persistence".into(),
                description: "Registry Run key — SecurityHelper".into(),
            },
            // WMI event subscription
            AttackStep {
                delay: Duration::from_secs(60),
                events: {
                    let ts = now + chrono::Duration::seconds(60);
                    target.spawn_process("wmic.exe", r"C:\Windows\System32\wbem\WMIC.exe",
                        r#"wmic.exe /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="BotFilter", EventNamespace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'""#, None);
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Persistence".into(),
                description: "WMI event subscription".into(),
            },
            // Startup folder
            AttackStep {
                delay: Duration::from_secs(90),
                events: {
                    let ts = now + chrono::Duration::seconds(90);
                    let user = target.user.split('\\').last().unwrap_or("user");
                    target.spawn_process("cmd.exe", r"C:\Windows\System32\cmd.exe",
                        &format!(r#"cmd.exe /c copy "C:\ProgramData\helper.exe" "C:\Users\{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.exe""#, user), None);
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Persistence".into(),
                description: "Copy to Startup folder".into(),
            },
            // Service creation
            AttackStep {
                delay: Duration::from_secs(120),
                events: {
                    let ts = now + chrono::Duration::seconds(120);
                    target.spawn_process("sc.exe", r"C:\Windows\System32\sc.exe",
                        r#"sc.exe create WindowsDefenderUpdate binPath= "C:\ProgramData\svcupdate.exe" start= auto"#,
                        Some(r"NT AUTHORITY\SYSTEM"));
                    vec![sysmon.generate(ts, target, &mut rng)]
                },
                stage: "Persistence".into(),
                description: "Create service — WindowsDefenderUpdate".into(),
            },
        ]
    }
}
