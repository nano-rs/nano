//! Data exfiltration scenario — staging, compression, upload.
//!
//! Sysmon scripted steps go through `process_create_step` (NAN-1058). The two
//! proxy-traffic stages stay as random `proxy.generate` calls because their
//! purpose is "lots of HTTPS uploads", not specific URL patterns.

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::{ProxyGenerator, SysmonGenerator};

use super::{process_create_step, AttackScenario, AttackStep};

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
            process_create_step(
                &sysmon,
                target,
                now,
                0,
                "cmd.exe",
                r"C:\Windows\System32\cmd.exe",
                r"cmd.exe /c dir /s /b C:\Users\*.docx C:\Users\*.xlsx C:\Users\*.pdf",
                None,
                "Collection",
                "Enumerate documents for staging",
            ),
            process_create_step(
                &sysmon,
                target,
                now,
                30,
                "robocopy.exe",
                r"C:\Windows\System32\robocopy.exe",
                r"robocopy C:\Users\Public\Documents C:\temp\staging *.docx *.xlsx *.pdf /S",
                None,
                "Collection",
                "Stage documents to temp directory",
            ),
            process_create_step(
                &sysmon,
                target,
                now,
                90,
                "powershell.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r#"powershell.exe -c "Compress-Archive -Path C:\temp\staging -DestinationPath C:\temp\backup.zip -Force""#,
                None,
                "Exfiltration",
                "Compress staged data",
            ),
            process_create_step(
                &sysmon,
                target,
                now,
                150,
                "certutil.exe",
                r"C:\Windows\System32\certutil.exe",
                r"certutil.exe -encode C:\temp\backup.zip C:\temp\backup.b64",
                None,
                "Exfiltration",
                "Base64 encode for transfer",
            ),
            // Stage 5: HTTPS upload burst — random proxy events for volume.
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
            process_create_step(
                &sysmon,
                target,
                now,
                300,
                "cmd.exe",
                r"C:\Windows\System32\cmd.exe",
                r"cmd.exe /c rd /s /q C:\temp\staging & del /f C:\temp\backup.zip C:\temp\backup.b64",
                None,
                "Defense Evasion",
                "Delete staging artifacts",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_core::entity::WorldState;

    /// NAN-1058 regression — scripted sysmon steps must carry their command
    /// lines. The two proxy-only stages are random and not asserted here.
    #[test]
    fn exfil_scenario_emits_scripted_command_lines() {
        let world = WorldState::new(1);
        let target = world.entities().first().expect("one-entity world");
        let steps = ExfilScenario.generate(target, world.entities());

        let wire: String = steps
            .iter()
            .flat_map(|s| s.events.iter().map(|e| e.message.clone()))
            .collect::<Vec<_>>()
            .join("\n");

        for required in [
            "dir /s /b",         // doc enumeration
            "robocopy",          // staging copy
            "Compress-Archive",  // compression
            "certutil.exe",      // base64 encode
            "-encode",
            "rd /s /q",          // cleanup
        ] {
            assert!(
                wire.contains(required),
                "exfil scenario wire payload missing `{required}`. \
                 NAN-1058 regression. Full payload:\n{wire}"
            );
        }
    }
}
