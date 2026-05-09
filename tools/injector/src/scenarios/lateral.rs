//! Lateral movement scenario — pivot across hosts via RDP/SMB

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::{SysmonGenerator, WindowsEventGenerator};

use super::{AttackScenario, AttackStep};

pub struct LateralScenario;

impl AttackScenario for LateralScenario {
    fn name(&self) -> &str {
        "lateral"
    }

    fn generate(&self, target: &Entity, all_entities: &[Entity]) -> Vec<AttackStep> {
        let sysmon = SysmonGenerator::new();
        let winevt = WindowsEventGenerator::new();
        let mut rng = rand::rng();
        let now = Utc::now();
        let mut steps = Vec::new();

        // Phase 1: Initial compromise on target
        steps.push(AttackStep {
            delay: Duration::from_secs(0),
            events: vec![sysmon.generate(now, target, &mut rng)],
            stage: "Initial Access".into(),
            description: format!("Initial compromise on {}", target.hostname),
        });

        // Phase 2: Recon for other hosts
        steps.push(AttackStep {
            delay: Duration::from_secs(30),
            events: {
                let ts = now + chrono::Duration::seconds(30);
                target.spawn_process(
                    "net.exe",
                    r"C:\Windows\System32\net.exe",
                    "net view /domain",
                    None,
                );
                vec![sysmon.generate(ts, target, &mut rng)]
            },
            stage: "Discovery".into(),
            description: "net view /domain — enumerate hosts".into(),
        });

        // Phase 3: Pivot to neighbor hosts
        let pivot_targets: Vec<&Entity> = target
            .neighbor_indices
            .iter()
            .filter_map(|&idx| all_entities.get(idx))
            .take(2)
            .collect();

        for (i, pivot) in pivot_targets.iter().enumerate() {
            let base_delay = 120 + (i as u64 * 300); // 2min, 7min

            // RDP/SMB logon event on pivot target
            steps.push(AttackStep {
                delay: Duration::from_secs(base_delay),
                events: {
                    let ts = now + chrono::Duration::seconds(base_delay as i64);
                    vec![winevt.generate(ts, pivot, all_entities, &mut rng)]
                },
                stage: "Lateral Movement".into(),
                description: format!("Lateral move to {} via RDP/SMB", pivot.hostname),
            });

            // Recon on pivot host
            steps.push(AttackStep {
                delay: Duration::from_secs(base_delay + 15),
                events: {
                    let ts = now + chrono::Duration::seconds(base_delay as i64 + 15);
                    pivot.spawn_process(
                        "whoami.exe",
                        r"C:\Windows\System32\whoami.exe",
                        "whoami",
                        None,
                    );
                    vec![sysmon.generate(ts, pivot, &mut rng)]
                },
                stage: "Discovery".into(),
                description: format!("Recon on {}", pivot.hostname),
            });

            // Process execution on pivot
            steps.push(AttackStep {
                delay: Duration::from_secs(base_delay + 45),
                events: {
                    let ts = now + chrono::Duration::seconds(base_delay as i64 + 45);
                    pivot.spawn_process(
                        "powershell.exe",
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                        r"powershell.exe -enc SQBFAFgA...",
                        None,
                    );
                    vec![sysmon.generate(ts, pivot, &mut rng)]
                },
                stage: "Execution".into(),
                description: format!("PowerShell execution on {}", pivot.hostname),
            });
        }

        steps
    }
}
