//! Lateral movement scenario — pivot across hosts via RDP/SMB
//!
//! Scripted sysmon steps go through `process_create_step` (NAN-1058) so the
//! wire payload carries the actual command lines. The `WindowsEventGenerator`
//! call for the RDP/SMB logon stays as a random event — it's noise that
//! contributes to the logon graph but doesn't try to assert a specific
//! command-line pattern.

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::{SysmonGenerator, WindowsEventGenerator};

use super::{process_create_step, AttackScenario, AttackStep};

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

        // Phase 1: Initial compromise — dropper lands on target.
        steps.push(process_create_step(
            &sysmon,
            target,
            now,
            0,
            "update.exe",
            r"C:\Users\Public\Downloads\update.exe",
            r"update.exe --silent --install",
            None,
            "Initial Access",
            format!("Initial compromise on {}", target.hostname),
        ));

        // Phase 2: Recon — enumerate hosts in the domain.
        steps.push(process_create_step(
            &sysmon,
            target,
            now,
            30,
            "net.exe",
            r"C:\Windows\System32\net.exe",
            "net view /domain",
            None,
            "Discovery",
            "net view /domain — enumerate hosts",
        ));

        // Phase 3: Pivot to neighbor hosts via RDP/SMB.
        let pivot_targets: Vec<&Entity> = target
            .neighbor_indices
            .iter()
            .filter_map(|&idx| all_entities.get(idx))
            .take(2)
            .collect();

        for (i, pivot) in pivot_targets.iter().enumerate() {
            let base_delay = 120 + (i as u64 * 300); // 2 min, 7 min

            // RDP/SMB logon event on pivot host — uses the Windows Event
            // generator, not the sysmon process-create path. Detection rules
            // for lateral movement key off Event ID 4624 logon type, which the
            // winevt generator produces correctly.
            steps.push(AttackStep {
                delay: Duration::from_secs(base_delay),
                events: {
                    let ts = now + chrono::Duration::seconds(base_delay as i64);
                    vec![winevt.generate(ts, pivot, all_entities, &mut rng)]
                },
                stage: "Lateral Movement".into(),
                description: format!("Lateral move to {} via RDP/SMB", pivot.hostname),
            });

            steps.push(process_create_step(
                &sysmon,
                pivot,
                now,
                base_delay + 15,
                "whoami.exe",
                r"C:\Windows\System32\whoami.exe",
                "whoami",
                None,
                "Discovery",
                format!("Recon on {}", pivot.hostname),
            ));

            steps.push(process_create_step(
                &sysmon,
                pivot,
                now,
                base_delay + 45,
                "powershell.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r"powershell.exe -enc SQBFAFgA...",
                None,
                "Execution",
                format!("PowerShell execution on {}", pivot.hostname),
            ));
        }

        steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_core::entity::WorldState;

    /// NAN-1058 regression — scripted sysmon steps must carry their command
    /// lines to the wire. The winevt logon steps are not asserted here
    /// (they're random Event ID 4624s for the logon graph).
    #[test]
    fn lateral_scenario_emits_scripted_command_lines() {
        // 100 entities so target picks up a couple of neighbors for the pivot phase.
        let world = WorldState::new(100);
        let target = &world.entities()[0];
        let steps = LateralScenario.generate(target, world.entities());

        let wire: String = steps
            .iter()
            .flat_map(|s| s.events.iter().map(|e| e.message.clone()))
            .collect::<Vec<_>>()
            .join("\n");

        for required in [
            "update.exe",            // initial access
            "net view /domain",      // recon
            // Pivot phase lands at least one of these depending on neighbor count;
            // assert the discovery + execution patterns are present.
            "whoami",
            "powershell.exe -enc",
        ] {
            assert!(
                wire.contains(required),
                "lateral scenario wire payload missing `{required}`. \
                 NAN-1058 regression. Full payload:\n{wire}"
            );
        }
    }
}
