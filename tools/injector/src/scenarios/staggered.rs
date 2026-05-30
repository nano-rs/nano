//! Staggered low-and-slow APT scenario — C2 beacons spread over time.
//!
//! Sysmon scripted steps go through `process_create_step` (NAN-1058) so the
//! rundll32 javascript and recon command lines actually land on the wire.
//! Proxy beacons remain random (their purpose is volume/cadence, not specific
//! payload patterns).

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::{ProxyGenerator, SysmonGenerator};

use super::{process_create_step, AttackScenario, AttackStep};

pub struct StaggeredScenario;

impl AttackScenario for StaggeredScenario {
    fn name(&self) -> &str {
        "staggered"
    }

    fn generate(&self, target: &Entity, _all_entities: &[Entity]) -> Vec<AttackStep> {
        let sysmon = SysmonGenerator::new();
        let proxy = ProxyGenerator::new();
        let mut rng = rand::rng();
        let now = Utc::now();
        let mut steps = Vec::new();

        // Initial access — backdoor binary lands on disk and executes.
        steps.push(process_create_step(
            &sysmon,
            target,
            now,
            0,
            "svchost_helper.exe",
            r"C:\ProgramData\svchost_helper.exe",
            r"svchost_helper.exe --service",
            None,
            "Initial Access",
            format!("Backdoor installed on {}", target.hostname),
        ));

        // C2 beacons every 5-15 minutes over 1 hour.
        let beacon_intervals = [
            300u64, 420, 780, 900, 1200, 1500, 1860, 2100, 2520, 2880, 3300, 3600,
        ];
        for (i, &delay) in beacon_intervals.iter().enumerate() {
            if i % 3 == 0 {
                // Proxy beacon: HTTP callback to C2 — random payload is fine,
                // matches against proxy-based detection rules (URL/IP based).
                let ts = now + chrono::Duration::seconds(delay as i64);
                steps.push(AttackStep {
                    delay: Duration::from_secs(delay),
                    events: vec![proxy.generate(ts, target, &mut rng)],
                    stage: "Command & Control".into(),
                    description: format!("C2 beacon #{} via HTTPS", i + 1),
                });
            } else {
                // Process beacon: rundll32 javascript callback.
                steps.push(process_create_step(
                    &sysmon,
                    target,
                    now,
                    delay,
                    "rundll32.exe",
                    r"C:\Windows\System32\rundll32.exe",
                    r"rundll32.exe javascript:void(0)",
                    None,
                    "Command & Control",
                    format!("C2 beacon #{} via rundll32", i + 1),
                ));
            }

            // Intermittent recon (every 3rd beacon).
            if i % 3 == 2 {
                let recon_cmds = ["systeminfo", "tasklist", "net user /domain", "nltest /dclist:"];
                let cmd = recon_cmds[i / 3 % recon_cmds.len()];
                let exe_owned = if cmd.starts_with("net ") || cmd.starts_with("nltest") {
                    "net.exe".to_string()
                } else {
                    // first word + .exe — e.g. "systeminfo" -> "systeminfo.exe"
                    format!("{}.exe", cmd.split_whitespace().next().unwrap_or("cmd"))
                };
                let path = format!(r"C:\Windows\System32\{}", exe_owned);
                steps.push(process_create_step(
                    &sysmon,
                    target,
                    now,
                    delay + 30,
                    &exe_owned,
                    &path,
                    cmd,
                    None,
                    "Discovery",
                    format!("Staggered recon: {}", cmd),
                ));
            }
        }

        steps
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_core::entity::WorldState;

    /// NAN-1058 regression — scripted sysmon steps must carry their command
    /// lines. Proxy beacons are random; not asserted.
    #[test]
    fn staggered_scenario_emits_scripted_command_lines() {
        let world = WorldState::new(1);
        let target = world.entities().first().expect("one-entity world");
        let steps = StaggeredScenario.generate(target, world.entities());

        let wire: String = steps
            .iter()
            .flat_map(|s| s.events.iter().map(|e| e.message.clone()))
            .collect::<Vec<_>>()
            .join("\n");

        for required in [
            "svchost_helper.exe",          // initial access backdoor
            "rundll32.exe javascript",     // C2 beacon process pattern
        ] {
            assert!(
                wire.contains(required),
                "staggered scenario wire payload missing `{required}`. \
                 NAN-1058 regression. Full payload:\n{wire}"
            );
        }

        // At least one recon command must appear in the payload.
        let recon_present = ["systeminfo", "tasklist", "net user /domain", "nltest"]
            .iter()
            .any(|tok| wire.contains(tok));
        assert!(
            recon_present,
            "staggered scenario should emit at least one intermittent recon command, \
             none found in payload:\n{wire}"
        );
    }
}
