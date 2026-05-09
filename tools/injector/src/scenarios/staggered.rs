//! Staggered low-and-slow APT scenario — C2 beacons spread over time

use chrono::Utc;
use std::time::Duration;

use event_core::entity::Entity;
use event_core::generators::{ProxyGenerator, SysmonGenerator};

use super::{AttackScenario, AttackStep};

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

        // Initial access
        steps.push(AttackStep {
            delay: Duration::from_secs(0),
            events: vec![sysmon.generate(now, target, &mut rng)],
            stage: "Initial Access".into(),
            description: format!("Backdoor installed on {}", target.hostname),
        });

        // C2 beacons every 5-15 minutes over 1 hour
        let beacon_intervals = [
            300, 420, 780, 900, 1200, 1500, 1860, 2100, 2520, 2880, 3300, 3600,
        ];
        for (i, &delay) in beacon_intervals.iter().enumerate() {
            let ts = now + chrono::Duration::seconds(delay as i64);

            // Alternate between process-based and proxy-based beacons
            if i % 3 == 0 {
                // Proxy beacon: HTTP callback to C2
                steps.push(AttackStep {
                    delay: Duration::from_secs(delay),
                    events: vec![proxy.generate(ts, target, &mut rng)],
                    stage: "Command & Control".into(),
                    description: format!("C2 beacon #{} via HTTPS", i + 1),
                });
            } else {
                // Process beacon: rundll32 or powershell callback
                target.spawn_process(
                    "rundll32.exe",
                    r"C:\Windows\System32\rundll32.exe",
                    r"rundll32.exe javascript:void(0)",
                    None,
                );
                steps.push(AttackStep {
                    delay: Duration::from_secs(delay),
                    events: vec![sysmon.generate(ts, target, &mut rng)],
                    stage: "Command & Control".into(),
                    description: format!("C2 beacon #{} via rundll32", i + 1),
                });
            }

            // Intermittent recon (every 3rd beacon)
            if i % 3 == 2 {
                let recon_delay = delay + 30;
                let ts2 = now + chrono::Duration::seconds(recon_delay as i64);
                let recon_cmds = [
                    "systeminfo",
                    "tasklist",
                    "net user /domain",
                    "nltest /dclist:",
                ];
                let cmd = recon_cmds[i / 3 % recon_cmds.len()];
                let exe = if cmd.starts_with("net ") || cmd.starts_with("nltest") {
                    "net.exe"
                } else {
                    &format!("{}.exe", cmd.split_whitespace().next().unwrap_or("cmd"))
                };
                target.spawn_process(exe, &format!(r"C:\Windows\System32\{}", exe), cmd, None);
                steps.push(AttackStep {
                    delay: Duration::from_secs(recon_delay),
                    events: vec![sysmon.generate(ts2, target, &mut rng)],
                    stage: "Discovery".into(),
                    description: format!("Staggered recon: {}", cmd),
                });
            }
        }

        steps
    }
}
