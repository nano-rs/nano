//! Persistence scenario — multiple persistence mechanisms.
//!
//! All scripted sysmon steps route through `process_create_step` (NAN-1058);
//! the service-creation step uses `process_create_step_as` to spawn under
//! `NT AUTHORITY\SYSTEM` so persistence detection rules that key off
//! SYSTEM-spawned binaries can hit.

use chrono::Utc;

use event_core::entity::Entity;
use event_core::generators::SysmonGenerator;

use super::{process_create_step, process_create_step_as, AttackScenario, AttackStep};

pub struct PersistenceScenario;

impl AttackScenario for PersistenceScenario {
    fn name(&self) -> &str {
        "persistence"
    }

    fn generate(&self, target: &Entity, _all_entities: &[Entity]) -> Vec<AttackStep> {
        let sysmon = SysmonGenerator::new();
        let now = Utc::now();

        let user = target.user.split('\\').last().unwrap_or("user").to_string();
        let startup_cmd = format!(
            r#"cmd.exe /c copy "C:\ProgramData\helper.exe" "C:\Users\{}\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\helper.exe""#,
            user
        );

        vec![
            process_create_step(
                &sysmon,
                target,
                now,
                0,
                "schtasks.exe",
                r"C:\Windows\System32\schtasks.exe",
                r#"schtasks.exe /create /tn "WindowsUpdate" /tr "C:\ProgramData\updater.exe" /sc onlogon /ru SYSTEM"#,
                None,
                "Persistence",
                "Create scheduled task — WindowsUpdate",
            ),
            process_create_step(
                &sysmon,
                target,
                now,
                30,
                "reg.exe",
                r"C:\Windows\System32\reg.exe",
                r#"reg.exe add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v SecurityHelper /t REG_SZ /d "C:\ProgramData\helper.exe" /f"#,
                None,
                "Persistence",
                "Registry Run key — SecurityHelper",
            ),
            process_create_step(
                &sysmon,
                target,
                now,
                60,
                "wmic.exe",
                r"C:\Windows\System32\wbem\WMIC.exe",
                r#"wmic.exe /NAMESPACE:"\\root\subscription" PATH __EventFilter CREATE Name="BotFilter", EventNamespace="root\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'""#,
                None,
                "Persistence",
                "WMI event subscription",
            ),
            process_create_step(
                &sysmon,
                target,
                now,
                90,
                "cmd.exe",
                r"C:\Windows\System32\cmd.exe",
                &startup_cmd,
                None,
                "Persistence",
                "Copy to Startup folder",
            ),
            process_create_step_as(
                &sysmon,
                target,
                now,
                120,
                "sc.exe",
                r"C:\Windows\System32\sc.exe",
                r#"sc.exe create WindowsDefenderUpdate binPath= "C:\ProgramData\svcupdate.exe" start= auto"#,
                Some(r"NT AUTHORITY\SYSTEM"),
                None,
                "Persistence",
                "Create service — WindowsDefenderUpdate",
            ),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use event_core::entity::WorldState;

    /// NAN-1058 regression. All five persistence techniques must carry their
    /// scripted command lines.
    #[test]
    fn persistence_scenario_emits_scripted_command_lines() {
        let world = WorldState::new(1);
        let target = world.entities().first().expect("one-entity world");
        let steps = PersistenceScenario.generate(target, world.entities());

        assert_eq!(steps.len(), 5, "persistence should produce exactly 5 scripted steps");

        let wire: String = steps
            .iter()
            .flat_map(|s| s.events.iter().map(|e| e.message.clone()))
            .collect::<Vec<_>>()
            .join("\n");

        for required in [
            "schtasks.exe",
            "WindowsUpdate",
            "reg.exe",
            "CurrentVersion\\\\Run",
            "wmic.exe",
            "__EventFilter",
            "Startup\\\\helper.exe",
            "sc.exe",
            "WindowsDefenderUpdate",
        ] {
            assert!(
                wire.contains(required),
                "persistence scenario wire payload missing `{required}`. \
                 NAN-1058 regression. Full payload:\n{wire}"
            );
        }
    }
}
