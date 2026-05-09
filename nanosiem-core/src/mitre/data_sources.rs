// SPDX-License-Identifier: AGPL-3.0-or-later

//! Mapping from MITRE ATT&CK data sources to nanosiem source types.
//!
//! The MITRE STIX bundle declares required data sources per technique using
//! human-readable labels like `"Process: Process Creation"` or
//! `"Network Traffic: Flow"`. To decide whether a given technique is "covered"
//! by our telemetry, we map each MITRE label to one or more nanosiem
//! `source_type` identifiers (the same identifiers that appear in detection
//! rule nPL queries — e.g. `source_type=windows_sysmon`).
//!
//! A MITRE data source is considered *connected* when at least one detection
//! rule in this deployment queries a `source_type` in its mapped set.
//!
//! ## Coverage of the mapping
//!
//! This is intentionally a curated subset — not every MITRE data source has
//! an entry. Unknown labels yield an empty mapping and the data source will
//! always render as `connected = false`. This is the right default: we'd
//! rather under-report coverage than fabricate it.
//!
//! ## Stable ids
//!
//! Each MITRE label is also mapped to a stable lowercase snake_case `id`
//! that the frontend can use as a React key / filter token. The id is derived
//! deterministically from the label by [`stable_id`].

/// Returns the set of nanosiem `source_type` identifiers that satisfy the
/// MITRE data-source label `mitre_label`. Returns an empty slice when the
/// label is unknown (in which case the data source is treated as not
/// connected).
///
/// Match is case-insensitive on the label.
pub fn nanosiem_sources_for(mitre_label: &str) -> &'static [&'static str] {
    let normalized = mitre_label.trim().to_ascii_lowercase();
    for (label, sources) in MAPPING {
        if label.eq_ignore_ascii_case(&normalized) {
            return sources;
        }
    }
    // Fallback: try matching the prefix before the first `:`. MITRE labels
    // are formatted as `"Category: Component"`; some bundles drop the
    // component portion. This lets us still match the broader category.
    if let Some((prefix, _)) = normalized.split_once(':') {
        let prefix = prefix.trim();
        for (label, sources) in MAPPING {
            if let Some((label_prefix, _)) = label.split_once(':') {
                if label_prefix.trim().eq_ignore_ascii_case(prefix) {
                    return sources;
                }
            }
        }
    }
    &[]
}

/// Derive a stable lowercase snake_case id from a MITRE data source label.
/// Used as the `DataSource.id` returned to the frontend.
///
/// `"Process: Process Creation"` → `"process__process_creation"`
/// `"Network Traffic: Flow"`     → `"network_traffic__flow"`
pub fn stable_id(mitre_label: &str) -> String {
    let mut out = String::with_capacity(mitre_label.len());
    let mut last_was_sep = true;
    for ch in mitre_label.chars() {
        if ch.is_ascii_alphanumeric() {
            out.extend(ch.to_lowercase());
            last_was_sep = false;
        } else if !last_was_sep {
            out.push('_');
            last_was_sep = true;
        }
    }
    // Trim trailing underscores
    while out.ends_with('_') {
        out.pop();
    }
    out
}

/// Curated MITRE data source label → nanosiem source_type set.
///
/// Labels are taken verbatim from the ATT&CK STIX bundle's
/// `x_mitre_data_sources` strings. Source types match the `source_type`
/// values used in nPL queries (which in turn are the parser identifiers
/// under `config/vector/sources/parsers/`).
///
/// Adding to this mapping is safe: unknown labels simply return `connected =
/// false`. Removing entries downgrades reported coverage for affected
/// techniques.
const MAPPING: &[(&str, &[&str])] = &[
    // ---------------- Process / Endpoint ----------------
    (
        "Process: Process Creation",
        &["windows_sysmon", "linux_auditd", "microsoft_sysmon__json_"],
    ),
    (
        "Process: Process Termination",
        &["windows_sysmon", "linux_auditd"],
    ),
    (
        "Process: Process Access",
        &["windows_sysmon", "microsoft_defender_for_endpoint"],
    ),
    (
        "Process: Process Metadata",
        &["windows_sysmon", "linux_auditd"],
    ),
    (
        "Process: OS API Execution",
        &["windows_sysmon", "microsoft_defender_for_endpoint"],
    ),
    // ---------------- Command / Script ----------------
    (
        "Command: Command Execution",
        &["windows_sysmon", "linux_auditd"],
    ),
    (
        "Script: Script Execution",
        &["windows_sysmon", "linux_auditd"],
    ),
    // ---------------- File ----------------
    (
        "File: File Creation",
        &["windows_sysmon", "linux_auditd"],
    ),
    (
        "File: File Modification",
        &["windows_sysmon", "linux_auditd"],
    ),
    (
        "File: File Deletion",
        &["windows_sysmon", "linux_auditd"],
    ),
    (
        "File: File Access",
        &["windows_sysmon", "linux_auditd"],
    ),
    (
        "File: File Metadata",
        &["windows_sysmon", "linux_auditd"],
    ),
    // ---------------- Module / Driver ----------------
    ("Module: Module Load", &["windows_sysmon"]),
    ("Driver: Driver Load", &["windows_sysmon"]),
    // ---------------- Windows Registry ----------------
    ("Windows Registry: Windows Registry Key Creation", &["windows_sysmon"]),
    ("Windows Registry: Windows Registry Key Modification", &["windows_sysmon"]),
    ("Windows Registry: Windows Registry Key Deletion", &["windows_sysmon"]),
    ("Windows Registry: Windows Registry Key Access", &["windows_sysmon"]),
    // ---------------- Logon / Auth ----------------
    (
        "Logon Session: Logon Session Creation",
        &["windows_event_log", "okta", "azure_ad"],
    ),
    (
        "Logon Session: Logon Session Metadata",
        &["windows_event_log", "okta", "azure_ad"],
    ),
    (
        "User Account: User Account Authentication",
        &["windows_event_log", "okta", "azure_ad", "linux_auditd"],
    ),
    (
        "User Account: User Account Creation",
        &["windows_event_log", "okta", "azure_ad", "aws_cloudtrail", "linux_auditd"],
    ),
    (
        "User Account: User Account Modification",
        &["windows_event_log", "okta", "azure_ad", "aws_cloudtrail", "linux_auditd"],
    ),
    (
        "User Account: User Account Deletion",
        &["windows_event_log", "okta", "azure_ad", "aws_cloudtrail", "linux_auditd"],
    ),
    (
        "User Account: User Account Metadata",
        &["okta", "azure_ad"],
    ),
    // ---------------- Group ----------------
    (
        "Group: Group Modification",
        &["windows_event_log", "okta", "azure_ad", "aws_cloudtrail"],
    ),
    (
        "Group: Group Enumeration",
        &["windows_event_log", "okta", "azure_ad", "aws_cloudtrail"],
    ),
    // ---------------- Active Directory ----------------
    (
        "Active Directory: Active Directory Object Creation",
        &["windows_event_log", "azure_ad"],
    ),
    (
        "Active Directory: Active Directory Object Modification",
        &["windows_event_log", "azure_ad"],
    ),
    (
        "Active Directory: Active Directory Credential Request",
        &["windows_event_log"],
    ),
    (
        "Active Directory: Active Directory Object Access",
        &["windows_event_log", "azure_ad"],
    ),
    // ---------------- Network ----------------
    (
        "Network Traffic: Network Traffic Flow",
        &["netflow"],
    ),
    (
        "Network Traffic: Network Traffic Content",
        &["netflow", "squid_proxy", "conduit_mitm_proxy"],
    ),
    (
        "Network Traffic: Network Connection Creation",
        &["netflow"],
    ),
    (
        "Network Share: Network Share Access",
        &["windows_sysmon", "windows_event_log"],
    ),
    // ---------------- DNS ----------------
    ("Application Log: Application Log Content", &["dns"]),
    // ---------------- Cloud Service ----------------
    (
        "Cloud Service: Cloud Service Enumeration",
        &["aws_cloudtrail", "gcp_audit", "azure_ad"],
    ),
    (
        "Cloud Service: Cloud Service Modification",
        &["aws_cloudtrail", "gcp_audit", "azure_ad"],
    ),
    (
        "Cloud Service: Cloud Service Disable",
        &["aws_cloudtrail", "gcp_audit", "azure_ad"],
    ),
    (
        "Cloud Service: Cloud Service Metadata",
        &["aws_cloudtrail", "gcp_audit", "azure_ad"],
    ),
    // ---------------- Cloud Storage ----------------
    (
        "Cloud Storage: Cloud Storage Access",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Cloud Storage: Cloud Storage Creation",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Cloud Storage: Cloud Storage Modification",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Cloud Storage: Cloud Storage Deletion",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Cloud Storage: Cloud Storage Metadata",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Cloud Storage: Cloud Storage Enumeration",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    // ---------------- Instance / Snapshot / Image / Volume ----------------
    (
        "Instance: Instance Creation",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Instance: Instance Modification",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Instance: Instance Deletion",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Instance: Instance Start",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Instance: Instance Stop",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Instance: Instance Enumeration",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Instance: Instance Metadata",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Snapshot: Snapshot Creation",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Snapshot: Snapshot Modification",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    ("Snapshot: Snapshot Deletion", &["aws_cloudtrail", "gcp_audit"]),
    (
        "Volume: Volume Modification",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Volume: Volume Creation",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Volume: Volume Deletion",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    // ---------------- Web ----------------
    (
        "Web Credential: Web Credential Usage",
        &["okta", "azure_ad", "aws_cloudtrail"],
    ),
    (
        "Web Credential: Web Credential Creation",
        &["okta", "azure_ad", "aws_cloudtrail"],
    ),
    // ---------------- Application / Container ----------------
    (
        "Container: Container Creation",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Container: Container Start",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Container: Container Enumeration",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Pod: Pod Creation",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Pod: Pod Modification",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    (
        "Pod: Pod Enumeration",
        &["aws_cloudtrail", "gcp_audit"],
    ),
    // ---------------- Sensors ----------------
    (
        "Sensor Health: Host Status",
        &["microsoft_defender_for_endpoint"],
    ),
    // ---------------- Firmware ----------------
    ("Firmware: Firmware Modification", &["windows_event_log"]),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_known_label() {
        let sources = nanosiem_sources_for("Process: Process Creation");
        assert!(sources.contains(&"windows_sysmon"));
        assert!(sources.contains(&"linux_auditd"));
    }

    #[test]
    fn maps_case_insensitive() {
        let sources = nanosiem_sources_for("network traffic: network traffic flow");
        assert_eq!(sources, &["netflow"]);
    }

    #[test]
    fn unknown_label_returns_empty() {
        assert!(nanosiem_sources_for("Asteroid: Asteroid Impact").is_empty());
    }

    #[test]
    fn unknown_component_falls_back_to_category() {
        // "Cloud Service: Made Up Component" should still match "Cloud Service: ..."
        let sources = nanosiem_sources_for("Cloud Service: Made Up Component");
        assert!(sources.contains(&"aws_cloudtrail"));
    }

    #[test]
    fn stable_id_snake_cases() {
        assert_eq!(
            stable_id("Process: Process Creation"),
            "process_process_creation"
        );
        assert_eq!(
            stable_id("Network Traffic: Network Traffic Flow"),
            "network_traffic_network_traffic_flow"
        );
    }

    #[test]
    fn stable_id_strips_trailing_separators() {
        assert_eq!(stable_id("Foo: "), "foo");
    }
}
