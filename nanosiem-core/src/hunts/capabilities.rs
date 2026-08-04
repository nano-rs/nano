// SPDX-License-Identifier: AGPL-3.0-or-later

//! Portable hunt telemetry requirements and environment-specific bindings.
//!
//! Hunt authors know they need “identity authentication” or “VPN session”
//! telemetry. They cannot know that one customer calls the concrete feed
//! `okta`, another `corp_idp_prod`, and a third `weird-okta-export-7`.
//! This module keeps those layers separate:
//!
//! * frontmatter carries semantic [`HuntTelemetryRequirements`];
//! * recon infers inspectable [`InferredCapability`] rows from source identity
//!   hints and normalized field population;
//! * analysts may override a row in Postgres;
//! * readiness resolves the stored bindings against telemetry observed now;
//! * sweep provenance remains derived from events actually read elsewhere.
//!
//! Name inference is deliberately evidence, not magic. Exact or token-delimited
//! vendor aliases clear the automatic trust threshold. A loose substring is a
//! visible suggestion unless independent field-shape evidence corroborates it.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use crate::playbooks::models::HuntTelemetryRequirements;

use super::models::{CapabilityResolution, HuntTelemetryReadiness, SourceCapabilityBinding};

pub const MAX_CAPABILITIES_PER_GROUP: usize = 32;
pub const MAX_CAPABILITY_LEN: usize = 96;

/// Inferred rows at or above this confidence may satisfy a hard requirement.
/// Lower-confidence rows are still persisted and shown so an analyst can
/// confirm them, but a guess must not silently turn “blind” into “ready”.
pub const AUTOMATIC_BINDING_CONFIDENCE: f64 = 0.80;

#[derive(Debug, Clone, PartialEq)]
pub struct InferredCapability {
    pub source_type: String,
    pub capability: String,
    pub confidence: f64,
    pub basis: String,
    pub evidence: String,
}

/// One field-population observation from recon.
#[derive(Debug, Clone, Copy)]
pub struct FieldObservation<'a> {
    pub field: &'a str,
    pub populated_pct: f64,
}

#[derive(Debug, Clone, Copy)]
struct AliasRule {
    alias: &'static str,
    capabilities: &'static [&'static str],
}

/// Product-owned vocabulary. The aliases are hints found in concrete customer
/// source names; the capability strings are the portable authoring contract.
const ALIAS_RULES: &[AliasRule] = &[
    AliasRule {
        alias: "okta",
        capabilities: &[
            "identity.authentication",
            "identity.admin_audit",
            "saas.audit",
        ],
    },
    AliasRule {
        alias: "saas_audit",
        capabilities: &["saas.audit"],
    },
    AliasRule {
        alias: "auth0",
        capabilities: &["identity.authentication", "identity.admin_audit"],
    },
    AliasRule {
        alias: "duo",
        capabilities: &["identity.authentication", "identity.mfa"],
    },
    AliasRule {
        alias: "azure_ad",
        capabilities: &[
            "identity.authentication",
            "identity.admin_audit",
            "saas.audit",
        ],
    },
    AliasRule {
        alias: "entra",
        capabilities: &[
            "identity.authentication",
            "identity.admin_audit",
            "saas.audit",
        ],
    },
    AliasRule {
        alias: "windows_security",
        capabilities: &[
            "identity.authentication",
            "identity.kerberos",
            "identity.privilege_changes",
        ],
    },
    AliasRule {
        alias: "windows_event_log",
        capabilities: &[
            "identity.authentication",
            "identity.kerberos",
            "identity.privilege_changes",
        ],
    },
    AliasRule {
        alias: "active_directory",
        capabilities: &["identity.kerberos", "identity.privilege_changes"],
    },
    AliasRule {
        alias: "kerberos",
        capabilities: &["identity.kerberos"],
    },
    AliasRule {
        alias: "office365",
        capabilities: &["saas.audit", "saas.data_export", "mailbox.audit"],
    },
    AliasRule {
        alias: "o365",
        capabilities: &["saas.audit", "saas.data_export", "mailbox.audit"],
    },
    AliasRule {
        alias: "microsoft365",
        capabilities: &["saas.audit", "saas.data_export", "mailbox.audit"],
    },
    AliasRule {
        alias: "m365",
        capabilities: &["saas.audit", "saas.data_export", "mailbox.audit"],
    },
    AliasRule {
        alias: "exchange",
        capabilities: &["saas.audit", "saas.data_export", "mailbox.audit"],
    },
    AliasRule {
        alias: "google_workspace",
        capabilities: &["identity.authentication", "saas.audit", "mailbox.audit"],
    },
    AliasRule {
        alias: "gmail",
        capabilities: &["saas.audit", "mailbox.audit"],
    },
    AliasRule {
        alias: "salesforce",
        capabilities: &["saas.audit", "saas.data_export"],
    },
    AliasRule {
        alias: "github",
        capabilities: &["saas.audit", "cicd.audit"],
    },
    AliasRule {
        alias: "gitlab",
        capabilities: &["saas.audit", "cicd.audit"],
    },
    AliasRule {
        alias: "jenkins",
        capabilities: &["cicd.audit"],
    },
    AliasRule {
        alias: "circleci",
        capabilities: &["cicd.audit"],
    },
    AliasRule {
        alias: "azure_devops",
        capabilities: &["cicd.audit"],
    },
    AliasRule {
        alias: "kubernetes_audit",
        capabilities: &["kubernetes.audit"],
    },
    AliasRule {
        alias: "kube_audit",
        capabilities: &["kubernetes.audit"],
    },
    AliasRule {
        alias: "veeam",
        capabilities: &["backup.audit"],
    },
    AliasRule {
        alias: "rubrik",
        capabilities: &["backup.audit"],
    },
    AliasRule {
        alias: "cohesity",
        capabilities: &["backup.audit"],
    },
    AliasRule {
        alias: "commvault",
        capabilities: &["backup.audit"],
    },
    AliasRule {
        alias: "backup",
        capabilities: &["backup.audit"],
    },
    AliasRule {
        alias: "globalprotect",
        capabilities: &["network.vpn"],
    },
    AliasRule {
        alias: "anyconnect",
        capabilities: &["network.vpn"],
    },
    AliasRule {
        alias: "fortinet",
        capabilities: &["network.vpn", "network.edge_admin"],
    },
    AliasRule {
        alias: "fortigate",
        capabilities: &["network.vpn", "network.edge_admin"],
    },
    AliasRule {
        alias: "paloalto",
        capabilities: &["network.vpn", "network.edge_admin"],
    },
    AliasRule {
        alias: "panorama",
        capabilities: &["network.vpn", "network.edge_admin"],
    },
    AliasRule {
        alias: "vpn",
        capabilities: &["network.vpn"],
    },
    AliasRule {
        alias: "aws_cloudtrail",
        capabilities: &["cloud.control_plane", "cloud.data_plane"],
    },
    AliasRule {
        alias: "azure_activity",
        capabilities: &["cloud.control_plane", "cloud.data_plane"],
    },
    AliasRule {
        alias: "gcp_audit",
        capabilities: &["cloud.control_plane", "cloud.data_plane"],
    },
    AliasRule {
        alias: "edr",
        capabilities: &[
            "endpoint.process",
            "endpoint.file",
            "endpoint.network",
            "endpoint.persistence",
        ],
    },
    AliasRule {
        alias: "windows_sysmon",
        capabilities: &["endpoint.process", "endpoint.file", "endpoint.persistence"],
    },
    AliasRule {
        alias: "linux_auditd",
        capabilities: &["endpoint.process", "endpoint.file", "endpoint.persistence"],
    },
    AliasRule {
        alias: "crowdstrike",
        capabilities: &["endpoint.process", "endpoint.file", "endpoint.persistence"],
    },
    AliasRule {
        alias: "sentinelone",
        capabilities: &["endpoint.process", "endpoint.file", "endpoint.persistence"],
    },
    AliasRule {
        alias: "defender_endpoint",
        capabilities: &["endpoint.process", "endpoint.file", "endpoint.persistence"],
    },
    AliasRule {
        alias: "squid",
        capabilities: &["network.web", "network.connection"],
    },
    AliasRule {
        alias: "proxy",
        capabilities: &["network.web", "network.connection"],
    },
    AliasRule {
        alias: "zscaler",
        capabilities: &["network.web", "network.connection"],
    },
    AliasRule {
        alias: "netskope",
        capabilities: &["network.web", "network.connection"],
    },
    AliasRule {
        alias: "waf",
        capabilities: &["network.waf", "network.web"],
    },
    AliasRule {
        alias: "cloudflare",
        capabilities: &["network.waf", "network.web"],
    },
    AliasRule {
        alias: "imperva",
        capabilities: &["network.waf", "network.web"],
    },
    AliasRule {
        alias: "app_auth",
        capabilities: &["application.authentication", "application.activity"],
    },
    AliasRule {
        alias: "email_gateway",
        capabilities: &["email.gateway"],
    },
    AliasRule {
        alias: "proofpoint",
        capabilities: &["email.gateway"],
    },
    AliasRule {
        alias: "mimecast",
        capabilities: &["email.gateway"],
    },
    AliasRule {
        alias: "dns",
        capabilities: &["network.dns"],
    },
    AliasRule {
        alias: "zeek",
        capabilities: &["network.dns", "network.connection"],
    },
];

pub fn normalize_requirements(
    raw: &HuntTelemetryRequirements,
) -> Result<HuntTelemetryRequirements, String> {
    Ok(HuntTelemetryRequirements {
        all_of: normalize_capability_group("telemetry.all_of", &raw.all_of)?,
        one_of: normalize_capability_group("telemetry.one_of", &raw.one_of)?,
        optional: normalize_capability_group("telemetry.optional", &raw.optional)?,
    })
}

pub fn normalize_capability(raw: &str) -> Result<String, String> {
    let normalized = raw.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > MAX_CAPABILITY_LEN
        || !normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
        || !normalized
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(format!(
            "invalid telemetry capability `{raw}`; expected [A-Za-z0-9][A-Za-z0-9._-]*"
        ));
    }
    Ok(normalized)
}

fn normalize_capability_group(label: &str, raw: &[String]) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for value in raw {
        let capability = normalize_capability(value)?;
        if !out.contains(&capability) {
            out.push(capability);
        }
    }
    if out.len() > MAX_CAPABILITIES_PER_GROUP {
        return Err(format!(
            "{label} contains {} capabilities; the ceiling is {MAX_CAPABILITIES_PER_GROUP}",
            out.len()
        ));
    }
    Ok(out)
}

/// Infer capability suggestions from one recon census row.
pub fn infer_source_capabilities(
    source_type: &str,
    fields: &[FieldObservation<'_>],
) -> Vec<InferredCapability> {
    let source_type = source_type.trim().to_ascii_lowercase();
    if source_type.is_empty() {
        return Vec::new();
    }

    let mut candidates: BTreeMap<String, InferredCapability> = BTreeMap::new();
    for rule in ALIAS_RULES {
        let Some((confidence, basis)) = alias_match(&source_type, rule.alias) else {
            continue;
        };
        for capability in rule.capabilities {
            merge_inference(
                &mut candidates,
                InferredCapability {
                    source_type: source_type.clone(),
                    capability: (*capability).to_string(),
                    confidence,
                    basis: basis.to_string(),
                    evidence: format!("source name matched `{}`", rule.alias),
                },
            );
        }
    }

    let population: BTreeMap<&str, f64> = fields
        .iter()
        .map(|field| (field.field, field.populated_pct.clamp(0.0, 100.0)))
        .collect();
    let pct = |field: &str| population.get(field).copied().unwrap_or(0.0);

    if pct("user") >= 5.0 && pct("auth_result") >= 5.0 {
        merge_inference(
            &mut candidates,
            field_inference(
                &source_type,
                "identity.authentication",
                0.82,
                format!(
                    "normalized auth fields populated (user {:.1}%, auth_result {:.1}%)",
                    pct("user"),
                    pct("auth_result")
                ),
            ),
        );
    }
    if pct("process_name") >= 5.0 || pct("command_line") >= 5.0 {
        merge_inference(
            &mut candidates,
            field_inference(
                &source_type,
                "endpoint.process",
                0.82,
                format!(
                    "normalized process fields populated (process_name {:.1}%, command_line {:.1}%)",
                    pct("process_name"),
                    pct("command_line")
                ),
            ),
        );
    }
    if pct("file_path") >= 5.0 {
        merge_inference(
            &mut candidates,
            field_inference(
                &source_type,
                "endpoint.file",
                0.80,
                format!("normalized file_path populated ({:.1}%)", pct("file_path")),
            ),
        );
    }
    if pct("url") >= 5.0 && (pct("src_ip") >= 5.0 || pct("dest_ip") >= 5.0) {
        merge_inference(
            &mut candidates,
            field_inference(
                &source_type,
                "network.web",
                0.80,
                format!(
                    "normalized URL and network fields populated (url {:.1}%, src_ip {:.1}%, dest_ip {:.1}%)",
                    pct("url"),
                    pct("src_ip"),
                    pct("dest_ip")
                ),
            ),
        );
    }
    if pct("src_ip") >= 20.0
        && pct("dest_ip") >= 20.0
        && pct("auth_result") < 5.0
        && pct("process_name") < 5.0
    {
        merge_inference(
            &mut candidates,
            field_inference(
                &source_type,
                "network.connection",
                0.80,
                format!(
                    "network-shaped source has populated endpoints without auth/process fields (src_ip {:.1}%, dest_ip {:.1}%)",
                    pct("src_ip"),
                    pct("dest_ip")
                ),
            ),
        );
    }

    candidates.into_values().collect()
}

fn field_inference(
    source_type: &str,
    capability: &str,
    confidence: f64,
    evidence: String,
) -> InferredCapability {
    InferredCapability {
        source_type: source_type.to_string(),
        capability: capability.to_string(),
        confidence,
        basis: "field_shape".to_string(),
        evidence,
    }
}

fn alias_match(source_type: &str, alias: &str) -> Option<(f64, &'static str)> {
    let source = normalize_name(source_type);
    let alias = normalize_name(alias);
    if source == alias {
        return Some((0.99, "canonical_name"));
    }
    let padded = format!("_{source}_");
    if padded.contains(&format!("_{alias}_")) {
        return Some((0.92, "name_token"));
    }
    let source_compact: String = source.chars().filter(|c| *c != '_').collect();
    let alias_compact: String = alias.chars().filter(|c| *c != '_').collect();
    source_compact
        .contains(&alias_compact)
        .then_some((0.68, "name_substring"))
}

fn normalize_name(value: &str) -> String {
    let mut out = String::new();
    let mut separated = false;
    for ch in value.trim().to_ascii_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            separated = false;
        } else if !separated && !out.is_empty() {
            out.push('_');
            separated = true;
        }
    }
    while out.ends_with('_') {
        out.pop();
    }
    out
}

fn merge_inference(
    candidates: &mut BTreeMap<String, InferredCapability>,
    incoming: InferredCapability,
) {
    let Some(existing) = candidates.get_mut(&incoming.capability) else {
        candidates.insert(incoming.capability.clone(), incoming);
        return;
    };

    if existing.basis == incoming.basis {
        if incoming.confidence > existing.confidence {
            *existing = incoming;
        }
        return;
    }

    // Independent hints corroborate one another. The complement product is a
    // bounded noisy-OR: two modest signals can become trustworthy without ever
    // exceeding 1.0 or requiring model-authored arithmetic.
    existing.confidence =
        (1.0 - (1.0 - existing.confidence) * (1.0 - incoming.confidence)).clamp(0.0, 1.0);
    existing.basis = "corroborated".to_string();
    existing.evidence = format!("{}; {}", existing.evidence, incoming.evidence);
}

/// Concrete source types worth probing for a hunt's readiness calculation.
pub fn readiness_candidates(
    requirements: &HuntTelemetryRequirements,
    legacy_required_sources: &[String],
    bindings: &[SourceCapabilityBinding],
) -> Vec<String> {
    let wanted: BTreeSet<&str> = requirements
        .all_of
        .iter()
        .chain(&requirements.one_of)
        .chain(&requirements.optional)
        .map(String::as_str)
        .collect();
    let mut out: BTreeSet<String> = legacy_required_sources
        .iter()
        .map(|source| source.trim().to_ascii_lowercase())
        .filter(|source| !source.is_empty())
        .collect();
    for binding in bindings {
        if wanted.contains(binding.capability.as_str()) && binding_is_trusted(binding) {
            out.insert(binding.source_type.trim().to_ascii_lowercase());
        }
    }
    out.into_iter().collect()
}

/// Resolve requirements after the caller has measured which candidate sources
/// are silent. `silent_source_types` is server-observed state, never supplied
/// by a hunt file or agent.
pub fn evaluate_readiness(
    requirements: &HuntTelemetryRequirements,
    legacy_required_sources: &[String],
    bindings: &[SourceCapabilityBinding],
    silent_source_types: &BTreeSet<String>,
    evaluated_at: DateTime<Utc>,
) -> HuntTelemetryReadiness {
    let all_of = resolve_group(&requirements.all_of, bindings, silent_source_types);
    let one_of = resolve_group(&requirements.one_of, bindings, silent_source_types);
    let optional = resolve_group(&requirements.optional, bindings, silent_source_types);

    let required_source_types: Vec<String> = legacy_required_sources
        .iter()
        .map(|source| source.trim().to_ascii_lowercase())
        .filter(|source| !source.is_empty())
        .collect();
    let live_required_source_types: Vec<String> = required_source_types
        .iter()
        .filter(|source| !silent_source_types.contains(source.as_str()))
        .cloned()
        .collect();

    let mut blocking_reasons: Vec<String> = all_of
        .iter()
        .filter(|resolution| !resolution.satisfied)
        .map(|resolution| {
            format!(
                "capability `{}` has no live bound source",
                resolution.capability
            )
        })
        .collect();
    if !one_of.is_empty() && !one_of.iter().any(|resolution| resolution.satisfied) {
        blocking_reasons.push(format!(
            "none of the alternative capabilities are live: {}",
            requirements.one_of.join(", ")
        ));
    }
    for source in required_source_types
        .iter()
        .filter(|source| silent_source_types.contains(source.as_str()))
    {
        blocking_reasons.push(format!("required source `{source}` is silent"));
    }

    HuntTelemetryReadiness {
        ready: blocking_reasons.is_empty(),
        evaluated_at,
        all_of,
        one_of,
        optional,
        required_source_types,
        live_required_source_types,
        silent_source_types: silent_source_types.iter().cloned().collect(),
        blocking_reasons,
    }
}

fn resolve_group(
    capabilities: &[String],
    bindings: &[SourceCapabilityBinding],
    silent_source_types: &BTreeSet<String>,
) -> Vec<CapabilityResolution> {
    capabilities
        .iter()
        .map(|capability| {
            let source_types: Vec<String> = bindings
                .iter()
                .filter(|binding| binding.capability == *capability && binding_is_trusted(binding))
                .map(|binding| binding.source_type.trim().to_ascii_lowercase())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let live_source_types: Vec<String> = source_types
                .iter()
                .filter(|source| !silent_source_types.contains(source.as_str()))
                .cloned()
                .collect();
            CapabilityResolution {
                capability: capability.clone(),
                source_types,
                satisfied: !live_source_types.is_empty(),
                live_source_types,
            }
        })
        .collect()
}

fn binding_is_trusted(binding: &SourceCapabilityBinding) -> bool {
    binding.state == "mapped"
        && (binding.origin == "analyst" || binding.confidence >= AUTOMATIC_BINDING_CONFIDENCE)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding(source_type: &str, capability: &str) -> SourceCapabilityBinding {
        SourceCapabilityBinding {
            source_type: source_type.into(),
            capability: capability.into(),
            state: "mapped".into(),
            origin: "inferred".into(),
            confidence: 0.92,
            basis: "name_token".into(),
            evidence: "test".into(),
            last_observed_at: None,
            updated_by: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn customer_okta_name_resolves_without_exact_source_identity() {
        let inferred = infer_source_capabilities("corp_okta_prod", &[]);
        let auth = inferred
            .iter()
            .find(|entry| entry.capability == "identity.authentication")
            .expect("Okta authentication binding");
        assert_eq!(auth.basis, "name_token");
        assert!(auth.confidence >= AUTOMATIC_BINDING_CONFIDENCE);
    }

    #[test]
    fn generic_product_gate_names_also_resolve_to_semantic_capabilities() {
        let inferred = infer_source_capabilities("customer_saas_audit_prod", &[]);
        let audit = inferred
            .iter()
            .find(|entry| entry.capability == "saas.audit")
            .expect("SaaS audit binding");
        assert_eq!(audit.basis, "name_token");
        assert!(audit.confidence >= AUTOMATIC_BINDING_CONFIDENCE);
    }

    #[test]
    fn stock_hunt_source_families_resolve_from_customer_names() {
        let cases = [
            ("corp_backup_platform", "backup.audit"),
            ("corp_m365_audit", "saas.data_export"),
            ("corp_m365_audit", "mailbox.audit"),
            ("corp_github_audit", "cicd.audit"),
            ("corp_gcp_audit", "cloud.control_plane"),
            ("corp_entra_audit", "identity.admin_audit"),
            ("corp_entra_signin", "identity.authentication"),
            ("corp_windows_security", "identity.kerberos"),
            ("corp_windows_security", "identity.privilege_changes"),
            ("corp_windows_sysmon", "endpoint.persistence"),
            ("corp_edr_telemetry_prod", "endpoint.process"),
            ("branch_squid_proxy", "network.web"),
            ("edge_waf_logs", "network.waf"),
            ("customer_app_auth", "application.authentication"),
            ("secure_email_gateway", "email.gateway"),
            ("regional_dns_logs", "network.dns"),
            ("fleet_linux_auditd", "endpoint.persistence"),
            ("prod_kubernetes_audit", "kubernetes.audit"),
            ("crm_saas_audit", "saas.audit"),
            ("branch_vpn_logs", "network.vpn"),
        ];

        for (source_type, expected) in cases {
            let inferred = infer_source_capabilities(source_type, &[]);
            let capability = inferred
                .iter()
                .find(|entry| entry.capability == expected)
                .unwrap_or_else(|| panic!("{source_type} should infer {expected}"));
            assert!(capability.confidence >= AUTOMATIC_BINDING_CONFIDENCE);
        }
    }

    #[test]
    fn normalized_network_shape_infers_connection_telemetry() {
        let inferred = infer_source_capabilities(
            "customer_defined_flow_feed",
            &[
                FieldObservation {
                    field: "src_ip",
                    populated_pct: 99.0,
                },
                FieldObservation {
                    field: "dest_ip",
                    populated_pct: 98.0,
                },
            ],
        );
        let connection = inferred
            .iter()
            .find(|entry| entry.capability == "network.connection")
            .expect("network connection binding");
        assert_eq!(connection.basis, "field_shape");
        assert!(connection.confidence >= AUTOMATIC_BINDING_CONFIDENCE);
    }

    #[test]
    fn loose_name_substring_stays_a_suggestion_without_corroboration() {
        let inferred = infer_source_capabilities("probablyoktabutunknown", &[]);
        let auth = inferred
            .iter()
            .find(|entry| entry.capability == "identity.authentication")
            .expect("substring suggestion");
        assert!(auth.confidence < AUTOMATIC_BINDING_CONFIDENCE);
    }

    #[test]
    fn field_shape_can_corroborate_a_loose_vendor_hint() {
        let inferred = infer_source_capabilities(
            "probablyoktabutunknown",
            &[
                FieldObservation {
                    field: "user",
                    populated_pct: 95.0,
                },
                FieldObservation {
                    field: "auth_result",
                    populated_pct: 92.0,
                },
            ],
        );
        let auth = inferred
            .iter()
            .find(|entry| entry.capability == "identity.authentication")
            .expect("corroborated authentication binding");
        assert_eq!(auth.basis, "corroborated");
        assert!(auth.confidence >= AUTOMATIC_BINDING_CONFIDENCE);
    }

    #[test]
    fn requirements_are_normalized_and_deduplicated() {
        let normalized = normalize_requirements(&HuntTelemetryRequirements {
            all_of: vec![
                " Identity.Authentication ".into(),
                "identity.authentication".into(),
            ],
            one_of: vec!["Network.VPN".into()],
            optional: vec![],
        })
        .expect("valid requirements");
        assert_eq!(normalized.all_of, vec!["identity.authentication"]);
        assert_eq!(normalized.one_of, vec!["network.vpn"]);
    }

    #[test]
    fn all_of_and_one_of_use_live_environment_bindings() {
        let requirements = HuntTelemetryRequirements {
            all_of: vec!["identity.authentication".into()],
            one_of: vec!["network.vpn".into(), "network.edge_admin".into()],
            optional: vec!["endpoint.process".into()],
        };
        let bindings = vec![
            binding("corp_okta_prod", "identity.authentication"),
            binding("edge_vpn", "network.vpn"),
            binding("edr", "endpoint.process"),
        ];
        let readiness = evaluate_readiness(
            &requirements,
            &[],
            &bindings,
            &BTreeSet::from(["edr".to_string()]),
            Utc::now(),
        );
        assert!(readiness.ready);
        assert!(readiness.all_of[0].satisfied);
        assert!(readiness.one_of[0].satisfied);
        assert!(!readiness.optional[0].satisfied);
    }

    #[test]
    fn unresolved_hard_capability_and_silent_legacy_source_hold_the_hunt() {
        let requirements = HuntTelemetryRequirements {
            all_of: vec!["mailbox.audit".into()],
            ..Default::default()
        };
        let readiness = evaluate_readiness(
            &requirements,
            &["custom_dc_events".into()],
            &[],
            &BTreeSet::from(["custom_dc_events".to_string()]),
            Utc::now(),
        );
        assert!(!readiness.ready);
        assert_eq!(readiness.blocking_reasons.len(), 2);
    }
}
