// SPDX-License-Identifier: AGPL-3.0-or-later

//! UDM Field Context Generation for AI Agents
//!
//! This module provides functions to generate comprehensive UDM field context
//! for AI agents, organized by category with descriptions and examples.
//!
//! Requirements: 3.1, 3.2, 3.3, 3.4, 3.5

use crate::schema::{SchemaId, SchemaProfile};
use crate::udm::fields::{UdmField, UdmFieldCategory};

/// Build a field glossary from the ACTIVE schema profile's field universe
/// (`profile.fields()`), grouped by category. Used for the non-UDM (OCSF)
/// branch of the AI-context functions so the LLM is taught the schema's real
/// field names (e.g. `src_endpoint.ip`, `api.operation`, `resources.type`)
/// instead of the hardcoded UDM glossary. UDM-style aliases (`src_ip`, `user`,
/// …) still resolve at query time via `OcsfProfile::resolve`, so they're noted
/// as also-valid. (NAN-1252)
fn schema_field_glossary(profile: &dyn SchemaProfile, names_only: bool, heading: &str) -> String {
    use std::collections::BTreeMap;
    let mut by_cat: BTreeMap<String, Vec<&crate::schema::FieldDef>> = BTreeMap::new();
    for f in profile.fields() {
        by_cat
            .entry(format!("{:?}", f.category))
            .or_default()
            .push(f);
    }
    let mut out = format!("{heading}\n\n");
    out.push_str(
        "The deployment uses the OCSF schema. Use these field names directly. UDM-style \
         aliases (e.g. `src_ip`, `user`, `dest_ip`, `file_hash`) also resolve to the \
         corresponding OCSF column at query time.\n\n",
    );
    for (cat, fields) in by_cat {
        out.push_str(&format!("### {cat}\n"));
        if names_only {
            let names: Vec<String> = fields.iter().map(|f| format!("`{}`", f.name)).collect();
            out.push_str(&names.join(", "));
            out.push_str("\n\n");
        } else {
            for f in fields {
                out.push_str(&format!("- `{}` ({:?})\n", f.name, f.field_type));
            }
            out.push('\n');
        }
    }
    out
}

/// Generate comprehensive UDM field context for AI agents
///
/// Returns a formatted string containing all UDM fields organized by category,
/// with field names, data types, and descriptions. This context helps AI agents
/// understand available fields when generating queries, detections, or parsers.
///
/// Requirements: 3.4, 3.5
pub fn get_udm_field_context(profile: &dyn SchemaProfile) -> String {
    if profile.id() != SchemaId::Udm {
        return schema_field_glossary(profile, false, "## Available Fields");
    }
    let mut context = String::from("## Available UDM Fields\n\n");
    context.push_str("The following fields are available in the Unified Data Model (UDM). ");
    context.push_str(
        "Use these field names directly in queries, detections, and parser mappings.\n\n",
    );

    // Get all categories
    let categories = vec![
        UdmFieldCategory::Inventory,
        UdmFieldCategory::Network,
        UdmFieldCategory::Authentication,
        UdmFieldCategory::Endpoint,
        UdmFieldCategory::Web,
        UdmFieldCategory::Email,
        UdmFieldCategory::Database,
        UdmFieldCategory::Dns,
        UdmFieldCategory::Certificate,
        UdmFieldCategory::Malware,
        UdmFieldCategory::Intrusion,
        UdmFieldCategory::Vulnerability,
        UdmFieldCategory::Performance,
        UdmFieldCategory::Alerts,
        UdmFieldCategory::Change,
        UdmFieldCategory::Cloud,
        UdmFieldCategory::DataAccess,
        UdmFieldCategory::DataLossPrevention,
        UdmFieldCategory::InterprocessMessaging,
        UdmFieldCategory::Custom,
    ];

    for category in categories {
        let fields = UdmField::by_category(category);
        if fields.is_empty() {
            continue;
        }

        context.push_str(&format!(
            "### {} Fields\n\n",
            format_category_name(category)
        ));

        // Include ALL fields - 508 fields at ~20 tokens each is ~10K tokens,
        // well within Claude's 200K context window
        for field in fields.iter() {
            let column_name = field.column_name();
            let data_type = field.data_type();
            let description = field.description();

            context.push_str(&format!(
                "- `{}` ({:?}) - {}\n",
                column_name, data_type, description
            ));
        }

        context.push('\n');
    }

    context
}

/// Generate UDM field context for specific categories
///
/// Returns a formatted string containing UDM fields for the specified categories only.
/// Useful when you want to provide focused context for specific use cases.
///
/// Requirements: 3.2, 3.3, 3.4
pub fn get_udm_field_context_for_categories(
    profile: &dyn SchemaProfile,
    categories: &[UdmFieldCategory],
) -> String {
    if profile.id() != SchemaId::Udm {
        // OCSF: the UdmFieldCategory filter doesn't map 1:1 to the OCSF field
        // universe; emit the full OCSF glossary (≈90 promoted fields, token-cheap).
        return schema_field_glossary(profile, false, "## Relevant Fields");
    }
    let mut context = String::from("## Relevant UDM Fields\n\n");

    for category in categories {
        let fields = UdmField::by_category(*category);
        if fields.is_empty() {
            continue;
        }

        context.push_str(&format!(
            "### {} Fields\n\n",
            format_category_name(*category)
        ));

        for field in fields.iter() {
            let column_name = field.column_name();
            let data_type = field.data_type();
            let description = field.description();

            context.push_str(&format!(
                "- `{}` ({:?}) - {}\n",
                column_name, data_type, description
            ));
        }

        context.push('\n');
    }

    context
}

/// Generate a concise UDM field reference (field names only)
///
/// Returns a compact list of field names organized by category.
/// Useful when you need a quick reference without full descriptions.
pub fn get_udm_field_names_by_category(profile: &dyn SchemaProfile) -> String {
    if profile.id() != SchemaId::Udm {
        return schema_field_glossary(profile, true, "## Field Names by Category");
    }
    let mut context = String::from("## UDM Field Names by Category\n\n");

    let categories = vec![
        UdmFieldCategory::Inventory,
        UdmFieldCategory::Network,
        UdmFieldCategory::Authentication,
        UdmFieldCategory::Endpoint,
        UdmFieldCategory::Web,
        UdmFieldCategory::Email,
        UdmFieldCategory::Database,
        UdmFieldCategory::Dns,
        UdmFieldCategory::Certificate,
        UdmFieldCategory::Malware,
        UdmFieldCategory::Intrusion,
        UdmFieldCategory::Vulnerability,
        UdmFieldCategory::Performance,
        UdmFieldCategory::Alerts,
        UdmFieldCategory::Change,
        UdmFieldCategory::Cloud,
        UdmFieldCategory::DataAccess,
        UdmFieldCategory::DataLossPrevention,
        UdmFieldCategory::InterprocessMessaging,
        UdmFieldCategory::Custom,
    ];

    for category in categories {
        let fields = UdmField::by_category(category);
        if fields.is_empty() {
            continue;
        }

        context.push_str(&format!("### {}\n", format_category_name(category)));

        let field_names: Vec<String> = fields
            .iter()
            .map(|f| format!("`{}`", f.column_name()))
            .collect();

        context.push_str(&field_names.join(", "));
        context.push_str("\n\n");
    }

    context
}

/// OCSF-profile field guidance (replaces the UDM-specific mistakes warning under
/// `NANO_SCHEMA_PROFILE=ocsf`). The concrete field list is supplied dynamically by
/// the glossary functions (`profile.fields()`); this is the static how-to. (NAN-1252)
const OCSF_FIELD_NOTES: &str = r#"SCHEMA: OCSF is active. Field guidance:
- Prefer the canonical OCSF field names from the field list above (dotted paths,
  e.g. `src_endpoint.ip`, `actor.user.name`, `actor.process.cmd_line`,
  `file.hashes.sha256`, `api.operation`, `cloud.provider`, `resources.type`).
- UDM-style aliases also resolve at query time (e.g. `src_ip`→`src_endpoint.ip`,
  `user`→`user.name`, `dest_ip`→`dst_endpoint.ip`, `process`→`actor.process.cmd_line`,
  `file_hash`→`file.hashes.sha256`), so either name is valid in nPL.
- VALUE encodings differ from UDM: `status_id`, `auth_protocol_id`, and
  `activity_id` are INTEGER enums (e.g. status_id 1=Success, 2=Failure;
  activity_id 1=Create/3=Update/4=Delete on API Activity). Filter them by the
  integer code, not a string literal. The sibling `status` string is capitalized
  ('Success'/'Failure').
- OCSF-only fields (no UDM equivalent): `api.operation` (the AWS/cloud API verb),
  `resources.type`/`resources.uid`/`resources.name`, `is_mfa`, `class_uid`,
  `category_uid`, `activity_id`."#;

/// Get the common field mistakes warning that should be included in AI prompts
///
/// Returns a formatted string with critical warnings about fields that don't exist
/// and their correct alternatives. This should be included in ALL AI prompts that
/// generate queries to prevent the AI from using non-existent fields.
pub fn get_field_mistakes_warning(profile: &dyn SchemaProfile) -> &'static str {
    if profile.id() != SchemaId::Udm {
        return OCSF_FIELD_NOTES;
    }
    r#"CRITICAL - ONLY use these UDM fields (others DO NOT exist):
- Users: user, src_user, dest_user
- Hosts: src_host, dest_host (NOT hostname, NOT host)
- IPs: src_ip, dest_ip (NOT ip, NOT client_ip, NOT server_ip)
- Network: src_port, dest_port, protocol, bytes_in, bytes_out
- DNS: query, dns_answers, query_type (NOT domain - use url_domain for web)
- Web: url, url_domain, http_method, http_status_code, http_user_agent
- Auth: event_type, status, signature_id (NOT event_id; `action` is a legacy synonym for event_type)
- Process (nano UDM):
  - command_line = full command line (NOT process!)
  - process_name = just the exe filename
  - parent_command_line = full parent command line
  - parent_process_name = just the parent exe filename
  - process_id, process_path, process_hash
- Files: file_path, file_name, file_hash
- Source: source_type (use to filter by log source)

FIELDS THAT DO NOT EXIST (NEVER USE THESE):
- action_type - USE event_type INSTEAD
- eventtype - USE event_type INSTEAD
- ActionType - USE event_type INSTEAD
- (action is a legacy synonym for event_type — both work in queries, but emit event_type)
- domain - USE url_domain or query INSTEAD
- host - USE src_host or dest_host INSTEAD
- hostname - USE src_host or dest_host INSTEAD
- dst_host - USE dest_host INSTEAD
- ip - USE src_ip or dest_ip INSTEAD
- dst_ip - USE dest_ip INSTEAD
- dst_port - USE dest_port INSTEAD
- event_id - USE signature_id INSTEAD
- process - USE command_line INSTEAD (nano UDM: command_line = full command line)
- dns_query - USE query INSTEAD
- dns_response - USE dns_answers INSTEAD
- http_status - USE http_status_code INSTEAD"#
}

/// Get a compact query syntax reference for AI prompts
///
/// Returns query syntax rules that should be included in prompts that generate queries.
pub fn get_query_syntax_reference() -> &'static str {
    r#"IMPORTANT - Query Syntax Rules:
- Use piped syntax: search_terms | command1 | command2
- Field filters: field=value, field>5, field<10, field!="value"
- Boolean: term1 AND term2, term1 OR term2, NOT term
- Stats: | stats count, sum(field), avg(field) by group_field
- Sort: | sort -field (descending) or | sort field (ascending)
- Time modifiers: earliest=-24h, earliest=-7d, latest=now (optional, overrides UI time picker)"#
}

/// Format category name for display
fn format_category_name(category: UdmFieldCategory) -> String {
    match category {
        UdmFieldCategory::Alerts => "Alert".to_string(),
        UdmFieldCategory::Authentication => "Authentication".to_string(),
        UdmFieldCategory::Certificate => "Certificate (SSL/TLS)".to_string(),
        UdmFieldCategory::Change => "Change Management".to_string(),
        UdmFieldCategory::DataAccess => "Data Access".to_string(),
        UdmFieldCategory::Database => "Database".to_string(),
        UdmFieldCategory::DataLossPrevention => "Data Loss Prevention".to_string(),
        UdmFieldCategory::Dns => "DNS".to_string(),
        UdmFieldCategory::Email => "Email".to_string(),
        UdmFieldCategory::Endpoint => "Endpoint/Host".to_string(),
        UdmFieldCategory::InterprocessMessaging => "Interprocess Messaging".to_string(),
        UdmFieldCategory::Intrusion => "Intrusion Detection".to_string(),
        UdmFieldCategory::Inventory => "Asset Inventory".to_string(),
        UdmFieldCategory::Malware => "Malware Detection".to_string(),
        UdmFieldCategory::Network => "Network Traffic".to_string(),
        UdmFieldCategory::Performance => "System Performance".to_string(),
        UdmFieldCategory::Vulnerability => "Vulnerability Scanning".to_string(),
        UdmFieldCategory::Web => "Web/HTTP Traffic".to_string(),
        UdmFieldCategory::Custom => "Custom nano Extensions".to_string(),
        UdmFieldCategory::System => "System/Metadata".to_string(),
        UdmFieldCategory::Enrichment => "GeoIP/ASN Enrichment".to_string(),
        UdmFieldCategory::ThreatIntelligence => "Threat Intelligence (IOC)".to_string(),
        UdmFieldCategory::CustomEnrichment => "Custom Enrichment".to_string(),
        UdmFieldCategory::Prevalence => "Prevalence Tracking".to_string(),
        UdmFieldCategory::Risk => "Risk Scoring".to_string(),
        UdmFieldCategory::Detection => "Detection Engine".to_string(),
        UdmFieldCategory::Cloud => "Cloud Infrastructure".to_string(),
    }
}

#[cfg(any())]
mod tests {
    use super::*;

    #[test]
    fn test_get_udm_field_context() {
        let context = get_udm_field_context();

        // Should contain category headers
        assert!(context.contains("### Network"));
        assert!(context.contains("### Authentication"));

        // Should contain field names
        assert!(context.contains("`src_ip`"));
        assert!(context.contains("`dest_ip`"));
        assert!(context.contains("`user`"));
    }

    #[test]
    fn test_get_udm_field_context_for_categories() {
        let categories = vec![UdmFieldCategory::Network, UdmFieldCategory::Authentication];
        let context = get_udm_field_context_for_categories(&categories);

        // Should contain requested categories
        assert!(context.contains("### Network"));
        assert!(context.contains("### Authentication"));

        // Should not contain other categories
        assert!(!context.contains("### Email"));
    }

    #[test]
    fn test_get_udm_field_names_by_category() {
        let context = get_udm_field_names_by_category();

        // Should be more concise than full context
        assert!(context.len() < get_udm_field_context().len());

        // Should still contain field names
        assert!(context.contains("`src_ip`"));
    }
}
