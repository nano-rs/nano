// SPDX-License-Identifier: AGPL-3.0-or-later

//! Wire formats for `POST /api/rules/import` and `GET /api/rules/export`.
//!
//! Shared by the dedicated handler (`nanosiem-api`) and the enterprise-shared
//! adapter (the enterprise crate) so both deployments accept and emit the
//! same shapes:
//!
//! * Import takes either the structured `{"rules": [...]}` body or the web
//!   client's file-upload body `{"data": "<file contents>", "format":
//!   "json"|"yaml"}`. The file may hold a list of rules, a `{rules: [...]}`
//!   document, or a single rule — so an export file (either format) imports
//!   back unchanged.
//! * Export honors `?format=json|yaml` (JSON by default) with a matching
//!   `Content-Type` and an attachment filename.

use serde::{Deserialize, Serialize};

use crate::models::{DetectionRule, NewDetectionRule};

/// File format for rule import/export.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum RuleTransferFormat {
    #[default]
    Json,
    #[serde(alias = "yml")]
    Yaml,
}

impl RuleTransferFormat {
    pub fn content_type(self) -> &'static str {
        match self {
            Self::Json => "application/json",
            Self::Yaml => "application/yaml",
        }
    }

    pub fn filename(self) -> &'static str {
        match self {
            Self::Json => "detection-rules.json",
            Self::Yaml => "detection-rules.yaml",
        }
    }
}

/// Why an import body could not be turned into rules (a 400 for the caller).
#[derive(Debug, thiserror::Error)]
pub enum RuleImportParseError {
    #[error("Provide either `rules` or `data` (file contents), not both")]
    Ambiguous,
    #[error("Request must include `rules` (array) or `data` (file contents)")]
    Missing,
    #[error("Invalid {format} rule file: {message}")]
    Syntax { format: &'static str, message: String },
    #[error("Rule file must contain a list of rules, a `rules:` list, or a single rule")]
    Shape,
    #[error("Rule #{index} is invalid: {message}")]
    Rule { index: usize, message: String },
}

/// Resolve an import request's two accepted shapes to the rules to create.
pub fn resolve_import_rules(
    rules: Option<Vec<NewDetectionRule>>,
    data: Option<&str>,
    format: Option<RuleTransferFormat>,
) -> Result<Vec<NewDetectionRule>, RuleImportParseError> {
    match (rules, data) {
        (Some(_), Some(_)) => Err(RuleImportParseError::Ambiguous),
        (Some(rules), None) => Ok(rules),
        (None, Some(data)) => parse_rule_file(data, format.unwrap_or_default()),
        (None, None) => Err(RuleImportParseError::Missing),
    }
}

/// Parse an exported / hand-written rule file.
pub fn parse_rule_file(
    data: &str,
    format: RuleTransferFormat,
) -> Result<Vec<NewDetectionRule>, RuleImportParseError> {
    let document: serde_json::Value = match format {
        RuleTransferFormat::Json => serde_json::from_str(data).map_err(|e| RuleImportParseError::Syntax {
            format: "JSON",
            message: e.to_string(),
        })?,
        RuleTransferFormat::Yaml => {
            let yaml: serde_yaml::Value = serde_yaml::from_str(data).map_err(|e| RuleImportParseError::Syntax {
                format: "YAML",
                message: e.to_string(),
            })?;
            serde_json::to_value(yaml).map_err(|e| RuleImportParseError::Syntax {
                format: "YAML",
                message: e.to_string(),
            })?
        }
    };
    let items = match document {
        serde_json::Value::Array(items) => items,
        serde_json::Value::Object(mut map) => match map.remove("rules") {
            Some(serde_json::Value::Array(items)) => items,
            Some(_) => return Err(RuleImportParseError::Shape),
            None => vec![serde_json::Value::Object(map)],
        },
        _ => return Err(RuleImportParseError::Shape),
    };
    items
        .into_iter()
        .enumerate()
        .map(|(i, item)| {
            serde_json::from_value(item).map_err(|e| RuleImportParseError::Rule { index: i + 1, message: e.to_string() })
        })
        .collect()
}

/// Serialize an export in the requested format.
pub fn render_rules_export(rules: &[DetectionRule], format: RuleTransferFormat) -> Result<Vec<u8>, String> {
    match format {
        RuleTransferFormat::Json => serde_json::to_vec(rules).map_err(|e| e.to_string()),
        RuleTransferFormat::Yaml => serde_yaml::to_string(rules).map(String::into_bytes).map_err(|e| e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AlertMode, DetectionMode, RuleMode, Severity};
    use chrono::Utc;
    use uuid::Uuid;

    fn exported_rule(name: &str) -> DetectionRule {
        let json = serde_json::json!({
            "id": crate::typeid::encode("rule", &Uuid::new_v4()),
            "name": name,
            "description": "ssh brute force",
            "query": "event_type=auth auth_result=failure | stats count by src_ip | where count > 10",
            "severity": "high",
            "mitre_tactics": ["credential-access"],
            "mitre_techniques": ["T1110"],
            "schedule_cron": "*/5 * * * *",
            "mode": "live",
            "narrative": null,
            "reference_url": null,
            "author": "soc",
            "tags": ["ssh", "brute-force"],
            "ai_generated": false,
            "realtime_enabled": false,
            "detection_mode": "scheduled",
            "materialized_view_name": null,
            "risk_score": 70,
            "risk_entity_field": "src_ip",
            "risk_modifiers": [],
        });
        // Two literals: one would exceed the json! macro recursion limit.
        let rest = serde_json::json!({
            "created_at": Utc::now(),
            "updated_at": Utc::now(),
            "last_run_at": null,
            "last_match_at": null,
            "match_count": 12,
            "live_match_count": 3,
            "archived": false,
            "folder": "identity",
            "ai_triage_hints": {},
            "lookback_minutes": 15,
            "dataset": "logs",
            "auto_tuning_enabled": false,
            "auto_tuning_min_confidence": 0.8,
            "auto_tuning_critical": false,
            "auto_tuning_disabled_until": null,
            "case_visibility": "public",
            "case_assigned_group": null,
            "alert_mode": "grouped",
            "next_run_at": null,
            "claimed_by": null,
            "claimed_at": null,
            "playbook_selector_mode": "none",
            "playbook_id": null,
        });
        let mut json = json;
        json.as_object_mut().unwrap().extend(rest.as_object().unwrap().clone());
        serde_json::from_value(json).expect("fixture is a valid DetectionRule")
    }

    fn assert_equivalent(exported: &DetectionRule, imported: &NewDetectionRule) {
        assert_eq!(imported.name, exported.name);
        assert_eq!(imported.description, exported.description);
        assert_eq!(imported.query, exported.query);
        assert_eq!(imported.severity, exported.severity);
        assert_eq!(imported.mitre_tactics.as_deref(), Some(exported.mitre_tactics.as_slice()));
        assert_eq!(imported.mitre_techniques.as_deref(), Some(exported.mitre_techniques.as_slice()));
        assert_eq!(imported.schedule_cron, exported.schedule_cron);
        assert_eq!(imported.mode, Some(exported.mode));
        assert_eq!(imported.tags.as_deref(), Some(exported.tags.as_slice()));
        assert_eq!(imported.detection_mode, Some(exported.detection_mode));
        assert_eq!(imported.risk_score, exported.risk_score);
        assert_eq!(imported.risk_entity_field, exported.risk_entity_field);
        assert_eq!(imported.lookback_minutes, exported.lookback_minutes);
        assert_eq!(imported.dataset, exported.dataset);
        assert_eq!(imported.folder, exported.folder);
        assert_eq!(imported.alert_mode, Some(exported.alert_mode));
    }

    #[test]
    fn export_round_trips_through_import_in_both_formats() {
        let rules = vec![exported_rule("audit-roundtrip-a"), exported_rule("audit-roundtrip-b")];
        for format in [RuleTransferFormat::Json, RuleTransferFormat::Yaml] {
            let body = String::from_utf8(render_rules_export(&rules, format).unwrap()).unwrap();
            if format == RuleTransferFormat::Yaml {
                assert!(serde_json::from_str::<serde_json::Value>(&body).is_err(), "YAML export must not be JSON");
                assert!(body.contains("name: audit-roundtrip-a"), "{body}");
            }
            let imported = resolve_import_rules(None, Some(&body), Some(format)).unwrap();
            assert_eq!(imported.len(), 2, "{format:?}");
            for (exported, imported) in rules.iter().zip(&imported) {
                assert_equivalent(exported, imported);
            }
        }
        // Sanity on the enum fixtures the equivalence checks rely on.
        assert_eq!(rules[0].severity, Severity::High);
        assert_eq!(rules[0].mode, RuleMode::Live);
        assert_eq!(rules[0].detection_mode, DetectionMode::Scheduled);
        assert_eq!(rules[0].alert_mode, AlertMode::Grouped);
    }

    #[test]
    fn web_client_file_upload_body_deserializes() {
        #[derive(Deserialize)]
        struct Body {
            data: Option<String>,
            format: Option<RuleTransferFormat>,
        }
        let body: Body = serde_json::from_value(serde_json::json!({
            "data": "- name: a\n  query: error\n  severity: low\n",
            "format": "yaml",
        }))
        .unwrap();
        let rules = resolve_import_rules(None, body.data.as_deref(), body.format).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].name, "a");
        assert_eq!(rules[0].severity, Severity::Low);
    }

    #[test]
    fn file_shapes_list_wrapped_and_single() {
        let single = r#"{"name":"one","query":"error","severity":"medium"}"#;
        let wrapped = "rules:\n  - name: w\n    query: error\n    severity: low\n";
        assert_eq!(parse_rule_file(single, RuleTransferFormat::Json).unwrap()[0].name, "one");
        assert_eq!(parse_rule_file(wrapped, RuleTransferFormat::Yaml).unwrap()[0].name, "w");
        // YAML parses JSON too.
        assert_eq!(parse_rule_file(single, RuleTransferFormat::Yaml).unwrap()[0].name, "one");
    }

    #[test]
    fn bad_bodies_are_rejected_with_a_reason() {
        let rules = Some(vec![]);
        assert!(matches!(resolve_import_rules(rules, Some("[]"), None), Err(RuleImportParseError::Ambiguous)));
        assert!(matches!(resolve_import_rules(None, None, None), Err(RuleImportParseError::Missing)));
        assert!(matches!(
            parse_rule_file("{not json", RuleTransferFormat::Json),
            Err(RuleImportParseError::Syntax { format: "JSON", .. })
        ));
        assert!(matches!(parse_rule_file("42", RuleTransferFormat::Json), Err(RuleImportParseError::Shape)));
        assert!(matches!(parse_rule_file(r#"{"rules": 1}"#, RuleTransferFormat::Json), Err(RuleImportParseError::Shape)));
        let missing_query = "- name: ok\n  query: q\n  severity: low\n- name: broken\n  severity: low\n";
        match parse_rule_file(missing_query, RuleTransferFormat::Yaml) {
            Err(RuleImportParseError::Rule { index: 2, message }) => assert!(message.contains("query"), "{message}"),
            other => panic!("expected rule #2 error, got {other:?}"),
        }
    }

    #[test]
    fn format_query_values() {
        #[derive(Deserialize)]
        struct Q {
            format: Option<RuleTransferFormat>,
        }
        let parse = |s: &str| serde_json::from_str::<Q>(s).unwrap().format;
        assert_eq!(parse(r#"{"format":"yaml"}"#), Some(RuleTransferFormat::Yaml));
        assert_eq!(parse(r#"{"format":"yml"}"#), Some(RuleTransferFormat::Yaml));
        assert_eq!(parse(r#"{"format":"json"}"#), Some(RuleTransferFormat::Json));
        assert_eq!(RuleTransferFormat::Yaml.content_type(), "application/yaml");
    }
}
