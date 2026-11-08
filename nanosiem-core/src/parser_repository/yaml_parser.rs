// SPDX-License-Identifier: AGPL-3.0-or-later

//! YAML parser for parser.yaml format

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct ParserYaml {
    pub name: String,
    pub display_name: Option<String>,
    pub version: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub vendor: Option<String>,
    pub product: Option<String>,
    pub parser_vrl: Option<String>,
    pub match_values: Option<Vec<String>>,
    // NAN-1149: enrichment-parser flavor. When `kind: enrichment`, this parser
    // normalizes a pushed `nano_enrich` record into `target_table` via
    // `normalize_vrl`, rather than parsing a log `source_type`. `kind`,
    // `enrich_kind`, and `enrich_source` may be set explicitly here or inferred
    // from the repo path `enrichments/<enrich_kind>/<enrich_source>/parser.yaml`.
    #[serde(default)]
    pub kind: Option<String>,
    #[serde(default)]
    pub enrich_kind: Option<String>,
    #[serde(default)]
    pub enrich_source: Option<String>,
    #[serde(default)]
    pub target_table: Option<String>,
    #[serde(default)]
    pub normalize_vrl: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ParserYamlError {
    #[error("YAML parsing error: {0}")]
    Parse(#[from] serde_yaml::Error),

    #[error("Missing required field: {0}")]
    MissingField(String),
}

/// Parse a parser.yaml string into a ParserYaml struct
pub fn parse_parser_yaml(content: &str) -> Result<ParserYaml, ParserYamlError> {
    let parsed: ParserYaml = serde_yaml::from_str(content)?;

    if parsed.name.is_empty() {
        return Err(ParserYamlError::MissingField("name".to_string()));
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_parser_yaml() {
        let yaml = r#"
name: apache
display_name: Apache HTTP Server
version: "1.0.0"
description: "Parses Apache combined/common log format"
category: application
vendor: "Apache Software Foundation"
product: "Apache HTTP Server"
parser_vrl: |
  .udm = {}
  .message = .message
"#;
        let result = parse_parser_yaml(yaml).unwrap();
        assert_eq!(result.name, "apache");
        assert_eq!(result.display_name.as_deref(), Some("Apache HTTP Server"));
        assert_eq!(result.version.as_deref(), Some("1.0.0"));
        assert_eq!(result.category.as_deref(), Some("application"));
        assert!(result.parser_vrl.is_some());
    }

    #[test]
    fn test_parse_parser_yaml_with_match_values() {
        let yaml = r#"
name: apache
display_name: Apache HTTP Server
match_values:
  - apache
  - apache_access
  - apache_error
parser_vrl: |
  .udm = {}
"#;
        let result = parse_parser_yaml(yaml).unwrap();
        assert_eq!(
            result.match_values,
            Some(vec![
                "apache".to_string(),
                "apache_access".to_string(),
                "apache_error".to_string(),
            ])
        );
    }

    #[test]
    fn test_parse_parser_yaml_without_match_values() {
        let yaml = r#"
name: custom_parser
parser_vrl: |
  .udm = {}
"#;
        let result = parse_parser_yaml(yaml).unwrap();
        assert_eq!(result.match_values, None);
    }

    #[test]
    fn test_missing_name() {
        let yaml = r#"
name: ""
display_name: Test
"#;
        let result = parse_parser_yaml(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_enrichment_parser_yaml() {
        let yaml = r#"
name: ad_identity
kind: enrichment
enrich_kind: identity
enrich_source: ad
target_table: user_registry
normalize_vrl: |
  external_id = to_string(.external_id) ?? ""
  . = { "external_id": external_id }
"#;
        let result = parse_parser_yaml(yaml).unwrap();
        assert_eq!(result.name, "ad_identity");
        assert_eq!(result.kind.as_deref(), Some("enrichment"));
        assert_eq!(result.enrich_kind.as_deref(), Some("identity"));
        assert_eq!(result.enrich_source.as_deref(), Some("ad"));
        assert_eq!(result.target_table.as_deref(), Some("user_registry"));
        assert!(result.normalize_vrl.is_some());
    }

    #[test]
    fn test_log_parser_yaml_has_no_enrichment_fields() {
        let yaml = "name: apache\nparser_vrl: |\n  .udm = {}\n";
        let result = parse_parser_yaml(yaml).unwrap();
        assert_eq!(result.kind, None);
        assert_eq!(result.enrich_kind, None);
        assert_eq!(result.target_table, None);
    }
}
