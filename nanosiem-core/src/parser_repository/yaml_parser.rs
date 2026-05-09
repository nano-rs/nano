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
}
