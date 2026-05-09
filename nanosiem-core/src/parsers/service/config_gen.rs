// SPDX-License-Identifier: AGPL-3.0-or-later

//! Vector TOML configuration generation

use super::ParserService;
use crate::parsers::types::Parser;

impl ParserService {
    /// Generate Vector TOML configuration for a parser
    pub fn generate_vector_config(&self, parser: &Parser) -> String {
        let source_name = format!("{}_source", parser.name);
        let transform_name = format!("parse_{}", parser.name);

        let source_config = match parser.source_type.as_str() {
            "file" => {
                let config: serde_json::Value = parser.source_config.clone();
                let include = config["include"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .map(|s| format!("\"{}\"", s))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();
                let read_from = config["read_from"].as_str().unwrap_or("end");

                format!(
                    r#"[sources.{}]
type = "file"
include = [{}]
read_from = "{}"
"#,
                    source_name, include, read_from
                )
            }
            "syslog" => {
                let config: serde_json::Value = parser.source_config.clone();
                let mode = config["mode"].as_str().unwrap_or("tcp");
                let address = config["address"].as_str().unwrap_or("0.0.0.0:514");

                format!(
                    r#"[sources.{}]
type = "syslog"
mode = "{}"
address = "{}"
"#,
                    source_name, mode, address
                )
            }
            "http" => {
                let config: serde_json::Value = parser.source_config.clone();
                let address = config["address"].as_str().unwrap_or("0.0.0.0:8080");

                format!(
                    r#"[sources.{}]
type = "http_server"
address = "{}"
"#,
                    source_name, address
                )
            }
            _ => format!(
                r#"[sources.{}]
type = "stdin"
"#,
                source_name
            ),
        };

        let transform_config = format!(
            r#"
[transforms.{}]
type = "remap"
inputs = ["{}"]
source = '''
{}
'''
"#,
            transform_name, source_name, parser.parser_vrl
        );

        format!("{}{}", source_config, transform_config)
    }
}
