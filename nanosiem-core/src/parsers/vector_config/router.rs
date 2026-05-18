// SPDX-License-Identifier: AGPL-3.0-or-later

//! Dynamic router configuration generation for Vector.
//!
//! Generates the source_router transform that routes logs to deployed parsers
//! based on source type, with fallback to a generic parser for unknown types.

use std::path::PathBuf;

use tokio::fs;

use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

/// Built-in source types that get placeholder routes when no parser is deployed.
pub(super) const BUILTIN_TYPES: [&str; 12] = [
    "windows_event",
    "sysmon",
    "palo_alto",
    "fortinet",
    "cisco_asa",
    "syslog",
    "aws_cloudtrail",
    "aws_guardduty",
    "azure_activity",
    "azure_signin",
    "okta",
    "nginx",
];

impl VectorConfigManager {
    /// Get the directory for source configuration files
    fn source_configs_dir(&self) -> PathBuf {
        self.config_dir.join("sources").join("configs")
    }

    /// Find deployed source configuration route transform names
    ///
    /// Scans the sources/configs directory for deployed source configurations
    /// and returns the names of their routing transforms (e.g., "aws_cloudtrail_queue_route")
    pub(super) async fn get_source_config_routes(&self) -> Vec<String> {
        let configs_dir = self.source_configs_dir();
        let mut routes = Vec::new();

        if !configs_dir.exists() {
            return routes;
        }

        // Read all .toml files in the configs directory
        if let Ok(mut entries) = fs::read_dir(&configs_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    // Extract config name from filename (e.g., "aws_cloudtrail_queue.toml" -> "aws_cloudtrail_queue")
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        // The route transform is named {safe_name}_route
                        routes.push(format!("{}_route", stem));
                    }
                }
            }
        }

        routes.sort();
        routes
    }

    /// Check if any deployed source config routes are system-level (consume from source_type_extract).
    ///
    /// System-level routes (http, vector) act as intermediaries between source_type_extract
    /// and source_router. When they exist, source_type_extract must NOT also be a direct
    /// input to source_router, or every event will be duplicated.
    pub(super) async fn has_system_level_source_config_routes(&self) -> bool {
        let configs_dir = self.source_configs_dir();
        if !configs_dir.exists() {
            return false;
        }

        if let Ok(mut entries) = fs::read_dir(&configs_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&path).await {
                        // System-level routes consume directly from source_type_extract
                        if content.contains("inputs = [\"source_type_extract\"]") {
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    /// Write the dynamic router config based on deployed parsers
    ///
    /// This generates a router that includes routes for all deployed routed parsers.
    /// Unknown source types fall through to the generic parser.
    pub(super) async fn write_router_config(
        &self,
        parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        // Write router to parsers_dir so it gets included in the S3 config sync.
        // In distributed deployments (Rackspace), the API sidecar syncs sources/ to S3,
        // and Vector pods pull from S3. Writing to config_dir (parent) would be outside
        // the synced directory and never reach Vector.
        // Uses underscore prefix like _combiner.toml for consistency.
        let router_path = self.parsers_dir.join("_router.toml");

        // Get all enabled parsers that take input from the router
        // "routed" = HTTP ingestion, "vector" = Vector-to-Vector native protocol
        let routed_parsers: Vec<_> = parsers
            .iter()
            .filter(|p| p.enabled && (p.source_type == "routed" || p.source_type == "vector"))
            .collect();

        let mut config = String::from(
            "# Auto-generated dynamic router for deployed parsers\n\
             # DO NOT EDIT - changes will be overwritten by parser deployment\n\
             # Generated at: ",
        );
        config.push_str(&chrono::Utc::now().to_rfc3339());
        config.push_str("\n\n");

        // Generate the route section
        // Accepts input from HTTP pipeline (source_type_extract), Vector native
        // (vector_merge), and Splunk HEC (hec_normalize). Note: this block is
        // discarded and rebuilt below — kept consistent for diff readability.
        config.push_str(
            "# =============================================================================\n\
             # Dynamic Source Type Router\n\
             # =============================================================================\n\
             # Routes logs to deployed parsers based on source type.\n\
             # Accepts input from HTTP pipeline, Vector native, and Splunk HEC.\n\
             # Unknown source types fall through to the generic parser.\n\n\
             [transforms.source_router]\n\
             type = \"route\"\n\
             inputs = [\"source_type_extract\", \"vector_merge\", \"hec_normalize\"]\n\n\
             [transforms.source_router.route]\n",
        );

        // Add routes for each deployed routed parser
        for parser in &routed_parsers {
            let safe_name = Self::safe_name(&parser.name);
            config.push_str(&format!(
                "{} = '.source_type == \"{}\"'\n",
                safe_name, safe_name
            ));
        }

        // Always add the generic catch-all route
        config.push_str("generic = 'true'\n\n");

        // Generate placeholder transforms for source types that don't have deployed parsers
        config.push_str(
            "# =============================================================================\n\
             # Placeholder Transforms for Built-in Source Types\n\
             # =============================================================================\n\
             # These handle logs for source types that don't have deployed parsers yet.\n\n",
        );

        // Collect placeholder inputs for the combiner
        let mut placeholder_inputs: Vec<String> = Vec::new();

        for source_type in BUILTIN_TYPES {
            // Skip if there's a deployed parser for this source type
            let has_parser = routed_parsers
                .iter()
                .any(|p| Self::safe_name(&p.name) == source_type);
            if has_parser {
                config.push_str(&format!(
                    "# {} - has deployed parser, skipping placeholder\n\n",
                    source_type
                ));
                continue;
            }

            // Add route for this source type if not already in the router
            // (built-in types need explicit routes)
            config.push_str(&format!(
                "[transforms.{}_placeholder]\n\
                 type = \"remap\"\n\
                 inputs = [\"source_router.{}\"]\n\
                 source = '.metadata.awaiting_parser = \"{}\"'\n\n",
                source_type, source_type, source_type
            ));

            placeholder_inputs.push(format!("\"{}_placeholder\"", source_type));
        }

        // We need to add routes for built-in types to the router
        // Rewrite the router section with all routes
        config.clear();

        // Build inputs list: base sources + source configuration routes.
        // If system-level routes exist (http/vector configs that consume from source_type_extract),
        // exclude source_type_extract from direct inputs to avoid duplicate events — those routes
        // act as intermediaries and already feed into source_router.
        // hec_normalize is the Splunk HEC ingest channel and is always present
        // alongside vector_merge in OOTB open-core deployments.
        let has_system_routes = self.has_system_level_source_config_routes().await;
        let mut router_inputs = if has_system_routes {
            vec!["vector_merge".to_string(), "hec_normalize".to_string()]
        } else {
            vec![
                "source_type_extract".to_string(),
                "vector_merge".to_string(),
                "hec_normalize".to_string(),
            ]
        };
        let source_config_routes = self.get_source_config_routes().await;
        router_inputs.extend(source_config_routes);
        let inputs_formatted = router_inputs
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");

        config.push_str(&format!(
            "# Auto-generated dynamic router for deployed parsers\n\
             # DO NOT EDIT - changes will be overwritten by parser deployment\n\
             # Generated at: {}\n\n\
             # =============================================================================\n\
             # Dynamic Source Type Router\n\
             # =============================================================================\n\
             # Accepts input from HTTP pipeline, Vector native protocol, and source configurations.\n\
             [transforms.source_router]\n\
             type = \"route\"\n\
             inputs = [{}]\n\n\
             [transforms.source_router.route]\n",
            chrono::Utc::now().to_rfc3339(),
            inputs_formatted
        ));

        // Add routes for deployed parsers
        // Use match_values when available (the actual source_type values this parser handles),
        // falling back to safe_name for backward compatibility with legacy parsers.
        for parser in &routed_parsers {
            let safe_name = Self::safe_name(&parser.name);
            let route_condition = Self::build_route_condition(parser);
            config.push_str(&format!("{} = '{}'\n", safe_name, route_condition));
        }

        // Add routes for built-in types (that don't have deployed parsers)
        for source_type in BUILTIN_TYPES {
            let has_parser = routed_parsers
                .iter()
                .any(|p| Self::parser_handles_source_type(p, source_type));
            if !has_parser {
                config.push_str(&format!(
                    "{} = '.source_type == \"{}\"'\n",
                    source_type, source_type
                ));
            }
        }

        // Generic catch-all - excludes all known source types to prevent duplicates
        // Collect all known source types for the exclusion list
        let mut all_known_types: Vec<String> = routed_parsers
            .iter()
            .flat_map(|p| Self::parser_source_types(p))
            .collect();
        for source_type in BUILTIN_TYPES {
            if !all_known_types.contains(&source_type.to_string()) {
                all_known_types.push(source_type.to_string());
            }
        }
        let exclusion_list = all_known_types
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");
        config.push_str(&format!(
            "generic = '!includes([{}], .source_type)'\n\n",
            exclusion_list
        ));

        // Add placeholder transforms
        config.push_str(
            "# =============================================================================\n\
             # Placeholder Transforms\n\
             # =============================================================================\n\n",
        );

        placeholder_inputs.clear();
        for source_type in BUILTIN_TYPES {
            let has_parser = routed_parsers
                .iter()
                .any(|p| Self::parser_handles_source_type(p, source_type));
            if !has_parser {
                config.push_str(&format!(
                    "[transforms.{}_placeholder]\n\
                     type = \"remap\"\n\
                     inputs = [\"source_router.{}\"]\n\
                     source = '.metadata.awaiting_parser = \"{}\"'\n\n",
                    source_type, source_type, source_type
                ));
                placeholder_inputs.push(format!("\"{}_placeholder\"", source_type));
            }
        }

        // Generate the placeholder combiner
        config.push_str(
            "# =============================================================================\n\
             # Placeholder Combiner\n\
             # =============================================================================\n",
        );

        if placeholder_inputs.is_empty() {
            // No placeholders — use filter that drops everything (empty inputs rejected by Vector)
            config.push_str(
                "[transforms.placeholder_combiner]\n\
                 type = \"filter\"\n\
                 inputs = [\"prepare_output\"]\n\
                 condition = \"false\"\n",
            );
        } else {
            config.push_str(
                "[transforms.placeholder_combiner]\n\
                 type = \"remap\"\n",
            );
            config.push_str(&format!("inputs = [{}]\n", placeholder_inputs.join(", ")));
            config.push_str(
                "source = '''\n\
                 .routed = true\n\
                 '''\n",
            );
        }

        fs::write(&router_path, &config).await?;
        tracing::info!(
            "Generated dynamic router config at {} with {} deployed parsers",
            router_path.display(),
            routed_parsers.len()
        );

        Ok(())
    }
}
