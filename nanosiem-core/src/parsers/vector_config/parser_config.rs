// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser-level Vector configuration generation.
//!
//! Generates complete TOML configuration for individual parsers,
//! including source routing, VRL transform, and output transform blocks.

use super::VectorConfigManager;
use crate::parsers::types::Parser;

impl VectorConfigManager {
    /// Generate Vector TOML config for a single parser (returns string)
    pub fn generate_parser_config_string(&self, parser: &Parser) -> String {
        self.generate_parser_config(parser)
    }

    /// Generate Vector TOML config for a single parser
    pub(super) fn generate_parser_config(&self, parser: &Parser) -> String {
        let mut config = format!(
            "# Auto-generated Vector configuration for parser: {}\n\
             # DO NOT EDIT - changes will be overwritten\n\
             # Generated at: {}\n\n",
            parser.name,
            chrono::Utc::now().to_rfc3339()
        );

        let (source_config, source_name) = self.generate_source_config(parser);
        let transform_config = self.generate_transform_config(parser, &source_name);
        let output_config = self.generate_output_transform(parser);

        config.push_str(&source_config);
        config.push_str("\n");
        config.push_str(&transform_config);
        config.push_str("\n");
        config.push_str(&output_config);

        if let Some(sample_config) = self.generate_sample_transform(parser) {
            config.push_str("\n");
            config.push_str(&sample_config);
        }

        config
    }

    /// Generate a sample transform for parsers with sampling enabled.
    /// Returns None if sampling is not configured or ratio is out of range.
    pub(super) fn generate_sample_transform(&self, parser: &Parser) -> Option<String> {
        let ratio = parser.sampling_ratio?;
        if ratio <= 0.0 || ratio >= 1.0 {
            return None;
        }

        let safe_name = Self::safe_name(&parser.name);
        let output_name = format!("{}_output", safe_name);
        let sample_name = format!("{}_sample", safe_name);

        let exclude = parser.sampling_exclude_condition.as_deref().unwrap_or("");
        let exclude_block = if !exclude.is_empty() {
            format!("exclude = \"{}\"\n", exclude.replace('"', "\\\""))
        } else {
            String::new()
        };

        Some(format!(
            "[transforms.{sample_name}]\n\
             type = \"sample\"\n\
             inputs = [\"{output_name}\"]\n\
             ratio = {ratio}\n\
             {exclude_block}\n"
        ))
    }

    /// Generate transform configuration with the parser's VRL code
    pub(super) fn generate_transform_config(&self, parser: &Parser, source_name: &str) -> String {
        let safe_name = Self::safe_name(&parser.name);
        let transform_name = format!("{}_parse", safe_name);

        // SECURITY: Sanitize VRL code to prevent TOML injection
        // The validator should have already blocked ''', but double-check here
        let sanitized_vrl = parser
            .parser_vrl
            .replace("'''", "' ' '") // Break up triple quotes
            .replace("\r\n", "\n") // Normalize line endings
            .replace("\r", "\n");

        format!(
            "[transforms.{}]\n\
             type = \"remap\"\n\
             inputs = [\"{}\"]\n\
             source = '''\n\
             {}\n\
             '''\n",
            transform_name, source_name, sanitized_vrl
        )
    }

    /// Generate output transform that flattens to the expected format
    ///
    /// NOTE: This template avoids using `??` (error coalescing) operators inline
    /// because Vector's strict mode (E651) rejects them when the left-hand side
    /// is guaranteed to exist. Instead, we use explicit null checks with if/else.
    ///
    /// IMPORTANT: This transform preserves .ext fields from the parser. The .ext object
    /// is passed through to the ClickHouse mapping where it becomes a native JSON column.
    /// Parsers should set source-specific queryable fields on .ext (e.g., .ext.risk_level).
    ///
    /// This transform also injects vendor, product, and category from log_sources metadata
    /// so they flow through to ClickHouse columns without requiring parsers to set them.
    pub(super) fn generate_output_transform(&self, parser: &Parser) -> String {
        let safe_name = Self::safe_name(&parser.name);
        let parse_name = format!("{}_parse", safe_name);
        let output_name = format!("{}_output", safe_name);

        // For routed parsers, use the parser name as source_type (e.g., "apache")
        // For other source types, use the source_type field
        let output_source_type = if parser.source_type == "routed" {
            safe_name.clone()
        } else {
            parser.source_type.clone()
        };

        // Generate timezone VRL if non-UTC
        let timezone_vrl = crate::timezone::generate_timezone_vrl(&parser.timezone);

        // Get vendor, product, category, namespace from log_sources config
        let vendor = parser.vendor.clone().unwrap_or_default();
        let product = parser.product.clone().unwrap_or_default();
        let category = parser.category.clone().unwrap_or_default();
        let namespace = &parser.namespace;

        // Build vendor_product for backwards compatibility
        let vendor_product = match (&parser.vendor, &parser.product) {
            (Some(v), Some(p)) if !v.is_empty() && !p.is_empty() => format!("{} {}", v, p),
            (Some(v), None) if !v.is_empty() => v.clone(),
            (None, Some(p)) if !p.is_empty() => p.clone(),
            _ => String::new(),
        };

        format!(
            "[transforms.{}]\n\
             type = \"remap\"\n\
             inputs = [\"{}\"]\n\
             source = '''\n\
             # Flatten for ClickHouse - standard NanoSIEM format\n\
             # Spread all .udm fields to top level, preserve .ext\n\
             # The clickhouse_mapping transform handles final column assignment and ext capture\n\
             \n\
             # Handle timestamp - use udm.timestamp if set, otherwise now()\n\
             ts_val = .udm.timestamp\n\
             if ts_val == null {{\n\
                 ts_val = now()\n\
             }}\n\
             \n\
             {}\
             # Handle metadata - ensure it's an object\n\
             meta_val = .metadata\n\
             if meta_val == null {{\n\
                 meta_val = {{}}\n\
             }}\n\
             \n\
             # Handle ext - preserve source-specific queryable fields\n\
             # Parser sets fields like .ext.principal_id, .ext.bucket_name\n\
             ext_val = .ext\n\
             if ext_val == null {{\n\
                 ext_val = {{}}\n\
             }}\n\
             \n\
             # Handle source_type - use .source_type if set, otherwise default\n\
             st_val = .source_type\n\
             if st_val == null {{\n\
                 st_val = \"{}\"\n\
             }}\n\
             \n\
             # Preserve message and udm object\n\
             msg_val = .message\n\
             udm_val = .udm\n\
             if udm_val == null {{\n\
                 udm_val = {{}}\n\
             }}\n\
             \n\
             # Start with base fields\n\
             . = {{\n\
                 \"timestamp\": ts_val,\n\
                 \"message\": msg_val,\n\
                 \"metadata\": encode_json(meta_val),\n\
                 \"ext\": ext_val,\n\
                 \"source_type\": st_val\n\
             }}\n\
             \n\
             # Inject vendor, product, and category from log_sources metadata\n\
             # These are configured in the UI and don't require parser VRL to set them\n\
             .vendor = \"{}\"\n\
             .product = \"{}\"\n\
             .vendor_product = \"{}\"\n\
             .category = \"{}\"\n\
             .namespace = \"{}\"\n\
             \n\
             # Spread ALL .udm fields to top level for clickhouse_mapping\n\
             # This includes src_ip, action, user, category, user_type, etc.\n\
             # Note: category from udm will override the default if parser sets it\n\
             udm_keys, err = keys(udm_val)\n\
             if err == null {{\n\
                 for_each(udm_keys) -> |_idx, key| {{\n\
                     if key != \"timestamp\" && key != \"message\" {{\n\
                         val, get_err = get(udm_val, [key])\n\
                         if get_err == null && val != null {{\n\
                             . = set!(., [key], val)\n\
                         }}\n\
                     }}\n\
                 }}\n\
             }}\n\
             '''\n",
            output_name,
            parse_name,
            timezone_vrl
                .as_deref()
                .map(|vrl| format!("{}\n             \n             ", vrl))
                .unwrap_or_default(),
            output_source_type,
            vendor,
            product,
            vendor_product,
            category,
            namespace
        )
    }
}
