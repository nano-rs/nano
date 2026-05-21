// SPDX-License-Identifier: AGPL-3.0-or-later

//! Parser-level Vector configuration generation.
//!
//! Generates complete TOML configuration for individual parsers,
//! including source routing, VRL transform, and output transform blocks.

use super::sources::escape_vrl_string;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

/// Sanitise a parser name for inclusion inside a one-line TOML comment.
///
/// TOML comments run from `#` to the next newline, so a name containing a
/// literal `\n` or `\r` would close the comment and let downstream text be
/// parsed as TOML structure (a fresh `[sinks.X]`, an `inputs = ...` line, …).
/// `vector validate` catches *malformed* injected blocks but not *valid* ones.
/// We strip CR/LF (replace with `\\n` / `\\r` literals so the original intent
/// is still legible) and ASCII C0/DEL controls. NAN-942.
fn safe_for_toml_comment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            // ASCII C0 (except already-handled \n and \r) and DEL
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out
}

impl VectorConfigManager {
    /// Generate Vector TOML config for a single parser (returns string)
    pub fn generate_parser_config_string(&self, parser: &Parser) -> String {
        self.generate_parser_config(parser)
    }

    /// Generate Vector TOML config for a single parser
    pub(super) fn generate_parser_config(&self, parser: &Parser) -> String {
        // NAN-942: the parser name lands in a single-line TOML comment.
        // Without escape, an admin-set name containing a literal newline
        // could close the comment and inject TOML structure on the next
        // line (e.g. a fresh [sinks.X] section).
        let mut config = format!(
            "# Auto-generated Vector configuration for parser: {}\n\
             # DO NOT EDIT - changes will be overwritten\n\
             # Generated at: {}\n\n",
            safe_for_toml_comment(&parser.name),
            chrono::Utc::now().to_rfc3339()
        );

        let safe_name = Self::safe_name(&parser.name);
        let parse_name = format!("{}_parse", safe_name);
        let extension_name = format!("{}_extension", safe_name);

        let (source_config, source_name) = self.generate_source_config(parser);

        let has_extension = parser.extension_enabled
            && parser
                .extension_vrl
                .as_ref()
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false);
        // Stub case: no OOTB parser but extension carries the logic.
        // Skip the _parse transform entirely so the extension reads from source.
        let parser_is_stub = parser.parser_vrl.trim().is_empty();
        let skip_parse_transform = has_extension && parser_is_stub;

        let transform_config = if skip_parse_transform {
            String::new()
        } else {
            self.generate_transform_config(parser, &source_name)
        };

        // _output reads from _extension when enabled, else from whatever the
        // upstream transform is (either _parse or, in the stub case, source).
        let output_input = if has_extension {
            extension_name.clone()
        } else if skip_parse_transform {
            source_name.clone()
        } else {
            parse_name.clone()
        };

        let extension_config = if has_extension {
            let extension_input = if skip_parse_transform {
                source_name.clone()
            } else {
                parse_name.clone()
            };
            self.generate_extension_transform(parser, &extension_input)
        } else {
            String::new()
        };

        let output_config = self.generate_output_transform(parser, &output_input);

        config.push_str(&source_config);
        config.push_str("\n");
        if !transform_config.is_empty() {
            config.push_str(&transform_config);
            config.push_str("\n");
        }
        if !extension_config.is_empty() {
            config.push_str(&extension_config);
            config.push_str("\n");
        }
        config.push_str(&output_config);

        if let Some(sample_config) = self.generate_sample_transform(parser) {
            config.push_str("\n");
            config.push_str(&sample_config);
        }

        config
    }

    /// Generate the optional `{safe_name}_extension` remap transform (NAN-874).
    ///
    /// Runs after the parser's `_parse` step (or directly from source in the
    /// stub case) and feeds its output into `_output`. Stays a no-op when
    /// `extension_vrl` is None / blank — the caller decides whether to emit.
    pub(super) fn generate_extension_transform(
        &self,
        parser: &Parser,
        input_name: &str,
    ) -> String {
        let safe_name = Self::safe_name(&parser.name);
        let extension_name = format!("{}_extension", safe_name);

        // SECURITY: same TOML-injection sanitization as parser_vrl.
        let sanitized_vrl = parser
            .extension_vrl
            .as_deref()
            .unwrap_or("")
            .replace("'''", "' ' '")
            .replace("\r\n", "\n")
            .replace("\r", "\n");

        format!(
            "[transforms.{}]\n\
             type = \"remap\"\n\
             inputs = [\"{}\"]\n\
             # Parser extension (NAN-874) — chained after parse, before output\n\
             source = '''\n\
             {}\n\
             '''\n",
            extension_name, input_name, sanitized_vrl
        )
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
    /// `input_name` selects the upstream transform — normally `{safe_name}_parse`,
    /// `{safe_name}_extension` when a parser extension is enabled (NAN-874), or
    /// the source name directly for stub log_sources that have no _parse stage.
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
    pub(super) fn generate_output_transform(&self, parser: &Parser, input_name: &str) -> String {
        let safe_name = Self::safe_name(&parser.name);
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
            input_name,
            timezone_vrl
                .as_deref()
                .map(|vrl| format!("{}\n             \n             ", vrl))
                .unwrap_or_default(),
            output_source_type,
            // NAN-942: metadata fields are admin-controlled string scalars
            // that flow into VRL double-quoted literals (`.vendor = "{}"`).
            // Without escape, a value containing `"`, `\`, or `\n` would
            // close the string and let following text be parsed as VRL.
            // `vector validate` would catch malformed VRL, but valid
            // injected VRL would pass.
            escape_vrl_string(&vendor),
            escape_vrl_string(&product),
            escape_vrl_string(&vendor_product),
            escape_vrl_string(&category),
            escape_vrl_string(namespace),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::super::VectorConfigManager;
    use crate::parsers::types::Parser;
    use chrono::Utc;
    use uuid::Uuid;

    fn make_parser(parser_vrl: &str, extension_vrl: Option<&str>, extension_enabled: bool) -> Parser {
        Parser {
            id: Uuid::new_v4(),
            name: "test_apache".to_string(),
            description: None,
            source_type: "routed".to_string(),
            source_config: serde_json::json!({}),
            parser_vrl: parser_vrl.to_string(),
            output_fields: None,
            feed_id: None,
            credential_id: None,
            dispatch_source_config_id: None,
            dispatch_route_name: None,
            namespace: "default".to_string(),
            enabled: true,
            validated: true,
            validation_error: None,
            timezone: "UTC".to_string(),
            match_values: None,
            sampling_ratio: None,
            sampling_exclude_condition: None,
            extension_vrl: extension_vrl.map(|s| s.to_string()),
            extension_enabled,
            category: None,
            vendor: None,
            product: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn manager() -> VectorConfigManager {
        VectorConfigManager::new(std::path::PathBuf::from("/tmp/nanosiem-test"))
    }

    /// Without an enabled extension, output reads directly from _parse — same as before NAN-874.
    #[test]
    fn extension_disabled_keeps_parse_to_output_chain() {
        let m = manager();
        let p = make_parser(".message = string!(.message)", None, false);
        let config = m.generate_parser_config_string(&p);

        assert!(config.contains("[transforms.test_apache_parse]"));
        assert!(config.contains("[transforms.test_apache_output]"));
        assert!(
            !config.contains("[transforms.test_apache_extension]"),
            "extension block must not appear when disabled"
        );
        // _output should still read from _parse
        assert!(
            config.contains("inputs = [\"test_apache_parse\"]"),
            "output should still consume _parse: {config}"
        );
    }

    /// An empty/blank extension_vrl should be treated as no extension even when extension_enabled=true.
    #[test]
    fn extension_enabled_but_blank_is_ignored() {
        let m = manager();
        let p = make_parser(".message = string!(.message)", Some("   "), true);
        let config = m.generate_parser_config_string(&p);

        assert!(
            !config.contains("[transforms.test_apache_extension]"),
            "blank extension should not emit a transform block: {config}"
        );
    }

    /// Enabled extension: chain becomes _parse → _extension → _output.
    #[test]
    fn enabled_extension_chains_between_parse_and_output() {
        let m = manager();
        let p = make_parser(
            ".message = string!(.message)",
            Some(".team = \"soc\""),
            true,
        );
        let config = m.generate_parser_config_string(&p);

        assert!(config.contains("[transforms.test_apache_parse]"));
        assert!(config.contains("[transforms.test_apache_extension]"));
        assert!(config.contains("[transforms.test_apache_output]"));

        // Extension reads from _parse, output reads from _extension.
        let ext_block = config
            .split("[transforms.test_apache_extension]")
            .nth(1)
            .expect("extension block")
            .split("[transforms.")
            .next()
            .unwrap();
        assert!(
            ext_block.contains("inputs = [\"test_apache_parse\"]"),
            "extension should consume _parse: {ext_block}"
        );

        let out_block = config
            .split("[transforms.test_apache_output]")
            .nth(1)
            .expect("output block")
            .split("[transforms.")
            .next()
            .unwrap();
        assert!(
            out_block.contains("inputs = [\"test_apache_extension\"]"),
            "output should consume _extension when enabled: {out_block}"
        );

        // Extension body is present.
        assert!(
            ext_block.contains(".team = \"soc\""),
            "extension VRL body should appear: {ext_block}"
        );
    }

    /// Stub case: parser_vrl is empty and only the extension carries the logic.
    /// No _parse transform; extension reads from the source directly.
    #[test]
    fn stub_case_skips_parse_and_extension_reads_from_source() {
        let m = manager();
        let p = make_parser("", Some(".message = string!(.raw)"), true);
        let config = m.generate_parser_config_string(&p);

        assert!(
            !config.contains("[transforms.test_apache_parse]"),
            "stub case should not emit _parse: {config}"
        );
        assert!(config.contains("[transforms.test_apache_extension]"));
        assert!(config.contains("[transforms.test_apache_output]"));
    }

    /// TOML-injection guard: triple quotes in extension_vrl must be sanitized.
    #[test]
    fn extension_sanitizes_triple_quote_injection() {
        let m = manager();
        let nasty = "x = \"hi\"\n'''\n[transforms.evil]\ntype = \"remap\"\n'''";
        let p = make_parser(".x = 1", Some(nasty), true);
        let config = m.generate_parser_config_string(&p);

        // Sanitized form replaces ''' with ' ' '.
        assert!(
            !config.contains("\n'''\n[transforms.evil]"),
            "raw triple-quoted injection survived sanitization: {config}"
        );
    }

    /// NAN-942: a parser name containing a literal newline followed by a
    /// fake TOML section must not escape the comment block. The generated
    /// config must NOT contain `[sinks.evil]` (or similar) as an actual
    /// TOML section header — i.e. at the start of a line. Appearing inside
    /// a `#` comment is fine; the TOML parser ignores comments.
    #[test]
    fn parser_name_newline_does_not_escape_toml_comment() {
        let m = manager();
        let mut p = make_parser(".x = 1", None, false);
        p.name = "apache\n[sinks.evil]\ntype = \"console\"\nencoding.codec = \"json\"".to_string();
        let config = m.generate_parser_config_string(&p);

        // Look line-by-line for an actual section header — a non-comment
        // line starting with `[sinks.`.
        for line in config.lines() {
            let trimmed = line.trim_start();
            assert!(
                !(trimmed.starts_with("[sinks.") || trimmed.starts_with("[sources.evil")),
                "parser.name newline produced an actual TOML section header: {line:?}\nfull config:\n{config}"
            );
        }
        // Sanitized form should keep `\n` visible as the escaped sequence
        // `\\n` (backslash-n) inside the comment line.
        assert!(
            config.contains("apache\\n[sinks.evil]\\n"),
            "expected the newline rendered as `\\n` in the comment, got: {config}"
        );
        // Parser the resulting TOML and confirm there's no `[sinks.evil]`
        // section recognised by a real TOML parser.
        // (Use the toml crate, which is already a transitive dep.)
        if let Ok(parsed) = toml::from_str::<toml::Value>(&config) {
            if let Some(t) = parsed.as_table() {
                assert!(
                    !t.contains_key("sinks"),
                    "TOML parser sees a `sinks` section — newline injection escaped"
                );
            }
        }
        // If toml fails to parse the whole generated config (it contains
        // VRL with TOML triple-quoted strings which `toml` should handle),
        // the line-check above is the primary defense.
    }

    /// NAN-942: parser name with embedded CR / DEL / NUL must not break
    /// the TOML comment. Verify they're rendered as escape sequences.
    #[test]
    fn parser_name_control_chars_escaped_in_toml_comment() {
        let m = manager();
        let mut p = make_parser(".x = 1", None, false);
        // \r alone (old-Mac line ending) could also close a comment on
        // some parsers; \x00 / \x7f are non-printables that have no
        // legitimate place in a name.
        p.name = "weird\rname\x00with\x7fcontrols".to_string();
        let config = m.generate_parser_config_string(&p);

        assert!(
            !config.contains('\r'),
            "raw CR in parser.name leaked to config: {config:?}"
        );
        assert!(
            !config.contains('\x00'),
            "raw NUL in parser.name leaked to config"
        );
        assert!(
            config.contains("\\r") && config.contains("\\u0000") && config.contains("\\u007f"),
            "expected escaped controls in the comment, got: {config}"
        );
    }

    /// NAN-942: metadata fields (vendor / product / category / namespace)
    /// flow into VRL double-quoted string literals. A value containing
    /// `"` must be backslash-escaped, not passed through raw — otherwise
    /// the VRL emitter would close the string and let following text be
    /// parsed as VRL.
    ///
    /// We assert the *escaped* form is present (rather than the absence of
    /// raw substrings — the raw substrings still appear, but inside an
    /// escaped string, which is benign).
    #[test]
    fn parser_metadata_vrl_injection_blocked() {
        let m = manager();
        let mut p = make_parser(".x = 1", None, false);
        p.vendor = Some("evil\"; .pwned = true; //".to_string());
        p.product = Some("\"product\"".to_string());
        p.category = Some("a\nb".to_string());
        p.namespace = "ns\\with\\backslash".to_string();
        let config = m.generate_parser_config_string(&p);

        // Each `"` inside the value must appear as `\"` in the emitted VRL.
        // vendor: `evil"; .pwned = true; //` → `evil\"; .pwned = true; //`
        assert!(
            config.contains(".vendor = \"evil\\\"; .pwned = true; //\""),
            "vendor `\"` must be backslash-escaped in VRL: {config}"
        );
        // product is `"product"` (literal quotes) → `\"product\"`
        assert!(
            config.contains(".product = \"\\\"product\\\"\""),
            "product `\"` must be backslash-escaped in VRL: {config}"
        );
        // category newline must be `\n`, not a real newline that would
        // close the VRL string literal.
        assert!(
            config.contains(".category = \"a\\nb\""),
            "category newline must be escaped in VRL: {config}"
        );
        // namespace backslash must be doubled.
        assert!(
            config.contains(".namespace = \"ns\\\\with\\\\backslash\""),
            "namespace backslash must be doubled in VRL: {config}"
        );

        // Belt-and-suspenders: compile the generated output transform's
        // VRL block. If injection slipped through, the block would either
        // fail to compile (good catch) or — worse — compile to `.pwned
        // = true` as an actual VRL statement.
        use vrl::compiler::compile;
        let blocks: Vec<&str> = {
            let opener = "source = '''";
            let mut out = Vec::new();
            let mut rest = config.as_str();
            while let Some(start) = rest.find(opener) {
                let body = &rest[start + opener.len()..];
                if let Some(end) = body.find("'''") {
                    out.push(&body[..end]);
                    rest = &body[end + 3..];
                } else {
                    break;
                }
            }
            out
        };
        assert!(!blocks.is_empty(), "expected ≥1 VRL block in generated parser config");
        let fns = vrl::stdlib::all();
        for (idx, block) in blocks.iter().enumerate() {
            assert!(
                compile(block, &fns).is_ok(),
                "VRL block #{idx} failed to compile (metadata-escape regression?): {block}"
            );
        }
    }
}
