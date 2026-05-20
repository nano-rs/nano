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

/// Base inputs for the `[transforms.source_router]` transform, before any
/// per-source-config routes are appended.
///
/// Each `*_covered` flag indicates that a user-deployed source-config route
/// intermediates the corresponding always-on channel (consumes from it and
/// then feeds `source_router`). When covered, the channel is omitted here so
/// events don't reach `source_router` twice — once via the intermediary and
/// once via the direct base input.
///
/// - `source_type_extract_covered`: an http/vector routing config is deployed
/// - `hec_normalize_covered`: a splunk_hec routing config is deployed
/// - `hec_normalize_present`: the deployment's base Vector config actually
///   defines `[transforms.hec_normalize]`. OOTB open-core (config/vector/
///   02-hec-source.toml) does; nano-main customer deploys do not — their
///   Splunk HEC events flow through `splunk_in` → `auth_check` →
///   `source_type_extract` instead. Emitting `hec_normalize` when absent
///   makes Vector 0.55 reject the config on startup (`Input "hec_normalize"
///   for transform "source_router" doesn't match any components`). NAN-867.
///
/// `vector_merge` has no per-config intermediary (the Vector-native protocol
/// is always direct), so it stays unconditionally present.
///
/// Single source of truth for all writers of `_router.toml` (full rewrite,
/// staging, and the surgical line-replacer in `source_configs::service`) so
/// the list cannot drift between them.
pub fn base_router_inputs(
    source_type_extract_covered: bool,
    hec_normalize_covered: bool,
    hec_normalize_present: bool,
) -> Vec<&'static str> {
    let mut inputs = Vec::with_capacity(3);
    if !source_type_extract_covered {
        inputs.push("source_type_extract");
    }
    inputs.push("vector_merge");
    if hec_normalize_present && !hec_normalize_covered {
        inputs.push("hec_normalize");
    }
    inputs
}

/// Whether the deployment's base Vector config defines `[transforms.hec_normalize]`.
///
/// Reads `NANOSIEM_VECTOR_HEC_NORMALIZE_PRESENT`. Defaults to `true` to
/// preserve the OOTB open-core invariant from NAN-836 — that path ships
/// `02-hec-source.toml` and the router must keep wiring HEC events into
/// `source_router` directly.
///
/// nano-main customer deploys (Hetzner via compose-generator, K8s via
/// k8s-manifests/vector.ts) set this to `"false"`; their base config uses
/// `splunk_in` + `auth_check` and never defines `hec_normalize`.
pub fn hec_normalize_present() -> bool {
    std::env::var("NANOSIEM_VECTOR_HEC_NORMALIZE_PRESENT")
        .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "no" | "off"))
        .unwrap_or(true)
}

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

/// NAN-923: return true iff the file's TOML content declares the named
/// route transform. Uses a simple substring search rather than parsing
/// TOML so a fully-commented `# [transforms.foo_route]` is correctly
/// rejected — the `#` prefix means the substring `[transforms.foo_route]`
/// doesn't appear on the active line. Cheap, deterministic, and matches
/// the way generated files actually look.
pub(super) fn file_declares_route_transform(content: &str, route_name: &str) -> bool {
    let needle = format!("[transforms.{}]", route_name);
    content
        .lines()
        .any(|line| !line.trim_start().starts_with('#') && line.contains(&needle))
}

impl VectorConfigManager {
    /// Get the directory for source configuration files
    fn source_configs_dir(&self) -> PathBuf {
        self.config_dir.join("sources").join("configs")
    }

    /// Find deployed source configuration route transform names
    ///
    /// Scans the sources/configs directory for deployed source configurations
    /// and returns the names of their routing transforms (e.g., "aws_cloudtrail_queue_route").
    ///
    /// NAN-923: only include files that actually declare the
    /// `[transforms.<stem>_route]` block. A bare or fully-commented-out
    /// .toml file (e.g. a local-dev placeholder for a disabled source
    /// config) would otherwise add an input to `source_router` that
    /// references a non-existent transform, and Vector would refuse to
    /// load the config with "Input <name>_route for transform source_router
    /// doesn't match any components."
    pub(super) async fn get_source_config_routes(&self) -> Vec<String> {
        let configs_dir = self.source_configs_dir();
        let mut routes = Vec::new();

        if !configs_dir.exists() {
            return routes;
        }

        if let Ok(mut entries) = fs::read_dir(&configs_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                        let route_name = format!("{}_route", stem);
                        // Verify the file actually declares the transform
                        // before adding it to source_router inputs.
                        if let Ok(content) = fs::read_to_string(&path).await {
                            if file_declares_route_transform(&content, &route_name) {
                                routes.push(route_name);
                            }
                        }
                    }
                }
            }
        }

        routes.sort();
        routes
    }

    /// Detect which always-on intermediary channels are covered by a
    /// deployed source-config routing transform. Returns
    /// `(source_type_extract_covered, hec_normalize_covered)`.
    ///
    /// When a channel is covered, the per-config route consumes it and feeds
    /// `source_router`, so the base router inputs must NOT also include the
    /// channel directly — otherwise events arrive at `source_router` twice.
    pub(super) async fn source_config_intermediary_coverage(&self) -> (bool, bool) {
        let configs_dir = self.source_configs_dir();
        let mut source_type_extract = false;
        let mut hec_normalize = false;
        if !configs_dir.exists() {
            return (source_type_extract, hec_normalize);
        }

        if let Ok(mut entries) = fs::read_dir(&configs_dir).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let path = entry.path();
                if path.extension().map(|e| e == "toml").unwrap_or(false) {
                    if let Ok(content) = fs::read_to_string(&path).await {
                        // NAN-923: only consider non-commented lines so a
                        // fully-commented placeholder file doesn't
                        // incorrectly cover an intermediary channel.
                        for line in content.lines() {
                            if line.trim_start().starts_with('#') {
                                continue;
                            }
                            if line.contains("inputs = [\"source_type_extract\"]") {
                                source_type_extract = true;
                            }
                            if line.contains("inputs = [\"hec_normalize\"]") {
                                hec_normalize = true;
                            }
                        }
                        if source_type_extract && hec_normalize {
                            return (true, true);
                        }
                    }
                }
            }
        }

        (source_type_extract, hec_normalize)
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

        let (source_type_extract_covered, hec_normalize_covered) =
            self.source_config_intermediary_coverage().await;
        let mut router_inputs: Vec<String> = base_router_inputs(
            source_type_extract_covered,
            hec_normalize_covered,
            hec_normalize_present(),
        )
        .into_iter()
        .map(String::from)
        .collect();
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

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-923: a file with a real `[transforms.foo_route]` block is
    /// recognized — gets added to source_router.inputs.
    #[test]
    fn file_declares_route_transform_matches_real_declaration() {
        let content = r#"
[transforms.foo_route]
type = "remap"
inputs = ["hec_normalize"]
source = ".source_type = \"foo\""
"#;
        assert!(file_declares_route_transform(content, "foo_route"));
    }

    /// NAN-923: a fully-commented placeholder file (the gcp_pub_sub.toml
    /// failure mode) must NOT be recognized.
    #[test]
    fn file_declares_route_transform_rejects_fully_commented_file() {
        let content = r#"
# [sources.gcp_pub_sub_source]
# type = "gcp_pubsub"
#
# [transforms.gcp_pub_sub_route]
# type = "remap"
# inputs = ["gcp_pub_sub_source"]
"#;
        assert!(!file_declares_route_transform(content, "gcp_pub_sub_route"));
    }

    /// NAN-923: don't match a similarly-named transform that isn't the
    /// expected route — e.g. `[transforms.foo_route_helper]` should NOT
    /// register as `foo_route`.
    #[test]
    fn file_declares_route_transform_does_not_match_prefix() {
        let content = "[transforms.foo_route_helper]\ntype = \"filter\"\n";
        assert!(!file_declares_route_transform(content, "foo_route"));
    }

    /// NAN-923: whitespace at the start of the line should not throw off
    /// the comment check (defensive — TOML doesn't usually indent but a
    /// hand-edited file might).
    #[test]
    fn file_declares_route_transform_handles_indented_comments() {
        let content = "    # [transforms.foo_route]\n";
        assert!(!file_declares_route_transform(content, "foo_route"));
    }

    /// `vector_merge` has no per-config intermediary — always direct.
    #[test]
    fn base_router_inputs_always_includes_vector_merge() {
        for src_covered in [true, false] {
            for hec_covered in [true, false] {
                for hec_present in [true, false] {
                    assert!(
                        base_router_inputs(src_covered, hec_covered, hec_present)
                            .contains(&"vector_merge"),
                        "vector_merge missing for ({src_covered}, {hec_covered}, {hec_present})"
                    );
                }
            }
        }
    }

    /// HEC OOTB invariant (NAN-836): when the base config defines
    /// `hec_normalize` and no splunk_hec route is deployed, `hec_normalize`
    /// must feed `source_router` directly so HEC events on :8088 reach
    /// the router.
    #[test]
    fn base_router_inputs_includes_hec_normalize_when_uncovered_and_present() {
        assert!(base_router_inputs(false, false, true).contains(&"hec_normalize"));
        assert!(base_router_inputs(true, false, true).contains(&"hec_normalize"));
    }

    /// NAN-857: when a splunk_hec route is deployed, `hec_normalize` must NOT
    /// be in base inputs — the route already intermediates it. Otherwise
    /// every HEC event reaches source_router twice (once direct, once via
    /// the route) and lands in CH duplicated.
    #[test]
    fn base_router_inputs_excludes_hec_normalize_when_covered() {
        for hec_present in [true, false] {
            assert!(!base_router_inputs(false, true, hec_present).contains(&"hec_normalize"));
            assert!(!base_router_inputs(true, true, hec_present).contains(&"hec_normalize"));
        }
    }

    /// NAN-867: when the base config doesn't define `hec_normalize` (nano-main
    /// customer deploys), the router must never reference it. Vector 0.55
    /// rejects dangling input references and aborts startup.
    #[test]
    fn base_router_inputs_excludes_hec_normalize_when_absent() {
        for src_covered in [true, false] {
            for hec_covered in [true, false] {
                assert!(
                    !base_router_inputs(src_covered, hec_covered, false).contains(&"hec_normalize"),
                    "hec_normalize emitted with hec_normalize_present=false ({src_covered}, {hec_covered})"
                );
            }
        }
    }

    /// Symmetric invariant for http/vector: when an http/vector route is
    /// deployed, `source_type_extract` must be suppressed from base inputs.
    #[test]
    fn base_router_inputs_excludes_source_type_extract_when_covered() {
        for hec_present in [true, false] {
            assert!(
                !base_router_inputs(true, false, hec_present).contains(&"source_type_extract")
            );
            assert!(!base_router_inputs(true, true, hec_present).contains(&"source_type_extract"));
        }
    }

    #[test]
    fn base_router_inputs_includes_source_type_extract_when_uncovered() {
        for hec_present in [true, false] {
            assert!(
                base_router_inputs(false, false, hec_present).contains(&"source_type_extract")
            );
            assert!(base_router_inputs(false, true, hec_present).contains(&"source_type_extract"));
        }
    }
}
