// SPDX-License-Identifier: AGPL-3.0-or-later

//! Staging directory support for Vector configuration validation.
//!
//! Provides staging, validation, and promotion workflow for parser configs
//! to ensure safe deployment without disrupting active Vector configuration.

use std::path::Path;

use tokio::fs;

use super::router::{base_router_inputs, hec_normalize_present, BUILTIN_TYPES};
use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

impl VectorConfigManager {
    /// Stage a parser config for validation before deployment
    /// Writes the config to the staging directory without affecting active config
    pub async fn stage_parser(&self, parser: &Parser) -> Result<(), VectorConfigError> {
        // Ensure staging directory exists
        fs::create_dir_all(&self.staging_dir).await?;

        // Generate and write config to staging
        let config = self.generate_parser_config(parser);
        let filename = format!("{}.toml", Self::safe_name(&parser.name));
        let filepath = self.staging_dir.join(&filename);

        fs::write(&filepath, &config).await?;
        tracing::info!("Staged parser '{}' to {}", parser.name, filepath.display());

        Ok(())
    }

    /// Stage multiple parsers for validation
    ///
    /// This copies all base config files to staging along with the parser configs,
    /// ensuring that `vector validate` runs against a complete configuration.
    pub async fn stage_parsers(&self, parsers: &[Parser]) -> Result<(), VectorConfigError> {
        // Ensure staging directory exists and is clean
        self.cleanup_staging().await?;
        fs::create_dir_all(&self.staging_dir).await?;

        // Copy base config files to staging for complete validation
        // This ensures vector validate sees the full config context
        self.copy_base_configs_to_staging().await?;

        // Create staging parsers subdirectory
        let staging_parsers_dir = self.staging_dir.join("sources").join("parsers");
        fs::create_dir_all(&staging_parsers_dir).await?;

        for parser in parsers.iter().filter(|p| p.enabled) {
            let config = self.generate_parser_config(parser);
            let filename = format!("{}.toml", Self::safe_name(&parser.name));
            let filepath = staging_parsers_dir.join(&filename);
            fs::write(&filepath, &config).await?;
        }

        // Also stage the combiner config
        self.write_staged_combiner_config(parsers).await?;

        // Generate and stage the dynamic router config
        self.write_staged_router_config(parsers).await?;

        // Stage the static pipeline config (normalization, CH mapping, sink)
        self.write_staged_pipeline_config().await?;

        // Stage the push enrichment lane (NAN-1124) so `vector validate` sees it
        // and promote_staged copies it to the active parsers dir. Pass parsers
        // so the staged lane is generated per-source (NAN-1151), matching the
        // active writer — not the static fallback.
        self.write_staged_enrichment_config(parsers).await?;

        let enabled_count = parsers.iter().filter(|p| p.enabled).count();
        tracing::info!(
            "Staged {} parser(s) to {} with full config context",
            enabled_count,
            self.staging_dir.display()
        );

        Ok(())
    }

    /// Copy base Vector config files to staging directory
    ///
    /// This ensures that `vector validate` runs against a complete configuration
    /// that includes sources, sinks, and other transforms.
    async fn copy_base_configs_to_staging(&self) -> Result<(), VectorConfigError> {
        // Copy all .toml files from config_dir to staging (except those in subdirs)
        // This ensures vector validate sees the complete config context
        let mut entries = fs::read_dir(&self.config_dir).await?;
        let mut copied_count = 0;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                if let Some(ext) = path.extension() {
                    if ext == "toml" {
                        let filename = entry.file_name();
                        let dst_path = self.staging_dir.join(&filename);
                        fs::copy(&path, &dst_path).await?;
                        tracing::debug!("Copied {:?} to staging", filename);
                        copied_count += 1;
                    }
                }
            }
        }

        if copied_count == 0 {
            tracing::warn!(
                "No base config files found in {}",
                self.config_dir.display()
            );
        } else {
            tracing::info!("Copied {} base config files to staging", copied_count);
        }

        Ok(())
    }

    /// Write the dynamic router config to staging directory
    async fn write_staged_router_config(
        &self,
        parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        let staging_parsers_dir = self.staging_dir.join("sources").join("parsers");
        fs::create_dir_all(&staging_parsers_dir).await?;
        let router_path = staging_parsers_dir.join("_router.toml");

        // Get all enabled parsers that take input from the router
        // "routed" = HTTP ingestion, "vector" = Vector-to-Vector native protocol
        let routed_parsers: Vec<_> = parsers
            .iter()
            .filter(|p| p.enabled && (p.source_type == "routed" || p.source_type == "vector"))
            .collect();

        let (source_type_extract_covered, hec_normalize_covered) =
            self.source_config_intermediary_coverage().await;
        let base_inputs: Vec<String> = base_router_inputs(
            source_type_extract_covered,
            hec_normalize_covered,
            hec_normalize_present(),
        )
        .into_iter()
        .map(String::from)
        .collect();
        let source_config_routes = self.get_source_config_routes().await;

        // NAN-930: apply the same claim-dedupe substitution as the active
        // router writer (router.rs::write_router_config). `promote_staged`
        // copies this file over the active `_router.toml` after validation,
        // so without this call the staging output would re-introduce raw
        // route names in `source_router.inputs` and the double-write bug
        // would return. Shared helper keeps the two writers in lockstep.
        let (router_inputs, unclaimed_filter_blocks) =
            super::router::build_router_inputs_with_claim_dedupe(
                base_inputs,
                &source_config_routes,
                parsers,
            );
        let inputs_formatted = router_inputs
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");

        let mut config = format!(
            "# Auto-generated dynamic router for staged validation\n\
             # Generated at: {}\n\n\
             {}\
             # Accepts input from HTTP pipeline, Vector native protocol, and source configurations.\n\
             [transforms.source_router]\n\
             type = \"route\"\n\
             inputs = [{}]\n\n\
             [transforms.source_router.route]\n",
            chrono::Utc::now().to_rfc3339(),
            unclaimed_filter_blocks,
            inputs_formatted
        );

        // Add routes for deployed parsers (use match_values for condition when available)
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

        // Generic catch-all
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
        // NAN-1124: also exclude `nano_enrich` (push-enrichment) from the generic
        // log route — kept in lockstep with router.rs::write_router_config, since
        // promote_staged copies this file over the active _router.toml.
        config.push_str(&format!(
            "generic = '!includes([{}], .source_type) && !starts_with(downcase(to_string(.source_type) ?? \"\"), \"nano_enrich\")'\n\n",
            exclusion_list
        ));

        // NAN-1124 / NAN-1151: enrichment lane router. Built via the SAME shared
        // helper as the active writer (router.rs) so the staged file can't
        // byte-drift from it (promote_staged copies this over the active
        // _router.toml). Routes nano_enrich records to per-source outputs.
        let enabled_enrichment: Vec<&Parser> = parsers
            .iter()
            .filter(|p| p.enabled && p.kind == "enrichment")
            .collect();
        config.push_str(&super::router::enrichment_router_block(
            &enabled_enrichment,
            &inputs_formatted,
        ));

        // Add placeholder transforms for built-in types without parsers
        let mut placeholder_inputs: Vec<String> = Vec::new();
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

        // Placeholder combiner
        if placeholder_inputs.is_empty() {
            // NAN-1083: no-op filter sharing the same upstream-input fix as
            // `router.rs::write_router_config` (prior `prepare_output` input
            // formed a cycle). Keep both writers in lockstep.
            config.push_str(
                "[transforms.placeholder_combiner]\n\
                 type = \"filter\"\n\
                 inputs = [\"source_router.generic\"]\n\
                 condition = \"false\"\n",
            );
        } else {
            config.push_str(
                "[transforms.placeholder_combiner]\n\
                             type = \"remap\"\n",
            );
            config.push_str(&format!("inputs = [{}]\n", placeholder_inputs.join(", ")));
            config.push_str("source = '''\n.routed = true\n'''\n");
        }

        fs::write(&router_path, &config).await?;
        Ok(())
    }

    /// Write combiner config to staging directory
    async fn write_staged_combiner_config(
        &self,
        parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        // Combiner goes in sources/parsers subdirectory
        let staging_parsers_dir = self.staging_dir.join("sources").join("parsers");
        fs::create_dir_all(&staging_parsers_dir).await?;
        let combiner_path = staging_parsers_dir.join("_combiner.toml");

        let enabled_parsers: Vec<_> = parsers.iter().filter(|p| p.enabled).collect();

        let mut config = String::from(
            "# Auto-generated combiner for all DB parsers\n\
             # DO NOT EDIT - changes will be overwritten\n\n",
        );

        if enabled_parsers.is_empty() {
            // No parsers enabled — use a filter that drops everything so Vector
            // has a valid input (empty inputs = [] is rejected by Vector).
            config.push_str(
                "# No enabled parsers\n\
                 [transforms.db_parsers_combined]\n\
                 type = \"filter\"\n\
                 inputs = [\"prepare_output\"]\n\
                 condition = \"false\"\n",
            );
        } else {
            let inputs: Vec<String> = enabled_parsers
                .iter()
                .map(|p| {
                    let safe = Self::safe_name(&p.name);
                    let has_sampling = p
                        .sampling_ratio
                        .map(|r| r > 0.0 && r < 1.0)
                        .unwrap_or(false);
                    if has_sampling {
                        format!("\"{}_sample\"", safe)
                    } else {
                        format!("\"{}_output\"", safe)
                    }
                })
                .collect();

            config.push_str(&format!(
                "[transforms.db_parsers_combined]\n\
                 type = \"remap\"\n\
                 inputs = [{}]\n\
                 source = '''\n. = .\n'''\n",
                inputs.join(", ")
            ));
        }

        fs::write(&combiner_path, &config).await?;
        Ok(())
    }

    /// Write the static pipeline config to staging directory
    async fn write_staged_pipeline_config(&self) -> Result<(), VectorConfigError> {
        let staging_parsers_dir = self.staging_dir.join("sources").join("parsers");
        fs::create_dir_all(&staging_parsers_dir).await?;
        let pipeline_path = staging_parsers_dir.join("_pipeline.toml");
        fs::write(&pipeline_path, Self::pipeline_config_content()).await?;
        Ok(())
    }

    /// Write the push enrichment lane config to staging (NAN-1124). Mirror of
    /// write_staged_pipeline_config so promote_staged copies it to the active
    /// parsers dir alongside _pipeline.toml.
    async fn write_staged_enrichment_config(
        &self,
        parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        let staging_parsers_dir = self.staging_dir.join("sources").join("parsers");
        fs::create_dir_all(&staging_parsers_dir).await?;
        let enrichment_path = staging_parsers_dir.join("_enrichment.toml");
        // NAN-1151: stage the SAME per-source lane the active writer generates
        // (was the static `enrichment_lane_content`, so stage→promote silently
        // reverted dynamic enrichment parsers to the committed static lane).
        let enrichment_parsers: Vec<Parser> = parsers
            .iter()
            .filter(|p| p.kind == "enrichment")
            .cloned()
            .collect();
        let content = Self::enrichment_lane_config(&enrichment_parsers);
        // NAN-1150: same deploy-time guardrails as the active writer, so a
        // malformed enrichment parser is rejected at the stage→validate→promote
        // path too — never promoted to the active lane.
        Self::guard_enrichment_lane(&enrichment_parsers, &content)?;
        fs::write(&enrichment_path, content).await?;
        Ok(())
    }

    /// Clean up the staging directory
    pub async fn cleanup_staging(&self) -> Result<(), VectorConfigError> {
        if self.staging_dir.exists() {
            fs::remove_dir_all(&self.staging_dir).await?;
            tracing::info!(
                "Cleaned up staging directory: {}",
                self.staging_dir.display()
            );
        }
        Ok(())
    }

    /// Promote staged config to active directories
    /// Copies parser files from staging to the active parsers directory
    /// and updates the dynamic router config
    pub async fn promote_staged(&self) -> Result<(), VectorConfigError> {
        if !self.staging_dir.exists() {
            return Err(VectorConfigError::StagingError(
                "Staging directory does not exist".to_string(),
            ));
        }

        // Ensure parsers directory exists
        fs::create_dir_all(&self.parsers_dir).await?;

        // Copy staged parser files from sources/parsers to active parsers directory
        let staging_parsers_dir = self.staging_dir.join("sources").join("parsers");
        if staging_parsers_dir.exists() {
            let mut entries = fs::read_dir(&staging_parsers_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let dest = self.parsers_dir.join(entry.file_name());
                fs::copy(entry.path(), &dest).await?;
                tracing::debug!("Promoted {} to {}", entry.path().display(), dest.display());
            }
        }

        // The dynamic router is now inside staging parsers dir (_router.toml)
        // and gets copied with the other parser files above, no separate step needed.
        // Legacy cleanup: remove old 20-dynamic-router.toml from config_dir if present
        let legacy_router = self.config_dir.join("20-dynamic-router.toml");
        if legacy_router.exists() {
            fs::remove_file(&legacy_router).await.ok();
            tracing::info!(
                "Removed legacy router config from {}",
                legacy_router.display()
            );
        }

        // Cleanup staging after successful promotion
        self.cleanup_staging().await?;

        tracing::info!("Promoted staged config to {}", self.parsers_dir.display());
        Ok(())
    }

    /// Get the staging directory path
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }
}
