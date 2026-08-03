// SPDX-License-Identifier: AGPL-3.0-or-later

//! Staging directory support for Vector configuration validation.
//!
//! Provides staging, validation, and promotion workflow for parser configs
//! to ensure safe deployment without disrupting active Vector configuration.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use tokio::fs;

use super::router::{base_router_inputs, hec_normalize_present, BUILTIN_TYPES};
use super::VectorConfigError;
use super::VectorConfigManager;
use crate::parsers::types::Parser;

/// Written last by [`VectorConfigManager::stage_parsers`] and required by
/// [`VectorConfigManager::promote_staged`] before it touches the active tree.
///
/// NAN-2298: without it, a staging directory that exists but is empty or
/// half-written promoted as a SUCCESS — nothing copied, nothing pruned, staging
/// cleaned up, `Ok(())` returned, and the caller recording a successful
/// deployment. A partially written tree was worse: one copied file made the
/// promoted set non-empty and authorized pruning every active parser missing
/// from it.
///
/// Lives in the staging ROOT, not `sources/parsers`, so promotion's copy loop
/// never carries it into the active config. Not a `.toml`, so
/// `copy_base_configs_to_staging` cannot mistake it for a base config.
const STAGING_COMPLETE_MARKER: &str = ".staging-complete";

/// Every directory Vector is launched with as a `--config-dir`, relative to the
/// config root. The staged candidate tree reproduces all of them, and
/// [`VectorConfigManager::validate_staged_config`] validates exactly this set.
///
/// NAN-2305: `vector validate` has to see the SAME component graph the running
/// Vector loads, or it passes judgement on a topology nobody is going to run.
/// The staged tree only ever held the root TOMLs plus `sources/parsers`, and
/// both directions of that gap hurt:
///
/// * Under-staged, validation FAILS on a healthy config. `stage_parsers` adds
///   every deployed source config's route (`prod_kafka_route`) to
///   `source_router.inputs`, but those transforms are declared in
///   `sources/configs`, which was never copied. Vector treats an input naming a
///   missing component as fatal to the whole config, so a tenant running any
///   pull source had EVERY parser deploy refused, indefinitely.
/// * Validation bypassed (`SKIP_VECTOR_VALIDATION=true`, or the Docker-mount
///   fallback that used to report success), the same incomplete tree is
///   promoted having been validated against nothing.
///
/// Mirrors the `--config-dir` list in docker-compose.yml. `--config-dir` is NOT
/// recursive (NAN-1234), so each directory must be named explicitly. Layouts
/// differ per deployment and some of these do not exist everywhere; staging
/// creates all of them regardless, because a `--config-dir` pointing at a
/// missing path is itself a Vector startup error.
pub(super) const STAGED_CONFIG_SUBDIRS: &[&str] =
    &["sources/parsers", "sources/configs", "sinks"];

/// The subset of [`STAGED_CONFIG_SUBDIRS`] copied verbatim out of the active
/// tree. `sources/parsers` is deliberately absent: staging GENERATES it from the
/// parser list. Copying the active files in first would carry every pre-rename
/// orphan into the candidate tree, and since `promote_staged` mirrors that tree
/// back onto the active one, the copy would re-publish precisely the stale files
/// NAN-2296 exists to remove.
const STAGED_MIRROR_SUBDIRS: &[&str] = &["sources/configs", "sinks"];

/// Records which files in the active parsers directory this subsystem
/// generated.
///
/// NAN-2305: promotion MIRRORS the staged tree (NAN-2296), and mirroring means
/// deleting active `.toml` files that are absent from the promoted set. Every
/// file the generator emits is re-emitted on each deploy, so none of ours is
/// ever wrongly deleted — but a TOML that is NOT ours (hand-added by a tenant,
/// or left behind by an older version whose generator used different names) was
/// silently deleted on the first deploy after upgrade, even when the running
/// graph still needed it. Deleting a file nobody can reconstruct is the one
/// outcome a config generator must never produce, so the manifest draws the
/// boundary: listed files are ours to delete, everything else is quarantined.
///
/// A dotfile, so Vector's `--config-dir` ignores it and both prune loops (here
/// and `deploy.rs::deploy_parsers`) skip it, exactly like `.gitkeep`.
const OWNERSHIP_MANIFEST: &str = ".nano-generated";

/// Files the generator emits under FIXED names whatever the parser set is.
///
/// Seeds ownership on the first promotion after upgrade, before any manifest
/// exists: these names are unambiguously ours, so an OCSF→UDM profile switch
/// still deletes `_ocsf_sink.toml` (and the legacy `_ocsf.toml`) instead of
/// quarantining it. Per-parser files cannot be recognised this way — `safe_name`
/// maps every non-alphanumeric to `_`, so "(Legacy) Apache" produces
/// `_legacy__apache.toml` and no name shape separates a parser file from a
/// tenant's own. Those get quarantined once, and from the first promotion
/// onward the manifest knows them by name.
/// Appended to a quarantined file so the copy is not a `.toml` any more. Vector
/// ignores unknown extensions, and — the reason this exists — the S3 config sync
/// walks the entire config root uploading every `.toml`, so a quarantined parser
/// that kept its extension would be replicated straight back out to the Vector
/// pods it was just removed from.
const QUARANTINE_SUFFIX: &str = ".quarantined";

const ALWAYS_GENERATED: &[&str] = &[
    "_router.toml",
    "_combiner.toml",
    "_pipeline.toml",
    "_enrichment.toml",
    "_ocsf_sink.toml",
    "_ocsf.toml",
];

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
        // NAN-2298: invalidate any previous completion marker FIRST — before the
        // collision check below, which returns early and would otherwise leave a
        // finished prior stage looking current. `cleanup_staging` further down
        // clears the tree, but only on the paths that reach it. From here on,
        // the marker exists only if THIS call ran to completion.
        let marker = self.staging_dir.join(STAGING_COMPLETE_MARKER);
        if marker.exists() {
            fs::remove_file(&marker).await?;
        }

        // NAN-1149 / NAN-2305: the same split the active writer performs
        // (deploy.rs::deploy_parsers). Enrichment parsers are not log sources —
        // they get no per-parser TOML, no `source_router` route and no combiner
        // input; they reach ClickHouse through the enrichment lane alone.
        //
        // NAN-2305: this split existed here for the collision check ONLY, and
        // every writer below was then handed the FULL parser list. A staged
        // enrichment parser therefore acquired a `source_router` route, its own
        // parser output and a combiner input, so its records entered the LOGS
        // pipeline as well as the enrichment lane — and promotion published that
        // divergence over the correct active config.
        let enrichment_parsers: Vec<Parser> = parsers
            .iter()
            .filter(|p| p.kind == "enrichment")
            .cloned()
            .collect();
        let log_parsers: Vec<Parser> = parsers
            .iter()
            .filter(|p| p.kind != "enrichment")
            .cloned()
            .collect();

        // NAN-2247: the same claim check the active writer runs
        // (deploy.rs::deploy_parsers). Staging exists to catch a bad config
        // before it is promoted on top of the live one, and `promote_staged`
        // copies these files over the active ones — so a collision that only
        // the active path rejected would still reach disk by this route.
        // Enrichment parsers claim no source_type, so only log parsers are
        // checked.
        let collisions = super::router::find_source_type_collisions(&log_parsers);
        if !collisions.is_empty() {
            let detail = super::router::describe_collisions(&collisions);
            tracing::error!(collisions = collisions.len(), "{}", detail);
            return Err(VectorConfigError::ValidationFailed(detail));
        }

        // NAN-2305: same reasoning as the check above, one level down — two
        // enabled parsers whose names collapse to one `safe_name` write one
        // `<safe_name>.toml` in the loop below and emit one duplicated route
        // key into the staged `_router.toml`. `promote_staged` copies both
        // over the active tree, so a collision caught only by the active
        // writer would still reach disk by this route. Scoped to the enabled
        // parsers because that is exactly the set this function writes.
        let identity_collisions = crate::vector_naming::find_identity_collisions(
            parsers
                .iter()
                .filter(|p| p.enabled)
                .map(|p| (p.id, Self::safe_name(&p.name), p.name.clone())),
        );
        if !identity_collisions.is_empty() {
            let detail = crate::vector_naming::describe_identity_collisions(
                "log source",
                &identity_collisions,
            );
            tracing::error!(collisions = identity_collisions.len(), "{}", detail);
            return Err(VectorConfigError::ValidationFailed(detail));
        }

        // Ensure staging directory exists and is clean
        self.cleanup_staging().await?;
        fs::create_dir_all(&self.staging_dir).await?;

        // Copy base config files to staging for complete validation
        // This ensures vector validate sees the full config context
        self.copy_base_configs_to_staging().await?;

        // Create staging parsers subdirectory
        let staging_parsers_dir = self.staged_parsers_dir();

        for parser in log_parsers.iter().filter(|p| p.enabled) {
            let config = self.generate_parser_config(parser);
            let filename = format!("{}.toml", Self::safe_name(&parser.name));
            let filepath = staging_parsers_dir.join(&filename);
            fs::write(&filepath, &config).await?;
        }

        // Also stage the combiner config
        self.write_staged_combiner_config(&log_parsers).await?;

        // Generate and stage the dynamic router config
        self.write_staged_router_config(&log_parsers, &enrichment_parsers)
            .await?;

        // Stage the static pipeline config (normalization, CH mapping, sink)
        self.write_staged_pipeline_config().await?;

        // NAN-1584: stage the OCSF ingestion sink too. Without this, a
        // single-source publish (log_sources::deploy → stage_parsers →
        // promote_staged) regenerated the combiner/router/pipeline but left the
        // active `_ocsf_sink.toml` at its last full-deploy state, so a freshly
        // published parser's `_ocsf_prepare` fork reached no sink and its OCSF
        // events were silently dropped. promote_staged copies this to the active
        // parsers dir. No-op under UDM.
        self.write_staged_ocsf_sink_config(&log_parsers).await?;

        // Stage the push enrichment lane (NAN-1124) so `vector validate` sees it
        // and promote_staged copies it to the active parsers dir. Generated
        // per-source from the enrichment parsers (NAN-1151), matching the active
        // writer — not the static fallback.
        self.write_staged_enrichment_config(&enrichment_parsers)
            .await?;

        // NAN-2298: written LAST, so its presence means every step above
        // completed. `promote_staged` refuses to touch the active tree without
        // it — an interrupted or corrupt stage now fails loudly instead of
        // promoting nothing and reporting success.
        fs::write(
            self.staging_dir.join(STAGING_COMPLETE_MARKER),
            "staged\n",
        )
        .await?;

        let enabled_count = log_parsers.iter().filter(|p| p.enabled).count();
        tracing::info!(
            "Staged {} parser(s) to {} with full config context",
            enabled_count,
            self.staging_dir.display()
        );

        Ok(())
    }

    /// NAN-1584: stage the OCSF ingestion sink (`_ocsf_sink.toml`) so the
    /// staged → promoted publish path re-wires it to every enabled parser's
    /// `_ocsf_prepare` fork, exactly like the active `write_ocsf_sink_config`.
    /// Uses the shared `ocsf_sink_inputs` / `ocsf_sink_content` helpers so the
    /// staged and active forms cannot byte-drift. Under UDM (or no parsers) it
    /// writes nothing and clears any stale staged sink.
    async fn write_staged_ocsf_sink_config(
        &self,
        log_parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        let sink_path = self.staged_parsers_dir().join("_ocsf_sink.toml");

        let inputs = Self::ocsf_sink_inputs(log_parsers);
        if inputs.is_empty() {
            if sink_path.exists() {
                fs::remove_file(&sink_path).await?;
            }
            return Ok(());
        }

        fs::write(&sink_path, Self::ocsf_sink_content(&inputs)).await?;
        Ok(())
    }

    /// Path of the generated parsers directory inside the candidate tree. Not
    /// created here — [`Self::copy_base_configs_to_staging`] creates every
    /// directory in [`STAGED_CONFIG_SUBDIRS`] up front.
    fn staged_parsers_dir(&self) -> PathBuf {
        self.staging_dir.join("sources").join("parsers")
    }

    /// Build the candidate tree that `vector validate` will be pointed at:
    /// every directory Vector loads, carrying the config Vector would load from
    /// it.
    ///
    /// NAN-2305: this used to copy the ROOT `.toml` files and nothing else, so
    /// the candidate tree was missing `sources/configs` and `sinks` — two of the
    /// four `--config-dir` arguments the running Vector is given. The staged
    /// `_router.toml` names each source config's `<stem>_route` transform in
    /// `source_router.inputs`, and an input naming a component validation cannot
    /// see is fatal to the WHOLE config, so every parser deploy for a tenant
    /// running a pull source was refused. See [`STAGED_CONFIG_SUBDIRS`] for the
    /// full failure mode, including the inverse when validation is skipped.
    ///
    /// The directories are created whether or not the active tree has them: a
    /// `--config-dir` pointing at a missing path is itself an error, and staging
    /// must never invent one. An empty one is fine — the shipped `sinks/` holds
    /// no loadable TOML today and Vector boots against it.
    async fn copy_base_configs_to_staging(&self) -> Result<(), VectorConfigError> {
        // Copy all .toml files from config_dir to staging (except those in subdirs)
        // This ensures vector validate sees the complete config context
        let copied_count = Self::copy_toml_files(&self.config_dir, &self.staging_dir).await?;

        if copied_count == 0 {
            tracing::warn!(
                "No base config files found in {}",
                self.config_dir.display()
            );
        } else {
            tracing::info!("Copied {} base config files to staging", copied_count);
        }

        for subdir in STAGED_CONFIG_SUBDIRS {
            let staged = self.staging_dir.join(subdir);
            fs::create_dir_all(&staged).await?;
        }

        for subdir in STAGED_MIRROR_SUBDIRS {
            let source = self.config_dir.join(subdir);
            if !fs::try_exists(&source).await? {
                continue;
            }
            let copied = Self::copy_toml_files(&source, &self.staging_dir.join(subdir)).await?;
            tracing::debug!("Copied {} config file(s) from {} to staging", copied, subdir);
        }

        Ok(())
    }

    /// Copy the top-level `.toml` files of `src` into `dst`, returning how many.
    ///
    /// Non-recursive on purpose: `--config-dir` is not recursive either
    /// (NAN-1234), so a nested file is not part of the config Vector loads and
    /// must not be part of the tree it is validated against.
    ///
    /// Symlinks are FOLLOWED (`metadata`, not `symlink_metadata`). Under a
    /// Kubernetes ConfigMap mount every config file is a symlink into `..data/`,
    /// so refusing to follow them would stage an empty tree on exactly the
    /// deployments that need validation most — and the target is the same byte
    /// stream Vector itself reads through that link.
    async fn copy_toml_files(src: &Path, dst: &Path) -> Result<usize, VectorConfigError> {
        fs::create_dir_all(dst).await?;
        let mut entries = fs::read_dir(src).await?;
        let mut copied = 0usize;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().map(|ext| ext == "toml") != Some(true) {
                continue;
            }
            if !fs::metadata(&path).await.map(|m| m.is_file()).unwrap_or(false) {
                continue;
            }
            let filename = entry.file_name();
            fs::copy(&path, dst.join(&filename)).await?;
            tracing::debug!("Copied {:?} to staging", filename);
            copied += 1;
        }

        Ok(copied)
    }

    /// Write the dynamic router config to staging directory.
    ///
    /// Takes the two parser groups separately, exactly like the active writer
    /// (`router.rs::write_router_config`). NAN-2305: it used to take one
    /// combined slice and re-derive both groups from it, which meant the routed
    /// filter below saw enrichment parsers too — any enrichment parser with
    /// `source_type` "routed"/"vector" got a `source_router` route and its
    /// records entered the logs pipeline.
    async fn write_staged_router_config(
        &self,
        log_parsers: &[Parser],
        enrichment_parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        let staging_parsers_dir = self.staged_parsers_dir();
        fs::create_dir_all(&staging_parsers_dir).await?;
        let router_path = staging_parsers_dir.join("_router.toml");

        // Get all enabled parsers that take input from the router
        // "routed" = HTTP ingestion, "vector" = Vector-to-Vector native protocol
        let routed_parsers: Vec<_> = log_parsers
            .iter()
            .filter(|p| p.enabled && (p.source_type == "routed" || p.source_type == "vector"))
            .collect();

        let (source_type_extract_covered, hec_normalize_covered, otlp_logs_prep_covered) =
            self.source_config_intermediary_coverage().await;
        let base_inputs: Vec<String> = base_router_inputs(
            source_type_extract_covered,
            hec_normalize_covered,
            hec_normalize_present(),
            otlp_logs_prep_covered,
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
                log_parsers,
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
        let enabled_enrichment: Vec<&Parser> =
            enrichment_parsers.iter().filter(|p| p.enabled).collect();
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

    /// Write combiner config to staging directory. Log parsers only — an
    /// enrichment parser has no parser output to union, and giving it a combiner
    /// input would splice the enrichment lane into the logs pipeline
    /// (NAN-2305), which is why the active writer passes `log_parsers` too.
    async fn write_staged_combiner_config(
        &self,
        log_parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        // Combiner goes in sources/parsers subdirectory
        let staging_parsers_dir = self.staged_parsers_dir();
        fs::create_dir_all(&staging_parsers_dir).await?;
        let combiner_path = staging_parsers_dir.join("_combiner.toml");
        let config = Self::combiner_config_content_for(log_parsers, Self::ocsf_mode());
        fs::write(&combiner_path, &config).await?;
        Ok(())
    }

    /// Write the static pipeline config to staging directory
    async fn write_staged_pipeline_config(&self) -> Result<(), VectorConfigError> {
        let staging_parsers_dir = self.staged_parsers_dir();
        fs::create_dir_all(&staging_parsers_dir).await?;
        let pipeline_path = staging_parsers_dir.join("_pipeline.toml");
        // NAN-1325: same active-schema content as the deploy writer, so the staged
        // OCSF pipeline carries the generic Base Event lane and promote_staged copies
        // it over verbatim (UDM byte-identical).
        fs::write(&pipeline_path, Self::full_pipeline_config_content()).await?;
        Ok(())
    }

    /// Write the push enrichment lane config to staging (NAN-1124). Mirror of
    /// write_staged_pipeline_config so promote_staged copies it to the active
    /// parsers dir alongside _pipeline.toml.
    async fn write_staged_enrichment_config(
        &self,
        enrichment_parsers: &[Parser],
    ) -> Result<(), VectorConfigError> {
        let staging_parsers_dir = self.staged_parsers_dir();
        fs::create_dir_all(&staging_parsers_dir).await?;
        let enrichment_path = staging_parsers_dir.join("_enrichment.toml");
        // NAN-1151: stage the SAME per-source lane the active writer generates
        // (was the static `enrichment_lane_content`, so stage→promote silently
        // reverted dynamic enrichment parsers to the committed static lane).
        // NAN-2305: the split now happens once in `stage_parsers`, so this lane
        // and the logs lane can never disagree about which parsers are which.
        let content = Self::enrichment_lane_config(enrichment_parsers);
        // NAN-1150: same deploy-time guardrails as the active writer, so a
        // malformed enrichment parser is rejected at the stage→validate→promote
        // path too — never promoted to the active lane.
        Self::guard_enrichment_lane(enrichment_parsers, &content)?;
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

        // NAN-2298: refuse to promote a tree `stage_parsers` did not finish.
        // Checked BEFORE anything on the active side is copied or deleted, so a
        // failed stage leaves the running config exactly as it was.
        if !self.staging_dir.join(STAGING_COMPLETE_MARKER).exists() {
            return Err(VectorConfigError::StagingError(format!(
                "Staging tree at {} is incomplete: no {} marker. Refusing to promote — \
                 the stage did not finish, and promoting it would publish a partial \
                 config or prune active parsers that were never staged.",
                self.staging_dir.display(),
                STAGING_COMPLETE_MARKER,
            )));
        }

        // Ensure parsers directory exists
        fs::create_dir_all(&self.parsers_dir).await?;

        // Copy staged parser files from sources/parsers to active parsers directory
        let staging_parsers_dir = self.staged_parsers_dir();
        let mut promoted: HashSet<String> = HashSet::new();
        if staging_parsers_dir.exists() {
            let mut entries = fs::read_dir(&staging_parsers_dir).await?;
            while let Some(entry) = entries.next_entry().await? {
                let dest = self.parsers_dir.join(entry.file_name());
                fs::copy(entry.path(), &dest).await?;
                promoted.insert(entry.file_name().to_string_lossy().to_string());
                tracing::debug!("Promoted {} to {}", entry.path().display(), dest.display());
            }
        }

        // NAN-2296: promotion must MIRROR the staged tree, not overlay it.
        //
        // `deploy_parsers` prunes orphans, but on a deploy it runs against the
        // STAGING tree — which never held the old-name file — so a rename left
        // the stale TOML in the active directory untouched. That file's
        // `inputs` still points at `source_router.<old_safe_name>`, a route the
        // regenerated `_router.toml` no longer emits, and an input naming a
        // missing component is fatal to the WHOLE config. Vector then rejects
        // every reload and keeps serving the last good config, while deploy and
        // publish both report success because the reload is best-effort. Renaming
        // one log source froze an entire pipeline for hours that way.
        //
        // Underscore-prefixed files are mirrored too, deliberately. `safe_name`
        // maps every non-alphanumeric character to `_`, so a source named
        // "(Legacy) Apache" generates `_legacy__apache.toml` — a per-parser file
        // that a name-prefix skip would strand on rename, reproducing this exact
        // bug. The shared infrastructure files are safe without a skip because
        // `stage_parsers` always emits them: `_router`, `_combiner`, `_pipeline`,
        // `_enrichment`, and `_ocsf_sink` under OCSF. Under UDM the staged writer
        // removes `_ocsf_sink` from staging, so mirroring drops the active copy —
        // the same outcome as the explicit removal below, which stays as the
        // documented statement of that rule. It also clears the legacy
        // `_ocsf.toml` that the active writer deletes but promotion preserved.
        //
        // Dotfiles are skipped: `.gitkeep` and friends are not ours to delete.
        //
        // NAN-2305: "not in the promoted set" is not the same claim as "safe to
        // delete". Mirroring reached every `.toml` in the directory, including
        // ones this subsystem never wrote — a tenant-managed lane, or a file
        // left by an older version whose generator used different names — and
        // destroyed them on the first deploy after upgrade, silently, even when
        // the running graph still needed them. A generated file we delete is
        // rebuilt on the next deploy; a hand-written one is gone. So ownership
        // decides: files this subsystem generated (per the manifest, plus the
        // fixed-name set) are deleted, and anything else is QUARANTINED — moved
        // out of the loaded directory, because leaving it re-creates the
        // dangling-input outage above, but kept on disk because we cannot
        // recreate it.
        //
        // Only ever runs when staging produced at least one file — an empty
        // staging tree means something failed upstream, and clearing the active
        // config on the way past would turn that into an outage.
        if !promoted.is_empty() {
            let owned = self.read_ownership_manifest().await?;
            let mut strays: Vec<(PathBuf, String)> = Vec::new();

            let mut active = fs::read_dir(&self.parsers_dir).await?;
            while let Some(entry) = active.next_entry().await? {
                let file_name = entry.file_name().to_string_lossy().to_string();
                if file_name.starts_with('.') || !file_name.ends_with(".toml") {
                    continue;
                }
                if promoted.contains(&file_name) {
                    continue;
                }
                if owned.contains(&file_name) {
                    fs::remove_file(entry.path()).await?;
                    tracing::warn!(
                        "Removed orphaned active parser config '{}' (generated by a previous \
                         deploy, not in the promoted set)",
                        file_name
                    );
                } else {
                    strays.push((entry.path(), file_name));
                }
            }

            self.quarantine_unowned(strays).await?;

            // Written last, and only on the path that actually mirrored: the
            // manifest must describe the tree as it now stands. A promotion that
            // failed above leaves the previous manifest, which still describes
            // the files the previous promotion generated.
            self.write_ownership_manifest(&promoted).await?;
        }

        // NAN-1584: mirror write_ocsf_sink_config's UDM removal. promote_staged
        // only copies staged files, so a publish under UDM after a prior OCSF
        // deploy would otherwise leave a stale active `_ocsf_sink.toml` that
        // references OCSF-only transforms (`*_ocsf_prepare`, `generic_ocsf_prepare`)
        // which aren't emitted under UDM — a broken Vector config. Under OCSF the
        // staged writer always emits the sink (already copied above); under UDM it
        // must not exist, so drop any stale active copy.
        if !Self::ocsf_mode() {
            let active_sink = self.parsers_dir.join("_ocsf_sink.toml");
            if active_sink.exists() {
                fs::remove_file(&active_sink).await?;
                tracing::info!("Removed stale active OCSF sink under UDM profile");
            }
        }

        // Cleanup staging after successful promotion
        self.cleanup_staging().await?;

        // The dynamic router is now inside staging parsers dir (_router.toml)
        // and gets copied with the other parser files above, no separate step needed.
        //
        // Legacy cleanup: remove old 20-dynamic-router.toml from config_dir if
        // present. NAN-2301: moved AFTER every fallible step. It deletes a file
        // outside `parsers_dir`, which is the only tree the backup covers — so
        // deleting it before something else could fail meant a rollback could
        // not put it back. Now nothing after it can fail, and it stays
        // best-effort.
        let legacy_router = self.config_dir.join("20-dynamic-router.toml");
        if legacy_router.exists() {
            fs::remove_file(&legacy_router).await.ok();
            tracing::info!(
                "Removed legacy router config from {}",
                legacy_router.display()
            );
        }

        tracing::info!("Promoted staged config to {}", self.parsers_dir.display());
        Ok(())
    }

    /// Get the staging directory path
    pub fn staging_dir(&self) -> &Path {
        &self.staging_dir
    }

    /// Where unowned TOMLs are moved instead of being deleted. Lives beside
    /// `backup/` under the config root and NOT inside `parsers_dir`, so it is
    /// outside every `--config-dir` Vector loads and outside the tree
    /// `backup_current` snapshots — a quarantined file must stop affecting the
    /// running config without bloating every subsequent rollback target.
    pub(super) fn quarantine_dir(&self) -> PathBuf {
        self.config_dir.join("quarantine")
    }

    /// Move files this subsystem does not own out of the active parsers
    /// directory (NAN-2305). Loud, because a quarantine means the deployed graph
    /// just lost a component the operator put there by hand.
    async fn quarantine_unowned(
        &self,
        strays: Vec<(PathBuf, String)>,
    ) -> Result<(), VectorConfigError> {
        if strays.is_empty() {
            return Ok(());
        }

        // One directory per promotion, so successive deploys cannot overwrite
        // each other's quarantined copies.
        let batch = self
            .quarantine_dir()
            .join(chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ").to_string());
        fs::create_dir_all(&batch).await?;

        for (path, file_name) in strays {
            // Suffixed so the copy is no longer a `.toml`. The S3 config sync
            // (`deploy/src/s3.js::syncDirectory`) walks the whole config root
            // and uploads every `.toml` it finds, skipping only `backup` and
            // `staging` by name — a quarantined parser keeping its extension
            // would be replicated to every Vector pod's config bundle, which is
            // the opposite of quarantining it.
            let dest = batch.join(format!("{}{}", file_name, QUARANTINE_SUFFIX));
            // `rename` is atomic but only within a filesystem, and in K8s the
            // config root and the dynamic parsers dir can be different volumes.
            // Fall back to copy-then-remove so a cross-device move degrades
            // instead of failing the whole promotion.
            if fs::rename(&path, &dest).await.is_err() {
                fs::copy(&path, &dest).await?;
                fs::remove_file(&path).await?;
            }
            tracing::warn!(
                "Quarantined '{}' to {} — it is not in the promoted set and this subsystem did \
                 not generate it. Promotion mirrors the staged tree, so leaving it would risk a \
                 dangling input taking the whole Vector config down; it was moved rather than \
                 deleted because nothing here can regenerate it.",
                file_name,
                batch.display()
            );
        }

        Ok(())
    }

    /// File names in the active parsers directory that this subsystem
    /// generated. Union of the recorded manifest and [`ALWAYS_GENERATED`]; an
    /// absent or unreadable manifest degrades to the fixed-name set, which
    /// quarantines rather than deletes — the safe direction.
    async fn read_ownership_manifest(&self) -> Result<HashSet<String>, VectorConfigError> {
        let mut owned: HashSet<String> =
            ALWAYS_GENERATED.iter().map(|n| (*n).to_string()).collect();

        let path = self.parsers_dir.join(OWNERSHIP_MANIFEST);
        match fs::read_to_string(&path).await {
            Ok(body) => {
                for line in body.lines() {
                    let name = line.trim();
                    if name.is_empty() || name.starts_with('#') {
                        continue;
                    }
                    owned.insert(name.to_string());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                tracing::info!(
                    "No {} in {} — treating every unpromoted TOML as tenant-managed for this \
                     promotion. Files we generated before the manifest existed are quarantined \
                     once rather than deleted; from here on ownership is recorded.",
                    OWNERSHIP_MANIFEST,
                    self.parsers_dir.display()
                );
            }
            Err(e) => return Err(e.into()),
        }

        Ok(owned)
    }

    /// Record the file names this promotion generated, so the next one knows
    /// which orphans are its own to delete.
    async fn write_ownership_manifest(
        &self,
        promoted: &HashSet<String>,
    ) -> Result<(), VectorConfigError> {
        // One name per line, so a name carrying a line break would forge an
        // extra ownership entry. `safe_name` cannot produce one, and this
        // directory has no other writer — but the failure mode of a forged
        // entry is "delete a file we do not own", so it is excluded rather
        // than reasoned about. An excluded name is simply not owned, which
        // quarantines instead of deletes: the safe direction.
        let mut names: Vec<&str> = promoted
            .iter()
            .map(String::as_str)
            .filter(|n| n.ends_with(".toml") && !n.contains(['\n', '\r']))
            .collect();
        names.sort_unstable();

        let mut body = String::from(
            "# Generated by nano — DO NOT EDIT.\n\
             # Files listed here were written by the parser deploy subsystem and may be\n\
             # deleted by a later promotion. Any .toml in this directory that is NOT listed\n\
             # is treated as tenant-managed: it is quarantined under <config>/quarantine/\n\
             # instead of being deleted (NAN-2305).\n",
        );
        for name in names {
            body.push_str(name);
            body.push('\n');
        }

        fs::write(self.parsers_dir.join(OWNERSHIP_MANIFEST), body).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
