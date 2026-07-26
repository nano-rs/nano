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
/// - `otlp_logs_prep_covered`: an `otlp` routing config is deployed (NAN-1572).
///   `otlp_logs_prep` (config/vector/03-otlp-source.toml) normally feeds
///   `source_router` directly as a base input, but when a meaningful OTLP
///   routing transform is on disk it intermediates that channel — suppress
///   the direct input so OTLP logs don't reach `source_router` twice (the
///   NAN-1442 Saturn 2× double-write class).
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
    otlp_logs_prep_covered: bool,
) -> Vec<&'static str> {
    let mut inputs = Vec::with_capacity(4);
    if !source_type_extract_covered {
        inputs.push("source_type_extract");
    }
    inputs.push("vector_merge");
    if hec_normalize_present && !hec_normalize_covered {
        inputs.push("hec_normalize");
    }
    // NAN-1528: OTLP LogRecords ride the existing UDM/OCSF logs lane. The OTLP
    // source's `otlp_logs_prep` transform (config/vector/03-otlp-source.toml)
    // tags `source_type="otlp_log"` and feeds straight into `source_router`,
    // where a deployed parser's `match_values` claims them like any other
    // source_type. Gated on presence (same dangling-input class as
    // `hec_normalize_present`, NAN-867) so deployments without the OTLP source
    // file don't reference a non-existent component and crashloop Vector 0.55.
    // NAN-1572: also suppressed when an `otlp` source-config route intermediates
    // the channel (otlp_logs_prep_covered) so the stream isn't double-written.
    if otlp_source_present() && !otlp_logs_prep_covered {
        inputs.push("otlp_logs_prep");
    }
    inputs
}

/// Whether the deployment's base Vector config defines the OTLP source's
/// `[transforms.otlp_logs_prep]` (i.e. `config/vector/03-otlp-source.toml` is
/// shipped). NAN-1528.
///
/// Reads `NANOSIEM_VECTOR_OTLP_PRESENT`. Defaults to `true` for OOTB open-core
/// deployments (which ship `03-otlp-source.toml`). Deploys that don't mount the
/// OTLP source set this to `"false"` so the router never wires a dangling
/// `otlp_logs_prep` input.
pub fn otlp_source_present() -> bool {
    std::env::var("NANOSIEM_VECTOR_OTLP_PRESENT")
        .map(|v| {
            !matches!(
                v.to_ascii_lowercase().as_str(),
                "false" | "0" | "no" | "off"
            )
        })
        .unwrap_or(true)
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
        .map(|v| {
            !matches!(
                v.to_ascii_lowercase().as_str(),
                "false" | "0" | "no" | "off"
            )
        })
        .unwrap_or(true)
}

/// Built-in source types that get placeholder routes when no parser is deployed.
///
/// NAN-1083: emptied. The SIEM ships with zero opinionated pre-seeded routes —
/// users install parsers (hand-rolled or pulled from the managed parser repo)
/// and `match_values` on each parser drives all routing. Existing call sites
/// iterate over this slice and degrade to no-ops; the "no placeholders" branch
/// in `write_router_config` already handles the zero-case by emitting a no-op
/// filter for `placeholder_combiner` (which `_pipeline.toml`'s `normalize`
/// still requires as a named input).
pub(super) const BUILTIN_TYPES: [&str; 0] = [];

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

/// NAN-1442: parse the `inputs = [...]` of a source-config route transform,
/// returning the normalized upstream-list string (e.g. `["source_type_extract"]`).
/// Used to detect routes that read the SAME upstream so only one is wired into
/// `source_router`. Returns `None` when the block has no parseable `inputs`.
pub(super) fn route_transform_upstream(content: &str, route_name: &str) -> Option<String> {
    let header = format!("[transforms.{}]", route_name);
    let mut in_block = false;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if !in_block {
            if trimmed.contains(&header) {
                in_block = true;
            }
            continue;
        }
        // Next section header ends the block before any inputs line.
        if trimmed.starts_with('[') {
            break;
        }
        if let Some(rest) = trimmed.strip_prefix("inputs") {
            if let Some(rhs) = rest.trim_start().strip_prefix('=') {
                // Strip ALL whitespace so `["a"]`, `[ "a" ]`, and `["a", "b"]`
                // vs `["a","b"]` produce the same dedupe key (component ids
                // never contain spaces).
                return Some(rhs.split_whitespace().collect::<Vec<_>>().join(""));
            }
        }
    }
    None
}

/// NAN-1442: keep at most one source-config route per distinct upstream.
/// Two routes reading the same upstream (e.g. `http`/`vector` configs both
/// reading `source_type_extract`) would each feed `source_router`, duplicating
/// the entire stream into ClickHouse (the Saturn 2× bug). Deterministic: the
/// alphabetically-first route name wins per upstream. Routes whose upstream
/// could not be parsed are kept (fail-open — never silently drop a route we
/// don't understand). Distinct upstreams (pub/sub, HEC, owned fetch sources)
/// are all preserved, so no ingest method is dropped.
pub(super) fn dedupe_routes_by_upstream(mut routes: Vec<(String, Option<String>)>) -> Vec<String> {
    routes.sort_by(|a, b| a.0.cmp(&b.0));
    let mut seen_upstreams: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut out = Vec::new();
    for (name, upstream) in routes {
        match upstream {
            Some(up) => {
                if seen_upstreams.insert(up) {
                    out.push(name);
                }
            }
            None => out.push(name),
        }
    }
    out
}

/// NAN-930: which route does this parser pull events from? The router needs
/// this so that source-config routes claimed by a fetch-source parser (Kafka
/// / S3 / GCP) or by an HEC parser don't ALSO flow into `source_router` —
/// otherwise every event lands in ClickHouse twice (once parsed via the
/// parser pipeline, once raw via `source_router.generic`).
///
/// Returns `None` for parsers that don't claim a source-config route
/// (routed, vector, or non-dispatch fetch parsers that emit their own
/// owned Vector source — those don't share an input with source_router).
pub(super) fn parser_claimed_route(parser: &Parser) -> Option<&str> {
    match parser.source_type.as_str() {
        // HEC parsers always read from the OOTB/source-config splunk_hec_route.
        "splunk_hec" | "splunk" | "hec" => Some("splunk_hec_route"),
        // NAN-1528: OTLP log parsers fan out from the OOTB `otlp_logs_prep`
        // output (config/vector/03-otlp-source.toml). Since `otlp_logs_prep`
        // also feeds `source_router` directly as a base input
        // (base_router_inputs), claiming it here triggers the same
        // `<route>_unclaimed` substitution as HEC so an otlp_log event reaching
        // a parser filter does NOT also fall through to `source_router.generic`
        // and double-write (the NAN-930 class).
        "opentelemetry" | "otlp" => Some("otlp_logs_prep"),
        // Kafka/S3/GCP parsers only claim a route when bound to a source-config
        // via the DISPATCH FROM picker (NAN-928); otherwise they spin their own
        // owned source and don't intersect with source_router.
        "kafka" | "aws_s3" | "aws_sqs" | "gcp_pubsub" => parser.dispatch_route_name.as_deref(),
        _ => None,
    }
}

/// NAN-930: build the `<route>_unclaimed` filter condition — an event passes
/// only when its `.source_type` is NOT in any claiming parser's match_values.
/// Mirrors `build_hec_filter_condition` (sources.rs) but with the leading `!`
/// so we capture the leftover stream that no parser wants.
fn build_unclaimed_filter_condition(claimants: &[&Parser]) -> String {
    let mut values: Vec<String> = Vec::new();
    for parser in claimants {
        if let Some(match_values) = &parser.match_values {
            if !match_values.is_empty() {
                values.extend(match_values.iter().cloned());
                continue;
            }
        }
        // No match_values configured → claim falls back to the parser name
        // (same fallback `build_hec_filter_condition` uses).
        values.push(parser.name.clone());
    }
    values.sort();
    values.dedup();
    let list = values
        .iter()
        .map(|v| format!("\"{}\"", escape_vrl_string_for_router(v)))
        .collect::<Vec<_>>()
        .join(", ");
    format!("!includes([{}], to_string(.source_type) ?? \"\")", list)
}

/// Minimal VRL string escape — backslashes, quotes, and control characters.
/// Duplicated from `sources::escape_vrl_string` (private) to keep the router
/// module standalone; sub-50-char helper, not worth lifting yet.
fn escape_vrl_string_for_router(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            c if (c as u32) < 0x20 || (c as u32) == 0x7f => {
                out.push_str(&format!("\\u{:04x}", c as u32))
            }
            _ => out.push(ch),
        }
    }
    out
}

/// NAN-930: shared between `router.rs::write_router_config` (active path)
/// and `staging.rs::stage_parsers` (validation path). Both writers emit
/// `_router.toml` and both need the same dedupe-substitution to prevent
/// double-writes — without this shared helper the staging writer's output
/// (which gets promoted on top of the active file via `promote_staged`)
/// would clobber the active writer's substitution and the
/// double-write-to-ClickHouse bug would return.
///
/// Inputs:
///   - `base_inputs`: `base_router_inputs(...)` result (unchanged on disk).
///   - `source_config_routes`: routes from `get_source_config_routes`.
///   - `parsers`: full parser slice (used to detect HEC + dispatched
///     fetch-source claims).
///
/// Returns:
///   - The substituted Vec<String> of `source_router.inputs`.
///   - The TOML block for the `<route>_unclaimed` filter transforms
///     (empty when no claims, otherwise the full set of blocks ready to
///     `push_str` into the file before `[transforms.source_router]`).
pub(super) fn build_router_inputs_with_claim_dedupe(
    base_inputs: Vec<String>,
    source_config_routes: &[String],
    parsers: &[Parser],
) -> (Vec<String>, String) {
    use std::collections::HashMap;
    let mut claims: HashMap<&str, Vec<&Parser>> = HashMap::new();
    for parser in parsers.iter().filter(|p| p.enabled) {
        if let Some(route) = parser_claimed_route(parser) {
            claims.entry(route).or_default().push(parser);
        }
    }

    let substitutions: HashMap<String, String> = claims
        .keys()
        .map(|route| (route.to_string(), format!("{}_unclaimed", route)))
        .collect();

    let final_inputs: Vec<String> = base_inputs
        .iter()
        .chain(source_config_routes.iter())
        .map(|name| {
            substitutions
                .get(name)
                .cloned()
                .unwrap_or_else(|| name.clone())
        })
        .collect();

    let mut claimed_sorted: Vec<(&str, &Vec<&Parser>)> =
        claims.iter().map(|(k, v)| (*k, v)).collect();
    claimed_sorted.sort_by_key(|(k, _)| *k);

    let mut filter_blocks = String::new();
    if !claimed_sorted.is_empty() {
        filter_blocks.push_str(
            "# =============================================================================\n\
             # NAN-930: Unclaimed-event filters for parser-bound source-config routes\n\
             # =============================================================================\n\
             # Each `<route>_unclaimed` filter passes only events that NO parser-filter\n\
             # claimed (i.e., `.source_type` not in any claiming parser's match_values).\n\
             # Prevents events from being double-written: once via the parser pipeline\n\
             # and once via `source_router.generic`.\n\n",
        );
        for (route, claimants) in &claimed_sorted {
            let condition = build_unclaimed_filter_condition(claimants);
            filter_blocks.push_str(&format!(
                "[transforms.{}_unclaimed]\n\
                 type = \"filter\"\n\
                 inputs = [\"{}\"]\n\
                 condition = '{}'\n\n",
                route, route, condition,
            ));
        }
    }

    (final_inputs, filter_blocks)
}

/// Sanitize an `enrich_source` into a Vector component-id-safe route name.
/// The route key (`enrichment_router.<name>`) and the generated normalize
/// transform suffix (`enrichment_normalize_<name>`) MUST agree, so both
/// `enrichment_router_block` here and `generate_enrichment_lane` in deploy.rs
/// route through this one function. Real sources (`ad`, `entra`, `okta`,
/// `google`, `workday`) pass through unchanged.
pub(super) fn enrichment_route_name(source: &str) -> String {
    source
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

/// Emit the `[transforms.enrichment_router]` block (NAN-1124 / NAN-1151).
///
/// Routes `nano_enrich` records to per-`source` outputs
/// (`enrichment_router.<source>`) — one route per deployed enrichment parser's
/// `enrich_source` — which the generated lane's
/// `enrichment_normalize_<source>` transforms consume. When NO enrichment
/// parsers are deployed, `write_enrichment_config` falls back to the committed
/// static `_enrichment.toml` (which consumes the legacy per-`kind` outputs), so
/// we emit those per-kind routes in that case to keep its inputs from dangling
/// (NAN-867). Shared by the active writer (`router.rs`) and the staging writer
/// (`staging.rs`) so the two can never byte-drift.
pub(super) fn enrichment_router_block(
    enrichment_parsers: &[&Parser],
    inputs_formatted: &str,
) -> String {
    let mut out = format!(
        "# =============================================================================\n\
         # NAN-1124/NAN-1151: Enrichment lane router (nano_enrich -> per-source outputs)\n\
         # =============================================================================\n\
         [transforms.enrichment_router]\n\
         type = \"route\"\n\
         inputs = [{inputs_formatted}]\n\n\
         [transforms.enrichment_router.route]\n"
    );

    // Deployed enrichment parsers' sources, deduped + stable-ordered.
    let mut sources: Vec<&str> = enrichment_parsers
        .iter()
        .filter_map(|p| p.enrich_source.as_deref())
        .filter(|s| !s.is_empty())
        .collect();
    sources.sort_unstable();
    sources.dedup();

    if sources.is_empty() {
        // Static-fallback lane consumes the legacy per-kind outputs.
        for kind in ["identity", "ip_context", "ioc", "asset"] {
            out.push_str(&format!(
                "{kind} = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.kind) ?? \"\") == \"{kind}\"'\n"
            ));
        }
    } else {
        for source in sources {
            let route = enrichment_route_name(source);
            // Match the raw `.source` value; the route KEY is the sanitized name
            // so the lane's `enrichment_router.<route>` input resolves.
            out.push_str(&format!(
                "{route} = 'downcase(to_string(.source_type) ?? \"\") == \"nano_enrich\" && downcase(to_string(.source) ?? \"\") == \"{source}\"'\n"
            ));
        }
    }
    out.push('\n');
    out
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
        // (route_name, upstream-inputs) so we can dedupe by upstream below.
        let mut routes: Vec<(String, Option<String>)> = Vec::new();

        if !configs_dir.exists() {
            return Vec::new();
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
                                let upstream = route_transform_upstream(&content, &route_name);
                                routes.push((route_name, upstream));
                            }
                        }
                    }
                }
            }
        }

        // NAN-1442: collapse routes that read the same upstream so the shared
        // channel (e.g. source_type_extract) reaches source_router once. The
        // parser-deploy writer rebuilds _router.toml too, so without this the
        // next parser deploy would re-introduce the double-write.
        dedupe_routes_by_upstream(routes)
    }

    /// Detect which always-on intermediary channels are covered by a
    /// deployed source-config routing transform. Returns
    /// `(source_type_extract_covered, hec_normalize_covered)`.
    ///
    /// When a channel is covered, the per-config route consumes it and feeds
    /// `source_router`, so the base router inputs must NOT also include the
    /// channel directly — otherwise events arrive at `source_router` twice.
    pub(super) async fn source_config_intermediary_coverage(&self) -> (bool, bool, bool) {
        let configs_dir = self.source_configs_dir();
        let mut source_type_extract = false;
        let mut hec_normalize = false;
        let mut otlp_logs_prep = false;
        if !configs_dir.exists() {
            return (source_type_extract, hec_normalize, otlp_logs_prep);
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
                            // NAN-1572: an otlp routing config intermediates the
                            // otlp_logs_prep channel.
                            if line.contains("inputs = [\"otlp_logs_prep\"]") {
                                otlp_logs_prep = true;
                            }
                        }
                        if source_type_extract && hec_normalize && otlp_logs_prep {
                            return (true, true, true);
                        }
                    }
                }
            }
        }

        (source_type_extract, hec_normalize, otlp_logs_prep)
    }

    /// Write the dynamic router config based on deployed parsers
    ///
    /// This generates a router that includes routes for all deployed routed parsers.
    /// Unknown source types fall through to the generic parser.
    pub(super) async fn write_router_config(
        &self,
        parsers: &[Parser],
        enrichment_parsers: &[Parser],
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

        let (source_type_extract_covered, hec_normalize_covered, otlp_logs_prep_covered) =
            self.source_config_intermediary_coverage().await;
        let mut router_inputs: Vec<String> = base_router_inputs(
            source_type_extract_covered,
            hec_normalize_covered,
            hec_normalize_present(),
            otlp_logs_prep_covered,
        )
        .into_iter()
        .map(String::from)
        .collect();
        let source_config_routes = self.get_source_config_routes().await;

        // NAN-930: any source-config route that's also claimed by a parser
        // (HEC → splunk_hec_route, or kafka/s3/gcp bound via DISPATCH FROM →
        // <safe_name>_route) must NOT flow into `source_router` directly —
        // the parser-filter is already consuming it. Without this hop every
        // event landed in ClickHouse twice: once parsed via the parser
        // pipeline and once raw via `source_router.generic`. The shared
        // helper produces both the substituted inputs list and the
        // `<route>_unclaimed` filter blocks; staging.rs uses the same helper
        // so the staging-then-promote path can't clobber the substitution.
        let (router_inputs_substituted, unclaimed_filter_blocks) =
            build_router_inputs_with_claim_dedupe(router_inputs, &source_config_routes, parsers);
        router_inputs = router_inputs_substituted;
        let inputs_formatted = router_inputs
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");

        // NAN-930: emit the `<route>_unclaimed` filter transforms BEFORE
        // source_router (cosmetic — Vector resolves inputs across the
        // whole file regardless of order). Shared helper builds the blocks
        // so this writer and `staging.rs::stage_parsers` stay in lockstep.
        config.push_str(&unclaimed_filter_blocks);

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
        // NAN-1124: also exclude `nano_enrich` so push-enrichment records never
        // fall through to the generic log parser (they're claimed by
        // enrichment_router below). Matches the downcased source_type so a
        // mixed-case body value can't leak into the logs pipeline.
        config.push_str(&format!(
            "generic = '!includes([{}], .source_type) && !starts_with(downcase(to_string(.source_type) ?? \"\"), \"nano_enrich\")'\n\n",
            exclusion_list
        ));

        // NAN-1124: enrichment lane router — a sibling to source_router with the
        // IDENTICAL inputs, routing `nano_enrich` records by `.kind` to outputs
        // consumed by config/vector/03-enrichment-lane.toml. Non-enrichment
        // events fall to `enrichment_router._unmatched` (unconsumed → dropped);
        // `nano_enrich` is excluded from `source_router.generic` above, so
        // enrichment records never reach the logs pipeline and log events never
        // reach the enrichment sinks. Emitted UNCONDITIONALLY (every kind route
        // present) so the static lane file's `enrichment_router.<kind>` inputs
        // can never dangle on startup (NAN-867 dangling-input class).
        // NAN-1151: per-source enrichment routes from deployed enrichment
        // parsers (shared helper keeps router.rs + staging.rs in lockstep).
        let enabled_enrichment: Vec<&Parser> =
            enrichment_parsers.iter().filter(|p| p.enabled).collect();
        config.push_str(&enrichment_router_block(
            &enabled_enrichment,
            &inputs_formatted,
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
            // No placeholders — emit a no-op filter so `_pipeline.toml`'s
            // `normalize` still has a valid named input. Input must be an
            // upstream node; `source_router.generic` qualifies (it's already
            // routed by this transform's own `route` block earlier in the
            // file). NAN-1083: the prior `inputs = ["prepare_output"]` formed
            // a cycle (prepare_output → ... → normalize → placeholder_combiner
            // → prepare_output) and was never exercised because BUILTIN_TYPES
            // was non-empty.
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

    /// NAN-1442: parse the upstream `inputs` of a route block.
    #[test]
    fn route_transform_upstream_parses_inputs_line() {
        let content = r##"
[transforms.http_ingestion_route]
inputs = ["source_type_extract"]
type = "remap"
source = "# passthrough"
"##;
        assert_eq!(
            route_transform_upstream(content, "http_ingestion_route").as_deref(),
            Some("[\"source_type_extract\"]")
        );
        // Different layout / spacing normalizes to the same key.
        let spaced = "[transforms.vector_ingestion_route]\ntype = \"remap\"\ninputs = [ \"source_type_extract\" ]\n";
        assert_eq!(
            route_transform_upstream(spaced, "vector_ingestion_route").as_deref(),
            Some("[\"source_type_extract\"]")
        );
        // No inputs in block → None.
        assert_eq!(
            route_transform_upstream("[transforms.x_route]\ntype=\"remap\"\n", "x_route"),
            None
        );
    }

    /// NAN-1442 (Saturn 2× ingestion): http + vector routes both read
    /// `source_type_extract`; only one may feed `source_router`. Distinct
    /// upstreams (pub/sub) are preserved.
    #[test]
    fn dedupe_routes_by_upstream_collapses_shared_channel_keeps_distinct() {
        let routes = vec![
            (
                "vector_ingestion_route".to_string(),
                Some("[\"source_type_extract\"]".to_string()),
            ),
            (
                "http_ingestion_route".to_string(),
                Some("[\"source_type_extract\"]".to_string()),
            ),
            (
                "gcp_pub_sub_route".to_string(),
                Some("[\"gcp_pub_sub_source\"]".to_string()),
            ),
        ];
        // Alphabetically-first per upstream wins: http_ingestion_route (not
        // vector_ingestion_route) carries source_type_extract; pub/sub kept.
        assert_eq!(
            dedupe_routes_by_upstream(routes),
            vec!["gcp_pub_sub_route", "http_ingestion_route"]
        );
    }

    /// NAN-1442 fail-open: routes whose upstream couldn't be parsed are kept
    /// (we never silently drop a route we don't understand).
    #[test]
    fn dedupe_routes_by_upstream_keeps_unparseable() {
        let routes = vec![
            ("a_route".to_string(), None),
            ("b_route".to_string(), None),
            ("c_route".to_string(), Some("[\"x\"]".to_string())),
        ];
        assert_eq!(
            dedupe_routes_by_upstream(routes),
            vec!["a_route", "b_route", "c_route"]
        );
    }

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
                        base_router_inputs(src_covered, hec_covered, hec_present, false)
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
        assert!(base_router_inputs(false, false, true, false).contains(&"hec_normalize"));
        assert!(base_router_inputs(true, false, true, false).contains(&"hec_normalize"));
    }

    /// NAN-857: when a splunk_hec route is deployed, `hec_normalize` must NOT
    /// be in base inputs — the route already intermediates it. Otherwise
    /// every HEC event reaches source_router twice (once direct, once via
    /// the route) and lands in CH duplicated.
    #[test]
    fn base_router_inputs_excludes_hec_normalize_when_covered() {
        for hec_present in [true, false] {
            assert!(!base_router_inputs(false, true, hec_present, false).contains(&"hec_normalize"));
            assert!(!base_router_inputs(true, true, hec_present, false).contains(&"hec_normalize"));
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
                    !base_router_inputs(src_covered, hec_covered, false, false).contains(&"hec_normalize"),
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
            assert!(!base_router_inputs(true, false, hec_present, false)
                .contains(&"source_type_extract"));
            assert!(!base_router_inputs(true, true, hec_present, false)
                .contains(&"source_type_extract"));
        }
    }

    #[test]
    fn base_router_inputs_includes_source_type_extract_when_uncovered() {
        for hec_present in [true, false] {
            assert!(base_router_inputs(false, false, hec_present, false)
                .contains(&"source_type_extract"));
            assert!(base_router_inputs(false, true, hec_present, false)
                .contains(&"source_type_extract"));
        }
    }

    /// NAN-1572: OTLP OOTB invariant — when the OTLP source is present and no
    /// otlp route is deployed, `otlp_logs_prep` feeds `source_router` directly
    /// so OTLP logs reach the router. (Gated on `otlp_source_present()`, which
    /// defaults true; this test runs in the default OOTB env.)
    #[test]
    fn base_router_inputs_includes_otlp_logs_prep_when_uncovered() {
        // serial guard not needed: otlp_source_present() reads env, default true.
        if !otlp_source_present() {
            return;
        }
        for hec_present in [true, false] {
            assert!(
                base_router_inputs(false, false, hec_present, false).contains(&"otlp_logs_prep")
            );
            assert!(base_router_inputs(true, true, hec_present, false).contains(&"otlp_logs_prep"));
        }
    }

    /// NAN-1572: when an otlp route is deployed (`otlp_logs_prep_covered`), the
    /// direct `otlp_logs_prep` base input must be suppressed — otherwise OTLP
    /// logs reach `source_router` twice (direct + via the route), the NAN-1442
    /// Saturn 2× double-write class.
    #[test]
    fn base_router_inputs_excludes_otlp_logs_prep_when_covered() {
        for src_covered in [true, false] {
            for hec_covered in [true, false] {
                for hec_present in [true, false] {
                    assert!(
                        !base_router_inputs(src_covered, hec_covered, hec_present, true)
                            .contains(&"otlp_logs_prep"),
                        "otlp_logs_prep emitted when covered ({src_covered}, {hec_covered}, {hec_present})"
                    );
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // NAN-930: parser_claimed_route + build_unclaimed_filter_condition
    // ------------------------------------------------------------------

    use chrono::Utc;
    use uuid::Uuid;

    fn parser_for_claim_tests(source_type: &str, dispatch: Option<&str>) -> Parser {
        Parser {
            id: Uuid::new_v4(),
            name: "Apache HTTP Server".to_string(),
            description: None,
            source_type: source_type.to_string(),
            parser_vrl: String::new(),
            output_fields: None,
            feed_id: None,
            dispatch_source_config_id: dispatch.map(|_| Uuid::new_v4()),
            dispatch_route_name: dispatch.map(|s| s.to_string()),
            enabled: true,
            validated: true,
            validation_error: None,
            category: None,
            vendor: None,
            product: None,
            kind: "log".to_string(),
            enrich_kind: None,
            enrich_source: None,
            target_table: None,
            normalize_vrl: None,
            namespace: "default".to_string(),
            timezone: "UTC".to_string(),
            match_values: Some(vec!["apache_access".to_string(), "apache".to_string()]),
            sampling_ratio: None,
            sampling_exclude_condition: None,
            extension_vrl: None,
            extension_enabled: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// HEC parsers always claim `splunk_hec_route` — singleton-owned by the OOTB HEC source.
    #[test]
    fn parser_claimed_route_returns_splunk_hec_for_hec_parsers() {
        for source_type in ["splunk_hec", "splunk", "hec"] {
            let p = parser_for_claim_tests(source_type, None);
            assert_eq!(parser_claimed_route(&p), Some("splunk_hec_route"));
        }
    }

    /// Fetch-source parser bound via DISPATCH FROM claims that route.
    #[test]
    fn parser_claimed_route_returns_dispatch_route_for_bound_fetch_parser() {
        for source_type in ["kafka", "aws_s3", "aws_sqs", "gcp_pubsub"] {
            let p = parser_for_claim_tests(source_type, Some("nan884_smoke_route"));
            assert_eq!(parser_claimed_route(&p), Some("nan884_smoke_route"));
        }
    }

    /// Fetch-source parser with no dispatch (legacy parser-owned source)
    /// doesn't claim a shared route — its source is private to the parser.
    #[test]
    fn parser_claimed_route_returns_none_for_unbound_fetch_parser() {
        let p = parser_for_claim_tests("kafka", None);
        assert!(parser_claimed_route(&p).is_none());
    }

    /// Routed and vector parsers don't share a route with source_router —
    /// they consume `source_router.<name>` outputs.
    #[test]
    fn parser_claimed_route_returns_none_for_routed_and_vector() {
        for source_type in ["routed", "vector"] {
            let p = parser_for_claim_tests(source_type, None);
            assert!(parser_claimed_route(&p).is_none());
        }
    }

    /// Condition is `!includes([...])` with sorted+deduped match_values.
    #[test]
    fn build_unclaimed_filter_condition_negates_union_of_match_values() {
        let p1 = parser_for_claim_tests("kafka", Some("r"));
        let p2 = Parser {
            match_values: Some(vec!["nginx".to_string(), "apache".to_string()]),
            ..parser_for_claim_tests("kafka", Some("r"))
        };
        let cond = build_unclaimed_filter_condition(&[&p1, &p2]);
        assert_eq!(
            cond,
            r#"!includes(["apache", "apache_access", "nginx"], to_string(.source_type) ?? "")"#,
        );
    }

    /// Empty match_values falls back to the parser name (same fallback
    /// `sources.rs::build_hec_filter_condition` uses).
    #[test]
    fn build_unclaimed_filter_condition_falls_back_to_parser_name() {
        let mut p = parser_for_claim_tests("kafka", Some("r"));
        p.match_values = None;
        p.name = "lone_parser".to_string();
        let cond = build_unclaimed_filter_condition(&[&p]);
        assert!(cond.contains(r#"["lone_parser"]"#), "got: {cond}");
    }
}
