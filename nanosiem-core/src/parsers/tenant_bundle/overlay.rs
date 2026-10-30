// SPDX-License-Identifier: AGPL-3.0-or-later

//! Tenant overlay: generate it on a platform base, and strip/verify it.
//!
//! A tenant bundle is the release-pinned platform base plus a tenant overlay.
//! The overlay is exactly:
//!
//! * one parser file per tenant source, `sources/parsers/tenant__<slug>.toml`,
//!   produced by the open-core generator (`generate_parser_config_with`);
//! * items added to six platform wiring points — the HEC delivery tokens and
//!   the HEC normalizer's allowlist (`02-hec-source.toml`), one route line plus
//!   the `generic` exclusion list (`_router.toml`), the combiner and parser
//!   health inputs (`_combiner.toml`), and the lake storage-prepare inputs
//!   (`_ocsf_sink.toml`).
//!
//! Everything else is platform and must be byte-identical to the base.
//! [`verify_against_base`] proves that independently of the generator: it
//! removes exactly the overlay items it can attribute to a tenant slug and
//! then requires the remainder to equal the base, byte for byte, file for
//! file. A bundle that edits any platform byte — a sink, `_pipeline`, the lake
//! sink's VRL, the output guard, another parser — is refused.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use chrono::{TimeZone, Utc};
use regex::Regex;
use sha2::{Digest, Sha256};

use super::archive::BundleTree;
use super::model::{GuardFinding, TenantSource, SOURCE_SLUG_RE};
use super::scan;
use super::TenantBundleError;
use crate::parsers::types::Parser;
use crate::parsers::{ParserConfigOptions, VectorConfigManager};

pub const HEC_FILE: &str = "02-hec-source.toml";
pub const ROUTER_FILE: &str = "sources/parsers/_router.toml";
pub const COMBINER_FILE: &str = "sources/parsers/_combiner.toml";
pub const LAKE_SINK_FILE: &str = "sources/parsers/_ocsf_sink.toml";
pub const OUTPUT_GUARD_FILE: &str = "07-output-guards.toml";
pub const TENANT_PARSER_DIR: &str = "sources/parsers/";
/// Reserved prefix for every tenant identifier. The platform never uses it;
/// a base that does is refused, so a tenant name can never shadow a platform
/// component.
pub const TENANT_PREFIX: &str = "tenant__";
/// Transport-only enrollments: no parser, route or sink is introduced.
pub const UNPARSED_SOURCES_FILE: &str = "tenant__unparsed.manifest";

pub fn unparsed_sources(tree: &BundleTree) -> Result<Vec<String>, String> {
    let Some(bytes) = tree.file(UNPARSED_SOURCES_FILE) else { return Ok(Vec::new()) };
    if bytes.len() > 32 * 1024 { return Err("unparsed source manifest exceeds its bound".into()) }
    let slugs: Vec<String> = serde_json::from_slice(bytes).map_err(|_| "invalid unparsed source manifest")?;
    if slugs.is_empty() || slugs.len() > super::model::MAX_SOURCES
        || slugs.iter().any(|s| !SOURCE_SLUG_RE.is_match(s) || ["unknown", "default", "audit", "otlp_log", "otlp_metric", "otlp_trace"].contains(&s.as_str()))
        || slugs.windows(2).any(|pair| pair[0] >= pair[1])
        || serde_json::to_vec(&slugs).map_err(|e| e.to_string())? != bytes
    {
        return Err("unparsed sources must be canonical, sorted, unique tenant slugs".into());
    }
    Ok(slugs)
}


const HEC_TOKEN_PREFIX: &str = "${VECTOR_AUTH_TOKEN}:nano-source-v1:";
/// Fixed `# Generated at:` value: the artifact is content-addressed, so it
/// must not depend on the clock.
// mirror-gate: wire (bundle bytes are content-addressed)
const GENERATED_AT: &str = "content-addressed tenant parser bundle (NAN-2604)";
/// Transform types a tenant parser file may declare.
const TENANT_TRANSFORM_TYPES: [&str; 7] = [
    "remap",
    "route",
    "sample",
    "dedupe",
    "reduce",
    "exclusive_route",
    "lua",
];
/// Remaps that run tenant VRL and must reroute runtime errors.
const TENANT_VRL_SUFFIXES: [&str; 2] = ["_parse", "_extension"];
/// NAN-3369 (R5): component keys a tenant transform may never carry. `file`
/// / `files` make `remap` load VRL from a path inside the container (the
/// bundle, `/etc/cloudflare/certs/*`, ...), which the source scans never see
/// and which could read local files into events. The generator only emits
/// inline `source`.
pub const TENANT_FORBIDDEN_TRANSFORM_KEYS: [&str; 2] = ["file", "files"];
const TENANT_COMPONENT_SUFFIXES: [&str; 7] = [
    "_parse",
    "_extension",
    "_ocsf_split",
    "_ocsf_prepare",
    "_output",
    "_sample",
    "_ocsf_sample",
];

static TENANT_ROUTE_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"^(tenant__[a-z0-9_]+) = '\.source_type == "([a-z0-9][a-z0-9_-]{0,99})"'$"#)
        .expect("static regex")
});
static QUOTED_ITEM_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r#""([^"\\]*)""#).expect("static regex"));

/// The identifiers one tenant slug owns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantName {
    pub slug: String,
    /// `tenant__<safe_name(slug)>`: parser name, route key, component prefix.
    pub name: String,
    /// Whether the parser file carries a `_sample` transform (the combiner
    /// then consumes `_sample` instead of `_output`, as the open-core deploy
    /// does).
    pub sampled: bool,
    /// NAN-3197: whether the parser file also samples its OCSF lane
    /// (`_ocsf_sample`); the lake storage prepare then consumes
    /// `_ocsf_sample` instead of `_ocsf_prepare`. A bundle built before
    /// NAN-3197 carries `_sample` without it and still strips cleanly.
    pub ocsf_sampled: bool,
}

impl TenantName {
    pub fn new(slug: &str, sampled: bool) -> Self {
        Self {
            slug: slug.to_string(),
            name: format!("{TENANT_PREFIX}{}", crate::vector_naming::safe_name(slug)),
            sampled,
            ocsf_sampled: false,
        }
    }

    /// [`Self::new`] for a parser file whose OCSF lane is sampled.
    pub fn with_ocsf_sampled(mut self, ocsf_sampled: bool) -> Self {
        self.ocsf_sampled = ocsf_sampled;
        self
    }

    pub fn file(&self) -> String {
        format!("{TENANT_PARSER_DIR}{}.toml", self.name)
    }

    fn component(&self, suffix: &str) -> String {
        format!("{}{suffix}", self.name)
    }

    fn route_line(&self) -> String {
        format!("{} = '.source_type == \"{}\"'", self.name, self.slug)
    }

    fn allowed_components(&self) -> BTreeSet<String> {
        TENANT_COMPONENT_SUFFIXES
            .iter()
            .map(|suffix| self.component(suffix))
            .collect()
    }
}

/// One generated tenant source.
#[derive(Debug, Clone)]
pub struct GeneratedSource {
    pub processing_plan: Option<crate::parsers::pipe::Plan>,
    pub processing_failures: Vec<String>,
    pub tenant: TenantName,
    pub components: Vec<String>,
    /// The first transform tenant VRL runs in (`_parse`, or `_extension` for
    /// an extension-only stub): where `vector test` inserts samples.
    pub entry_component: String,
}

// ---------------------------------------------------------------------------
// Line-level wiring edits
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
enum Placement {
    /// Merge tenant items into an already sorted list, keeping it sorted.
    Sorted,
    /// Append tenant items after the platform items.
    Append,
}

#[derive(Debug, Clone, Copy)]
enum Items {
    HecToken,
    /// The HEC normalizer's authorized-source allowlist.
    HecSlug,
    /// The router's generic-lane exclusion list.
    RouteSlug,
    CombinedOutput,
    HealthInputs,
    OcsfPrepare,
}

struct ArrayPoint {
    file: &'static str,
    section: &'static str,
    prefix: &'static str,
    items: Items,
    placement: Placement,
}

const ARRAY_POINTS: [ArrayPoint; 6] = [
    ArrayPoint {
        file: HEC_FILE,
        section: "sources.splunk_hec_ingest",
        prefix: "valid_tokens = [",
        items: Items::HecToken,
        placement: Placement::Sorted,
    },
    ArrayPoint {
        file: HEC_FILE,
        section: "transforms.hec_normalize",
        prefix: "if !includes([",
        items: Items::HecSlug,
        placement: Placement::Sorted,
    },
    ArrayPoint {
        file: ROUTER_FILE,
        section: "transforms.source_router.route",
        prefix: "generic = '!includes([",
        items: Items::RouteSlug,
        placement: Placement::Append,
    },
    ArrayPoint {
        file: COMBINER_FILE,
        section: "transforms.db_parsers_combined",
        prefix: "inputs = [",
        items: Items::CombinedOutput,
        placement: Placement::Append,
    },
    ArrayPoint {
        file: COMBINER_FILE,
        section: "transforms.db_parser_health",
        prefix: "inputs = [",
        items: Items::HealthInputs,
        placement: Placement::Append,
    },
    ArrayPoint {
        file: LAKE_SINK_FILE,
        section: "transforms.ocsf_lake_storage_prepare",
        prefix: "inputs = [",
        items: Items::OcsfPrepare,
        placement: Placement::Append,
    },
];

/// Which platform base an overlay is generated on / verified against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverlayProfile {
    /// The tenant's ingest bundle: the full platform base, push sources and
    /// all six wiring points.
    Full,
    /// NAN-3369: a pull base ([`super::pull::pull_base`]): no push sources, so
    /// no HEC file and no HEC wiring points; the other four points (route,
    /// generic exclusion, combiner/health, lake prepare) are unchanged.
    Pull,
}

impl OverlayProfile {
    fn points(self) -> impl Iterator<Item = &'static ArrayPoint> {
        ARRAY_POINTS
            .iter()
            .filter(move |point| self == Self::Full || point.file != HEC_FILE)
    }

    fn required_files(self) -> &'static [&'static str] {
        match self {
            Self::Full => &[HEC_FILE, ROUTER_FILE, COMBINER_FILE, LAKE_SINK_FILE, OUTPUT_GUARD_FILE],
            Self::Pull => &[ROUTER_FILE, COMBINER_FILE, LAKE_SINK_FILE, OUTPUT_GUARD_FILE],
        }
    }

    /// Platform HEC slugs: a pull base enrolls none.
    fn platform_slugs(self, base: &BundleTree) -> Result<BTreeSet<String>, TenantBundleError> {
        match self {
            Self::Full => Ok(platform_slugs(base)?.into_iter().collect()),
            Self::Pull => Ok(BTreeSet::new()),
        }
    }

    fn slug_allowed(self, base: &BundleTree, platform: &BTreeSet<String>, slug: &str) -> Result<(), String> {
        match self {
            Self::Full => tenant_slug_allowed(base, platform, slug),
            Self::Pull => pull_slug_allowed(base, slug),
        }
    }
}

/// NAN-3369: whether a pull bundle may carry a tenant lane for `slug`. The
/// pull base keeps no plumbing lane, so the plumbing and platform slugs are
/// simply reserved; a platform parser lane is never a pull lane.
pub fn pull_slug_allowed(base: &BundleTree, slug: &str) -> Result<(), String> {
    if slug == UNDECLARED_SOURCE_SLUG
        || is_plumbing_slug(slug)
        || slug == super::platform_audit_lane::AUDIT_SLUG
    {
        return Err(format!("{slug} is a reserved ingestion slug; it has no pull lane"));
    }
    if platform_parser_file(base, slug).is_some() {
        return Err(format!("{slug} is parsed by a platform lane, not a tenant lane"));
    }
    Ok(())
}

const ROUTE_SECTION: &str = "transforms.source_router.route";
const ROUTE_ANCHOR: &str = "generic = '!includes([";

fn tenant_items(items: Items, tenants: &[TenantName]) -> Vec<String> {
    // A tenant parser on a plumbing slug (NAN-2977) reuses the platform's own
    // HEC token and allowlist entry; only its route and components are added.
    let enrolled = || tenants.iter().filter(|t| !is_plumbing_slug(&t.slug));
    match items {
        Items::HecToken => enrolled()
            .map(|t| format!("{HEC_TOKEN_PREFIX}{}", t.slug))
            .collect(),
        Items::HecSlug => enrolled().map(|t| t.slug.clone()).collect(),
        Items::RouteSlug => tenants.iter().map(|t| t.slug.clone()).collect(),
        Items::CombinedOutput => tenants
            .iter()
            .map(|t| t.component(if t.sampled { "_sample" } else { "_output" }))
            .collect(),
        // Mirrors the open-core combiner: every `_output`, then every
        // `_ocsf_prepare`.
        Items::HealthInputs => tenants
            .iter()
            .map(|t| t.component("_output"))
            .chain(tenants.iter().map(|t| t.component("_ocsf_prepare")))
            .collect(),
        // The lake lane reads the sampled OCSF stream when there is one
        // (NAN-3197); parser health above stays pre-sampling.
        Items::OcsfPrepare => tenants
            .iter()
            .map(|t| t.component(if t.ocsf_sampled { "_ocsf_sample" } else { "_ocsf_prepare" }))
            .collect(),
    }
}

/// Lines with their terminators, so edits never disturb other bytes.
fn lines(text: &str) -> Vec<&str> {
    text.split_inclusive('\n').collect()
}

/// Index of the single line in `section` starting with `prefix`. Headers are
/// only recognized outside multi-line strings; the prefix may be inside one
/// (the HEC allowlist lives in the normalizer's VRL).
fn find_line(all: &[&str], section: &str, prefix: &str) -> Result<usize, String> {
    let mut current: Option<String> = None;
    let mut in_multiline = false;
    let mut hits = Vec::new();
    for (index, raw) in all.iter().enumerate() {
        let line = raw.trim_end_matches(['\n', '\r']);
        if !in_multiline && line.starts_with('[') && !line.starts_with("[[") {
            current = line
                .trim_end()
                .strip_prefix('[')
                .and_then(|rest| rest.strip_suffix(']'))
                .map(str::to_string);
        }
        if current.as_deref() == Some(section) && line.starts_with(prefix) {
            hits.push(index);
        }
        let quotes = line.matches("'''").count() + line.matches("\"\"\"").count();
        if quotes % 2 == 1 {
            in_multiline = !in_multiline;
        }
    }
    match hits.as_slice() {
        [one] => Ok(*one),
        [] => Err(format!("[{section}] has no line starting {prefix:?}")),
        _ => Err(format!(
            "[{section}] has more than one line starting {prefix:?}"
        )),
    }
}

/// Split `…[ "a", "b" ]…` into (head, items, tail); the items must be
/// exactly `"x"` joined by `", "` so re-rendering is byte-exact.
fn split_array(line: &str) -> Result<(&str, Vec<String>, &str), String> {
    let open = line.find('[').ok_or("no array")?;
    let close = open + line[open..].find(']').ok_or("unterminated array")?;
    let body = &line[open + 1..close];
    let items: Vec<String> = QUOTED_ITEM_RE
        .captures_iter(body)
        .map(|c| c[1].to_string())
        .collect();
    if render_items(&items) != body {
        return Err("array is not in the canonical \"a\", \"b\" form".into());
    }
    Ok((&line[..=open], items, &line[close..]))
}

fn render_items(items: &[String]) -> String {
    items
        .iter()
        .map(|item| format!("\"{item}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

fn insert_array(text: &str, point: &ArrayPoint, tenants: &[TenantName]) -> Result<String, String> {
    let mut all = lines(text);
    let index = find_line(&all, point.section, point.prefix)?;
    let (head, base_items, tail) = split_array(all[index])?;
    if base_items.iter().any(|item| item.contains(TENANT_PREFIX)) {
        return Err(format!(
            "[{}] already carries a tenant__ item",
            point.section
        ));
    }
    let added = tenant_items(point.items, tenants);
    let items = match point.placement {
        Placement::Sorted => {
            let mut sorted = base_items.clone();
            sorted.sort();
            if sorted != base_items {
                return Err(format!("[{}] platform list is not sorted", point.section));
            }
            let mut merged = base_items;
            merged.extend(added);
            merged.sort();
            merged
        }
        Placement::Append => {
            let mut merged = base_items;
            merged.extend(added);
            merged
        }
    };
    let rebuilt = format!("{head}{}{tail}", render_items(&items));
    all[index] = &rebuilt;
    Ok(all.concat())
}

/// Remove exactly the tenant items; refuse a missing, extra or duplicated one.
fn strip_array(text: &str, point: &ArrayPoint, tenants: &[TenantName]) -> Result<String, String> {
    let mut all = lines(text);
    let index = find_line(&all, point.section, point.prefix)?;
    let (head, items, tail) = split_array(all[index])?;
    let expected: BTreeSet<String> = tenant_items(point.items, tenants).into_iter().collect();
    let (found, remaining): (Vec<String>, Vec<String>) = items
        .iter()
        .cloned()
        .partition(|item| expected.contains(item));
    let found_set: BTreeSet<String> = found.iter().cloned().collect();
    if found.len() != found_set.len() || found_set != expected {
        return Err(format!(
            "[{}] tenant items differ from the declared tenant sources",
            point.section
        ));
    }
    if matches!(point.placement, Placement::Sorted) {
        let mut sorted = items.clone();
        sorted.sort();
        if sorted != items {
            return Err(format!("[{}] list is not sorted", point.section));
        }
    }
    let rebuilt = format!("{head}{}{tail}", render_items(&remaining));
    all[index] = &rebuilt;
    Ok(all.concat())
}

fn insert_routes(text: &str, tenants: &[TenantName]) -> Result<String, String> {
    let mut all: Vec<String> = lines(text).into_iter().map(str::to_string).collect();
    let borrowed: Vec<&str> = all.iter().map(String::as_str).collect();
    let anchor = find_line(&borrowed, ROUTE_SECTION, ROUTE_ANCHOR)?;
    let routes: Vec<String> = tenants
        .iter()
        .map(|t| format!("{}\n", t.route_line()))
        .collect();
    all.splice(anchor..anchor, routes);
    Ok(all.concat())
}

/// Tenant route lines declared in the router's route table, in file order.
fn tenant_routes(text: &str) -> Result<Vec<(String, String)>, String> {
    let all = lines(text);
    // Scope the scan to the route section.
    let anchor = find_line(&all, ROUTE_SECTION, ROUTE_ANCHOR)?;
    let mut start = anchor;
    while start > 0 && !all[start - 1].starts_with('[') {
        start -= 1;
    }
    let mut routes = Vec::new();
    for raw in &all[start..] {
        let line = raw.trim_end_matches('\n');
        if line.starts_with('[') {
            break;
        }
        if line.starts_with(TENANT_PREFIX) {
            let captures = TENANT_ROUTE_RE
                .captures(line)
                .ok_or_else(|| format!("route line {line:?} is not a tenant route"))?;
            routes.push((captures[1].to_string(), captures[2].to_string()));
        }
    }
    Ok(routes)
}

fn strip_routes(text: &str, tenants: &[TenantName]) -> Result<String, String> {
    let expected: BTreeSet<String> = tenants.iter().map(TenantName::route_line).collect();
    let mut seen = BTreeSet::new();
    let mut kept = Vec::new();
    for raw in lines(text) {
        let line = raw.trim_end_matches('\n');
        if expected.contains(line) {
            if !seen.insert(line.to_string()) {
                return Err("a tenant route is declared twice".into());
            }
            continue;
        }
        kept.push(raw);
    }
    if seen != expected {
        return Err("a tenant source has no route".into());
    }
    Ok(kept.concat())
}

// ---------------------------------------------------------------------------
// Platform facts
// ---------------------------------------------------------------------------

/// Platform slugs: the base's HEC delivery tokens.
pub fn platform_slugs(base: &BundleTree) -> Result<Vec<String>, TenantBundleError> {
    let text = base.text(HEC_FILE)?;
    let all = lines(text);
    let index = find_line(&all, ARRAY_POINTS[0].section, ARRAY_POINTS[0].prefix)
        .map_err(TenantBundleError::Base)?;
    let (_, items, _) = split_array(all[index]).map_err(TenantBundleError::Base)?;
    items
        .iter()
        .map(|item| {
            item.strip_prefix(HEC_TOKEN_PREFIX)
                .filter(|slug| SOURCE_SLUG_RE.is_match(slug))
                .map(str::to_string)
                .ok_or_else(|| TenantBundleError::Base(format!("unexpected HEC token {item:?}")))
        })
        .collect()
}

/// NAN-2977: source slugs the platform base keeps as ingestion PLUMBING (no
/// platform parser): the OTLP logs lane. A tenant may install its own parser
/// on one (e.g. OTLP -> OCSF from the catalog); it reuses the base's HEC
/// token and allowlist entry.
pub const PLUMBING_SOURCE_SLUGS: &[&str] = &["otlp_log"];
/// The collector-v2 undeclared-source lane: never a tenant parser.
pub const UNDECLARED_SOURCE_SLUG: &str = "unknown";

pub fn is_plumbing_slug(slug: &str) -> bool {
    PLUMBING_SOURCE_SLUGS.contains(&slug)
}

/// Whether a tenant parser may route `slug` on `base`. There are no built-in
/// parsers (NAN-2977): the only reserved slugs are ingestion plumbing (the
/// undeclared lane; the `otlp_log` token, which a tenant parser may reuse).
/// A legacy (pre-NAN-2977) base still routes its own parsers; a tenant parser
/// on one of those slugs installs once the tenant merges the platform update.
pub fn tenant_slug_allowed(base: &BundleTree, platform: &BTreeSet<String>, slug: &str) -> Result<(), String> {
    if slug == UNDECLARED_SOURCE_SLUG {
        return Err(format!("{slug} is a reserved ingestion slug (the undeclared-source lane)"));
    }
    if platform_parser_file(base, slug).is_some() || (platform.contains(slug) && !is_plumbing_slug(slug)) {
        return Err(format!(
            "{slug} is still parsed by this tenant's current parser base; merge the platform update to install it from the catalog"
        ));
    }
    // A plumbing slug reuses the base's HEC token: the base must enroll it.
    if is_plumbing_slug(slug) && !platform.contains(slug) {
        return Err(format!("{slug} is a reserved ingestion slug this parser base does not enroll"));
    }
    Ok(())
}

/// The platform parser file that serves `slug` in `tree`, if any: the route
/// key whose condition is exactly `.source_type == "<slug>"`.
pub fn platform_parser_file(tree: &BundleTree, slug: &str) -> Option<String> {
    let text = std::str::from_utf8(tree.file(ROUTER_FILE)?).ok()?;
    let condition = format!("= '.source_type == \"{slug}\"'");
    text.lines()
        .filter(|line| !line.starts_with(TENANT_PREFIX))
        .find_map(|line| line.strip_suffix(condition.as_str()))
        .map(|key| format!("{TENANT_PARSER_DIR}{}.toml", key.trim()))
        .filter(|path| tree.files.contains_key(path))
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn check_base(base: &BundleTree, profile: OverlayProfile) -> Result<(), TenantBundleError> {
    for path in profile.required_files() {
        base.text(path)?;
    }
    if base.files.keys().any(|path| path.contains(TENANT_PREFIX))
        || base
            .files
            .values()
            .any(|data| String::from_utf8_lossy(data).contains(TENANT_PREFIX))
    {
        return Err(TenantBundleError::Base(
            "platform base already uses the reserved tenant__ namespace".into(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

fn tenant_parser(source: &TenantSource, tenant: &TenantName) -> Parser {
    let epoch = Utc.timestamp_opt(0, 0).single().expect("epoch");
    Parser {
        id: source.log_source_id,
        name: tenant.name.clone(),
        description: None,
        source_type: "routed".into(),
        parser_vrl: source.parser_vrl.clone(),
        output_fields: None,
        feed_id: None,
        dispatch_source_config_id: None,
        dispatch_route_name: None,
        enabled: true,
        validated: true,
        validation_error: None,
        category: source.category.clone(),
        vendor: source.vendor.clone(),
        product: source.product.clone(),
        kind: "log".into(),
        enrich_kind: None,
        enrich_source: None,
        target_table: None,
        normalize_vrl: None,
        namespace: source.namespace.clone(),
        timezone: source.timezone.clone(),
        match_values: Some(vec![source.slug.clone()]),
        // A ratio of 1 keeps everything: no sample transform at all.
        sampling_ratio: source.sampling_ratio.filter(|ratio| *ratio < 1.0),
        sampling_exclude_condition: source.sampling_exclude_condition.clone(),
        extension_vrl: source.extension_vrl.clone(),
        extension_enabled: source.extension_enabled,
        created_at: epoch,
        updated_at: epoch,
    }
}

/// Transform names declared by a parser file, in file order.
fn declared_transforms(text: &str) -> Result<(toml::Table, Vec<String>), String> {
    let table: toml::Table = text
        .parse()
        .map_err(|e: toml::de::Error| e.message().to_string())?;
    let names = table
        .get("transforms")
        .and_then(toml::Value::as_table)
        .map(|t| t.keys().cloned().collect())
        .unwrap_or_default();
    Ok((table, names))
}

/// Pure overlay generation: platform base + the tenant's published sources →
/// the candidate bundle tree and what was generated. Deterministic: the same
/// inputs give the same tree, independent of clock and environment.
pub fn apply_overlay(
    base: &BundleTree,
    sources: &[TenantSource],
) -> Result<(BundleTree, Vec<GeneratedSource>), TenantBundleError> {
    apply_overlay_with(base, sources, OverlayProfile::Full)
}

/// [`apply_overlay`] on a base of the given profile.
pub fn apply_overlay_with(
    base: &BundleTree,
    sources: &[TenantSource],
    profile: OverlayProfile,
) -> Result<(BundleTree, Vec<GeneratedSource>), TenantBundleError> {
    check_base(base, profile)?;
    let platform = profile.platform_slugs(base)?;
    let mut ordered: Vec<&TenantSource> = sources.iter().collect();
    ordered.sort_by(|a, b| a.slug.cmp(&b.slug));

    let manager = VectorConfigManager::new("/nonexistent/tenant-bundle-build");
    let mut candidate = base.clone();
    let mut generated = Vec::with_capacity(ordered.len());
    let mut names = BTreeMap::new();
    let mut unparsed = Vec::new();
    for source in ordered {
        if let Err(message) = profile.slug_allowed(base, &platform, &source.slug) {
            return Err(TenantBundleError::Overlay {
                slug: Some(source.slug.clone()),
                message,
            });
        }
        if source.parser_vrl.trim().is_empty()
            && !(source.extension_enabled && source.extension_vrl.as_deref().is_some_and(|v| !v.trim().is_empty()))
        {
            if ["default", "audit", "otlp_log", "otlp_metric", "otlp_trace"].contains(&source.slug.as_str()) {
                return Err(TenantBundleError::Input("reserved source cannot enroll as unparsed".into()));
            }
            unparsed.push(source.slug.clone());
            continue;
        }
        let sampled = source.sampling_ratio.is_some_and(|ratio| ratio < 1.0);
        let tenant = TenantName::new(&source.slug, sampled);
        if let Some(other) = names.insert(tenant.name.clone(), source.slug.clone()) {
            return Err(TenantBundleError::Overlay {
                slug: Some(source.slug.clone()),
                message: format!(
                    "{} and {other} map to the same component name {}",
                    source.slug, tenant.name
                ),
            });
        }
        let parser = tenant_parser(source, &tenant);
        let text = manager.generate_parser_config_with(
            &parser,
            &ParserConfigOptions {
                generated_at: Some(GENERATED_AT),
                ocsf: Some(true),
                pinned_source_type: Some(&source.slug),
                // NAN-3079: tenant bundles feed the lake bronze sink.
                lake_bronze: true,
                // NAN-3197: sampling covers the OCSF lake lane too.
                sample_ocsf_lane: true,
            },
        );
        let text = scan::escape_interpolation(&text);
        let text = crate::parsers::pipe::native::restore_lookup_paths(&tenant.name, &text)
            .map_err(TenantBundleError::Input)?;
        let mut processing_failures = Vec::new();
        if let Some(plan) = crate::parsers::pipe::stored_plan(&source.parser_vrl)
            .map_err(TenantBundleError::Input)?
            .filter(|plan| plan.has_native())
        {
            let chain = crate::parsers::pipe::native::render(
                &plan,
                &tenant.name,
                &tenant.component("_parse"),
            )
            .map_err(TenantBundleError::Input)?;
            processing_failures = chain.failures;
            processing_failures.push(format!("{}.dropped", tenant.component("_parse")));
            if source.extension_enabled
                && source
                    .extension_vrl
                    .as_ref()
                    .is_some_and(|code| !code.trim().is_empty())
            {
                processing_failures.push(format!("{}.dropped", tenant.component("_extension")));
            }
            for (path, data) in chain.files {
                candidate.put(&path, data);
            }
        }
        let (_, components) =
            declared_transforms(&text).map_err(|message| TenantBundleError::Overlay {
                slug: Some(source.slug.clone()),
                message: format!("generated parser file is not valid TOML: {message}"),
            })?;
        let entry = [tenant.component("_parse"), tenant.component("_extension")]
            .into_iter()
            .find(|name| components.contains(name))
            .ok_or_else(|| TenantBundleError::Overlay {
                slug: Some(source.slug.clone()),
                message: "generated parser has neither _parse nor _extension".into(),
            })?;
        let ocsf_sampled = components.contains(&tenant.component("_ocsf_sample"));
        if sampled && !ocsf_sampled {
            return Err(TenantBundleError::Overlay {
                slug: Some(source.slug.clone()),
                message: "generated parser samples its UDM lane but not its OCSF lane".into(),
            });
        }
        let tenant = tenant.with_ocsf_sampled(ocsf_sampled);
        candidate.put(&tenant.file(), text.into_bytes());
        generated.push(GeneratedSource {
            processing_failures,
            processing_plan: crate::parsers::pipe::stored_plan(&source.parser_vrl).map_err(TenantBundleError::Input)?,
            tenant,
            components,
            entry_component: entry,
        });
    }

    let tenants: Vec<TenantName> = generated.iter().map(|g| g.tenant.clone()).collect();
    if !tenants.is_empty() {
        let wiring_error = |message: String| TenantBundleError::Base(message);
        for point in profile.points() {
            let text = candidate.text(point.file)?.to_string();
            let edited = insert_array(&text, point, &tenants).map_err(wiring_error)?;
            candidate.put(point.file, edited.into_bytes());
        }
        let router = candidate.text(ROUTER_FILE)?.to_string();
        let routed = insert_routes(&router, &tenants).map_err(wiring_error)?;
        candidate.put(ROUTER_FILE, routed.into_bytes());
    }
    if !unparsed.is_empty() {
        if profile != OverlayProfile::Full {
            return Err(TenantBundleError::Input("unparsed sources have no pull lane".into()));
        }
        let enrollments: Vec<TenantName> = unparsed.iter().map(|slug| TenantName::new(slug, false)).collect();
        for point in profile.points().filter(|point| point.file == HEC_FILE) {
            let edited = insert_array(candidate.text(point.file)?, point, &enrollments).map_err(TenantBundleError::Base)?;
            candidate.put(point.file, edited.into_bytes());
        }
        candidate.put(UNPARSED_SOURCES_FILE, serde_json::to_vec(&unparsed).map_err(|e| TenantBundleError::Input(e.to_string()))?);
    }
    Ok((candidate, generated))
}

// ---------------------------------------------------------------------------
// Independent verification (the structural guard)
// ---------------------------------------------------------------------------

/// What [`verify_against_base`] proved about a candidate bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOverlay {
    pub tenants: Vec<TenantName>,
    pub unparsed_sources: Vec<String>,
    /// Sorted platform + tenant slugs (the source authority's `hec_sources`).
    pub hec_sources: Vec<String>,
    pub hec_config_sha256: String,
    pub output_guard_sha256: String,
    pub overlay_files: Vec<String>,
}

fn finding(path: Option<&str>, source: Option<&str>, rule: &str, message: String) -> GuardFinding {
    GuardFinding {
        path: path.map(str::to_string),
        source: source.map(str::to_string),
        rule: rule.to_string(),
        message,
    }
}

/// Remove the overlay from a bundle, returning the platform part and the
/// tenants it carried. Needs no base: tenant items are recognized by the
/// reserved `tenant__` route lines.
pub fn strip_overlay(
    candidate: &BundleTree,
) -> Result<(BundleTree, Vec<TenantName>), Vec<GuardFinding>> {
    strip_overlay_with(candidate, OverlayProfile::Full)
}

/// [`strip_overlay`] for a bundle of the given profile.
pub fn strip_overlay_with(
    candidate: &BundleTree,
    profile: OverlayProfile,
) -> Result<(BundleTree, Vec<TenantName>), Vec<GuardFinding>> {
    let mut findings = Vec::new();
    let router = match candidate.text(ROUTER_FILE) {
        Ok(text) => text.to_string(),
        Err(e) => {
            return Err(vec![finding(
                Some(ROUTER_FILE),
                None,
                "wiring",
                e.to_string(),
            )])
        }
    };
    let routes = match tenant_routes(&router) {
        Ok(routes) => routes,
        Err(e) => return Err(vec![finding(Some(ROUTER_FILE), None, "wiring", e)]),
    };
    let mut tenants = Vec::new();
    for (name, slug) in routes {
        let sampled_probe = TenantName::new(&slug, false);
        if sampled_probe.name != name {
            findings.push(finding(
                Some(ROUTER_FILE),
                Some(&slug),
                "namespace",
                format!("route {name} does not match its slug {slug}"),
            ));
            continue;
        }
        let declared = candidate
            .file(&sampled_probe.file())
            .and_then(|data| std::str::from_utf8(data).ok())
            .and_then(|text| declared_transforms(text).ok())
            .map(|(_, names)| names)
            .unwrap_or_default();
        let sampled = declared.contains(&sampled_probe.component("_sample"));
        let ocsf_sampled = declared.contains(&sampled_probe.component("_ocsf_sample"));
        tenants.push(TenantName::new(&slug, sampled).with_ocsf_sampled(ocsf_sampled));
    }
    let unparsed = unparsed_sources(candidate).map_err(|message| vec![finding(Some(UNPARSED_SOURCES_FILE), None, "wiring", message)])?;
    if profile != OverlayProfile::Full && !unparsed.is_empty() {
        return Err(vec![finding(Some(UNPARSED_SOURCES_FILE), None, "wiring", "unparsed sources have no pull lane".into())]);
    }
    if unparsed.iter().any(|slug| tenants.iter().any(|tenant| &tenant.slug == slug)) {
        return Err(vec![finding(Some(UNPARSED_SOURCES_FILE), None, "wiring", "source is both parsed and unparsed".into())]);
    }
    let mut platform = candidate.clone();
    platform.files.remove(UNPARSED_SOURCES_FILE);
    if !unparsed.is_empty() {
        let enrollments: Vec<TenantName> = unparsed.iter().map(|slug| TenantName::new(slug, false)).collect();
        for point in profile.points().filter(|point| point.file == HEC_FILE) {
            match platform.text(point.file).map(str::to_string).map_err(|e| e.to_string()).and_then(|text| strip_array(&text, point, &enrollments)) {
                Ok(text) => platform.put(point.file, text.into_bytes()),
                Err(message) => findings.push(finding(Some(point.file), None, "wiring", message)),
            }
        }
    }
    if !tenants.is_empty() {
        for point in profile.points() {
            let Ok(text) = platform.text(point.file).map(str::to_string) else {
                findings.push(finding(
                    Some(point.file),
                    None,
                    "wiring",
                    "file is absent".into(),
                ));
                continue;
            };
            match strip_array(&text, point, &tenants) {
                Ok(stripped) => platform.put(point.file, stripped.into_bytes()),
                Err(e) => findings.push(finding(Some(point.file), None, "wiring", e)),
            }
        }
        let router = platform
            .text(ROUTER_FILE)
            .map(str::to_string)
            .unwrap_or_default();
        match strip_routes(&router, &tenants) {
            Ok(stripped) => platform.put(ROUTER_FILE, stripped.into_bytes()),
            Err(e) => findings.push(finding(Some(ROUTER_FILE), None, "wiring", e)),
        }
    }
    for tenant in &tenants {
        if let Ok(text) = candidate.text(&tenant.file()) {
            if let Ok(document) = text.parse::<toml::Table>() {
                match crate::parsers::pipe::native::lookup_files(&tenant.name, &document) {
                    Ok(paths) => {
                        for path in paths {
                            platform.files.remove(&path);
                        }
                    }
                    Err(message) => findings.push(finding(
                        Some(&tenant.file()),
                        Some(&tenant.slug),
                        "lookup_scope",
                        message,
                    )),
                }
            }
        }
        platform.files.remove(&tenant.file());
    }
    if findings.is_empty() {
        Ok((platform, tenants))
    } else {
        Err(findings)
    }
}

fn check_tenant_file(tenant: &TenantName, text: &str, findings: &mut Vec<GuardFinding>) {
    let path = tenant.file();
    let slug = Some(tenant.slug.as_str());
    let mut push = |rule: &str, message: String| {
        findings.push(finding(Some(&path), slug, rule, message));
    };
    for name in scan::blocked_function_calls(text) {
        push(
            "blocked_function",
            format!("calls blocked VRL function {name}"),
        );
    }
    let scanned = crate::parsers::pipe::native::interpolation_scan(&tenant.name, text)
        .unwrap_or_else(|_| text.into());
    if scan::has_unescaped_dollar(&scanned) {
        push(
            "interpolation",
            "contains an unescaped $ (environment interpolation)".into(),
        );
    }
    if scan::secret_material(text) {
        push("secret", "appears to contain secret material".into());
    }
    let (table, names) = match declared_transforms(text) {
        Ok(parsed) => parsed,
        Err(e) => return push("toml", format!("is not valid TOML: {e}")),
    };
    // Exempt only a byte-for-byte renderer-owned restore whose entire data
    // path is guarded. Scan decoded TOML strings so quoted VRL paths cannot
    // hide assignments behind TOML escaping. All other code stays read-only.
    let mut metadata_document = table.clone();
    if let Some(transforms) = table.get("transforms").and_then(toml::Value::as_table) {
        for name in &names {
            if crate::parsers::pipe::native::metadata::trusted_restore(&tenant.name, name, transforms) {
                metadata_document
                    .get_mut("transforms")
                    .and_then(toml::Value::as_table_mut)
                    .and_then(|transforms| transforms.get_mut(name))
                    .and_then(toml::Value::as_table_mut)
                    .expect("trusted restore is a transform table")
                    .remove("source");
            }
        }
    }
    if scan::metadata_writes_in_toml(&toml::Value::Table(metadata_document)) {
        push(
            "metadata_write",
            "writes Vector event metadata (%…); only the fixed guarded combine restore may write it".into(),
        );
    }
    if table
        .keys()
        .any(|key| !["transforms", "enrichment_tables"].contains(&key.as_str()))
    {
        push(
            "component_kind",
            "declares something other than transforms (sources, sinks, tests or globals)".into(),
        );
    }
    let allowed = tenant.allowed_components();
    if let Err(message) = crate::parsers::pipe::native::lookup_files(&tenant.name, &table) {
        push("lookup_scope", message);
    }
    let own: BTreeSet<String> = names.iter().cloned().collect();
    if !own.contains(&tenant.component("_output"))
        || !own.contains(&tenant.component("_ocsf_prepare"))
    {
        push("shape", "lacks the _output / _ocsf_prepare lane".into());
    }
    let transforms = table.get("transforms").and_then(toml::Value::as_table);
    for name in &names {
        if !allowed.contains(name)
            && !crate::parsers::pipe::native::owns_component(&tenant.name, name)
        {
            push(
                "namespace",
                format!("component {name} is outside the {} namespace", tenant.name),
            );
            continue;
        }
        let Some(body) = transforms
            .and_then(|t| t.get(name))
            .and_then(toml::Value::as_table)
        else {
            push("shape", format!("component {name} is not a table"));
            continue;
        };
        let kind = body.get("type").and_then(toml::Value::as_str).unwrap_or("");
        if kind == "reduce" {
            // Reduce consumes the prepared events plus the fixed Lua gate's
            // end-group markers; exactly one input must be that gate.
            let bounded = body
                .get("inputs")
                .and_then(toml::Value::as_array)
                .filter(|inputs| inputs.len() == 2)
                .is_some_and(|inputs| {
                    inputs
                        .iter()
                        .filter(|input| {
                            input
                                .as_str()
                                .and_then(|input| {
                                    transforms.and_then(|transforms| transforms.get(input))
                                })
                                .and_then(toml::Value::as_table)
                                .is_some_and(|gate| {
                                    gate.get("type").and_then(toml::Value::as_str) == Some("lua")
                                        && crate::parsers::pipe::native::guard_transform(
                                            "lua", gate,
                                        )
                                        .is_ok()
                                })
                        })
                        .count()
                        == 1
                });
            if !bounded {
                push(
                    "runtime_safety",
                    format!("component {name} has no fixed group-bound gate"),
                );
            }
        }
        if let Err(message) = crate::parsers::pipe::native::guard_transform(kind, body) {
            push("runtime_safety", format!("component {name}: {message}"));
        }
        if let Some(source) = body.get("source").and_then(toml::Value::as_str) {
            if !crate::parsers::pipe::native::lookup_calls_owned(&tenant.name, source) {
                push(
                    "lookup_scope",
                    format!("component {name} queries a foreign or dynamic lookup table"),
                );
            }
        }
        if !TENANT_TRANSFORM_TYPES.contains(&kind) {
            push(
                "component_kind",
                format!("component {name} has type {kind:?}"),
            );
        }
        let inputs: Vec<&str> = body
            .get("inputs")
            .and_then(toml::Value::as_array)
            .map(|a| a.iter().filter_map(toml::Value::as_str).collect())
            .unwrap_or_default();
        for input in inputs {
            let owner = input.split('.').next().unwrap_or(input);
            let own_route = input == format!("source_router.{}", tenant.name);
            if !own_route && !own.contains(owner) {
                push(
                    "inputs",
                    format!("component {name} reads {input}, which the tenant does not own"),
                );
            }
        }
        for key in TENANT_FORBIDDEN_TRANSFORM_KEYS {
            if body.contains_key(key) {
                push(
                    "vrl_file",
                    format!("component {name} sets {key:?}: tenant VRL must be inline, never loaded from a path"),
                );
            }
        }
        if kind == "remap" && crate::parsers::pipe::native::owns_component(&tenant.name, name)
            || TENANT_VRL_SUFFIXES
                .iter()
                .any(|s| *name == tenant.component(s))
        {
            for flag in ["drop_on_error", "reroute_dropped"] {
                if body.get(flag) != Some(&toml::Value::Boolean(true)) {
                    push(
                        "runtime_safety",
                        format!("component {name} must set {flag} = true"),
                    );
                }
            }
        }
    }
}

/// The structural guard: prove `candidate` is `base` plus a well-formed
/// tenant overlay and nothing else.
pub fn verify_against_base(
    base: &BundleTree,
    candidate: &BundleTree,
) -> Result<VerifiedOverlay, Vec<GuardFinding>> {
    verify_against_base_with(base, candidate, OverlayProfile::Full)
}

/// [`verify_against_base`] for a base of the given profile. NAN-3369: a pull
/// bundle is verified against its filtered base exactly like a tenant bundle
/// against the full base (filtering is a set operation on the base, not new
/// verification logic).
pub fn verify_against_base_with(
    base: &BundleTree,
    candidate: &BundleTree,
    profile: OverlayProfile,
) -> Result<VerifiedOverlay, Vec<GuardFinding>> {
    if let Err(e) = check_base(base, profile) {
        return Err(vec![finding(None, None, "base", e.to_string())]);
    }
    let (platform, tenants) = strip_overlay_with(candidate, profile)?;
    let mut findings = Vec::new();

    let paths: BTreeSet<&String> = base.files.keys().chain(platform.files.keys()).collect();
    for path in paths {
        match (base.files.get(path), platform.files.get(path)) {
            (Some(a), Some(b)) if a == b => {}
            (Some(_), Some(_)) => findings.push(finding(
                Some(path),
                None,
                "platform_identical",
                "platform file differs from the base".into(),
            )),
            (Some(_), None) => findings.push(finding(
                Some(path),
                None,
                "platform_identical",
                "platform file was removed".into(),
            )),
            (None, _) => findings.push(finding(
                Some(path),
                None,
                "overlay_scope",
                "file is neither platform nor a tenant parser file".into(),
            )),
        }
    }
    let implied: BTreeSet<String> = tenants
        .iter()
        .flat_map(|t| {
            let file = t.file();
            std::path::Path::new(&file)
                .ancestors()
                .skip(1)
                .map(|p| p.to_string_lossy().into_owned())
                .filter(|p| !p.is_empty())
                .collect::<Vec<_>>()
        })
        .collect();
    let extra_dirs: Vec<&String> = candidate
        .dirs
        .iter()
        .filter(|dir| !base.dirs.contains(*dir) && !implied.contains(*dir))
        .collect();
    for dir in extra_dirs {
        findings.push(finding(
            Some(dir),
            None,
            "overlay_scope",
            "directory is neither platform nor a tenant parser directory".into(),
        ));
    }
    for dir in base.dirs.difference(&candidate.dirs) {
        findings.push(finding(
            Some(dir),
            None,
            "platform_identical",
            "platform directory was removed".into(),
        ));
    }

    let platform_slugs: BTreeSet<String> = match profile.platform_slugs(base) {
        Ok(slugs) => slugs,
        Err(e) => return Err(vec![finding(Some(HEC_FILE), None, "base", e.to_string())]),
    };
    let unparsed = unparsed_sources(candidate).map_err(|message| vec![finding(Some(UNPARSED_SOURCES_FILE), None, "wiring", message)])?;
    for slug in &unparsed {
        if let Err(message) = profile.slug_allowed(base, &platform_slugs, slug) {
            findings.push(finding(None, Some(slug), "namespace", message));
        }
    }
    for tenant in &tenants {
        if let Err(message) = profile.slug_allowed(base, &platform_slugs, &tenant.slug) {
            findings.push(finding(
                None,
                Some(&tenant.slug),
                "namespace",
                format!("tenant slug collides with the parser base: {message}"),
            ));
        }
        match candidate.file(&tenant.file()).map(std::str::from_utf8) {
            Some(Ok(text)) => {
                check_tenant_file(tenant, text, &mut findings);
                if let Ok(doc) = text.parse::<toml::Table>() {
                    if let Ok(files) =
                        crate::parsers::pipe::native::lookup_files(&tenant.name, &doc)
                    {
                        for path in files {
                            if !candidate.file(&path).is_some_and(|data| {
                                data.len() <= 256 * 1024 && std::str::from_utf8(data).is_ok()
                            }) {
                                findings.push(finding(
                                    Some(&path),
                                    Some(&tenant.slug),
                                    "lookup_scope",
                                    "lookup snapshot is absent, oversized or not UTF-8".into(),
                                ));
                            }
                        }
                    }
                }
            }
            Some(Err(_)) => findings.push(finding(
                Some(&tenant.file()),
                Some(&tenant.slug),
                "toml",
                "is not UTF-8".into(),
            )),
            None => findings.push(finding(
                Some(&tenant.file()),
                Some(&tenant.slug),
                "shape",
                "routed tenant source has no parser file".into(),
            )),
        }
    }
    let mut names: Vec<&str> = tenants.iter().map(|t| t.name.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|pair| pair[0] == pair[1]) {
        findings.push(finding(
            None,
            None,
            "namespace",
            "two tenant slugs share a name".into(),
        ));
    }
    if !findings.is_empty() {
        return Err(findings);
    }

    // A tenant parser on a plumbing slug adds no source (a set, sorted).
    let hec_sources: Vec<String> = platform_slugs
        .into_iter()
        .chain(tenants.iter().map(|t| t.slug.clone()))
        .chain(unparsed.iter().cloned())
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect();
    let mut overlay_files: Vec<String> = tenants.iter().map(TenantName::file).collect();
    if !unparsed.is_empty() { overlay_files.push(UNPARSED_SOURCES_FILE.into()); }
    Ok(VerifiedOverlay {
        hec_config_sha256: sha256_hex(candidate.file(HEC_FILE).unwrap_or_default()),
        output_guard_sha256: sha256_hex(candidate.file(OUTPUT_GUARD_FILE).unwrap_or_default()),
        tenants,
        unparsed_sources: unparsed,
        hec_sources,
        overlay_files,
    })
}
