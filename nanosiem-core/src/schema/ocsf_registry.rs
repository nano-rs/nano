// SPDX-License-Identifier: AGPL-3.0-or-later

//! Version-agnostic OCSF schema registry (NAN-4903).
//!
//! The ClickHouse OCSF store (`nanosiem.ocsf_events`, see
//! `docs/design/OCSF-CLICKHOUSE.md`) is not a "1.9 table". Every event keeps its
//! full OCSF object in a native `JSON` column plus its own `metadata.version`,
//! and a small set of hot paths is promoted to typed columns. What makes a
//! dotted nPL field queryable is therefore *schema knowledge*, not DDL: this
//! registry answers "is `answers.rdata` an OCSF attribute, which of its segments
//! are arrays, and what is the leaf type?" from the compact contracts generated
//! out of the official OCSF schema export (`scripts/update-ocsf-contract.py`).
//!
//! - **Several versions at once.** [`CONTRACTS`] lists every embedded contract,
//!   oldest first. A lookup succeeds if ANY version defines the path, and
//!   reports the newest one that does, so a 2.0 attribute resolves for 2.0 rows
//!   while a 1.9 attribute that 2.0 dropped still resolves for the 1.9 rows
//!   that carry it. Rows never need a rewrite or backfill.
//! - **Renames.** [`OCSF_ALIASES`] maps a superseded path to its replacement
//!   (with the version that introduced it). Field resolution queries both the
//!   new and the old location, so one nPL name spans rows of both versions.
//! - **Union across classes.** nPL fields are class-agnostic (`process.name`
//!   means the same thing in 1007 and 4001), so the top level is the union of
//!   every class's attributes.
//!
//! Single tenant: the registry is process-wide and immutable.

use std::collections::{BTreeMap, HashMap};
use std::io::Read;
use std::sync::OnceLock;

use flate2::read::GzDecoder;
use serde::Deserialize;

/// Embedded OCSF contracts, OLDEST FIRST. Adding an OCSF version is one line
/// here plus the generated file (see the module docs and the design doc).
const CONTRACTS: &[(&str, &[u8])] = &[(
    "1.9.0",
    include_bytes!("ocsf_contracts/ocsf-1.9.0-contract.json.gz"),
)];

/// Superseded-path → replacement-path map (cross-version renames), applied by
/// field resolution so one nPL name covers rows written under either version.
const ALIASES_JSON: &str = include_str!("ocsf_contracts/aliases.json");

/// Recursion guard for self-referential objects (`process.parent_process…`).
const MAX_PATH_DEPTH: usize = 16;

#[derive(Debug, Deserialize)]
struct Contract {
    version: String,
    classes: BTreeMap<String, Item>,
    objects: BTreeMap<String, Item>,
}

#[derive(Debug, Deserialize)]
struct Item {
    #[serde(default)]
    uid: Option<i64>,
    #[serde(default)]
    attributes: BTreeMap<String, Attr>,
}

#[derive(Debug, Clone, Deserialize)]
struct Attr {
    #[serde(rename = "type")]
    type_name: String,
    #[serde(default)]
    object_type: Option<String>,
    #[serde(default)]
    is_array: bool,
    #[serde(default)]
    deprecated: Option<Deprecation>,
}

/// An `@deprecated` marker carried over from the OCSF schema export.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct Deprecation {
    /// Upstream guidance (usually names the replacement attribute).
    #[serde(default)]
    pub message: Option<String>,
    /// OCSF version that deprecated the attribute.
    #[serde(default)]
    pub since: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AliasFile {
    aliases: Vec<AliasEntry>,
}

/// One cross-version rename: rows written before `since` carry `from`.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct AliasEntry {
    /// The superseded dotted path.
    pub from: String,
    /// The replacement dotted path.
    pub to: String,
    /// OCSF version that introduced `to`.
    pub since: String,
}

/// Leaf value type of an OCSF attribute, collapsed to what SQL generation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OcsfLeafType {
    /// `string_t` and every string-derived type (ip_t, hostname_t, …).
    String,
    /// `integer_t` / `port_t` (and enum ids).
    Integer,
    /// `long_t` / `timestamp_t`.
    Long,
    /// `float_t`.
    Float,
    /// `boolean_t`.
    Boolean,
    /// `json_t`: an opaque JSON value; any sub-path below it is accepted.
    Json,
    /// An `object_t` attribute (the path stops at an object, not a leaf).
    Object,
}

/// What the registry knows about a dotted path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OcsfPathInfo {
    /// Path segments (`["answers", "rdata"]`).
    pub segments: Vec<String>,
    /// `arrays[i]` is true when segment `i` is an array (`answers` → true).
    pub arrays: Vec<bool>,
    /// Leaf type of the final segment.
    pub leaf: OcsfLeafType,
    /// Newest embedded OCSF version that defines this path.
    pub version: &'static str,
    /// Set when the newest defining version marks the leaf deprecated.
    pub deprecated: Option<Deprecation>,
}

impl OcsfPathInfo {
    /// True when any segment is an array, so the path yields a list of values.
    pub fn is_multi_valued(&self) -> bool {
        self.arrays.iter().any(|a| *a)
    }

    /// Number of array segments (nesting depth of the resulting SQL array).
    pub fn array_depth(&self) -> usize {
        self.arrays.iter().filter(|a| **a).count()
    }
}

/// Result of [`lookup`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OcsfLookup {
    /// The path is an OCSF attribute in at least one embedded version.
    Known(OcsfPathInfo),
    /// Not an OCSF attribute. `suggestions` are near-miss attribute names at the
    /// first segment that failed (did-you-mean), already joined into full paths.
    Unknown { suggestions: Vec<String> },
}

struct Version {
    version: &'static str,
    /// Union of every class's top-level attributes.
    top: HashMap<String, Attr>,
    objects: HashMap<String, HashMap<String, Attr>>,
    /// class_uid → class name (for docs/UI; also proves the class exists).
    class_names: HashMap<i64, String>,
}

struct Registry {
    versions: Vec<Version>,
    aliases: Vec<AliasEntry>,
}

fn registry() -> &'static Registry {
    static REG: OnceLock<Registry> = OnceLock::new();
    REG.get_or_init(|| {
        let versions = CONTRACTS
            .iter()
            .map(|(label, gz)| {
                let mut json = String::new();
                GzDecoder::new(*gz)
                    .read_to_string(&mut json)
                    .expect("embedded OCSF contract must be valid gzip");
                let c: Contract =
                    serde_json::from_str(&json).expect("embedded OCSF contract must be valid JSON");
                assert_eq!(&c.version, label, "OCSF contract version label mismatch");
                let mut top: HashMap<String, Attr> = HashMap::new();
                let mut class_names = HashMap::new();
                for (name, class) in &c.classes {
                    if let Some(uid) = class.uid {
                        class_names.insert(uid, name.clone());
                    }
                    for (attr, def) in &class.attributes {
                        top.entry(attr.clone()).or_insert_with(|| def.clone());
                    }
                }
                let objects = c
                    .objects
                    .into_iter()
                    .map(|(name, item)| (name, item.attributes.into_iter().collect()))
                    .collect();
                Version {
                    version: label,
                    top,
                    objects,
                    class_names,
                }
            })
            .collect();
        let aliases: AliasFile =
            serde_json::from_str(ALIASES_JSON).expect("ocsf_contracts/aliases.json must be valid");
        Registry {
            versions,
            aliases: aliases.aliases,
        }
    })
}

fn leaf_type(type_name: &str) -> OcsfLeafType {
    match type_name {
        "object_t" => OcsfLeafType::Object,
        "integer_t" | "port_t" => OcsfLeafType::Integer,
        "long_t" | "timestamp_t" => OcsfLeafType::Long,
        "float_t" => OcsfLeafType::Float,
        "boolean_t" => OcsfLeafType::Boolean,
        "json_t" => OcsfLeafType::Json,
        _ => OcsfLeafType::String,
    }
}

/// Walk `segments` through one version. `Err(i)` is the index of the first
/// segment that is not an attribute at its level.
fn walk(v: &Version, segments: &[&str]) -> Result<OcsfPathInfo, usize> {
    if segments.is_empty() || segments.len() > MAX_PATH_DEPTH {
        return Err(0);
    }
    let mut level = &v.top;
    let mut arrays = Vec::with_capacity(segments.len());
    for (i, seg) in segments.iter().enumerate() {
        let attr = level.get(*seg).ok_or(i)?;
        arrays.push(attr.is_array);
        let ty = leaf_type(&attr.type_name);
        let last = i + 1 == segments.len();
        match ty {
            OcsfLeafType::Object => {
                let obj = attr
                    .object_type
                    .as_deref()
                    .and_then(|o| v.objects.get(o))
                    .ok_or(i)?;
                if last {
                    return Ok(info(v, segments, arrays, ty, attr));
                }
                level = obj;
            }
            OcsfLeafType::Json => {
                // Anything below a json_t attribute is free-form.
                arrays.extend(std::iter::repeat(false).take(segments.len() - i - 1));
                return Ok(info(v, segments, arrays, ty, attr));
            }
            _ if last => return Ok(info(v, segments, arrays, ty, attr)),
            _ => return Err(i + 1),
        }
    }
    Err(segments.len())
}

fn info(
    v: &Version,
    segments: &[&str],
    arrays: Vec<bool>,
    leaf: OcsfLeafType,
    attr: &Attr,
) -> OcsfPathInfo {
    OcsfPathInfo {
        segments: segments.iter().map(|s| s.to_string()).collect(),
        arrays,
        leaf,
        version: v.version,
        deprecated: attr.deprecated.clone(),
    }
}

/// Look a dotted OCSF path up across every embedded version (newest wins).
pub fn lookup(path: &str) -> OcsfLookup {
    let segments: Vec<&str> = path.split('.').collect();
    if segments.iter().any(|s| s.is_empty()) {
        return OcsfLookup::Unknown {
            suggestions: Vec::new(),
        };
    }
    let reg = registry();
    let mut deepest_fail = (0usize, None::<&Version>);
    for v in reg.versions.iter().rev() {
        match walk(v, &segments) {
            Ok(info) => return OcsfLookup::Known(info),
            Err(i) => {
                if deepest_fail.1.is_none() || i > deepest_fail.0 {
                    deepest_fail = (i, Some(v));
                }
            }
        }
    }
    let (fail_at, version) = deepest_fail;
    let suggestions = version
        .map(|v| suggest(v, &segments, fail_at))
        .unwrap_or_default();
    OcsfLookup::Unknown { suggestions }
}

/// Convenience: `Some(info)` when `path` is a known OCSF attribute.
pub fn known(path: &str) -> Option<OcsfPathInfo> {
    match lookup(path) {
        OcsfLookup::Known(info) => Some(info),
        OcsfLookup::Unknown { .. } => None,
    }
}

/// Every path that an nPL `path` must also consult: the path itself plus any
/// superseded spelling that was renamed TO it (and, symmetrically, the new
/// spelling when an old name is queried). Order: the queried path first.
pub fn equivalent_paths(path: &str) -> Vec<String> {
    let mut out = vec![path.to_string()];
    for a in &registry().aliases {
        if a.to == path && !out.contains(&a.from) {
            out.push(a.from.clone());
        }
        if a.from == path && !out.contains(&a.to) {
            out.push(a.to.clone());
        }
    }
    out
}

/// All registered cross-version renames.
pub fn aliases() -> &'static [AliasEntry] {
    &registry().aliases
}

/// The embedded `(version, gzip contract)` pairs, oldest first. The offline
/// event validator (`parsers::ocsf_validation`) decodes the same files with
/// the requirement, constraint and data-type detail this registry ignores.
pub fn embedded_contracts() -> &'static [(&'static str, &'static [u8])] {
    CONTRACTS
}

/// Embedded OCSF versions, oldest first.
pub fn versions() -> Vec<&'static str> {
    registry().versions.iter().map(|v| v.version).collect()
}

/// Class name (`process_activity`) for a `class_uid`, from the newest version
/// that defines it.
pub fn class_name(class_uid: i64) -> Option<&'static str> {
    registry()
        .versions
        .iter()
        .rev()
        .find_map(|v| v.class_names.get(&class_uid).map(String::as_str))
}

const MAX_SUGGEST_SEGMENT_LEN: usize = 64;

fn suggest(v: &Version, segments: &[&str], fail_at: usize) -> Vec<String> {
    // Re-walk to the level where the failure happened.
    let mut level = &v.top;
    for seg in &segments[..fail_at.min(segments.len())] {
        let Some(attr) = level.get(*seg) else {
            return Vec::new();
        };
        match attr.object_type.as_deref().and_then(|o| v.objects.get(o)) {
            Some(obj) => level = obj,
            None => return Vec::new(),
        }
    }
    let Some(bad) = segments.get(fail_at) else {
        return Vec::new();
    };
    // The segment is user input and edit distance is O(len × key len) per
    // attribute at this level; no OCSF attribute name is anywhere near this long.
    if bad.len() > MAX_SUGGEST_SEGMENT_LEN {
        return Vec::new();
    }
    let prefix = segments[..fail_at].join(".");
    let max = (bad.len() / 3).max(2);
    let mut scored: Vec<(usize, &String)> = level
        .keys()
        .map(|k| (edit_distance(bad, k), k))
        .filter(|(d, _)| *d <= max)
        .collect();
    scored.sort();
    scored
        .into_iter()
        .take(3)
        .map(|(_, k)| {
            if prefix.is_empty() {
                k.clone()
            } else {
                format!("{prefix}.{k}")
            }
        })
        .collect()
}

fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.iter().enumerate() {
        let mut cur = vec![i + 1; b.len() + 1];
        for (j, cb) in b.iter().enumerate() {
            let cost = usize::from(ca != cb);
            cur[j + 1] = (prev[j + 1] + 1).min(cur[j] + 1).min(prev[j] + cost);
        }
        prev = cur;
    }
    prev[b.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_1_9_and_resolves_scalar_leaves() {
        assert_eq!(versions(), vec!["1.9.0"]);
        let i = known("process.cmd_line").expect("process.cmd_line is OCSF");
        assert_eq!(i.leaf, OcsfLeafType::String);
        assert!(!i.is_multi_valued());
        assert_eq!(i.version, "1.9.0");
        assert_eq!(known("src_endpoint.port").unwrap().leaf, OcsfLeafType::Integer);
        assert_eq!(known("time").unwrap().leaf, OcsfLeafType::Long);
        assert_eq!(known("is_mfa").unwrap().leaf, OcsfLeafType::Boolean);
    }

    #[test]
    fn marks_array_segments() {
        let i = known("answers.rdata").expect("dns answers");
        assert_eq!(i.arrays, vec![true, false]);
        assert_eq!(i.array_depth(), 1);
        let h = known("evidences.process.file.hashes.value").expect("nested arrays");
        assert_eq!(h.array_depth(), 2);
        assert!(known("observables.value").unwrap().is_multi_valued());
        // arrays of scalars are multi-valued too
        assert!(known("metadata.profiles").unwrap().is_multi_valued());
    }

    #[test]
    fn recurses_through_self_referential_objects() {
        assert!(known("actor.process.parent_process.parent_process.cmd_line").is_some());
    }

    #[test]
    fn objects_and_unknowns() {
        assert_eq!(known("src_endpoint").unwrap().leaf, OcsfLeafType::Object);
        assert!(known("src_endpoint.ipp").is_none());
        match lookup("src_endpoint.ipp") {
            OcsfLookup::Unknown { suggestions } => {
                assert!(suggestions.contains(&"src_endpoint.ip".to_string()), "{suggestions:?}")
            }
            other => panic!("{other:?}"),
        }
        // scalar leaves have no children
        assert!(known("process.name.extra").is_none());
        assert!(known("").is_none());
        assert!(known("a..b").is_none());
    }

    #[test]
    fn every_rule_field_of_the_content_repo_shape_resolves() {
        // The hottest 1.9 rule fields (nano-rs/rules main) must all be OCSF.
        for f in [
            "actor.user.name",
            "device.hostname",
            "process.cmd_line",
            "process.file.hashes.value",
            "actor.process.file.hashes.value",
            "metadata.event_code",
            "metadata.log_source",
            "http_request.url.url_string",
            "logon_type_id",
            "disposition_id",
            "module.file.signatures.state",
            "actual_permissions",
        ] {
            assert!(known(f).is_some(), "{f} should be a 1.9 attribute");
        }
    }

    #[test]
    fn class_names_come_from_the_contract() {
        assert_eq!(class_name(1007), Some("process_activity"));
        assert_eq!(class_name(4003), Some("dns_activity"));
        assert_eq!(class_name(-1), None);
    }

    #[test]
    fn alias_targets_are_known_paths() {
        for a in aliases() {
            assert!(known(&a.to).is_some(), "alias target {} must be OCSF", a.to);
            let eq = equivalent_paths(&a.to);
            assert!(eq.contains(&a.from));
        }
        assert_eq!(equivalent_paths("process.name"), vec!["process.name".to_string()]);
    }
}
