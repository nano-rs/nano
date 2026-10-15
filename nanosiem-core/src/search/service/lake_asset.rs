// SPDX-License-Identifier: AGPL-3.0-or-later

//! Canonical OCSF 1.9 implementation of the Asset product view.
//!
//! The `_*` and flat keys returned here are an explicit frontend DTO. They are
//! never sent back to the lake worker as fields. Every storage predicate below
//! uses an exact OCSF path, and arbitrary legacy UDM names fail closed.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use super::asset_dossier::{
    AssetActivityTimeline, AssetAuthSummary, AssetDnsSummary, AssetDossier, AssetFilesSummary,
    AssetIdentity, AssetLogSource, AssetNetworkSummary, AssetProcessesSummary, AuthRecent, DnsTop,
    FileRecent, NetworkDest, ProcessRare, ProcessTop,
};
use super::core_search::{parse_lake_timestamp, set_lake_ocsf_value_if_empty};
use super::lake_views::lake_product_cursor;
use super::*;
use crate::auth::{ArtifactScope, ScopeSet};
use crate::prevalence::TimeWindow as PrevalenceTimeWindow;
use crate::query::{Command, Query};
use crate::search::query_processing::{extract_asset_identifier_from_query, AssetCommandInfo};

#[path = "lake_asset_snapshot.rs"]
mod snapshot;

#[path = "lake_asset_cards.rs"]
mod cards;
use cards::{
    card_hash_values, CARD_ACTOR_CMD, CARD_ACTOR_HASH, CARD_BUCKET, CARD_BYTES_IN,
    CARD_BYTES_OUT, CARD_FIRST_SEEN, CARD_PROCESS_CMD, CARD_PROCESS_HASH, CARD_WEIGHT,
};
pub use cards::{LakeAssetCardRead, LakeAssetCards};

use super::asset_dossier::{ProductViewProgress, RARITY_UNAVAILABLE};

/// NAN-3094: how long one view request waits on the shared snapshot before it
/// answers with what the snapshot covers so far (the client polls the rest).
const LAKE_ASSET_VIEW_WAIT: std::time::Duration = std::time::Duration::from_secs(2);

const LAKE_ASSET_SCAN_CAP: usize = 50_000;
const LAKE_ASSET_PAGE_SIZE: usize = 200;
const LAKE_ASSET_IDENTITY_CAP: usize = 200;
/// NAN-3291: time granularity of one IP -> host resolution binding.
const LAKE_ASSET_RESOLVE_BUCKET: chrono::Duration = chrono::Duration::minutes(15);
/// NAN-3291: most IP -> host bindings one artifact enrichment resolves.
const LAKE_ASSET_RESOLVE_BINDINGS: usize = 512;
// NAN-2361 layer 3: an artifact this asset touched only 1-5 times, in-window,
// can still be globally common (`stackoverflow.com`: 1996 distinct IPs across
// the environment) -- neither the baseline snapshot (broken host coalesce for
// IP-only sources) nor this asset's own in-window rows (scoped to one asset)
// can see that. Global discovery is a real query per borderline artifact, so
// it only runs when the cheaper layers already look "rare" -- anything with
// a healthy host count from either of those is left alone.
const ASSET_GLOBAL_DISCOVERY_HOST_CEILING: u64 = 5;

const LAKE_ASSET_EVENT_PROJECTION: &[&str] = &[
    "time",
    "metadata.uid",
    "metadata.log_source",
    "class_uid",
    "class_name",
    "category_name",
    "status",
    "status_id",
    "api.operation",
    "process.cmd_line",
    "process.name",
    "actor.process.cmd_line",
    "actor.process.name",
    "activity_name",
    "user.name",
    "actor.user.name",
    "device.hostname",
    "src_endpoint.hostname",
    "src_endpoint.ip",
    "dst_endpoint.hostname",
    "dst_endpoint.ip",
    "query.hostname",
    "file.name",
    "file.path",
    "http_request.url.url_string",
];

/// NAN-3059: the exact columns the dossier / artifact assemblers read. The
/// asset row read used to materialize FULL OCSF events (`predicate | sort
/// -time`); on the lean cell that locate-then-fetch of every column was the
/// dominant cost (live 1h: 10.3 s full rows vs 3.6 s projected, same 400
/// rows). Hash arrays are projected as their `.value` leaves, which the
/// readers below accept alongside the nested `[{value}]` shape.
const LAKE_ASSET_ROW_PROJECTION: &[&str] = &[
    "time",
    "metadata.uid",
    "metadata.log_source",
    "metadata.product.name",
    "metadata.product.vendor_name",
    "class_uid",
    "class_name",
    "category_name",
    "activity_name",
    "activity_id",
    "status",
    "status_id",
    "auth_protocol",
    "logon_type",
    "raw_data_size",
    "api.operation",
    "device.hostname",
    "src_endpoint.hostname",
    "src_endpoint.ip",
    "src_endpoint.mac",
    "dst_endpoint.hostname",
    "dst_endpoint.ip",
    "dst_endpoint.mac",
    "dst_endpoint.port",
    "actor.user.name",
    "user.name",
    "process.name",
    "process.cmd_line",
    "process.file.hashes.value",
    "actor.process.name",
    "actor.process.cmd_line",
    "actor.process.file.hashes.value",
    "file.name",
    "file.path",
    "file.hashes.value",
    "query.hostname",
    "http_request.url.hostname",
    "url.hostname",
    "traffic.bytes_in",
    "traffic.bytes_out",
    "unmapped.error_message",
    "unmapped.failure_reason",
    "unmapped.logon_type",
    "unmapped.signed",
    "unmapped.status",
];

/// Hash values under `<prefix>.hashes` in either row shape: nested full
/// events carry `[{algorithm_id, value}]`, projected rows the flat
/// `<prefix>.hashes.value` leaf array.
fn lake_hash_values(row: &Value, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(values) = lake_value(row, &format!("{prefix}.hashes")).and_then(Value::as_array) {
        out.extend(
            values
                .iter()
                .filter_map(|value| value.get("value").and_then(Value::as_str))
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        );
    }
    if let Some(values) = row.get(&format!("{prefix}.hashes.value")).and_then(Value::as_array) {
        out.extend(
            values
                .iter()
                .filter_map(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_string),
        );
    }
    out
}

const LAKE_ASSET_FIELDS: &[&str] = &[
    "src_endpoint.hostname",
    "dst_endpoint.hostname",
    "device.hostname",
    "src_endpoint.ip",
    "dst_endpoint.ip",
    "user.name",
    "actor.user.name",
    "src_endpoint.mac",
    "dst_endpoint.mac",
    "device.ip",
    "user.email_addr",
    "actor.user.email_addr",
];

/// NAN-3689: identity paths an asset pivot reads that have no entity-range
/// rows. Parsers write them (EDR / Entra / Okta `device.ip`, IdP
/// `*.email_addr`), so a pivot without them silently missed those rows.
/// NAN-3694 gives them Parquet blooms and candidate hints (an OR leg on one
/// prunes like any identity leg, and a file that stores no such leaf proves
/// the leg absent), but `/v1/entity/ranges` still refuses them: older parts
/// carry no range rows, so first/last seen comes from the other paths only.
/// A pivot names one only when the tenant actually stores it (see
/// [`lake_asset_rangeless_fields`]).
pub(super) const LAKE_ASSET_RANGELESS_FIELDS: &[&str] =
    &["device.ip", "user.email_addr", "actor.user.email_addr"];

/// The [`LAKE_ASSET_RANGELESS_FIELDS`] an asset pivot should read for a tenant
/// whose stored field inventory is `stored` (the active lake profile's
/// snapshot leaves). A path the tenant has never stored matches no row, so
/// naming it only adds a leg to every pivot. An empty inventory is unknown,
/// not empty: every path is kept.
pub(super) fn lake_asset_rangeless_fields(stored: &[(String, crate::schema::FieldType)]) -> Vec<&'static str> {
    LAKE_ASSET_RANGELESS_FIELDS
        .iter()
        .copied()
        .filter(|field| stored.is_empty() || stored.iter().any(|(path, _)| path == field))
        .collect()
}

fn lake_value<'a>(row: &'a Value, path: &str) -> Option<&'a Value> {
    row.get(path)
        .or_else(|| path.split('.').try_fold(row, |value, part| value.get(part)))
}

fn lake_string(row: &Value, path: &str) -> Option<String> {
    match lake_value(row, path)? {
        Value::String(value) if !value.is_empty() => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn lake_u64(row: &Value, path: &str) -> Option<u64> {
    lake_value(row, path).and_then(Value::as_u64)
}

/// NAN-3465: the nPL form of "this OCSF event's outcome is Failure". OCSF
/// `status_id` (1 Success, 2 Failure) is authoritative; the `status` caption
/// decides only when `status_id` is neither (null, 0 Unknown, 99 Other).
/// Producers that fill only `status_id` (Windows / Sysmon via Tenzir, the
/// open-core sweep's brute force) left `status` null, and the dossier read
/// every failed logon as a success. `NOT` compiles null-safe
/// (`NOT ifNull(…, false)`), so a null `status_id` falls through to the
/// caption in both search predicates and `eval` expressions.
pub(super) const LAKE_STATUS_FAILURE_NPL: &str =
    "(status_id=2 OR (NOT status_id=1 AND lower(status)=\"failure\"))";

/// NAN-3465: the Rust twin of [`LAKE_STATUS_FAILURE_NPL`] over one lake row.
fn lake_status_failed(row: &Value) -> bool {
    let status_id = match lake_value(row, "status_id") {
        Some(Value::Number(value)) => value.as_u64(),
        Some(Value::String(value)) => value.trim().parse::<u64>().ok(),
        _ => None,
    };
    match status_id {
        Some(2) => true,
        Some(1) => false,
        _ => lake_string(row, "status").is_some_and(|value| value.eq_ignore_ascii_case("failure")),
    }
}

/// NAN-3262: how many events a row stands for. An event row is one; a card
/// aggregate group (`lake_asset_cards`) carries its `count()` as
/// [`CARD_WEIGHT`], so the same assemblers fold events and groups alike.
fn row_weight(row: &Value) -> u64 {
    match row.get(CARD_WEIGHT) {
        Some(Value::Number(value)) => value
            .as_u64()
            .or_else(|| value.as_f64().map(|value| value.max(0.0) as u64))
            .unwrap_or(0),
        Some(Value::String(value)) => value.trim().parse().unwrap_or(0),
        _ => 1,
    }
}

/// A numeric field of a row or, on a card group, its pre-summed alias.
fn row_sum(row: &Value, group_alias: &str, path: &str) -> u64 {
    match row.get(group_alias) {
        Some(Value::Number(value)) => value
            .as_u64()
            .or_else(|| value.as_f64().map(|value| value.max(0.0) as u64))
            .unwrap_or(0),
        Some(Value::String(value)) => value.trim().parse().unwrap_or(0),
        Some(_) => 0,
        None => lake_u64(row, path).unwrap_or(0),
    }
}

fn safe_literal(value: &str, description: &str) -> Result<String, SearchError> {
    if value.is_empty()
        || value.len() > 2_048
        || value.chars().any(char::is_control)
        || (value.contains('"') && value.contains('\''))
    {
        return Err(SearchError::SqlValidationError(format!(
            "{description} cannot be represented safely in nPL"
        )));
    }
    Ok(crate::query::npl_quoted_literal(value))
}

/// Hash paths an artifact can appear under, mirroring
/// `collect_artifact_occurrences`.
const LAKE_ASSET_HASH_PATHS: &[&str] = &[
    "file.hashes.value",
    "process.file.hashes.value",
    "actor.process.file.hashes.value",
];

/// One predicate matching any of `artifacts` (`(value, is_hash)`) across every
/// OCSF path it can appear under, mirroring `collect_artifact_occurrences`
/// (hash paths) and the frontend's `DOMAIN_PATHS` (`inWindowObservation.ts` /
/// `Search.tsx`'s drilldown builder) exactly -- a global discovery query that
/// missed one of these paths would silently undercount the same way the
/// original `in_window_host_counts` did before it covered all three hash
/// paths.
///
/// NAN-3276: grouped by path, not by artifact: one `path IN (…)` list per
/// path (`lower(col) IN (…)` for a domain column, one `arrayExists(… IN …)`
/// for a hash array), so the predicate has a fixed number of legs and
/// constant nesting depth whatever the artifact count. The per-artifact
/// `(a OR b OR c) OR (…) OR …` form nested one level per artifact and its
/// compiled SQL exceeded the lake compiler's parser depth at 50 artifacts.
pub(super) fn build_global_artifacts_predicate<'a>(
    artifacts: impl IntoIterator<Item = (&'a str, bool)>,
) -> Result<String, SearchError> {
    let (mut hashes, mut domains) = (Vec::new(), Vec::new());
    for (artifact, is_hash) in artifacts {
        let literal = safe_literal(artifact, "artifact")?;
        if is_hash {
            hashes.push(literal);
        } else {
            domains.push(literal);
        }
    }
    let mut legs = Vec::new();
    for (paths, literals) in [
        (LAKE_ASSET_HASH_PATHS, &hashes),
        (LAKE_ASSET_DOMAIN_PATHS, &domains),
    ] {
        if !literals.is_empty() {
            let list = literals.join(", ");
            legs.extend(paths.iter().map(|path| format!("{path} IN ({list})")));
        }
    }
    if legs.is_empty() {
        return Err(SearchError::SqlValidationError(
            "global artifact predicate needs at least one artifact".to_string(),
        ));
    }
    Ok(format!("({})", legs.join(" OR ")))
}

fn strip_asset_and_after(query: &Query) -> Query {
    match query {
        Query::Search(_) => query.clone(),
        Query::Piped { source, command } => {
            let stripped = strip_asset_and_after(source);
            if matches!(command, Command::Asset { .. }) || query_contains_asset(source) {
                stripped
            } else {
                Query::Piped {
                    source: Box::new(stripped),
                    command: command.clone(),
                }
            }
        }
    }
}

fn query_contains_asset(query: &Query) -> bool {
    match query {
        Query::Search(_) => false,
        Query::Piped { source, command } => {
            matches!(command, Command::Asset { .. }) || query_contains_asset(source)
        }
    }
}

fn asset_semantic(field: &str) -> Option<&'static str> {
    match field {
        "src_endpoint.ip" | "dst_endpoint.ip" | "device.ip" => Some("ip"),
        "src_endpoint.hostname" | "dst_endpoint.hostname" | "device.hostname" => Some("host"),
        "user.name" | "actor.user.name" | "user.email_addr" | "actor.user.email_addr" => Some("user"),
        "src_endpoint.mac" | "dst_endpoint.mac" => Some("mac"),
        _ => None,
    }
}

/// Every identity path of `semantic`, indexed paths first (so the auto-detect
/// walk and every slice start on the paths with sidecar hints), then the
/// [`LAKE_ASSET_RANGELESS_FIELDS`] of that kind that `rangeless` admits.
fn asset_fields_for_semantic(semantic: &str, rangeless: &[&'static str]) -> Vec<&'static str> {
    let extra: &[&'static str] = match semantic {
        "ip" => &["device.ip"],
        "user" => &["user.email_addr", "actor.user.email_addr"],
        _ => &[],
    };
    asset_indexed_fields_for_semantic(semantic)
        .iter()
        .chain(extra.iter().filter(|field| rangeless.contains(field)))
        .copied()
        .collect()
}

fn asset_indexed_fields_for_semantic(semantic: &str) -> &'static [&'static str] {
    match semantic {
        "ip" => &["src_endpoint.ip", "dst_endpoint.ip"],
        "host" => &[
            "src_endpoint.hostname",
            "device.hostname",
            "dst_endpoint.hostname",
        ],
        "user" => &["user.name", "actor.user.name"],
        "mac" => &["src_endpoint.mac", "dst_endpoint.mac"],
        _ => &[],
    }
}

/// NAN-3262: the lake compiler turns an OR of at most this many exact
/// equalities into ONE candidate-hint union (`MAX_CANDIDATE_HINTS` in
/// `lake_query_compile`), so the worker reads only the parts its entity /
/// keyword sidecars name. `field IN (...)` yields no hint at all, and neither
/// does a longer OR: the asset predicate used to be both, so every asset read
/// scanned every part of the window (live: 55 s for one host-hour whose
/// single-field `stats count` takes 1.5 s).
const LAKE_ASSET_HINT_TERMS: usize = 8;
/// Most disjoint hintable slices one asset read is split into before it
/// falls back to the single (unhinted) predicate.
const LAKE_ASSET_MAX_SLICES: usize = 3;

/// One `field=literal` equality per (identity field, value). `=` compiles to
/// exactly the SQL `IN` did (exact match, plus the `startsWith` short-host
/// expansion for a dotless host), but each equality carries a sidecar hint.
fn asset_predicate_terms(
    identifier_field: &str,
    identifier_value: &str,
    identities: &[Value],
    rangeless: &[&'static str],
) -> Result<(Vec<String>, Vec<String>), SearchError> {
    let values = asset_identity_values(identifier_field, identifier_value, identities)?;
    let seed = asset_semantic(identifier_field);
    let mut terms = Vec::new();
    let mut in_lists = Vec::new();
    for (kind, kind_values) in values {
        let literals = kind_values
            .iter()
            .map(|value| Ok((value.contains('@'), safe_literal(value, "asset identifier")?)))
            .collect::<Result<Vec<_>, SearchError>>()?;
        // NAN-3689: rangeless paths only for the pivot's own kind. A host
        // pivot binds the host's IPs too; widening those onto `device.ip`
        // would add a leg to every host dossier for no host semantics.
        let fields = if seed == Some(kind) {
            asset_fields_for_semantic(kind, rangeless)
        } else {
            asset_indexed_fields_for_semantic(kind).to_vec()
        };
        for field in fields {
            // An `*.email_addr` leg can only match an address: a bare
            // username never pays its unhinted scan.
            let email_only = field.ends_with(".email_addr");
            let literals = literals
                .iter()
                .filter(|(is_address, _)| *is_address || !email_only)
                .map(|(_, literal)| literal.as_str())
                .collect::<Vec<_>>();
            if literals.is_empty() {
                continue;
            }
            in_lists.push(format!("{field} IN ({})", literals.join(",")));
            terms.extend(literals.iter().map(|literal| format!("{field}={literal}")));
        }
    }
    if in_lists.is_empty() {
        return Err(SearchError::SqlValidationError(
            "asset query did not contain a usable canonical identifier".to_string(),
        ));
    }
    Ok((terms, in_lists))
}

/// Kill switch: `NANO_LAKE_ASSET_IN_PREDICATE=1` restores the unhinted
/// `IN` predicate (a hinted entity read takes the worker's whole-file pivot
/// fetch instead of column ranges; see NAN-3262).
fn asset_predicate_hinted() -> bool {
    std::env::var("NANO_LAKE_ASSET_IN_PREDICATE").as_deref() != Ok("1")
}

fn checked_predicate(predicate: String) -> Result<String, SearchError> {
    if predicate.len() > 262_144 {
        return Err(SearchError::ResourceExhausted(
            "resolved Asset identity predicate exceeds the lake compiler envelope".to_string(),
        ));
    }
    Ok(predicate)
}

fn build_lake_asset_predicate(
    identifier_field: &str,
    identifier_value: &str,
    identities: &[Value],
    rangeless: &[&'static str],
) -> Result<String, SearchError> {
    let (terms, in_lists) =
        asset_predicate_terms(identifier_field, identifier_value, identities, rangeless)?;
    checked_predicate(if terms.len() <= LAKE_ASSET_HINT_TERMS && asset_predicate_hinted() {
        format!("({})", terms.join(" OR "))
    } else {
        format!("({})", in_lists.join(" OR "))
    })
}

/// NAN-3262: the asset predicate as disjoint slices that each fit one
/// candidate-hint union. Their union is exactly [`build_lake_asset_predicate`]
/// and no event matches two of them (each later slice excludes the earlier
/// ones with an opaque `NOT`, which leaves its own hint intact), so counts and
/// rows from the slices add up without double counting. An identity set too
/// large to slice is one unhinted predicate, as before.
fn build_lake_asset_predicate_slices(
    identifier_field: &str,
    identifier_value: &str,
    identities: &[Value],
    rangeless: &[&'static str],
) -> Result<Vec<String>, SearchError> {
    let (terms, _) =
        asset_predicate_terms(identifier_field, identifier_value, identities, rangeless)?;
    let groups = terms.chunks(LAKE_ASSET_HINT_TERMS).collect::<Vec<_>>();
    if groups.len() <= 1 || groups.len() > LAKE_ASSET_MAX_SLICES || !asset_predicate_hinted() {
        return Ok(vec![build_lake_asset_predicate(
            identifier_field,
            identifier_value,
            identities,
            rangeless,
        )?]);
    }
    let unions = groups
        .iter()
        .map(|group| format!("({})", group.join(" OR ")))
        .collect::<Vec<_>>();
    unions
        .iter()
        .enumerate()
        .map(|(index, union)| {
            checked_predicate(if index == 0 {
                union.clone()
            } else {
                format!("({union} AND NOT ({}))", unions[..index].join(" OR "))
            })
        })
        .collect()
}

/// NAN-3094: the `(identity path, values)` lookups that cover exactly the
/// asset predicate's identities, for `/v1/entity/ranges`.
fn asset_entity_range_lookups(
    identifier_field: &str,
    identifier_value: &str,
    identities: &[Value],
) -> Result<Vec<(&'static str, Vec<String>)>, SearchError> {
    let values = asset_identity_values(identifier_field, identifier_value, identities)?;
    let mut lookups = Vec::new();
    for (kind, kind_values) in values {
        let kind_values = kind_values.into_iter().collect::<Vec<_>>();
        for chunk in kind_values.chunks(1_000) {
            // The worker serves entity ranges for indexed paths only.
            for field in asset_indexed_fields_for_semantic(kind) {
                lookups.push((*field, chunk.to_vec()));
            }
        }
    }
    Ok(lookups)
}

/// The identity values one identity tuple adds to the asset whose identifier
/// is `identifier_value` (of `semantic`): none unless the tuple is DIRECTLY
/// related to the seed (same host / IP / user / MAC). A tuple that only shares
/// a peer, a user or an endpoint with the asset adds nothing.
fn related_identity_values(
    semantic: &str,
    identifier_value: &str,
    identity: &Value,
) -> Vec<(&'static str, String)> {
    let field = |name: &str| {
        identity
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    let (ip, hostname, user, mac) = (field("ip"), field("hostname"), field("user"), field("mac"));
    let seed = identifier_value.to_ascii_lowercase();
    let same_host = |candidate: &str| {
        let candidate = candidate.to_ascii_lowercase();
        candidate == seed || candidate.split('.').next() == seed.split('.').next()
    };
    let directly_related = match semantic {
        "host" => hostname.is_some_and(same_host),
        "ip" => ip.is_some_and(|value| value.eq_ignore_ascii_case(identifier_value)),
        "user" => user.is_some_and(|value| value.eq_ignore_ascii_case(identifier_value)),
        "mac" => mac.is_some_and(|value| value.eq_ignore_ascii_case(identifier_value)),
        _ => false,
    };
    if !directly_related {
        return Vec::new();
    }
    let mut out = Vec::new();
    if let Some(value) = ip {
        out.push(("ip", value.to_string()));
    }
    if let Some(value) = hostname {
        out.push(("host", value.to_string()));
    }
    if semantic == "user" {
        if let Some(value) = user {
            out.push(("user", value.to_string()));
        }
    }
    if let Some(value) = mac {
        out.push(("mac", value.to_string()));
    }
    out
}

/// Identity values of the asset, by semantic (`host`, `ip`, `user`, `mac`).
fn asset_identity_values(
    identifier_field: &str,
    identifier_value: &str,
    identities: &[Value],
) -> Result<BTreeMap<&'static str, BTreeSet<String>>, SearchError> {
    let semantic = asset_semantic(identifier_field).ok_or_else(|| {
        SearchError::SqlValidationError(format!(
            "asset identifier field {identifier_field:?} is not an exact OCSF field; supported: {}",
            LAKE_ASSET_FIELDS.join(", ")
        ))
    })?;
    if identities.len() > LAKE_ASSET_IDENTITY_CAP {
        return Err(SearchError::SqlValidationError(format!(
            "asset identity set is limited to {LAKE_ASSET_IDENTITY_CAP} rows"
        )));
    }

    let mut values: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    values
        .entry(semantic)
        .or_default()
        .insert(identifier_value.to_string());
    for identity in identities {
        for (kind, value) in related_identity_values(semantic, identifier_value, identity) {
            values.entry(kind).or_default().insert(value);
        }
    }

    // NAN-2361: bind a host by BOTH spellings, whichever one the analyst typed.
    //
    // The nPL generator expands a dotless hostname to `= v OR startsWith(v.)`,
    // so a short name already reaches the FQDN rows. The reverse is not true —
    // an FQDN literal is exact — so opening the dossier by FQDN silently
    // dropped every row a source recorded under the short name, and the same
    // host answered with two different event sets depending on how you spelled
    // it. The ClickHouse path derives both directions (`asset.rs`); this is the
    // lake equivalent, kept here (rather than in the generator) because turning
    // an FQDN into a short name is an ASSET-identity judgement, not a general
    // query-language rule.
    if let Some(hosts) = values.get("host") {
        let short_forms = hosts
            .iter()
            .filter_map(|value| value.split_once('.').map(|(short, _)| short.to_string()))
            .filter(|short| !short.is_empty())
            .collect::<Vec<_>>();
        if !short_forms.is_empty() {
            values.entry("host").or_default().extend(short_forms);
        }
    }

    Ok(values)
}

/// Accepted `| asset field=…` forms on the lake, for error messages.
const LAKE_ASSET_FIELD_FORMS: &str = "an exact OCSF identifier (src_endpoint.hostname, \
dst_endpoint.hostname, device.hostname, src_endpoint.ip, dst_endpoint.ip, user.name, \
actor.user.name, src_endpoint.mac, dst_endpoint.mac, device.ip, user.email_addr, \
actor.user.email_addr), a UDM alias (user, src_ip, dest_ip, \
src_host, dest_host, host), or an identity kind (host, ip, user, mac)";

/// Resolve an `| asset field=…` argument to the OCSF identity fields to read
/// (NAN-3258). An exact OCSF identifier stays exactly that one field. A UDM
/// alias (`user`, `src_ip`, `host`, …) or a bare identity kind (`ip`, `mac`)
/// resolves through the lake 1.9 UDM→OCSF alias map to its OCSF target and
/// widens to every OCSF field of the same identity kind (target first), so
/// `field=user` reads both `user.name` and `actor.user.name`. Anything else is
/// refused with an error that names the accepted forms. Field-based only:
/// nothing here keys on a log source.
fn resolve_lake_asset_fields(field: &str) -> Result<Vec<&'static str>, SearchError> {
    if let Some(exact) = LAKE_ASSET_FIELDS.iter().copied().find(|f| *f == field) {
        return Ok(vec![exact]);
    }
    let lowered = field.trim().to_ascii_lowercase();
    // UDM alias → OCSF path through the lake 1.9 alias map. Class-spanning
    // concepts (`src_host`, `dest_host`, …) stay un-rewritten by
    // `canonicalize`; their OCSF source paths come from the same profile's
    // class-split map (primary path first).
    let target = {
        use crate::schema::SchemaProfile;
        let profile = crate::schema::OcsfProfile::lake_1_9();
        let canonical = profile.canonicalize(&lowered).into_owned();
        let mut candidates = vec![canonical.clone()];
        if let Some((primary, fallback)) = profile.class_split_source_fields(&canonical) {
            candidates.push(primary.to_string());
            candidates.push(fallback.to_string());
        }
        candidates
            .into_iter()
            .find_map(|candidate| LAKE_ASSET_FIELDS.iter().copied().find(|f| *f == candidate))
    };
    let semantic = target.and_then(asset_semantic).or(match lowered.as_str() {
        "host" | "hostname" => Some("host"),
        "ip" => Some("ip"),
        "user" | "username" => Some("user"),
        "mac" => Some("mac"),
        _ => None,
    });
    let Some(semantic) = semantic else {
        return Err(SearchError::SqlValidationError(format!(
            "asset field {field:?} is not a supported asset identifier; use {LAKE_ASSET_FIELD_FORMS}"
        )));
    };
    let mut fields: Vec<&'static str> = target.into_iter().collect();
    for f in asset_fields_for_semantic(semantic, LAKE_ASSET_RANGELESS_FIELDS) {
        if !fields.contains(&f) {
            fields.push(f);
        }
    }
    Ok(fields)
}

fn detect_identifier(rows: &[Value], fields: &[&str]) -> Result<(String, String), SearchError> {
    for row in rows.iter().take(10) {
        for field in fields {
            if let Some(value) = lake_string(row, field) {
                return Ok(((*field).to_string(), value));
            }
        }
    }
    Err(SearchError::SqlValidationError(format!(
        "could not auto-detect an OCSF asset identifier; use field=<{LAKE_ASSET_FIELD_FORMS}>"
    )))
}

fn lake_event_kind(row: &Value) -> String {
    match lake_u64(row, "class_uid") {
        Some(1001) => "FILE".to_string(),
        Some(1007) => "PROCESS".to_string(),
        Some(3002) => {
            if lake_status_failed(row) {
                "AUTH_FAILURE".to_string()
            } else {
                "AUTH_SUCCESS".to_string()
            }
        }
        Some(4001) => "NETWORK".to_string(),
        Some(4003) => "DNS".to_string(),
        Some(6003) => "CLOUD_API".to_string(),
        _ => lake_string(row, "class_name")
            .or_else(|| lake_string(row, "category_name"))
            .unwrap_or_else(|| "OTHER".to_string())
            .to_ascii_uppercase()
            .replace(' ', "_"),
    }
}

fn lake_event_summary(row: &Value) -> String {
    lake_string(row, "api.operation")
        .or_else(|| lake_string(row, "process.cmd_line"))
        .or_else(|| lake_string(row, "process.name"))
        .or_else(|| lake_string(row, "actor.process.cmd_line"))
        .or_else(|| lake_string(row, "actor.process.name"))
        .or_else(|| lake_string(row, "activity_name"))
        .or_else(|| lake_string(row, "class_name"))
        .unwrap_or_else(|| "OCSF event".to_string())
}

fn asset_event_dto(row: &Value, ordinal: usize) -> Value {
    let mut row = row.clone();
    if let Some(object) = row.as_object_mut() {
        object.remove(ASSET_PAGE_PROJECTION_ALIAS);
    }
    let row = &row;
    json!({
        "id": lake_string(row, "metadata.uid").unwrap_or_else(|| format!("event-{ordinal}")),
        "timestamp": lake_string(row, "time").unwrap_or_default(),
        "source_type": lake_string(row, "metadata.log_source").unwrap_or_else(|| "unknown".to_string()),
        "event_kind": lake_event_kind(row),
        "summary": lake_event_summary(row),
        "details": row,
    })
}

/// Alias the page query's projection eval writes; removed from every row.
const ASSET_PAGE_PROJECTION_ALIAS: &str = "asset_page_projection";

/// NAN-3094: the Asset event page as a newest-first event query.
///
/// `| table … | sort -time -metadata.uid` compiled to an unordered outer
/// SELECT that query[T] can only answer by scanning the WHOLE window before
/// the first row (a chatty host: 25-46 s at 4 h, a 504 at 24 h). The bare
/// predicate keeps the compiler's newest-first contract, so query[T] walks
/// widening chunks from the newest data and stops once the page is full
/// (~2 s). The eval names every column the event DTO reads, and the page is
/// requested with `table_view`, which then projects exactly those columns
/// instead of whole OCSF events.
fn asset_page_query(filtered: &str) -> String {
    format!(
        "{filtered} | eval {ASSET_PAGE_PROJECTION_ALIAS}=coalesce({})",
        LAKE_ASSET_EVENT_PROJECTION
            .iter()
            .map(|field| format!("tostring({field})"))
            .collect::<Vec<_>>()
            .join(",")
    )
}

/// Most `(source, class, auth failure, user)` groups one summary returns.
const LAKE_ASSET_SUMMARY_GROUP_CAP: usize = 10_000;

/// NAN-3094: the Asset total and every facet from ONE grouped aggregate
/// (was three parallel scans of the same rows).
fn asset_summary_query(filtered: &str) -> String {
    format!(
        "{filtered} | eval asset_user=coalesce(actor.user.name,user.name), \
         asset_auth_failure=if(class_uid=3002 AND {LAKE_STATUS_FAILURE_NPL}, 1, 0) \
         | stats count() as event_count by metadata.log_source, class_uid, asset_auth_failure, asset_user"
    )
}

/// Total and facets from [`asset_summary_query`] rows, with the labels of
/// the event DTO (`lake_event_kind`).
fn asset_facets_from_grouped_rows(rows: &[Value]) -> (u64, AssetFacets) {
    let mut total = 0u64;
    let mut kinds = BTreeMap::<&'static str, u64>::new();
    let mut sources = BTreeMap::<String, u64>::new();
    let mut users = BTreeMap::<String, u64>::new();
    for row in rows {
        let count = count_from_row(row);
        total = total.saturating_add(count);
        let failure = lake_u64(row, "asset_auth_failure").unwrap_or(0) == 1
            || lake_string(row, "asset_auth_failure").as_deref() == Some("1");
        let kind = match lake_u64(row, "class_uid") {
            Some(1001) => "FILE",
            Some(1007) => "PROCESS",
            Some(3002) if failure => "AUTH_FAILURE",
            Some(3002) => "AUTH_SUCCESS",
            Some(4001) => "NETWORK",
            Some(4003) => "DNS",
            Some(6003) => "CLOUD_API",
            _ => "OTHER",
        };
        *kinds.entry(kind).or_default() += count;
        if let Some(source) = lake_string(row, "metadata.log_source").filter(|v| !v.is_empty()) {
            *sources.entry(source).or_default() += count;
        }
        if let Some(user) = lake_string(row, "asset_user").filter(|v| !v.is_empty()) {
            *users.entry(user).or_default() += count;
        }
    }
    let ranked = |counts: BTreeMap<String, u64>| {
        let mut values = counts.into_iter().collect::<Vec<_>>();
        values.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        values.truncate(50);
        values
    };
    let mut event_kind = kinds
        .into_iter()
        .filter(|(_, count)| *count > 0)
        .map(|(kind, count)| (kind.to_string(), count))
        .collect::<Vec<_>>();
    event_kind.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    (
        total,
        AssetFacets {
            source_type: ranked(sources),
            event_kind,
            user: ranked(users),
        },
    )
}

fn quoted_list(values: &[String], description: &str) -> Result<String, SearchError> {
    values
        .iter()
        .map(|value| safe_literal(value, description))
        .collect::<Result<Vec<_>, _>>()
        .map(|values| values.join(","))
}

fn event_kind_predicate(kind: &str) -> Result<String, SearchError> {
    Ok(match kind.to_ascii_uppercase().as_str() {
        "FILE" => "class_uid=1001".to_string(),
        "PROCESS" => "class_uid=1007".to_string(),
        "AUTH_FAILURE" => format!("(class_uid=3002 AND {LAKE_STATUS_FAILURE_NPL})"),
        // NAN-3465: the complement of the failure form, null-safe (`NOT`), so
        // an event with neither `status_id` nor `status` is a success here
        // exactly as it is in `lake_event_kind`.
        "AUTH_SUCCESS" => format!("(class_uid=3002 AND NOT {LAKE_STATUS_FAILURE_NPL})"),
        "NETWORK" => "class_uid=4001".to_string(),
        "DNS" => "class_uid=4003".to_string(),
        "CLOUD_API" => "class_uid=6003".to_string(),
        _ => {
            return Err(SearchError::SqlValidationError(format!(
                "unsupported lake asset event kind {kind:?}"
            )))
        }
    })
}

fn build_asset_filter_predicate(
    filters: Option<&AssetEventFilters>,
) -> Result<Option<String>, SearchError> {
    let Some(filters) = filters else {
        return Ok(None);
    };
    let mut clauses = Vec::new();
    if let Some(values) = filters
        .source_types
        .as_ref()
        .filter(|values| !values.is_empty())
    {
        clauses.push(format!(
            "metadata.log_source IN ({})",
            quoted_list(values, "asset source type")?
        ));
    }
    if let Some(values) = filters
        .event_kinds
        .as_ref()
        .filter(|values| !values.is_empty())
    {
        clauses.push(format!(
            "({})",
            values
                .iter()
                .map(|value| event_kind_predicate(value))
                .collect::<Result<Vec<_>, _>>()?
                .join(" OR ")
        ));
    }
    if let Some(values) = filters.users.as_ref().filter(|values| !values.is_empty()) {
        let values = quoted_list(values, "asset user")?;
        clauses.push(format!(
            "(actor.user.name IN ({values}) OR user.name IN ({values}))"
        ));
    }
    if let Some(term) = filters
        .search_text
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        let literal = safe_literal(term, "asset search text")?;
        clauses.push(format!(
            "({})",
            [
                "message",
                "process.name",
                "process.cmd_line",
                "actor.process.name",
                "actor.process.cmd_line",
                "file.name",
                "file.path",
                "http_request.url.url_string",
                "api.operation",
                "activity_name",
            ]
            .iter()
            .map(|field| format!("{field} contains {literal}"))
            .collect::<Vec<_>>()
            .join(" OR ")
        ));
    }
    Ok((!clauses.is_empty()).then(|| clauses.join(" AND ")))
}

fn apply_asset_filters(
    base: &str,
    filters: Option<&AssetEventFilters>,
) -> Result<String, SearchError> {
    Ok(match build_asset_filter_predicate(filters)? {
        Some(filters) => format!("({base}) AND ({filters})"),
        None => base.to_string(),
    })
}

fn count_from_row(row: &Value) -> u64 {
    lake_u64(row, "event_count")
        .or_else(|| lake_u64(row, "count"))
        .unwrap_or_default()
}

/// Collect distinct identity DTOs from `rows`, stopping at `cap`.
///
/// NAN-2361: `cap` is a parameter rather than a hardcoded
/// `LAKE_ASSET_IDENTITY_CAP` so the DISCOVERY caller can ask for `cap + 1` and
/// therefore distinguish "exactly at the limit" from "over it". Collecting
/// exactly `LAKE_ASSET_IDENTITY_CAP` made a 201-identity asset indistinguishable
/// from a 200-identity one, so the downstream `> cap` overflow check could never
/// fire on discovery alone and the surplus identities were dropped from the
/// predicate in silence — the exact failure the overflow error exists to stop.
fn collect_identity_dtos(rows: &[Value], cap: usize) -> Vec<Value> {
    let mut observations = BTreeMap::<(String, String, String, String), Value>::new();
    for row in rows.iter().take(5_000) {
        let timestamp = lake_string(row, "time").unwrap_or_default();
        let source = lake_string(row, "metadata.log_source").unwrap_or_default();
        for endpoint in ["src_endpoint", "dst_endpoint"] {
            let ip = lake_string(row, &format!("{endpoint}.ip")).unwrap_or_default();
            let hostname = lake_string(row, &format!("{endpoint}.hostname"))
                .or_else(|| lake_string(row, "device.hostname"))
                .unwrap_or_default();
            let mac = lake_string(row, &format!("{endpoint}.mac")).unwrap_or_default();
            let user = lake_string(row, "actor.user.name")
                .or_else(|| lake_string(row, "user.name"))
                .unwrap_or_default();
            if ip.is_empty() && hostname.is_empty() && mac.is_empty() && user.is_empty() {
                continue;
            }
            let key = (ip.clone(), hostname.clone(), user.clone(), mac.clone());
            observations.entry(key).or_insert_with(|| {
                json!({
                    "ip": ip,
                    "hostname": hostname,
                    "user": user,
                    "mac": mac,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "source": source,
                })
            });
            if observations.len() >= cap {
                return observations.into_values().collect();
            }
        }
    }
    observations.into_values().collect()
}

/// Only admit domain-shaped values as domain artifacts.
///
/// `lake_string` guards nothing beyond non-emptiness, so OCSF's literal `"-"`
/// placeholder (and other junk) was plotted as a real domain artifact and
/// counted in the in-window host counts. Mirrors the ClickHouse summary path's
/// `position(col, '.') > 0 AND match(col, '^\d+\.\d+\.\d+\.\d+$') = 0`
/// admission plus the shared placeholder rejection
/// (`lateral_graph::is_placeholder_value`, client `isPlaceholderValue()`).
fn is_lake_domain_artifact(value: &str) -> bool {
    let trimmed = value.trim();
    if super::lateral_graph::is_placeholder_value(trimmed) || !trimmed.contains('.') {
        return false;
    }
    // All-numeric dotted labels (IPv4 literals and the like) are not domains.
    !trimmed
        .split('.')
        .all(|label| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit()))
}

/// Every OCSF path a domain artifact can occupy. Single source of truth shared
/// by the occurrence collector and the global-discovery predicate so the two
/// can never disagree about what "a domain sighting" means.
const LAKE_ASSET_DOMAIN_PATHS: &[&str] = &[
    "query.hostname",
    "http_request.url.hostname",
    "url.hostname",
    "dst_endpoint.hostname",
];

fn collect_artifact_occurrences(rows: &[Value]) -> (Vec<(String, String)>, Vec<(String, String)>) {
    let mut hashes = Vec::new();
    let mut domains = Vec::new();
    for row in rows {
        let timestamp = lake_string(row, "time").unwrap_or_default();
        for prefix in ["file", "process.file", "actor.process.file"] {
            for hash in lake_hash_values(row, prefix) {
                hashes.push((hash.to_ascii_lowercase(), timestamp.clone()));
            }
        }
        // NAN-2361: must cover EVERY path the domain predicate searches
        // (`build_global_artifacts_predicate` / the frontend's DOMAIN_PATHS).
        // `dst_endpoint.hostname` and `url.hostname` were missing, so a domain
        // seen only as a connection destination or a bare URL host was matched
        // by the query but then dropped by this collector — it vanished from
        // artifact summaries and global host counts while the predicate claimed
        // to look for it.
        for path in LAKE_ASSET_DOMAIN_PATHS {
            if let Some(domain) = lake_string(row, path).filter(|v| is_lake_domain_artifact(v)) {
                domains.push((domain.to_ascii_lowercase(), timestamp.clone()));
            }
        }
    }
    (hashes, domains)
}

/// Host identity for in-window counting.
///
/// NAN-2361: this used to unconditionally mirror the baseline builder's
/// `coalesce(nullIf(device.hostname,''), nullIf(src_endpoint.hostname,''), 'unknown')`
/// (`prevalence_build.rs` SQL_OBSERVATION_PART) -- rows carrying neither
/// hostname (a plain `conduit_proxy` HTTP event, for example, which carries
/// `src_endpoint.ip` but NEVER a hostname) all collapsed into the single
/// literal host `'unknown'`. Confirmed live: `http_request.url.hostname=
/// "slack.com"` returned `events: 14664, hosts: 1` -- 14,664 real hits from
/// (almost certainly) many distinct machines, all counted as one host,
/// because nothing here could tell them apart.
///
/// `resolve_asset_host_identities` (below) now widens rows BEFORE this
/// function ever sees them: any row with an IP but no hostname gets its
/// `device.hostname` filled in from the lake identity directory (the same
/// resolver `resolve_identity` uses) when a match exists, or the raw IP
/// substituted as a distinct-but-unresolved identity otherwise -- a distinct
/// IP is still real evidence of a distinct machine even unresolved, which
/// `'unknown'` is not. This function itself is UNCHANGED and still falls
/// back to the literal `'unknown'` bucket for rows with neither a hostname
/// nor an IP at all (a bare event with no endpoint fields).
///
/// This deliberately DIVERGES from the baseline builder (`prevalence_build.rs`
/// SQL_OBSERVATION_PART), which still does the raw, unresolved coalesce --
/// that SQL runs as a single chDB aggregate with no per-row Rust hook to
/// intervene on, so fixing it needs either a chDB-joinable identity source or
/// a rework of the builder's execution model, tracked separately. The UI
/// already has a `prevalenceSource: 'baseline' | 'in-window'` badge for
/// exactly this situation, so a widened in-window count outscoring a stale,
/// unresolved baseline reads as "fresher data," not a contradiction.
fn lake_host_identity(row: &Value) -> String {
    for path in ["device.hostname", "src_endpoint.hostname"] {
        if let Some(host) = lake_string(row, path) {
            let host = host.trim().to_ascii_lowercase();
            if !host.is_empty() {
                return host;
            }
        }
    }
    "unknown".to_string()
}

/// Distinct hosts per artifact, observed in the rows we already loaded.
///
/// NAN-2361 layer 1 for asset mode. The immutable prevalence snapshot rebuilds
/// per generation and lags ingest by 30-90 minutes, so for a freshly-seen
/// artifact it returns nothing and the panel showed `host_count: 0` --
/// indistinguishable from "common and boring". These rows are already in hand
/// for the occurrence list, so this costs no extra query.
///
/// This is a strict LOWER BOUND on environment prevalence: an asset that
/// touched the artifact outside the queried window is not counted. It is
/// therefore reported alongside the baseline, never as a replacement for it.
fn in_window_host_counts(rows: &[Value]) -> BTreeMap<String, BTreeSet<String>> {
    let mut counts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for row in rows {
        let host = lake_host_identity(row);
        for prefix in ["file", "process.file", "actor.process.file"] {
            for hash in lake_hash_values(row, prefix) {
                counts
                    .entry(hash.to_ascii_lowercase())
                    .or_default()
                    .insert(host.clone());
            }
        }
        // NAN-2361: same shared list as the predicate and the occurrence
        // collector. Checking only two of the four paths meant a domain seen
        // solely via `url.hostname` or `dst_endpoint.hostname` had no cheap
        // in-window count and fell through to the fallible global query.
        for path in LAKE_ASSET_DOMAIN_PATHS {
            if let Some(domain) = lake_string(row, path).filter(|v| is_lake_domain_artifact(v)) {
                counts
                    .entry(domain.to_ascii_lowercase())
                    .or_default()
                    .insert(host.clone());
            }
        }
    }
    counts
}

fn latest_nonempty(rows: &[Value], paths: &[&str]) -> Option<String> {
    rows.iter().find_map(|row| {
        paths
            .iter()
            .find_map(|path| lake_string(row, path).filter(|value| !value.is_empty()))
    })
}

fn lake_asset_identity(rows: &[Value]) -> AssetIdentity {
    let hostname = latest_nonempty(
        rows,
        &[
            "device.hostname",
            "src_endpoint.hostname",
            "dst_endpoint.hostname",
        ],
    );
    let mut sources = BTreeMap::<String, (u64, String)>::new();
    for row in rows {
        let source = lake_string(row, "metadata.log_source").unwrap_or_default();
        if source.is_empty() {
            continue;
        }
        let timestamp = lake_string(row, "time").unwrap_or_default();
        let entry = sources.entry(source).or_default();
        entry.0 += row_weight(row);
        if timestamp > entry.1 {
            entry.1 = timestamp;
        }
    }
    let mut log_sources = sources
        .into_iter()
        .map(|(name, (event_count, last_event))| AssetLogSource {
            name,
            event_count,
            last_event,
        })
        .collect::<Vec<_>>();
    log_sources.sort_by(|left, right| {
        right
            .event_count
            .cmp(&left.event_count)
            .then_with(|| left.name.cmp(&right.name))
    });
    let domain = hostname.as_deref().and_then(|value| {
        (!value.parse::<std::net::IpAddr>().is_ok())
            .then(|| value.split_once('.').map(|(_, suffix)| suffix.to_string()))
            .flatten()
    });
    AssetIdentity {
        hostname,
        ip: latest_nonempty(rows, &["src_endpoint.ip", "dst_endpoint.ip"]),
        mac: latest_nonempty(rows, &["src_endpoint.mac", "dst_endpoint.mac"]),
        user: latest_nonempty(rows, &["actor.user.name", "user.name"]),
        vendor_product: latest_nonempty(
            rows,
            &["metadata.product.name", "metadata.product.vendor_name"],
        ),
        first_seen_in_range: rows
            .iter()
            .filter_map(|row| lake_string(row, CARD_FIRST_SEEN).or_else(|| lake_string(row, "time")))
            .min(),
        last_seen_in_range: rows.iter().filter_map(|row| lake_string(row, "time")).max(),
        log_sources,
        domain,
    }
}

fn dossier_lane(row: &Value) -> Option<usize> {
    match lake_u64(row, "class_uid") {
        Some(3002) => Some(0),
        Some(1007) => Some(1),
        Some(4001 | 4003) => Some(2),
        Some(1001) => Some(3),
        Some(2001..=2999) => Some(4),
        _ => None,
    }
}

/// Timeline buckets across the window.
const TIMELINE_BUCKETS: usize = 28;

fn lake_asset_timeline(rows: &[Value], time_range: &TimeRange) -> AssetActivityTimeline {
    const BUCKETS: usize = TIMELINE_BUCKETS;
    let start = time_range.start.timestamp_micros();
    let duration = (time_range.end.timestamp_micros() - start).max(1);
    let mut counts = [[0_u64; 5]; BUCKETS];
    for row in rows {
        let Some(lane) = dossier_lane(row) else {
            continue;
        };
        // A card group carries the bucket the lake computed for it.
        let bucket = if let Some(bucket) = row.get(CARD_BUCKET) {
            let bucket = bucket
                .as_f64()
                .or_else(|| bucket.as_str().and_then(|value| value.trim().parse().ok()));
            match bucket {
                Some(bucket) if bucket >= 0.0 && bucket <= BUCKETS as f64 => {
                    (bucket as usize).min(BUCKETS - 1)
                }
                _ => continue,
            }
        } else {
            let Some(timestamp) =
                lake_string(row, "time").and_then(|value| parse_lake_asset_time(&value))
            else {
                continue;
            };
            let elapsed = timestamp.timestamp_micros() - start;
            if elapsed < 0 || elapsed > duration {
                continue;
            }
            ((elapsed as i128 * BUCKETS as i128) / duration as i128).min((BUCKETS - 1) as i128)
                as usize
        };
        counts[bucket][lane] += row_weight(row);
    }
    let mut maxima = [1_u64; 5];
    for lane in 0..5 {
        maxima[lane] = counts
            .iter()
            .map(|bucket| bucket[lane])
            .max()
            .unwrap_or(1)
            .max(1);
    }
    let mut points = Vec::new();
    for (bucket, lanes) in counts.iter().enumerate() {
        for (lane, count) in lanes.iter().enumerate() {
            if *count == 0 {
                continue;
            }
            let ratio = *count as f64 / maxima[lane] as f64;
            let weight = if ratio >= 0.66 {
                3
            } else if ratio >= 0.33 {
                2
            } else {
                1
            };
            points.push([bucket as u32, lane as u32, weight]);
        }
    }
    AssetActivityTimeline {
        buckets: BUCKETS as u32,
        lanes: vec![
            "auth".into(),
            "proc".into(),
            "net".into(),
            "file".into(),
            "alert".into(),
        ],
        points,
    }
}

/// Render a lake time string as RFC3339 UTC (`...Z`).
///
/// Lake rows carry NAIVE timestamps (`"2026-08-21 10:54:52.343000"`, no zone
/// suffix); a browser `new Date(...)` on that parses as LOCAL time. The
/// ClickHouse path already emits `Z`-suffixed strings, so normalize here at the
/// emission seam instead of patching every frontend call site. Unparseable
/// input falls through unchanged.
fn lake_time_rfc3339(value: &str) -> String {
    parse_lake_asset_time(value)
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
        .unwrap_or_else(|| value.to_string())
}

fn parse_lake_asset_time(value: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .map(|value| value.with_timezone(&chrono::Utc))
        .ok()
        .or_else(|| {
            chrono::NaiveDateTime::parse_from_str(value, "%Y-%m-%d %H:%M:%S%.f")
                .ok()
                .map(|value| value.and_utc())
        })
}

fn process_observation(row: &Value) -> Option<(String, Option<String>, Option<String>)> {
    for (prefix, hash_alias, cmd_alias) in [
        ("process", CARD_PROCESS_HASH, CARD_PROCESS_CMD),
        ("actor.process", CARD_ACTOR_HASH, CARD_ACTOR_CMD),
    ] {
        if let Some(name) = lake_string(row, &format!("{prefix}.name")) {
            let hash = lake_hash_values(row, &format!("{prefix}.file"))
                .into_iter()
                .chain(card_hash_values(row, hash_alias))
                .next()
                .map(|value| value.to_ascii_lowercase());
            let command = lake_string(row, &format!("{prefix}.cmd_line"))
                .or_else(|| lake_string(row, cmd_alias));
            return Some((name, hash, command));
        }
    }
    None
}

fn lake_asset_processes(
    rows: &[Value],
    prevalence: &BTreeMap<String, (u64, bool, u8)>,
) -> AssetProcessesSummary {
    let mut processes = BTreeMap::<String, (u64, Option<String>, Option<String>)>::new();
    let mut unsigned = 0;
    let mut from_office = 0;
    for row in rows {
        let Some((name, hash, command)) = process_observation(row) else {
            continue;
        };
        let weight = row_weight(row);
        let entry = processes.entry(name).or_insert((0, None, None));
        entry.0 += weight;
        if entry.1.is_none() {
            entry.1 = hash;
        }
        if entry.2.is_none() {
            entry.2 = command;
        }
        unsigned += weight * u64::from(lake_bool_value(row, "unmapped.signed") == Some(false));
        let parent = lake_string(row, "actor.process.name")
            .unwrap_or_default()
            .to_ascii_lowercase();
        from_office += weight
            * u64::from(OFFICE_PARENTS.contains(&parent.as_str()));
    }
    let mut top = processes
        .iter()
        .map(|(name, (count, hash, _))| ProcessTop {
            name: name.clone(),
            count: *count,
            prev: hash
                .as_ref()
                .and_then(|hash| prevalence.get(hash))
                .map(|(_, _, score)| *score as f32)
                .unwrap_or(0.0),
        })
        .collect::<Vec<_>>();
    top.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    top.truncate(8);
    let mut rare_list = processes
        .iter()
        .filter_map(|(name, (_, hash, command))| {
            let hash_value = hash.as_ref()?;
            let prevalence_row = prevalence.get(hash_value);
            if prevalence_row.is_some_and(|(_, is_rare, _)| !is_rare) {
                return None;
            }
            Some(ProcessRare {
                name: name.clone(),
                hash: hash.clone(),
                prev: prevalence_row
                    .map(|(_, _, score)| *score as f32)
                    .unwrap_or(0.0),
                cmd: command.clone(),
                flags: Vec::new(),
            })
        })
        .collect::<Vec<_>>();
    rare_list.sort_by(|left, right| {
        left.prev
            .total_cmp(&right.prev)
            .then_with(|| left.name.cmp(&right.name))
    });
    rare_list.truncate(5);
    AssetProcessesSummary {
        unique: processes.len() as u64,
        rare: rare_list.len() as u64,
        unsigned,
        from_office,
        top,
        rare_list,
    }
}

/// Office parents that make a child process suspicious.
const OFFICE_PARENTS: &[&str] = &["winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"];

fn lake_bool_value(row: &Value, path: &str) -> Option<bool> {
    match lake_value(row, path)? {
        Value::Bool(value) => Some(*value),
        // A card group key comes back as the lake's string rendering.
        Value::String(value) if value.eq_ignore_ascii_case("true") => Some(true),
        Value::String(value) if value.eq_ignore_ascii_case("false") => Some(false),
        _ => None,
    }
}

fn lake_asset_network(
    rows: &[Value],
    prevalence: &BTreeMap<String, (u64, bool, u8)>,
) -> AssetNetworkSummary {
    let mut total_conns = 0;
    let mut bytes_in = 0;
    let mut bytes_out = 0;
    let mut destinations = BTreeMap::<(String, String), (u64, u64)>::new();
    let mut domains = BTreeSet::new();
    for row in rows {
        if !matches!(lake_u64(row, "class_uid"), Some(4001 | 4003)) {
            continue;
        }
        let weight = row_weight(row);
        let row_bytes_out = row_sum(row, CARD_BYTES_OUT, "traffic.bytes_out");
        total_conns += weight;
        bytes_in += row_sum(row, CARD_BYTES_IN, "traffic.bytes_in");
        bytes_out += row_bytes_out;
        let host = lake_string(row, "dst_endpoint.hostname")
            .filter(|value| value != "-")
            .or_else(|| lake_string(row, "query.hostname"))
            .unwrap_or_default();
        let ip = lake_string(row, "dst_endpoint.ip").unwrap_or_default();
        if !host.is_empty() {
            domains.insert(host.to_ascii_lowercase());
        }
        if !host.is_empty() || !ip.is_empty() {
            let entry = destinations.entry((host, ip)).or_default();
            entry.0 += weight;
            entry.1 += row_bytes_out;
        }
    }
    let unique_dsts = destinations.len() as u64;
    let mut top_dsts = destinations
        .into_iter()
        .map(|((host, ip), (conns, bytes))| {
            let prevalence_row = prevalence.get(&host.to_ascii_lowercase());
            NetworkDest {
                host: if host.is_empty() { ip.clone() } else { host },
                ip: (!ip.is_empty()).then_some(ip),
                country: None,
                bytes,
                conns,
                rep: if prevalence_row.is_some_and(|(_, is_rare, _)| *is_rare) {
                    "new-domain"
                } else {
                    "unknown"
                }
                .to_string(),
            }
        })
        .collect::<Vec<_>>();
    top_dsts.sort_by(|left, right| {
        right
            .bytes
            .cmp(&left.bytes)
            .then_with(|| right.conns.cmp(&left.conns))
    });
    top_dsts.truncate(8);
    let new_domains = domains
        .iter()
        .filter(|domain| {
            prevalence
                .get(*domain)
                .is_none_or(|(_, is_rare, _)| *is_rare)
        })
        .count() as u64;
    AssetNetworkSummary {
        total_conns,
        bytes_in,
        bytes_out,
        unique_dsts,
        new_domains,
        top_dsts,
        rare_countries: Vec::new(),
    }
}

/// NAN-3408: an OCSF Authentication Logoff (activity_id 2, Windows 4634).
/// It ends a session: it is neither a logon attempt nor a success, so the
/// auth card skips it (the card queries already filter it in the lake).
fn is_logoff(row: &Value) -> bool {
    lake_u64(row, "activity_id") == Some(2)
        || lake_string(row, "activity_name").is_some_and(|name| name.eq_ignore_ascii_case("logoff"))
}

fn lake_asset_auth(rows: &[Value]) -> AssetAuthSummary {
    let mut summary = AssetAuthSummary::default();
    for row in rows {
        if lake_u64(row, "class_uid") != Some(3002) || is_logoff(row) {
            continue;
        }
        let weight = row_weight(row);
        let success = !lake_status_failed(row);
        if success {
            summary.success += weight;
        } else {
            summary.failure += weight;
        }
        // NAN-3408: the logon TYPE (Interactive / Network / Remote
        // Interactive …) lives in OCSF `logon_type`; `auth_protocol` is the
        // PROTOCOL (NTLM / Kerberos / Negotiate). Keying the INTERACT. /
        // NETWORK tiles off the protocol read 0 / 0 for every Windows logon
        // (live load-test tenant: randerson 6h = 1.3K Interactive, 3.2K Network).
        let auth_type = lake_string(row, "auth_protocol").unwrap_or_else(|| "other".to_string());
        let logon_kind = lake_string(row, "logon_type")
            .or_else(|| lake_string(row, "unmapped.logon_type"))
            .unwrap_or_default()
            .to_ascii_lowercase();
        summary.interactive += weight * u64::from(logon_kind.contains("interactive"));
        summary.network += weight * u64::from(logon_kind.contains("network"));
        summary.lateral += weight
            * u64::from(
            logon_kind.contains("lateral")
                || matches!(
                    lake_u64(row, "dst_endpoint.port"),
                    Some(22 | 445 | 3389 | 5985 | 5986)
                ),
        );
        summary.recent.push(AuthRecent {
            ts: lake_string(row, "time").unwrap_or_default(),
            auth_type,
            user: lake_string(row, "actor.user.name").or_else(|| lake_string(row, "user.name")),
            src: lake_string(row, "src_endpoint.hostname")
                .or_else(|| lake_string(row, "src_endpoint.ip")),
            result: if success { "success" } else { "failure" }.to_string(),
            reason: lake_string(row, "unmapped.failure_reason")
                .or_else(|| lake_string(row, "unmapped.error_message")),
        });
    }
    summary.recent.sort_by(|left, right| right.ts.cmp(&left.ts));
    summary.recent.truncate(8);
    summary
}

fn lake_asset_files(rows: &[Value]) -> AssetFilesSummary {
    let mut summary = AssetFilesSummary::default();
    for row in rows {
        if lake_u64(row, "class_uid") != Some(1001) {
            continue;
        }
        let action = lake_string(row, "activity_name")
            .unwrap_or_else(|| "activity".to_string())
            .to_ascii_lowercase();
        let path = lake_string(row, "file.path")
            .or_else(|| lake_string(row, "file.name"))
            .unwrap_or_default();
        let weight = row_weight(row);
        summary.writes += weight
            * u64::from(
            ["create", "update", "write", "delete"]
                .iter()
                .any(|value| action.contains(value)),
        );
        let lower = path.to_ascii_lowercase();
        summary.sensitive += weight
            * u64::from(
            ["/etc/", "\\windows\\system32", ".ssh", "sam", "security"]
                .iter()
                .any(|value| lower.contains(value)),
        );
        summary.exec += weight
            * u64::from(
            [".exe", ".dll", ".sh", ".ps1", ".bat"]
                .iter()
                .any(|value| lower.ends_with(value)),
        );
        summary.recent.push(FileRecent {
            ts: lake_string(row, "time").unwrap_or_default(),
            path,
            size_bytes: lake_u64(row, "raw_data_size").unwrap_or(0),
            action,
            proc: lake_string(row, "actor.process.name")
                .or_else(|| lake_string(row, "process.name")),
        });
    }
    summary.recent.sort_by(|left, right| right.ts.cmp(&left.ts));
    summary.recent.truncate(8);
    summary
}

fn lake_asset_dns(rows: &[Value]) -> AssetDnsSummary {
    let mut counts = BTreeMap::<String, (u64, u64)>::new();
    for row in rows {
        if lake_u64(row, "class_uid") != Some(4003) {
            continue;
        }
        let Some(domain) = lake_string(row, "query.hostname") else {
            continue;
        };
        let nx = u64::from(
            lake_status_failed(row)
                || lake_string(row, "unmapped.status")
                    .is_some_and(|value| value.eq_ignore_ascii_case("nxdomain")),
        );
        let weight = row_weight(row);
        let entry = counts.entry(domain).or_default();
        entry.0 += weight;
        entry.1 += weight * nx;
    }
    let queries = counts.values().map(|(count, _)| *count).sum();
    let mut top = counts
        .into_iter()
        .map(|(domain, (count, nx))| DnsTop { domain, count, nx })
        .collect::<Vec<_>>();
    top.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.domain.cmp(&right.domain))
    });
    let unique = top.len() as u64;
    let nx = top.iter().map(|row| row.nx).sum();
    let rare_tlds = top
        .iter()
        .filter(|row| {
            [".zip", ".mov", ".top", ".xyz", ".click"]
                .iter()
                .any(|suffix| row.domain.ends_with(suffix))
        })
        .count() as u64;
    top.truncate(8);
    AssetDnsSummary {
        queries,
        unique,
        nx,
        rare_tlds,
        top,
    }
}

impl SearchService {
    /// NAN-3689: the rangeless identity paths this tenant actually stores
    /// (its active profile is its own field inventory on the lean lake).
    fn lake_asset_rangeless(&self) -> Vec<&'static str> {
        lake_asset_rangeless_fields(&self.active_profile().snapshot_fields())
    }

    /// Widen rows lacking a direct hostname by resolving `src_endpoint.ip`/
    /// `dst_endpoint.ip` through the lake identity directory before
    /// `in_window_host_counts` runs its (unchanged) coalesce over them.
    /// Returns a CLONE of `rows` with `device.hostname` filled in wherever a
    /// resolution (or a raw-IP fallback) applies; rows that already had a
    /// hostname, or have neither a hostname nor an IP, pass through
    /// unmodified. See `lake_host_identity`'s doc comment for why this
    /// exists (confirmed live: `slack.com` read `events: 14664, hosts: 1`).
    ///
    /// NAN-3252: best effort under `deadline`. Point-in-time bindings are one
    /// per distinct (IP, row time), and while a cell's identity index
    /// backfills each distinct time is its own event scan, so an unbounded
    /// resolution held the Asset page incomplete for minutes. Past the
    /// deadline it answers like a failed resolution: raw IPs.
    async fn resolve_asset_host_identities(
        &self,
        rows: &[Value],
        time_range: &TimeRange,
        scope: &ScopeSet,
        deadline: tokio::time::Instant,
    ) -> Vec<Value> {
        let fallback_reference_time = time_range.end;

        let mut widened = rows.to_vec();
        let mut row_indices = Vec::new();
        let mut items = Vec::new();
        for (index, row) in widened.iter().enumerate() {
            if lake_host_identity(row) != "unknown" {
                continue;
            }
            let Some(ip) = lake_string(row, "src_endpoint.ip")
                .or_else(|| lake_string(row, "dst_endpoint.ip"))
                .filter(|v| !v.is_empty())
            else {
                continue;
            };
            let Ok(parsed_ip) = ip.trim().parse::<std::net::IpAddr>() else {
                continue;
            };
            // NAN-3291: one binding per IP and quarter hour, not per row
            // time (a busy asset had 7,240 distinct (IP, time) bindings and
            // never resolved inside its budget).
            let reference_time = lake_string(row, "time")
                .and_then(|s| parse_lake_timestamp(&s))
                .map(|time| {
                    let bucket = LAKE_ASSET_RESOLVE_BUCKET.num_seconds();
                    chrono::DateTime::from_timestamp(time.timestamp().div_euclid(bucket) * bucket, 0)
                        .unwrap_or(time)
                        .min(fallback_reference_time)
                })
                .unwrap_or(fallback_reference_time);
            row_indices.push(index);
            items.push((parsed_ip, reference_time));
        }
        if items.is_empty() {
            return widened;
        }
        // NAN-3058: the tenant's identity resolution (index, or the bounded
        // event scan while it backfills). Best effort: a failure keeps the
        // raw-IP fallback below.
        // Share identical bindings only: the same IP can identify different
        // hosts over time, so a later row must never rename an earlier one.
        // NAN-3291: at most LAKE_ASSET_RESOLVE_BINDINGS, the ones that name
        // the most rows; the rest keep their raw IP (a lower bound, as a
        // failed resolution already was).
        let mut weights = BTreeMap::<(std::net::IpAddr, chrono::DateTime<chrono::Utc>), usize>::new();
        for item in &items {
            *weights.entry(*item).or_default() += 1;
        }
        let total_bindings = weights.len();
        let mut ranked = weights.into_iter().collect::<Vec<_>>();
        ranked.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        ranked.truncate(LAKE_ASSET_RESOLVE_BINDINGS);
        let mut distinct = ranked.into_iter().map(|(binding, _)| binding).collect::<Vec<_>>();
        distinct.sort();
        if total_bindings > distinct.len() {
            tracing::debug!(
                bindings = total_bindings,
                resolved = distinct.len(),
                "lake asset host identity resolution bounded; the quietest bindings keep raw IPs"
            );
        }
        let resolved = tokio::time::timeout_at(
            deadline,
            self.resolve_lake_identity_ips(&distinct, scope.deny_set()),
        )
        .await;
        match resolved {
            Ok(Ok(answers)) => {
                let names = distinct
                    .iter()
                    .zip(answers)
                    .filter_map(|(binding, answer)| {
                        Some((
                            *binding,
                            answer
                                .map(|o| o.hostname.trim().to_string())
                                .filter(|h| !h.is_empty())?,
                        ))
                    })
                    .collect::<BTreeMap<_, _>>();
                for (&row_index, binding) in row_indices.iter().zip(items.iter()) {
                    if let Some(hostname) = names.get(binding) {
                        set_lake_ocsf_value_if_empty(
                            &mut widened[row_index],
                            "device.hostname",
                            hostname,
                        );
                    }
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(error = %error, "lake asset host identity widening failed; using raw IPs")
            }
            Err(_) => tracing::info!(
                bindings = distinct.len(),
                "lake asset host identity resolution exceeded its budget; using raw IPs"
            ),
        }
        // Rows the resolution couldn't name (no observation) still fall
        // back to the raw IP -- distinct from `lake_host_identity`'s
        // "unknown" bucket, preserving distinctness even without a name.
        for (row_index, (ip, _)) in row_indices.iter().zip(items.iter()) {
            if lake_host_identity(&widened[*row_index]) == "unknown" {
                set_lake_ocsf_value_if_empty(
                    &mut widened[*row_index],
                    "device.hostname",
                    &ip.to_string(),
                );
            }
        }
        widened
    }

    /// NAN-3094: the dossier over the shared progressive snapshot. Answers
    /// within [`LAKE_ASSET_VIEW_WAIT`] with what is covered so far; `progress`
    /// tells the client whether to ask again.
    pub(crate) async fn query_lake_asset_dossier(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        scope: &ScopeSet,
        fresh: bool,
    ) -> Result<AssetDossier, SearchError> {
        // A recent interactive snapshot cannot complete a wider investigation.
        // Validate before handing the request to the handler's durable fallback.
        build_lake_asset_predicate(identifier_field, identifier_value, identities, &self.lake_asset_rangeless())?;
        if snapshot::summary_requires_durable(time_range) {
            return Err(SearchError::ResourceExhausted(
                "Asset dossier window requires the durable lane".to_string(),
            ));
        }
        let view = self
            .lake_asset_snapshot_with(
                snapshot::SnapshotRequest {
                    identifier_field,
                    identifier_value,
                    identities,
                    time_range,
                    scope,
                },
                fresh,
                LAKE_ASSET_VIEW_WAIT,
                true,
            )
            .await?;
        snapshot::dossier_from_view(&view)
    }

    pub fn assemble_lake_asset_dossier(
        rows: Vec<Value>,
        time_range: &TimeRange,
        prevalence: &BTreeMap<String, (u64, bool, u8)>,
    ) -> AssetDossier {
        Self::assemble_lake_asset_dossier_from(&rows, time_range, prevalence)
    }

    pub fn assemble_lake_asset_dossier_from(
        rows: &[Value],
        time_range: &TimeRange,
        prevalence: &BTreeMap<String, (u64, bool, u8)>,
    ) -> AssetDossier {
        let rows = rows;
        AssetDossier {
            identity: lake_asset_identity(&rows),
            timeline: lake_asset_timeline(&rows, time_range),
            processes: lake_asset_processes(&rows, &prevalence),
            network: lake_asset_network(&rows, &prevalence),
            auth: lake_asset_auth(&rows),
            files: lake_asset_files(&rows),
            dns: lake_asset_dns(&rows),
            durable_job: None,
            progress: None,
        }
    }

    /// NAN-3276: the card reads of a durable Asset dossier: the same
    /// bounded lake aggregates the interactive dossier reads, over the
    /// asset's predicate slices and the whole admitted `window`. Fold the
    /// results with [`LakeAssetCards`].
    ///
    /// NAN-3689: query[T] runs this without a tenant field inventory, so the
    /// durable (background) dossier names every rangeless identity path; a
    /// path the tenant never stored compiles to no match, and its leg is
    /// pruned per file (NAN-3694).
    pub fn lake_asset_dossier_card_reads(
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        window: &TimeRange,
    ) -> Result<Vec<LakeAssetCardRead>, SearchError> {
        let slices = build_lake_asset_predicate_slices(
            identifier_field,
            identifier_value,
            identities,
            LAKE_ASSET_RANGELESS_FIELDS,
        )?;
        Ok(cards::dossier_card_reads(&slices, window))
    }

    pub async fn enqueue_durable_asset_dossier(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        scope: &ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        // query[T] supports this bounded assembler on its isolated job lane.
        // Oversized investigations fail explicitly rather than publishing a slice.
        let (generation_pin, time_range) =
            self.durable_view_admission("durable Asset dossiers", time_range).await?;
        let time_range = &time_range;
        if self.lake_query.mode != super::LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Asset dossiers require the primary lake backend".to_string(),
            ));
        }
        let predicate = build_lake_asset_predicate(identifier_field, identifier_value, identities, &self.lake_asset_rangeless())?;
        let event_query = format!(
            "{predicate} | table {} | sort -time",
            LAKE_ASSET_ROW_PROJECTION.join(",")
        );
        let request = SearchRequest {
            query: format!(
                "{identifier_field}={} | asset field={identifier_field}",
                safe_literal(identifier_value, "asset identifier")?
            ),
            time_range: TimeRangeInput::new(time_range.start, time_range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &crate::search::DurableLakeTask::AssetDossierV1 {
                    identifier_field: identifier_field.to_string(),
                    identifier_value: identifier_value.to_string(),
                    identities: identities.to_vec(),
                    event_query,
                },
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Asset dossier admission failed: {error}"
                ))
            })
    }

    pub(crate) async fn build_lake_asset_view(
        &self,
        query: &Query,
        asset_info: &AssetCommandInfo,
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<Vec<Value>, SearchError> {
        let time_range = time_range.clone();
        let base_query = strip_asset_and_after(query);
        // NAN-3258: resolve `field=` (exact OCSF path, UDM alias, or identity
        // kind) to the OCSF identity fields up front; an unknown field fails
        // here with the accepted forms named.
        let explicit_fields = asset_info
            .identifier_field
            .as_deref()
            .map(resolve_lake_asset_fields)
            .transpose()?;
        let pre_extracted = match explicit_fields.as_deref() {
            Some(fields) => fields.iter().find_map(|field| {
                let info = AssetCommandInfo {
                    identifier_field: Some((*field).to_string()),
                    ..asset_info.clone()
                };
                extract_asset_identifier_from_query(query, &info)
            }),
            None => extract_asset_identifier_from_query(query, asset_info),
        };
        let seed_rows = if pre_extracted.is_some() {
            Vec::new()
        } else {
            let seed_query = if let Some(fields) = explicit_fields.as_deref() {
                // An explicit field is a promise about WHICH identity to use,
                // not a promise that one of the first arbitrary rows contains
                // it. Ask the lake for the first non-null value so sparse OCSF
                // class fields cannot make a valid asset view fail depending on
                // row order.
                let present = fields
                    .iter()
                    .map(|field| format!("isnotnull({field})"))
                    .collect::<Vec<_>>()
                    .join(" OR ");
                format!("{} | where {present}", base_query.pretty_print())
            } else {
                base_query.pretty_print()
            };
            self.execute_lake_view_query(
                seed_query,
                &time_range,
                scope,
                "asset-seed",
                if asset_info.identifier_field.is_some() {
                    1
                } else {
                    10
                },
            )
            .await?
            .results
        };
        if seed_rows.is_empty() && pre_extracted.is_none() {
            return Ok(vec![json!({
                "_display_type": "asset",
                "_asset_profile": {"primary_identifier": null, "identities": [], "first_seen": null, "last_seen": null, "storage_model": "ocsf-1.9-iceberg"},
                "_asset_events": [],
                "_asset_pagination": {"total_count": 0, "offset": 0, "limit": LAKE_ASSET_PAGE_SIZE, "has_more": false, "facets": AssetFacets::default()},
            })]);
        }
        let (identifier_field, identifier_value) = pre_extracted
            .map(Ok)
            .unwrap_or_else(|| {
                detect_identifier(
                    &seed_rows,
                    explicit_fields.as_deref().unwrap_or(LAKE_ASSET_FIELDS),
                )
            })?;
        // This response is only a typed dispatcher marker. AssetStream and the
        // dossier immediately call their dedicated endpoints, so materializing
        // 50k full events here duplicated the expensive read and then discarded
        // it. Preserve any identities already present in the bounded seed; the
        // typed endpoints can widen them from the immutable identity snapshot.
        let identities = collect_identity_dtos(&seed_rows, LAKE_ASSET_IDENTITY_CAP);
        Ok(vec![json!({
            "_display_type": "asset",
            "_asset_profile": {
                "primary_identifier": {"field": identifier_field, "value": identifier_value},
                "identities": identities,
                "first_seen": null,
                "last_seen": null,
                "reanchored": false,
                "effective_time_range": null,
                "storage_model": "ocsf-1.9-iceberg",
            },
            "_asset_events": [],
            "_asset_pagination": {
                "total_count": 0,
                "offset": 0,
                "limit": LAKE_ASSET_PAGE_SIZE,
                "has_more": false,
                "facets": AssetFacets::default(),
                "deferred_to_typed_endpoint": true,
            },
        })])
    }

    pub(crate) async fn query_lake_asset_events_paginated(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
        filters: Option<&AssetEventFilters>,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, u64, AssetFacets), SearchError> {
        let (events, _, _) = self
            .query_lake_asset_events_page(
                identifier_field,
                identifier_value,
                identities,
                time_range,
                offset,
                limit,
                None,
                filters,
                scope,
            )
            .await?;
        let (total_count, facets, _) = self
            .query_lake_asset_events_summary(
                identifier_field,
                identifier_value,
                identities,
                time_range,
                filters,
                scope,
                false,
            )
            .await?;
        Ok((events, total_count, facets))
    }

    pub(crate) async fn query_lake_asset_events_page(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        offset: usize,
        limit: usize,
        cursor: Option<&ProductViewCursor>,
        filters: Option<&AssetEventFilters>,
        scope: &ScopeSet,
    ) -> Result<(Vec<Value>, bool, Option<ProductViewCursor>), SearchError> {
        if limit == 0 || limit > 5_000 {
            return Err(SearchError::SqlValidationError(
                "lake asset page limit must be between 1 and 5000".to_string(),
            ));
        }
        let base = build_lake_asset_predicate(identifier_field, identifier_value, identities, &self.lake_asset_rangeless())?;
        let filtered = apply_asset_filters(&base, filters)?;
        let page = self
            .execute_lake_view_query_cursor_page_projected(
                asset_page_query(&filtered),
                time_range,
                scope,
                "asset-page",
                limit.saturating_add(1),
                if cursor.is_some() { 0 } else { offset },
                cursor,
            )
            .await?;
        let has_more = page.results.len() > limit;
        let next_cursor = if has_more {
            page.results
                .get(limit.saturating_sub(1))
                .map(lake_product_cursor)
                .transpose()?
        } else {
            None
        };
        let events = page
            .results
            .iter()
            .take(limit)
            .enumerate()
            .map(|(ordinal, row)| asset_event_dto(row, offset + ordinal))
            .collect();
        Ok((events, has_more, next_cursor))
    }

    /// The Asset event total and facets.
    ///
    /// NAN-3094: an unfiltered `progressive` summary is read from the page's
    /// shared snapshot (no extra lake call; `progress` says whether it is
    /// final). A filtered one, or a non-progressive caller, runs ONE grouped
    /// aggregate (it used to be three parallel scans).
    pub(crate) async fn query_lake_asset_events_summary(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        filters: Option<&AssetEventFilters>,
        scope: &ScopeSet,
        progressive: bool,
    ) -> Result<(u64, AssetFacets, Option<ProductViewProgress>), SearchError> {
        let base = build_lake_asset_predicate(identifier_field, identifier_value, identities, &self.lake_asset_rangeless())?;
        // NAN-3077: the progressive page snapshot only reads the newest 24h.
        // Refuse a wide summary so the handler admits its exact companion over
        // the full retention-bound window, including filtered summaries.
        if progressive && snapshot::summary_requires_durable(time_range) {
            return Err(SearchError::ResourceExhausted(
                "Asset summary window requires the durable lane".to_string(),
            ));
        }
        // The opt-in signed facet lane can complete independently of the
        // dossier snapshot, including assets beyond its 50k event envelope.
        if progressive
            && std::env::var("NANO_LAKE_ASSET_FACET_READS").as_deref() != Ok("1")
            && build_asset_filter_predicate(filters)?.is_none()
        {
            let view = self
                .lake_asset_snapshot(
                    snapshot::SnapshotRequest {
                        identifier_field,
                        identifier_value,
                        identities,
                        time_range,
                        scope,
                    },
                    false,
                    LAKE_ASSET_VIEW_WAIT,
                )
                .await?;
            // NAN-3291: the total and facets come from the full-window count
            // aggregates (exact, whatever the asset's volume); the capped
            // snapshot rows and their notes qualify event detail only.
            match snapshot::stream_counts(&view) {
                snapshot::StreamCounts::Exact(total, facets) => {
                    return Ok((total, facets, Some(snapshot::stream_counts_progress(&view))));
                }
                snapshot::StreamCounts::Pending => {
                    // Paint what the rows give so far; ask again.
                    let (total, facets) = snapshot::facets_from_rows(&view.rows);
                    let mut progress = view.progress_at(snapshot::Stage::Rows);
                    progress.complete = false;
                    progress.note = None;
                    progress.retry_after_ms = Some(snapshot::RETRY_AFTER_MS);
                    return Ok((total, facets, Some(progress)));
                }
                // NAN-3252: without the aggregates, count and facets read the
                // rows; they are final once the rows are.
                snapshot::StreamCounts::Unavailable => {
                    let (total, facets) = snapshot::facets_from_rows(&view.rows);
                    return Ok((total, facets, Some(view.progress_at(snapshot::Stage::Rows))));
                }
            }
        }
        let filtered = apply_asset_filters(&base, filters)?;
        let response = self.execute_lake_view_query(
                asset_summary_query(&filtered), time_range, scope, "asset-counts",
                LAKE_ASSET_SUMMARY_GROUP_CAP,)
            .await?;
        if !response.total_count_exact {
            return Err(SearchError::ResourceExhausted(
                "Asset summary groups exceed the interactive envelope".to_string(),
        ));
        }
        let (total, facets) = asset_facets_from_grouped_rows(&response.results);
        Ok((total, facets, None))
    }

    /// Admit an exact Asset summary to the isolated durable lane after the
    /// interactive attempt reaches a bounded resource limit. Visible events
    /// have already painted through `query_lake_asset_events_page`; this task
    /// owns only the exact count/facets companion.
    pub async fn enqueue_durable_asset_summary(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        filters: Option<&AssetEventFilters>,
        scope: &ScopeSet,
        user_id: uuid::Uuid,
        authority: Option<&crate::search::DurableSearchJobAuthority>,
    ) -> Result<String, SearchError> {
        // NAN-3078: bound to the retention cutoff; the job result carries its proof.
        let (generation_pin, time_range) =
            self.durable_view_admission("durable Asset summaries", time_range).await?;
        let time_range = &time_range;
        if self.lake_query.mode != super::LakeQueryMode::Primary {
            return Err(SearchError::ServiceUnavailable(
                "durable Asset summaries require the primary lake backend".to_string(),
            ));
        }
        let base = build_lake_asset_predicate(identifier_field, identifier_value, identities, &self.lake_asset_rangeless())?;
        let filtered = apply_asset_filters(&base, filters)?;
        let summary_query = format!(
            "{filtered} | stats count() as event_count, count(eval(class_uid=1001)) as file_count, count(eval(class_uid=1007)) as process_count, count(eval(class_uid=3002 AND {LAKE_STATUS_FAILURE_NPL})) as auth_failure_count, count(eval(class_uid=3002 AND NOT {LAKE_STATUS_FAILURE_NPL})) as auth_success_count, count(eval(class_uid=4001)) as network_count, count(eval(class_uid=4003)) as dns_count, count(eval(class_uid=6003)) as cloud_api_count"
        );
        let source_query = format!(
            "{filtered} | where metadata.log_source!=\"\" | stats count() as event_count by metadata.log_source | sort -event_count | head 50"
        );
        let user_query = format!(
            "{filtered} | eval asset_user=coalesce(actor.user.name,user.name) | where asset_user!=\"\" | stats count() as event_count by asset_user | sort -event_count | head 50"
        );
        let literal = safe_literal(identifier_value, "asset identifier")?;
        let request = SearchRequest {
            query: format!("{identifier_field}={literal} | asset field={identifier_field}"),
            time_range: TimeRangeInput::new(time_range.start, time_range.end),
            limit: Some(1),
            offset: Some(0),
            include_sql: Some(false),
            skip_histogram: true,
            skip_field_stats: true,
            use_cache: false,
            table_view: false,
            request_id: None,
            async_mode: true,
            priority: Some("analytics".to_string()),
            dataset: Some("logs".to_string()),
        };
        self.job_control()
            .create_durable_queued(
                request,
                &crate::search::DurableLakeTask::AssetV1 {
                    identifier_field: identifier_field.to_string(),
                    identifier_value: identifier_value.to_string(),
                    identities: identities.to_vec(),
                    filters: filters.cloned(),
                    summary_query,
                    source_query,
                    user_query,
                },
                user_id,
                crate::search::QueryPriority::Analytics,
                scope,
                &generation_pin,
                authority,
            )
            .await
            .map_err(|error| {
                SearchError::ServiceUnavailable(format!(
                    "durable Asset summary admission failed: {error}"
                ))
            })
    }

    pub(crate) async fn query_lake_asset_true_time_range(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        retention_range: Option<&TimeRange>,
        scope: &ScopeSet,
    ) -> Result<(Option<String>, Option<String>), SearchError> {
        let predicate = build_lake_asset_predicate(identifier_field, identifier_value, identities, &self.lake_asset_rangeless())?;
        let default_range = TimeRange::new(
            chrono::DateTime::from_timestamp(0, 0).expect("Unix epoch is valid"),
            chrono::Utc::now() + chrono::Duration::days(1),
        );
        let range = retention_range.unwrap_or(&default_range);
        // NAN-3094: an unrestricted caller reads first/last seen from the
        // parts' entity-range partials: no event scan (the scan over all
        // retained data took 60 s and 504'd). The partials carry no source,
        // so a scoped caller keeps the scoped scan (NAN-2072).
        if scope.deny_set().is_empty() {
            if let Some(client) = self
                .lake_query
                .client
                .as_ref()
                .filter(|client| client.is_lake_cell())
            {
                let mut first: Option<i64> = None;
                let mut last: Option<i64> = None;
                for (path, values) in
                    asset_entity_range_lookups(identifier_field, identifier_value, identities)?
                {
                    let input = TimeRangeInput::new(range.start, range.end);
                    for row in client.entity_ranges(path, &values, &input).await? {
                        first =
                            Some(first.map_or(row.first_us, |current| current.min(row.first_us)));
                        last = Some(last.map_or(row.last_us, |current| current.max(row.last_us)));
                    }
                }
                let render = |micros: Option<i64>| {
                    micros
                        .and_then(chrono::DateTime::<chrono::Utc>::from_timestamp_micros)
                        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Micros, true))
                };
                return Ok((render(first), render(last)));
            }
        }
        let row = self
            .execute_lake_view_query(
                format!("{predicate} | stats min(time) as first_seen,max(time) as last_seen"),
                range,
                scope,
                "asset-range",
                1,
            )
            .await?
            .results
            .into_iter()
            .next();
        Ok((
            row.as_ref().and_then(|row| lake_string(row, "first_seen")),
            row.as_ref().and_then(|row| lake_string(row, "last_seen")),
        ))
    }

    /// NAN-3094: the artifact summary over the page's shared snapshot (no
    /// extra scan). `progress` in the JSON tells the handler whether it is
    /// final.
    pub(crate) async fn query_lake_asset_artifact_summary(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        scope: &ScopeSet,
    ) -> Result<Value, SearchError> {
        if self.prevalence_lookup.is_none() {
            return Err(SearchError::SqlValidationError(
                "lake prevalence snapshot is unavailable".to_string(),
            ));
        }
        let view = self
            .lake_asset_snapshot(
                snapshot::SnapshotRequest {
                    identifier_field,
                identifier_value,
                identities,
                time_range,
                scope,
                },
                false,
                LAKE_ASSET_VIEW_WAIT,
            )
            .await?;
        Ok(snapshot::artifact_summary_json(&view))
    }

    pub(crate) async fn query_lake_asset_artifact_occurrences(
        &self,
        identifier_field: &str,
        identifier_value: &str,
        identities: &[Value],
        time_range: &TimeRange,
        hash_filter: Option<&[String]>,
        domain_filter: Option<&[String]>,
        scope: &ScopeSet,
    ) -> Result<Value, SearchError> {
        // The summary just waited on the same snapshot; read it as it is now.
        let view = self
            .lake_asset_snapshot(
                snapshot::SnapshotRequest {
                    identifier_field,
                    identifier_value,
                    identities,
                    time_range,
                    scope,
                },
                false,
                std::time::Duration::ZERO,
            )
            .await?;
        let (hashes, domains) = collect_artifact_occurrences(&view.rows);
        let allowed_hashes = hash_filter.map(|values| values.iter().collect::<BTreeSet<_>>());
        let allowed_domains = domain_filter.map(|values| values.iter().collect::<BTreeSet<_>>());
        Ok(json!({
            "hashes": hashes.into_iter().filter(|(value, _)| allowed_hashes.as_ref().is_none_or(|allowed| allowed.contains(value)))
            .map(|(artifact, timestamp)| json!({"artifact": artifact, "timestamp": lake_time_rfc3339(&timestamp)})).collect::<Vec<_>>(),
            "domains": domains.into_iter().filter(| (value, _)| allowed_domains.as_ref().is_none_or(|allowed| allowed.contains(value))).map(|(artifact, timestamp)| json!({"artifact": artifact, "timestamp": lake_time_rfc3339(&timestamp)})).collect::<Vec<_>>(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// NAN-2361: discovery must be able to REPORT overflow, not absorb it.
    ///
    /// `collect_identity_dtos` used to stop at exactly `LAKE_ASSET_IDENTITY_CAP`,
    /// so 201 distinct identities and 200 distinct identities produced the same
    /// 200-element vector. The union's `> cap` guard then read clean and the
    /// surplus identities were dropped from the asset predicate silently. The
    /// discovery caller now asks for `cap + 1`, which makes overflow observable.
    #[test]
    fn identity_collection_at_cap_plus_one_exposes_overflow() {
        let rows: Vec<Value> = (0..(LAKE_ASSET_IDENTITY_CAP + 50))
            .map(|i| {
                json!({
                    "time": "2026-08-21 00:00:00.000000",
                    "metadata": { "log_source": "test" },
                    "src_endpoint": { "ip": format!("10.0.{}.{}", i / 256, i % 256) },
                })
            })
            .collect();

        // At the plain cap the caller cannot tell "exactly full" from "over".
        assert_eq!(
            collect_identity_dtos(&rows, LAKE_ASSET_IDENTITY_CAP).len(),
            LAKE_ASSET_IDENTITY_CAP
        );

        // With the sentinel it can: the extra element trips the `> cap` check.
        let discovered = collect_identity_dtos(&rows, LAKE_ASSET_IDENTITY_CAP + 1);
        assert_eq!(discovered.len(), LAKE_ASSET_IDENTITY_CAP + 1);
        assert!(discovered.len() > LAKE_ASSET_IDENTITY_CAP);
    }

    fn row(host: Option<&str>, src_host: Option<&str>, hash: &str) -> Value {
        let mut r = json!({
            "file": { "hashes": [ { "value": hash } ] },
        });
        if let Some(h) = host {
            r["device"] = json!({ "hostname": h });
        }
        if let Some(h) = src_host {
            r["src_endpoint"] = json!({ "hostname": h });
        }
        r
    }

    /// NAN-2361: the in-window count is distinct HOSTS, not events. Two events
    /// from the same host are one host; the whole point of the number is spread.
    #[test]
    fn in_window_counts_distinct_hosts_not_events() {
        let rows = vec![
            row(Some("ws-1"), None, "AABB"),
            row(Some("ws-1"), None, "AABB"),
            row(Some("ws-2"), None, "AABB"),
        ];
        let counts = in_window_host_counts(&rows);
        assert_eq!(counts.get("aabb").map(|h| h.len()), Some(2));
    }

    /// Must mirror the baseline builder's coalesce, or layer 1 and layer 2
    /// count different things and disagree on screen for the same artifact.
    #[test]
    fn in_window_host_identity_falls_back_to_src_endpoint() {
        let rows = vec![row(None, Some("ws-9"), "CCDD")];
        assert_eq!(lake_host_identity(&rows[0]), "ws-9");
        assert_eq!(
            in_window_host_counts(&rows).get("ccdd").map(|h| h.len()),
            Some(1)
        );
    }

    /// Documented limitation shared with the builder: host-less rows collapse
    /// into ONE synthetic host, so an artifact seen only on such rows reports 1
    /// and reads as rare when its spread is actually unknown.
    #[test]
    fn hostless_rows_collapse_into_a_single_unknown_bucket() {
        let rows = vec![row(None, None, "EEFF"), row(None, None, "EEFF")];
        assert_eq!(lake_host_identity(&rows[0]), "unknown");
        assert_eq!(
            in_window_host_counts(&rows).get("eeff").map(|h| h.len()),
            Some(1)
        );
    }

    /// Artifacts are matched case-insensitively; the baseline stores them
    /// lower-trimmed, so the two sides must agree on casing.
    #[test]
    fn in_window_lowercases_artifacts() {
        let rows = vec![row(Some("ws-1"), None, "AbCdEf")];
        let counts = in_window_host_counts(&rows);
        assert!(
            counts.contains_key("abcdef"),
            "keys: {:?}",
            counts.keys().collect::<Vec<_>>()
        );
    }

    /// NAN-3059: the asset row read is projected, so hash arrays arrive as
    /// flat `<prefix>.hashes.value` leaves. Every consumer must read them as
    /// it read the nested `[{value}]` shape of a full event.
    #[test]
    fn projected_hash_leaves_read_like_nested_hash_objects() {
        let nested = json!({
            "time": "2026-09-30 01:00:00.000000",
            "device": {"hostname": "ws-1"},
            "process": {"name": "cmd.exe", "file": {"hashes": [{"algorithm_id": 3, "value": "AA11"}]}},
            "file": {"hashes": [{"value": "bb22"}]},
        });
        let flat = json!({
            "time": "2026-09-30 01:00:00.000000",
            "device.hostname": "ws-1",
            "process.name": "cmd.exe",
            "process.file.hashes.value": ["AA11"],
            "actor.process.file.hashes.value": [],
            "file.hashes.value": ["bb22"],
        });
        for row in [nested, flat] {
            let rows = vec![row];
            let (hashes, _) = collect_artifact_occurrences(&rows);
            let mut hashes = hashes.into_iter().map(|(h, _)| h).collect::<Vec<_>>();
            hashes.sort();
            assert_eq!(hashes, vec!["aa11", "bb22"]);
            assert_eq!(process_observation(&rows[0]).unwrap().1.as_deref(), Some("aa11"));
            assert!(in_window_host_counts(&rows)["bb22"].contains("ws-1"));
        }
        // Every path the assemblers read is projected.
        for path in ["process.cmd_line", "unmapped.signed", "traffic.bytes_out", "dst_endpoint.port"] {
            assert!(LAKE_ASSET_ROW_PROJECTION.contains(&path), "{path}");
        }
    }

    /// `lake_string` only guards non-emptiness, so the OCSF `"-"` placeholder
    /// (and dotless / all-numeric junk) used to become a plotted domain
    /// artifact AND an in-window host count entry. Mirrors the ClickHouse
    /// path's dot + IPv4-exclusion admission.
    #[test]
    fn placeholder_and_junk_values_are_not_domain_artifacts() {
        for junk in ["-", "--", " ", "", "nodots", "10.0.0.1", "1.2.3"] {
            assert!(!is_lake_domain_artifact(junk), "admitted junk: {junk:?}");
        }
        for real in ["evil.example.com", "a1.b2.co", "xn--nxasmq6b.example"] {
            assert!(
                is_lake_domain_artifact(real),
                "rejected real domain: {real:?}"
            );
        }

        let rows = vec![
            json!({ "time": "2026-08-21 10:54:52.343000", "device": {"hostname": "ws-1"},
                    "query": {"hostname": "-"} }),
            json!({ "time": "2026-08-21 10:54:53.343000", "device": {"hostname": "ws-1"},
                    "query": {"hostname": "evil.example.com"} }),
        ];
        let (_, domains) = collect_artifact_occurrences(&rows);
        assert_eq!(
            domains.iter().map(|(d, _)| d.as_str()).collect::<Vec<_>>(),
            vec!["evil.example.com"]
        );
        let counts = in_window_host_counts(&rows);
        assert!(!counts.contains_key("-"));
        assert!(counts.contains_key("evil.example.com"));
    }

    /// Lake rows carry NAIVE timestamps; emission must normalize to `Z`-suffixed
    /// RFC3339 so browsers don't parse them as local time (the ClickHouse path
    /// already emits `Z`).
    #[test]
    fn lake_time_rfc3339_normalizes_naive_timestamps() {
        assert_eq!(
            lake_time_rfc3339("2026-08-21 10:54:52.343000"),
            "2026-08-21T10:54:52.343000Z"
        );
        // Already-zoned input is normalized to UTC, not double-shifted.
        assert_eq!(
            lake_time_rfc3339("2026-08-21T10:54:52.343000+02:00"),
            "2026-08-21T08:54:52.343000Z"
        );
        // Unparseable input passes through unchanged.
        assert_eq!(lake_time_rfc3339("not-a-time"), "not-a-time");
    }

    use super::*;

    #[test]
    fn asset_predicate_uses_only_exact_ocsf_paths() {
        let predicate = build_lake_asset_predicate("src_endpoint.ip", "10.0.0.1", &[], LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        assert_eq!(
            predicate,
            "(src_endpoint.ip=\"10.0.0.1\" OR dst_endpoint.ip=\"10.0.0.1\" OR device.ip=\"10.0.0.1\")"
        );
        assert!(!predicate.contains("src_ip"));
    }

    #[test]
    fn asset_predicate_does_not_silently_drop_related_identities_after_one_hundred() {
        let identities = (0..150)
            .map(|index| {
                json!({
                    "ip": "10.0.0.1",
                    "hostname": format!("host-{index}.corp.local"),
                })
            })
            .collect::<Vec<_>>();
        let predicate =
            build_lake_asset_predicate("src_endpoint.ip", "10.0.0.1", &identities, LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        assert!(predicate.contains("\"host-149.corp.local\""));
    }

    #[test]
    fn legacy_asset_identifier_fails_closed() {
        assert!(build_lake_asset_predicate("src_ip", "10.0.0.1", &[], LAKE_ASSET_RANGELESS_FIELDS).is_err());
    }

    #[test]
    fn nested_event_becomes_explicit_view_dto() {
        let row = json!({
            "time": "2026-08-11 01:02:03.000000",
            "class_uid": 3002,
            "status": "Failure",
            "metadata": {"uid": "event-1", "log_source": "windows_event"},
            "actor": {"user": {"name": "alice"}},
        });
        let dto = asset_event_dto(&row, 0);
        assert_eq!(dto["source_type"], "windows_event");
        assert_eq!(dto["event_kind"], "AUTH_FAILURE");
        assert_eq!(dto["details"]["metadata"]["uid"], "event-1");
    }

    #[test]
    fn dotted_projection_becomes_explicit_view_dto() {
        let row = json!({
            "time": "2026-08-11 01:02:03.000000",
            "class_uid": 1007,
            "metadata.uid": "event-2",
            "metadata.log_source": "windows_sysmon",
            "actor.process.name": "powershell.exe",
        });
        let dto = asset_event_dto(&row, 0);
        assert_eq!(dto["source_type"], "windows_sysmon");
        assert_eq!(dto["event_kind"], "PROCESS");
        assert_eq!(dto["summary"], "powershell.exe");
    }

    #[test]
    fn filters_compile_to_canonical_ocsf_predicates() {
        let filters = AssetEventFilters {
            source_types: Some(vec!["windows_sysmon".to_string()]),
            event_kinds: Some(vec!["PROCESS".to_string(), "AUTH_FAILURE".to_string()]),
            users: Some(vec!["alice".to_string()]),
            search_text: Some("powershell".to_string()),
        };
        let predicate = build_asset_filter_predicate(Some(&filters))
            .unwrap()
            .unwrap();
        assert!(predicate.contains("metadata.log_source IN"));
        assert!(predicate.contains("class_uid=1007"));
        assert!(predicate.contains("class_uid=3002"));
        assert!(predicate.contains("actor.user.name IN"));
        assert!(predicate.contains("process.cmd_line contains"));
        assert!(!predicate.contains("source_type"));
        assert!(!predicate.contains("command_line"));
        parse_query(&predicate).expect("generated asset predicate must remain valid nPL");
    }

    #[test]
    fn grouped_summary_rows_produce_exact_total_and_facets() {
        let rows = vec![
            json!({"metadata.log_source": "windows_sysmon", "class_uid": 1007, "asset_auth_failure": 0, "asset_user": "alice", "event_count": 7}),
            json!({"metadata.log_source": "windows_event", "class_uid": 3002, "asset_auth_failure": 1, "asset_user": "bob", "event_count": 3}),
            json!({"metadata.log_source": "windows_event", "class_uid": 3002, "asset_auth_failure": "0", "asset_user": null, "event_count": 1}),
            json!({"metadata.log_source": "windows_sysmon", "class_uid": 201001, "asset_auth_failure": 0, "asset_user": "alice", "event_count": 1}),
        ];
        let (total, facets) = asset_facets_from_grouped_rows(&rows);
        assert_eq!(total, 12);
        assert_eq!(
            facets.event_kind,
            vec![
                ("PROCESS".to_string(), 7),
                ("AUTH_FAILURE".to_string(), 3),
                ("AUTH_SUCCESS".to_string(), 1),
                ("OTHER".to_string(), 1),
            ]
        );
        assert_eq!(
            facets.source_type,
            vec![
                ("windows_sysmon".to_string(), 8),
                ("windows_event".to_string(), 4)
            ]
        );
        assert_eq!(
            facets.user,
            vec![("alice".to_string(), 8), ("bob".to_string(), 3)]
        );
        let query = asset_summary_query(r#"(device.hostname IN ("h"))"#);
        parse_query(&query).expect("the grouped summary must remain valid nPL");
    }

    #[test]
    fn the_event_page_is_a_newest_first_event_query_naming_every_dto_column() {
        let query = asset_page_query(r#"(device.hostname IN ("h"))"#);
        // No `table` / `sort`: those shapes lose query[T]'s newest-first walk.
        assert!(
            !query.contains("| table") && !query.contains("| sort"),
            "{query}"
        );
        for field in LAKE_ASSET_EVENT_PROJECTION {
            assert!(query.contains(&format!("tostring({field})")), "{field}");
        }
        parse_query(&query).expect("the page query must remain valid nPL");
        let dto = asset_event_dto(
            &json!({"time": "t", "metadata.uid": "u", ASSET_PAGE_PROJECTION_ALIAS: "x"}),
            0,
        );
        assert!(dto["details"].get(ASSET_PAGE_PROJECTION_ALIAS).is_none());
    }

    #[test]
    fn entity_range_lookups_cover_every_predicate_identity() {
        let lookups = asset_entity_range_lookups(
            "src_endpoint.hostname",
            "srv-db02.corp.local",
            &[json!({"ip": "10.2.1.35", "hostname": "srv-db02.corp.local"})],
        )
        .unwrap();
        let paths = lookups
            .iter()
            .map(|(path, _)| *path)
            .collect::<BTreeSet<_>>();
        for path in [
            "src_endpoint.hostname",
            "device.hostname",
            "dst_endpoint.hostname",
            "src_endpoint.ip",
            "dst_endpoint.ip",
        ] {
            assert!(paths.contains(path), "{path}");
        }
        let hosts = &lookups
            .iter()
            .find(|(path, _)| *path == "device.hostname")
            .unwrap()
            .1;
        assert!(hosts.contains(&"srv-db02.corp.local".to_string()));
        assert!(
            hosts.contains(&"srv-db02".to_string()),
            "short form, like the predicate"
        );
    }

    #[test]
    fn durable_asset_assembler_preserves_prevalence_and_sections() {
        let rows = vec![json!({
            "time": "2026-08-11T01:02:03Z",
            "class_uid": 1007,
            "device.hostname": "srv-web02.corp.local",
            "metadata.log_source": "windows_sysmon",
            "process.name": "powershell.exe",
            "process.cmd_line": "powershell -enc AAA",
            "process.file.hashes": [{"value": "deadbeef"}],
        })];
        let prevalence = BTreeMap::from([("deadbeef".to_string(), (1, true, 1))]);
        let range = TimeRange::new(
            chrono::DateTime::parse_from_rfc3339("2026-08-11T00:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
            chrono::DateTime::parse_from_rfc3339("2026-08-11T02:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        let dossier = SearchService::assemble_lake_asset_dossier(rows, &range, &prevalence);
        assert_eq!(
            dossier.identity.hostname.as_deref(),
            Some("srv-web02.corp.local")
        );
        assert_eq!(dossier.processes.unique, 1);
        assert_eq!(
            dossier.processes.rare_list[0].hash.as_deref(),
            Some("deadbeef")
        );
        assert!(dossier.durable_job.is_none());
    }

    /// NAN-3408: the INTERACT. / NETWORK tiles read 0 / 0 for every Windows
    /// logon because they keyed off `auth_protocol` (NTLM / Kerberos), never
    /// the OCSF `logon_type`. The protocol stays the recent-list label.
    #[test]
    fn auth_logon_type_tiles_read_logon_type_not_protocol() {
        let rows = vec![
            json!({"time": "2026-10-09 11:39:46.419000", "class_uid": 3002, "status": "Success",
                   "auth_protocol": "NTLM", "logon_type": "Interactive"}),
            json!({"time": "2026-10-09 11:39:45.000000", "class_uid": 3002, "status": "Success",
                   "auth_protocol": "Kerberos", "logon_type": "Remote Interactive"}),
            json!({"time": "2026-10-09 11:39:44.000000", "class_uid": 3002, "status": "Failure",
                   "auth_protocol": "NTLM", "logon_type": "Network"}),
            json!({"time": "2026-10-09 11:39:43.000000", "class_uid": 3002, "status": "Success",
                   "unmapped.logon_type": "network"}),
            json!({"time": "2026-10-09 11:39:42.000000", "class_uid": 3002, "status": "Success",
                   "auth_protocol": "Negotiate", "logon_type": "OS Service"}),
        ];
        let auth = lake_asset_auth(&rows);
        assert_eq!((auth.success, auth.failure), (4, 1));
        assert_eq!(auth.interactive, 2);
        assert_eq!(auth.network, 2);
        assert_eq!(auth.recent[0].auth_type, "NTLM");
        assert_eq!(auth.recent[3].auth_type, "other");
    }

    /// NAN-3465: the CT 106 sweep's brute force carried only `status_id`
    /// (20 x 2 Failure, 1 x 1 Success, `status` null) and read as 21
    /// successes. `status_id` decides; the caption only fills its gaps.
    #[test]
    fn auth_outcome_reads_status_id_before_the_status_caption() {
        let mut rows = (0..20)
            .map(|i| json!({"time": format!("2026-10-09 01:39:{i:02}.000000"), "class_uid": 3002,
                            "activity_id": 1, "status_id": 2, "user.name": "oc-sweep-alice"}))
            .collect::<Vec<_>>();
        rows.push(json!({"time": "2026-10-09 01:40:00.000000", "class_uid": 3002,
                         "activity_id": 1, "status_id": 1, "user.name": "oc-sweep-alice"}));
        let auth = lake_asset_auth(&rows);
        assert_eq!((auth.success, auth.failure), (1, 20));
        assert_eq!(auth.recent[0].result, "success");
        assert!(auth.recent[1..].iter().all(|r| r.result == "failure"));
        assert_eq!(lake_event_kind(&rows[0]), "AUTH_FAILURE");
        assert_eq!(lake_event_kind(&rows[20]), "AUTH_SUCCESS");
        let (_, facets) = super::snapshot::facets_from_rows(&rows);
        assert!(facets.event_kind.contains(&("AUTH_FAILURE".to_string(), 20)), "{:?}", facets.event_kind);
    }

    #[test]
    fn status_failed_precedence_is_id_then_caption() {
        for (row, failed) in [
            (json!({"status_id": 2}), true),
            (json!({"status_id": "2"}), true),
            (json!({"status_id": 1, "status": "Failure"}), false),
            (json!({"status_id": 2, "status": "Success"}), true),
            (json!({"status": "Failure"}), true),
            (json!({"status_id": 0, "status": "failure"}), true),
            (json!({"status_id": 99, "status": "Success"}), false),
            (json!({}), false),
        ] {
            assert_eq!(lake_status_failed(&row), failed, "{row}");
        }
    }

    /// NAN-3465: every lake-side auth split (event-kind filter, grouped
    /// summary, durable counts, card counts) carries the same status_id-first
    /// form, and each still parses as nPL.
    #[test]
    fn auth_split_queries_read_status_id() {
        for kind in ["AUTH_FAILURE", "AUTH_SUCCESS"] {
            let predicate = event_kind_predicate(kind).unwrap();
            assert!(predicate.contains("status_id=2"), "{predicate}");
            parse_query(&predicate).expect("auth kind predicate must parse");
        }
        assert!(event_kind_predicate("AUTH_SUCCESS").unwrap().contains("NOT (status_id=2"));
        for query in [
            asset_summary_query("user.name=\"a\""),
            super::cards::count_query("user.name=\"a\""),
        ] {
            assert!(query.contains(LAKE_STATUS_FAILURE_NPL), "{query}");
            parse_query(&query).expect("auth split query must parse");
        }
        assert!(LAKE_ASSET_ROW_PROJECTION.contains(&"status_id"));
        assert!(LAKE_ASSET_EVENT_PROJECTION.contains(&"status_id"));
    }

    /// NAN-3408: a Logoff (4634 / OCSF activity_id 2) is not a logon: it
    /// counted as a "success" and filled "Recent logons" with protocol-less
    /// "other" rows (randerson 6h: 1.98K of 7.36K auth rows).
    #[test]
    fn auth_card_skips_logoffs() {
        let rows = vec![
            json!({"time": "2026-10-09 11:39:47.000000", "class_uid": 3002, "activity_id": 2,
                   "activity_name": "Logoff", "status": "Success", "logon_type": "Network"}),
            json!({"time": "2026-10-09 11:39:46.000000", "class_uid": 3002, "activity_id": 1,
                   "activity_name": "Logon", "status": "Success", "auth_protocol": "NTLM",
                   "logon_type": "Interactive"}),
            json!({"time": "2026-10-09 11:39:45.000000", "class_uid": 3002,
                   "activity_name": "logoff", "status": "Success", "logon_type": "Network"}),
            json!({"time": "2026-10-09 11:39:44.000000", "class_uid": 3002, "activity_id": 1,
                   "activity_name": "Logon", "status": "Failure", "auth_protocol": "NTLM",
                   "logon_type": "Network"}),
        ];
        let auth = lake_asset_auth(&rows);
        assert_eq!((auth.success, auth.failure), (1, 1));
        assert_eq!((auth.interactive, auth.network), (1, 1));
        assert_eq!(auth.recent.len(), 2);
        assert!(auth.recent.iter().all(|r| r.auth_type == "NTLM"));
    }

    /// NAN-3258: `| asset field=user` was refused on lean with "not an exact
    /// OCSF identifier" although the parser documents it. UDM aliases and
    /// identity kinds resolve through the lake alias map to the OCSF identity
    /// fields; exact OCSF paths stay exact; unknown fields name the forms.
    #[test]
    fn asset_field_accepts_udm_aliases_and_exact_ocsf_paths() {
        assert_eq!(
            resolve_lake_asset_fields("user").unwrap(),
            vec!["user.name", "actor.user.name", "user.email_addr", "actor.user.email_addr"]
        );
        assert_eq!(resolve_lake_asset_fields("user.name").unwrap(), vec!["user.name"]);
        assert_eq!(
            resolve_lake_asset_fields("actor.user.name").unwrap(),
            vec!["actor.user.name"]
        );
        assert_eq!(
            resolve_lake_asset_fields("src_ip").unwrap(),
            vec!["src_endpoint.ip", "dst_endpoint.ip", "device.ip"]
        );
        assert_eq!(
            resolve_lake_asset_fields("dest_ip").unwrap(),
            vec!["dst_endpoint.ip", "src_endpoint.ip", "device.ip"]
        );
        assert_eq!(
            resolve_lake_asset_fields("src_host").unwrap()[0],
            "src_endpoint.hostname"
        );
        assert_eq!(
            resolve_lake_asset_fields("dest_host").unwrap()[0],
            "dst_endpoint.hostname"
        );
        let host = resolve_lake_asset_fields("host").unwrap();
        assert_eq!(host[0], "device.hostname");
        assert_eq!(host.len(), 3);
        assert_eq!(
            resolve_lake_asset_fields("ip").unwrap(),
            vec!["src_endpoint.ip", "dst_endpoint.ip", "device.ip"]
        );
        assert_eq!(
            resolve_lake_asset_fields("mac").unwrap(),
            vec!["src_endpoint.mac", "dst_endpoint.mac"]
        );
        // Every resolved field must be one the predicate builder accepts.
        for field in ["user", "src_ip", "dest_ip", "src_host", "dest_host", "host", "ip", "mac"] {
            for resolved in resolve_lake_asset_fields(field).unwrap() {
                assert!(asset_semantic(resolved).is_some(), "{field} -> {resolved}");
            }
        }

        let err = resolve_lake_asset_fields("process.name").unwrap_err().to_string();
        assert!(err.contains("process.name"), "{err}");
        for form in ["user.name", "src_endpoint.ip", "user", "src_ip", "host"] {
            assert!(err.contains(form), "error must name accepted form {form}: {err}");
        }
    }

    /// NAN-3258: `user.name="bsmith" | asset field=user` binds the identity
    /// straight from the search term (no seed scan) under the OCSF field.
    #[test]
    fn asset_field_alias_preextracts_from_ocsf_search_term() {
        let query = crate::query::parse_query("user.name=\"bsmith\" | asset field=user").unwrap();
        let info = crate::search::query_processing::extract_asset_command(&query).unwrap();
        let fields = resolve_lake_asset_fields(info.identifier_field.as_deref().unwrap()).unwrap();
        let hit = fields.iter().find_map(|field| {
            let info = AssetCommandInfo {
                identifier_field: Some((*field).to_string()),
                ..info.clone()
            };
            extract_asset_identifier_from_query(&query, &info)
        });
        assert_eq!(hit, Some(("user.name".to_string(), "bsmith".to_string())));
    }

    #[test]
    fn detect_identifier_reads_every_resolved_field() {
        let rows = vec![json!({"actor": {"user": {"name": "bsmith"}}})];
        let fields = resolve_lake_asset_fields("user").unwrap();
        assert_eq!(
            detect_identifier(&rows, &fields).unwrap(),
            ("actor.user.name".to_string(), "bsmith".to_string())
        );
    }

    /// NAN-3689: an IP pivot reads `device.ip` (EDR / Entra sign-in rows carry
    /// the host IP only there) and a user pivot reads both `*.email_addr`
    /// paths (IdP rows). Exact OCSF paths stay exact.
    #[test]
    fn identity_pivots_read_device_ip_and_email_paths() {
        let predicate = build_lake_asset_predicate("device.ip", "10.0.0.9", &[], LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        for field in ["src_endpoint.ip", "dst_endpoint.ip", "device.ip"] {
            assert!(predicate.contains(&format!("{field}=\"10.0.0.9\"")), "{predicate}");
        }
        let predicate = build_lake_asset_predicate("actor.user.email_addr", "a@corp.test", &[], LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        for field in ["user.name", "actor.user.name", "user.email_addr", "actor.user.email_addr"] {
            assert!(predicate.contains(&format!("{field}=\"a@corp.test\"")), "{predicate}");
        }
        parse_query(&predicate).expect("generated asset predicate must remain valid nPL");
        assert_eq!(resolve_lake_asset_fields("device.ip").unwrap(), vec!["device.ip"]);
        assert_eq!(
            resolve_lake_asset_fields("user.email_addr").unwrap(),
            vec!["user.email_addr"]
        );
        let rows = vec![json!({"device": {"ip": "10.0.0.9"}})];
        assert_eq!(
            detect_identifier(&rows, LAKE_ASSET_FIELDS).unwrap(),
            ("device.ip".to_string(), "10.0.0.9".to_string())
        );
    }

    /// A path the tenant never stored is dropped (it would only add a leg);
    /// an unknown (empty) inventory keeps every path; an
    /// empty admit list yields the indexed-only predicate.
    #[test]
    fn rangeless_identity_paths_follow_the_tenant_inventory() {
        use crate::schema::FieldType;
        assert_eq!(lake_asset_rangeless_fields(&[]), LAKE_ASSET_RANGELESS_FIELDS);
        let stored = vec![
            ("src_endpoint.ip".to_string(), FieldType::String),
            ("user.email_addr".to_string(), FieldType::String),
        ];
        assert_eq!(lake_asset_rangeless_fields(&stored), vec!["user.email_addr"]);
        let ip = build_lake_asset_predicate("src_endpoint.ip", "10.0.0.1", &[], &lake_asset_rangeless_fields(&stored)).unwrap();
        assert!(!ip.contains("device.ip"), "{ip}");
        let user = build_lake_asset_predicate("user.name", "a@corp.test", &[], &lake_asset_rangeless_fields(&stored)).unwrap();
        assert!(user.contains("user.email_addr=") && !user.contains("actor.user.email_addr"), "{user}");
        for semantic in ["ip", "user", "host", "mac"] {
            assert_eq!(asset_fields_for_semantic(semantic, &[]), asset_indexed_fields_for_semantic(semantic));
            let all = asset_fields_for_semantic(semantic, LAKE_ASSET_RANGELESS_FIELDS);
            let indexed = asset_indexed_fields_for_semantic(semantic);
            assert_eq!(&all[..indexed.len()], indexed, "indexed paths lead: {semantic}");
            assert!(all[indexed.len()..].iter().all(|f| LAKE_ASSET_RANGELESS_FIELDS.contains(f)));
        }
    }

    /// `/v1/entity/ranges` refuses paths without range rows (worker
    /// `ENTITY_RANGE_PATHS`), so first/last-seen lookups must never name one.
    #[test]
    fn entity_range_lookups_never_name_rangeless_paths() {
        for (field, value) in [("device.ip", "10.0.0.9"), ("actor.user.email_addr", "a@corp.test")] {
            let lookups = asset_entity_range_lookups(field, value, &[]).unwrap();
            assert!(!lookups.is_empty());
            for (path, _) in lookups {
                assert!(!LAKE_ASSET_RANGELESS_FIELDS.contains(&path), "{path}");
            }
        }
    }

    /// A host pivot binds the host's IPs as well; those stay on the ranged
    /// identity paths (no `device.ip` leg in a host dossier).
    #[test]
    fn host_pivot_does_not_widen_bound_ips_onto_rangeless_paths() {
        let predicate = build_lake_asset_predicate(
            "device.hostname",
            "srv-db02.corp.local",
            &[json!({"ip": "10.2.1.35", "hostname": "srv-db02.corp.local", "user": "svc"})],
            LAKE_ASSET_RANGELESS_FIELDS,
        )
        .unwrap();
        assert!(predicate.contains("src_endpoint.ip=\"10.2.1.35\""), "{predicate}");
        for field in LAKE_ASSET_RANGELESS_FIELDS {
            assert!(!predicate.contains(field), "{field}: {predicate}");
        }
    }

    /// A username pivot never names an `*.email_addr` leg (it could not
    /// match and would strip the hint); an address pivot names both.
    #[test]
    fn email_legs_only_for_address_values() {
        let user = build_lake_asset_predicate("user.name", "bsmith", &[], LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        assert!(!user.contains("email_addr"), "{user}");
        let address = build_lake_asset_predicate("user.name", "bsmith@corp.test", &[], LAKE_ASSET_RANGELESS_FIELDS).unwrap();
        assert!(address.contains("user.email_addr=") && address.contains("actor.user.email_addr="), "{address}");
    }
}
