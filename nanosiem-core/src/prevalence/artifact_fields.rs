// SPDX-License-Identifier: AGPL-3.0-or-later

//! Which event fields carry prevalence artifacts (file hashes, domains, URLs),
//! and the SQL that pulls distinct candidates out of the logs table for
//! `POST /api/prevalence/query-artifacts` (NAN-5280).
//!
//! These lists are the server-side copy of the search Rarity view's
//! client-side extractor, `nanosiem-web/src/lib/prevalence/artifactFields.ts`
//! (NAN-5270). The two MUST list the same paths, or the API/agent path and the
//! UI disagree about what a search contains. `tests/prevalence_artifact_fields_parity.rs`
//! parses the TS file and fails on any drift. Edit both together.
//!
//! The client reads these paths out of result rows (flat dotted keys, nested
//! objects, arrays). The server reads them as columns: each path is resolved
//! through the active [`SchemaProfile`], and only paths that land on a physical
//! column are used. Names that exist only in a row shape (`metadata.file_hash`)
//! or only under the other schema (`query.hostname` under UDM) are skipped,
//! never emitted as an unknown column.
//!
//! The OCSF paths cover what the OCSF prevalence baseline keys on
//! (`*_prevalence_source_ocsf_mv`: `file` / `process.file` `hashes.sha256`;
//! `dst_endpoint` / `query` / `url` `hostname`). Before NAN-5280 the endpoint
//! read only `file.hashes.sha256` and `dst_endpoint.hostname`, so Sysmon
//! process hashes and DNS query names never reached it.

use crate::internal_domains::InternalDomains;
use crate::schema::{FieldResolution, SchemaProfile};

/// UDM fields carrying a file hash.
pub const UDM_HASH_FIELDS: &[&str] = &[
    "file_hash",
    "process_hash",
    "metadata.file_hash",
    "metadata.process_hash",
];

/// OCSF fields carrying a file hash (scalar sha256 or hash arrays).
pub const OCSF_HASH_FIELDS: &[&str] = &[
    "file.hashes.sha256",
    "process.file.hashes.sha256",
    "actor.process.file.hashes.sha256",
    "file.hashes.value",
    "process.file.hashes.value",
    "actor.process.file.hashes.value",
    "process_hash_unified",
];

/// UDM fields carrying a bare domain / hostname.
pub const UDM_DOMAIN_FIELDS: &[&str] = &[
    "dest_host",
    "dest_domain",
    "domain",
    "query",
    "url_domain",
    "http_host",
];

/// OCSF fields carrying a bare domain / hostname.
pub const OCSF_DOMAIN_FIELDS: &[&str] = &[
    "dst_endpoint.hostname",
    "query.hostname",
    "url.hostname",
    "http_request.url.hostname",
    "url_domain_unified",
];

/// UDM fields that may carry a full URL (hostname parsed out).
pub const UDM_URL_FIELDS: &[&str] = &["url", "http_referrer", "file_path"];

/// OCSF fields that may carry a full URL.
pub const OCSF_URL_FIELDS: &[&str] = &[
    "url.url_string",
    "http_request.url.url_string",
    "http_request.referrer",
    "url_unified",
];

/// One physical column an artifact class is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactColumn {
    /// Escaped column reference (`"process.file.hashes.sha256"`, `file_hash`).
    pub sql: String,
    /// `Array(String)` column (`file.hashes.value`): every element is a candidate.
    pub is_array: bool,
}

/// The columns each artifact class is read from under one schema profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactColumns {
    pub hashes: Vec<ArtifactColumn>,
    /// Columns holding a bare hostname.
    pub domains: Vec<ArtifactColumn>,
    /// Columns holding a full URL; the hostname is parsed out.
    pub urls: Vec<ArtifactColumn>,
}

impl ArtifactColumns {
    /// Resolve the shared UDM + OCSF path lists against `profile`, keeping only
    /// paths that land on a physical column (deduplicated, list order kept).
    pub fn resolve(profile: &dyn SchemaProfile) -> Self {
        Self {
            hashes: resolve_columns(profile, &[UDM_HASH_FIELDS, OCSF_HASH_FIELDS]),
            domains: resolve_columns(profile, &[UDM_DOMAIN_FIELDS, OCSF_DOMAIN_FIELDS]),
            urls: resolve_columns(profile, &[UDM_URL_FIELDS, OCSF_URL_FIELDS]),
        }
    }
}

fn resolve_columns(profile: &dyn SchemaProfile, lists: &[&[&str]]) -> Vec<ArtifactColumn> {
    let mut out: Vec<ArtifactColumn> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for path in lists.iter().flat_map(|l| l.iter()) {
        let FieldResolution::ExplicitColumn(col) = profile.resolve(path) else {
            continue;
        };
        if !seen.insert(col.clone()) {
            continue;
        }
        out.push(ArtifactColumn {
            sql: crate::query::escape_identifier(&col),
            is_array: profile.is_array_field(&col),
        });
    }
    out
}

/// Alias of the ARRAY JOINed candidate value. Deliberately not a column name
/// any schema uses, so it cannot shadow a column in the caller's filter.
const CANDIDATE: &str = "artifact_candidate";

/// One candidate array over `cols` (scalars as `[..]`, arrays via `arrayMap`,
/// joined with `arrayConcat`), plus the row pre-filter "any source column is
/// non-empty" so rows without an artifact are dropped before the ARRAY JOIN.
fn candidate_array(cols: &[(&ArtifactColumn, fn(&str) -> String)]) -> (String, String) {
    let mut scalars = Vec::new();
    let mut arrays = Vec::new();
    let mut nonempty = Vec::new();
    for (c, value) in cols {
        if c.is_array {
            arrays.push(format!("arrayMap(x -> {}, {})", value("x"), c.sql));
            nonempty.push(format!("notEmpty({})", c.sql));
        } else {
            scalars.push(value(&c.sql));
            nonempty.push(format!("{} != ''", c.sql));
        }
    }
    let mut parts = Vec::new();
    if !scalars.is_empty() {
        parts.push(format!("[{}]", scalars.join(", ")));
    }
    parts.extend(arrays);
    let array = if parts.len() == 1 {
        parts.pop().unwrap_or_default()
    } else {
        format!("arrayConcat({})", parts.join(", "))
    };
    (array, nonempty.join(" OR "))
}

fn lowered(expr: &str) -> String {
    format!("lower({expr})")
}

/// Hostname of a value that looks like an absolute URL, else `''`. The scheme
/// guard keeps Windows paths (`file_path`) and bare words from being read as
/// hosts.
fn url_host(expr: &str) -> String {
    format!("if(match({expr}, '^[a-zA-Z][a-zA-Z0-9+.-]*://'), lower(domain({expr})), '')")
}

/// Distinct file-hash candidates across every hash column, lowercased (the
/// prevalence aggregates key on `lower(hash)`), restricted to the MD5 / SHA-1 /
/// SHA-256 shapes the aggregates accept. `None` when the schema has no hash
/// column.
pub fn distinct_hash_candidates_sql(
    columns: &ArtifactColumns,
    logs_table: &str,
    filter: &str,
    cap: usize,
) -> Option<String> {
    if columns.hashes.is_empty() {
        return None;
    }
    let cols: Vec<(&ArtifactColumn, fn(&str) -> String)> =
        columns.hashes.iter().map(|c| (c, lowered as fn(&str) -> String)).collect();
    let (array, nonempty) = candidate_array(&cols);
    Some(format!(
        "SELECT DISTINCT {CANDIDATE} AS value FROM {logs_table} ARRAY JOIN {array} AS {CANDIDATE} \
         WHERE {filter} AND ({nonempty}) AND length({CANDIDATE}) IN (32, 40, 64) \
         AND match({CANDIDATE}, '^[0-9a-f]+$') LIMIT {cap}"
    ))
}

/// Distinct domain candidates across every hostname column plus the hosts of
/// every URL column, lowercased (the aggregates key on `lower(hostname)`).
///
/// NAN-3226: the internal-name exclusion runs in the WHERE, BEFORE
/// `DISTINCT ... LIMIT`, so a query that touches many internal hosts cannot
/// crowd external domains out of the `cap` budget. `None` when the schema has
/// no hostname or URL column.
pub fn distinct_domain_candidates_sql(
    columns: &ArtifactColumns,
    logs_table: &str,
    filter: &str,
    internal: &InternalDomains,
    cap: usize,
) -> Option<String> {
    let mut cols: Vec<(&ArtifactColumn, fn(&str) -> String)> = columns
        .domains
        .iter()
        .map(|c| (c, lowered as fn(&str) -> String))
        .collect();
    cols.extend(columns.urls.iter().map(|c| (c, url_host as fn(&str) -> String)));
    if cols.is_empty() {
        return None;
    }
    let (array, nonempty) = candidate_array(&cols);
    Some(format!(
        "SELECT DISTINCT {CANDIDATE} AS value FROM {logs_table} ARRAY JOIN {array} AS {CANDIDATE} \
         WHERE {filter} AND ({nonempty}) AND {CANDIDATE} != '' AND {not_internal} LIMIT {cap}",
        not_internal = internal.sql_not_internal(CANDIDATE),
    ))
}

#[cfg(test)]
#[path = "artifact_fields_tests.rs"]
mod tests;
