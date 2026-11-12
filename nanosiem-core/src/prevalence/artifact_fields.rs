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
pub use crate::prevalence::coverage::ArtifactKind;
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

/// UDM fields carrying an IP artifact (NAN-5293). Server-only: the Rarity
/// view does not extract IPs, so there is no TS copy to keep in parity.
pub const UDM_IP_FIELDS: &[&str] = &["dest_ip", "src_ip"];

/// OCSF fields carrying an IP artifact (NAN-5293). Server-only, see above.
pub const OCSF_IP_FIELDS: &[&str] = &["dst_endpoint.ip", "src_endpoint.ip"];

/// Every result-row key `kind` may be read from, in COALESCE priority order:
/// the UDM list, then the OCSF list (NAN-5293). These are the bare paths, NOT
/// profile-resolved columns: result rows carry the native columns
/// (`process.file.hashes.sha256`), never the `*_unified` ALIAS columns
/// `SELECT *` omits, so resolving through the profile produced keys no row
/// has. A row only ever carries one schema's names, so listing both is safe.
pub fn row_keys(kind: ArtifactKind) -> impl Iterator<Item = &'static str> {
    let (udm, ocsf): (&[&str], &[&str]) = match kind {
        ArtifactKind::Hash => (UDM_HASH_FIELDS, OCSF_HASH_FIELDS),
        ArtifactKind::Domain => (UDM_DOMAIN_FIELDS, OCSF_DOMAIN_FIELDS),
        ArtifactKind::Ip => (UDM_IP_FIELDS, OCSF_IP_FIELDS),
    };
    udm.iter().chain(ocsf.iter()).copied()
}

/// One physical column an artifact class is read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactColumn {
    /// Escaped column reference (`"process.file.hashes.sha256"`, `file_hash`).
    pub sql: String,
    /// `Array(String)` column (`file.hashes.value`): every element is a candidate.
    pub is_array: bool,
    /// Lowercased at ingest: compare it raw so its bloom / text index prunes.
    pub lowered: bool,
}

impl ArtifactColumn {
    /// A scalar column that is not lowercased at ingest.
    pub fn scalar(sql: impl Into<String>) -> Self {
        Self { sql: sql.into(), is_array: false, lowered: false }
    }
}

/// The columns each artifact class is read from under one schema profile.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ArtifactColumns {
    pub hashes: Vec<ArtifactColumn>,
    /// Columns holding a bare hostname.
    pub domains: Vec<ArtifactColumn>,
    /// Columns holding a full URL; the hostname is parsed out.
    pub urls: Vec<ArtifactColumn>,
    /// Columns holding an IP address.
    pub ips: Vec<ArtifactColumn>,
}

/// IPv4 literal, as a ClickHouse `match()` pattern inside a Rust string.
const IPV4_RE: &str = "'^[0-9]+\\\\.[0-9]+\\\\.[0-9]+\\\\.[0-9]+$'";

impl ArtifactColumns {
    /// Resolve the shared UDM + OCSF path lists against `profile`, keeping only
    /// paths that land on a physical column (deduplicated, list order kept).
    pub fn resolve(profile: &dyn SchemaProfile) -> Self {
        Self {
            hashes: resolve_columns(profile, &[UDM_HASH_FIELDS, OCSF_HASH_FIELDS]),
            domains: resolve_columns(profile, &[UDM_DOMAIN_FIELDS, OCSF_DOMAIN_FIELDS]),
            urls: resolve_columns(profile, &[UDM_URL_FIELDS, OCSF_URL_FIELDS]),
            ips: resolve_columns(profile, &[UDM_IP_FIELDS, OCSF_IP_FIELDS]),
        }
    }

    fn of(&self, kind: ArtifactKind) -> &[ArtifactColumn] {
        match kind {
            ArtifactKind::Hash => &self.hashes,
            ArtifactKind::Domain => &self.domains,
            ArtifactKind::Ip => &self.ips,
        }
    }

    fn scalars(&self, kind: ArtifactKind) -> impl Iterator<Item = &ArtifactColumn> {
        self.of(kind).iter().filter(|c| !c.is_array)
    }

    /// Per-row prevalence lookup key for `kind`: the first non-empty scalar
    /// artifact column, in list order (NAN-5293). This is the key the
    /// prevalence JOIN (`_hash_lookup` / `_domain_lookup` / `_ip_lookup`) and
    /// its NAN-1705 rescue probe look up. Hash and domain keys are lowercased
    /// (the dicts key on `lower(..)`); domain columns holding an IPv4 literal
    /// are skipped for the domain key and become the IP key's last fallback.
    /// The source host (`src_host`) is deliberately absent: under OCSF it
    /// falls back to `device.hostname`, so it keyed every DNS row on the
    /// workstation instead of `query.hostname`. `None` when the schema has no
    /// column for `kind`.
    pub fn lookup_key_sql(&self, kind: ArtifactKind) -> Option<String> {
        let mut branches: Vec<String> = Vec::new();
        match kind {
            ArtifactKind::Hash => {
                branches.extend(self.scalars(kind).map(|c| format!("nullIf({}, '')", c.sql)));
            }
            ArtifactKind::Domain => {
                branches.extend(self.scalars(kind).map(|c| {
                    format!(
                        "nullIf(CASE WHEN {c} != '' AND match({c}, {IPV4_RE}) = 0 THEN lower({c}) ELSE '' END, '')",
                        c = c.sql
                    )
                }));
            }
            ArtifactKind::Ip => {
                branches.extend(self.scalars(kind).map(|c| format!("nullIf({}, '')", c.sql)));
                if let Some(c) = self.scalars(ArtifactKind::Domain).next() {
                    branches.push(format!(
                        "nullIf(CASE WHEN match({c}, {IPV4_RE}) THEN {c} ELSE '' END, '')",
                        c = c.sql
                    ));
                }
            }
        }
        if branches.is_empty() {
            return None;
        }
        let coalesce = format!("COALESCE(\n            {}\n        )", branches.join(",\n            "));
        Some(match kind {
            ArtifactKind::Hash => format!("lower({coalesce})"),
            _ => coalesce,
        })
    }

    /// "This row carries `value` in any `kind` column" (NAN-5293): an OR over
    /// every column of the class, arrays included. Hash and domain values are
    /// compared lowercased (`lower(col)`, or the raw column when it is
    /// lowercased at ingest); IPs compare raw. `None` when the schema has no
    /// column for `kind`.
    pub fn match_sql(&self, kind: ArtifactKind, value: &str) -> Option<String> {
        self.match_any_sql(kind, std::slice::from_ref(&value.to_string()))
    }

    /// [`Self::match_sql`] over a value list (`col IN (..)`).
    pub fn match_any_sql(&self, kind: ArtifactKind, values: &[String]) -> Option<String> {
        let cols = self.of(kind);
        if cols.is_empty() || values.is_empty() {
            return None;
        }
        let fold = kind != ArtifactKind::Ip;
        let list = value_list_sql(kind, values);
        let preds: Vec<String> = cols
            .iter()
            .map(|c| {
                let col = if fold && !c.lowered { lowered(&c.sql) } else { c.sql.clone() };
                if c.is_array {
                    let elems = if fold && !c.lowered {
                        format!("arrayMap(x -> lower(x), {})", c.sql)
                    } else {
                        c.sql.clone()
                    };
                    format!("hasAny({elems}, [{list}])")
                } else if values.len() == 1 {
                    format!("{col} = {list}")
                } else {
                    format!("{col} IN ({list})")
                }
            })
            .collect();
        Some(format!("({})", preds.join(" OR ")))
    }

    /// Every distinct non-empty `kind` artifact a row carries, as one
    /// `Array(String)` expression (hash / domain lowercased). For an
    /// `ARRAY JOIN` that attributes a row to each artifact it holds, where a
    /// single COALESCE key would credit only the first.
    pub fn candidates_sql(&self, kind: ArtifactKind) -> Option<String> {
        let cols = self.of(kind);
        if cols.is_empty() {
            return None;
        }
        let value: fn(&str) -> String = if kind == ArtifactKind::Ip { raw } else { lowered };
        let pairs: Vec<(&ArtifactColumn, fn(&str) -> String)> =
            cols.iter().map(|c| (c, value)).collect();
        let (array, _) = candidate_array(&pairs);
        Some(format!("arrayDistinct(arrayFilter(x -> x != '', {array}))"))
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
            lowered: profile.is_lowercased_at_ingest(&col),
        });
    }
    out
}

/// `values` as an escaped SQL literal list (`'a', 'b'`), lowercased for hash
/// and domain (their keys are lowercase), raw for IP.
pub fn value_list_sql(kind: ArtifactKind, values: &[String]) -> String {
    values
        .iter()
        .map(|v| {
            let v = if kind == ArtifactKind::Ip { v.clone() } else { v.to_lowercase() };
            format!("'{}'", crate::sql_hygiene::escape_sql_string(&v))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Read `path` from a result row: the flat dotted key first (what the search
/// API returns for OCSF columns), then a nested walk that maps over arrays.
/// Mirrors `readField` in `artifactFields.ts`. Returns every non-empty string
/// value found, in order (a scalar yields at most one).
pub fn row_values(row: &serde_json::Map<String, serde_json::Value>, path: &str) -> Vec<String> {
    fn collect(v: &serde_json::Value, out: &mut Vec<String>) {
        match v {
            serde_json::Value::String(s) if !s.is_empty() => out.push(s.clone()),
            serde_json::Value::Array(items) => items.iter().for_each(|i| collect(i, out)),
            _ => {}
        }
    }
    fn walk(v: &serde_json::Value, parts: &[&str], out: &mut Vec<String>) {
        match (v, parts.split_first()) {
            (_, None) => collect(v, out),
            (serde_json::Value::Array(items), Some(_)) => {
                items.iter().for_each(|i| walk(i, parts, out))
            }
            (serde_json::Value::Object(m), Some((head, rest))) => {
                if let Some(child) = m.get(*head) {
                    walk(child, rest, out);
                }
            }
            _ => {}
        }
    }
    let mut out = Vec::new();
    if let Some(v) = row.get(path) {
        collect(v, &mut out);
    } else if path.contains('.') {
        let parts: Vec<&str> = path.split('.').collect();
        if let Some(first) = row.get(parts[0]) {
            walk(first, &parts[1..], &mut out);
        }
    }
    out
}

/// The row's `kind` artifact under COALESCE semantics (NAN-5293): the first
/// non-empty value across [`row_keys`], the same order
/// [`ArtifactColumns::lookup_key_sql`] uses, so the in-memory prevalence path
/// and the JOIN pushdown key a row on the same artifact. Domain keys skip IP
/// literals, as the SQL key does. Returns the key and the value.
pub fn first_row_artifact(
    row: &serde_json::Map<String, serde_json::Value>,
    kind: ArtifactKind,
) -> Option<(&'static str, String)> {
    row_keys(kind).find_map(|key| {
        row_values(row, key)
            .into_iter()
            .find(|v| kind != ArtifactKind::Domain || v.parse::<std::net::IpAddr>().is_err())
            .map(|v| (key, v))
    })
}

/// Distinct `(artifact_type, artifact)` pairs over every artifact column, for
/// the `/api/search/prevalence-artifacts` scatter (NAN-5293). Domains come
/// from the hostname columns plus the hosts of URL columns (as
/// [`distinct_domain_candidates_sql`]), never the source host. Hashes keep the
/// `length >= 32` floor, IPs the IPv4 gate, domains drop IPv4 literals and
/// anything without a dot. `None` when the schema has no artifact column.
pub fn scatter_artifacts_sql(
    columns: &ArtifactColumns,
    logs_table: &str,
    where_clause: &str,
    row_cap: usize,
) -> Option<String> {
    let mut entries: Vec<String> = Vec::new();
    let mut push = |kind: &str, cols: &[ArtifactColumn], value: fn(&str) -> String, gate: &str| {
        for c in cols {
            let tuple = |x: &str| format!("('{kind}', {x})");
            if c.is_array {
                entries.push(format!(
                    "arrayMap(y -> {}, arrayFilter(y -> {}, arrayMap(x -> {}, {})))",
                    tuple("y"),
                    gate.replace("{v}", "y"),
                    value("x"),
                    c.sql
                ));
            } else {
                let v = value(&c.sql);
                entries.push(format!("if({}, [{}], [])", gate.replace("{v}", &v), tuple(&v)));
            }
        }
    };
    push("domain", &columns.domains, lowered, "{v} != '' AND NOT isIPv4String({v}) AND position({v}, '.') > 0");
    push("domain", &columns.urls, url_host, "{v} != '' AND NOT isIPv4String({v}) AND position({v}, '.') > 0");
    push("hash", &columns.hashes, lowered, "length({v}) >= 32");
    push("ip", &columns.ips, raw, "{v} != '' AND isIPv4String({v})");
    if entries.is_empty() {
        return None;
    }
    Some(format!(
        "WITH matching_logs AS (\n    SELECT arrayConcat(\n        {entries}\n    ) AS pairs\n    FROM {logs_table}\n    WHERE {where_clause}\n    LIMIT {row_cap}\n)\nSELECT DISTINCT tupleElement(pair, 1) AS artifact_type, tupleElement(pair, 2) AS artifact\nFROM matching_logs\nARRAY JOIN pairs AS pair\nWHERE artifact != ''",
        entries = entries.join(",\n        "),
    ))
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

fn raw(expr: &str) -> String {
    expr.to_string()
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
